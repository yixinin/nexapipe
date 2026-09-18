use crate::connection_pool::{IrohConnectionPool, PRECONNECT_TIMEOUT};
use crate::auth::TwoFactorAuth;
use crate::lb::{LoadBalancingStrategy, RoundRobinBalancer, RandomBalancer, LoadBalancer};
use crate::ClientError;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh::endpoint::Connection;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "jni")]
use crate::jni_log;

/// No-op `jni_log!` for builds without the `jni` feature.
///
/// The format arguments are still *evaluated* (borrowed) inside a dead branch,
/// so the optimiser removes the call but `unused_variables` does not fire on
/// variables that only ever appear inside a log statement.
#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if false {
            let _ = ::std::format_args!($($arg)*);
        }
    };
}

#[derive(Debug, Clone)]
pub struct PooledConnection {
    conn: Connection,
    pool_index: usize,
}

impl PooledConnection {
    pub fn new(conn: Connection, pool_index: usize) -> Self {
        Self { conn, pool_index }
    }

    pub fn into_inner(self) -> Connection {
        self.conn
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn pool_index(&self) -> usize {
        self.pool_index
    }
}

pub struct DomainPools {
    pools: Vec<Arc<IrohConnectionPool>>,
    balancer: Box<dyn LoadBalancer + Sync + Send>,
}

impl DomainPools {
    pub fn new(pools: Vec<Arc<IrohConnectionPool>>, strategy: LoadBalancingStrategy) -> Self {
        let balancer: Box<dyn LoadBalancer + Sync + Send> = match strategy {
            LoadBalancingStrategy::RoundRobin => Box::new(RoundRobinBalancer::new()),
            LoadBalancingStrategy::Random => Box::new(RandomBalancer::new()),
        };
        Self { pools, balancer }
    }

    pub async fn get_connection(&self) -> Result<PooledConnection, ClientError> {
        if self.pools.is_empty() {
            return Err(ClientError::InvalidConfig("No endpoint pools configured".to_string()));
        }
        let index = self.balancer.select(self.pools.len());
        let conn = self.pools[index].get_connection().await?;
        Ok(PooledConnection::new(conn, index))
    }

    pub async fn return_connection(&self, pooled_conn: PooledConnection) {
        if self.pools.is_empty() {
            return;
        }
        let index = pooled_conn.pool_index();
        if index < self.pools.len() {
            self.pools[index].return_connection(pooled_conn.into_inner()).await;
        }
    }

    /// The backend node IDs this domain load-balances across (the configured
    /// `server_node_id`s), one per pool.
    pub fn node_ids(&self) -> Vec<EndpointId> {
        self.pools.iter().map(|p| p.backend_id()).collect()
    }
}

pub struct EndpointGroup {
    domains: HashMap<String, Arc<DomainPools>>,
    default_pools: Option<Arc<DomainPools>>,
}

/// Which configured backends answered a reachability probe.
///
/// Building an `EndpointGroup` never dials anything: a well-formed but
/// nonexistent `server_node_id` passes every setup call, and only an actual
/// connection attempt reveals that nothing is there. This report is that
/// attempt, per backend, so a caller can refuse to call a start "successful"
/// when it reached no backend at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreconnectReport {
    /// Backend nodes that accepted a connection.
    pub reachable: Vec<EndpointId>,
    /// Backend nodes that refused, were unreachable, or timed out.
    pub unreachable: Vec<EndpointId>,
    /// Backend nodes that answered the QUIC handshake and then refused the
    /// connection because this client has no 2FA credentials.
    ///
    /// A client without credentials cannot fail the 2FA handshake — it never
    /// starts one — so as far as QUIC is concerned these backends are up. They
    /// are listed here as well as in `unreachable`, so the caller can say *why*
    /// a backend that answered is not going to serve anything.
    pub auth_required: Vec<EndpointId>,
}

impl PreconnectReport {
    /// How many distinct backends were probed. Zero means none was configured.
    pub fn total(&self) -> usize {
        self.reachable.len() + self.unreachable.len()
    }

    /// True when at least one configured backend answered.
    pub fn any_reachable(&self) -> bool {
        !self.reachable.is_empty()
    }

    /// True when at least one backend demanded 2FA credentials this client does
    /// not have. Such a backend answers, then refuses to serve anything.
    pub fn any_auth_required(&self) -> bool {
        !self.auth_required.is_empty()
    }

    /// The unreachable backends as a comma-separated list, for error details.
    ///
    /// Empty when everything answered.
    pub fn unreachable_ids(&self) -> String {
        self.unreachable
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl EndpointGroup {
    pub async fn new_with_nodes(
        nodes: Vec<NodeConfig>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
    ) -> Result<Self, ClientError> {
        let domain_mappings: Vec<DomainMapping> = nodes
            .into_iter()
            .flat_map(|node| node.to_domain_mappings())
            .collect();

        Self::new_with_domain_mappings(domain_mappings, default_endpoint_addr, default_strategy).await
    }

    pub async fn new_with_domain_mappings(
        domain_mappings: Vec<DomainMapping>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
    ) -> Result<Self, ClientError> {
        let mut pool_by_key: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_keys: HashMap<String, Vec<String>> = HashMap::new();

        jni_log!("[DEBUG:endpoint-group] Creating EndpointGroup with {} domain mappings", domain_mappings.len());
        for (i, mapping) in domain_mappings.iter().enumerate() {
            let key = mapping.key();
            let domain_lower = mapping.domain.to_lowercase();
            jni_log!("[DEBUG:endpoint-group] Mapping {}: domain='{}', key='{}'", i, domain_lower, key);
            
            if !pool_by_key.contains_key(&key) {
                let endpoint_addr = mapping.to_endpoint_addr()?;
                let pool = IrohConnectionPool::new(endpoint_addr).await?;
                pool_by_key.insert(key.clone(), Arc::new(pool));
                jni_log!("[DEBUG:endpoint-group] Created connection pool for key: {}", key);
            }

            domain_to_keys.entry(domain_lower.clone()).or_default().push(key.clone());
            jni_log!("[DEBUG:endpoint-group] Mapping domain '{}' to backend '{}'", domain_lower, key);
        }

        let mut domains = HashMap::new();
        for (domain, keys) in domain_to_keys {
            jni_log!("[DEBUG:endpoint-group] Domain '{}' maps to backends: {:?}", domain, keys);
            let pools: Vec<Arc<IrohConnectionPool>> = keys
                .into_iter()
                .filter_map(|k| pool_by_key.get(&k).cloned())
                .collect();
            if !pools.is_empty() {
                let domain_pools = Arc::new(DomainPools::new(pools, default_strategy));
                domains.insert(domain.clone(), domain_pools);
                jni_log!("[DEBUG:endpoint-group] Created DomainPools for domain '{}'", domain);
            }
        }

        jni_log!("[DEBUG:endpoint-group] Final domain map: {:?}", domains.keys());

        let default_pools = if let Some(addr) = default_endpoint_addr {
            let pool = IrohConnectionPool::new(addr).await?;
            Some(Arc::new(DomainPools::new(vec![Arc::new(pool)], default_strategy)))
        } else {
            None
        };

        Ok(Self { domains, default_pools })
    }

    pub async fn new_with_nodes_and_endpoint(
        nodes: Vec<NodeConfig>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
        ep: Endpoint,
    ) -> Result<Self, ClientError> {
        let domain_mappings: Vec<DomainMapping> = nodes
            .into_iter()
            .flat_map(|node| node.to_domain_mappings())
            .collect();

        Self::new_with_domain_mappings_and_endpoint(domain_mappings, default_endpoint_addr, default_strategy, ep).await
    }

    pub async fn new_with_domain_mappings_and_endpoint(
        domain_mappings: Vec<DomainMapping>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
        ep: Endpoint,
    ) -> Result<Self, ClientError> {
        let mut pool_by_key: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_keys: HashMap<String, Vec<String>> = HashMap::new();

        jni_log!("[DEBUG:endpoint-group] Creating EndpointGroup (with endpoint) with {} domain mappings", domain_mappings.len());
        for (i, mapping) in domain_mappings.iter().enumerate() {
            let key = mapping.key();
            let domain_lower = mapping.domain.to_lowercase();
            jni_log!("[DEBUG:endpoint-group] Mapping {}: domain='{}', key='{}'", i, domain_lower, key);
            
            if !pool_by_key.contains_key(&key) {
                let endpoint_addr = mapping.to_endpoint_addr()?;
                let pool = IrohConnectionPool::new_with_endpoint(ep.clone(), endpoint_addr);
                pool_by_key.insert(key.clone(), Arc::new(pool));
                jni_log!("[DEBUG:endpoint-group] Created connection pool for key: {}", key);
            }

            domain_to_keys.entry(domain_lower.clone()).or_default().push(key.clone());
            jni_log!("[DEBUG:endpoint-group] Mapping domain '{}' to backend '{}'", domain_lower, key);
        }

        let mut domains = HashMap::new();
        for (domain, keys) in domain_to_keys {
            jni_log!("[DEBUG:endpoint-group] Domain '{}' maps to backends: {:?}", domain, keys);
            let pools: Vec<Arc<IrohConnectionPool>> = keys
                .into_iter()
                .filter_map(|k| pool_by_key.get(&k).cloned())
                .collect();
            if !pools.is_empty() {
                let domain_pools = Arc::new(DomainPools::new(pools, default_strategy));
                domains.insert(domain.clone(), domain_pools);
                jni_log!("[DEBUG:endpoint-group] Created DomainPools for domain '{}'", domain);
            }
        }

        jni_log!("[DEBUG:endpoint-group] Final domain map (with endpoint): {:?}", domains.keys());

        let default_pools = if let Some(addr) = default_endpoint_addr {
            let pool = IrohConnectionPool::new_with_endpoint(ep, addr);
            Some(Arc::new(DomainPools::new(vec![Arc::new(pool)], default_strategy)))
        } else {
            None
        };

        Ok(Self { domains, default_pools })
    }

    pub async fn new_with_single_pool(conn_pool: IrohConnectionPool) -> Self {
        let default_pools = Some(Arc::new(DomainPools::new(vec![Arc::new(conn_pool)], LoadBalancingStrategy::RoundRobin)));
        Self {
            domains: HashMap::new(),
            default_pools,
        }
    }

    /// Configure client 2FA credentials on every pool in this group.
    /// Safe to call any time before connections are established.
    pub async fn set_two_factor(&self, auth: Option<TwoFactorAuth>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                pool.set_two_factor(auth.clone()).await;
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                pool.set_two_factor(auth.clone()).await;
            }
        }
    }

    pub async fn get_connection(&self, domain: &str) -> Result<PooledConnection, ClientError> {
        let domain_lower = domain.to_lowercase();
        jni_log!("[DEBUG:endpoint-group] Looking up connection for domain: '{}'", domain_lower);
        
        if let Some(pools) = self.domains.get(&domain_lower) {
            jni_log!("[DEBUG:endpoint-group] Found exact match for domain: '{}'", domain_lower);
            return pools.get_connection().await;
        }
        
        let mut parts: Vec<&str> = domain_lower.split('.').collect();
        while parts.len() > 1 {
            parts.remove(0);
            let parent_domain = parts.join(".");
            jni_log!("[DEBUG:endpoint-group] Trying parent domain: '{}'", parent_domain);
            if let Some(pools) = self.domains.get(&parent_domain) {
                jni_log!("[DEBUG:endpoint-group] Found parent domain match: '{}'", parent_domain);
                return pools.get_connection().await;
            }
        }
        
        if let Some(default) = &self.default_pools {
            jni_log!("[DEBUG:endpoint-group] Using default pools for domain: '{}'", domain_lower);
            return default.get_connection().await;
        }
        
        jni_log!("[DEBUG:endpoint-group] No endpoint configured for domain: '{}'", domain_lower);
        Err(ClientError::InvalidConfig(format!("No endpoint configured for domain: {}", domain)))
    }

    pub async fn return_connection(&self, domain: &str, pooled_conn: PooledConnection) {
        let domain_lower = domain.to_lowercase();
        
        if let Some(pools) = self.domains.get(&domain_lower) {
            pools.return_connection(pooled_conn).await;
            return;
        }
        
        let mut parts: Vec<&str> = domain_lower.split('.').collect();
        while parts.len() > 1 {
            parts.remove(0);
            let parent_domain = parts.join(".");
            if let Some(pools) = self.domains.get(&parent_domain) {
                pools.return_connection(pooled_conn).await;
                return;
            }
        }
        
        if let Some(default) = &self.default_pools {
            default.return_connection(pooled_conn).await;
        }
    }

    /// Test iroh-level connectivity to each unique backend node, in parallel.
    ///
    /// Unlike the old sequential preconnect, this:
    /// - Deduplicates pools by *backend* node ID (same backend serving several
    ///   domains is tested once) — deliberately not by the pool's local endpoint
    ///   ID, which is identical for every pool when the group shares one
    ///   caller-owned endpoint, and would collapse all backends into a single
    ///   probe
    /// - Runs all connectivity tests in parallel via `JoinSet`
    /// - Applies a short per-pool timeout (PRECONNECT_TIMEOUT = 5s)
    /// - Caps the overall phase at 10s
    ///
    /// This ensures that a single unreachable backend node does not block the
    /// entire connection flow.
    ///
    /// Returns how many nodes answered. Call [`Self::preconnect_report`] when the
    /// caller also needs to name the ones that did not.
    pub async fn preconnect_all(&self) -> usize {
        self.preconnect_report().await.reachable.len()
    }

    /// Probe every unique backend node in parallel and report which answered.
    ///
    /// This is the availability check every entry point shares. Because no setup
    /// call ever dials, a config pointing at a node that does not exist looks
    /// perfectly valid until something connects; callers therefore treat
    /// [`PreconnectReport::any_reachable`] being false as a failed start rather
    /// than reporting a connection that was never established.
    pub async fn preconnect_report(&self) -> PreconnectReport {
        // Collect unique pools by backend node ID. Multiple domains pointing to
        // the same backend share a single connection pool, so we only need to
        // test each backend once.
        let mut seen_nodes: Vec<EndpointId> = Vec::new();
        let mut unique_pools: Vec<(EndpointId, Arc<IrohConnectionPool>)> = Vec::new();

        let all_pools: Vec<&Arc<IrohConnectionPool>> = self
            .domains
            .values()
            .flat_map(|dp| dp.pools.iter())
            .chain(
                self.default_pools
                    .as_ref()
                    .map(|dp| dp.pools.iter())
                    .into_iter()
                    .flatten(),
            )
            .collect();

        for pool in all_pools {
            let backend_id = pool.backend_id();
            if !seen_nodes.contains(&backend_id) {
                seen_nodes.push(backend_id);
                unique_pools.push((backend_id, pool.clone()));
            }
        }

        jni_log!(
            "[preconnect] Testing connectivity to {} unique node(s) in parallel",
            unique_pools.len()
        );

        let mut report = PreconnectReport::default();
        if unique_pools.is_empty() {
            return report;
        }

        // Run connectivity tests in parallel, each capped at PRECONNECT_TIMEOUT.
        let mut join_set = tokio::task::JoinSet::new();
        for (backend_id, pool) in &unique_pools {
            let backend_id = *backend_id;
            let pool = pool.clone();
            join_set.spawn(async move {
                let answered = match tokio::time::timeout(PRECONNECT_TIMEOUT, pool.preconnect()).await
                {
                    Ok(true) => true,
                    Ok(false) => {
                        jni_log!("[preconnect] Node unreachable (preconnect returned false)");
                        false
                    }
                    Err(_) => {
                        jni_log!(
                            "[preconnect] Node timed out after {}s",
                            PRECONNECT_TIMEOUT.as_secs()
                        );
                        false
                    }
                };
                (backend_id, answered)
            });
        }

        // Overall cap: 10s for the entire preconnect phase.
        let overall_deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
        let mut probed = 0usize;
        while let Ok(result) = tokio::time::timeout_at(overall_deadline, join_set.join_next()).await
        {
            match result {
                Some(Ok((backend_id, true))) => {
                    probed += 1;
                    report.reachable.push(backend_id);
                }
                Some(Ok((backend_id, false))) => {
                    probed += 1;
                    report.unreachable.push(backend_id);
                }
                Some(Err(_e)) => {
                    jni_log!("[preconnect] Task failed");
                }
                None => break, // JoinSet empty
            }
        }

        // A task the overall cap cut off never reported. Count it as unreachable:
        // a backend may only be called usable when it actually answered, and
        // `total()` must still equal the number of configured backends.
        if probed < seen_nodes.len() {
            let mut classified = report.reachable.clone();
            classified.extend(report.unreachable.iter().copied());
            let missing = seen_nodes
                .iter()
                .copied()
                .filter(|id| !classified.contains(id));
            report.unreachable.extend(missing);
        }

        // A backend that answered and then refused the connection leaves the
        // reason on its pool. Collect it so the caller can report "this server
        // wants 2FA" instead of an "unreachable" that hides the real cause.
        for (backend_id, pool) in &unique_pools {
            if let Some(reason) = pool.take_auth_required().await {
                jni_log!("[preconnect] Node {} requires 2FA: {}", backend_id, reason);
                report.auth_required.push(*backend_id);
            }
        }

        jni_log!(
            "[preconnect] Connectivity test done: {}/{} node(s) reachable",
            report.reachable.len(),
            seen_nodes.len()
        );
        report
    }

    /// The backend node IDs configured in this group (one per pool, deduplicated
    /// per domain). These are the servers traffic is dialed to, i.e. the
    /// `server_node_id`s from the client configuration.
    pub fn node_ids(&self) -> Vec<EndpointId> {
        let mut ids = Vec::new();
        for pools in self.domains.values() {
            ids.extend(pools.node_ids());
        }
        if let Some(default) = &self.default_pools {
            ids.extend(default.node_ids());
        }
        ids
    }

    pub async fn close_all(&self) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                pool.close_all().await;
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                pool.close_all().await;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainMapping {
    pub domain: String,
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
}

impl DomainMapping {
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, ClientError> {
        crate::connection_pool::parse_endpoint_addr(
            self.server_node_id.as_deref(),
            self.server_ticket.as_deref(),
        )
    }

    pub fn key(&self) -> String {
        if let Some(id) = &self.server_node_id {
            format!("node_id:{}", id)
        } else if let Some(ticket) = &self.server_ticket {
            format!("ticket:{}", ticket)
        } else {
            "unknown".to_string()
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
    pub domains: Vec<String>,
}

impl NodeConfig {
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, ClientError> {
        crate::connection_pool::parse_endpoint_addr(
            self.server_node_id.as_deref(),
            self.server_ticket.as_deref(),
        )
    }

    pub fn key(&self) -> String {
        if let Some(id) = &self.server_node_id {
            format!("node_id:{}", id)
        } else if let Some(ticket) = &self.server_ticket {
            format!("ticket:{}", ticket)
        } else {
            "unknown".to_string()
        }
    }

    pub fn to_domain_mappings(&self) -> Vec<DomainMapping> {
        self.domains.iter().map(|domain| DomainMapping {
            domain: domain.clone(),
            server_node_id: self.server_node_id.clone(),
            server_ticket: self.server_ticket.clone(),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::endpoint::presets;

    /// A syntactically valid backend node ID that no endpoint is bound to.
    fn unused_backend_id() -> EndpointId {
        iroh::SecretKey::generate()
            .public()
            .to_string()
            .parse()
            .expect("a generated public key is a valid node ID")
    }

    fn node(backend: EndpointId, domain: &str) -> NodeConfig {
        NodeConfig {
            server_node_id: Some(backend.to_string()),
            server_ticket: None,
            domains: vec![domain.to_string()],
        }
    }

    /// Regression guard: the group must report the *configured* backend IDs.
    ///
    /// When every pool shares one caller-owned endpoint (the Android JNI shape),
    /// `IrohConnectionPool::node_id()` answers with the same local endpoint ID
    /// for all of them. Reporting that made `preconnect_all` dedupe every
    /// backend into a single probe, so only one of N nodes was ever checked and
    /// N-1 unreachable nodes went unnoticed.
    #[tokio::test]
    async fn node_ids_are_the_configured_backends_not_the_local_endpoint() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");

        let backend_a = unused_backend_id();
        let backend_b = unused_backend_id();
        assert_ne!(backend_a, backend_b);

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![node(backend_a, "a.example.com"), node(backend_b, "b.example.com")],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep.clone(),
        )
        .await
        .expect("a bogus but well-formed node ID must still build a group");

        let ids = group.node_ids();
        assert_eq!(ids.len(), 2, "both backends must be listed: {ids:?}");
        assert!(ids.contains(&backend_a), "{ids:?} is missing {backend_a}");
        assert!(ids.contains(&backend_b), "{ids:?} is missing {backend_b}");
        assert!(
            !ids.contains(&ep.id()),
            "the group reported its local endpoint ID {ids:?} instead of the backends"
        );
    }

    /// Two distinct backends behind two domains must stay two pools, so the
    /// dedup in `preconnect_all` probes each of them.
    #[tokio::test]
    async fn distinct_backends_stay_distinct_pools() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");

        let backend_a = unused_backend_id();
        let backend_b = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![node(backend_a, "a.example.com"), node(backend_b, "b.example.com")],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        // One pool per backend, and each domain load-balances over its own pool.
        for (domain, expected) in [("a.example.com", backend_a), ("b.example.com", backend_b)] {
            let pools = group
                .domains
                .get(domain)
                .expect("the domain must have a pool");
            assert_eq!(pools.pools.len(), 1, "{domain} should map to one pool");
            assert_eq!(pools.pools[0].backend_id(), expected);
        }
    }

    /// A group with no backend must not look like a reachable one: the callers
    /// treat an empty report as a failed start, so `total()` has to be 0 rather
    /// than "all of nothing answered".
    #[tokio::test]
    async fn group_without_backends_reports_nothing_probed() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let group = EndpointGroup::new_with_nodes_and_endpoint(
            Vec::new(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        let report = group.preconnect_report().await;
        assert_eq!(report.total(), 0);
        assert!(!report.any_reachable());
        assert_eq!(report.unreachable_ids(), "");
    }

    /// The report is what callers put in their error messages, so the summary
    /// must name exactly the backends that failed and nothing else.
    #[test]
    fn report_names_only_the_unreachable_backends() {
        let reached = unused_backend_id();
        let failed = unused_backend_id();

        let report = PreconnectReport {
            reachable: vec![reached],
            unreachable: vec![failed],
            auth_required: Vec::new(),
        };

        assert_eq!(report.total(), 2);
        assert!(report.any_reachable());
        assert!(!report.any_auth_required());
        assert_eq!(report.unreachable_ids(), failed.to_string());
        assert!(!report.unreachable_ids().contains(&reached.to_string()));

        let all_failed = PreconnectReport {
            reachable: Vec::new(),
            unreachable: vec![reached, failed],
            auth_required: Vec::new(),
        };
        assert!(!all_failed.any_reachable());
        assert_eq!(
            all_failed.unreachable_ids(),
            format!("{}, {}", reached, failed)
        );

        // A backend that answers the handshake and then refuses it for missing
        // 2FA is unreachable *and* named as such: the caller's error message
        // has to be able to say why.
        let needs_2fa = PreconnectReport {
            reachable: Vec::new(),
            unreachable: vec![failed],
            auth_required: vec![failed],
        };
        assert!(!needs_2fa.any_reachable());
        assert!(needs_2fa.any_auth_required());
    }
}
