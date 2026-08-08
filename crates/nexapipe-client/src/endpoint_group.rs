use crate::connection_pool::IrohConnectionPool;
use crate::lb::{LoadBalancingStrategy, RoundRobinBalancer, RandomBalancer, LoadBalancer};
use crate::ClientError;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh::endpoint::Connection;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "jni")]
use crate::jni_log;

#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {};
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

    pub fn node_ids(&self) -> Vec<EndpointId> {
        self.pools.iter().map(|p| p.node_id()).collect()
    }
}

pub struct EndpointGroup {
    domains: HashMap<String, Arc<DomainPools>>,
    default_pools: Option<Arc<DomainPools>>,
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

    /// Warm up one iroh connection per backend pool (and the default pool if
    /// configured), returning them to the pool immediately so the first real
    /// request does not pay the QUIC/relay handshake latency. Returns the
    /// number of pools that have a connection available afterwards.
    pub async fn preconnect_all(&self) -> usize {
        let mut warmed = 0usize;
        for pools in self.domains.values() {
            for pool in &pools.pools {
                if pool.preconnect().await {
                    warmed += 1;
                }
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                if pool.preconnect().await {
                    warmed += 1;
                }
            }
        }
        warmed
    }

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