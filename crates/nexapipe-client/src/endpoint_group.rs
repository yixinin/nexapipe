use crate::connection_pool::IrohConnectionPool;
use crate::lb::{LoadBalancingStrategy, RoundRobinBalancer, RandomBalancer, LoadBalancer};
use crate::ClientError;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh::endpoint::Connection;
use std::collections::HashMap;
use std::sync::Arc;

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
        let mut pool_by_node: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_nodes: HashMap<String, Vec<String>> = HashMap::new();

        for node in &nodes {
            let node_key = node.key();
            if !pool_by_node.contains_key(&node_key) {
                let endpoint_addr = node.to_endpoint_addr()?;
                let pool = IrohConnectionPool::new(endpoint_addr).await?;
                pool_by_node.insert(node_key.clone(), Arc::new(pool));
            }

            for domain in &node.domains {
                domain_to_nodes.entry(domain.to_lowercase()).or_default().push(node_key.clone());
            }
        }

        let mut domains = HashMap::new();
        for (domain, node_keys) in domain_to_nodes {
            let pools: Vec<Arc<IrohConnectionPool>> = node_keys
                .into_iter()
                .filter_map(|k| pool_by_node.get(&k).cloned())
                .collect();
            if !pools.is_empty() {
                let domain_pools = Arc::new(DomainPools::new(pools, default_strategy));
                domains.insert(domain, domain_pools);
            }
        }

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
        let mut pool_by_node: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_nodes: HashMap<String, Vec<String>> = HashMap::new();

        for node in &nodes {
            let node_key = node.key();
            if !pool_by_node.contains_key(&node_key) {
                let endpoint_addr = node.to_endpoint_addr()?;
                let pool = IrohConnectionPool::new_with_endpoint(ep.clone(), endpoint_addr);
                pool_by_node.insert(node_key.clone(), Arc::new(pool));
            }

            for domain in &node.domains {
                domain_to_nodes.entry(domain.to_lowercase()).or_default().push(node_key.clone());
            }
        }

        let mut domains = HashMap::new();
        for (domain, node_keys) in domain_to_nodes {
            let pools: Vec<Arc<IrohConnectionPool>> = node_keys
                .into_iter()
                .filter_map(|k| pool_by_node.get(&k).cloned())
                .collect();
            if !pools.is_empty() {
                let domain_pools = Arc::new(DomainPools::new(pools, default_strategy));
                domains.insert(domain, domain_pools);
            }
        }

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
        
        if let Some(pools) = self.domains.get(&domain_lower) {
            pools.get_connection().await
        } else if let Some(default) = &self.default_pools {
            default.get_connection().await
        } else {
            Err(ClientError::InvalidConfig(format!("No endpoint configured for domain: {}", domain)))
        }
    }

    pub async fn return_connection(&self, domain: &str, pooled_conn: PooledConnection) {
        let domain_lower = domain.to_lowercase();
        
        if let Some(pools) = self.domains.get(&domain_lower) {
            pools.return_connection(pooled_conn).await;
        } else if let Some(default) = &self.default_pools {
            default.return_connection(pooled_conn).await;
        }
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
}