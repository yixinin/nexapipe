use crate::config::LocalProxyConfig;
use crate::shutdown::ShutdownSignal;
use iroh::endpoint::presets;
use iroh::Endpoint;
use nexapipe_client::{EndpointGroup, NodeConfig, LoadBalancingStrategy, LocalProxy};
use std::sync::Arc;

pub async fn run_local_proxy(
    config: LocalProxyConfig,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr.clone();
    let proxy_domains = config.proxy_domains;

    tracing::info!("Starting local proxy on: {}", listen_addr);
    tracing::info!("Proxy domains: {:?}", proxy_domains);

    let default_strategy = get_strategy(&config.strategy);

    let endpoint_group = if let Some(nodes) = config.nodes {
        tracing::info!("Using multi-endpoint configuration with {} nodes", nodes.len());
        
        let ep = Endpoint::builder(presets::N0).bind().await?;
        tracing::info!("Shared iroh endpoint created, client node ID: {}", ep.id());
        
        let node_configs: Vec<NodeConfig> = nodes.into_iter()
            .map(|n| NodeConfig {
                server_node_id: n.server_node_id,
                server_ticket: n.server_ticket,
                domains: n.domains,
            })
            .collect();

        let default_endpoint_addr = if config.server_node_id.is_some() || config.server_ticket.is_some() {
            Some(nexapipe_client::connection_pool::parse_endpoint_addr(
                config.server_node_id.as_deref(),
                config.server_ticket.as_deref(),
            )?)
        } else {
            None
        };

        EndpointGroup::new_with_nodes_and_endpoint(node_configs, default_endpoint_addr, default_strategy, ep).await?
    } else {
        tracing::info!("Using single-endpoint configuration");
        
        let server_ticket = config.server_ticket.as_deref();
        let server_node_id = config.server_node_id.as_deref();
        
        let endpoint_addr = nexapipe_client::connection_pool::parse_endpoint_addr(server_node_id, server_ticket)?;
        let conn_pool = nexapipe_client::IrohConnectionPool::new(endpoint_addr).await?;
        
        tracing::info!("Iroh client endpoint started, node ID: {}", conn_pool.node_id());
        
        EndpointGroup::new_with_single_pool(conn_pool).await
    };

    let node_ids = endpoint_group.node_ids();
    tracing::info!("Connected to {} endpoint(s): {:?}", node_ids.len(), node_ids);

    let local_proxy = Arc::new(LocalProxy::new(&listen_addr, proxy_domains, endpoint_group).await?);
    
    let local_proxy_clone = local_proxy.clone();
    tokio::spawn(async move {
        loop {
            if shutdown_signal.is_shutdown_requested() {
                tracing::info!("Shutdown signal received, stopping local proxy");
                local_proxy_clone.stop();
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    });

    local_proxy.run().await?;
    local_proxy.close_all().await;

    Ok(())
}

fn get_strategy(strategy: &Option<String>) -> LoadBalancingStrategy {
    match strategy.as_deref() {
        Some("random") | Some("Random") => LoadBalancingStrategy::Random,
        Some("round_robin") | Some("RoundRobin") | Some("roundrobin") => LoadBalancingStrategy::RoundRobin,
        None | Some(_) => LoadBalancingStrategy::RoundRobin,
    }
}