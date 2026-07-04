use crate::config::LocalProxyConfig;
use crate::shutdown::ShutdownSignal;
use nexapipe_client::{IrohConnectionPool, LocalProxy};
use std::sync::Arc;

pub async fn run_local_proxy(
    config: LocalProxyConfig,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr.clone();
    let proxy_domains = config.proxy_domains;
    let server_ticket = config.server_ticket.as_deref();
    let server_node_id = config.server_node_id.as_deref();

    tracing::info!("Starting local proxy on: {}", listen_addr);
    tracing::info!("Proxy domains: {:?}", proxy_domains);

    let endpoint_addr = nexapipe_client::connection_pool::parse_endpoint_addr(server_node_id, server_ticket)?;
    let conn_pool = IrohConnectionPool::new(endpoint_addr).await?;

    tracing::info!("Iroh client endpoint started, node ID: {}", conn_pool.node_id());

    let local_proxy = LocalProxy::new(&listen_addr, proxy_domains, conn_pool).await?;
    
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        loop {
            if shutdown_signal.is_shutdown_requested() {
                tracing::info!("Shutdown signal received, stopping local proxy");
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    });

    local_proxy.run().await?;

    Ok(())
}
