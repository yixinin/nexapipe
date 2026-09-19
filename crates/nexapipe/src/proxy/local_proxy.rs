use crate::config::LocalProxyConfig;
use crate::shutdown::ShutdownSignal;
use iroh::Endpoint;
use iroh::endpoint::presets;
use nexapipe_client::auth::{TotpAlgorithm, TwoFactorAuth};
use nexapipe_client::{EndpointGroup, LoadBalancingStrategy, LocalProxy, NodeConfig};
use std::sync::Arc;

pub async fn run_local_proxy(
    config: LocalProxyConfig,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr.clone();
    let two_factor_config = config.two_factor.clone();

    let mut proxy_domains = config.proxy_domains;

    if let Some(nodes) = &config.nodes {
        for node in nodes {
            for domain in &node.domains {
                if !proxy_domains.contains(domain) {
                    proxy_domains.push(domain.clone());
                }
            }
        }
    }

    tracing::info!("Starting local proxy on: {}", listen_addr);
    tracing::info!("Proxy domains: {:?}", proxy_domains);

    let default_strategy = get_strategy(&config.strategy);

    let endpoint_group = if let Some(nodes) = config.nodes {
        tracing::info!(
            "Using multi-endpoint configuration with {} nodes",
            nodes.len()
        );

        // Same transport tuning as the server side: leaving the default 1.25 MB per-stream
        // window would cap every proxied connection at ~50 Mbps on a 200 ms path.
        let transport_tuning = nexapipe_client::transport::TransportTuning::from_env();
        tracing::info!("QUIC transport tuning: {}", transport_tuning.describe());

        let ep = Endpoint::builder(presets::N0)
            .transport_config(transport_tuning.transport_config())
            .bind()
            .await?;
        tracing::info!("Shared iroh endpoint created, client node ID: {}", ep.id());

        let node_configs: Vec<NodeConfig> = nodes
            .into_iter()
            .map(|n| NodeConfig {
                server_node_id: n.server_node_id,
                server_ticket: n.server_ticket,
                domains: n.domains,
            })
            .collect();

        let default_endpoint_addr =
            if config.server_node_id.is_some() || config.server_ticket.is_some() {
                Some(nexapipe_client::connection_pool::parse_endpoint_addr(
                    config.server_node_id.as_deref(),
                    config.server_ticket.as_deref(),
                )?)
            } else {
                None
            };

        EndpointGroup::new_with_nodes_and_endpoint(
            node_configs,
            default_endpoint_addr,
            default_strategy,
            ep,
        )
        .await?
    } else {
        tracing::info!("Using single-endpoint configuration");

        let server_ticket = config.server_ticket.as_deref();
        let server_node_id = config.server_node_id.as_deref();

        let endpoint_addr =
            nexapipe_client::connection_pool::parse_endpoint_addr(server_node_id, server_ticket)?;
        let conn_pool = nexapipe_client::IrohConnectionPool::new(endpoint_addr).await?;

        tracing::info!(
            "Iroh client endpoint started, node ID: {}",
            conn_pool.node_id()
        );

        EndpointGroup::new_with_single_pool(conn_pool).await
    };

    // 2FA: if `[local_proxy.two_factor]` is configured and enabled, every new connection
    // performs an authentication handshake first.
    if let Some(tf) = two_factor_config
        && tf.enabled.unwrap_or(false)
    {
        let auth = TwoFactorAuth::new(
            &tf.client_id,
            &tf.secret,
            TotpAlgorithm::from_name(tf.algorithm.as_deref().unwrap_or("sha1")),
        )?;
        endpoint_group.set_two_factor(Some(auth)).await;
        tracing::info!("2FA enabled for local proxy, client_id: {}", tf.client_id);
    }

    let node_ids = endpoint_group.node_ids();
    tracing::info!("Configured {} backend(s): {:?}", node_ids.len(), node_ids);

    // Reachability gate. Nothing above dials: `parse_endpoint_addr` only checks
    // the format and `EndpointGroup::new_*` only binds a local endpoint, so a
    // node ID that does not exist gets this far looking valid. Probing here —
    // before the listen socket is bound — is what keeps the process from
    // announcing a proxy that forwards to nothing.
    let report = endpoint_group.preconnect_report().await;
    if !report.any_reachable() {
        if report.total() == 0 {
            anyhow::bail!(
                "No backend is configured: neither [local_proxy] server_node_id/server_ticket \
                 nor any [[local_proxy.nodes]] entry is set"
            );
        }
        // A backend that answered and then closed for missing 2FA looks exactly
        // like an unreachable one from here, so name the real cause: the fix is
        // on this side of the connection, not on the server's.
        if report.any_auth_required() {
            anyhow::bail!(
                "The server requires 2FA but this client has no credentials: {} accepted the \
                 connection and then refused it. Set [local_proxy.two_factor] with the client id \
                 and secret the server lists under [auth.clients].",
                report.unreachable_ids()
            );
        }
        anyhow::bail!(
            "No backend is reachable: all {} configured node(s) failed to connect ({})",
            report.total(),
            report.unreachable_ids()
        );
    }
    if !report.unreachable.is_empty() {
        tracing::warn!(
            "{} of {} backend(s) unreachable, continuing with the remaining {}: {}",
            report.unreachable.len(),
            report.total(),
            report.reachable.len(),
            report.unreachable_ids()
        );
    }
    tracing::info!("{} backend(s) reachable", report.reachable.len());

    let local_proxy =
        Arc::new(LocalProxy::new(&listen_addr, proxy_domains, Arc::new(endpoint_group)).await?);

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
        Some("round_robin") | Some("RoundRobin") | Some("roundrobin") => {
            LoadBalancingStrategy::RoundRobin
        }
        None | Some(_) => LoadBalancingStrategy::RoundRobin,
    }
}
