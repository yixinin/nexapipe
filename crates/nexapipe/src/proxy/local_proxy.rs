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

    // The strategy is the client's, because what it picks is a node: the
    // server's own `config::get_strategy` picks a backend out of a route's
    // pool, which is a different choice with a different list. The rule that
    // turns a name into one is the enum's own, in the client crate, and it
    // refuses a name it does not have rather than answering with round-robin.
    let default_strategy = local_proxy_strategy(config.strategy.as_deref())?;

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

    let endpoint_group = Arc::new(endpoint_group);

    // Keeps health current, which here means "capable of being restored".
    // Nothing records a backend *answering* except the background probe, so a
    // group without this task marks backends down and then leaves them there: a
    // domain with several of them stops forwarding, and only a restart clears
    // it. Every other long-lived owner of a group already starts this.
    //
    // Not instead of the report below — that one is the startup gate, and it
    // decides whether this process runs at all.
    endpoint_group.start_health_probe();

    // 2FA: if `[local_proxy.two_factor]` is configured and enabled, every new connection
    // performs an authentication handshake first.
    if let Some(tf) = two_factor_config
        && tf.enabled.unwrap_or(false)
    {
        // A name nobody supports is refused rather than downgraded: the node
        // would compute codes this server does not accept.
        let algorithm = TotpAlgorithm::try_from_name(tf.algorithm.as_deref().unwrap_or("sha1"))?;
        let auth = TwoFactorAuth::new(&tf.client_id, &tf.secret, algorithm)?;
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

    // The local proxy hands out the tunnel of a connection that has already
    // authenticated, so anything that reaches the port gets the tunnel without
    // a credential. A loopback bind is the default and a non-loopback one has
    // to be asked for — the same shape as `[server] expose`.
    let exposed = config.expose.unwrap_or(false);
    let local_proxy = Arc::new(if exposed {
        LocalProxy::new_exposed(&listen_addr, proxy_domains, endpoint_group).await?
    } else {
        LocalProxy::new(&listen_addr, proxy_domains, endpoint_group).await?
    });

    // Waits for the notice instead of polling for it, and is aborted once
    // `run()` is over: the watcher used to keep running — waking ten times a
    // second — for the rest of the process, long after the listener it watched
    // had stopped.
    let stopper = {
        let local_proxy = local_proxy.clone();
        let shutdown_signal = shutdown_signal.clone();
        tokio::spawn(async move {
            shutdown_signal.requested().await;
            tracing::info!("Shutdown signal received, stopping local proxy");
            local_proxy.stop();
        })
    };

    let result = local_proxy.run().await;
    // Whatever brought `run()` back, there is nothing left to stop.
    stopper.abort();
    local_proxy.close_all().await;

    result?;
    Ok(())
}

/// The strategy the local proxy picks a node with.
///
/// The local proxy is a **client** here: what it balances over is a list of
/// servers, and it picks one of them for a connection. The server's own
/// `config::get_strategy` balances over the backends of a route, which is a
/// different list and a different choice, so the two rules are kept apart.
///
/// **A name it does not have is refused rather than guessed.** It used to be
/// answered with round-robin — every unknown name, including a misspelling of
/// one that exists — and the local proxy then ran a strategy the file did not
/// say it was running, with nothing reporting it. Refusing it stops the
/// process instead, which is the only thing that tells the operator the file
/// is wrong.
fn local_proxy_strategy(name: Option<&str>) -> anyhow::Result<LoadBalancingStrategy> {
    match name {
        None | Some("") => Ok(LoadBalancingStrategy::RoundRobin),
        Some(name) => LoadBalancingStrategy::from_name(name).map_err(|e| anyhow::anyhow!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name that is not there is refused, and the local proxy does not
    /// start.
    ///
    /// This is the behaviour change: a `[local_proxy] strategy` the client
    /// cannot honour used to be answered with round-robin and the process ran
    /// happily on a strategy nobody asked for.
    #[test]
    fn a_name_the_client_has_no_strategy_for_is_refused() {
        for name in ["least_conn", "round-robin", "round_robinn"] {
            let error = local_proxy_strategy(Some(name))
                .expect_err("a name the client cannot honour must not start the proxy");
            let message = error.to_string();
            assert!(
                message.contains(name),
                "the refusal names the strategy it turned down: {message}"
            );
            assert!(
                message.contains("strategy"),
                "and says what the name was about: {message}"
            );
        }
    }

    /// The two names the client has are honoured, under the spellings the
    /// server accepts.
    #[test]
    fn the_names_the_client_has_are_honoured() {
        assert_eq!(
            local_proxy_strategy(Some("round_robin")).expect("a name the client has"),
            LoadBalancingStrategy::RoundRobin
        );
        assert_eq!(
            local_proxy_strategy(Some("Random")).expect("a name the client has"),
            LoadBalancingStrategy::Random
        );
    }

    /// A file that says nothing gets the default.
    #[test]
    fn no_strategy_is_the_default_one() {
        assert_eq!(
            local_proxy_strategy(None).expect("no strategy is the default"),
            LoadBalancingStrategy::RoundRobin
        );
        assert_eq!(
            local_proxy_strategy(Some("")).expect("an empty strategy is the default"),
            LoadBalancingStrategy::RoundRobin
        );
    }
}
