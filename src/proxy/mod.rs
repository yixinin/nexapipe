pub mod local_proxy;

use crate::config::{IrohConfig, LocalProxyConfig, ServerConfig};
use crate::conn;
use crate::routes::Route;
use crate::routes::RouteConfig;
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMap, RelayUrl};
use iroh_tickets::Ticket;
use iroh_tickets::endpoint::EndpointTicket;
use std::fs;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

pub async fn run_proxy(
    routes: Vec<Route>,
    default_backend: String,
    server_config: Option<ServerConfig>,
    iroh_config: Option<IrohConfig>,
) -> anyhow::Result<()> {
    let config = Arc::new(RouteConfig::new(routes, default_backend.clone()));

    let mut builder = Endpoint::builder(presets::N0).alpns(vec![ALPN_HTTP3.to_vec()]);

    if let Some(iroh_cfg) = iroh_config {
        if let Some(port) = iroh_cfg.bind_port {
            let addr = SocketAddr::from_str(&format!("0.0.0.0:{}", port))
                .map_err(|e| anyhow::anyhow!("Invalid bind address: {}", e))?;
            builder = builder.bind_addr(addr)?;
            tracing::info!("Iroh bind port: {}", port);
        }

        if let Some(relay_url) = iroh_cfg.relay_url {
            if let Some(mode) = iroh_cfg.relay_mode {
                match mode.as_str() {
                    "disabled" | "Disabled" => {
                        tracing::warn!("Relay mode is disabled but relay URL is set, ignoring URL");
                    }
                    "default" | "Default" | "native" | "Native" => {
                        tracing::warn!("Relay mode is default/native but custom URL is set");
                    }
                    "custom" | "Custom" => {
                        tracing::info!("Configuring custom relay: {}", relay_url);
                        let relay_url = RelayUrl::from_str(&relay_url)?;
                        let relay_urls = RelayMap::from_iter(vec![relay_url]);
                        builder = builder.relay_mode(iroh::RelayMode::Custom(relay_urls));
                    }
                    _ => {
                        tracing::warn!("Unknown relay mode: {}", mode);
                    }
                }
            } else {
                tracing::info!("Configuring custom relay: {}", relay_url);
            }
        }
    }

    let ep = builder.bind().await?;

    let node_id = ep.id();
    let node_addr = ep.addr();

    tracing::info!("Iroh proxy endpoint started successfully");
    tracing::info!("Node ID: {}", node_id);
    tracing::info!("Default backend: {}", default_backend);

    if let Some(server) = server_config {
        let tls_enabled = server.tls_enabled.unwrap_or(false);
        tracing::info!("Server TLS enabled: {}", tls_enabled);

        if tls_enabled {
            if let (Some(cert_path), Some(key_path)) = (server.cert_path, server.key_path) {
                if fs::metadata(&cert_path).is_ok() && fs::metadata(&key_path).is_ok() {
                    tracing::info!(
                        "TLS certificate files found: {} and {}",
                        cert_path,
                        key_path
                    );
                } else {
                    tracing::warn!("TLS certificate or key file not found");
                }
            }
        }
    }

    for (i, route) in config.routes().iter().enumerate() {
        tracing::info!(
            "Route {}: host={}, path={} (prefix={}), backends={}, strategy={:?}",
            i + 1,
            route.host_pattern(),
            route.path_pattern(),
            route.path_is_prefix(),
            route.backend_pool().len(),
            route.backend_pool().strategy()
        );
    }

    let ticket = EndpointTicket::new(node_addr);
    let ticket_str = ticket.encode_string();

    println!("\n========================================");
    println!("Proxy Connection Information");
    println!("========================================");
    println!("Node ID: {}", node_id);
    println!("Ticket (for clients): {}", ticket_str);
    println!("========================================\n");

    tracing::info!("Connection ticket: {}", ticket_str);

    loop {
        match ep.accept().await {
            Some(incoming) => {
                let config_clone = config.clone();
                tokio::spawn(async move {
                    conn::handle_incoming(incoming, config_clone).await;
                });
            }
            None => {
                tracing::info!("Endpoint closed");
                break;
            }
        }
    }

    Ok(())
}

pub async fn run_local_proxy(local_proxy_config: LocalProxyConfig) -> anyhow::Result<()> {
    local_proxy::run_local_proxy(local_proxy_config).await
}

const ALPN_HTTP3: &[u8] = b"\x05http/3";
