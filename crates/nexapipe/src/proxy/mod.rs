pub mod local_proxy;

use crate::auth::AuthConfig;
use crate::config::{IrohConfig, LocalProxyConfig, RouteMode, ServerConfig};
use crate::config_watcher::ConfigWatcher;
use crate::conn;
use crate::health::HealthChecker;
use crate::http;
use crate::log;
use crate::passthrough;
use crate::routes::RouteConfig;
use crate::shutdown::ShutdownSignal;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::client::legacy;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMap, RelayUrl, SecretKey};
use iroh_tickets::Ticket;
use iroh_tickets::endpoint::EndpointTicket;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Shared by the startup path and the config watcher, which spawns checkers for
/// routes that appear in a reload.
pub type HttpClient = legacy::Client<legacy::connect::HttpConnector, http_body_util::Full<bytes::Bytes>>;

/// One background `GET /health` probe per `http` route.
///
/// Called again after a reload, so it only starts checkers for routes it has not
/// seen before: a probe runs until the process ends, and re-starting one per
/// reload would pile up tasks that all poke the same backend. The trade-off is
/// that a route deleted from the config keeps being probed — harmless, because
/// its pool is no longer reachable from the routing table, but it does keep
/// logging if that backend really is gone.
pub async fn spawn_health_checks(
    config: &Arc<RouteConfig>,
    http_client: &Arc<HttpClient>,
    seen: &tokio::sync::Mutex<std::collections::HashSet<String>>,
) {
    let mut seen = seen.lock().await;

    for route in config.routes().await {
        // Only an http:// backend answers `GET /health`. A passthrough backend is
        // a TLS listener and an L4 backend is whatever the route points at — a
        // database, a TURN server, an SSH daemon. Probing either would fail, mark
        // the backend down, and the pool would then quietly fall back to its first
        // entry. There is nothing to probe without speaking the protocol, so the
        // pool is left alone; a dead backend shows up as a connect error when a
        // flow arrives.
        // A route serving `http` *and* something else is still probed: the pool
        // is shared, so its health is what the other modes dial into as well.
        if !route.serves(RouteMode::Http) {
            tracing::info!(
                "Route {}: modes={:?}, skipping the HTTP health check",
                route.host_pattern(),
                route.modes()
            );
            continue;
        }

        let key = format!(
            "{}|{:?}",
            route.host_pattern(),
            route.backend_pool().backends().await
        );
        if !seen.insert(key) {
            continue;
        }

        let backend_pool = route.backend_pool().clone();
        let http_client_clone = http_client.clone();
        let health_checker = HealthChecker::new(
            backend_pool,
            http_client_clone,
            tokio::time::Duration::from_secs(10),
            tokio::time::Duration::from_secs(5),
            3,
            "/health",
        );
        tokio::spawn(async move {
            health_checker.run().await;
        });
    }
}

/// How long the plaintext listener waits for a first byte before handing the
/// connection to the HTTP server. Long enough for a TLS `ClientHello` to
/// arrive, short enough not to park the task.
const FIRST_BYTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn run_proxy(
    config: Arc<RouteConfig>,
    server_config: Option<ServerConfig>,
    iroh_config: Option<IrohConfig>,
    config_path: &str,
    shutdown_signal: Arc<ShutdownSignal>,
    auth_config: Option<AuthConfig>,
) -> anyhow::Result<()> {
    let http_client = Arc::new(http::create_http_client());

    let health_seen = Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    spawn_health_checks(&config, &http_client, &health_seen).await;

    // The watcher needs both to apply a reload: it rebuilds the routes and
    // restarts whatever health checks the new routes need.
    let config_watcher = Arc::new(ConfigWatcher::new(
        config_path.to_string(),
        config.clone(),
        http_client.clone(),
        health_seen,
    ));
    tokio::spawn({
        let config_watcher_clone = config_watcher.clone();
        async move {
            config_watcher_clone.start_watch().await;
        }
    });
    tracing::info!("Config watcher started, monitoring: {}", config_path);

    // 2FA state: the shared config plus the file its lockout counters persist to.
    let auth_state = auth_config.map(|cfg| conn::AuthState::new(cfg, config_path));

    let mut builder = Endpoint::builder(presets::N0).alpns(vec![ALPN_NEXAPIPE.to_vec()]);

    if let Some(iroh_cfg) = iroh_config {
        // Use configured secret key for stable endpoint identity
        if let Some(secret_key_str) = &iroh_cfg.secret_key {
            match secret_key_str.parse::<SecretKey>() {
                Ok(secret_key) => {
                    builder = builder.secret_key(secret_key);
                    tracing::info!("Using configured secret key for stable endpoint identity");
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse secret_key from config, generating new one: {}",
                        e
                    );
                }
            }
        }

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

    // QUIC transport tuning: one inner TCP connection maps to one QUIC bi-stream, so the
    // per-stream receive window sets the throughput ceiling of every proxied connection.
    // See nexapipe_client::transport for the numbers and the override variables.
    let transport_tuning = nexapipe_client::transport::TransportTuning::from_env();
    tracing::info!("QUIC transport tuning: {}", transport_tuning.describe());
    let builder = builder.transport_config(transport_tuning.transport_config());

    let ep = builder.bind().await?;

    let node_id = ep.id();
    let node_addr = ep.addr();

    tracing::info!("Iroh proxy endpoint started successfully");
    tracing::info!("Node ID: {}", node_id);

    for (i, route) in config.routes().await.into_iter().enumerate() {
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
    println!("Node ID (stable, for server_node_id): {}", node_id);
    println!("Ticket (for clients): {}", ticket_str);
    println!("========================================");
    println!("To use stable connection, add to [local_proxy] in config.toml:");
    println!("server_node_id = \"{}\"", node_id);
    println!("========================================\n");

    tracing::info!("Connection ticket: {}", ticket_str);
    tracing::info!("Node ID (for server_node_id config): {}", node_id);

    let listen_addr = server_config
        .as_ref()
        .and_then(|s| s.listen_addr.clone())
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let http_listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("HTTP server listening on: {}", listen_addr);

    let config_clone = config.clone();
    let http_client_clone = http_client.clone();
    let shutdown_signal_clone = shutdown_signal.clone();

    tokio::spawn(async move {
        if let Err(e) = start_http_server(
            http_listener,
            config_clone,
            http_client_clone,
            shutdown_signal_clone,
        )
        .await
        {
            tracing::error!("HTTP server failed: {}", e);
        }
    });

    loop {
        tokio::select! {
            incoming = ep.accept() => {
                match incoming {
                    Some(incoming) => {
                        let config_clone = config.clone();
                        let http_client_clone = http_client.clone();
                        let auth_state_clone = auth_state.clone();
                        tokio::spawn(async move {
                            conn::handle_incoming(incoming, config_clone, http_client_clone, auth_state_clone).await;
                        });
                    }
                    None => {
                        tracing::info!("Endpoint closed");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                if shutdown_signal.is_shutdown_requested() {
                    tracing::info!("Shutdown signal received, stopping proxy");
                    break;
                }
            }
        }
    }

    tracing::info!("Waiting for existing connections to close...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    Ok(())
}

async fn start_http_server(
    listener: TcpListener,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, addr) = result?;
                tracing::debug!("New connection on the plaintext listener from: {}", addr);

                let config_clone = config.clone();
                let client_clone = client.clone();
                let remote_addr_str = addr.to_string();

                tokio::spawn(async move {
                    // The listener speaks HTTP, but a client may also open a
                    // TLS session straight at it. One peeked byte tells the two
                    // apart — a request line can never start with 0x16 — and a
                    // TLS session goes to the passthrough path, since this
                    // process has no key material and never decrypts anything.
                    if is_tls_connection(&stream).await {
                        tracing::debug!("TLS session on the plaintext listener from: {}", remote_addr_str);
                        if let Err(e) =
                            passthrough::handle_tcp_stream(stream, Vec::new(), &config_clone).await
                        {
                            tracing::error!("TLS passthrough failed for {}: {}", remote_addr_str, e);
                        }
                        return;
                    }

                    let http_builder = Builder::new(hyper_util::rt::TokioExecutor::new());
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        proxy_handler(req, config_clone.clone(), client_clone.clone(), remote_addr_str.clone())
                    });

                    let io = TokioIo::new(stream);
                    if let Err(e) = http_builder.serve_connection_with_upgrades(io, service).await {
                        tracing::error!("Failed to serve connection: {}", e);
                    }
                });
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                if shutdown_signal.is_shutdown_requested() {
                    tracing::info!("Shutdown signal received, stopping HTTP server");
                    break;
                }
            }
        }
    }
    Ok(())
}

/// True when the peer opened a TLS session rather than sending a request.
async fn is_tls_connection(stream: &tokio::net::TcpStream) -> bool {
    let mut first = [0u8; 1];
    match tokio::time::timeout(FIRST_BYTE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(1)) => passthrough::is_tls_handshake(first[0]),
        // EOF, error, or a peer that never sends anything: hand it to the HTTP
        // server, which owns read timeouts and error responses.
        _ => false,
    }
}

async fn proxy_handler(
    req: hyper::Request<Incoming>,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
    remote_addr: String,
) -> Result<
    hyper::Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>>,
    anyhow::Error,
> {
    let start = std::time::Instant::now();
    let method = req.method().to_string();
    let uri = req.uri().to_string();

    if http::is_websocket_request(&req) {
        tracing::debug!("WebSocket request detected");
        return Ok(http::create_error_response(
            hyper::StatusCode::UPGRADE_REQUIRED,
            "WebSocket not supported via HTTP server",
        ));
    }

    let response = match http::proxy_request(&client, req, config.clone()).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Proxy request failed: {}", e);
            let duration = start.elapsed();
            log::log_access(
                &remote_addr,
                &method,
                &uri,
                hyper::StatusCode::BAD_GATEWAY.as_u16(),
                duration.as_millis() as u64,
                0,
            );
            return Ok(http::create_error_response(
                hyper::StatusCode::BAD_GATEWAY,
                &format!("Proxy error: {}", e),
            ));
        }
    };

    let duration = start.elapsed();
    let status = response.status().as_u16();
    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    log::log_access(
        &remote_addr,
        &method,
        &uri,
        status,
        duration.as_millis() as u64,
        content_length,
    );

    Ok(response)
}

pub async fn run_local_proxy(
    local_proxy_config: LocalProxyConfig,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    local_proxy::run_local_proxy(local_proxy_config, shutdown_signal).await
}

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
