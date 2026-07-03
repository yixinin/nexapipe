pub mod local_proxy;

use crate::config::{IrohConfig, LocalProxyConfig, ServerConfig};
use crate::conn;
use crate::health::HealthChecker;
use crate::http;
use crate::log;
use crate::routes::{Route, RouteConfig};
use crate::shutdown::ShutdownSignal;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::client::legacy;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMap, RelayUrl, SecretKey};
use iroh_tickets::Ticket;
use iroh_tickets::endpoint::EndpointTicket;
use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

type HttpClient = legacy::Client<
    hyper_rustls::HttpsConnector<legacy::connect::HttpConnector>,
    http_body_util::Full<bytes::Bytes>,
>;

pub async fn run_proxy(
    routes: Vec<Route>,
    default_backend: String,
    server_config: Option<ServerConfig>,
    iroh_config: Option<IrohConfig>,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    let config = Arc::new(RouteConfig::new(routes, default_backend.clone()));
    let http_client = Arc::new(http::create_http_client());

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
                    tracing::warn!("Failed to parse secret_key from config, generating new one: {}", e);
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

    let ep = builder.bind().await?;

    let node_id = ep.id();
    let node_addr = ep.addr();

    tracing::info!("Iroh proxy endpoint started successfully");
    tracing::info!("Node ID: {}", node_id);
    tracing::info!("Default backend: {}", default_backend);

    if let Some(ref server) = server_config {
        let tls_enabled = server.tls_enabled.unwrap_or(false);
        tracing::info!("Server TLS enabled: {}", tls_enabled);

        if tls_enabled {
            if let (Some(cert_path), Some(key_path)) =
                (server.cert_path.as_ref(), server.key_path.as_ref())
            {
                if fs::metadata(cert_path).is_ok() && fs::metadata(key_path).is_ok() {
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
    println!("Node ID: {}", node_id);
    println!("Ticket (for clients): {}", ticket_str);
    println!("========================================\n");

    tracing::info!("Connection ticket: {}", ticket_str);

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

    if let Some(ref server) = server_config {
        let tls_enabled = server.tls_enabled.unwrap_or(false);
        if tls_enabled {
            if let (Some(cert_path), Some(key_path)) =
                (server.cert_path.as_ref(), server.key_path.as_ref())
            {
                match load_tls_acceptor(cert_path, key_path) {
                    Ok(tls_acceptor) => {
                        let tls_listen_addr = server
                            .tls_listen_addr
                            .clone()
                            .unwrap_or_else(|| "0.0.0.0:8443".to_string());
                        let https_listener = TcpListener::bind(&tls_listen_addr).await?;
                        tracing::info!("HTTPS server listening on: {}", tls_listen_addr);

                        let config_clone = config.clone();
                        let http_client_clone = http_client.clone();
                        let shutdown_signal_clone = shutdown_signal.clone();

                        tokio::spawn(async move {
                            if let Err(e) = start_https_server(
                                https_listener,
                                tls_acceptor,
                                config_clone,
                                http_client_clone,
                                shutdown_signal_clone,
                            )
                            .await
                            {
                                tracing::error!("HTTPS server failed: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to load TLS certificates: {}", e);
                    }
                }
            } else {
                tracing::warn!("TLS enabled but no certificate/key paths provided");
            }
        }
    }

    for route in config.routes().await.into_iter() {
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

    loop {
        tokio::select! {
            incoming = ep.accept() => {
                match incoming {
                    Some(incoming) => {
                        let config_clone = config.clone();
                        let http_client_clone = http_client.clone();
                        tokio::spawn(async move {
                            conn::handle_incoming(incoming, config_clone, http_client_clone).await;
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
                tracing::debug!("New HTTP connection from: {}", addr);

                let config_clone = config.clone();
                let client_clone = client.clone();
                let remote_addr_str = addr.to_string();

                tokio::spawn(async move {
                    let http_builder = Builder::new(hyper_util::rt::TokioExecutor::new());
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        proxy_handler(req, config_clone.clone(), client_clone.clone(), false, remote_addr_str.clone())
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

async fn proxy_handler(
    req: hyper::Request<Incoming>,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
    is_https: bool,
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

    let response = match http::proxy_request(&client, req, config.clone(), is_https).await {
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

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<TlsAcceptor>> {
    let file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("failed to open cert file: {}", e))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse cert file: {}", e))?;

    let file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("failed to open key file: {}", e))?;
    let mut reader = std::io::BufReader::new(file);
    let keys: Vec<PrivatePkcs8KeyDer<'static>> = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse key file: {}", e))?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
    let key = PrivateKeyDer::Pkcs8(key);

    let config = rustls::ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| anyhow::anyhow!("Failed to create TLS config: {}", e))?;

    Ok(Arc::new(TlsAcceptor::from(Arc::new(config))))
}

async fn start_https_server(
    listener: TcpListener,
    tls_acceptor: Arc<TlsAcceptor>,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, addr) = result?;
                tracing::debug!("New HTTPS connection from: {}", addr);

                let tls_acceptor_clone = tls_acceptor.clone();
                let config_clone = config.clone();
                let client_clone = client.clone();
                let remote_addr_str = addr.to_string();

                tokio::spawn(async move {
                    match tls_acceptor_clone.accept(stream).await {
                        Ok(tls_stream) => {
                            let http_builder = Builder::new(hyper_util::rt::TokioExecutor::new());
                            let service = service_fn(move |req: hyper::Request<Incoming>| {
                                proxy_handler(req, config_clone.clone(), client_clone.clone(), true, remote_addr_str.clone())
                            });

                            let io = TokioIo::new(tls_stream);
                            if let Err(e) = http_builder.serve_connection_with_upgrades(io, service).await {
                                tracing::error!("Failed to serve HTTPS connection: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("TLS handshake failed: {}", e);
                        }
                    }
                });
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                if shutdown_signal.is_shutdown_requested() {
                    tracing::info!("Shutdown signal received, stopping HTTPS server");
                    break;
                }
            }
        }
    }
    Ok(())
}

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
