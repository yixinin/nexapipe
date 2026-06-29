pub mod local_proxy;

use crate::config::{IrohConfig, LocalProxyConfig, ServerConfig};
use crate::conn;
use crate::http;
use crate::routes::BackendInfo;
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

    let listen_addr = server_config
        .as_ref()
        .and_then(|s| s.listen_addr.clone())
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let http_listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("HTTP server listening on: {}", listen_addr);

    let config_clone = config.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_http_connections(http_listener, config_clone).await {
            tracing::error!("HTTP server failed: {}", e);
        }
    });

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

async fn handle_http_connections(
    listener: TcpListener,
    config: Arc<RouteConfig>,
) -> anyhow::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::debug!("New HTTP connection from: {}", addr);

                let config_clone = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_http_request(stream, &config_clone).await {
                        tracing::error!("Failed to handle HTTP request from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("Failed to accept HTTP connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_http_websocket(
    mut client_stream: tokio::net::TcpStream,
    req: &::http::Request<()>,
    backend_url: &str,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tracing::debug!(
        "handle_http_websocket entered, method={}, uri={}",
        req.method(),
        req.uri()
    );

    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?;
    let port = url.port_or_known_default().unwrap_or(80);

    tracing::debug!("Connecting to backend {}:{}", host, port);

    let mut backend_stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;

    tracing::debug!("Backend TCP connection established");

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let request_line = format!("{} {} HTTP/1.1\r\n", req.method(), path);

    let mut request_buf = Vec::new();
    request_buf.extend_from_slice(request_line.as_bytes());
    request_buf.extend_from_slice(b"Host: ");
    request_buf.extend_from_slice(host.as_bytes());
    request_buf.extend_from_slice(b"\r\n");

    for (name, value) in req.headers() {
        if name.as_str().to_lowercase() == "host" {
            continue;
        }
        request_buf.extend_from_slice(name.as_str().as_bytes());
        request_buf.extend_from_slice(b": ");
        request_buf.extend_from_slice(value.as_bytes());
        request_buf.extend_from_slice(b"\r\n");
    }
    request_buf.extend_from_slice(b"\r\n");

    tracing::debug!(
        "Sending WebSocket handshake to backend, size={} bytes",
        request_buf.len()
    );

    backend_stream.write_all(&request_buf).await?;

    tracing::debug!("Waiting for backend WebSocket handshake response");

    let mut response_buf = Vec::new();
    let mut line_buf = Vec::new();

    loop {
        let byte = backend_stream.read_u8().await?;
        response_buf.push(byte);
        line_buf.push(byte);

        if line_buf.len() >= 4 {
            let last_four = &line_buf[line_buf.len() - 4..];
            if last_four == b"\r\n\r\n" {
                break;
            }
        }
    }

    tracing::debug!(
        "Received WebSocket handshake response, size={} bytes",
        response_buf.len()
    );

    let response = http::parse_http_response(&response_buf)?;
    if response.status().as_u16() == 101 {
        tracing::debug!("Handshake successful (101), forwarding response to client");

        client_stream.write_all(&response_buf).await?;

        tracing::debug!("Response forwarded to client, entering bidirectional stream mode");

        let (client_read, mut client_write) = tokio::io::split(client_stream);
        let (backend_read, mut backend_write) = tokio::io::split(backend_stream);

        tracing::debug!("Streams split successfully, starting bidirectional forwarding");

        let client_to_backend = async {
            let mut buf = [0u8; 8192];
            let mut client_read = client_read;
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = backend_write.write_all(&buf[..n]).await {
                            tracing::debug!("WebSocket client_to_backend write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("WebSocket client_to_backend read error: {}", e);
                        break;
                    }
                }
            }
        };

        let backend_to_client = async {
            let mut buf = [0u8; 8192];
            let mut backend_read = backend_read;
            loop {
                match backend_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = client_write.write_all(&buf[..n]).await {
                            tracing::debug!("WebSocket backend_to_client write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("WebSocket backend_to_client read error: {}", e);
                        break;
                    }
                }
            }
        };

        tracing::debug!("Entering tokio::select! for bidirectional forwarding");

        tokio::select! {
            _ = client_to_backend => tracing::debug!("client_to_backend branch completed"),
            _ = backend_to_client => tracing::debug!("backend_to_client branch completed"),
        }

        tracing::debug!("WebSocket connection closed normally");
    } else {
        tracing::debug!(
            "HTTP WebSocket handshake failed with backend, status: {}",
            response.status()
        );
        client_stream.write_all(&response_buf).await?;
    }

    Ok(())
}

async fn handle_http_request(
    stream: tokio::net::TcpStream,
    config: &RouteConfig,
) -> anyhow::Result<()> {
    let mut stream = stream;
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    let peer_addr = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;

    tracing::debug!(
        "HTTP connection info - peer: {}, local: {}, bytes_read: {}",
        peer_addr,
        local_addr,
        n
    );

    let request_str = String::from_utf8_lossy(&buf[..n]);
    tracing::debug!("Raw HTTP request:\n{}", request_str);

    let request = http::parse_http_request(&buf[..n])?;

    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h));

    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path());

    let backend_info: BackendInfo = match host {
        Some(h) => config.get_backend(h, path).await,
        None => BackendInfo {
            url: config.default_backend().to_string(),
            verify_cert: true,
        },
    };

    tracing::debug!(
        "HTTP Request: host={:?}, path={} -> backend={}",
        host,
        path,
        backend_info.url
    );

    if http::is_websocket_request(&request) {
        tracing::debug!("HTTP server detected WebSocket request");
        handle_http_websocket(stream, &request, &backend_info.url).await?;
    } else {
        let response =
            http::proxy_to_backend(&request, &backend_info.url, backend_info.verify_cert).await?;

        let mut response_buf = Vec::new();
        let status = response.status();
        let status_text = status.canonical_reason().unwrap_or("Unknown");
        response_buf.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status_text).as_bytes(),
        );

        for (name, value) in response.headers() {
            response_buf.extend_from_slice(name.as_str().as_bytes());
            response_buf.extend_from_slice(b": ");
            response_buf.extend_from_slice(value.as_bytes());
            response_buf.extend_from_slice(b"\r\n");
        }

        response_buf.extend_from_slice(b"\r\n");
        response_buf.extend_from_slice(response.body());

        stream.write_all(&response_buf).await?;
    }

    Ok(())
}

pub async fn run_local_proxy(local_proxy_config: LocalProxyConfig) -> anyhow::Result<()> {
    local_proxy::run_local_proxy(local_proxy_config).await
}

const ALPN_HTTP3: &[u8] = b"\x05http/3";
