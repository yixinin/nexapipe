use crate::config::LocalProxyConfig;
use crate::http;
use crate::shutdown::ShutdownSignal;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use iroh_tickets::endpoint::EndpointTicket;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
const MAX_RESPONSE_SIZE: usize = 1024 * 1024 * 10; // 10MB

pub async fn run_local_proxy(
    config: LocalProxyConfig,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr.clone();
    let proxy_domains = Arc::new(config.proxy_domains);
    let server_ticket = config.server_ticket;

    tracing::info!("Starting local proxy on: {}", listen_addr);
    tracing::info!("Proxy domains: {:?}", proxy_domains);

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("Local proxy listener bound successfully");

    let ep = Endpoint::builder(presets::N0).bind().await?;
    let node_id = ep.id();
    tracing::info!("Iroh client endpoint started, node ID: {}", node_id);

    let ticket_str = if let Some(ticket) = server_ticket {
        ticket
    } else {
        println!("Enter server ticket:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let ticket: EndpointTicket = ticket_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse ticket: {}", e))?;
    let endpoint_addr: EndpointAddr = ticket.into();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        tracing::debug!("New connection from: {}", addr);

                        let proxy_domains_clone = proxy_domains.clone();
                        let ep_clone = ep.clone();
                        let endpoint_addr_clone = endpoint_addr.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_local_connection(
                                stream,
                                proxy_domains_clone,
                                ep_clone,
                                endpoint_addr_clone,
                            )
                            .await
                            {
                                tracing::error!("Failed to handle local connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                if shutdown_signal.is_shutdown_requested() {
                    tracing::info!("Shutdown signal received, stopping local proxy");
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn handle_local_connection(
    mut stream: tokio::net::TcpStream,
    proxy_domains: Arc<Vec<String>>,
    ep: Endpoint,
    endpoint_addr: EndpointAddr,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buf[..n]);
    tracing::debug!("Request: {}", request_str);

    let request = match http::parse_http_request_legacy(&buf[..n]) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!("Failed to parse HTTP request: {}", e);
            return Ok(());
        }
    };

    // Handle CONNECT method for HTTP tunneling (used by WebSocket)
    if request.method().as_str() == "CONNECT" {
        let uri = request.uri().to_string();
        let host_port = uri.split(':').next().unwrap_or(&uri);
        let host = host_port.to_string();

        // Check if this domain should be proxied
        if !should_proxy_domain(&host, &proxy_domains) {
            tracing::debug!("CONNECT target {} not in proxy domains, skipping", host);
            return Ok(());
        }

        tracing::info!("Establishing CONNECT tunnel for: {}", host);

        // Send 200 Connection Established response to client
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Establish bidirectional Iroh stream for tunneling
        let conn = ep.connect(endpoint_addr, ALPN_NEXAPIPE).await?;
        let (send, recv) = conn.open_bi().await?;

        // Forward data bidirectionally through the tunnel
        handle_connect_tunnel(stream, send, recv).await?;
        return Ok(());
    }

    let mut target_host = None;
    for header in request.headers().get_all("host") {
        if let Ok(h) = header.to_str() {
            let h = h.split(':').next().unwrap_or(h);
            if should_proxy_domain(&h, &proxy_domains) {
                target_host = Some(h.to_string());
                break;
            }
        }
    }

    if target_host.is_none() {
        tracing::debug!("No matching host in proxy domains, skipping");
        return Ok(());
    }

    let host = target_host.unwrap();
    tracing::info!("Proxying request for host: {}", host);

    let conn = ep.connect(endpoint_addr, ALPN_NEXAPIPE).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    let mut modified_request = Vec::with_capacity(n);
    let request_str = String::from_utf8_lossy(&buf[..n]);
    let mut host_replaced = false;

    for line in request_str.lines() {
        if line.to_lowercase().starts_with("host:") {
            if !host_replaced {
                modified_request.extend_from_slice(format!("Host: {}\r\n", host).as_bytes());
                host_replaced = true;
            }
        } else {
            modified_request.extend_from_slice(line.as_bytes());
            modified_request.extend_from_slice(b"\r\n");
        }
    }

    if http::is_websocket_request_static(&request) {
        tracing::debug!("WebSocket request detected, handling bidirectional stream");
        handle_local_websocket(stream, send, recv, &modified_request).await?;
    } else {
        send.write_all(&modified_request).await?;
        send.finish()?;
        let response = recv.read_to_end(MAX_RESPONSE_SIZE).await?;
        stream.write_all(&response).await?;
    }

    Ok(())
}

async fn handle_local_websocket(
    mut client_stream: tokio::net::TcpStream,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    initial_request: &[u8],
) -> anyhow::Result<()> {
    send.write_all(initial_request).await?;

    let (client_read, mut client_write) = tokio::io::split(client_stream);

    let client_to_iroh = async {
        let mut buf = [0u8; 8192];
        let mut client_read = client_read;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        tracing::debug!("WebSocket client_to_iroh error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("WebSocket client_to_iroh read error: {}", e);
                    break;
                }
            }
        }
    };

    let iroh_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        tracing::debug!("WebSocket iroh_to_client error: {}", e);
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        tracing::debug!("WebSocket iroh_to_client flush error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("WebSocket iroh_to_client read error: {}", e);
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = client_to_iroh => (),
        _ = iroh_to_client => (),
    }

    Ok(())
}

async fn handle_connect_tunnel(
    client_stream: tokio::net::TcpStream,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
) -> anyhow::Result<()> {
    let (client_read, mut client_write) = tokio::io::split(client_stream);

    let client_to_iroh = async {
        let mut buf = [0u8; 8192];
        let mut client_read = client_read;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        tracing::debug!("Tunnel client_to_iroh write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Tunnel client_to_iroh read error: {}", e);
                    break;
                }
            }
        }
    };

    let iroh_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        tracing::debug!("Tunnel iroh_to_client write error: {}", e);
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        tracing::debug!("Tunnel iroh_to_client flush error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Tunnel iroh_to_client read error: {}", e);
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = client_to_iroh => (),
        _ = iroh_to_client => (),
    }

    tracing::debug!("CONNECT tunnel closed");
    Ok(())
}

fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    let host_lower = host.to_lowercase();
    for domain in proxy_domains {
        if domain.starts_with('*') {
            let suffix = &domain[1..];
            if host_lower.ends_with(suffix) {
                return true;
            }
        } else if host_lower == domain.to_lowercase() {
            return true;
        }
    }
    false
}
