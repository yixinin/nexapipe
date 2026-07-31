use crate::http;
use crate::routes::{BackendInfo, RouteConfig};
use ::http::Request;
use hyper_util::client::legacy;
use iroh::endpoint::{Connection, Incoming};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;

type HttpClient = legacy::Client<
    hyper_rustls::HttpsConnector<legacy::connect::HttpConnector>,
    http_body_util::Full<bytes::Bytes>,
>;

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

pub async fn handle_bidi_stream(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    config: &RouteConfig,
    client: &HttpClient,
) -> anyhow::Result<()> {
    let mut recv = recv;
    let mut buf = Vec::with_capacity(8192);
    let mut read_buf = [0u8; 8192];
    let mut body_data = Vec::new();

    loop {
        match recv.read(&mut read_buf).await {
            Ok(None) => break,
            Ok(Some(n)) => {
                buf.extend_from_slice(&read_buf[..n]);

                if let Some(pos) = find_headers_end(&buf) {
                    let headers_end = pos + 4;
                    if buf.len() > headers_end {
                        body_data.extend_from_slice(&buf[headers_end..]);
                    }
                    buf.truncate(headers_end);
                    break;
                }

                if buf.len() > 64 * 1024 {
                    tracing::warn!("Request headers too large");
                    break;
                }
            }
            Err(e) => {
                tracing::debug!("Failed to read from iroh stream: {}", e);
                return Err(e.into());
            }
        }
    }

    tracing::debug!("Iroh stream data received - bytes_read: {}", buf.len());

    let request_str = String::from_utf8_lossy(&buf);
    tracing::debug!("Raw Iroh request:\n{}", request_str);

    let request = http::parse_http_request_legacy(&buf)?;

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
            url: config.default_backend().await,
            verify_cert: true,
            path_rewrite: None,
            redirect_to_https: false,
            path_pattern: "/".to_string(),
            path_is_prefix: true,
        },
    };

    tracing::debug!(
        "Request: host={:?}, path={} -> backend={}, verify_cert={}",
        host,
        path,
        backend_info.url,
        backend_info.verify_cert
    );
    tracing::debug!("Received request: {} {}", request.method(), request.uri());

    if http::is_websocket_request_static(&request) {
        tracing::debug!("WebSocket request detected");
        handle_websocket_stream(send, recv, &request, &backend_info.url).await?;
    } else {
        let mut send = send;
        http::proxy_to_backend_streaming(client, &request, &backend_info.url, body_data, &mut send, &mut recv)
            .await?;
    }

    Ok(())
}

async fn handle_websocket_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    req: &Request<()>,
    backend_url: &str,
) -> anyhow::Result<()> {
    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let original_host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.to_string())
        .unwrap_or_else(|| host.to_string());

    let mut backend_stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let request_line = format!("{} {} HTTP/1.1\r\n", req.method(), path);

    let mut request_buf = Vec::new();
    request_buf.extend_from_slice(request_line.as_bytes());
    request_buf.extend_from_slice(b"Host: ");
    request_buf.extend_from_slice(original_host.as_bytes());
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

    backend_stream.write_all(&request_buf).await?;

    let mut response_buf = Vec::with_capacity(8192);
    let mut trailing_ws_data = Vec::new();
    let mut read_buf = [0u8; 8192];

    loop {
        match backend_stream.read(&mut read_buf).await {
            Ok(0) => break,
            Ok(n) => {
                response_buf.extend_from_slice(&read_buf[..n]);

                if let Some(pos) = find_headers_end(&response_buf) {
                    let headers_end = pos + 4;
                    if response_buf.len() > headers_end {
                        trailing_ws_data.extend_from_slice(&response_buf[headers_end..]);
                    }
                    response_buf.truncate(headers_end);
                    break;
                }

                if response_buf.len() > 64 * 1024 {
                    tracing::warn!("WebSocket handshake response too large");
                    break;
                }
            }
            Err(e) => {
                tracing::debug!("Failed to read from backend stream: {}", e);
                return Err(e.into());
            }
        }
    }

    let response = http::parse_http_response_legacy(&response_buf)?;
    if response.status().as_u16() == 101 {
        tracing::debug!("WebSocket handshake successful with backend");
        send.write_all(&response_buf).await?;
        if !trailing_ws_data.is_empty() {
            tracing::debug!(
                "WebSocket handshake response contained {} trailing bytes",
                trailing_ws_data.len()
            );
            send.write_all(&trailing_ws_data).await?;
        }

        let (backend_read, mut backend_write) = tokio::io::split(backend_stream);

        let iroh_to_backend = async {
            let mut buf = [0u8; 8192];
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) => {
                        tracing::debug!("WebSocket iroh stream finished");
                        return "iroh_finished";
                    }
                    Ok(Some(n)) => {
                        if let Err(e) = backend_write.write_all(&buf[..n]).await {
                            tracing::debug!("WebSocket iroh_to_backend error: {}", e);
                            return "backend_write_error";
                        }
                    }
                    Err(e) => {
                        tracing::debug!("WebSocket iroh_to_backend read error: {}", e);
                        return "iroh_read_error";
                    }
                }
            }
        };

        let backend_to_iroh = async {
            let mut buf = [0u8; 8192];
            let mut backend_read = backend_read;
            loop {
                match backend_read.read(&mut buf).await {
                    Ok(0) => {
                        tracing::debug!("WebSocket backend stream closed");
                        return "backend_finished";
                    }
                    Ok(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            tracing::debug!("WebSocket backend_to_iroh error: {}", e);
                            return "iroh_write_error";
                        }
                    }
                    Err(e) => {
                        tracing::debug!("WebSocket backend_to_iroh read error: {}", e);
                        return "backend_read_error";
                    }
                }
            }
        };

        let (closed_direction, close_reason) = tokio::select! {
            reason = iroh_to_backend => ("iroh_to_backend", reason),
            reason = backend_to_iroh => ("backend_to_iroh", reason),
        };
        tracing::debug!(
            "WebSocket tunnel closed first by {}, reason: {}",
            closed_direction,
            close_reason
        );
    } else {
        tracing::debug!(
            "WebSocket handshake failed with backend, status: {}",
            response.status()
        );
        send.write_all(&response_buf).await?;
        send.finish()?;
    }

    Ok(())
}

fn get_connection_type(path: &iroh::endpoint::Path<'_>) -> &'static str {
    if path.is_ip() {
        "Direct (直连)"
    } else if path.is_relay() {
        "Relay (中转)"
    } else {
        "Unknown"
    }
}

pub async fn handle_connection(
    conn: Connection,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
) {
    let peer_id = conn.remote_id();
    tracing::info!("New connection from peer: {}", peer_id);
    tracing::debug!("Iroh connection info - peer_id: {}", peer_id);

    let paths = conn.paths();
    if let Some(selected_path) = paths.iter().find(|p| p.is_selected()) {
        tracing::info!("Initial connection type: {}", get_connection_type(&selected_path));
    } else {
        tracing::info!("Initial connection type: Unknown (no selected path)");
    }

    let conn_clone = conn.clone();
    tokio::spawn(async move {
        let mut path_events = conn_clone.path_events();
        while let Some(event) = path_events.next().await {
            match event {
                iroh::endpoint::PathEvent::Selected { remote_addr, .. } => {
                    if remote_addr.is_ip() {
                        tracing::info!("Connection upgraded: Relay → Direct (直连)");
                    } else if remote_addr.is_relay() {
                        tracing::info!("Connection downgraded: Direct → Relay (中转)");
                    }
                }
                iroh::endpoint::PathEvent::Opened { remote_addr, .. } => {
                    if remote_addr.is_ip() {
                        tracing::info!("Direct path opened (waiting for selection)");
                    } else if remote_addr.is_relay() {
                        tracing::info!("Relay path opened");
                    }
                }
                _ => {}
            }
        }
    });

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let config_clone = config.clone();
                let client_clone = client.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_bidi_stream(send, recv, &config_clone, &client_clone).await
                    {
                        tracing::error!("Failed to handle stream from {}: {}", peer_id, e);
                    }
                });
            }
            Err(e) => {
                if e.to_string().contains("closed by peer") {
                    tracing::debug!("Connection {} closed by peer", peer_id);
                } else {
                    tracing::warn!("Connection {} stream accept error: {}", peer_id, e);
                }
                break;
            }
        }
    }

    tracing::info!("Connection closed for peer: {}", peer_id);
}

pub async fn handle_incoming(
    incoming: Incoming,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
) {
    match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => {
                tokio::spawn(async move {
                    handle_connection(conn, config, client).await;
                });
            }
            Err(e) => {
                tracing::error!("Failed to complete connection: {}", e);
            }
        },
        Err(e) => {
            tracing::error!("Failed to accept incoming connection: {}", e);
        }
    }
}
