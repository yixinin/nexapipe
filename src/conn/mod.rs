use crate::http;
use crate::routes::{BackendInfo, RouteConfig};
use ::http::Request;
use iroh::endpoint::{Connection, Incoming};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn handle_bidi_stream(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    config: &RouteConfig,
) -> anyhow::Result<()> {
    let mut recv = recv;
    let mut buf = Vec::new();
    let mut line_buf = Vec::new();
    let mut temp_byte = [0u8; 1];
    
    loop {
        match recv.read(&mut temp_byte).await {
            Ok(None) => break,
            Ok(Some(1)) => {
                let byte = temp_byte[0];
                buf.push(byte);
                line_buf.push(byte);
                
                if line_buf.len() >= 4 {
                    let last_four = &line_buf[line_buf.len() - 4..];
                    if last_four == b"\r\n\r\n" {
                        break;
                    }
                }
            }
            Ok(Some(_)) => {
                let byte = temp_byte[0];
                buf.push(byte);
            }
            Err(e) => {
                tracing::debug!("Failed to read from iroh stream: {}", e);
                return Err(e.into());
            }
        }
    }

    tracing::debug!(
        "Iroh stream data received - bytes_read: {}",
        buf.len()
    );

    let request_str = String::from_utf8_lossy(&buf);
    tracing::debug!("Raw Iroh request:\n{}", request_str);

    let request = http::parse_http_request(&buf)?;

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
        "Request: host={:?}, path={} -> backend={}, verify_cert={}",
        host,
        path,
        backend_info.url,
        backend_info.verify_cert
    );
    tracing::debug!("Received request: {} {}", request.method(), request.uri());

    if http::is_websocket_request(&request) {
        tracing::debug!("WebSocket request detected");
        handle_websocket_stream(send, recv, &request, &backend_info.url).await?;
    } else {
        let mut send = send;
        let response = http::proxy_to_backend(&request, &backend_info.url, backend_info.verify_cert).await?;
        tracing::debug!("Proxy response status: {}", response.status());
        http::send_response(&mut send, &response).await?;
    }

    Ok(())
}

async fn handle_websocket_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    req: &Request<()>,
    backend_url: &str,
) -> anyhow::Result<()> {
    let url = url::Url::parse(backend_url)
        .map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?;
    let port = url.port_or_known_default().unwrap_or(80);

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

    backend_stream.write_all(&request_buf).await?;

    let mut response_buf = Vec::new();
    let mut line_buf = Vec::new();
    let mut header_done = false;
    
    loop {
        let byte = backend_stream.read_u8().await?;
        response_buf.push(byte);
        line_buf.push(byte);
        
        if line_buf.len() >= 4 {
            let last_four = &line_buf[line_buf.len() - 4..];
            if last_four == b"\r\n\r\n" {
                header_done = true;
                break;
            }
        }
    }

    let response = http::parse_http_response(&response_buf)?;
    if response.status().as_u16() == 101 {
        tracing::debug!("WebSocket handshake successful with backend");
        send.write_all(&response_buf).await?;

        let (backend_read, mut backend_write) = tokio::io::split(backend_stream);

        let iroh_to_backend = async {
            let mut buf = [0u8; 8192];
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) => break,
                    Ok(Some(n)) => {
                        if let Err(e) = backend_write.write_all(&buf[..n]).await {
                            tracing::debug!("WebSocket iroh_to_backend error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("WebSocket iroh_to_backend read error: {}", e);
                        break;
                    }
                }
            }
        };

        let backend_to_iroh = async {
            let mut buf = [0u8; 8192];
            let mut backend_read = backend_read;
            loop {
                match backend_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            tracing::debug!("WebSocket backend_to_iroh error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("WebSocket backend_to_iroh read error: {}", e);
                        break;
                    }
                }
            }
        };

        tokio::select! {
            _ = iroh_to_backend => (),
            _ = backend_to_iroh => (),
        }
    } else {
        tracing::debug!("WebSocket handshake failed with backend, status: {}", response.status());
        send.write_all(&response_buf).await?;
        send.finish()?;
    }

    Ok(())
}

pub async fn handle_connection(conn: Connection, config: Arc<RouteConfig>) {
    let peer_id = conn.remote_id();
    tracing::info!("New connection from peer: {}", peer_id);
    tracing::debug!("Iroh connection info - peer_id: {}", peer_id);

    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let config_clone = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_bidi_stream(send, recv, &config_clone).await {
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

pub async fn handle_incoming(incoming: Incoming, config: Arc<RouteConfig>) {
    match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => {
                tokio::spawn(async move {
                    handle_connection(conn, config).await;
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
