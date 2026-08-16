use crate::auth::{AuthConfig, AuthMessage, TotpValidator};
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
                    Ok(None) => return "iroh_finished",
                    Ok(Some(n)) => {
                        if let Err(e) = backend_write.write_all(&buf[..n]).await {
                            return "backend_write_error";
                        }
                    }
                    Err(_) => return "iroh_read_error",
                }
            }
        };

        let backend_to_iroh = async {
            let mut buf = [0u8; 8192];
            let mut backend_read = backend_read;
            loop {
                match backend_read.read(&mut buf).await {
                    Ok(0) => return "backend_finished",
                    Ok(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            return "iroh_write_error";
                        }
                    }
                    Err(_) => return "backend_read_error",
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
        "Direct"
    } else if path.is_relay() {
        "Relay"
    } else {
        "Unknown"
    }
}

/// Perform 2FA authentication handshake with a client.
///
/// Protocol:
/// 1. Receive AUTH_START from client
/// 2. Send AUTH_CHALLENGE with nonce
/// 3. Receive AUTH_RESPONSE with TOTP code
/// 4. Validate and send AUTH_OK or AUTH_FAILED
async fn perform_authentication(
    conn: &Connection,
    config: &AuthConfig,
) -> Result<String, anyhow::Error> {
    let (mut send, mut recv) = conn.accept_bi().await
        .map_err(|e| anyhow::anyhow!("Failed to open auth stream: {}", e))?;

    // Step 1: Receive AUTH_START
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await
        .map_err(|e| anyhow::anyhow!("Failed to read AUTH_START length: {}", e))?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf).await
        .map_err(|e| anyhow::anyhow!("Failed to read AUTH_START message: {}", e))?;

    let start_msg = AuthMessage::from_bytes(&msg_buf)
        .map_err(|e| anyhow::anyhow!("Failed to parse AUTH_START: {}", e))?;

    let client_id = match start_msg {
        AuthMessage::Start { client_id, .. } => client_id,
        _ => return Err(anyhow::anyhow!("Expected AUTH_START message")),
    };

    // Step 2: Send AUTH_CHALLENGE
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let challenge_msg = AuthMessage::Challenge { nonce };

    let challenge_bytes = challenge_msg.to_bytes()
        .map_err(|e| anyhow::anyhow!("Failed to serialize challenge: {}", e))?;
    let len = challenge_bytes.len() as u32;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(&challenge_bytes).await?;

    // Step 3: Receive AUTH_RESPONSE
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await
        .map_err(|e| anyhow::anyhow!("Failed to read AUTH_RESPONSE length: {}", e))?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf).await
        .map_err(|e| anyhow::anyhow!("Failed to read AUTH_RESPONSE message: {}", e))?;

    let response_msg = AuthMessage::from_bytes(&msg_buf)
        .map_err(|e| anyhow::anyhow!("Failed to parse AUTH_RESPONSE: {}", e))?;

    let (resp_client_id, _timestamp, totp_code) = match response_msg {
        AuthMessage::Response { client_id, timestamp, totp_code } => {
            (client_id, timestamp, totp_code)
        }
        _ => return Err(anyhow::anyhow!("Expected AUTH_RESPONSE message")),
    };

    if resp_client_id != client_id {
        return Err(anyhow::anyhow!("Client ID mismatch in AUTH_RESPONSE"));
    }

    // Step 4: Validate TOTP code
    let validator = TotpValidator::new(config.clone());
    let is_valid = validator.validate(&client_id, &totp_code).unwrap_or(false);

    let result_msg = if is_valid {
        AuthMessage::Ok
    } else {
        AuthMessage::Failed {
            reason: "Invalid TOTP code".to_string(),
        }
    };

    let result_bytes = result_msg.to_bytes()
        .map_err(|e| anyhow::anyhow!("Failed to serialize auth result: {}", e))?;
    let len = result_bytes.len() as u32;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(&result_bytes).await?;
    send.finish()
        .map_err(|e| anyhow::anyhow!("Failed to finish auth stream: {}", e))?;

    if is_valid {
        Ok(client_id)
    } else {
        Err(anyhow::anyhow!("Invalid TOTP code for client '{}'", client_id))
    }
}

pub async fn handle_connection(
    conn: Connection,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
    auth_config: Option<Arc<tokio::sync::RwLock<AuthConfig>>>,
) {
    let peer_id = conn.remote_id();
    tracing::info!("New connection from peer: {}", peer_id);

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
                        tracing::info!("Connection upgraded: Relay -> Direct");
                    } else if remote_addr.is_relay() {
                        tracing::info!("Connection downgraded: Direct -> Relay");
                    }
                }
                _ => {}
            }
        }
    });

    // ===== 2FA Authentication Handshake =====
    if let Some(auth_cfg) = &auth_config {
        let cfg = auth_cfg.read().await;
        if cfg.enabled {
            match perform_authentication(&conn, &cfg).await {
                Ok(client_id) => {
                    tracing::info!("Client '{}' authenticated successfully from {}", client_id, peer_id);
                }
                Err(e) => {
                    tracing::warn!("Authentication failed for {}: {}", peer_id, e);
                    conn.close(0u32.into(), b"Authentication failed");
                    return;
                }
            }
        }
    }
    // ===== Authentication Complete =====

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
    auth_config: Option<Arc<tokio::sync::RwLock<AuthConfig>>>,
) {
    match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => {
                tokio::spawn(async move {
                    handle_connection(conn, config, client, auth_config).await;
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
