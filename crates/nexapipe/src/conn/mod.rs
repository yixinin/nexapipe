use crate::auth::{AuthConfig, AuthError, AuthMessage, TotpValidator};
use crate::config_watcher::save_auth_state;
use crate::http;
use crate::l4;
use crate::passthrough;
use crate::routes::{BackendInfo, RouteConfig};
use ::http::Request;
use hyper_util::client::legacy;
use iroh::endpoint::{Connection, Incoming};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;

type HttpClient = legacy::Client<
    legacy::connect::HttpConnector,
    http_body_util::Full<bytes::Bytes>,
>;

/// How long the server waits for the client to open the 2FA handshake stream.
///
/// A client that has credentials sends AUTH_START right after the QUIC
/// handshake finishes, so this only has to cover one round trip. Without it a
/// client that never authenticates — one with no 2FA configured, which happily
/// completes the QUIC handshake and then sends nothing — keeps the connection
/// and the task serving it alive until the peer itself goes away.
const AUTH_HANDSHAKE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(2);

/// The largest AUTH_* message the server accepts.
///
/// The length prefix is the first four bytes of whatever stream arrives first,
/// so it is attacker- and bug-controlled: a client that opens a data stream
/// instead of the auth stream would otherwise make the server allocate up to
/// 4 GiB before reading anything.
const MAX_AUTH_MESSAGE: usize = 64 * 1024;

/// Application error codes the server closes a connection with when 2FA fails.
///
/// These travel in the CONNECTION_CLOSE frame, so a client can read them from
/// its `close_reason()` and tell "you never authenticated" apart from "your code
/// was rejected" — the difference between a misconfigured client and a wrong
/// TOTP code. Keep in sync with `AUTH_REQUIRED_CLOSE_CODE` in
/// `crates/nexapipe-client/src/connection_pool.rs`.
mod auth_close_code {
    /// No AUTH_START arrived within the handshake deadline: the server requires
    /// 2FA the client did not perform.
    pub const REQUIRED: u32 = 2;
    /// The handshake ran, but the client is unknown or its code was rejected.
    pub const REJECTED: u32 = 3;
}

/// The live 2FA state a connection authenticates against.
///
/// The config is shared: every connection reads it to validate, and the ones
/// that fail write their lockout counters back into it. The path is where
/// those counters are persisted, so a lockout survives a restart.
#[derive(Clone)]
pub struct AuthState {
    config: Arc<tokio::sync::RwLock<AuthConfig>>,
    path: String,
}

impl AuthState {
    /// Wraps a freshly loaded config together with the file it came from.
    pub fn new(config: AuthConfig, path: impl Into<String>) -> Self {
        Self {
            config: Arc::new(tokio::sync::RwLock::new(config)),
            path: path.into(),
        }
    }

    /// The shared config to validate against.
    pub fn config(&self) -> &Arc<tokio::sync::RwLock<AuthConfig>> {
        &self.config
    }

    /// The config file the runtime counters are persisted to.
    pub fn path(&self) -> &str {
        &self.path
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

pub async fn handle_bidi_stream(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    config: &RouteConfig,
    client: &HttpClient,
    limiter: &Arc<l4::FlowLimiter>,
    peer: &str,
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

                // An L4 tunnel says so in its first byte, so it is recognised
                // rather than sniffed. This has to happen before the HTTP header
                // loop below: a preface is not a request line, and the client may
                // send its first payload in the same segment, which `buf` already
                // holds and must hand over intact.
                if buf.first().is_some_and(|b| l4::is_l4_stream(*b)) {
                    return l4::handle_iroh_stream(send, recv, buf, config, limiter, peer).await;
                }

                // TLS is terminated by the backend, so a ClientHello is not a
                // request: hand the raw bytes (and both halves of the stream)
                // to the passthrough path, which routes on SNI.
                if buf.first().is_some_and(|b| passthrough::is_tls_handshake(*b)) {
                    return passthrough::handle_iroh_stream(send, recv, buf, config).await;
                }

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

    let backend_info: Option<BackendInfo> = match host {
        Some(h) => config.get_backend(h, path).await,
        None => config.default_backend().await.map(|url| BackendInfo {
            url,
            path_rewrite: None,
            path_pattern: "/".to_string(),
            path_is_prefix: true,
        }),
    };

    let Some(backend_info) = backend_info else {
        // Nothing serves this host and there is no default backend. A 404 the
        // client can read beats closing the stream mid-request.
        tracing::warn!(
            "No route for host={:?} and no default_backend configured, answering 404",
            host
        );
        let mut send = send;
        let _ = send
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        let _ = send.finish();
        return Ok(());
    };

    tracing::debug!(
        "Request: host={:?}, path={} -> backend={}",
        host,
        path,
        backend_info.url
    );
    tracing::debug!("Received request: {} {}", request.method(), request.uri());

    if http::is_websocket_request_static(&request) {
        tracing::debug!("WebSocket request detected");
        handle_websocket_stream(send, recv, &request, &backend_info.url).await?;
    } else {
        let mut send = send;
        http::proxy_to_backend_streaming(
            client,
            &request,
            &backend_info.url,
            body_data,
            &mut send,
            &mut recv,
        )
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
                            tracing::debug!("WebSocket backend write failed: {}", e);
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
                            tracing::debug!("WebSocket iroh write failed: {}", e);
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

/// Why a 2FA handshake did not produce an authenticated client.
///
/// The difference is what the server closes the connection with, and the client
/// can read it back: [`AuthFailure::NotStarted`] means the client does not know
/// 2FA is required — it never opened the auth stream, so the close is the only
/// way it can ever find out — while [`AuthFailure::Rejected`] means it did
/// authenticate and the credentials were refused.
enum AuthFailure {
    /// No AUTH_START arrived, or the handshake could not be carried out at all.
    NotStarted(String),
    /// The handshake ran and the credentials were refused.
    Rejected(String),
}

/// Perform 2FA authentication handshake with a client.
///
/// Protocol:
/// 1. Receive AUTH_START from client
/// 2. Send AUTH_CHALLENGE with nonce
/// 3. Receive AUTH_RESPONSE with TOTP code and an HMAC over the nonce
/// 4. Validate and send AUTH_OK or AUTH_FAILED
///
/// The caller bounds this with a deadline, so every read in here has to be
/// cancel-safe: [`read_auth_message`] loops over `RecvStream::read` instead of
/// using `read_exact`.
async fn perform_authentication(
    conn: &Connection,
    auth: &AuthState,
    peer: &str,
) -> Result<String, AuthFailure> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| AuthFailure::NotStarted(format!("failed to open auth stream: {}", e)))?;

    // Step 1: Receive AUTH_START. A client that is not doing 2FA opens its
    // first data stream here instead, which does not parse as AUTH_START — that
    // is a refusal, not a parse error worth distinguishing in the log.
    let start_bytes = read_auth_message(&mut recv)
        .await
        .map_err(AuthFailure::NotStarted)?;

    let start_msg = AuthMessage::from_bytes(&start_bytes).map_err(|_| {
        AuthFailure::NotStarted("the first stream is not an AUTH_START".to_string())
    })?;

    let client_id = match start_msg {
        AuthMessage::Start { client_id, .. } => client_id,
        _ => {
            return Err(AuthFailure::NotStarted(
                "expected AUTH_START message".to_string(),
            ));
        }
    };

    // Step 2: Send AUTH_CHALLENGE
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let challenge_msg = AuthMessage::Challenge {
        nonce: nonce.clone(),
    };

    let challenge_bytes = challenge_msg
        .to_bytes()
        .map_err(|e| AuthFailure::NotStarted(format!("failed to serialize challenge: {}", e)))?;
    let len = challenge_bytes.len() as u32;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| AuthFailure::NotStarted(format!("failed to send challenge: {}", e)))?;
    send.write_all(&challenge_bytes)
        .await
        .map_err(|e| AuthFailure::NotStarted(format!("failed to send challenge: {}", e)))?;

    // Step 3: Receive AUTH_RESPONSE
    let response_bytes = read_auth_message(&mut recv)
        .await
        .map_err(AuthFailure::NotStarted)?;

    let response_msg = AuthMessage::from_bytes(&response_bytes)
        .map_err(|_| AuthFailure::NotStarted("expected AUTH_RESPONSE message".to_string()))?;

    let (resp_client_id, resp_timestamp, signature, totp_code) = match response_msg {
        AuthMessage::Response {
            client_id,
            timestamp,
            totp_code,
            signature,
        } => (client_id, timestamp, signature, totp_code),
        _ => {
            return Err(AuthFailure::NotStarted(
                "expected AUTH_RESPONSE message".to_string(),
            ));
        }
    };

    if resp_client_id != client_id {
        return Err(AuthFailure::Rejected(
            "client ID mismatch in AUTH_RESPONSE".to_string(),
        ));
    }

    // Step 4: Verify the response. The signature binds it to this
    // connection's challenge and the timestamp keeps it fresh; only then does
    // the TOTP code decide. The whole check runs under one read lock; the
    // write lock below is taken only when a counter actually moves.
    let outcome = {
        let cfg = auth.config().read().await;
        TotpValidator::new(&cfg).verify_response(
            &client_id,
            &nonce,
            resp_timestamp,
            &signature,
            &totp_code,
        )
    };

    // Only a wrong TOTP code counts toward the lockout: a skewed clock or a
    // mismatched signature is a refusal, not a failed attempt, and counting
    // those would let whoever replays a captured response lock its rightful
    // owner out.
    let (is_valid, wire_reason) = match outcome {
        Ok(true) => {
            let mut cfg = auth.config().write().await;
            // Clear the counters only when there is something to clear, so a
            // healthy client does not turn every connection into a disk write.
            let dirty = cfg
                .clients
                .get(&client_id)
                .is_some_and(|c| c.failed_attempts != 0 || c.locked_until.is_some());
            if dirty {
                if let Some(client) = cfg.clients.get_mut(&client_id) {
                    client.record_success();
                }
                if let Err(e) = save_auth_state(auth.path(), &cfg) {
                    tracing::warn!(
                        "2FA: failed to persist auth state for '{}' to {}: {}",
                        client_id,
                        auth.path(),
                        e
                    );
                }
            }
            (true, None)
        }
        Ok(false) => {
            let mut cfg = auth.config().write().await;
            let max_attempts = cfg.max_attempts;
            let lockout_duration = cfg.lockout_duration;
            if let Some(client) = cfg.clients.get_mut(&client_id) {
                client.record_failure(max_attempts, lockout_duration);
                if let Err(e) = save_auth_state(auth.path(), &cfg) {
                    tracing::warn!(
                        "2FA: failed to persist lockout for '{}' to {}: {}",
                        client_id,
                        auth.path(),
                        e
                    );
                }
            }
            (false, Some("Invalid TOTP code".to_string()))
        }
        Err(e) => {
            // Refusals are logged with their real reason; on the wire the
            // lockout stays visible (a user can wait it out) while everything
            // else reads as a generic rejection, so the AUTH_FAILED reason is
            // not an oracle for which client IDs exist.
            match &e {
                AuthError::ClientNotFound => {
                    tracing::warn!("2FA: unknown client '{}' from {}", client_id, peer);
                }
                AuthError::InvalidSecret | AuthError::TotpCreationFailed => {
                    tracing::error!(
                        "2FA: client '{}' cannot be validated, the server's auth config is broken: {}",
                        client_id,
                        e
                    );
                }
                AuthError::LockedOut => {
                    tracing::warn!("2FA: client '{}' from {} is locked out", client_id, peer);
                }
                _ => {
                    tracing::warn!("2FA: response from {} for '{}' rejected: {}", peer, client_id, e);
                }
            }
            let reason = if matches!(e, AuthError::LockedOut) {
                e.to_string()
            } else {
                "Invalid TOTP code".to_string()
            };
            (false, Some(reason))
        }
    };

    let fail_reason = wire_reason.unwrap_or_else(|| "Invalid TOTP code".to_string());
    let result_msg = if is_valid {
        AuthMessage::Ok
    } else {
        AuthMessage::Failed {
            reason: fail_reason.clone(),
        }
    };

    let result_bytes = result_msg
        .to_bytes()
        .map_err(|e| AuthFailure::NotStarted(format!("failed to serialize auth result: {}", e)))?;
    let len = result_bytes.len() as u32;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| AuthFailure::NotStarted(format!("failed to send auth result: {}", e)))?;
    send.write_all(&result_bytes)
        .await
        .map_err(|e| AuthFailure::NotStarted(format!("failed to send auth result: {}", e)))?;
    send.finish()
        .map_err(|e| AuthFailure::NotStarted(format!("failed to finish auth stream: {}", e)))?;

    if is_valid {
        Ok(client_id)
    } else {
        Err(AuthFailure::Rejected(format!(
            "authentication failed for client '{}': {}",
            client_id,
            fail_reason
        )))
    }
}

/// Reads one length-prefixed AUTH_* message from the handshake stream.
///
/// The length prefix is whatever the peer sent first, so it is only trusted
/// after the range check: a data stream offered to a 2FA server starts with
/// bytes that would otherwise ask for a gigabyte-sized buffer.
async fn read_auth_message(recv: &mut iroh::endpoint::RecvStream) -> Result<Vec<u8>, String> {
    let len_buf = read_bytes(recv, 4).await?;
    let msg_len = u32::from_le_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;

    if msg_len == 0 || msg_len > MAX_AUTH_MESSAGE {
        return Err(format!("auth message length {} is out of range", msg_len));
    }

    read_bytes(recv, msg_len).await
}

/// Reads exactly `len` bytes, one cancel-safe `read` at a time.
///
/// `RecvStream::read` is cancel-safe and `read_exact` is not, and the handshake
/// runs under a deadline that may drop this future mid-message.
async fn read_bytes(recv: &mut iroh::endpoint::RecvStream, len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        match recv.read(&mut buf[filled..]).await {
            Ok(Some(0)) => break,
            Ok(Some(n)) => filled += n,
            Ok(None) => break,
            Err(e) => return Err(format!("failed to read auth message: {}", e)),
        }
    }
    if filled < len {
        return Err(format!(
            "client closed the auth stream after {} of {} bytes",
            filled, len
        ));
    }
    Ok(buf)
}

pub async fn handle_connection(
    conn: Connection,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
    auth_state: Option<AuthState>,
) {
    let peer_id = conn.remote_id();
    let peer = peer_id.to_string();
    tracing::info!("New connection from peer: {}", peer_id);

    // One counter for the whole connection: the L4 path hands out a slot per flow and
    // answers `TooManyFlows` once it is full, so a client with many UDP flows fails the
    // one that does not fit instead of blocking inside `open_bi`.
    let limiter = Arc::new(l4::FlowLimiter::new(l4::DEFAULT_MAX_FLOWS_PER_CONNECTION));

    let paths = conn.paths();
    if let Some(selected_path) = paths.iter().find(|p| p.is_selected()) {
        tracing::info!(
            "Initial connection type: {}",
            get_connection_type(&selected_path)
        );
    } else {
        tracing::info!("Initial connection type: Unknown (no selected path)");
    }

    let conn_clone = conn.clone();
    tokio::spawn(async move {
        let mut path_events = conn_clone.path_events();
        while let Some(event) = path_events.next().await {
            if let iroh::endpoint::PathEvent::Selected { remote_addr, .. } = event {
                if remote_addr.is_ip() {
                    tracing::info!("Connection upgraded: Relay -> Direct");
                } else if remote_addr.is_relay() {
                    tracing::info!("Connection downgraded: Direct -> Relay");
                }
            }
        }
    });

    // ===== 2FA Authentication Handshake =====
    if let Some(auth) = &auth_state {
        if auth.config().read().await.enabled {
            let outcome = tokio::time::timeout(
                AUTH_HANDSHAKE_TIMEOUT,
                perform_authentication(&conn, auth, &peer),
            )
            .await;
            match outcome {
                Ok(Ok(client_id)) => {
                    tracing::info!(
                        "Client '{}' authenticated successfully from {}",
                        client_id,
                        peer_id
                    );
                }
                Ok(Err(AuthFailure::Rejected(reason))) => {
                    tracing::warn!("Authentication failed for {}: {}", peer_id, reason);
                    conn.close(
                        auth_close_code::REJECTED.into(),
                        b"2FA authentication failed",
                    );
                    return;
                }
                Ok(Err(AuthFailure::NotStarted(reason))) => {
                    // The client never offered credentials, which usually means
                    // it has no 2FA configured at all: the close code is what
                    // tells it so, since it is not reading anything else.
                    tracing::warn!(
                        "Connection from {} refused, 2FA is required: {}",
                        peer_id,
                        reason
                    );
                    conn.close(auth_close_code::REQUIRED.into(), b"2FA required");
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        "Connection from {} refused, no 2FA handshake within {}s",
                        peer_id,
                        AUTH_HANDSHAKE_TIMEOUT.as_secs()
                    );
                    conn.close(auth_close_code::REQUIRED.into(), b"2FA required");
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
                let limiter_clone = limiter.clone();
                let peer_clone = peer.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_bidi_stream(
                        send,
                        recv,
                        &config_clone,
                        &client_clone,
                        &limiter_clone,
                        &peer_clone,
                    )
                    .await
                    {
                        tracing::error!("Failed to handle stream from {}: {}", peer_clone, e);
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
    auth_state: Option<AuthState>,
) {
    match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => {
                tokio::spawn(async move {
                    handle_connection(conn, config, client, auth_state).await;
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
