use crate::ClientError;
use crate::connection_pool::IrohConnectionPool;
use crate::endpoint_group::EndpointGroup;
use crate::http::{is_websocket_request_static, parse_http_request_legacy};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[cfg(feature = "tracing")]
use tracing;

#[cfg(feature = "jni")]
use crate::jni_log;

#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {};
}

const STREAM_BUF_SIZE: usize = 128 * 1024;
const STREAM_OPERATION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);

#[derive(Clone)]
pub struct LocalProxy {
    listener: Arc<TcpListener>,
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
    stopped: Arc<AtomicBool>,
}

impl LocalProxy {
    pub async fn new(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
    ) -> Result<Self, ClientError> {
        #[cfg(feature = "jni")]
        jni_log!("[DEBUG:local-proxy] Binding to {}", listen_addr);
        let listener = match TcpListener::bind(listen_addr).await {
            Ok(l) => {
                #[cfg(feature = "jni")]
                jni_log!("[DEBUG:local-proxy] Bound successfully to {}", listen_addr);
                l
            }
            Err(e) => {
                #[cfg(feature = "jni")]
                jni_log!(
                    "[DEBUG:local-proxy] Failed to bind to {}: {}",
                    listen_addr,
                    e
                );
                return Err(e.into());
            }
        };
        #[cfg(feature = "tracing")]
        tracing::info!("Local proxy listening on: {}", listen_addr);
        Ok(Self {
            listener: Arc::new(listener),
            endpoint_group,
            proxy_domains: Arc::new(proxy_domains),
            stopped: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn new_with_single_pool(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        conn_pool: IrohConnectionPool,
    ) -> Result<Self, ClientError> {
        let listener = TcpListener::bind(listen_addr).await?;
        let endpoint_group = EndpointGroup::new_with_single_pool(conn_pool).await;
        #[cfg(feature = "tracing")]
        tracing::info!("Local proxy listening on: {}", listen_addr);
        Ok(Self {
            listener: Arc::new(listener),
            endpoint_group: Arc::new(endpoint_group),
            proxy_domains: Arc::new(proxy_domains),
            stopped: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn run(&self) -> Result<(), ClientError> {
        let stopped = self.stopped.clone();
        let listener = self.listener.clone();
        let proxy_domains = self.proxy_domains.clone();
        let endpoint_group = self.endpoint_group.clone();

        loop {
            if stopped.load(Ordering::Acquire) {
                #[cfg(feature = "tracing")]
                tracing::info!("Local proxy stopping");
                break;
            }

            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((stream, addr))) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("New connection from: {}", addr);

                    let proxy_domains_clone = proxy_domains.clone();
                    let endpoint_group_clone = endpoint_group.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_local_connection(
                            stream,
                            proxy_domains_clone,
                            endpoint_group_clone,
                        )
                        .await
                        {
                            #[cfg(feature = "tracing")]
                            tracing::error!("Failed to handle local connection: {}", e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    #[cfg(feature = "tracing")]
                    tracing::error!("Local proxy accept error: {}", e);
                    break;
                }
                Err(_) => {
                    continue;
                }
            }
        }
        Ok(())
    }

    pub fn stop(&self) {
        #[cfg(feature = "tracing")]
        tracing::info!("Stopping local proxy");
        self.stopped.store(true, Ordering::Release);
    }

    pub async fn close_all(&self) {
        self.endpoint_group.close_all().await;
    }
}

fn websocket_frame_preview(data: &[u8]) -> String {
    let mut preview = String::new();
    for &b in data.iter().take(256) {
        if b.is_ascii_graphic() || b == b' ' {
            preview.push(b as char);
        } else {
            preview.push_str(&format!("\\x{:02x}", b));
        }
    }
    if data.len() > 256 {
        preview.push_str("...");
    }
    format!("{} bytes: {}", data.len(), preview)
}

async fn handle_local_connection(
    mut stream: tokio::net::TcpStream,
    proxy_domains: Arc<Vec<String>>,
    endpoint_group: Arc<EndpointGroup>,
) -> Result<(), ClientError> {
    jni_log!("[DEBUG:local-proxy] New local connection received");

    // Step 1: Read the first chunk of data to determine protocol (HTTP vs TLS)
    let mut request_buf = Vec::new();
    let mut temp_buf = [0u8; STREAM_BUF_SIZE];

    let n = match tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        stream.read(&mut temp_buf),
    )
    .await
    {
        Ok(Ok(0)) => {
            jni_log!("[DEBUG:local-proxy] Empty request, closing connection");
            return Ok(());
        }
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            jni_log!("[DEBUG:local-proxy] Read error: {}", e);
            return Ok(());
        }
        Err(_) => {
            jni_log!("[DEBUG:local-proxy] Read timeout, closing connection");
            return Ok(());
        }
    };

    request_buf.extend_from_slice(&temp_buf[..n]);

    // Check if this is a TLS connection (ClientHello starts with 0x16 = Handshake content type)
    if !request_buf.is_empty() && request_buf[0] == 0x16 {
        jni_log!("[DEBUG:local-proxy] Detected TLS ClientHello, handling as raw tunnel via SNI");
        return handle_tls_tunnel(stream, request_buf, endpoint_group, proxy_domains).await;
    }

    // Step 2: HTTP — read the complete request header (up to \r\n\r\n)
    let mut header_end: Option<usize> = None;
    if let Some(pos) = request_buf[..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
    {
        header_end = Some(pos + 4);
    }

    while header_end.is_none() {
        let n = match tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            stream.read(&mut temp_buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                jni_log!("[DEBUG:local-proxy] Read error: {}", e);
                return Ok(());
            }
            Err(_) => {
                jni_log!("[DEBUG:local-proxy] Read timeout, closing connection");
                return Ok(());
            }
        };

        let prev_len = request_buf.len();
        request_buf.extend_from_slice(&temp_buf[..n]);

        // Search for \r\n\r\n, starting a few bytes before the new data
        let search_start = prev_len.saturating_sub(3);
        if let Some(pos) = request_buf[search_start..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
        {
            header_end = Some(search_start + pos + 4);
        }
    }

    let header_end = match header_end {
        Some(pos) => pos,
        None => {
            jni_log!("[DEBUG:local-proxy] HTTP header end not found, closing connection");
            return Ok(());
        }
    };

    let request = match parse_http_request_legacy(&request_buf[..header_end]) {
        Ok(req) => {
            jni_log!(
                "[DEBUG:local-proxy] Parsed HTTP request: {} {}",
                req.method(),
                req.uri()
            );
            req
        }
        Err(e) => {
            jni_log!("[DEBUG:local-proxy] Failed to parse HTTP request: {}", e);
            jni_log!(
                "[DEBUG:local-proxy] First 16 bytes: {:?}",
                &request_buf[..std::cmp::min(request_buf.len(), 16)]
            );
            return Ok(());
        }
    };

    if request.method().as_str() == "CONNECT" {
        let uri = request.uri().to_string();
        let host_port = uri.split(':').next().unwrap_or(&uri);
        let host = host_port.to_string();

        if !should_proxy_domain(&host, &proxy_domains) {
            return Ok(());
        }

        let (mut client_read, mut client_write) = tokio::io::split(stream);
        client_write
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let pooled_conn = endpoint_group.get_connection(&host).await?;
        let conn = pooled_conn.conn().clone();
        let (mut send, mut recv) = tokio::time::timeout(STREAM_OPERATION_TIMEOUT, conn.open_bi())
            .await
            .map_err(|_| crate::error::ClientError::TimeoutError)?
            .map_err(|e| anyhow::anyhow!(e))?;

        let client_to_iroh = async {
            let mut buf = [0u8; STREAM_BUF_SIZE];
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel client_to_iroh write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Tunnel client_to_iroh read error: {}", e);
                        break;
                    }
                }
            }
        };

        let iroh_to_client = async {
            let mut buf = [0u8; STREAM_BUF_SIZE];
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) => break,
                    Ok(Some(n)) => {
                        if let Err(e) = client_write.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel iroh_to_client write error: {}", e);
                            break;
                        }
                        if let Err(e) = client_write.flush().await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel iroh_to_client flush error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
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

        endpoint_group.return_connection(&host, pooled_conn).await;
        return Ok(());
    }

    let mut target_host = None;
    for header in request.headers().get_all("host") {
        if let Ok(h) = header.to_str() {
            let h = h.split(':').next().unwrap_or(h);
            jni_log!("[DEBUG:local-proxy] Found Host header: '{}'", h);
            if should_proxy_domain(&h, &proxy_domains) {
                target_host = Some(h.to_string());
                break;
            }
        }
    }

    if target_host.is_none() {
        jni_log!("[DEBUG:local-proxy] No matching Host header found");
        return Ok(());
    }

    let host = target_host.unwrap();
    jni_log!(
        "[DEBUG:local-proxy] Getting connection for domain: '{}'",
        host
    );

    // WebSocket upgrade: rewrite the request line to use an absolute "http://"
    // URI. When a browser connects through a normal HTTP proxy it sends
    // "GET http://host/path HTTP/1.1" (absolute-form request-target per
    // RFC 7230 §5.3.2). The backend uses this to recognize that the stream
    // should be kept alive for bidirectional data flow after the HTTP upgrade,
    // rather than treating it as a one-shot HTTP exchange.
    if is_websocket_request_static(&request) {
        jni_log!("[DEBUG:local-proxy] WebSocket request, rewriting to absolute URI");
        jni_log!(
            "[DEBUG:local-proxy] WebSocket request details: uri={}, host={}, headers={:?}",
            request.uri(),
            host,
            request.headers()
        );

        // Find the first line (request line)
        let first_line_end = request_buf[..header_end]
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(0);

        if first_line_end > 0 {
            let request_line = &request_buf[..first_line_end];
            let line_str = String::from_utf8_lossy(request_line);
            if let Some((method_rest, version)) = line_str.rsplit_once(" HTTP/") {
                if let Some(method) = method_rest.split_whitespace().next() {
                    let path = request.uri().path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/");
                    // Use http:// scheme (not ws://) — the backend handles
                    // the WebSocket upgrade via the Upgrade header, not the URI
                    let absolute_uri = format!("http://{}{}", host, path);
                    let new_line = format!("{} {} HTTP/{}\r\n", method, absolute_uri, version);

                    let mut request_to_send = Vec::with_capacity(
                        new_line.len() + header_end - first_line_end,
                    );
                    request_to_send.extend_from_slice(new_line.as_bytes());
                    // Copy the rest of headers (skip the original request line)
                    let rest_start = first_line_end + 2; // skip \r\n
                    if rest_start < header_end {
                        request_to_send.extend_from_slice(&request_buf[rest_start..header_end]);
                    }

                    jni_log!(
                        "[DEBUG:local-proxy] Rewrote WebSocket request line: {}",
                        new_line.trim()
                    );

                    // Open iroh bi-stream and send the modified request
                    let pooled_conn = endpoint_group.get_connection(&host).await?;
                    let conn = pooled_conn.conn().clone();
                    let (mut send, mut recv) = tokio::time::timeout(STREAM_OPERATION_TIMEOUT, conn.open_bi())
                        .await
                        .map_err(|_| crate::error::ClientError::TimeoutError)?
                        .map_err(|e| anyhow::anyhow!(e))?;

                    let (mut client_read, mut client_write) = tokio::io::split(stream);
                    send.write_all(&request_to_send).await?;
                    jni_log!(
                        "[DEBUG:local-proxy] WebSocket request sent to iroh: {} bytes",
                        request_to_send.len()
                    );

                    // Bidirectional forwarding (no send.finish() — keep stream open)
                    let client_to_iroh = async move {
                        let mut buf = [0u8; STREAM_BUF_SIZE];
                        loop {
                            match client_read.read(&mut buf).await {
                                Ok(0) => {
                                    jni_log!("[DEBUG:local-proxy] WS client EOF");
                                    return "client_eof";
                                }
                                Ok(n) => {
                                    jni_log!(
                                        "[DEBUG:local-proxy] WS client->iroh: {}",
                                        websocket_frame_preview(&buf[..n])
                                    );
                                    if let Err(e) = send.write_all(&buf[..n]).await {
                                        jni_log!("[DEBUG:local-proxy] WS client->backend err: {}", e);
                                        return "client_write_error";
                                    }
                                }
                                Err(e) => {
                                    jni_log!("[DEBUG:local-proxy] WS client read error: {}", e);
                                    return "client_read_error";
                                }
                            }
                        }
                    };

                    let iroh_to_client = async move {
                        let mut buf = [0u8; STREAM_BUF_SIZE];
                        let mut first = true;
                        loop {
                            match recv.read(&mut buf).await {
                                Ok(None) => {
                                    jni_log!("[DEBUG:local-proxy] WS iroh EOF");
                                    return "iroh_eof";
                                }
                                Ok(Some(n)) => {
                                    if first {
                                        first = false;
                                        let p = &buf[..std::cmp::min(n, 200)];
                                        jni_log!("[DEBUG:local-proxy] WS first response: {}",
                                            String::from_utf8_lossy(p));
                                    }
                                    jni_log!(
                                        "[DEBUG:local-proxy] WS iroh->client: {}",
                                        websocket_frame_preview(&buf[..n])
                                    );
                                    if n <= 1024 {
                                        jni_log!(
                                            "[DEBUG:local-proxy] WS iroh->client decoded: {}",
                                            String::from_utf8_lossy(&buf[..n])
                                        );
                                    }
                                    if client_write.write_all(&buf[..n]).await.is_err() {
                                        return "client_write_error";
                                    }
                                    let _ = client_write.flush().await;
                                }
                                Err(e) => {
                                    jni_log!("[DEBUG:local-proxy] WS iroh read error: {}", e);
                                    return "iroh_read_error";
                                }
                            }
                        }
                    };

                    let mut client_task = tokio::spawn(client_to_iroh);
                    let mut backend_task = tokio::spawn(iroh_to_client);

                    let (closed_direction, close_reason) = tokio::select! {
                        result = &mut client_task => {
                            ("client_to_iroh", result.unwrap_or_else(|_| "client_task_panicked"))
                        }
                        result = &mut backend_task => {
                            ("iroh_to_client", result.unwrap_or_else(|_| "backend_task_panicked"))
                        }
                    };

                    if closed_direction == "client_to_iroh" {
                        backend_task.abort();
                    } else {
                        client_task.abort();
                    }
                    jni_log!(
                        "[DEBUG:local-proxy] WebSocket tunnel closed first by {} ({})",
                        closed_direction,
                        close_reason
                    );

                    endpoint_group.return_connection(&host, pooled_conn).await;
                    return Ok(());
                }
            }
        }

        // Fallback: if we couldn't rewrite, just connect normally
        jni_log!("[DEBUG:local-proxy] WebSocket URI rewrite failed, falling back to regular HTTP");
    }

    // Regular HTTP path
    let pooled_conn = endpoint_group.get_connection(&host).await?;
    let conn = pooled_conn.conn().clone();
    let (mut send, mut recv) = tokio::time::timeout(STREAM_OPERATION_TIMEOUT, conn.open_bi())
        .await
        .map_err(|_| crate::error::ClientError::TimeoutError)?
        .map_err(|e| anyhow::anyhow!(e))?;

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    // Remove cache validation headers to prevent 304 responses with empty body
    let filtered_headers = remove_cache_validation_headers(&request_buf[..header_end]);
    let mut request_to_send = filtered_headers;
    request_to_send.extend_from_slice(&request_buf[header_end..]);

    jni_log!(
        "[DEBUG:local-proxy] Forwarding {} bytes to backend, Host: {}",
        request_to_send.len(),
        host
    );
    send.write_all(&request_to_send).await?;

    let client_to_backend = async move {
        let mut buf = [0u8; STREAM_BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Client to backend write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Client read error: {}", e);
                    break;
                }
            }
        }
        let _ = send.finish();
    };

    let backend_to_client = async move {
        let mut buf = [0u8; STREAM_BUF_SIZE];
        let mut total_bytes = 0;
        let mut debug_preview = Vec::with_capacity(1500);
        let mut response_sent = false;
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    total_bytes += n;
                    if !response_sent && debug_preview.len() < 1500 {
                        debug_preview.extend_from_slice(
                            &buf[..std::cmp::min(n, 1500 - debug_preview.len())],
                        );
                    }
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Backend to client write error: {}", e);
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Backend to client flush error: {}", e);
                        break;
                    }
                    if !response_sent {
                        response_sent = true;
                        jni_log!("[DEBUG:local-proxy] Response sent: {} bytes", total_bytes);
                        if !debug_preview.is_empty() {
                            jni_log!(
                                "[DEBUG:local-proxy] Response preview: {}",
                                String::from_utf8_lossy(&debug_preview)
                            );
                        }
                    }
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Backend read error: {}", e);
                    break;
                }
            }
        }
        if !response_sent && total_bytes > 0 {
            jni_log!("[DEBUG:local-proxy] Response sent (late): {} bytes", total_bytes);
            if !debug_preview.is_empty() {
                jni_log!(
                    "[DEBUG:local-proxy] Response preview: {}",
                    String::from_utf8_lossy(&debug_preview)
                );
            }
        }
    };
    // END regular HTTP closures

    // Regular HTTP request-response handling
    jni_log!("[DEBUG:local-proxy] Detected HTTP request, using request-response mode");
    jni_log!(
        "[DEBUG:local-proxy] Request headers: {:?}",
        request.headers()
    );
    let client_task = tokio::spawn(client_to_backend);
    let mut backend_task = tokio::spawn(backend_to_client);

    let _ = client_task.await;
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(60), &mut backend_task).await;

    endpoint_group.return_connection(&host, pooled_conn).await;
    jni_log!("[DEBUG:local-proxy] Connection closed");
    Ok(())
}

/// Handle a raw TLS tunnel connection via SNI extraction.
///
/// When a client connects to the VPN's virtual proxy IP on port 443, it sends
/// a TLS ClientHello directly (since it doesn't know there's an HTTP proxy in
/// between). This function extracts the SNI hostname from the ClientHello,
/// establishes an iroh tunnel to the appropriate backend, and forwards raw TCP
/// data bidirectionally — no HTTP parsing involved.
async fn handle_tls_tunnel(
    mut stream: tokio::net::TcpStream,
    initial_data: Vec<u8>,
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
) -> Result<(), ClientError> {
    jni_log!("[DEBUG:local-proxy] TLS tunnel mode");

    // Ensure we have enough data for the full TLS record (ClientHello)
    // Record header is 5 bytes: content_type(1) + version(2) + length(2)
    let mut data = initial_data;
    if data.len() >= 5 {
        let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
        let total_needed = 5 + record_len;
        while data.len() < total_needed {
            let mut extra = [0u8; 4096];
            match stream.read(&mut extra).await {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&extra[..n]),
                Err(_) => break,
            }
        }
    }

    // Extract SNI from TLS ClientHello
    let sni = match extract_sni_from_client_hello(&data) {
        Some(sni) => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: extracted SNI '{}'", sni);
            sni
        }
        None => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: could not extract SNI from ClientHello");
            return Ok(());
        }
    };

    if !should_proxy_domain(&sni, &proxy_domains) {
        jni_log!(
            "[DEBUG:local-proxy] TLS tunnel: SNI '{}' not in proxy domains, closing",
            sni
        );
        return Ok(());
    }

    jni_log!(
        "[DEBUG:local-proxy] TLS tunnel: establishing iroh tunnel for '{}'",
        sni
    );

    let pooled_conn = endpoint_group.get_connection(&sni).await?;
    let conn = pooled_conn.conn().clone();
    let (mut send, mut recv) = tokio::time::timeout(STREAM_OPERATION_TIMEOUT, conn.open_bi())
        .await
        .map_err(|_| crate::error::ClientError::TimeoutError)?
        .map_err(|e| anyhow::anyhow!(e))?;

    // Forward the initial TLS ClientHello through the iroh stream
    jni_log!(
        "[DEBUG:local-proxy] TLS tunnel: forwarding initial {} bytes",
        data.len()
    );
    send.write_all(&data).await?;

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    // Bidirectional raw data forwarding (TCP tunnel)
    let client_to_iroh = async {
        let mut buf = [0u8; STREAM_BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        jni_log!(
                            "[DEBUG:local-proxy] TLS tunnel client->iroh write error: {}",
                            e
                        );
                        break;
                    }
                }
                Err(e) => {
                    jni_log!(
                        "[DEBUG:local-proxy] TLS tunnel client read error: {}",
                        e
                    );
                    break;
                }
            }
        }
    };

    let iroh_to_client = async {
        let mut buf = [0u8; STREAM_BUF_SIZE];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        jni_log!(
                            "[DEBUG:local-proxy] TLS tunnel iroh->client write error: {}",
                            e
                        );
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        jni_log!("[DEBUG:local-proxy] TLS tunnel flush error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    jni_log!(
                        "[DEBUG:local-proxy] TLS tunnel backend read error: {}",
                        e
                    );
                    break;
                }
            }
        }
    };

    jni_log!("[DEBUG:local-proxy] TLS tunnel: bidirectional forwarding started");
    tokio::select! {
        _ = client_to_iroh => (),
        _ = iroh_to_client => (),
    }

    endpoint_group.return_connection(&sni, pooled_conn).await;
    jni_log!("[DEBUG:local-proxy] TLS tunnel closed");
    Ok(())
}

/// Extract the SNI (Server Name Indication) hostname from a TLS ClientHello.
///
/// The TLS 1.2/1.3 ClientHello format (simplified):
///   1 byte  content_type (0x16 = Handshake)
///   2 bytes version
///   2 bytes record length
///   --- record data ---
///   1 byte  handshake_type (0x01 = ClientHello)
///   3 bytes handshake length
///   2 bytes client version
///   32 bytes random
///   1 byte  session ID length + data
///   2 bytes cipher suites length + data
///   1 byte  compression methods length + data
///   2 bytes extensions length
///   extensions...
///
/// SNI extension type = 0x0000
fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Must be TLS Handshake content type
    if data[0] != 0x16 {
        return None;
    }

    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    let total_needed = 5 + record_len;
    if data.len() < total_needed {
        return None;
    }

    let mut pos = 5usize;

    // Handshake type: ClientHello (0x01)
    if pos >= data.len() || data[pos] != 0x01 {
        return None;
    }
    pos += 1;

    // Handshake length (3 bytes, big-endian)
    if pos + 3 > data.len() {
        return None;
    }
    let _hs_len = ((data[pos] as usize) << 16)
        | ((data[pos + 1] as usize) << 8)
        | (data[pos + 2] as usize);
    pos += 3;

    // Skip protocol version (2 bytes) + random (32 bytes)
    pos += 34;
    if pos > data.len() {
        return None;
    }

    // Skip session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos > data.len() {
        return None;
    }

    // Skip cipher suites
    if pos + 1 >= data.len() {
        return None;
    }
    let cipher_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2 + cipher_len;
    if pos > data.len() {
        return None;
    }

    // Skip compression methods
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos > data.len() {
        return None;
    }

    // Extensions
    if pos + 1 >= data.len() {
        return None;
    }
    let ext_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > data.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        let ext_data_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 {
            // server_name (SNI) extension
            if pos + 2 > ext_end {
                return None;
            }
            let _sni_list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            pos += 2;

            if pos + 3 <= ext_end.min(data.len()) {
                let name_type = data[pos];
                pos += 1;
                let name_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                pos += 2;

                if name_type == 0x00 && pos + name_len <= data.len() && pos + name_len <= ext_end
                {
                    // Read host_name (ASCII/UTF-8 encoded hostname)
                    return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
                }
            }
        }

        pos += ext_data_len;
    }

    None
}

fn remove_cache_validation_headers(header_bytes: &[u8]) -> Vec<u8> {
    // The input always ends with \r\n\r\n (the HTTP header terminator,
    // up to header_end). We iterate over each header line, strip the cache
    // validation headers, and preserve the original \r\n\r\n terminator
    // so the body (appended separately) starts at the right position.
    let mut result = Vec::with_capacity(header_bytes.len());
    let mut start = 0;

    while let Some(pos) = header_bytes[start..].windows(2).position(|w| w == b"\r\n") {
        let line_end = start + pos;
        let line = &header_bytes[start..line_end];

        let is_cache_header = line.len() >= 18 && {
            let lower = line.to_ascii_lowercase();
            lower.starts_with(b"if-modified-since:") || lower.starts_with(b"if-none-match:")
        };

        if !is_cache_header {
            result.extend_from_slice(line);
            result.extend_from_slice(b"\r\n");
        }

        start = line_end + 2;
    }

    // Loop already preserved the \r\n\r\n terminator — don't add an extra one
    result
}

fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    let host_lower = host.to_lowercase();
    for domain in proxy_domains {
        let domain_lower = domain.to_lowercase();
        if domain_lower.starts_with('*') {
            let suffix = &domain_lower[1..];
            if host_lower.ends_with(suffix) {
                return true;
            }
        } else if host_lower == domain_lower || host_lower.ends_with(&format!(".{}", domain_lower))
        {
            return true;
        }
    }
    false
}
