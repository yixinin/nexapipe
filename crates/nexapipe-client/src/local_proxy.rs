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
                jni_log!("[DEBUG:local-proxy] Failed to bind to {}: {}", listen_addr, e);
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

async fn handle_local_connection(
    mut stream: tokio::net::TcpStream,
    proxy_domains: Arc<Vec<String>>,
    endpoint_group: Arc<EndpointGroup>,
) -> Result<(), ClientError> {
    jni_log!("[DEBUG:local-proxy] New local connection received");

    // Step 1: Read the complete HTTP request header (up to \r\n\r\n)
    let mut request_buf = Vec::new();
    let mut temp_buf = [0u8; STREAM_BUF_SIZE];
    let mut header_end: Option<usize> = None;

    while header_end.is_none() {
        let n = match tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            stream.read(&mut temp_buf)
        ).await {
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
        if let Some(pos) = request_buf[search_start..].windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(search_start + pos + 4);
        }
    }

    if request_buf.is_empty() {
        jni_log!("[DEBUG:local-proxy] Empty request, closing connection");
        return Ok(());
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
            jni_log!("[DEBUG:local-proxy] Parsed HTTP request: {} {}", req.method(), req.uri());
            req
        },
        Err(e) => {
            jni_log!("[DEBUG:local-proxy] Failed to parse HTTP request: {}", e);
            jni_log!("[DEBUG:local-proxy] First 16 bytes: {:?}", &request_buf[..std::cmp::min(request_buf.len(), 16)]);
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
        client_write.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        let pooled_conn = endpoint_group.get_connection(&host).await?;
        let conn = pooled_conn.conn().clone();
        let (mut send, mut recv) = tokio::time::timeout(
            STREAM_OPERATION_TIMEOUT,
            conn.open_bi(),
        )
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
    jni_log!("[DEBUG:local-proxy] Getting connection for domain: '{}'", host);

    let pooled_conn = endpoint_group.get_connection(&host).await?;
    let conn = pooled_conn.conn().clone();
    let (mut send, mut recv) = tokio::time::timeout(
        STREAM_OPERATION_TIMEOUT,
        conn.open_bi(),
    )
    .await
    .map_err(|_| crate::error::ClientError::TimeoutError)?
    .map_err(|e| anyhow::anyhow!(e))?;

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    // Remove cache validation headers to prevent 304 responses with empty body
    let filtered_headers = remove_cache_validation_headers(&request_buf[..header_end]);
    let mut request_to_send = filtered_headers;
    request_to_send.extend_from_slice(&request_buf[header_end..]);

    jni_log!("[DEBUG:local-proxy] Forwarding {} bytes to backend, Host: {}", request_to_send.len(), host);
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
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    total_bytes += n;
                    if debug_preview.len() < 1500 {
                        debug_preview.extend_from_slice(&buf[..std::cmp::min(n, 1500 - debug_preview.len())]);
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
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Backend read error: {}", e);
                    break;
                }
            }
        }
        jni_log!("[DEBUG:local-proxy] Response sent: {} bytes", total_bytes);
        if !debug_preview.is_empty() {
            jni_log!("[DEBUG:local-proxy] Response preview: {}", String::from_utf8_lossy(&debug_preview));
        }
    };

    if is_websocket_request_static(&request) {
        // WebSocket: run both directions until either side closes
        let mut client_task = tokio::spawn(client_to_backend);
        let mut backend_task = tokio::spawn(backend_to_client);
        tokio::select! {
            _ = &mut client_task => (),
            _ = &mut backend_task => (),
        }
    } else {
        // HTTP: forward the full request first, then drain the full response.
        // This prevents the request body from being truncated when the backend
        // returns an early error response.
        let client_task = tokio::spawn(client_to_backend);
        let mut backend_task = tokio::spawn(backend_to_client);

        let _ = client_task.await;
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_secs(300),
            &mut backend_task
        ).await;
    }

    endpoint_group.return_connection(&host, pooled_conn).await;
    jni_log!("[DEBUG:local-proxy] Connection closed");
    Ok(())
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
        } else if host_lower == domain_lower || host_lower.ends_with(&format!(".{}", domain_lower)) {
            return true;
        }
    }
    false
}
