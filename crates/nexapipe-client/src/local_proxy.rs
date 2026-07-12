use crate::connection_pool::IrohConnectionPool;
use crate::endpoint_group::EndpointGroup;
use crate::http::{parse_http_request_legacy, is_websocket_request_static};
use crate::ClientError;
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
        endpoint_group: EndpointGroup,
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
            endpoint_group: Arc::new(endpoint_group),
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

            match tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                listener.accept(),
            ).await {
                Ok(Ok((stream, addr))) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("New connection from: {}", addr);

                    let proxy_domains_clone = proxy_domains.clone();
                    let endpoint_group_clone = endpoint_group.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_local_connection(stream, proxy_domains_clone, endpoint_group_clone).await {
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
    let mut buf = [0u8; STREAM_BUF_SIZE];
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    let request = match parse_http_request_legacy(&buf[..n]) {
        Ok(req) => req,
        Err(e) => {
            #[cfg(feature = "tracing")]
            tracing::warn!("Failed to parse HTTP request: {}", e);
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

        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        let pooled_conn = endpoint_group.get_connection(&host).await?;
        let conn = pooled_conn.conn().clone();
        let (send, recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

        handle_connect_tunnel(stream, send, recv).await?;
        endpoint_group.return_connection(&host, pooled_conn).await;
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
        return Ok(());
    }

    let host = target_host.unwrap();

    let pooled_conn = endpoint_group.get_connection(&host).await?;
    let conn = pooled_conn.conn().clone();
    let (mut send, recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

    let mut modified_request = Vec::with_capacity(n);
    let request_str = String::from_utf8_lossy(&buf[..n]);

    let header_end = request_str.find("\r\n\r\n").map(|pos| pos + 4);
    let (headers_part, body_part) = if let Some(pos) = header_end {
        let headers = &request_str[..pos];
        let body = &buf[pos..n];
        (headers, Some(body))
    } else {
        (request_str.as_ref(), None)
    };

    let mut host_replaced = false;
    for line in headers_part.lines() {
        if line.is_empty() {
            continue;
        }
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

    modified_request.extend_from_slice(b"\r\n");

    if let Some(body) = body_part {
        modified_request.extend_from_slice(body);
    }

    if is_websocket_request_static(&request) {
        handle_local_websocket(stream, send, recv, &modified_request).await?;
    } else {
        send.write_all(&modified_request).await?;
        send.finish().map_err(|e| anyhow::anyhow!(e))?;
        stream_response_to_client(stream, recv).await?;
    }

    endpoint_group.return_connection(&host, pooled_conn).await;
    Ok(())
}

async fn handle_local_websocket(
    client_stream: tokio::net::TcpStream,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    initial_request: &[u8],
) -> Result<(), ClientError> {
    send.write_all(initial_request).await?;

    let (client_read, mut client_write) = tokio::io::split(client_stream);

    let client_to_iroh = async {
        let mut buf = [0u8; STREAM_BUF_SIZE];
        let mut client_read = client_read;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("WebSocket client_to_iroh error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("WebSocket client_to_iroh read error: {}", e);
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
                        tracing::debug!("WebSocket iroh_to_client error: {}", e);
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("WebSocket iroh_to_client flush error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
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
) -> Result<(), ClientError> {
    let (client_read, mut client_write) = tokio::io::split(client_stream);

    let client_to_iroh = async {
        let mut buf = [0u8; STREAM_BUF_SIZE];
        let mut client_read = client_read;
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

    Ok(())
}

async fn stream_response_to_client(
    mut client_stream: tokio::net::TcpStream,
    mut recv: iroh::endpoint::RecvStream,
) -> Result<(), ClientError> {
    let mut buf = [0u8; STREAM_BUF_SIZE];
    loop {
        match recv.read(&mut buf).await {
            Ok(None) => break,
            Ok(Some(n)) => {
                if let Err(e) = client_stream.write_all(&buf[..n]).await {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Stream response write error: {}", e);
                    break;
                }
                if let Err(e) = client_stream.flush().await {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Stream response flush error: {}", e);
                    break;
                }
            }
            Err(e) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Stream response read error: {}", e);
                return Err(e.into());
            }
        }
    }
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