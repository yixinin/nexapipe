use crate::connection_pool::IrohConnectionPool;
use crate::http::{parse_http_request_legacy, is_websocket_request_static};
use crate::ClientError;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[cfg(feature = "tracing")]
use tracing;

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
const MAX_RESPONSE_SIZE: usize = 1024 * 1024 * 10;
const MAX_CONNECTIONS: usize = 10;

pub struct LocalProxy {
    listener: Option<TcpListener>,
    conn_pool: Arc<IrohConnectionPool>,
    proxy_domains: Arc<Vec<String>>,
}

impl LocalProxy {
    pub async fn new(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        conn_pool: IrohConnectionPool,
    ) -> Result<Self, ClientError> {
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            listener: Some(listener),
            conn_pool: Arc::new(conn_pool),
            proxy_domains: Arc::new(proxy_domains),
        })
    }

    pub async fn run(self) -> Result<(), ClientError> {
        let listener = self.listener.ok_or_else(|| ClientError::InvalidConfig("Listener not initialized".to_string()))?;

        loop {
            let (stream, addr) = listener.accept().await?;
            #[cfg(feature = "tracing")]
            tracing::debug!("New connection from: {}", addr);

            let proxy_domains_clone = self.proxy_domains.clone();
            let conn_pool_clone = self.conn_pool.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_local_connection(stream, proxy_domains_clone, conn_pool_clone).await {
                    #[cfg(feature = "tracing")]
                    tracing::error!("Failed to handle local connection: {}", e);
                }
            });
        }
    }

    pub fn stop(&mut self) {
        self.listener = None;
    }
}

async fn handle_local_connection(
    mut stream: tokio::net::TcpStream,
    proxy_domains: Arc<Vec<String>>,
    conn_pool: Arc<IrohConnectionPool>,
) -> Result<(), ClientError> {
    let mut buf = [0u8; 8192];
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

        let conn = conn_pool.get_connection().await?;
        let (send, recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

        handle_connect_tunnel(stream, send, recv).await?;
        conn_pool.return_connection(conn).await;
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

    let conn = conn_pool.get_connection().await?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

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
        let response = recv.read_to_end(MAX_RESPONSE_SIZE).await.map_err(|e| anyhow::anyhow!(e))?;
        stream.write_all(&response).await?;
    }

    conn_pool.return_connection(conn).await;
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
        let mut buf = [0u8; 8192];
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
        let mut buf = [0u8; 8192];
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
        let mut buf = [0u8; 8192];
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
        let mut buf = [0u8; 8192];
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
