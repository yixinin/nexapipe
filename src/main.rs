use iroh::Endpoint;
use iroh::endpoint::presets;
use iroh::endpoint::{Connection, Incoming};
use iroh_tickets::Ticket;
use iroh_tickets::endpoint::EndpointTicket;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ALPN_HTTP3: &[u8] = b"\x05http/3";
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

struct ProxyConfig {
    backend_routes: Arc<HashMap<String, String>>,
    default_backend: Arc<String>,
}

impl ProxyConfig {
    fn new(backend_routes: HashMap<String, String>, default_backend: String) -> Self {
        Self {
            backend_routes: Arc::new(backend_routes),
            default_backend: Arc::new(default_backend),
        }
    }

    fn get_backend(&self, host: Option<&str>) -> &str {
        match host {
            Some(hostname) => {
                // 尝试精确匹配
                if let Some(backend) = self.backend_routes.get(hostname) {
                    return backend;
                }

                // 尝试通配符匹配 (*.example.com)
                let parts: Vec<&str> = hostname.split('.').collect();
                if parts.len() >= 2 {
                    let wildcard = format!("*.{}", parts[1..].join("."));
                    if let Some(backend) = self.backend_routes.get(&wildcard) {
                        return backend;
                    }
                }

                // 使用默认后端
                &self.default_backend
            }
            None => &self.default_backend,
        }
    }
}

async fn proxy_to_backend(
    req: &http::Request<()>,
    backend_url: &str,
) -> anyhow::Result<http::Response<Vec<u8>>> {
    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?;
    let port = url.port_or_known_default().unwrap_or(80);

    let mut tcp_stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let request_line = format!("{} {} HTTP/1.1\r\n", req.method(), path);
    tcp_stream.write_all(request_line.as_bytes()).await?;

    tcp_stream.write_all(b"Host: ").await?;
    tcp_stream.write_all(host.as_bytes()).await?;
    tcp_stream.write_all(b"\r\n").await?;

    for (name, value) in req.headers() {
        tcp_stream.write_all(name.as_str().as_bytes()).await?;
        tcp_stream.write_all(b": ").await?;
        tcp_stream.write_all(value.as_bytes()).await?;
        tcp_stream.write_all(b"\r\n").await?;
    }

    tcp_stream.write_all(b"\r\n").await?;

    let mut response = Vec::new();
    tcp_stream.read_to_end(&mut response).await?;

    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> anyhow::Result<http::Response<Vec<u8>>> {
    let response_str = String::from_utf8_lossy(response);
    let mut lines = response_str.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response: missing status line"))?;

    let status_parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code = if status_parts.len() >= 2 {
        status_parts[1]
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid status code: {}", e))?
    } else {
        500
    };

    let mut builder = http::Response::builder().status(status_code);

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    Ok(builder.body(response.to_vec())?)
}

async fn handle_bidi_stream(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    config: &ProxyConfig,
) -> anyhow::Result<()> {
    let buf = recv.read_to_end(MAX_REQUEST_SIZE).await?;

    let request = parse_http_request(&buf)?;

    // 从请求中提取 Host 头部
    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h)); // 移除端口号

    let backend_url = config.get_backend(host);

    tracing::debug!("Request for host: {:?} -> backend: {}", host, backend_url);
    tracing::debug!("Received request: {} {}", request.method(), request.uri());

    let response = proxy_to_backend(&request, backend_url).await?;
    tracing::debug!("Proxy response status: {}", response.status());

    send_response(send, &response).await?;

    Ok(())
}

fn parse_http_request(buf: &[u8]) -> anyhow::Result<http::Request<()>> {
    let request_str = String::from_utf8_lossy(buf);
    let mut lines = request_str.split("\r\n");

    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP request: missing request line"))?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("invalid HTTP request line"));
    }

    let method = http::Method::from_bytes(parts[0].as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid HTTP method: {}", e))?;
    let uri = http::Uri::try_from(parts[1]).map_err(|e| anyhow::anyhow!("invalid URI: {}", e))?;

    let mut builder = http::Request::builder().method(method).uri(uri);

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    Ok(builder.body(())?)
}

async fn send_response(
    send: &mut iroh::endpoint::SendStream,
    response: &http::Response<Vec<u8>>,
) -> anyhow::Result<()> {
    let status = response.status();
    let status_text = status.canonical_reason().unwrap_or("Unknown");

    let mut response_buf = Vec::new();
    response_buf
        .extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status_text).as_bytes());

    for (name, value) in response.headers() {
        response_buf.extend_from_slice(name.as_str().as_bytes());
        response_buf.extend_from_slice(b": ");
        response_buf.extend_from_slice(value.as_bytes());
        response_buf.extend_from_slice(b"\r\n");
    }

    response_buf.extend_from_slice(b"\r\n");
    response_buf.extend_from_slice(response.body());

    send.write_all(&response_buf).await?;
    send.finish()?;

    Ok(())
}

async fn handle_connection(conn: Connection, config: Arc<ProxyConfig>) {
    let peer_id = conn.remote_id();
    tracing::info!("New connection from peer: {}", peer_id);

    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let config_clone = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_bidi_stream(&mut send, &mut recv, &config_clone).await {
                        tracing::error!("Failed to handle stream from {}: {}", peer_id, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Connection {} stream accept error: {}", peer_id, e);
                break;
            }
        }
    }

    tracing::info!("Connection closed for peer: {}", peer_id);
}

async fn handle_incoming(incoming: Incoming, config: Arc<ProxyConfig>) {
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

async fn run_proxy(
    backend_routes: HashMap<String, String>,
    default_backend: String,
) -> anyhow::Result<()> {
    let config = Arc::new(ProxyConfig::new(backend_routes, default_backend));

    let ep = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_HTTP3.to_vec()])
        .bind()
        .await?;

    let node_id = ep.id();
    let node_addr = ep.addr();

    tracing::info!("Iroh proxy endpoint started successfully");
    tracing::info!("Node ID: {}", node_id);
    tracing::info!("Backend routes: {:?}", config.backend_routes);
    tracing::info!("Default backend: {}", config.default_backend);

    // 生成可分享的连接凭证
    let ticket = EndpointTicket::new(node_addr);
    let ticket_str = ticket.encode_string();

    println!("\n========================================");
    println!("Proxy Connection Information");
    println!("========================================");
    println!("Node ID: {}", node_id);
    println!("Ticket (for clients): {}", ticket_str);
    println!("========================================\n");

    tracing::info!("Connection ticket: {}", ticket_str);

    loop {
        match ep.accept().await {
            Some(incoming) => {
                let config_clone = config.clone();
                tokio::spawn(async move {
                    handle_incoming(incoming, config_clone).await;
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // 配置域名到后端的映射
    let mut backend_routes = HashMap::<String, String>::new();
    backend_routes.insert(
        "gw.iroh.iakl.top".to_string(),
        "http://127.0.0.1:9080".to_string(),
    );
    backend_routes.insert(
        "gw1.iroh.iakl.top".to_string(),
        "http://127.0.0.1:9081".to_string(),
    );
    backend_routes.insert(
        "*.iroh.iakl.top".to_string(),
        "http://127.0.0.1:9082".to_string(),
    ); // 通配符匹配

    // 默认后端
    let default_backend = "http://127.0.0.1:9080".to_string();

    tracing::info!("Starting proxy with domain-based routing");
    tracing::info!("Routes: {:?}", backend_routes);
    tracing::info!("Default: {}", default_backend);

    if let Err(e) = run_proxy(backend_routes, default_backend).await {
        tracing::error!("Proxy failed: {}", e);
        std::process::exit(1);
    }
}
