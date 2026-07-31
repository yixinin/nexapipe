use crate::routes::{BackendInfo, RouteConfig};
use ::http::{Request, Response, StatusCode};
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use std::io::Write;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type HttpClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<bytes::Bytes>,
>;

pub fn create_http_client() -> HttpClient {
    let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(std::time::Duration::from_secs(30)));
    http_connector.enforce_http(false);

    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("no native root CA certificates found")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector);

    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Some(std::time::Duration::from_secs(120)))
        .http1_title_case_headers(true)
        .http1_ignore_invalid_headers_in_responses(true)
        .build(https)
}

const MAX_COMPRESS_SIZE: usize = 1024 * 1024;

pub async fn proxy_request(
    client: &HttpClient,
    req: Request<Incoming>,
    config: Arc<RouteConfig>,
    is_https: bool,
) -> Result<
    Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>>,
    anyhow::Error,
> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h))
        .ok_or_else(|| anyhow::anyhow!("Missing host header"))?;

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let accept_encoding = req
        .headers()
        .get("accept-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let headers_clone = req.headers().clone();
    let method = req.method().clone();

    let backend_info: BackendInfo = config.get_backend(host, path).await;

    if backend_info.redirect_to_https && !is_https {
        let redirect_url = format!("https://{}{}", host, path);
        tracing::debug!("Redirecting to HTTPS: {}", redirect_url);
        return Ok(create_redirect_response(&redirect_url));
    }

    let rewritten_path = if let Some(rewrite_pattern) = &backend_info.path_rewrite {
        if backend_info.path_is_prefix && path.starts_with(&backend_info.path_pattern) {
            let suffix = &path[backend_info.path_pattern.len()..];
            rewrite_pattern.replace("{}", suffix)
        } else if !backend_info.path_is_prefix && path == backend_info.path_pattern {
            rewrite_pattern.replace("{}", "")
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    };

    let backend_url = url::Url::parse(&backend_info.url)
        .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

    let backend_scheme = backend_url.scheme();
    let backend_host = backend_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Backend URL missing host"))?;
    let backend_port = backend_url.port_or_known_default().unwrap_or(80);

    let new_uri = format!(
        "{}://{}:{}{}",
        backend_scheme, backend_host, backend_port, rewritten_path
    )
    .parse::<http::Uri>()
    .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let body = req.into_body().collect().await?.to_bytes();

    let mut builder = Request::builder().method(method).uri(new_uri);

    for (name, value) in headers_clone.iter() {
        if name.as_str().to_lowercase() != "host" {
            builder = builder.header(name, value);
        }
    }
    builder = builder.header("host", backend_host);

    let proxied_req = builder.body(Full::new(body))?;

    tracing::debug!(
        "Proxying request: {} {} -> {}://{}:{}",
        proxied_req.method(),
        proxied_req.uri(),
        backend_scheme,
        backend_host,
        backend_port
    );

    let response = client.request(proxied_req).await?;

    let content_encoding = response.headers().get("content-encoding");
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok());

    if content_encoding.is_none() && should_compress(content_type) {
        if let Some(encodings) = accept_encoding {
            if encodings.contains("gzip") {
                return Ok(compress_response(response, "gzip").await);
            }
        }
    }

    Ok(response.map(|body| http_body_util::BodyExt::boxed_unsync(body)))
}

fn should_compress(content_type: Option<&str>) -> bool {
    if let Some(ct) = content_type {
        ct.starts_with("text/")
            || ct.contains("application/json")
            || ct.contains("application/javascript")
            || ct.contains("application/xml")
            || ct.contains("application/xhtml")
    } else {
        false
    }
}

async fn compress_response(
    response: Response<hyper::body::Incoming>,
    encoding: &str,
) -> Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>> {
    let (parts, body) = response.into_parts();

    if let Some(content_length) = parts.headers.get("content-length") {
        if let Ok(content_length_str) = content_length.to_str() {
            if let Ok(len) = content_length_str.parse::<usize>() {
                if len > MAX_COMPRESS_SIZE {
                    tracing::debug!("Response too large for compression: {} bytes", len);
                    return Response::from_parts(
                        parts,
                        http_body_util::BodyExt::boxed_unsync(body),
                    );
                }
            }
        }
    }

    let bytes = body.collect().await.unwrap().to_bytes();

    if bytes.len() > MAX_COMPRESS_SIZE {
        tracing::debug!("Response too large for compression: {} bytes", bytes.len());
        return Response::from_parts(
            parts,
            http_body_util::BodyExt::boxed_unsync(Full::new(bytes).map_err(|_| unreachable!())),
        );
    }

    let compressed_bytes = {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bytes).unwrap();
        encoder.finish().unwrap()
    };

    let mut new_parts = parts;
    new_parts.headers.remove("content-encoding");
    new_parts.headers.remove("content-length");
    new_parts
        .headers
        .insert("content-encoding", encoding.parse().unwrap());

    Response::from_parts(
        new_parts,
        http_body_util::BodyExt::boxed_unsync(
            Full::new(compressed_bytes.into()).map_err(|_| unreachable!()),
        ),
    )
}

pub fn create_error_response(
    status: StatusCode,
    message: &str,
) -> Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(http_body_util::BodyExt::boxed_unsync(
            Full::new(message.as_bytes().to_vec().into()).map_err(|_| unreachable!()),
        ))
        .unwrap()
}

pub fn create_redirect_response(
    url: &str,
) -> Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header("location", url)
        .header("content-type", "text/html")
        .body(http_body_util::BodyExt::boxed_unsync(
            Full::new(
                format!(
                    "<html><body>Redirecting to <a href=\"{}\">{}</a></body></html>",
                    url, url
                )
                .into_bytes()
                .into(),
            )
            .map_err(|_| unreachable!()),
        ))
        .unwrap()
}

pub fn is_websocket_request(req: &Request<Incoming>) -> bool {
    if let Some(upgrade) = req.headers().get("upgrade") {
        if let Ok(upgrade_str) = upgrade.to_str() {
            if upgrade_str.to_lowercase() == "websocket" {
                if let Some(connection) = req.headers().get("connection") {
                    if let Ok(connection_str) = connection.to_str() {
                        return connection_str.to_lowercase().contains("upgrade");
                    }
                }
            }
        }
    }
    false
}

pub fn is_websocket_request_static(req: &Request<()>) -> bool {
    if let Some(upgrade) = req.headers().get("upgrade") {
        if let Ok(upgrade_str) = upgrade.to_str() {
            if upgrade_str.to_lowercase() == "websocket" {
                if let Some(connection) = req.headers().get("connection") {
                    if let Ok(connection_str) = connection.to_str() {
                        return connection_str.to_lowercase().contains("upgrade");
                    }
                }
            }
        }
    }
    false
}

#[deprecated(note = "Use proxy_to_backend_streaming for large file support")]
pub async fn proxy_to_backend_using_client(
    client: &HttpClient,
    req: &Request<()>,
    backend_url: &str,
    body_data: Vec<u8>,
) -> Result<Response<Vec<u8>>, anyhow::Error> {
    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let new_uri = format!(
        "{}://{}:{}{}",
        url.scheme(), host, port, path
    )
    .parse::<http::Uri>()
    .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let mut builder = Request::builder().method(req.method()).uri(new_uri);

    for (name, value) in req.headers() {
        if name.as_str().to_lowercase() != "host" {
            builder = builder.header(name, value);
        }
    }
    builder = builder.header("host", host);

    let proxied_req = builder.body(Full::new(body_data.into()))?;

    tracing::debug!(
        "Proxying request via client: {} {}",
        proxied_req.method(),
        proxied_req.uri()
    );

    let response = client.request(proxied_req).await?;

    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();

    let mut builder = Response::builder().status(parts.status);
    for (name, value) in parts.headers.iter() {
        if name.as_str().to_lowercase() != "transfer-encoding" {
            builder = builder.header(name, value);
        }
    }
    builder = builder.header("content-length", bytes.len());

    Ok(builder.body(bytes.to_vec())?)
}

pub async fn proxy_to_backend_streaming(
    client: &HttpClient,
    req: &Request<()>,
    backend_url: &str,
    body_data: Vec<u8>,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<(), anyhow::Error> {
    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    let is_https = url.scheme() == "https";

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    if is_websocket_request_static(req) {
        tracing::debug!("WebSocket request detected, using direct TCP proxy");
        return if is_https {
            proxy_websocket_direct_https(send, recv, &req, &host, port).await
        } else {
            proxy_websocket_direct_http(send, recv, &req, &host, port).await
        };
    }

    let new_uri = format!(
        "{}://{}:{}{}",
        url.scheme(), host, port, path
    )
    .parse::<http::Uri>()
    .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let mut builder = Request::builder().method(req.method()).uri(new_uri);

    for (name, value) in req.headers() {
        if name.as_str().to_lowercase() != "host" {
            builder = builder.header(name, value);
        }
    }
    builder = builder.header("host", host);

    let mut full_body = body_data;
    if let Some(content_length) = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        read_remaining_request_body(recv, &mut full_body, content_length).await?;
    }

    let proxied_req = builder.body(Full::new(full_body.into()))?;

    tracing::debug!(
        "Proxying request via client (streaming): {} {}",
        proxied_req.method(),
        proxied_req.uri()
    );

    let response = client.request(proxied_req).await.map_err(|e| {
        tracing::error!("Failed to send request: {:?}", e);
        anyhow::anyhow!("failed to send request: {:?}", e)
    })?;

    let (parts, body) = response.into_parts();

    let status = parts.status;
    let status_text = status.canonical_reason().unwrap_or("Unknown");

    let mut response_buf = Vec::new();
    response_buf
        .extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status_text).as_bytes());

    let original_was_chunked = parts
        .headers
        .get("transfer-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|v| v.to_lowercase().contains("chunked"))
        .unwrap_or(false);
    let has_content_length = parts.headers.get("content-length").is_some();

    for (name, value) in parts.headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if name_lower == "transfer-encoding" {
            continue;
        }
        response_buf.extend_from_slice(name.as_str().as_bytes());
        response_buf.extend_from_slice(b": ");
        response_buf.extend_from_slice(value.as_bytes());
        response_buf.extend_from_slice(b"\r\n");
    }

    let use_chunked = !has_content_length && original_was_chunked;
    if use_chunked {
        response_buf.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    response_buf.extend_from_slice(b"\r\n");

    send.write_all(&response_buf).await?;

    let mut body_stream = http_body_util::BodyExt::into_data_stream(body);
    while let Some(chunk) = body_stream.next().await {
        match chunk {
            Ok(data) => {
                if use_chunked {
                    let size_line = format!("{:x}\r\n", data.len());
                    send.write_all(size_line.as_bytes()).await?;
                    send.write_all(&data).await?;
                    send.write_all(b"\r\n").await?;
                } else {
                    send.write_all(&data).await?;
                }
            }
            Err(e) => {
                tracing::debug!("Streaming response read error: {}", e);
                return Err(e.into());
            }
        }
    }

    if use_chunked {
        send.write_all(b"0\r\n\r\n").await?;
    }

    send.finish()?;

    Ok(())
}

async fn read_remaining_request_body(
    recv: &mut iroh::endpoint::RecvStream,
    body: &mut Vec<u8>,
    content_length: usize,
) -> Result<(), anyhow::Error> {
    let mut remaining = content_length.saturating_sub(body.len());
    let mut buf = [0u8; 8192];

    while remaining > 0 {
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read request body from iroh: {}", e))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "request body ended before content-length: expected {} bytes, got {}",
                    content_length,
                    body.len()
                )
            })?;

        let take = n.min(remaining);
        body.extend_from_slice(&buf[..take]);
        remaining -= take;
    }

    tracing::debug!(
        "Read request body from iroh: {} bytes (content-length {})",
        body.len(),
        content_length
    );
    Ok(())
}

async fn proxy_websocket_direct_http(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    req: &Request<()>,
    host: &str,
    port: u16,
) -> Result<(), anyhow::Error> {
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

    let tcp_stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;

    let (mut backend_read, mut backend_write) = tokio::io::split(tcp_stream);

    backend_write.write_all(&request_buf).await?;

    let mut response_buf = Vec::new();
    let mut line_buf = Vec::new();
    let mut in_body = false;
    let mut response_sent = false;

    loop {
        let mut buf = [0u8; 1];
        let n = backend_read.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        if !in_body {
            line_buf.push(buf[0]);
            if line_buf.ends_with(b"\r\n") {
                if line_buf == b"\r\n" {
                    in_body = true;
                    response_buf.extend_from_slice(b"\r\n");
                    send.write_all(&response_buf).await?;
                    response_sent = true;
                } else {
                    response_buf.extend_from_slice(&line_buf);
                }
                line_buf.clear();
            }
        } else {
            break;
        }
    }

    if !response_sent {
        send.write_all(&response_buf).await?;
    }

    let iroh_to_backend = async {
        let mut buf = [0u8; 8192];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => {
                    tracing::debug!("Iroh recv stream closed");
                    break;
                }
                Ok(Some(n)) => {
                    tracing::debug!("Received {} bytes from iroh", n);
                    if let Err(e) = backend_write.write_all(&buf[..n]).await {
                        tracing::debug!("Iroh to backend write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Iroh read error: {}", e);
                    break;
                }
            }
        }
    };

    let backend_to_iroh = async {
        let mut buf = [0u8; 8192];
        loop {
            match backend_read.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!("Backend stream closed");
                    break;
                }
                Ok(n) => {
                    tracing::debug!("Received {} bytes from backend", n);
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        tracing::debug!("Backend to iroh write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Backend read error: {}", e);
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = iroh_to_backend => (),
        _ = backend_to_iroh => (),
    }

    Ok(())
}

async fn proxy_websocket_direct_https(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    req: &Request<()>,
    host: &str,
    port: u16,
) -> Result<(), anyhow::Error> {
    use tokio_rustls::TlsConnector;

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

    let tcp_stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;

    let mut root_certs = rustls::RootCertStore::empty();
    root_certs.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_certs)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let host_str: &'static str = Box::leak(host.to_string().into_boxed_str());
    let server_name = rustls_pki_types::ServerName::try_from(host_str)
        .map_err(|e| anyhow::anyhow!("invalid server name: {}", e))?;

    let tls_stream = connector.connect(server_name, tcp_stream).await?;

    let (mut backend_read, mut backend_write) = tokio::io::split(tls_stream);

    backend_write.write_all(&request_buf).await?;

    let mut response_buf = Vec::new();
    let mut line_buf = Vec::new();
    let mut in_body = false;
    let mut response_sent = false;

    loop {
        let mut buf = [0u8; 1];
        let n = backend_read.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        if !in_body {
            line_buf.push(buf[0]);
            if line_buf.ends_with(b"\r\n") {
                if line_buf == b"\r\n" {
                    in_body = true;
                    response_buf.extend_from_slice(b"\r\n");
                    send.write_all(&response_buf).await?;
                    response_sent = true;
                } else {
                    response_buf.extend_from_slice(&line_buf);
                }
                line_buf.clear();
            }
        } else {
            break;
        }
    }

    if !response_sent {
        send.write_all(&response_buf).await?;
    }

    let iroh_to_backend = async {
        let mut buf = [0u8; 8192];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => {
                    tracing::debug!("Iroh recv stream closed");
                    break;
                }
                Ok(Some(n)) => {
                    tracing::debug!("Received {} bytes from iroh", n);
                    if let Err(e) = backend_write.write_all(&buf[..n]).await {
                        tracing::debug!("Iroh to backend write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Iroh read error: {}", e);
                    break;
                }
            }
        }
    };

    let backend_to_iroh = async {
        let mut buf = [0u8; 8192];
        loop {
            match backend_read.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!("Backend stream closed");
                    break;
                }
                Ok(n) => {
                    tracing::debug!("Received {} bytes from backend", n);
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        tracing::debug!("Backend to iroh write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Backend read error: {}", e);
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = iroh_to_backend => (),
        _ = backend_to_iroh => (),
    }

    Ok(())
}

pub async fn proxy_to_backend_legacy(
    req: &Request<()>,
    backend_url: &str,
    _verify_cert: bool,
) -> Result<Response<Vec<u8>>, anyhow::Error> {
    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);

    let is_https = url.scheme() == "https";

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
        if name.as_str().to_lowercase() == "connection" {
            continue;
        }
        request_buf.extend_from_slice(name.as_str().as_bytes());
        request_buf.extend_from_slice(b": ");
        request_buf.extend_from_slice(value.as_bytes());
        request_buf.extend_from_slice(b"\r\n");
    }
    request_buf.extend_from_slice(b"Connection: close\r\n");
    request_buf.extend_from_slice(b"\r\n");

    if is_https {
        use tokio_rustls::TlsConnector;

        let tcp_stream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;

        let mut root_certs = rustls::RootCertStore::empty();
        root_certs.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let host_str: &'static str = Box::leak(host.clone().into_boxed_str());
        let server_name = rustls_pki_types::ServerName::try_from(host_str)
            .map_err(|e| anyhow::anyhow!("invalid server name: {}", e))?;

        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        use tokio::io::AsyncWriteExt;
        tls_stream.write_all(&request_buf).await?;

        let mut response = Vec::new();
        use tokio::io::AsyncReadExt;
        tls_stream.read_to_end(&mut response).await?;

        parse_http_response_legacy(&response)
    } else {
        let mut tcp_stream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;

        use tokio::io::AsyncWriteExt;
        tcp_stream.write_all(&request_buf).await?;

        let mut response = Vec::new();
        use tokio::io::AsyncReadExt;
        tcp_stream.read_to_end(&mut response).await?;

        parse_http_response_legacy(&response)
    }
}

pub fn parse_http_response_legacy(response: &[u8]) -> Result<Response<Vec<u8>>, anyhow::Error> {
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

    let mut builder = Response::builder().status(status_code);

    let mut body_start = status_line.len() + 2;
    for line in lines {
        if line.is_empty() {
            body_start += 2;
            break;
        }
        body_start += line.len() + 2;
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    let body = if body_start < response.len() {
        response[body_start..].to_vec()
    } else {
        Vec::new()
    };

    Ok(builder.body(body)?)
}

pub fn parse_http_request_legacy(buf: &[u8]) -> Result<Request<()>, anyhow::Error> {
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

    let mut builder = Request::builder().method(method).uri(uri);

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

pub async fn send_response_legacy(
    send: &mut iroh::endpoint::SendStream,
    response: &Response<Vec<u8>>,
) -> Result<(), anyhow::Error> {
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
