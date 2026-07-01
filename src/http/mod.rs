use crate::routes::{BackendInfo, RouteConfig};
use ::http::{Request, Response, StatusCode};
use flate2::Compression;
use flate2::write::GzEncoder;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use std::io::Write;
use std::sync::Arc;

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
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Some(std::time::Duration::from_secs(60)))
        .http1_title_case_headers(true)
        .http1_ignore_invalid_headers_in_responses(true)
        .build(https)
}

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
    let bytes = body.collect().await.unwrap().to_bytes();

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
