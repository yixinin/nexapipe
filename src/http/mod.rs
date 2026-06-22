use anyhow::Result;
use http::{Request, Response};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

const MAX_REQUEST_SIZE: usize = 1024 * 1024;

pub async fn proxy_to_backend(
    req: &Request<()>,
    backend_url: &str,
    _verify_cert: bool,
) -> Result<Response<Vec<u8>>> {
    tracing::debug!(
        "Proxying request to backend: method={}, uri={}, backend={}",
        req.method(),
        req.uri(),
        backend_url
    );

    let url = Url::parse(backend_url)
        .map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);

    let is_https = url.scheme() == "https";
    tracing::debug!(
        "Backend connection: host={}, port={}, is_https={}",
        host,
        port,
        is_https
    );

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
        request_buf.extend_from_slice(name.as_str().as_bytes());
        request_buf.extend_from_slice(b": ");
        request_buf.extend_from_slice(value.as_bytes());
        request_buf.extend_from_slice(b"\r\n");
    }
    request_buf.extend_from_slice(b"\r\n");

    if is_https {
        use tokio_rustls::TlsConnector;
        
        tracing::debug!("Establishing HTTPS connection to {}:{}", host, port);
        let tcp_stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;
        tracing::debug!("TCP connection established");

        let mut root_certs = rustls::RootCertStore::empty();
        root_certs.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let host_str: &'static str = Box::leak(host.clone().into_boxed_str());
        let server_name = ServerName::try_from(host_str)
            .map_err(|e| anyhow::anyhow!("invalid server name: {}", e))?;

        tracing::debug!("Starting TLS handshake");
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;
        tracing::debug!("TLS handshake completed");

        tracing::debug!("Sending request to backend, size={}", request_buf.len());
        tls_stream.write_all(&request_buf).await?;

        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response).await?;
        tracing::debug!("Received response from backend, size={}", response.len());

        parse_http_response(&response)
    } else {
        tracing::debug!("Establishing HTTP connection to {}:{}", host, port);
        let mut tcp_stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to backend: {}", e))?;
        tracing::debug!("TCP connection established");

        tracing::debug!("Sending request to backend, size={}", request_buf.len());
        tcp_stream.write_all(&request_buf).await?;

        let mut response = Vec::new();
        tcp_stream.read_to_end(&mut response).await?;
        tracing::debug!("Received response from backend, size={}", response.len());

        parse_http_response(&response)
    }
}

pub fn parse_http_response(response: &[u8]) -> Result<Response<Vec<u8>>> {
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

pub fn parse_http_request(buf: &[u8]) -> Result<Request<()>> {
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

pub async fn send_response(
    send: &mut iroh::endpoint::SendStream,
    response: &Response<Vec<u8>>,
) -> Result<()> {
    let status = response.status();
    let status_text = status.canonical_reason().unwrap_or("Unknown");

    let mut response_buf = Vec::new();
    response_buf.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status_text).as_bytes());

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

pub fn get_max_request_size() -> usize {
    MAX_REQUEST_SIZE
}
