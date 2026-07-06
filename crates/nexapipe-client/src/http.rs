use std::collections::HashMap;
use ::http::Request;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    method: String,
    path: String,
    host: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: &str, path: &str, host: &str) -> Self {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            host: host.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", self.method, self.path).as_bytes());
        buf.extend_from_slice(format!("Host: {}\r\n", self.host).as_bytes());
        
        for (name, value) in &self.headers {
            buf.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }
        
        if !self.body.is_empty() {
            buf.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.body);
        buf
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    status_code: u16,
    status_text: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn parse(response: &[u8]) -> Result<Self, crate::error::ClientError> {
        let response_str = String::from_utf8_lossy(response);
        let mut lines = response_str.split("\r\n");

        let status_line = lines
            .next()
            .ok_or_else(|| crate::error::ClientError::ParseError("Missing status line".to_string()))?;

        let status_parts: Vec<&str> = status_line.split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err(crate::error::ClientError::ParseError("Invalid status line".to_string()));
        }

        let status_code = status_parts[1]
            .parse::<u16>()
            .map_err(|e| crate::error::ClientError::ParseError(format!("Invalid status code: {}", e)))?;

        let status_text = if status_parts.len() > 2 {
            status_parts[2..].join(" ")
        } else {
            String::new()
        };

        let mut headers = HashMap::new();
        let mut body_start = status_line.len() + 2;

        for line in lines {
            if line.is_empty() {
                body_start += 2;
                break;
            }
            body_start += line.len() + 2;
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_lowercase(), value.trim().to_string());
            }
        }

        let body = if body_start < response.len() {
            response[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(HttpResponse {
            status_code,
            status_text,
            headers,
            body,
        })
    }
}

pub fn parse_http_request_legacy(buf: &[u8]) -> Result<Request<()>, crate::error::ClientError> {
    let request_str = String::from_utf8_lossy(buf);
    let mut lines = request_str.split("\r\n");

    let request_line = lines
        .next()
        .ok_or_else(|| crate::error::ClientError::ParseError("Invalid HTTP request: missing request line".to_string()))?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(crate::error::ClientError::ParseError("Invalid HTTP request line".to_string()));
    }

    let method = http::Method::from_bytes(parts[0].as_bytes())
        .map_err(|e| crate::error::ClientError::ParseError(format!("Invalid HTTP method: {}", e)))?;
    let uri = http::Uri::try_from(parts[1]).map_err(|e| crate::error::ClientError::ParseError(format!("Invalid URI: {}", e)))?;

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
