use std::fmt;
use std::sync::Arc;

/// The errors this crate reports.
///
/// **`Clone` is load-bearing.** The connection pool shares one dial between
/// everything that asked for a connection while it was in progress, and a
/// shared result has to be clonable — so the one variant that could not be
/// cloned holds its `io::Error` behind an `Arc`.
///
/// That is the only reason the variant is boxed. Nothing else about it
/// changed, and a caller that matches on it sees the same thing it always
/// did.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
// `flat_error`: only `Display` crosses the boundary. `IoError(Arc<std::io::Error>)`
// is not a uniffi type, so the variants cannot be lowered structurally.
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum ClientError {
    ConnectionError(String),
    ConnectionFailed(String),
    AuthenticationFailed(String),
    ParseError(String),
    SendError(String),
    ReceiveError(String),
    TimeoutError,
    InvalidConfig(String),
    IoError(Arc<std::io::Error>),
    Other(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            ClientError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            ClientError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            ClientError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            ClientError::SendError(msg) => write!(f, "Send error: {}", msg),
            ClientError::ReceiveError(msg) => write!(f, "Receive error: {}", msg),
            ClientError::TimeoutError => write!(f, "Operation timed out"),
            ClientError::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
            ClientError::IoError(e) => write!(f, "IO error: {}", e),
            ClientError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::IoError(Arc::new(e))
    }
}

impl From<anyhow::Error> for ClientError {
    fn from(e: anyhow::Error) -> Self {
        ClientError::ConnectionError(e.to_string())
    }
}

impl From<iroh::endpoint::WriteError> for ClientError {
    fn from(e: iroh::endpoint::WriteError) -> Self {
        ClientError::SendError(e.to_string())
    }
}

impl From<iroh::endpoint::ReadError> for ClientError {
    fn from(e: iroh::endpoint::ReadError) -> Self {
        ClientError::ReceiveError(e.to_string())
    }
}

impl From<http::Error> for ClientError {
    fn from(e: http::Error) -> Self {
        ClientError::ParseError(e.to_string())
    }
}
