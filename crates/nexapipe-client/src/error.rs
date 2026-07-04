use std::fmt;

#[derive(Debug)]
pub enum ClientError {
    ConnectionError(String),
    ParseError(String),
    SendError(String),
    ReceiveError(String),
    TimeoutError,
    InvalidConfig(String),
    IoError(std::io::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            ClientError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            ClientError::SendError(msg) => write!(f, "Send error: {}", msg),
            ClientError::ReceiveError(msg) => write!(f, "Receive error: {}", msg),
            ClientError::TimeoutError => write!(f, "Operation timed out"),
            ClientError::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
            ClientError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::IoError(e)
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

impl From<http::Error> for ClientError {
    fn from(e: http::Error) -> Self {
        ClientError::ParseError(e.to_string())
    }
}
