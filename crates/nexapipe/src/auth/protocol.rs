//! Authentication protocol for client-server handshake.
//!
//! Protocol flow:
//! 1. Client -> Server: AUTH_START { client_id, timestamp }
//! 2. Server -> Client: AUTH_CHALLENGE { nonce }
//! 3. Client -> Server: AUTH_RESPONSE { client_id, timestamp, totp_code }
//! 4. Server -> Client: AUTH_OK | AUTH_FAILED { reason }

use serde::{Deserialize, Serialize};

/// Messages exchanged during authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMessage {
    /// Client initiates authentication
    #[serde(rename = "AUTH_START")]
    Start { client_id: String, timestamp: i64 },
    /// Server sends challenge nonce
    #[serde(rename = "AUTH_CHALLENGE")]
    Challenge { nonce: Vec<u8> },
    /// Client responds with TOTP code
    #[serde(rename = "AUTH_RESPONSE")]
    Response {
        client_id: String,
        timestamp: i64,
        totp_code: String,
    },
    /// Server confirms authentication success
    #[serde(rename = "AUTH_OK")]
    Ok,
    /// Server rejects authentication
    #[serde(rename = "AUTH_FAILED")]
    Failed { reason: String },
}

impl AuthMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Authentication state for a connection
#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    /// Not yet authenticated
    Unauthenticated,
    /// Authentication in progress
    InProgress { client_id: String, nonce: Vec<u8> },
    /// Successfully authenticated
    Authenticated { client_id: String },
    /// Authentication failed
    Failed { reason: String },
}

impl AuthState {
    /// Check if we can proceed with proxying
    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthState::Authenticated { .. })
    }

    /// Get client ID if authenticated
    pub fn client_id(&self) -> Option<&str> {
        match self {
            AuthState::Authenticated { client_id } => Some(client_id),
            _ => None,
        }
    }
}
