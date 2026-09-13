// 2FA authentication module for Nexapipe client.
//
// Provides TOTP code generation and authentication handshake.

use crate::ClientError;
use iroh::endpoint::Connection;
use totp_rs::{Algorithm, Secret, TOTP};

/// TOTP algorithm variants
#[derive(Debug, Clone, PartialEq)]
pub enum TotpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl Default for TotpAlgorithm {
    fn default() -> Self {
        TotpAlgorithm::SHA1
    }
}

impl TotpAlgorithm {
    fn to_totp_rs(&self) -> Algorithm {
        match self {
            TotpAlgorithm::SHA1 => Algorithm::SHA1,
            TotpAlgorithm::SHA256 => Algorithm::SHA256,
            TotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }

    /// Parse an algorithm name from configuration / UI (case-insensitive).
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "sha256" => TotpAlgorithm::SHA256,
            "sha512" => TotpAlgorithm::SHA512,
            _ => TotpAlgorithm::SHA1,
        }
    }

    /// Canonical lowercase algorithm name for config / UI.
    pub fn name(&self) -> &'static str {
        match self {
            TotpAlgorithm::SHA1 => "sha1",
            TotpAlgorithm::SHA256 => "sha256",
            TotpAlgorithm::SHA512 => "sha512",
        }
    }
}

/// Client-side 2FA credentials loaded from config file / app settings.
#[derive(Debug, Clone, PartialEq)]
pub struct TwoFactorConfig {
    pub client_id: String,
    pub secret: String,
    pub algorithm: TotpAlgorithm,
}

impl TwoFactorConfig {
    /// Build a [`TwoFactorAuth`] if a secret is configured; returns `Ok(None)`
    /// when the secret is empty (2FA effectively disabled).
    pub fn to_auth(&self) -> Result<Option<TwoFactorAuth>, ClientError> {
        if self.secret.trim().is_empty() {
            return Ok(None);
        }
        TwoFactorAuth::new(&self.client_id, &self.secret, self.algorithm.clone()).map(Some)
    }
}

/// Client-side 2FA authenticator
#[derive(Debug, Clone)]
pub struct TwoFactorAuth {
    client_id: String,
    secret: Vec<u8>,
    algorithm: TotpAlgorithm,
    time_step: u32,
    digits: u32,
}

impl TwoFactorAuth {
    /// Create a new 2FA authenticator
    pub fn new(
        client_id: &str,
        secret_base32: &str,
        algorithm: TotpAlgorithm,
    ) -> Result<Self, ClientError> {
        let secret = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret_base32)
            .ok_or_else(|| ClientError::InvalidConfig("Invalid Base32 secret".to_string()))?;

        Ok(Self {
            client_id: client_id.to_string(),
            secret,
            algorithm,
            time_step: 30,
            digits: 6,
        })
    }

    /// Create with custom time step and digits
    pub fn with_params(
        client_id: &str,
        secret_base32: &str,
        algorithm: TotpAlgorithm,
        time_step: u32,
        digits: u32,
    ) -> Result<Self, ClientError> {
        let secret = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret_base32)
            .ok_or_else(|| ClientError::InvalidConfig("Invalid Base32 secret".to_string()))?;

        Ok(Self {
            client_id: client_id.to_string(),
            secret,
            algorithm,
            time_step,
            digits,
        })
    }

    /// Generate current TOTP code
    pub fn generate_code(&self) -> Result<String, ClientError> {
        let totp = TOTP::new(
            self.algorithm.to_totp_rs(),
            self.digits as usize,
            0,
            self.time_step as u64,
            self.secret.clone(),
        )
        .map_err(|e| ClientError::Other(format!("Failed to create TOTP: {}", e)))?;

        totp.generate_current()
            .map_err(|e| ClientError::Other(format!("Failed to generate TOTP code: {}", e)))
    }

    /// Get client ID
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Authenticate with the server over a connection
    pub async fn authenticate(&self, conn: &Connection) -> Result<(), ClientError> {
        use crate::auth::auth_protocol::AuthMessage;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to open stream: {}", e)))?;

        // Step 1: Send AUTH_START
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let start_msg = AuthMessage::Start {
            client_id: self.client_id.clone(),
            timestamp,
        };

        let start_bytes = start_msg
            .to_bytes()
            .map_err(|e| ClientError::Other(format!("Serialization error: {}", e)))?;

        // Send message length + message
        let len = start_bytes.len() as u32;
        send.write_all(&len.to_le_bytes())
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send length: {}", e)))?;
        send.write_all(&start_bytes)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send message: {}", e)))?;

        // Step 2: Receive AUTH_CHALLENGE
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to read length: {}", e)))?;
        let msg_len = u32::from_le_bytes(len_buf) as usize;

        let mut msg_buf = vec![0u8; msg_len];
        recv.read_exact(&mut msg_buf)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to read message: {}", e)))?;

        let challenge_msg = AuthMessage::from_bytes(&msg_buf)
            .map_err(|e| ClientError::Other(format!("Deserialization error: {}", e)))?;

        let _nonce = match challenge_msg {
            AuthMessage::Challenge { nonce } => nonce,
            _ => return Err(ClientError::Other("Expected AUTH_CHALLENGE".to_string())),
        };

        // Step 3: Generate and send AUTH_RESPONSE
        let totp_code = self.generate_code()?;

        let response_msg = AuthMessage::Response {
            client_id: self.client_id.clone(),
            timestamp,
            totp_code,
        };

        let response_bytes = response_msg
            .to_bytes()
            .map_err(|e| ClientError::Other(format!("Serialization error: {}", e)))?;

        let len = response_bytes.len() as u32;
        send.write_all(&len.to_le_bytes())
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send length: {}", e)))?;
        send.write_all(&response_bytes)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send message: {}", e)))?;
        send.finish().map_err(|e| {
            ClientError::ConnectionFailed(format!("Failed to finish stream: {}", e))
        })?;

        // Step 4: Receive AUTH_OK or AUTH_FAILED
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to read length: {}", e)))?;
        let msg_len = u32::from_le_bytes(len_buf) as usize;

        let mut msg_buf = vec![0u8; msg_len];
        recv.read_exact(&mut msg_buf)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to read message: {}", e)))?;

        let result_msg = AuthMessage::from_bytes(&msg_buf)
            .map_err(|e| ClientError::Other(format!("Deserialization error: {}", e)))?;

        match result_msg {
            AuthMessage::Ok => Ok(()),
            AuthMessage::Failed { reason } => Err(ClientError::AuthenticationFailed(reason)),
            _ => Err(ClientError::Other("Unexpected response".to_string())),
        }
    }
}

/// Generate a new secret for client setup
pub fn generate_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

/// Protocol messages for authentication handshake
pub mod auth_protocol {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type")]
    pub enum AuthMessage {
        #[serde(rename = "AUTH_START")]
        Start { client_id: String, timestamp: i64 },
        #[serde(rename = "AUTH_CHALLENGE")]
        Challenge { nonce: Vec<u8> },
        #[serde(rename = "AUTH_RESPONSE")]
        Response {
            client_id: String,
            timestamp: i64,
            totp_code: String,
        },
        #[serde(rename = "AUTH_OK")]
        Ok,
        #[serde(rename = "AUTH_FAILED")]
        Failed { reason: String },
    }

    impl AuthMessage {
        pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(self)
        }

        pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
            serde_json::from_slice(bytes)
        }
    }
}
