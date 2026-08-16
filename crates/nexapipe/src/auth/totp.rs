//! TOTP validation logic.

use super::config::{AuthConfig, TotpAlgorithm};
use totp_rs::{Algorithm, TOTP};

/// TOTP validator for verifying client codes
pub struct TotpValidator {
    config: AuthConfig,
}

impl TotpValidator {
    /// Create a new TOTP validator from config
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Get the TOTP algorithm from config
    fn get_algorithm(&self) -> Algorithm {
        match self.config.algorithm {
            TotpAlgorithm::SHA1 => Algorithm::SHA1,
            TotpAlgorithm::SHA256 => Algorithm::SHA256,
            TotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }

    /// Validate a TOTP code for a given client
    pub fn validate(&self, client_id: &str, code: &str) -> Result<bool, AuthError> {
        if !self.config.enabled {
            return Ok(true);
        }

        let client = self
            .config
            .clients
            .get(client_id)
            .ok_or(AuthError::ClientNotFound)?;

        if client.is_locked_out() {
            return Err(AuthError::LockedOut);
        }

        let secret = client
            .decode_secret()
            .map_err(|_| AuthError::InvalidSecret)?;

        let totp = TOTP::new(
            self.get_algorithm(),
            self.config.digits as usize,
            self.config.window as u8,
            self.config.time_step as u64,
            secret,
        )
        .map_err(|_| AuthError::TotpCreationFailed)?;

        let is_valid = totp.check_current(code).unwrap_or(false);

        Ok(is_valid)
    }

    /// Record a failed attempt for a client
    pub fn record_failure(&mut self, client_id: &str) {
        if let Some(client) = self.config.clients.get_mut(client_id) {
            client.record_failure(self.config.max_attempts, self.config.lockout_duration);
        }
    }

    /// Record a successful authentication
    pub fn record_success(&mut self, client_id: &str) {
        if let Some(client) = self.config.clients.get_mut(client_id) {
            client.record_success();
        }
    }

    /// Generate a new TOTP secret for a client (for setup)
    pub fn generate_secret() -> String {
        totp_rs::Secret::generate_secret().to_encoded().to_string()
    }
}

/// Authentication errors
#[derive(Debug, Clone)]
pub enum AuthError {
    ClientNotFound,
    InvalidSecret,
    TotpCreationFailed,
    LockedOut,
    InvalidCode,
    ProtocolError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::ClientNotFound => write!(f, "Client not found"),
            AuthError::InvalidSecret => write!(f, "Invalid secret configuration"),
            AuthError::TotpCreationFailed => write!(f, "Failed to create TOTP validator"),
            AuthError::LockedOut => {
                write!(f, "Client is locked out due to too many failed attempts")
            }
            AuthError::InvalidCode => write!(f, "Invalid TOTP code"),
            AuthError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}
