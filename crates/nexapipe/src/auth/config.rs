//! Configuration structures for 2FA authentication.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// TOTP algorithm variants
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
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

/// Main authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Whether 2FA is enabled
    #[serde(default)]
    pub enabled: bool,
    /// TOTP algorithm to use
    #[serde(default)]
    pub algorithm: TotpAlgorithm,
    /// Time step in seconds (default: 30)
    #[serde(default = "default_time_step")]
    pub time_step: u32,
    /// Number of digits in the TOTP code
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// Tolerance window (number of time steps to accept)
    #[serde(default = "default_window")]
    pub window: u32,
    /// Client configurations
    #[serde(default)]
    pub clients: HashMap<String, ClientAuth>,
    /// Maximum authentication attempts before lockout
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Lockout duration in seconds
    #[serde(default = "default_lockout_duration")]
    pub lockout_duration: u64,
}

fn default_time_step() -> u32 {
    30
}
fn default_digits() -> u32 {
    6
}
fn default_window() -> u32 {
    1
}
fn default_max_attempts() -> u32 {
    5
}
fn default_lockout_duration() -> u64 {
    300
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: TotpAlgorithm::default(),
            time_step: default_time_step(),
            digits: default_digits(),
            window: default_window(),
            clients: HashMap::new(),
            max_attempts: default_max_attempts(),
            lockout_duration: default_lockout_duration(),
        }
    }
}

/// Client authentication information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    /// Base32-encoded secret key
    pub secret: String,
    /// When this client was created
    #[serde(default = "default_created_at")]
    pub created_at: String,
    /// Last successful authentication time (Unix timestamp)
    #[serde(default)]
    pub last_used: Option<u64>,
    /// Number of failed attempts
    #[serde(default)]
    pub failed_attempts: u32,
    /// Lockout expiry time (Unix timestamp)
    #[serde(default)]
    pub locked_until: Option<u64>,
}

fn default_created_at() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

impl ClientAuth {
    /// Check if client is currently locked out
    pub fn is_locked_out(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now < locked_until
        } else {
            false
        }
    }

    /// Record a failed authentication attempt
    pub fn record_failure(&mut self, max_attempts: u32, lockout_duration: u64) {
        self.failed_attempts += 1;
        if self.failed_attempts >= max_attempts {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.locked_until = Some(now + lockout_duration);
        }
    }

    /// Reset failed attempts on successful authentication
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.locked_until = None;
        self.last_used = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
    }

    /// Decode the Base32 secret into bytes
    pub fn decode_secret(&self) -> Result<Vec<u8>, anyhow::Error> {
        base32::decode(base32::Alphabet::RFC4648 { padding: false }, &self.secret)
            .ok_or_else(|| anyhow::anyhow!("Invalid Base32 secret"))
    }
}
