//! TOTP validation logic.

use super::config::{AuthConfig, TotpAlgorithm};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use totp_rs::{Algorithm, TOTP};

/// HMAC-SHA256 keyed by the client's TOTP secret.
type HmacSha256 = Hmac<Sha256>;

/// How far an AUTH_RESPONSE timestamp may sit from the server clock, in
/// seconds. The signature already pins the response to one challenge; the
/// timestamp bounds how long even a correctly signed response stays
/// acceptable, so an intercepted one cannot be replayed next week.
const TIMESTAMP_WINDOW_SECS: i64 = 30;

/// TOTP validator for verifying client codes.
///
/// Borrows the [`AuthConfig`] it validates against: the config is shared and
/// mutated by the connection layer (lockout counters), so owning a clone here
/// would both copy the whole client map per connection and validate against a
/// snapshot nobody can correct.
pub struct TotpValidator<'a> {
    config: &'a AuthConfig,
}

impl<'a> TotpValidator<'a> {
    /// Create a new TOTP validator borrowing the given config.
    pub fn new(config: &'a AuthConfig) -> Self {
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

    /// Verifies one AUTH_RESPONSE against the challenge this connection
    /// issued.
    ///
    /// Everything a response must prove is checked here, in order: the client
    /// is known and not locked out, its secret decodes, its timestamp is
    /// fresh, its signature matches HMAC-SHA256(secret, nonce || timestamp),
    /// and finally the TOTP code is current. Only the last step can return
    /// `Ok(false)`: a wrong code is a user mistake and counts toward the
    /// lockout, while every `Err` is a refusal the caller logs instead of
    /// counting.
    pub fn verify_response(
        &self,
        client_id: &str,
        nonce: &[u8],
        timestamp: i64,
        signature: &[u8],
        code: &str,
    ) -> Result<bool, AuthError> {
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

        let now = current_timestamp();
        if (now - timestamp).abs() > TIMESTAMP_WINDOW_SECS {
            return Err(AuthError::StaleTimestamp);
        }

        let expected = hmac_signature(&secret, nonce, timestamp);
        if !constant_time_eq(signature, &expected) {
            return Err(AuthError::ChallengeMismatch);
        }

        let totp = TOTP::new(
            self.get_algorithm(),
            self.config.digits as usize,
            self.config.window as u8,
            self.config.time_step as u64,
            secret,
        )
        .map_err(|_| AuthError::TotpCreationFailed)?;

        Ok(totp.check_current(code).unwrap_or(false))
    }

    /// Generate a new TOTP secret for a client (for setup)
    pub fn generate_secret() -> String {
        totp_rs::Secret::generate_secret().to_encoded().to_string()
    }
}

/// The signature a client attaches to AUTH_RESPONSE:
/// HMAC-SHA256(secret, nonce || timestamp.to_le_bytes()).
///
/// Keep in sync with `TwoFactorAuth::sign_challenge` in
/// `crates/nexapipe-client/src/auth.rs`.
pub(crate) fn hmac_signature(secret: &[u8], nonce: &[u8], timestamp: i64) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(&timestamp.to_le_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Length-safe constant-time comparison: an HMAC-SHA256 tag is never secret
/// in length (32 bytes), but comparing it byte-wise stops the first mismatch
/// from leaking how many leading bytes were right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Authentication errors
#[derive(Debug, Clone)]
pub enum AuthError {
    ClientNotFound,
    InvalidSecret,
    TotpCreationFailed,
    LockedOut,
    InvalidCode,
    /// The response timestamp sits outside the acceptance window.
    StaleTimestamp,
    /// The response signature does not match the challenge that was issued.
    ChallengeMismatch,
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
            AuthError::StaleTimestamp => write!(
                f,
                "Response timestamp is more than {TIMESTAMP_WINDOW_SECS}s away from the server clock"
            ),
            AuthError::ChallengeMismatch => {
                write!(f, "Response signature does not match the challenge")
            }
            AuthError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}
