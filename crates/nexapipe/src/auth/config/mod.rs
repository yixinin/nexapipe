//! Configuration structures for 2FA authentication.
//!
//! It is the configuration itself and four things that hang off it:
//!
//! - `client` — the credentials a client holds.
//! - `device` — the credentials a device holds, which prove themselves
//!   without a human present.
//! - `step` — the rule about a TOTP step being used twice, which both of
//!   them apply.
//! - `acl` — which hosts a client may reach once it has authenticated.
//!
//! This one holds the configuration, and what the others share.

mod acl;
mod client;
mod device;
mod step;

#[cfg(test)]
mod tests;

use nexapipe_proto::secret::{SecretBytes, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub use acl::ClientAcl;
pub use client::ClientAuth;
pub use device::{DeviceAuth, DeviceMaterial};
pub use step::StepVerdict;

/// TOTP algorithm variants
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TotpAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl TotpAlgorithm {
    /// Canonical lowercase name, as used by `[auth] algorithm`, the clients and
    /// the `otpauth://` URI.
    pub fn name(&self) -> &'static str {
        match self {
            TotpAlgorithm::SHA1 => "sha1",
            TotpAlgorithm::SHA256 => "sha256",
            TotpAlgorithm::SHA512 => "sha512",
        }
    }
}

impl From<&TotpAlgorithm> for nexapipe_proto::auth::Algorithm {
    /// The algorithm as it travels.
    ///
    /// The configuration has its own spelling of the three algorithms and the
    /// wire has its own, and this is where the two meet: the wire's is a
    /// closed type, so a name that is not one of the three cannot be put on
    /// it at all.
    fn from(algorithm: &TotpAlgorithm) -> Self {
        match algorithm {
            TotpAlgorithm::SHA1 => nexapipe_proto::auth::Algorithm::Sha1,
            TotpAlgorithm::SHA256 => nexapipe_proto::auth::Algorithm::Sha256,
            TotpAlgorithm::SHA512 => nexapipe_proto::auth::Algorithm::Sha512,
        }
    }
}

/// Main authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Whether 2FA is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Issuer label shown by authenticator apps that import the enrollment QR
    /// code produced by `nexapipe --generate-2fa`
    #[serde(default = "default_issuer")]
    pub issuer: String,
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

fn default_issuer() -> String {
    crate::auth::otpauth::DEFAULT_ISSUER.to_string()
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

/// Whether a peer that names no device may still answer with this client's own
/// `secret`.
///
/// `true` by default, because that is the only spelling a client that predates
/// the device table can authenticate under, and turning it off without having
/// enrolled every device would lock out the ones that never named themselves.
fn default_unnamed_device_allowed() -> bool {
    true
}

fn default_lockout_duration() -> u64 {
    300
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: default_issuer(),
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

/// Shared with the loader in `crates/nexapipe/src/config/auth_file.rs`, which
/// fills in the same "issued now" for a client or a device the file does not
/// date.
pub(crate) fn default_created_at() -> String {
    unix_now().to_string()
}

impl AuthConfig {
    /// A copy carrying only the counters the config file is written back to.
    ///
    /// The whole config used to be cloned on every attempt worth counting, and
    /// a clone copies every client's secret and enrollment token with it — once
    /// per wrong code, from any peer that can name a client id. Only
    /// `failed_attempts`, `locked_until`, `enrollment_failed_attempts`,
    /// `enrollment_locked_until`, `last_used`, `last_used_step` and each
    /// device's `last_used` and `last_used_step` are persisted, so only those
    /// travel. Extend this alongside `save_auth_state`, or a field added there
    /// is silently written as empty.
    pub fn counter_snapshot(&self) -> AuthConfig {
        AuthConfig {
            enabled: self.enabled,
            issuer: String::new(),
            algorithm: self.algorithm.clone(),
            time_step: self.time_step,
            digits: self.digits,
            window: self.window,
            clients: self
                .clients
                .iter()
                .map(|(id, client)| {
                    (
                        id.clone(),
                        ClientAuth {
                            secret: SecretString::default(),
                            created_at: String::new(),
                            allow_hosts: None,
                            allow_ports: None,
                            allow_ports_strict: false,
                            // The pending token travels, and only the pending
                            // token: the state file records which token the
                            // enrollment counters were paid for, and it computes
                            // that from the token itself. The secret above is
                            // blanked, and neither of the two ever reaches the
                            // file — the state file writes a digest.
                            pending_enrollment: client.pending_enrollment.clone(),
                            // Names and stamps only. A snapshot exists so a
                            // wrong code does not copy a credential, and every
                            // device secret is one — so a device travels with
                            // its secret emptied and everything else blank,
                            // and `save_auth_state` writes back the one field
                            // a connection can change: `last_used`. A public
                            // key is not a secret, but it is the other half of
                            // a credential and no counter either, so it is
                            // dropped with everything else.
                            devices: client
                                .devices
                                .iter()
                                .map(|(name, device)| {
                                    (
                                        name.clone(),
                                        DeviceAuth {
                                            secret: SecretString::default(),
                                            public_key: None,
                                            created_at: String::new(),
                                            last_used: device.last_used,
                                            last_used_step: device.last_used_step,
                                        },
                                    )
                                })
                                .collect(),
                            // Not a counter, and not one of the per-device
                            // stamps either: a snapshot is only ever spent
                            // writing the fields above, so carrying this cannot
                            // change what a reload sees even though it travels.
                            unnamed_device_allowed: client.unnamed_device_allowed,
                            last_used: client.last_used,
                            last_used_step: client.last_used_step,
                            failed_attempts: client.failed_attempts,
                            locked_until: client.locked_until,
                            enrollment_failed_attempts: client.enrollment_failed_attempts,
                            enrollment_locked_until: client.enrollment_locked_until,
                        },
                    )
                })
                .collect(),
            max_attempts: self.max_attempts,
            lockout_duration: self.lockout_duration,
        }
    }
    /// Whether this step may be used by this credential, and the memory that
    /// goes with the answer.
    ///
    /// The credential is the one the code was checked against: the named
    /// device, or the client's own secret for the unnamed device. They are
    /// different credentials, and a step accepted for one says nothing about
    /// the other — so the memory is kept apart as well.
    ///
    /// The rule: a step that is **behind** the last accepted one has been used
    /// already. The same step again is allowed — a client that opens several
    /// connections in the same step sends the same code for each of them.
    pub fn accept_step(
        &mut self,
        client_id: &str,
        device_id: Option<&str>,
        step: u64,
    ) -> StepVerdict {
        let Some(client) = self.clients.get_mut(client_id) else {
            // The client was checked before this, so it cannot be gone. If it
            // were, refusing is the safe direction.
            return StepVerdict::Refused;
        };
        match device_id {
            Some(name) => match client.devices.get_mut(name) {
                Some(device) => device.accept_step(step),
                // The device was checked before this too.
                None => StepVerdict::Refused,
            },
            None => client.accept_step(step),
        }
    }

    /// Whether the file holds a 2FA secret that nothing else protects.
    ///
    /// A client's seed, or a device's. A device that proves itself with a
    /// signature has no seed, and its entry holds nothing but a public key —
    /// so it is not one of these.
    ///
    /// This is the credential the config file's own permission is all that
    /// stands between: anybody who can read the file can generate a valid
    /// code. See [`crate::config::warn_about_readable_credentials`].
    pub fn holds_inline_secrets(&self) -> bool {
        self.clients.values().any(|client| {
            !client.secret.as_str().is_empty()
                || client
                    .devices
                    .values()
                    .any(|device| !device.secret.as_str().is_empty())
        })
    }
}

/// Checks every seed in the configuration.
///
/// The decode is lazy: a seed is read when a connection proves itself, and
/// the TOTP library refuses a seed under 128 bits when it builds the
/// validator. So without this, a seed that cannot work is found at the
/// operator's first login — long after it was accepted, handed out in an
/// enrollment URI and written down — and it is found as a failed
/// authentication rather than as the configuration error it is.
///
/// A seed that is empty is not a seed: a client with no secret of its own
/// answers with the device's, and a device that proves itself with a
/// signature carries no seed at all.
pub fn validate_seeds(config: &AuthConfig) -> anyhow::Result<()> {
    for (client_id, client) in &config.clients {
        if !client.secret.as_str().is_empty() {
            decode_base32_secret(client.secret.as_str()).map_err(|reason| {
                anyhow::anyhow!("the seed of client {client_id:?} is not usable: {reason}")
            })?;
        }
        for (device, entry) in &client.devices {
            if !entry.secret.as_str().is_empty() {
                decode_base32_secret(entry.secret.as_str()).map_err(|reason| {
                    anyhow::anyhow!(
                        "the seed of device {device:?} of client {client_id:?} is not usable: {reason}"
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Decodes a stored Base32 secret, shared by [`ClientAuth`] and
/// [`DeviceAuth`].
///
/// The stored spelling is normalised first. An invite puts the secret through
/// `otpauth::normalize_secret`, which tolerates lower case and `=` padding, so
/// a secret written either of those ways in the config has to work as well —
/// otherwise it fails to decode here and the client is stuck at "Invalid
/// Base32 secret" with nothing saying the spelling is why.
fn decode_base32_secret(stored: &str) -> Result<SecretBytes, anyhow::Error> {
    // The normalised spelling is a copy of the seed in the clear, so it is
    // held in a `Secret`: it is wiped when this function returns rather than
    // being left in the heap for the allocator to hand out again.
    let secret = crate::auth::otpauth::normalize_secret(stored)
        .ok_or_else(|| anyhow::anyhow!("Invalid Base32 secret"))?;
    let decoded = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        secret.as_str(),
    )
    .ok_or_else(|| anyhow::anyhow!("Invalid Base32 secret"))?;
    // A seed that decodes to nothing is a challenge keyed with an empty key,
    // and one that decodes to a handful of bytes is a challenge anybody can
    // brute force. The TOTP library refuses such a seed when the validator is
    // built, which is at the operator's first login: the seed is refused here
    // instead, at the start, where the operator is told why.
    if decoded.len() < crate::auth::otpauth::MIN_SECRET_BYTES {
        anyhow::bail!(
            "the seed decodes to {} byte{}; a TOTP secret is at least {} bytes",
            decoded.len(),
            if decoded.len() == 1 { "" } else { "s" },
            crate::auth::otpauth::MIN_SECRET_BYTES
        );
    }
    Ok(SecretBytes::new(decoded))
}

/// Seconds since the Unix epoch.
///
/// The fallible `SystemTime` dance is centralised here so the lockout rules
/// below read as arithmetic; a clock before 1970 is treated as 0, which only
/// means "long ago" to every comparison made with it.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A fresh one-time enrollment token: 32 random bytes, hex-encoded.
///
/// Wide enough that guessing one is not a strategy, and opaque — it is
/// compared, never parsed, so its spelling is free to change.
pub fn generate_enrollment_token() -> String {
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        *byte = rand::random();
    }
    hex::encode(bytes)
}
