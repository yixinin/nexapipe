//! The 2FA side of the client.
//!
//! It is five things, and they are five files:
//!
//! - `totp` — the algorithm, the configuration, and the secret.
//! - `two_factor` — the authenticator that answers a challenge with a code.
//! - `device` — the key a device proves itself with.
//! - `enrollment` — the exchange that trades an invitation for a credential.
//! - `message` — the framing of the handshake's messages.
//!
//! This one holds what the rest of the crate calls, and the shared imports.

mod device;
mod enrollment;
mod message;
mod totp;
mod two_factor;

/// The smallest seed a TOTP secret may be, in bytes.
///
/// The same floor the server applies, and the same one
/// [`crate::provisioning`] applies to an invite: RFC 4226 asks for at least
/// 128 bits, and the TOTP library both sides build their codes with refuses
/// to work with less. A seed under it is a credential that can never verify,
/// so it is refused where it is configured rather than at the first handshake
/// — where the only symptom is a library error about a secret length.
pub(crate) const MIN_SECRET_BYTES: usize = 16;

#[cfg(test)]
mod tests;

pub use device::{DeviceKey, device_id_is_usable};
pub use enrollment::{Enrollment, IssuedCredential};
pub use totp::{TotpAlgorithm, TwoFactorConfig, generate_secret};
pub use two_factor::TwoFactorAuth;
