//! The time-based side of a credential.
//!
//! The algorithm, the configuration that goes with it, and the secret
//! itself. A secret is never printed: the `Debug` says whether there is
//! one and nothing else.

use nexapipe_proto::auth::Algorithm as ProtoAlgorithm;
use nexapipe_proto::secret::{SecretBytes, SecretString};
use totp_rs::{Algorithm, Secret as TotpSecret};

use crate::ClientError;

use super::two_factor::TwoFactorAuth;

/// TOTP algorithm variants
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl TotpAlgorithm {
    pub(super) fn to_totp_rs(&self) -> Algorithm {
        match self {
            TotpAlgorithm::SHA1 => Algorithm::SHA1,
            TotpAlgorithm::SHA256 => Algorithm::SHA256,
            TotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }

    /// Parse an algorithm name, refusing one nobody supports.
    ///
    /// The names are the canonical ones, in any case: `sha1`, `sha256`,
    /// `sha512`. An empty name is the default, `sha1` — which is what the
    /// Android client does with the same field, and what a URI that leaves
    /// the parameter out means.
    ///
    /// Anything else is an error that names the value and the spellings that
    /// are accepted. A name quietly turned into a different algorithm is a
    /// silent downgrade: the client computes codes the server does not
    /// accept, and every attempt fails with "wrong code" rather than the
    /// algorithm being named once as unsupported.
    pub fn try_from_name(name: &str) -> Result<Self, ClientError> {
        let name = name.trim();
        if name.is_empty() {
            return Ok(TotpAlgorithm::SHA1);
        }
        if name.eq_ignore_ascii_case("sha1") {
            return Ok(TotpAlgorithm::SHA1);
        }
        if name.eq_ignore_ascii_case("sha256") {
            return Ok(TotpAlgorithm::SHA256);
        }
        if name.eq_ignore_ascii_case("sha512") {
            return Ok(TotpAlgorithm::SHA512);
        }
        Err(ClientError::InvalidConfig(format!(
            "unsupported algorithm {name:?} (expected SHA1, SHA256 or SHA512)"
        )))
    }

    /// Parse an algorithm name, falling back to SHA1.
    ///
    /// **Only for a value that is already one of ours** — a name this crate
    /// produced. A name that came from a peer or from a file is read with
    /// [`TotpAlgorithm::try_from_name`], which refuses one nobody supports
    /// instead of quietly computing a different code.
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

impl From<ProtoAlgorithm> for TotpAlgorithm {
    /// The algorithm as the protocol spells it.
    ///
    /// The two are the same three algorithms and neither is free-form: the
    /// protocol's is a closed type, so a name nobody supports is refused
    /// where the message is read rather than turned into a different
    /// algorithm here.
    fn from(algorithm: ProtoAlgorithm) -> Self {
        match algorithm {
            ProtoAlgorithm::Sha1 => TotpAlgorithm::SHA1,
            ProtoAlgorithm::Sha256 => TotpAlgorithm::SHA256,
            ProtoAlgorithm::Sha512 => TotpAlgorithm::SHA512,
        }
    }
}

/// Client-side 2FA credentials loaded from config file / app settings.
///
/// `Debug` is written out rather than derived, and `secret` is the reason: a
/// derived one prints the TOTP seed in full, so every `{:?}` that reaches a log
/// line, a panic message or a bug report pastes a working credential into it.
/// An empty `secret` prints as `""` for the same reason — an absent secret and a
/// masked one should not be told apart by a reader.
///
/// The seed itself is a [`SecretString`], so it is wiped when this config is
/// dropped rather than left in the heap for the allocator to hand out again.
#[derive(Clone, PartialEq)]
pub struct TwoFactorConfig {
    pub client_id: String,
    /// The TOTP seed, in the Base32 spelling it was configured with.
    pub secret: SecretString,
    pub algorithm: TotpAlgorithm,
}

impl std::fmt::Debug for TwoFactorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorConfig")
            .field("client_id", &self.client_id)
            .field("secret", &masked(self.secret.as_str()))
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// What a secret prints as: present, and how long — never the value itself.
pub(super) fn masked(secret: &str) -> String {
    if secret.is_empty() {
        String::new()
    } else {
        format!("<{} chars>", secret.chars().count())
    }
}

impl TwoFactorConfig {
    /// Build a [`TwoFactorAuth`] if a secret is configured; returns `Ok(None)`
    /// when the secret is empty (2FA effectively disabled).
    pub fn to_auth(&self) -> Result<Option<TwoFactorAuth>, ClientError> {
        if self.secret.as_str().trim().is_empty() {
            return Ok(None);
        }
        TwoFactorAuth::new(
            &self.client_id,
            self.secret.as_str(),
            self.algorithm.clone(),
        )
        .map(Some)
    }
}

/// Decodes a client-side Base32 secret.
///
/// The spelling is normalised first, because `base32` 0.5's `Rfc4648` alphabet
/// decodes upper case only: a secret written in lower case — a hand-copied
/// config, an app that stores what it was handed — decoded before the upgrade
/// and is rejected now, with an error that names neither the spelling nor the
/// case. Whitespace and `=` padding are dropped too; both are presentation
/// rather than part of the secret, and grouping it is common enough that
/// refusing it would only look pedantic.
///
/// The normalised spelling is a copy of the seed in the clear, so it is held
/// in a [`SecretString`] rather than a `String`: it is wiped when this
/// function returns, instead of being left in the heap for the allocator to
/// hand out again.
pub(super) fn decode_base32(secret_base32: &str) -> Result<SecretBytes, ClientError> {
    let normalized = SecretString::new(
        secret_base32
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );

    // An empty string decodes to an empty key, which would then generate codes
    // from nothing and fail every handshake with no hint as to why. It is a
    // missing secret, not a short one.
    if normalized.as_str().is_empty() {
        return Err(ClientError::InvalidConfig(
            "Invalid Base32 secret".to_string(),
        ));
    }

    base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        normalized.as_str(),
    )
    .map(SecretBytes::new)
    .ok_or_else(|| ClientError::InvalidConfig("Invalid Base32 secret".to_string()))
    .and_then(|decoded| {
        // A seed that decodes to less than 128 bits is a challenge anybody can
        // brute force, and the TOTP library refuses it when the validator is
        // built — at the first handshake, with an error about a secret length
        // that says nothing about what to do. The floor is the same one the
        // server applies, and it is applied here so a secret that cannot work
        // is refused where it is configured.
        let length = decoded.expose_secret().len();
        if length < super::MIN_SECRET_BYTES {
            return Err(ClientError::InvalidConfig(format!(
                "the 2FA secret decodes to {} byte{}; a TOTP secret is at least {} bytes",
                length,
                if length == 1 { "" } else { "s" },
                super::MIN_SECRET_BYTES
            )));
        }
        Ok(decoded)
    })
}

/// Generate a new secret for client setup
///
/// A plain string, because it is on its way to a config file or an
/// authenticator app: the copy that leaves this process is not ours to wipe.
pub fn generate_secret() -> String {
    TotpSecret::generate().to_base32()
}
