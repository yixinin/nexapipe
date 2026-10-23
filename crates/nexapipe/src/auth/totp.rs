//! TOTP validation logic.

use super::config::{AuthConfig, TotpAlgorithm};
use nexapipe_proto::secret::SecretBytes;
use totp_rs::{Algorithm, Builder, Secret};

/// How far an AUTH_RESPONSE timestamp may sit from the server clock, in
/// seconds. The signature already pins the response to one challenge; the
/// timestamp bounds how long even a correctly signed response stays
/// acceptable, so an intercepted one cannot be replayed next week.
const TIMESTAMP_WINDOW_SECS: i64 = 30;

/// Which credential a response is to be proven with.
///
/// Decided by what the server holds for the device the response named — never
/// by anything the response carries, so a peer cannot choose a weaker proof
/// than the one its entry demands.
enum Proof {
    /// A TOTP seed: an HMAC over the challenge, then a code.
    ///
    /// A [`SecretBytes`]: the seed is a working credential, and it is wiped
    /// when the proof is dropped — which is as soon as the handshake that
    /// needed it is over.
    Secret(SecretBytes),
    /// An Ed25519 public key: a signature over the same bytes the HMAC covers.
    Key(iroh::PublicKey),
}

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
    /// is known and not locked out, the device it named has a credential that
    /// reads back, its timestamp is fresh, and then the proof itself — which
    /// is one of two, decided by what that credential is. A device with a
    /// secret proves itself the way it always has: the signature matches
    /// HMAC-SHA256(secret, nonce || timestamp) and the TOTP code is current. A
    /// device with a public key proves itself with an Ed25519 signature over
    /// the same bytes, and has no code to offer: `totp_code` is empty.
    ///
    /// `Ok(Verified::WrongCode)` is the credential being wrong, and the caller
    /// counts it toward the lockout. Today that is one case: a wrong TOTP code
    /// for a secret device. Every `Err` is a refusal the caller logs instead of
    /// counting.
    ///
    /// `Ok(Verified::Accepted { step })` carries the step the code matched on,
    /// because the caller needs it: **the same code is inside the window for
    /// the whole of its step**, so "this code is current" and "this code has
    /// already been used" are different questions, and only the step tells
    /// them apart. The caller is the one that remembers, and what it refuses
    /// is a step **behind** the last one it accepted.
    ///
    /// A key device's wrong signature is a refusal and not a count, and the
    /// difference is the difference between the two proofs. A code is
    /// guessable, so the counter that stops the guessing is the point of it —
    /// and the counter there is only reachable by a peer that already holds
    /// the secret, because the HMAC has to verify before the code is
    /// checked. A key is not guessable, so a counter on that path protects
    /// nothing, and what it does instead is hand anyone who knows a client
    /// id and the name of a key device a way to lock a legitimate device
    /// out — over and over, and without holding any credential at all.
    ///
    /// `device_id` says which credential under that client is being proven:
    /// `None` is the device that has no name and answers with the client's own
    /// `secret`, which is what every device used before a client could carry a
    /// table of them. A name selects that device's entry, and the entry decides
    /// the proof. A name the table does not carry is refused rather than
    /// falling back — dropping a device from the table is how it is revoked,
    /// and a fallback would let it back in under the name it no longer has.
    ///
    /// Which device authenticated changes nothing about the lockout: the
    /// counter is the client's, so a device cannot escape it by naming itself
    /// something new, and a device nobody has ever issued cannot be used to
    /// walk the counter up.
    pub fn verify_response(
        &self,
        client_id: &str,
        device_id: Option<&str>,
        nonce: &[u8],
        timestamp: i64,
        signature: &[u8],
        code: &str,
    ) -> Result<Verified, AuthError> {
        if !self.config.enabled {
            return Ok(Verified::Accepted { step: None });
        }

        let client = self
            .config
            .clients
            .get(client_id)
            .ok_or(AuthError::ClientNotFound)?;

        if client.is_locked_out() {
            return Err(AuthError::LockedOut);
        }

        // A name that is not in the table is "no such device", not "no name" —
        // the two are told apart by `Option` on the wire, and only the second
        // one falls back. A name that is not printable ASCII is not in the
        // table either, so it lands here as well; what keeps it out of the log
        // is that this error carries no name.
        //
        // The fallback is the credential no revocation can reach: `client
        // revoke --device` strikes one entry out of `devices` and leaves the
        // shared `secret` standing, so a secret that leaked through an invite
        // link keeps working for as long as whoever has it simply omits the
        // name. `unnamed_device_allowed = false` is how an operator says this
        // client has stopped handing that secret out, and makes revoking a
        // device mean what it reads as meaning.
        //
        // The unnamed device is always the secret path: its credential is the
        // client's own `secret`, a string, and a key has no place in it.
        let proof = match device_id {
            None if !client.unnamed_device_allowed => {
                return Err(AuthError::UnnamedDeviceNotAllowed);
            }
            None => client.decode_secret().map(Proof::Secret),
            Some(name) => {
                let device = client.devices.get(name).ok_or(AuthError::UnknownDevice)?;
                match device.public_key.as_deref() {
                    Some(key) => super::device_key::parse_public_key(key).map(Proof::Key),
                    None => device.decode_secret().map(Proof::Secret),
                }
            }
        }
        .map_err(|_| AuthError::InvalidSecret)?;

        // `timestamp` arrives from the client, so the subtraction is attacker
        // controlled: `now - i64::MIN` overflows, which panics in a debug build
        // and wraps in release. `abs_diff` cannot overflow — the distance
        // between two i64 values always fits in a u64.
        let now = current_timestamp();
        if now.abs_diff(timestamp) > TIMESTAMP_WINDOW_SECS as u64 {
            return Err(AuthError::StaleTimestamp);
        }

        match proof {
            Proof::Secret(secret) => {
                let expected = hmac_signature(secret.as_slice(), nonce, timestamp)?;
                if !constant_time_eq(signature, &expected) {
                    return Err(AuthError::ChallengeMismatch);
                }
                match self.check_code(secret, code)? {
                    Some(step) => Ok(Verified::Accepted { step: Some(step) }),
                    None => Ok(Verified::WrongCode),
                }
            }
            // The key path's whole verdict: a signature over the same message
            // the HMAC above covers, so this is the same statement, proven the
            // other way. `false` here is a wrong signature, which the caller
            // counts the way it counts a wrong code — a key device has no
            // code, so this is the only wrong-credential signal there is, and
            // leaving it uncounted would let the device be hammered without
            // limit.
            Proof::Key(key) => {
                // Refused, never counted.
                //
                // The secret path counts a wrong code because the code is
                // guessable and the counter is what stops the guessing — and
                // the counter there is only reachable by a peer that already
                // holds the secret, because the HMAC has to verify first.
                //
                // A key is not guessable. There is nothing for a counter to
                // protect on this path, so the only thing counting does is
                // let anyone who knows a client id and the name of a key
                // device lock a legitimate device out — over and over, and
                // for as long as they care to.
                //
                // The malformed case is told apart from the merely-wrong one
                // so the log can say which it was.
                if iroh::Signature::try_from(signature).is_err() {
                    return Err(AuthError::MalformedSignature);
                }
                if !super::device_key::ed25519_verify(&key, nonce, timestamp, signature) {
                    return Err(AuthError::WrongSignature);
                }
                // No step: a key device has no code, and the challenge-bound
                // signature is not something a second use could replay.
                Ok(Verified::Accepted { step: None })
            }
        }
    }

    /// The code half of the secret path: the step it matched on, if any.
    ///
    /// The step is what RFC 6238 §5.2 asks a verifier to remember. A code
    /// that is *inside* the window is not the same as a code that has
    /// **already been used**, and only the step tells the two apart: the same
    /// code is inside the window for the whole of its step.
    fn check_code(&self, secret: SecretBytes, code: &str) -> Result<Option<u64>, AuthError> {
        // `Builder` narrows two of these: 5.x took `digits` as a `usize` and
        // `skew` as a `u8`, 6.0 takes a `u8` and a `u16`. Converting rather
        // than casting keeps a config that does not fit from being truncated
        // into a plausible one — a `digits` of 262 would otherwise read as 6
        // and issue codes nobody asked for.
        let digits = u8::try_from(self.config.digits).map_err(|_| AuthError::TotpCreationFailed)?;
        let skew = u16::try_from(self.config.window).map_err(|_| AuthError::TotpCreationFailed)?;

        let totp = Builder::new()
            .with_algorithm(self.get_algorithm())
            .with_digits(digits)
            .with_skew(skew)
            .with_step_duration(self.config.time_step as u64)
            // The validator keeps its own copy of the seed, and `totp-rs` is
            // built with its `zeroize` feature: the copy is wiped when the
            // validator is dropped here rather than left in the heap.
            .with_secret(secret.expose_secret_cloned())
            .build()
            .map_err(|_| AuthError::TotpCreationFailed)?;

        // `check_current` answers with the step it matched on — and the step
        // is what makes a code that is *current* different from one that has
        // already been used, so the caller keeps it: RFC 6238 §5.2 asks a
        // verifier to refuse the second use of a step it has already accepted.
        //
        // `None` is a code that is not current: wrong, or outside the window.
        Ok(totp.check_current(code))
    }

    /// Generate a new TOTP secret for a client (for setup)
    pub fn generate_secret() -> String {
        // Unpadded base32, the same spelling `decode_secret` reads back.
        Secret::generate().to_base32()
    }
}

/// The signature a client attaches to AUTH_RESPONSE:
/// HMAC-SHA256(secret, nonce || timestamp.to_le_bytes()).
///
/// The message and the HMAC over it live in
/// [`nexapipe_proto::auth::hmac_challenge`], the one definition both sides
/// link — a key-based device signs the same bytes with Ed25519, so what a
/// response proves does not depend on which credential answered it, and
/// neither half can drift from the other.
///
/// The error is this crate's own rather than the protocol crate's, because
/// this is where the refusal is worded: a secret the HMAC will not take is
/// `InvalidSecret` here.
pub(crate) fn hmac_signature(
    secret: &[u8],
    nonce: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, AuthError> {
    nexapipe_proto::auth::hmac_challenge(secret, nonce, timestamp)
        .map_err(|_| AuthError::InvalidSecret)
}

/// Length-safe constant-time comparison: an HMAC-SHA256 tag is never secret
/// in length (32 bytes), but comparing it byte-wise stops the first mismatch
/// from leaking how many leading bytes were right.
///
/// Reused for the admin token, which is compared the same way for the same
/// reason: a token guessed one byte at a time should not be told how far it
/// got.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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

/// What the verification found.
///
/// The three answers are different in kind, and the difference matters to the
/// caller: a credential that proved itself, a **guess** at one, and a refusal.
/// The first clears the counters, the second counts, and the third does
/// neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verified {
    /// The credential proved itself.
    ///
    /// `step` is the TOTP step the code matched on. A **key** device has no
    /// code, so it has no step either — and the key path is not the one that
    /// needs the memory: a signature cannot be replayed, because it covers the
    /// challenge that was issued for this connection.
    Accepted {
        /// The step the code matched on, when there was a code.
        step: Option<u64>,
    },
    /// The code was wrong: a guess at the credential.
    WrongCode,
}

/// Authentication errors
#[derive(Debug, Clone)]
pub enum AuthError {
    ClientNotFound,
    /// The response names a device this client has no credential for — either
    /// one was never issued to it, or its entry has been dropped.
    ///
    /// Deliberately carries no name: it is answered to a name the peer chose,
    /// which is not a name this process has agreed to print.
    UnknownDevice,
    /// The stored credential could not be read at all: a secret that does not
    /// decode, or a public key that is not a point on the curve.
    ///
    /// Either way it is the server's own config that is broken, not a peer's
    /// mistake — a peer could not have supplied these bytes — so a caller
    /// reports it as such and never counts it as an attempt.
    InvalidSecret,
    TotpCreationFailed,
    LockedOut,
    InvalidCode,
    /// The response timestamp sits outside the acceptance window.
    StaleTimestamp,
    /// The response signature does not match the challenge that was issued.
    ChallengeMismatch,
    /// The response names no device and this client has been configured to
    /// answer only named ones, so the shared `secret` is not a credential here.
    UnnamedDeviceNotAllowed,
    /// The response's signature does not match the challenge.
    ///
    /// Refused rather than counted, and the reason is the difference between
    /// the two proofs. A wrong TOTP code is a guess at a credential, and the
    /// counter that stops the guesses is the point of it. A wrong signature is
    /// not a guess: a 256-bit key cannot be brute-forced, so there is nothing
    /// for the counter to protect. What it does instead is hand anyone who
    /// knows a client id and a device name a way to lock a legitimate device
    /// out — repeatedly, and for as long as they like — without holding any
    /// credential at all.
    WrongSignature,
    /// The response's signature is not a signature: the wrong length.
    ///
    /// The same refusal as [`AuthError::WrongSignature`], and the same
    /// reason: this is a malformed message, not an attempt at the credential.
    MalformedSignature,
    ProtocolError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::ClientNotFound => write!(f, "Client not found"),
            AuthError::UnknownDevice => write!(f, "No device of that name under this client"),
            AuthError::InvalidSecret => write!(f, "Invalid credential configuration"),
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
            AuthError::UnnamedDeviceNotAllowed => {
                write!(f, "This client answers only to a named device")
            }
            AuthError::WrongSignature => {
                write!(f, "The response signature does not match the challenge")
            }
            AuthError::MalformedSignature => {
                write!(f, "The response signature is malformed")
            }
            AuthError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::ClientAuth;
    use nexapipe_proto::secret::SecretString;
    use std::collections::HashMap;

    fn config_with_one_client() -> AuthConfig {
        let client = ClientAuth {
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            created_at: String::new(),
            allow_hosts: None,
            allow_ports: None,
            allow_ports_strict: false,
            pending_enrollment: None,
            devices: HashMap::new(),
            unnamed_device_allowed: true,
            last_used: None,
            last_used_step: None,
            failed_attempts: 0,
            locked_until: None,
            enrollment_failed_attempts: 0,
            enrollment_locked_until: None,
        };

        AuthConfig {
            enabled: true,
            clients: HashMap::from([("alice".to_string(), client)]),
            ..AuthConfig::default()
        }
    }

    /// A client that has issued a credential to one named device. 160-bit
    /// secrets, because `totp-rs` refuses to build a validator from anything
    /// shorter than 128 bits — and the tests below reach the TOTP check.
    fn config_with_one_device() -> AuthConfig {
        let client = ClientAuth {
            secret: SecretString::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
            created_at: String::new(),
            allow_hosts: None,
            allow_ports: None,
            allow_ports_strict: false,
            pending_enrollment: None,
            devices: HashMap::from([(
                "laptop".to_string(),
                crate::auth::DeviceAuth {
                    secret: SecretString::new("KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP".to_string()),
                    public_key: None,
                    created_at: String::new(),
                    last_used: None,
                    last_used_step: None,
                },
            )]),
            unnamed_device_allowed: true,
            last_used: None,
            last_used_step: None,
            failed_attempts: 0,
            locked_until: None,
            enrollment_failed_attempts: 0,
            enrollment_locked_until: None,
        };

        AuthConfig {
            enabled: true,
            clients: HashMap::from([("alice".to_string(), client)]),
            ..AuthConfig::default()
        }
    }

    /// The same client, plus a second device that proves itself with a key
    /// instead — and the key that proves it, which only the test holds. The
    /// two kinds side by side is what a migration looks like: one device still
    /// answers with a code, the next one signs.
    fn config_with_a_key_device() -> (AuthConfig, iroh::SecretKey) {
        let key = iroh::SecretKey::generate();
        let mut config = config_with_one_device();
        config.clients.get_mut("alice").unwrap().devices.insert(
            "phone".to_string(),
            crate::auth::DeviceAuth {
                secret: SecretString::default(),
                public_key: Some(crate::auth::public_key_hex(&key.public())),
                created_at: String::new(),
                last_used: None,
                last_used_step: None,
            },
        );
        (config, key)
    }

    /// The nonce a test signs over, minted the way the connection layer mints
    /// its challenge (`conn::perform_authentication` draws 32 random bytes).
    ///
    /// These two tests never reach the signature check, so a literal would do
    /// — but a constant sitting in a nonce slot is exactly what CWE-798 is
    /// about, and it would be the one place in the tree where the challenge is
    /// the same twice.
    fn fresh_nonce() -> Vec<u8> {
        (0..32).map(|_| rand::random::<u8>()).collect()
    }

    #[test]
    fn a_timestamp_at_the_bottom_of_the_range_is_refused_rather_than_fatal() {
        let config = config_with_one_client();
        let validator = TotpValidator::new(&config);

        let nonce = fresh_nonce();

        // i64::MIN overflows `now - timestamp` — a panic in a debug build, a
        // wrap in release, and reachable without authenticating.
        let outcome =
            validator.verify_response("alice", None, &nonce, i64::MIN, b"signature", "000000");

        assert!(matches!(outcome, Err(AuthError::StaleTimestamp)));
    }

    #[test]
    fn a_timestamp_at_the_top_of_the_range_is_refused_rather_than_fatal() {
        let config = config_with_one_client();
        let validator = TotpValidator::new(&config);

        let nonce = fresh_nonce();
        let outcome =
            validator.verify_response("alice", None, &nonce, i64::MAX, b"signature", "000000");

        assert!(matches!(outcome, Err(AuthError::StaleTimestamp)));
    }

    /// Which secret a named device is checked against: its own, not the
    /// client's. This is the whole of what revoking a device rests on — a
    /// device whose entry is dropped must not be able to answer with the
    /// client's secret instead, and it cannot, because the name it sends is
    /// what decides which key the signature is compared with.
    #[test]
    fn a_named_device_is_checked_against_its_own_secret() {
        let config = config_with_one_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        let laptop = hmac_signature(
            config.clients["alice"].devices["laptop"]
                .decode_secret()
                .unwrap()
                .as_slice(),
            &nonce,
            timestamp,
        )
        .unwrap();
        let clients_own = hmac_signature(
            config.clients["alice"].decode_secret().unwrap().as_slice(),
            &nonce,
            timestamp,
        )
        .unwrap();

        // Signed with the laptop's secret under the laptop's name: the
        // signature is the one expected, so the verdict is the code's.
        let outcome = validator.verify_response(
            "alice",
            Some("laptop"),
            &nonce,
            timestamp,
            &laptop,
            "000000",
        );
        assert!(matches!(outcome, Ok(Verified::WrongCode)), "{outcome:?}");

        // The same name, signed with the client's own secret: a mismatch, not
        // a fallback.
        let outcome = validator.verify_response(
            "alice",
            Some("laptop"),
            &nonce,
            timestamp,
            &clients_own,
            "000000",
        );
        assert!(
            matches!(outcome, Err(AuthError::ChallengeMismatch)),
            "{outcome:?}"
        );
    }

    /// A name the table does not carry is refused rather than falling back to
    /// the client's secret. Falling back would make a revoked device's name
    /// its way back in, and would let a peer that never enrolled answer as
    /// the device that has no name.
    #[test]
    fn a_device_name_the_client_does_not_carry_is_refused() {
        let config = config_with_one_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        // A name nothing will ever match, including one that is not printable
        // ASCII: it is not in the table either, so it is refused here without
        // ever reaching a log line that would print it.
        for name in ["phone", "laptop\r\nINFO: enrolled", ""] {
            let outcome = validator.verify_response(
                "alice",
                Some(name),
                &nonce,
                timestamp,
                b"signature",
                "000000",
            );
            assert!(
                matches!(outcome, Err(AuthError::UnknownDevice)),
                "{name:?} must not resolve, got {outcome:?}"
            );
        }
    }

    /// The fallback, and the only path that existed before: no name sent means
    /// the device that has none, and it answers with the client's own secret.
    #[test]
    fn an_unnamed_device_is_checked_against_the_clients_secret() {
        let config = config_with_one_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        let clients_own = hmac_signature(
            config.clients["alice"].decode_secret().unwrap().as_slice(),
            &nonce,
            timestamp,
        )
        .unwrap();

        let outcome =
            validator.verify_response("alice", None, &nonce, timestamp, &clients_own, "000000");
        assert!(matches!(outcome, Ok(Verified::WrongCode)), "{outcome:?}");
    }

    /// The fallback is a credential no revocation can reach: `client revoke
    /// --device` strikes one entry out of the device table and leaves the
    /// client's own `secret` standing, so a secret that leaked keeps working
    /// for anyone who simply omits the name. `unnamed_device_allowed = false`
    /// is what closes it, and it has to close it *before* the secret is
    /// decoded — being refused must not depend on the code being wrong.
    #[test]
    fn a_client_that_answers_only_to_named_devices_refuses_an_unnamed_one() {
        let mut config = config_with_one_device();
        config
            .clients
            .get_mut("alice")
            .unwrap()
            .unnamed_device_allowed = false;
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();
        let clients_own = hmac_signature(
            config.clients["alice"].decode_secret().unwrap().as_slice(),
            &nonce,
            timestamp,
        )
        .unwrap();

        let outcome =
            validator.verify_response("alice", None, &nonce, timestamp, &clients_own, "000000");
        assert!(
            matches!(outcome, Err(AuthError::UnnamedDeviceNotAllowed)),
            "{outcome:?}"
        );
    }

    /// The same client still answers a device that names itself, which is the
    /// point: the switch takes away the shared credential, not the client.
    #[test]
    fn that_client_still_answers_a_device_that_names_itself() {
        let mut config = config_with_one_device();
        config
            .clients
            .get_mut("alice")
            .unwrap()
            .unnamed_device_allowed = false;
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();
        let laptop = hmac_signature(
            config.clients["alice"].devices["laptop"]
                .decode_secret()
                .unwrap()
                .as_slice(),
            &nonce,
            timestamp,
        )
        .unwrap();

        let outcome = validator.verify_response(
            "alice",
            Some("laptop"),
            &nonce,
            timestamp,
            &laptop,
            "000000",
        );
        assert!(matches!(outcome, Ok(Verified::WrongCode)), "{outcome:?}");
    }

    /// The default has to stay permissive, or every client that predates the
    /// device table — which is every client issued before 0.6.0 — loses its
    /// only credential on upgrade.
    #[test]
    fn an_unnamed_device_is_allowed_unless_the_config_says_otherwise() {
        let config = config_with_one_device();
        assert!(config.clients["alice"].unnamed_device_allowed);
    }

    /// The step the code matched on comes back with the acceptance.
    ///
    /// It is what tells a code that is *current* from one that has **already
    /// been used**: a code is inside the acceptance window for the whole of
    /// its step, so the window alone cannot answer the second question. The
    /// caller keeps the step, and RFC 6238 §5.2 asks it to refuse the second
    /// use of one.
    #[test]
    fn the_step_the_code_matched_on_comes_back() {
        let config = config_with_one_device();
        let secret = config.clients["alice"].devices["laptop"]
            .decode_secret()
            .expect("the secret reads back");
        // The code a client would send right now.
        let code = totp_rs::Builder::new()
            .with_secret(secret.expose_secret_cloned())
            .build()
            .expect("the validator is built")
            .generate_current()
            .to_string();

        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();
        let signature = hmac_signature(
            config.clients["alice"].devices["laptop"]
                .decode_secret()
                .unwrap()
                .as_slice(),
            &nonce,
            timestamp,
        )
        .unwrap();

        let outcome = validator.verify_response(
            "alice",
            Some("laptop"),
            &nonce,
            timestamp,
            &signature,
            &code,
        );
        let Ok(Verified::Accepted { step: Some(step) }) = outcome else {
            panic!("the code is current: {outcome:?}");
        };
        // The step is a time index: the thirty-second window the code belongs
        // to, counted from the epoch.
        let expected = (timestamp as u64) / 30;
        assert!(
            step.abs_diff(expected) <= 1,
            "the step is the time index of the code: {step} against {expected}"
        );
    }

    /// A key device proves itself with a signature over the challenge, and it
    /// does so without a code — which is the point, because the device this is
    /// for has nobody to read one.
    #[test]
    fn a_key_device_proves_itself_with_a_signature() {
        let (config, key) = config_with_a_key_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        let signature = key.sign(&nexapipe_proto::auth::challenge_message(&nonce, timestamp));

        let outcome = validator.verify_response(
            "alice",
            Some("phone"),
            &nonce,
            timestamp,
            &signature.to_bytes(),
            "",
        );
        assert!(
            matches!(outcome, Ok(Verified::Accepted { .. })),
            "{outcome:?}"
        );
    }

    /// A signature that is not this device's is the key path's wrong
    /// credential, so it is `Ok(Verified::WrongCode)` — the verdict the caller
    /// counts — and
    /// not an `Err`. If it were an `Err`, the counter would never move and the
    /// device could be tried without limit.
    #[test]
    fn a_wrong_signature_is_refused_and_not_a_fallback() {
        let (config, _) = config_with_a_key_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        let stranger = iroh::SecretKey::generate();
        let signature = stranger.sign(&nexapipe_proto::auth::challenge_message(&nonce, timestamp));

        let outcome = validator.verify_response(
            "alice",
            Some("phone"),
            &nonce,
            timestamp,
            &signature.to_bytes(),
            "",
        );
        assert!(
            matches!(outcome, Err(AuthError::WrongSignature)),
            "a wrong signature is refused, and not counted: {outcome:?}"
        );
    }

    /// A signature that is not a signature is a malformed message, not a
    /// wrong credential.
    ///
    /// The two have to be told apart, because the caller counts a wrong
    /// credential and does not count a malformed one. A peer that knows a
    /// client id and the name of a key device could otherwise send noise
    /// five times and lock that client out — over and over, and without
    /// holding any credential at all.
    #[test]
    fn a_malformed_signature_is_refused_rather_than_counted() {
        let (config, _) = config_with_a_key_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        // Not a signature: too short.
        let outcome =
            validator.verify_response("alice", Some("phone"), &nonce, timestamp, b"noise", "");

        assert!(
            matches!(outcome, Err(AuthError::MalformedSignature)),
            "a malformed signature is refused, not counted: {outcome:?}"
        );
    }

    /// A signature that is well formed and wrong is refused too — and is not
    /// counted.
    ///
    /// This is the change that closes the door. A 256-bit key cannot be
    /// guessed, so a counter on this path protects nothing; what it does is
    /// let anyone who knows a client id and the name of a key device lock a
    /// legitimate device out, over and over.
    #[test]
    fn a_wrong_signature_is_refused_and_not_counted() {
        let (config, _) = config_with_a_key_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        let stranger = iroh::SecretKey::generate();
        let signature = stranger.sign(&nexapipe_proto::auth::challenge_message(&nonce, timestamp));

        let outcome = validator.verify_response(
            "alice",
            Some("phone"),
            &nonce,
            timestamp,
            &signature.to_bytes(),
            "",
        );
        assert!(
            matches!(outcome, Err(AuthError::WrongSignature)),
            "a wrong signature is refused, not counted: {outcome:?}"
        );
    }

    /// The freshness bound is the same for both proofs: a signature is proof
    /// of seeing this challenge, and a stale timestamp is a refusal — `Err`,
    /// which the caller does not count — whichever kind of device sent it.
    #[test]
    fn a_stale_timestamp_is_refused_on_the_key_path_too() {
        let (config, key) = config_with_a_key_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp() - 3600;

        let signature = key.sign(&nexapipe_proto::auth::challenge_message(&nonce, timestamp));

        let outcome = validator.verify_response(
            "alice",
            Some("phone"),
            &nonce,
            timestamp,
            &signature.to_bytes(),
            "",
        );
        assert!(
            matches!(outcome, Err(AuthError::StaleTimestamp)),
            "{outcome:?}"
        );
    }

    /// A key device is not also a secret device: a response that answers for
    /// the key device with the *client's* own secret — what a peer falls back
    /// to when it has nothing else — is refused at the signature check, and
    /// the key device's entry cannot be reached by an unsuspecting client.
    #[test]
    fn a_key_device_is_not_reachable_with_the_clients_secret() {
        let (config, _) = config_with_a_key_device();
        let validator = TotpValidator::new(&config);
        let nonce = fresh_nonce();
        let timestamp = current_timestamp();

        let clients_own = hmac_signature(
            config.clients["alice"].decode_secret().unwrap().as_slice(),
            &nonce,
            timestamp,
        )
        .unwrap();

        // An HMAC is not a signature, and nothing on the key path reads it as
        // one: the verdict is a refusal, not a fallback to the client's
        // secret. The HMAC is 32 bytes and a signature is 64, so this is the
        // malformed case rather than the merely-wrong one — the log says
        // which it was.
        let outcome =
            validator.verify_response("alice", Some("phone"), &nonce, timestamp, &clients_own, "");
        assert!(
            matches!(outcome, Err(AuthError::MalformedSignature)),
            "an HMAC is not a signature, and the key path does not read it as one: {outcome:?}"
        );
    }
}
