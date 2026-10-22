// 2FA authentication module for Nexapipe client.
//
// Provides TOTP code generation and the authentication handshake, in the two
// shapes the server accepts: a secret-based device answers with an HMAC over
// the challenge plus a code, a key-based one signs the same bytes with an
// Ed25519 key it generated and never hands over. Which shape a credential has
// is whatever its enrollment produced.

use crate::ClientError;
use hmac::{Hmac, KeyInit, Mac};
use iroh::endpoint::Connection;
use nexapipe_proto::auth::{Algorithm as ProtoAlgorithm, AuthMessage, Format, VERSION_BINARY};
use nexapipe_proto::secret::{SecretBytes, SecretString};
use sha2::Sha256;
use std::fmt;
use totp_rs::{Algorithm, Builder, Secret as TotpSecret};

/// Application error codes the server closes a connection with during the 2FA
/// handshake. Must match `auth_close_code` in `crates/nexapipe/src/conn/mod.rs`
/// and `PEER_NOT_ALLOWED_CLOSE_CODE` in
/// `crates/nexapipe/src/conn/allow_list.rs`.
mod auth_close_code {
    /// No AUTH_START arrived within the handshake deadline, or the server does
    /// not run the handshake on that first stream at all.
    pub const REQUIRED: u32 = 2;
    /// The handshake ran and the credentials were refused.
    pub const REJECTED: u32 = 3;
    /// The peer already holds as many connections as it is allowed.
    pub const TOO_MANY: u32 = 4;
    /// The server runs a `[peers]` allow-list and this Node ID is not on it.
    /// Sent right after the QUIC handshake, so the client never gets as far as
    /// sending credentials.
    pub const PEER_NOT_ALLOWED: u32 = 5;
    /// This credential was struck out of `[auth]` *while this connection was
    /// open* — `nexapipe client revoke`, aimed at this client or at this one
    /// device of it. Unlike the four above this does not arrive during the
    /// handshake: a connection has to have authenticated to be revoked.
    pub const REVOKED: u32 = 6;
}

/// HMAC-SHA256 keyed by the TOTP secret, used to sign auth challenges.
type HmacSha256 = Hmac<Sha256>;

/// TOTP algorithm variants
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl TotpAlgorithm {
    fn to_totp_rs(&self) -> Algorithm {
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
fn masked(secret: &str) -> String {
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
fn decode_base32(secret_base32: &str) -> Result<SecretBytes, ClientError> {
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
}

/// What a client-side credential proves itself with.
///
/// Which variant is in play is decided by the server's record, never here: a
/// device is key-based iff the server holds a `public_key` for it, and a
/// response offering the other kind of proof is simply refused. The client
/// learns its own variant at the one moment both sides agreed — enrollment —
/// and keeps it: [`TwoFactorAuth::with_key`] for a key, [`TwoFactorAuth::new`]
/// for a secret.
#[derive(Debug, Clone)]
enum Proof {
    /// A TOTP seed: an HMAC over the challenge, then a code.
    ///
    /// The seed is a [`SecretBytes`], so it is wiped when the credential is
    /// dropped — and its `Debug` says nothing about its value, which is what
    /// lets this enum keep a derived one.
    Totp {
        secret: SecretBytes,
        algorithm: TotpAlgorithm,
        time_step: u32,
        digits: u32,
    },
    /// The device's own Ed25519 key: a signature over the same bytes the HMAC
    /// covers. The private half never leaves this process; the server holds
    /// the public half under the device's name.
    Key(iroh::SecretKey),
}

/// Client-side 2FA authenticator
///
/// The `Debug` is written out for the same reason [`TwoFactorConfig`]'s is: the
/// decoded `secret` is the credential itself, in a form a derived `Debug` would
/// print as a byte array.
#[derive(Clone)]
pub struct TwoFactorAuth {
    client_id: String,
    proof: Proof,
    /// Which of this client's devices this credential belongs to. `None` is the
    /// device that was never given a name, which is what every client was
    /// before a client could have several — it answers with the client's own
    /// secret, and it is the only thing a server that predates per-device
    /// credentials understands.
    device_id: Option<String>,
}

impl std::fmt::Debug for TwoFactorAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut rendered = f.debug_struct("TwoFactorAuth");
        rendered.field("client_id", &self.client_id);
        match &self.proof {
            Proof::Totp {
                secret,
                algorithm,
                time_step,
                digits,
            } => rendered
                .field(
                    "secret",
                    &format_args!("<{} bytes>", secret.as_slice().len()),
                )
                .field("algorithm", algorithm)
                .field("time_step", time_step)
                .field("digits", digits),
            // The private key never prints: not its length, not a placeholder
            // beside it — nothing that varies with the key's value.
            Proof::Key(_) => rendered.field("proof", &"device-key"),
        };
        rendered.field("device_id", &self.device_id).finish()
    }
}

impl TwoFactorAuth {
    /// Create a new 2FA authenticator
    pub fn new(
        client_id: &str,
        secret_base32: &str,
        algorithm: TotpAlgorithm,
    ) -> Result<Self, ClientError> {
        let secret = decode_base32(secret_base32)?;

        Ok(Self {
            client_id: client_id.to_string(),
            proof: Proof::Totp {
                secret,
                algorithm,
                time_step: 30,
                digits: 6,
            },
            device_id: None,
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
        let secret = decode_base32(secret_base32)?;

        Ok(Self {
            client_id: client_id.to_string(),
            proof: Proof::Totp {
                secret,
                algorithm,
                time_step,
                digits,
            },
            device_id: None,
        })
    }

    /// A credential that proves itself with a device key instead of a secret.
    ///
    /// The key is this device's own — the server holds its public half under
    /// `device_id`, and every handshake is proven by a signature only this
    /// credential can produce. There is no code to read, which is the point:
    /// an unattended device has nobody to read one.
    ///
    /// The name is required rather than optional, and not for convenience: a
    /// key cannot be the credential of the unnamed slot, which is the client's
    /// own shared secret — the server refuses a key that names no device.
    pub fn with_key(client_id: &str, key: iroh::SecretKey, device_id: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            proof: Proof::Key(key),
            device_id: Some(device_id.to_string()),
        }
    }

    /// The same credential, answering as one named device of its client.
    ///
    /// What this changes is which secret the server checks the response
    /// against: a device carries one of its own, issued at enrollment, instead
    /// of sharing the client's with every other device that names it — which is
    /// what made revoking one of them rotate all of them. The name is sent on
    /// both AUTH_START and AUTH_RESPONSE, because the response is the one the
    /// server looks the secret up from; sending it on the first alone would
    /// authenticate against the client's secret while claiming a device.
    ///
    /// Nothing checks the name here. The server does, and refuses one that is
    /// not printable ASCII; [`device_id_is_usable`] is the same rule, for a
    /// caller that would rather find out before a handshake than during one.
    pub fn with_device(mut self, device_id: &str) -> Self {
        self.device_id = Some(device_id.to_string());
        self
    }

    /// The device this credential answers as, if it was given one.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Who this credential proves itself as: the client, and the device of it.
    ///
    /// Two credentials with the same identity are the same account with a
    /// different secret — the seed was rotated, the account was not — and a
    /// connection authenticated as that account still stands for it. Two
    /// credentials with different identities are different accounts, and a
    /// connection authenticated as the old one is not the new one's.
    pub fn identity(&self) -> (&str, Option<&str>) {
        (self.client_id.as_str(), self.device_id.as_deref())
    }

    /// Generate current TOTP code
    pub fn generate_code(&self) -> Result<String, ClientError> {
        let Proof::Totp {
            secret,
            algorithm,
            time_step,
            digits,
        } = &self.proof
        else {
            return Err(ClientError::InvalidConfig(
                "this credential proves itself with a key; there is no TOTP code".to_string(),
            ));
        };
        // Same narrowing as the server's validator: `digits` is a `u8` here
        // where 5.x gave it a `usize`, so an out-of-range config is refused
        // rather than truncated into a digit count nobody asked for.
        let digits = u8::try_from(*digits).map_err(|_| {
            ClientError::InvalidConfig(format!("{} is not a TOTP digit count", digits))
        })?;

        let totp = Builder::new()
            .with_algorithm(algorithm.to_totp_rs())
            .with_digits(digits)
            // No skew: this side only ever generates, and a code is either the
            // current one or not. The server's window is what grants tolerance.
            .with_skew(0)
            .with_step_duration(*time_step as u64)
            // The validator is built from a copy of the seed, and it keeps
            // that copy: `totp-rs` is built with its `zeroize` feature, so the
            // copy is wiped when the validator is dropped at the end of this
            // function rather than left in the heap.
            .with_secret(secret.expose_secret_cloned())
            .build()
            .map_err(|e| ClientError::Other(format!("Failed to create TOTP: {e}")))?;

        // `generate_current` no longer returns a `Result`: the only thing it
        // could have failed on was a clock set before the Unix epoch, which is
        // not a condition a handshake can recover from.
        Ok(totp.generate_current().to_string())
    }

    /// Get client ID
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Sign a server challenge: HMAC-SHA256(secret, nonce || timestamp_le) for
    /// a secret-based credential, an Ed25519 signature over those same bytes
    /// for a key-based one.
    ///
    /// Keep in sync with `hmac_signature` in `crates/nexapipe/src/auth/totp.rs`
    /// and `sign_message` in `crates/nexapipe/src/auth/device_key.rs`: whichever
    /// proof is in play, what is signed is the nonce, byte for byte, then the
    /// timestamp as little-endian bytes.
    ///
    /// Fallible in the type only: HMAC takes a key of any length — a long one is
    /// hashed, a short one is zero-padded — so this has never failed. It is
    /// returned rather than `expect`ed because it runs inside a handshake, where
    /// a panic would kill the connection with nothing to report.
    pub fn sign_challenge(&self, nonce: &[u8], timestamp: i64) -> Result<Vec<u8>, ClientError> {
        match &self.proof {
            Proof::Totp { secret, .. } => {
                let mut mac = HmacSha256::new_from_slice(secret.as_slice())
                    .map_err(|e| ClientError::Other(format!("HMAC rejected the secret: {e}")))?;
                mac.update(nonce);
                mac.update(&timestamp.to_le_bytes());
                Ok(mac.finalize().into_bytes().to_vec())
            }
            Proof::Key(key) => {
                let mut message = Vec::with_capacity(nonce.len() + 8);
                message.extend_from_slice(nonce);
                message.extend_from_slice(&timestamp.to_le_bytes());
                Ok(key.sign(&message).to_bytes().to_vec())
            }
        }
    }

    /// The two fields an AUTH_RESPONSE is proven with, produced together.
    ///
    /// Together because they have to agree: the server knows from its own
    /// record which proof it will demand, and it reads the code only on the
    /// secret path — a key device signs, and an empty `totp_code` is what its
    /// response carries. Building the two apart is how they could end up
    /// disagreeing.
    fn prove(&self, nonce: &[u8], timestamp: i64) -> Result<(String, Vec<u8>), ClientError> {
        let signature = self.sign_challenge(nonce, timestamp)?;
        match &self.proof {
            Proof::Totp { .. } => Ok((self.generate_code()?, signature)),
            Proof::Key(_) => Ok((String::new(), signature)),
        }
    }

    /// Turn a failed handshake read into an error that says what happened.
    ///
    /// A refusal races its own connection close: the server writes AUTH_FAILED
    /// and then immediately closes, and whichever the client sees first decides
    /// between "your credentials were refused" and a bare transport error —
    /// "connection lost", which reads like the server died. The close frame
    /// carries the verdict independently of those bytes, so read it back.
    fn read_failure(
        &self,
        conn: &Connection,
        step: &str,
        source: impl fmt::Display,
    ) -> ClientError {
        let detail = format!("{}: {}", step, source);

        let Some(iroh::endpoint::ConnectionError::ApplicationClosed(close)) = conn.close_reason()
        else {
            // Nothing to learn from a connection that is still up, or that died
            // a transport death with no application verdict attached.
            return ClientError::ConnectionFailed(detail);
        };

        match u32::try_from(close.error_code.into_inner()) {
            Ok(auth_close_code::REJECTED) => {
                let subject = if self.client_id.is_empty() {
                    "these credentials".to_string()
                } else {
                    format!("the credentials of client '{}'", self.client_id)
                };
                ClientError::AuthenticationFailed(format!(
                    "the server rejected {subject} — the client_id/secret pair does not match \
                     its [auth].clients (the reason itself never arrived, the close did)"
                ))
            }
            Ok(auth_close_code::REQUIRED) => ClientError::ConnectionFailed(format!(
                "{}: the server closed the connection mid-handshake without ever accepting AUTH_START — \
                 either it does not have 2FA enabled at all, or the two sides run different handshake versions",
                detail
            )),
            Ok(auth_close_code::TOO_MANY) => ClientError::ConnectionFailed(format!(
                "{}: the server refused this connection because this peer already holds too many",
                detail
            )),
            Ok(auth_close_code::PEER_NOT_ALLOWED) => ClientError::AuthenticationFailed(
                "the server runs a [peers] allow-list and does not permit this Node ID; ask \
                 its operator to add it (the reason itself never arrived, the close did)"
                    .to_string(),
            ),
            Ok(auth_close_code::REVOKED) => {
                let subject = if self.client_id.is_empty() {
                    "the credentials this connection authenticated with".to_string()
                } else {
                    format!("the credentials of client '{}'", self.client_id)
                };
                // Re-authenticating on a fresh connection will not help, and
                // saying so is the point: this is not a wrong code that a retry
                // could fix, it is an entry the server no longer has.
                ClientError::AuthenticationFailed(format!(
                    "the server revoked {subject} while this connection was open — an operator ran \
                     `nexapipe client revoke` against it. Import a credential again to reconnect; \
                     retrying this connection only repeats the refusal"
                ))
            }
            _ => ClientError::ConnectionFailed(detail),
        }
    }

    /// Authenticate with the server over a connection.
    pub async fn authenticate(&self, conn: &Connection) -> Result<(), ClientError> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to open stream: {}", e)))?;
        self.authenticate_on(conn, &mut send, &mut recv).await
    }

    /// The handshake itself, over a stream the caller opened.
    ///
    /// Split out so an enrollment can run ahead of it on the same stream: the
    /// server reads ENROLL_START and AUTH_START in order off one bi-stream, and
    /// a second stream would arrive looking like data sent before any
    /// credential.
    pub async fn authenticate_on(
        &self,
        conn: &Connection,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<(), ClientError> {
        // Four round trips against a server this client may be meeting for the
        // first time. The server's own deadline covers the first stream only, so
        // a server that answers the challenge and then goes quiet is covered by
        // nothing on either side — and in `Enrollment::exchange` this runs while
        // the endpoint's lock is held, which would stall every other caller.
        let handshake = self.authenticate_on_inner(conn, send, recv);
        match tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, handshake).await {
            Ok(outcome) => outcome,
            Err(_) => Err(ClientError::ConnectionFailed(format!(
                "the server did not finish the 2FA handshake within {}s",
                AUTH_HANDSHAKE_TIMEOUT.as_secs()
            ))),
        }
    }

    async fn authenticate_on_inner(
        &self,
        conn: &Connection,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<(), ClientError> {
        use nexapipe_proto::auth::AuthMessage;

        // Step 1: Send AUTH_START
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // The old form, with the version this client speaks announced inside
        // it. A server that predates the version byte drops the field it does
        // not know and answers in the old form; a server that knows it
        // answers in the version that was asked for. A version byte *in front
        // of* the JSON would break the first case, because a server that
        // predates it reads the payload as JSON and would choke on it.
        let start_msg = self.start_message(timestamp);
        write_message(send, &start_msg, Format::LegacyJson).await?;

        // Step 2: Receive AUTH_CHALLENGE
        let (challenge, format) = read_message(recv)
            .await
            .map_err(|e| self.read_failure(conn, "the AUTH_CHALLENGE could not be read", e))?;
        let nonce = match challenge {
            AuthMessage::Challenge { nonce } => nonce,
            _ => return Err(ClientError::Other("Expected AUTH_CHALLENGE".to_string())),
        };

        // Step 3: Generate and send AUTH_RESPONSE. The signature proves
        // possession of the credential and binds the response to this
        // connection's challenge; the timestamp is taken now, not reused from
        // AUTH_START, so the server's freshness window is measured from the
        // actual response. The code travels beside it for a secret-based
        // credential and is empty for a key-based one — see `prove`.
        let response_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let (totp_code, signature) = self.prove(&nonce, response_timestamp)?;

        // The same name AUTH_START carried, and not for politeness: this is the
        // message the server reads the device from when it picks which secret
        // to check against, so a response that omits it proves possession of
        // the client's own secret while asking to be counted as a device.
        let response_msg = AuthMessage::Response {
            client_id: self.client_id.clone(),
            timestamp: response_timestamp,
            totp_code,
            signature,
            device_id: self.device_id.clone(),
        };

        // The form the server answered in: a server that knows the binary
        // form is answered in it, and a server that does not is answered in
        // the old one — which is the only form it can read.
        write_message(send, &response_msg, format).await?;
        send.finish().map_err(|e| {
            ClientError::ConnectionFailed(format!("Failed to finish stream: {}", e))
        })?;

        // Step 4: Receive AUTH_OK or AUTH_FAILED
        let (result_msg, _) = read_message(recv).await.map_err(|e| {
            self.read_failure(conn, "the authentication result could not be read", e)
        })?;

        match result_msg {
            AuthMessage::Ok => Ok(()),
            AuthMessage::Failed { reason } => Err(ClientError::AuthenticationFailed(reason)),
            _ => Err(ClientError::Other("Unexpected response".to_string())),
        }
    }

    /// The first message of the handshake.
    ///
    /// It carries the version this client speaks, **inside** the JSON: a
    /// server that predates the version byte drops the field it does not know
    /// and answers in the old form, and a server that knows it answers in the
    /// version that was asked for. A version byte in front of the JSON would
    /// break the first case, because a server that predates it reads the
    /// payload as JSON and would choke on it.
    fn start_message(&self, timestamp: i64) -> AuthMessage {
        AuthMessage::Start {
            client_id: self.client_id.clone(),
            timestamp,
            device_id: self.device_id.clone(),
            version: Some(VERSION_BINARY),
        }
    }

    /// The secret, back in the Base32 form it was configured with.
    ///
    /// An enrollment hands out a credential the app has never seen, and an app
    /// that cannot read it back cannot persist it — which would leave every
    /// restart trying to spend a token that has already been burned.
    ///
    /// Empty for a key-based credential, which has no secret: what such an app
    /// has to persist is the key — the private half is its own to keep, and
    /// [`Self::public_key_hex`] is the half the server knows it by.
    ///
    /// The string this returns is a plain one: it is on its way to durable
    /// storage, which is outside anything this process could wipe. That is the
    /// point of the method, not an oversight — the copy that stays here is
    /// still a [`SecretBytes`], and it is wiped with the credential.
    pub fn secret_base32(&self) -> String {
        match &self.proof {
            Proof::Totp { secret, .. } => base32::encode(
                base32::Alphabet::Rfc4648 { padding: false },
                secret.as_slice(),
            ),
            Proof::Key(_) => String::new(),
        }
    }

    /// The algorithm name, for the same reason as [`Self::secret_base32`].
    ///
    /// Empty for a key-based credential: there is no TOTP at all on that path,
    /// so there is no algorithm to name.
    pub fn algorithm_name(&self) -> &'static str {
        match &self.proof {
            Proof::Totp { algorithm, .. } => algorithm.name(),
            Proof::Key(_) => "",
        }
    }

    /// The public half of the key this credential proves itself with, lowercase
    /// hex — the spelling the server stores and an app has to persist.
    ///
    /// `None` for a secret-based credential, which has no key; a caller uses
    /// that to tell the two kinds apart. The private half is deliberately not
    /// readable from here: it was the caller's own before it was handed over,
    /// and the caller is the one that has to keep it.
    pub fn public_key_hex(&self) -> Option<String> {
        match &self.proof {
            Proof::Totp { .. } => None,
            Proof::Key(key) => Some(hex::encode(key.public().as_bytes())),
        }
    }
}

/// A device's own Ed25519 key: the credential a device proves itself with when
/// nobody is there to read a code off a screen.
///
/// The private half is the credential and never leaves the device; the public
/// half is what the server stores, under the name of the device the key was
/// issued to. Both are lowercase hex, because that is the spelling the server's
/// config file uses and the only spelling an app has to write down — an app
/// that keeps a key across a restart has nowhere else to put it but a string.
///
/// The type exists so that both apps agree on that spelling, and so that
/// neither of them has to do Ed25519 itself: Android's cryptography API has no
/// Ed25519 below API 33, and the app supports API 26.
#[derive(Clone)]
pub struct DeviceKey {
    key: iroh::SecretKey,
}

impl DeviceKey {
    /// A fresh key pair. The private half is never handed to anybody; the
    /// public half is what an enrollment offers.
    pub fn generate() -> Self {
        Self {
            key: iroh::SecretKey::generate(),
        }
    }

    /// Reads a private half back from the spelling it was stored in.
    ///
    /// The length is what is checked, and it is checked strictly: a key is 32
    /// bytes, so a stored key is 64 hex characters, and anything else is a
    /// string that is not a key. The bytes themselves are not a point on a
    /// curve — an Ed25519 private key is arbitrary bytes, and a key that was
    /// never offered to a server simply proves nothing.
    pub fn from_hex(spelled: &str) -> Result<Self, ClientError> {
        let trimmed = spelled.trim();
        let decoded = hex::decode(trimmed).map_err(|_| {
            ClientError::InvalidConfig(
                "a device key is 64 hex characters, and this is not hex".into(),
            )
        })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            ClientError::InvalidConfig(format!(
                "a device key is 64 hex characters, and this one is {} characters",
                trimmed.len()
            ))
        })?;
        Ok(Self {
            key: iroh::SecretKey::from_bytes(&bytes),
        })
    }

    /// The private half, lowercase hex — the spelling an app persists.
    ///
    /// It is the credential, so it is written down the way a TOTP secret is:
    /// encrypted at rest, behind the operating system's own door, and never
    /// shown on a screen.
    pub fn private_hex(&self) -> String {
        hex::encode(self.key.to_bytes())
    }

    /// The public half, lowercase hex — the spelling the server stores and the
    /// one an app displays.
    pub fn public_hex(&self) -> String {
        hex::encode(self.key.public().as_bytes())
    }

    /// The key itself, for the paths that need to sign with it.
    pub fn secret_key(&self) -> &iroh::SecretKey {
        &self.key
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key's own `Debug` is redacted, so this cannot leak the private
        // half — but the public half is named, because it is not a secret and
        // it is what identifies this device to an operator.
        f.debug_struct("DeviceKey")
            .field("public_key", &self.public_hex())
            .finish()
    }
}

/// A credential the server issued during enrollment, in the form an app can
/// store it.
///
/// Handed out once by
/// [`crate::connection_pool::IrohConnectionPool::take_issued_credential`],
/// right after a token has been spent. An app that keeps its settings somewhere
/// durable has to write these fields down: the token is gone, so a restart that
/// still holds the invite cannot enroll a second time.
///
/// `Debug` masks `secret`, for the reason [`TwoFactorConfig`]'s does.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    pub client_id: String,
    /// Base32, exactly as it goes into [`TwoFactorAuth::new`] next time.
    /// Empty when the device was issued a key instead — see [`Self::public_key`].
    ///
    /// A [`SecretString`]: the credential is wiped when this is dropped, and
    /// the value is read through [`Secret::expose_secret`] where it has to be.
    pub secret: SecretString,
    pub algorithm: String,
    /// The public half of the key the device was issued, lowercase hex — the
    /// spelling the server stores — with `None` for a credential that is a
    /// secret.
    ///
    /// A `Some` here is also what says the credential proves itself with a
    /// signature: an app persisting it has to keep the private half it
    /// generated, because the server knows this device by its key and would
    /// refuse a secret it never issued.
    pub public_key: Option<String>,
    /// The device this credential was issued for, which has to be persisted
    /// with it: the server filed the secret under that name, so an app that
    /// writes down the secret and not the name has a credential it can no
    /// longer answer with. `None` is the unnamed device — a server that
    /// answered an enrollment which named none, or one that predates devices
    /// entirely.
    pub device: Option<String>,
}

impl std::fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCredential")
            .field("client_id", &self.client_id)
            .field("secret", &masked(self.secret.as_str()))
            .field("algorithm", &self.algorithm)
            .field("device", &self.device)
            .finish()
    }
}

/// A credential that has not been issued yet.
///
/// A `v=2` invitation carries one of these instead of the client's secret: the
/// link stops being a credential the moment it has been used, because what it
/// holds is a token the server exchanges for a freshly generated secret — or,
/// when the enrollment offers one, records as a device key — and then
/// discards. The trade is that the app has to keep what comes back — see
/// [`Enrollment::exchange`].
///
/// No `PartialEq`: an offered key is secret material with no equality of its
/// own, and comparing enrollments is not a question this type is asked.
///
/// `Debug` masks `token`, for the reason [`TwoFactorConfig`]'s does: an
/// unspent invitation link *is* the credential, and this is the struct an app
/// is most likely to log while working out why an enrollment did not go through.
#[derive(Clone)]
pub struct Enrollment {
    client_id: String,
    /// The one-time token an invitation carried.
    ///
    /// A [`SecretString`]: an unspent invitation link *is* the credential, so
    /// the token is wiped when the enrollment is dropped — which is what
    /// happens the moment it has been spent.
    token: SecretString,
    /// The name to be enrolled under. The token is what authorizes the
    /// exchange, so this is a request rather than a claim: the server is free
    /// to answer with it or to refuse it, and what it answers with is what the
    /// credential is filed under.
    device_id: Option<String>,
    /// The device key to offer, if any. What travels is the public half, and
    /// what comes back tells this side whether the offer was taken: an empty
    /// `secret` in ENROLL_ISSUE is the server saying the key was recorded.
    ///
    /// The private half is wiped when the enrollment is dropped, the way the
    /// rest of the credentials here are: `iroh::SecretKey` is built on
    /// ed25519-dalek, whose signing key zeroes itself on the way out.
    key: Option<iroh::SecretKey>,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("client_id", &self.client_id)
            .field("token", &masked(self.token.as_str()))
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl Enrollment {
    pub fn new(client_id: &str, token: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            token: SecretString::new(token.to_string()),
            device_id: None,
            key: None,
        }
    }

    /// The same enrollment, asking to be issued under one device name.
    pub fn with_device(mut self, device_id: &str) -> Self {
        self.device_id = Some(device_id.to_string());
        self
    }

    /// The same enrollment, offering this device's key.
    ///
    /// What the server makes of the offer decides the credential: one that
    /// knows keys files the public half under the device name and answers with
    /// an empty secret — from then on nothing but a signature is sent — while
    /// one that predates them ignores the field and issues a secret, which
    /// then has to work as it always did. The public half travels in the
    /// clear, being public; the private half stays here.
    pub fn with_key(mut self, key: iroh::SecretKey) -> Self {
        self.key = Some(key);
        self
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The device this enrollment will ask for, if it was given one.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Trades the token for the real credential and authenticates with it, in
    /// one stream: ENROLL_START/ENROLL_ISSUE, then the ordinary handshake.
    ///
    /// The issued [`TwoFactorAuth`] is returned rather than kept, because what
    /// happens to it is the caller's decision — the process can use it for as
    /// long as it lives, but an app that wants to survive a restart has to
    /// persist [`TwoFactorAuth::secret_base32`] and drop the token.
    pub async fn exchange(&self, conn: &Connection) -> Result<TwoFactorAuth, ClientError> {
        // The same deadline the handshake below gets, and for the same reason:
        // a server that takes the ENROLL_START and never answers leaves this
        // future pending forever, and callers hold the endpoint's lock while
        // they wait for it.
        let exchange = self.exchange_inner(conn);
        match tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, exchange).await {
            Ok(outcome) => outcome,
            Err(_) => Err(ClientError::ConnectionFailed(format!(
                "the server did not answer the enrollment within {}s",
                AUTH_HANDSHAKE_TIMEOUT.as_secs()
            ))),
        }
    }

    async fn exchange_inner(&self, conn: &Connection) -> Result<TwoFactorAuth, ClientError> {
        use nexapipe_proto::auth::AuthMessage;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("Failed to open stream: {}", e)))?;

        // The old form: this is the first message of the exchange, and the
        // server reading it may be one that predates the version byte. The
        // version is announced in the AUTH_START that follows, on the same
        // stream.
        write_message(
            &mut send,
            &AuthMessage::EnrollStart {
                client_id: self.client_id.clone(),
                // Onto the wire, and out of this process: the copy that
                // travels is a plain string on the other side, because the
                // receiver has to compare it — but the one here is still a
                // `Secret`, and is wiped with the message.
                token: self.token.clone(),
                device_id: self.device_id.clone(),
                public_key: self
                    .key
                    .as_ref()
                    .map(|key| hex::encode(key.public().as_bytes())),
            },
            Format::LegacyJson,
        )
        .await?;

        let (issued_message, _) = read_message(&mut recv).await?;
        let issued = match issued_message {
            AuthMessage::EnrollIssue {
                client_id,
                secret,
                algorithm,
                digits,
                period,
                device_id,
            } => {
                if client_id != self.client_id {
                    return Err(ClientError::AuthenticationFailed(
                        "the server issued a credential for a different client id".to_string(),
                    ));
                }
                if secret.as_str().is_empty() {
                    // No secret in the answer means the server recorded the
                    // key this enrollment offered — it only ever does that
                    // when the request carried one, so this is that key,
                    // whose private half never left this process.
                    let Some(key) = self.key.clone() else {
                        return Err(ClientError::Other(
                            "the server issued an empty secret, but this enrollment offered \
                             no key"
                                .to_string(),
                        ));
                    };
                    // A key is one device's credential; the unnamed slot is
                    // the client's shared secret and the server refuses to
                    // file a key there, so a key answer always names the
                    // device it was filed under.
                    let Some(name) = device_id else {
                        return Err(ClientError::Other(
                            "the server issued a key credential without naming the device \
                             it was filed under"
                                .to_string(),
                        ));
                    };
                    TwoFactorAuth::with_key(&client_id, key, &name)
                } else {
                    // A secret came back, so a secret is the credential:
                    // either that is what was asked for, or a key was offered
                    // and the server predates keys — it ignores the field and
                    // issues a secret as it always has, which then has to
                    // work.
                    //
                    // The name the server filed this secret under is the only
                    // name this credential has, and it is whatever came back
                    // here — asked for in ENROLL_START, answered in this one.
                    //
                    // An answer that names no device is a server that filed it
                    // under no device: it predates the table, or it was asked
                    // for none. Either way it has nothing to match a name
                    // against, and putting the one that was asked for back
                    // sends it on every handshake from here on — which the
                    // server answers by refusing a device it does not know.
                    // Narrowed the way `digits` is narrowed in `generate_code`, and
                    // for the same reason: a cast truncates a period that does not
                    // fit into one that looks deliberate — a 90-second step read as
                    // some other number — where a refusal names the value the
                    // server actually sent.
                    let period = u32::try_from(period).map_err(|_| {
                        ClientError::InvalidConfig(format!("{period} is not a TOTP period"))
                    })?;
                    // The algorithm is a closed type on the wire now: a name
                    // nobody supports is refused where the message is read,
                    // rather than quietly turned into a different algorithm
                    // here — which would compute codes the server does not
                    // accept, and every attempt would fail with "wrong code".
                    let algorithm = TotpAlgorithm::from(algorithm);
                    let issued = TwoFactorAuth::with_params(
                        &client_id,
                        secret.as_str(),
                        algorithm,
                        period,
                        digits,
                    )?;
                    match device_id {
                        Some(name) => issued.with_device(&name),
                        None => issued,
                    }
                }
            }
            // One reply for every way this can fail: an enrollment token is
            // either right or it is not, and saying which would only help
            // someone who is guessing.
            AuthMessage::EnrollFailed { reason } => {
                return Err(ClientError::AuthenticationFailed(reason));
            }
            other => {
                return Err(ClientError::Other(format!(
                    "expected ENROLL_ISSUE, the server sent {}",
                    message_name(&other)
                )));
            }
        };

        issued.authenticate_on(conn, &mut send, &mut recv).await?;
        Ok(issued)
    }
}

/// Writes one length-prefixed message in the form asked for.
async fn write_message(
    send: &mut iroh::endpoint::SendStream,
    message: &AuthMessage,
    format: Format,
) -> Result<(), ClientError> {
    let bytes = message
        .to_payload(format)
        .map_err(|e| ClientError::Other(format!("Serialization error: {}", e)))?;
    let len = bytes.len() as u32;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send length: {}", e)))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to send message: {}", e)))
}

/// Reads one length-prefixed message.
async fn read_message(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<(AuthMessage, Format), ClientError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| {
        ClientError::ConnectionFailed(format!("Failed to read message length: {e}"))
    })?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    // The server caps what it will read at 64 KiB; anything longer is a peer
    // that is not speaking this protocol, not a message worth allocating for.
    if msg_len > MAX_AUTH_MESSAGE {
        return Err(ClientError::ConnectionFailed(format!(
            "auth message length {msg_len} is out of range"
        )));
    }
    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf)
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("Failed to read message: {e}")))?;
    AuthMessage::from_payload(&msg_buf)
        .map_err(|e| ClientError::Other(format!("Deserialization error: {}", e)))
}

/// The `type` tag of a message, for errors that name what arrived.
fn message_name(message: &AuthMessage) -> &'static str {
    match message {
        AuthMessage::Start { .. } => "AUTH_START",
        AuthMessage::Challenge { .. } => "AUTH_CHALLENGE",
        AuthMessage::Response { .. } => "AUTH_RESPONSE",
        AuthMessage::Ok => "AUTH_OK",
        AuthMessage::Failed { .. } => "AUTH_FAILED",
        AuthMessage::EnrollStart { .. } => "ENROLL_START",
        AuthMessage::EnrollIssue { .. } => "ENROLL_ISSUE",
        AuthMessage::EnrollFailed { .. } => "ENROLL_FAILED",
    }
}

/// The largest AUTH_* message the client accepts.
///
/// Mirrors `MAX_AUTH_MESSAGE` in `crates/nexapipe/src/conn/mod.rs`: the length
/// prefix is read before anything is known about the peer, so it is not
/// trusted until it is in range.
const MAX_AUTH_MESSAGE: usize = 64 * 1024;

/// How long the client waits for the server to finish the handshake.
///
/// Comfortably longer than the server's own five-second wait for the first
/// stream: that one covers a client that never speaks, while this covers a
/// server that answers and then stalls, which nothing else on either side does.
const AUTH_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Generate a new secret for client setup
///
/// A plain string, because it is on its way to a config file or an
/// authenticator app: the copy that leaves this process is not ours to wipe.
pub fn generate_secret() -> String {
    TotpSecret::generate().to_base32()
}

/// Whether a device name the server will accept.
///
/// The rule is the server's, and it now lives with the server's: printable
/// ASCII, space excluded, not empty, and short enough to sit in a config key
/// and a log line. A hostname is the obvious thing to name a device after and
/// the obvious way to break this — "MacBook Pro" has a space in it — so
/// whatever builds a name has to put the rule somewhere it is applied rather
/// than remembered.
///
/// An app can tell before it enrols rather than after, which is why it is
/// here at all: [`nexapipe_proto::auth::is_presentable_device_id`] is the same
/// rule, and this is the name it answers to on the client side.
pub fn device_id_is_usable(id: &str) -> bool {
    nexapipe_proto::auth::is_presentable_device_id(id)
}

#[cfg(test)]
mod tests {
    use super::{
        AuthMessage, DeviceKey, Enrollment, IssuedCredential, TotpAlgorithm, TwoFactorAuth,
        TwoFactorConfig, device_id_is_usable,
    };
    use nexapipe_proto::auth::{Algorithm as ProtoAlgorithm, MAX_DEVICE_ID_LEN, VERSION_BINARY};
    use nexapipe_proto::secret::SecretString;

    /// An algorithm nobody supports is refused, and the refusal says what was
    /// wrong.
    ///
    /// A name quietly turned into a different algorithm is a silent downgrade:
    /// the client computes codes the server does not accept, and every attempt
    /// fails with "wrong code" rather than the algorithm being named once.
    #[test]
    fn an_unknown_algorithm_name_is_refused() {
        let error = TotpAlgorithm::try_from_name("sha-256").expect_err("nobody supports it");
        let message = error.to_string();

        assert!(message.contains("sha-256"), "{message}");
        assert!(message.contains("SHA1"), "{message}");
        assert!(message.contains("SHA256"), "{message}");
        assert!(message.contains("SHA512"), "{message}");
    }

    /// The three names the client supports, in any case.
    #[test]
    fn the_supported_algorithm_names_parse_in_any_case() {
        for name in ["sha1", "SHA1", "Sha1", " sha1 "] {
            assert_eq!(
                TotpAlgorithm::try_from_name(name).expect("sha1"),
                TotpAlgorithm::SHA1,
                "{name:?} is sha1"
            );
        }
        for name in ["sha256", "SHA256", "Sha256"] {
            assert_eq!(
                TotpAlgorithm::try_from_name(name).expect("sha256"),
                TotpAlgorithm::SHA256,
                "{name:?} is sha256"
            );
        }
        for name in ["sha512", "SHA512", "Sha512"] {
            assert_eq!(
                TotpAlgorithm::try_from_name(name).expect("sha512"),
                TotpAlgorithm::SHA512,
                "{name:?} is sha512"
            );
        }
    }

    /// A name that is not there is the default, `sha1`.
    ///
    /// Which is what a URI that leaves the parameter out means, and what the
    /// Android client does with the same field.
    #[test]
    fn an_absent_algorithm_name_is_the_default() {
        assert_eq!(
            TotpAlgorithm::try_from_name("").expect("the default"),
            TotpAlgorithm::SHA1
        );
    }

    /// A `Debug` that prints a secret turns every log line, panic message and
    /// bug report that touches one into a credential disclosure — and these are
    /// exactly the values an app logs while working out why authentication
    /// stopped working. Every holder of a secret gets a hand-written `Debug` for
    /// that reason; this is the test that keeps the hand-written ones honest.
    #[test]
    fn no_debug_output_carries_a_secret() {
        let secret = "JBSWY3DPEHPK3PXP";
        let config = TwoFactorConfig {
            client_id: "node-1".to_string(),
            secret: SecretString::new(secret.to_string()),
            algorithm: TotpAlgorithm::SHA1,
        };
        let auth = TwoFactorAuth::new("node-1", secret, TotpAlgorithm::SHA1).expect("a credential");
        let issued = IssuedCredential {
            client_id: "node-1".to_string(),
            secret: SecretString::new(secret.to_string()),
            algorithm: "sha1".to_string(),
            public_key: None,
            device: Some("laptop".to_string()),
        };
        let enrollment = Enrollment::new("node-1", "an-invitation-token");

        for rendered in [
            format!("{config:?}"),
            format!("{auth:?}"),
            format!("{issued:?}"),
            format!("{enrollment:?}"),
        ] {
            assert!(
                !rendered.contains(secret),
                "a TOTP seed reached a Debug output: {rendered}"
            );
            assert!(
                !rendered.contains("an-invitation-token"),
                "an enrollment token reached a Debug output: {rendered}"
            );
        }
    }

    /// Masking must not turn into silence: a reader debugging a login needs to
    /// tell "no secret configured" from "a secret is there and I cannot see it",
    /// and needs to know the value is not the wrong length.
    #[test]
    fn a_masked_secret_still_says_whether_there_is_one() {
        let with_secret = TwoFactorConfig {
            client_id: "node-1".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: TotpAlgorithm::SHA1,
        };
        let without = TwoFactorConfig {
            client_id: "node-1".to_string(),
            secret: SecretString::new(String::new()),
            algorithm: TotpAlgorithm::SHA1,
        };

        let present = format!("{with_secret:?}");
        let absent = format!("{without:?}");

        // Neither message interpolates the rendering: a failure here would print
        // whatever the `Debug` let through, which is the leak under test.
        assert!(
            present != absent,
            "a masked secret and an absent one are indistinguishable"
        );
        assert!(present.contains("16 chars"), "the length is not reported");
        // The whole point of masking, stated as a test: the length is not the value.
        assert!(!present.contains("JBSWY3DPEHPK3PXP"));
    }

    /// A stand-in nonce, built rather than written out — the twin of the helper
    /// in `crates/nexapipe/src/auth/device_key.rs`. No test here needs a
    /// particular value, and a literal array where a nonce goes reads to the
    /// scanner as a hard-coded key.
    fn test_nonce(seed: u8) -> [u8; 32] {
        std::array::from_fn(|i| seed ^ (i as u8))
    }

    /// The mirror of the test in `crates/nexapipe/src/auth/protocol.rs`: the
    /// two sides define these messages separately, and the tag is all that
    /// decides which one a peer is looking at.
    #[test]
    fn enrollment_messages_keep_their_wire_names() {
        let start = AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("tok".to_string()),
            device_id: None,
            public_key: None,
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_START""#), "{json}");

        let issue = AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: ProtoAlgorithm::Sha1,
            digits: 6,
            period: 30,
            device_id: None,
        };
        let json = String::from_utf8(issue.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_ISSUE""#), "{json}");

        let failed = AuthMessage::EnrollFailed {
            reason: "no".to_string(),
        };
        let json = String::from_utf8(failed.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""type":"ENROLL_FAILED""#), "{json}");
    }

    /// The mirror of the server's test: the two sides define these messages
    /// separately, and the field may not appear at all — a client that predates
    /// keys sends none — so one without it has to still parse, and stay the
    /// same message on the way back out.
    #[test]
    fn an_enrollment_without_a_key_still_parses_on_the_wire() {
        let wire =
            br#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop"}"#;
        let start = AuthMessage::from_bytes(wire).unwrap();
        match &start {
            AuthMessage::EnrollStart { public_key, .. } => assert_eq!(public_key, &None),
            other => panic!("expected ENROLL_START, got {other:?}"),
        }
        assert_eq!(
            start.to_bytes().unwrap(),
            wire.to_vec(),
            "no public_key goes out as no public_key"
        );
    }

    /// And one that offers a key round-trips, exactly: the field is carried
    /// whole, not normalized in flight.
    #[test]
    fn an_enrollment_offering_a_key_round_trips_byte_exactly() {
        let wire = br#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop","public_key":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}"#;
        let start = AuthMessage::from_bytes(wire).unwrap();
        match &start {
            AuthMessage::EnrollStart { public_key, .. } => assert_eq!(
                public_key.as_deref(),
                Some("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
            ),
            other => panic!("expected ENROLL_START, got {other:?}"),
        }
        assert_eq!(start.to_bytes().unwrap(), wire.to_vec());
    }

    /// The offer is made of the public half, lowercase hex — the spelling the
    /// server's config stores — and the builder keeps the private half, which
    /// is what will sign every challenge once the offer is taken.
    #[test]
    fn an_enrollment_can_offer_a_key_beside_its_device_name() {
        let key = iroh::SecretKey::generate();
        let public_key = hex::encode(key.public().as_bytes());

        let enrollment = Enrollment::new("client-001", "tok")
            .with_device("phone-1a2b3c4d")
            .with_key(key.clone());
        assert!(
            enrollment.key.is_some(),
            "the offered key is kept to sign with"
        );

        // What those two produce on the wire, as `exchange_inner` sends it.
        let start = AuthMessage::EnrollStart {
            client_id: enrollment.client_id().to_string(),
            token: SecretString::new("tok".to_string()),
            device_id: enrollment.device_id().map(str::to_string),
            public_key: enrollment
                .key
                .as_ref()
                .map(|key| hex::encode(key.public().as_bytes())),
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(
            json.contains(&format!(r#""public_key":"{public_key}""#)),
            "{json}"
        );
        assert!(
            !json.contains(&hex::encode(key.to_bytes())),
            "the private half never goes on the wire: {json}"
        );
    }

    /// A key-based credential puts a signature where a secret-based one puts an
    /// HMAC and carries no code at all: the server reads the code only on the
    /// secret path, and an empty one is what a key response looks like.
    #[test]
    fn a_key_credential_responds_with_a_signature_and_no_code() {
        let key = iroh::SecretKey::generate();
        let public_key = hex::encode(key.public().as_bytes());
        let auth = TwoFactorAuth::with_key("client-001", key, "phone-1a2b3c4d");

        let (totp_code, signature) = auth.prove(&test_nonce(0x0a), 1_700_000_000).unwrap();
        assert_eq!(totp_code, "", "a key device sends no code");
        assert_eq!(signature.len(), 64, "an Ed25519 signature is 64 bytes");

        assert_eq!(auth.public_key_hex(), Some(public_key));
        assert_eq!(auth.secret_base32(), "", "a key credential has no secret");
        assert_eq!(auth.algorithm_name(), "", "and no algorithm to name");
        assert_eq!(auth.device_id(), Some("phone-1a2b3c4d"));
        assert!(
            auth.generate_code().is_err(),
            "there is no code to generate"
        );
    }

    /// What a key device signs is the same byte string the secret path HMACs —
    /// the nonce, byte for byte, then the timestamp little-endian — because the
    /// server verifies against exactly those bytes. This is the client half of
    /// the pin the server's `device_key` tests keep.
    #[test]
    fn a_key_credential_signs_the_nonce_then_the_little_endian_timestamp() {
        let key = iroh::SecretKey::generate();
        let public = key.public();
        let auth = TwoFactorAuth::with_key("client-001", key, "phone-1a2b3c4d");

        let nonce = test_nonce(0x01);
        let signature = auth.sign_challenge(&nonce, 0x0102030405060708).unwrap();
        assert_eq!(signature.len(), 64);

        let mut message = nonce.to_vec();
        message.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        public
            .verify(
                &message,
                &iroh::Signature::try_from(signature.as_slice()).expect("64 bytes of signature"),
            )
            .expect("the signature verifies against the public half");
    }

    /// An enrollment that succeeds has to hand back something the app can
    /// write down, or a restart has nothing left to authenticate with.
    #[test]
    fn an_issued_credential_comes_back_in_the_form_it_was_configured_with() {
        let auth = TwoFactorAuth::with_params(
            "client-001",
            "JBSWY3DPEHPK3PXP",
            TotpAlgorithm::SHA256,
            30,
            6,
        )
        .unwrap();
        assert_eq!(auth.secret_base32(), "JBSWY3DPEHPK3PXP");
        assert_eq!(auth.algorithm_name(), "sha256");
    }

    /// `base32` 0.5 decodes upper case only, so a secret that is correct but
    /// written in lower case — a hand-copied config, an app that stores what
    /// it was handed — used to decode and would now be rejected.
    #[test]
    fn a_secret_decodes_in_any_spelling() {
        for spelling in [
            "JBSWY3DPEHPK3PXP",
            "jbswy3dpehpk3pxp",
            "JbSwY3dPeHpK3pXp",
            "JBSW Y3DP EHPK 3PXP",
            "jbswy3dpehpk3pxp==",
        ] {
            let auth = TwoFactorAuth::new("client-001", spelling, TotpAlgorithm::SHA1)
                .unwrap_or_else(|e| panic!("{spelling:?} should decode: {e}"));
            assert_eq!(auth.secret_base32(), "JBSWY3DPEHPK3PXP", "{spelling:?}");
        }
    }

    /// The other half of the same guard: something that is not Base32 at all
    /// is still refused, in whatever spelling.
    #[test]
    fn a_secret_that_is_not_base32_is_still_refused() {
        assert!(TwoFactorAuth::new("client-001", "not-base32!", TotpAlgorithm::SHA1).is_err());
        assert!(TwoFactorAuth::new("client-001", "", TotpAlgorithm::SHA1).is_err());
    }

    /// A device is named on AUTH_START *and* on AUTH_RESPONSE, because the
    /// server reads the name off the response when it decides which secret to
    /// check against. Naming it on the first alone would ask to be counted as a
    /// device while proving possession of the client's own secret.
    #[test]
    fn a_named_device_speaks_on_both_messages() {
        let auth = TwoFactorAuth::new("client-001", "JBSWY3DPEHPK3PXP", TotpAlgorithm::SHA1)
            .unwrap()
            .with_device("laptop-7f3a9c21");
        assert_eq!(auth.device_id(), Some("laptop-7f3a9c21"));

        let start = AuthMessage::Start {
            client_id: auth.client_id().to_string(),
            timestamp: 0,
            device_id: auth.device_id().map(str::to_string),
            version: None,
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""device_id":"laptop-7f3a9c21""#), "{json}");

        let response = AuthMessage::Response {
            client_id: auth.client_id().to_string(),
            timestamp: 0,
            totp_code: "123456".to_string(),
            signature: vec![0u8; 32],
            device_id: auth.device_id().map(str::to_string),
        };
        let json = String::from_utf8(response.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""device_id":"laptop-7f3a9c21""#), "{json}");
    }

    /// The device that was never given a name has to look exactly like a client
    /// that predates devices: no `device_id` on the wire at all, not one set to
    /// null. A peer that predates this cannot be asked to understand a field it
    /// has never seen.
    #[test]
    fn an_unnamed_device_leaves_the_field_off_the_wire() {
        let auth =
            TwoFactorAuth::new("client-001", "JBSWY3DPEHPK3PXP", TotpAlgorithm::SHA1).unwrap();
        assert_eq!(auth.device_id(), None);

        let start = AuthMessage::Start {
            client_id: auth.client_id().to_string(),
            timestamp: 0,
            device_id: auth.device_id().map(str::to_string),
            version: None,
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(!json.contains("device_id"), "{json}");
    }

    /// The mirror of that, in the other direction: a server that predates
    /// per-device credentials sends no `device_id`, and ENROLL_ISSUE without
    /// one still has to deserialize.
    #[test]
    fn an_issue_from_a_server_that_names_no_device_still_parses() {
        let wire = br#"{"type":"ENROLL_ISSUE","client_id":"client-001","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}"#;
        let issue = AuthMessage::from_bytes(wire).unwrap();
        match issue {
            AuthMessage::EnrollIssue { device_id, .. } => assert_eq!(device_id, None),
            other => panic!("expected ENROLL_ISSUE, got {other:?}"),
        }
    }

    /// An enrollment carries the name it was given, and one that was given
    /// none asks for the client's own secret — which is the only thing a server
    /// that predates devices will answer.
    #[test]
    fn an_enrollment_asks_for_the_device_it_was_given() {
        assert_eq!(Enrollment::new("client-001", "tok").device_id(), None);
        let named = Enrollment::new("client-001", "tok").with_device("phone-1a2b3c4d");
        assert_eq!(named.device_id(), Some("phone-1a2b3c4d"));
        assert_eq!(named.client_id(), "client-001");
    }

    /// What the server will refuse, mirrored so an app can find out before a
    /// handshake rather than during one. A hostname is the obvious thing to
    /// name a device after, and "MacBook Pro" is the obvious way to break it.
    #[test]
    fn a_device_name_is_printable_ascii_without_spaces() {
        assert!(device_id_is_usable("laptop-7f3a9c21"));
        assert!(device_id_is_usable("phone"));

        assert!(!device_id_is_usable(""), "empty");
        assert!(!device_id_is_usable("MacBook Pro"), "a space");
        assert!(!device_id_is_usable("laptop\t"), "a tab");
        assert!(!device_id_is_usable("laptop\n"), "a newline");
        assert!(!device_id_is_usable("laptop‑pro"), "outside ASCII");
        assert!(
            !device_id_is_usable(&"x".repeat(MAX_DEVICE_ID_LEN + 1)),
            "too long"
        );

        assert!(device_id_is_usable(&"x".repeat(MAX_DEVICE_ID_LEN)));
    }

    /// A key survives the trip through the spelling an app stores it in, which
    /// is the only trip it ever makes: the private half is written down,
    /// sealed, and read back on the next start.
    #[test]
    fn a_device_key_round_trips_through_its_own_spelling() {
        let key = DeviceKey::generate();
        let private = key.private_hex();
        let public = key.public_hex();

        assert_eq!(private.len(), 64, "a private half is 32 bytes of hex");
        assert_eq!(public.len(), 64, "a public half is 32 bytes of hex");
        assert_ne!(private, public, "the two halves are not the same bytes");
        assert!(
            private
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{private} is lowercase hex"
        );

        let read_back = DeviceKey::from_hex(&private).expect("a key reads back");
        assert_eq!(read_back.private_hex(), private);
        assert_eq!(read_back.public_hex(), public);
    }

    /// A key is 32 bytes, so a stored key is 64 hex characters. Anything else
    /// is a string that is not a key, and an app that reads one has to be told
    /// rather than handed a credential that proves nothing.
    #[test]
    fn a_device_key_that_is_not_a_key_is_refused() {
        assert!(DeviceKey::from_hex("").is_err(), "empty");
        assert!(DeviceKey::from_hex("not hex at all").is_err(), "not hex");
        assert!(
            DeviceKey::from_hex(&"a".repeat(63)).is_err(),
            "one character short"
        );
        assert!(
            DeviceKey::from_hex(&"a".repeat(65)).is_err(),
            "one character long"
        );
    }

    /// The first message announces the version this client speaks, and the
    /// announcement rides **inside** the JSON.
    ///
    /// Inside, not in front: a server that predates the version byte drops the
    /// field it does not know and answers in the old form, and a version byte
    /// in front of the JSON would break that server instead — it reads the
    /// payload as JSON and would choke on it.
    #[test]
    fn the_first_message_announces_the_version_the_client_speaks() {
        let auth =
            TwoFactorAuth::new("client-001", "JBSWY3DPEHPK3PXP", TotpAlgorithm::SHA1).unwrap();
        let start = auth.start_message(1);

        assert_eq!(
            start.announced_version(),
            Some(VERSION_BINARY),
            "the client says which version it speaks"
        );
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""version":1"#), "{json}");
    }

    /// The key's own `Debug` is redacted, and this wrapper must not undo that:
    /// a `Debug` that prints a private half turns every log line and panic
    /// message that touches one into a credential disclosure.
    #[test]
    fn a_device_key_never_prints_its_private_half() {
        let key = DeviceKey::generate();
        let rendered = format!("{key:?}");

        assert!(!rendered.contains(&key.private_hex()), "{rendered}");
        assert!(
            rendered.contains(&key.public_hex()),
            "the public half is not a secret and is what names the device: {rendered}"
        );
    }
}
