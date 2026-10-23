//! The authentication handshake, as it travels between a client and the server.
//!
//! # Why this is here and not in either of them
//!
//! The handshake used to be written down twice — once in the server and once in
//! the client — and the two copies were kept in step by a comment in each
//! saying "keep in sync with the other one". That is the whole failure mode of
//! a protocol written down twice: a field added on one side and forgotten on
//! the other is a handshake that dies on its first message, and the comment
//! that was supposed to prevent it is the only thing standing between the two
//! copies.
//!
//! So there is one copy, and both sides link it. A change to the protocol is a
//! change here, and there is nowhere else for it to be forgotten.
//!
//! # The messages
//!
//! Protocol flow:
//! 1. Client -> Server: AUTH_START { client_id, timestamp }
//! 2. Server -> Client: AUTH_CHALLENGE { nonce }
//! 3. Client -> Server: AUTH_RESPONSE { client_id, timestamp, totp_code, signature }
//! 4. Server -> Client: AUTH_OK | AUTH_FAILED { reason }
//!
//! Optional enrollment, before the flow above:
//! 0a. Client -> Server: ENROLL_START { client_id, token }
//! 0b. Server -> Client: ENROLL_ISSUE { client_id, secret, algorithm, digits, period }
//!     | ENROLL_FAILED { reason }
//!
//! Enrollment is how an invitation that is safe to hand out stays safe after it
//! has been handed out: the link carries a one-time token instead of the
//! client's long-lived secret, the server exchanges it for a freshly generated
//! secret — or records the device key a key-based device offered — and burns
//! the token in the same write, so a link that was copied in transit stops
//! being a credential the moment it has been used once. The exchange runs on
//! the same stream, ahead of AUTH_START.
//!
//! The response is proven in one of two ways, and which one depends on what the
//! server holds for the device that answered — never on anything the
//! response itself says.
//!
//! The first is a secret: `signature` is
//! HMAC-SHA256(secret, nonce || timestamp.to_le_bytes()) over the client's
//! Base32-decoded TOTP secret, and `totp_code` carries a current code. So a
//! response only validates against the challenge that was issued for this very
//! connection — an intercepted response cannot be replayed over a new one —
//! and the timestamp bounds how long even the right response stays acceptable.
//!
//! The second is a device key: the same bytes signed with the Ed25519 private
//! half of the key registered under the device, with `totp_code` empty. A
//! device that runs unattended has nobody to read a code to it, so at
//! enrollment — the one moment a human is certainly present — such a device is
//! issued a credential that proves itself without one. Both proofs cover the
//! same message, so a response says the same thing either way: this client saw
//! this connection's nonce at this time.
//!
//! A `device_id` may ride along on the messages a client sends, and on the one
//! the server answers an enrollment with. It names which of a client's devices
//! is speaking, so one device can be revoked without rotating every other one.
//! It is `None` for a device that was never given a name — every client that
//! existed before per-device credentials — and a peer that does not know the
//! field ignores it rather than failing, so a client and a server built either
//! side of the change still complete a handshake.
//!
//! # The two forms
//!
//! A message travels in one of two forms, and the payload's first byte says
//! which:
//!
//! | first byte | the payload |
//! |---|---|
//! | `0x00` | the JSON form, behind the version byte |
//! | `0x01` | the binary form, behind the version byte |
//! | anything else | the JSON form with no version byte — what every peer sent before the version byte existed |
//!
//! A JSON message starts with `{`, which is neither of the two version bytes,
//! so the three are told apart by one look. The version byte is a
//! **discriminator**, not a negotiation: a message says what it is, and the
//! other end reads it. Nothing is agreed on beforehand, and nothing has to be
//! remembered between messages.
//!
//! The binary form exists because the JSON form is wasteful exactly where
//! the bytes are: a nonce and a signature are arrays of decimal numbers, so
//! each byte of either costs three. One handshake — a start, a challenge, a
//! response and an answer — is 427 bytes of JSON and 124 of binary.
//!
//! The JSON form stays, and stays readable, for as long as old peers exist.
//!
//! # What the wire format does change
//!
//! Two things, and both of them are things the wire should not have carried
//! in the first place:
//!
//! - **`algorithm` is a type.** It was a free-form string, and a name nobody
//!   supports was a name the receiving side had to decide what to do with. It
//!   is one of three now, and its spelling on the wire is the one the server
//!   has always sent.
//! - **`AUTH_START` can announce a version.** The field is optional and
//!   absent by default, so a peer that predates it sends exactly what it
//!   sent before.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::Sha256;

use crate::secret::SecretString;

/// The TOTP algorithm, as it travels.
///
/// The names are the canonical ones — `sha1`, `sha256`, `sha512` — and they
/// are read in any case, because the configuration this comes from is read
/// that way too. What is not free-form any more is the algorithm itself: it
/// was a string on the wire, and a name nobody supports was a name the
/// receiving side had to decide what to do with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// HMAC-SHA1 — the default, and what every client used before the choice
    /// existed.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl Algorithm {
    /// The canonical name, as the configuration and the wire spell it.
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
        }
    }

    /// The algorithm a name means, in any case — or `None` for a name nobody
    /// supports.
    ///
    /// `None` rather than a default: an algorithm that is quietly turned into
    /// a different one is a silent downgrade, and the client computes codes
    /// the server does not accept.
    pub fn from_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("sha1") {
            Some(Algorithm::Sha1)
        } else if name.eq_ignore_ascii_case("sha256") {
            Some(Algorithm::Sha256)
        } else if name.eq_ignore_ascii_case("sha512") {
            Some(Algorithm::Sha512)
        } else {
            None
        }
    }

    /// The byte this algorithm is in the binary form.
    pub fn to_byte(&self) -> u8 {
        match self {
            Algorithm::Sha1 => 0x01,
            Algorithm::Sha256 => 0x02,
            Algorithm::Sha512 => 0x03,
        }
    }

    /// The algorithm a byte is — or `None` for a byte that is not one.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Algorithm::Sha1),
            0x02 => Some(Algorithm::Sha256),
            0x03 => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

/// The name is read in any case, and a name nobody supports is an error
/// rather than a quiet fall back to SHA1.
impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Algorithm::from_name(&name).ok_or_else(|| {
            de::Error::custom(format!(
                "{name:?} is not a TOTP algorithm; expected \"sha1\", \"sha256\" or \"sha512\""
            ))
        })
    }
}

/// The version byte that says the payload behind it is the JSON form.
pub const VERSION_JSON: u8 = 0x00;

/// The version byte that says the payload behind it is the binary form.
pub const VERSION_BINARY: u8 = 0x01;

/// The form a message travels in.
///
/// The payload's first byte says which of these it is — and a payload that
/// does not start with a version byte is the JSON form, because that is what
/// every peer sent before the version byte existed. A JSON message always
/// starts with `{`, which is neither of the two version bytes, so the three
/// are told apart by one look.
///
/// The version byte is a **discriminator**, not a negotiation: a message says
/// what it is, and the other end reads it. Nothing is agreed on beforehand
/// and nothing has to be remembered between messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The JSON form with no version byte in front of it: what every peer
    /// sent before the version byte existed, and what a peer that predates it
    /// can read.
    LegacyJson,
    /// The JSON form behind the version byte [`VERSION_JSON`].
    ///
    /// A peer that speaks the versioned protocol but whose messages are still
    /// JSON. It keeps the JSON encoder alive inside the versioned protocol,
    /// which is what stops the two encoders drifting apart unnoticed.
    Json,
    /// The binary form behind the version byte [`VERSION_BINARY`].
    Binary,
}

impl Format {
    /// The version byte in front of a payload in this form — or `None` for
    /// the form that has none.
    pub fn version_byte(&self) -> Option<u8> {
        match self {
            Format::LegacyJson => None,
            Format::Json => Some(VERSION_JSON),
            Format::Binary => Some(VERSION_BINARY),
        }
    }

    /// The form a version number means, if this build knows it.
    pub fn from_version(version: u8) -> Option<Self> {
        match version {
            VERSION_JSON => Some(Format::Json),
            VERSION_BINARY => Some(Format::Binary),
            _ => None,
        }
    }
}

/// Why a message could not be put on the wire, or taken off it.
#[derive(Debug)]
pub enum CodecError {
    /// The JSON form: the payload is not JSON, or not a message.
    Json(serde_json::Error),
    /// The binary form: the payload is not a message this build knows.
    Binary(String),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Json(error) => write!(f, "{error}"),
            CodecError::Binary(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Messages exchanged during authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMessage {
    /// Client initiates authentication
    #[serde(rename = "AUTH_START")]
    Start {
        client_id: String,
        timestamp: i64,
        /// Which of this client's devices is authenticating. `None` is the
        /// device that was never given one, which is the only kind that
        /// existed before a client could have several.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        /// The version of the protocol this client speaks, when it speaks more
        /// than one.
        ///
        /// **Absent** is a client that does not: the server answers in the
        /// old form and the two never leave it. That is what an old client
        /// sends, and it is why the field is optional — a peer that predates
        /// it drops the field and is understood as one that has only the old
        /// form.
        ///
        /// A new client announces the best version it speaks here, because
        /// this message has to be readable by a server that predates the
        /// version byte: the announcement is inside the JSON, where an old
        /// server ignores it, rather than in front of it, where an old server
        /// would choke on it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<u8>,
    },
    /// Server sends challenge nonce
    #[serde(rename = "AUTH_CHALLENGE")]
    Challenge { nonce: Vec<u8> },
    /// Client responds with TOTP code
    #[serde(rename = "AUTH_RESPONSE")]
    Response {
        client_id: String,
        timestamp: i64,
        /// The current TOTP code. Empty when the device is known by a key:
        /// there is no code for it, and the signature is the whole proof.
        totp_code: String,
        /// Over `nonce || timestamp.to_le_bytes()`: HMAC-SHA256 keyed with the
        /// client's TOTP secret, or an Ed25519 signature by the device's key
        /// when the server holds one for it. Both prove the same thing — this
        /// client saw this connection's challenge at this time — so which one
        /// this is depends on the receiving end's credential, not on anything
        /// said here.
        signature: Vec<u8>,
        /// The same device [`AuthMessage::Start`] named. It is signed over
        /// nowhere, so it is not proof of anything on its own — what it does is
        /// say which device's credential the response is to be checked against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    /// Server confirms authentication success
    #[serde(rename = "AUTH_OK")]
    Ok,
    /// Server rejects authentication
    #[serde(rename = "AUTH_FAILED")]
    Failed { reason: String },
    /// Client offers a one-time enrollment token instead of a secret
    #[serde(rename = "ENROLL_START")]
    EnrollStart {
        client_id: String,
        /// The token out of a `v=2` invite; valid until it has been exchanged
        /// once.
        ///
        /// A [`SecretString`]: an unspent token is a credential, and this one is
        /// wiped when the message is dropped.
        token: SecretString,
        /// The name the device asking to enroll wants to be issued under. The
        /// server is free to answer with the same name or refuse; the token is
        /// what authorizes the exchange, not this field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        /// The device key this client is asking to be issued under, as the
        /// public half of an Ed25519 key pair in lowercase hex.
        ///
        /// Absent for a client that has no key to offer, which is every client
        /// built before keys existed; a server that predates this field ignores
        /// it and issues a secret as before, so a client offering one has to
        /// keep working with what it is given. Present, it must arrive with a
        /// device name — a key belongs to one device, and the device that names
        /// none answers with the client's shared secret, which has no key to
        /// check against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
    },
    /// Server issues the credential the token was standing in for
    #[serde(rename = "ENROLL_ISSUE")]
    EnrollIssue {
        client_id: String,
        /// Base32-encoded secret, generated fresh for this enrollment. Empty
        /// when the device was issued a key instead: the server recorded the
        /// public key the client offered, and this device will prove itself
        /// with a signature rather than a code.
        ///
        /// A [`SecretString`]: a credential that has just been issued is the
        /// most valuable thing this process holds.
        secret: SecretString,
        /// The algorithm the issued secret is to be used with.
        ///
        /// A closed set, and it was a string: the name was free-form on the
        /// wire, so a peer had to decide what to do with a name nobody
        /// supports. The names are the canonical ones, and they are read in
        /// any case.
        algorithm: Algorithm,
        digits: u32,
        period: u64,
        /// The device this credential was issued for, which is how the client
        /// learns the name it will have to send back. Absent when the server
        /// answered an enrollment that named no device — a client that predates
        /// per-device credentials reads that as "the shared one".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    /// Server refuses the token
    #[serde(rename = "ENROLL_FAILED")]
    EnrollFailed { reason: String },
}

/// Longest client id the handshake accepts.
///
/// Long enough for any name a config would carry, short enough that one cannot
/// be used to push a wall of text through the logs.
pub const MAX_CLIENT_ID_LEN: usize = 255;

/// Longest device id the handshake accepts, and the reason is the same one.
///
/// A device id is chosen by the peer that sends it — the server echoes back
/// what an enrollment asked for, and after that the device supplies it on every
/// handshake — so it reaches the audit log without having been checked against
/// anything.
pub const MAX_DEVICE_ID_LEN: usize = 255;

/// Whether an id may be printed as it stands.
///
/// The rule is one rule because both ids arrive the same way: from a peer,
/// before anything about that peer is known, and both end up in the log line
/// for every outcome.
fn is_presentable_id(id: &str, max_len: usize) -> bool {
    !id.is_empty() && id.len() <= max_len && id.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Whether a client id may be printed as it stands.
///
/// A client id arrives before anything about the peer is known, and the server
/// puts it in the log line for every outcome — a refusal, a lockout, an
/// unknown client. Printable ASCII only, which is what keeps a peer from
/// ending its id with a CRLF and writing the next line itself.
pub fn is_presentable_client_id(id: &str) -> bool {
    is_presentable_id(id, MAX_CLIENT_ID_LEN)
}

/// Whether a device id may be printed as it stands.
pub fn is_presentable_device_id(id: &str) -> bool {
    is_presentable_id(id, MAX_DEVICE_ID_LEN)
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

    /// The message as it travels, in the form asked for.
    ///
    /// The version byte is part of the payload: the frame around it is
    /// `[u32le length][payload]`, and the length covers the byte.
    pub fn to_payload(&self, format: Format) -> Result<Vec<u8>, CodecError> {
        match format {
            Format::LegacyJson => serde_json::to_vec(self).map_err(CodecError::Json),
            Format::Json => {
                let mut payload = Vec::new();
                payload.push(VERSION_JSON);
                payload.extend(serde_json::to_vec(self).map_err(CodecError::Json)?);
                Ok(payload)
            }
            Format::Binary => {
                let mut payload = Vec::new();
                payload.push(VERSION_BINARY);
                payload.extend(self.to_binary()?);
                Ok(payload)
            }
        }
    }

    /// The message a payload carries, and the form it was in.
    ///
    /// The form is read from the payload's first byte, and a payload that
    /// does not start with a version byte is the JSON form — which is what
    /// every peer sent before the version byte existed.
    pub fn from_payload(payload: &[u8]) -> Result<(Self, Format), CodecError> {
        match payload.first() {
            None => Err(CodecError::Binary("the payload is empty".to_string())),
            Some(&VERSION_JSON) => Ok((
                serde_json::from_slice(&payload[1..]).map_err(CodecError::Json)?,
                Format::Json,
            )),
            Some(&VERSION_BINARY) => Ok((Self::from_binary(&payload[1..])?, Format::Binary)),
            Some(_) => Ok((
                serde_json::from_slice(payload).map_err(CodecError::Json)?,
                Format::LegacyJson,
            )),
        }
    }

    /// The version this message announces, if it announces one.
    ///
    /// Only [`AuthMessage::Start`] announces: it is the first message of a
    /// handshake, and it has to be one an old peer can read.
    pub fn announced_version(&self) -> Option<u8> {
        match self {
            AuthMessage::Start { version, .. } => *version,
            _ => None,
        }
    }

    /// The message in the binary form, without the version byte.
    fn to_binary(&self) -> Result<Vec<u8>, CodecError> {
        let mut writer = Writer::default();
        match self {
            AuthMessage::Start {
                client_id,
                timestamp,
                device_id,
                version,
            } => {
                let mut flags = 0;
                if device_id.is_some() {
                    flags |= flag::DEVICE_ID;
                }
                if version.is_some() {
                    flags |= flag::VERSION;
                }
                writer.u8(kind::START);
                writer.u8(flags);
                writer.string(client_id)?;
                writer.i64(*timestamp);
                if let Some(device_id) = device_id {
                    writer.string(device_id)?;
                }
                if let Some(version) = version {
                    writer.u8(*version);
                }
            }
            AuthMessage::Challenge { nonce } => {
                writer.u8(kind::CHALLENGE);
                writer.u8(0);
                writer.bytes(nonce)?;
            }
            AuthMessage::Response {
                client_id,
                timestamp,
                totp_code,
                signature,
                device_id,
            } => {
                let mut flags = 0;
                if device_id.is_some() {
                    flags |= flag::DEVICE_ID;
                }
                writer.u8(kind::RESPONSE);
                writer.u8(flags);
                writer.string(client_id)?;
                writer.i64(*timestamp);
                writer.string(totp_code)?;
                writer.bytes(signature)?;
                if let Some(device_id) = device_id {
                    writer.string(device_id)?;
                }
            }
            AuthMessage::Ok => {
                writer.u8(kind::OK);
                writer.u8(0);
            }
            AuthMessage::Failed { reason } => {
                writer.u8(kind::FAILED);
                writer.u8(0);
                writer.string(reason)?;
            }
            AuthMessage::EnrollStart {
                client_id,
                token,
                device_id,
                public_key,
            } => {
                let mut flags = 0;
                if device_id.is_some() {
                    flags |= flag::DEVICE_ID;
                }
                if public_key.is_some() {
                    flags |= flag::PUBLIC_KEY;
                }
                writer.u8(kind::ENROLL_START);
                writer.u8(flags);
                writer.string(client_id)?;
                writer.string(token.expose_secret())?;
                if let Some(device_id) = device_id {
                    writer.string(device_id)?;
                }
                if let Some(public_key) = public_key {
                    writer.string(public_key)?;
                }
            }
            AuthMessage::EnrollIssue {
                client_id,
                secret,
                algorithm,
                digits,
                period,
                device_id,
            } => {
                let mut flags = 0;
                if device_id.is_some() {
                    flags |= flag::DEVICE_ID;
                }
                writer.u8(kind::ENROLL_ISSUE);
                writer.u8(flags);
                writer.string(client_id)?;
                writer.string(secret.expose_secret())?;
                writer.u8(algorithm.to_byte());
                writer.u32(*digits);
                writer.u64(*period);
                if let Some(device_id) = device_id {
                    writer.string(device_id)?;
                }
            }
            AuthMessage::EnrollFailed { reason } => {
                writer.u8(kind::ENROLL_FAILED);
                writer.u8(0);
                writer.string(reason)?;
            }
        }
        Ok(writer.into_bytes())
    }

    /// The message a binary payload carries.
    fn from_binary(payload: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(payload);
        let kind = reader.u8()?;
        let flags = reader.u8()?;
        if flags & !allowed_flags(kind) != 0 {
            return Err(CodecError::Binary(format!(
                "a message of type {kind:#04x} carries flags {flags:#04x} that it has no meaning for"
            )));
        }
        match kind {
            kind::START => {
                let client_id = reader.string()?;
                let timestamp = reader.i64()?;
                let device_id = if flags & flag::DEVICE_ID != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                let version = if flags & flag::VERSION != 0 {
                    Some(reader.u8()?)
                } else {
                    None
                };
                Ok(AuthMessage::Start {
                    client_id,
                    timestamp,
                    device_id,
                    version,
                })
            }
            kind::CHALLENGE => {
                let nonce = reader.bytes()?;
                Ok(AuthMessage::Challenge { nonce })
            }
            kind::RESPONSE => {
                let client_id = reader.string()?;
                let timestamp = reader.i64()?;
                let totp_code = reader.string()?;
                let signature = reader.bytes()?;
                let device_id = if flags & flag::DEVICE_ID != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                Ok(AuthMessage::Response {
                    client_id,
                    timestamp,
                    totp_code,
                    signature,
                    device_id,
                })
            }
            kind::OK => Ok(AuthMessage::Ok),
            kind::FAILED => {
                let reason = reader.string()?;
                Ok(AuthMessage::Failed { reason })
            }
            kind::ENROLL_START => {
                let client_id = reader.string()?;
                let token = SecretString::new(reader.string()?);
                let device_id = if flags & flag::DEVICE_ID != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                let public_key = if flags & flag::PUBLIC_KEY != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                Ok(AuthMessage::EnrollStart {
                    client_id,
                    token,
                    device_id,
                    public_key,
                })
            }
            kind::ENROLL_ISSUE => {
                let client_id = reader.string()?;
                let secret = SecretString::new(reader.string()?);
                let algorithm = Algorithm::from_byte(reader.u8()?).ok_or_else(|| {
                    CodecError::Binary("the algorithm is not one this build knows".to_string())
                })?;
                let digits = reader.u32()?;
                let period = reader.u64()?;
                let device_id = if flags & flag::DEVICE_ID != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                Ok(AuthMessage::EnrollIssue {
                    client_id,
                    secret,
                    algorithm,
                    digits,
                    period,
                    device_id,
                })
            }
            kind::ENROLL_FAILED => {
                let reason = reader.string()?;
                Ok(AuthMessage::EnrollFailed { reason })
            }
            other => Err(CodecError::Binary(format!(
                "unknown message type {other:#04x}"
            ))),
        }
    }
}

/// The message types of the binary form.
mod kind {
    pub const START: u8 = 0x01;
    pub const CHALLENGE: u8 = 0x02;
    pub const RESPONSE: u8 = 0x03;
    pub const OK: u8 = 0x04;
    pub const FAILED: u8 = 0x05;
    pub const ENROLL_START: u8 = 0x06;
    pub const ENROLL_ISSUE: u8 = 0x07;
    pub const ENROLL_FAILED: u8 = 0x08;
}

/// The flags of the binary form: one bit per optional field.
mod flag {
    /// The message carries a device id.
    pub const DEVICE_ID: u8 = 0b0000_0001;
    /// The message carries a public key.
    pub const PUBLIC_KEY: u8 = 0b0000_0010;
    /// The message announces the protocol version it speaks.
    pub const VERSION: u8 = 0b0000_0100;
}

/// The flags a message type may carry.
///
/// A flag a type has no meaning for is refused rather than ignored: a future
/// version that adds one would otherwise be read as if the field were
/// absent, which is the kind of quiet difference a version byte exists to
/// prevent.
fn allowed_flags(kind: u8) -> u8 {
    match kind {
        kind::START => flag::DEVICE_ID | flag::VERSION,
        kind::RESPONSE => flag::DEVICE_ID,
        kind::ENROLL_START => flag::DEVICE_ID | flag::PUBLIC_KEY,
        kind::ENROLL_ISSUE => flag::DEVICE_ID,
        _ => 0,
    }
}

/// Writes the binary form, a field at a time.
#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// A string: a `u16le` length and the UTF-8 bytes.
    ///
    /// Every string in the protocol is short — a client id is 255 bytes at
    /// most, a reason is a sentence — so two bytes of length are enough, and
    /// a string that would not fit is a message this build cannot write
    /// rather than one it writes wrong.
    fn string(&mut self, value: &str) -> Result<(), CodecError> {
        let bytes = value.as_bytes();
        let len = u16::try_from(bytes.len()).map_err(|_| {
            CodecError::Binary(format!(
                "a string of {} bytes does not fit the wire format",
                bytes.len()
            ))
        })?;
        self.u16(len);
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// A byte string: a `u32le` length and the bytes.
    fn bytes(&mut self, value: &[u8]) -> Result<(), CodecError> {
        let len = u32::try_from(value.len()).map_err(|_| {
            CodecError::Binary(format!(
                "{} bytes of payload do not fit the wire format",
                value.len()
            ))
        })?;
        self.u32(len);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Reads the binary form, a field at a time.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    /// The next `len` bytes — or an error if there are not that many left.
    ///
    /// The length in the payload is the peer's to write, so it is checked
    /// against what is actually there before anything is allocated for it.
    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self.at.checked_add(len).ok_or_else(|| {
            CodecError::Binary("the payload claims more bytes than it has".to_string())
        })?;
        if end > self.bytes.len() {
            return Err(CodecError::Binary(format!(
                "the payload ends after {} of the {len} bytes it claims",
                self.bytes.len() - self.at
            )));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn i64(&mut self) -> Result<i64, CodecError> {
        Ok(self.u64()? as i64)
    }

    fn string(&mut self) -> Result<String, CodecError> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| CodecError::Binary("a string is not UTF-8".to_string()))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}

/// The message a proof covers: the connection's nonce, then the client's
/// timestamp as little-endian bytes.
///
/// One definition, because the two proof paths have to cover the same bytes:
/// a secret-based credential HMACs this message, a key-based one signs it
/// with Ed25519, and the server checks the key path against these same bytes.
/// Whichever credential answers, what a response proves is the same thing:
/// this client saw this connection's nonce at this time.
///
/// It used to be written down three times — the server's HMAC path, the
/// server's key path and the client's — with a comment in each copy saying to
/// keep the others in step. Two of them drifting apart is a handshake that
/// succeeds with one credential and fails with the other, and nothing in the
/// failure says which.
pub fn challenge_message(nonce: &[u8], timestamp: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(nonce.len() + 8);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&timestamp.to_le_bytes());
    message
}

/// Why a challenge could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeError {
    /// What the underlying HMAC said.
    ///
    /// Carried as text rather than flattened away, because the two callers
    /// word it differently — the server reports a refused secret, the client
    /// reports one it could not use — and each of them has been saying so for
    /// as long as it has had a copy of this.
    pub message: String,
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChallengeError {}

/// HMAC-SHA256 over [`challenge_message`]: the proof a secret-based credential
/// gives.
///
/// The key path's Ed25519 half stays on either side — the key types are not
/// the same crate's — but it signs [`challenge_message`], so the two proofs
/// cover one byte string.
pub fn hmac_challenge(
    secret: &[u8],
    nonce: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, ChallengeError> {
    // Fallible in the type only: HMAC takes a key of any length — a long one
    // is hashed, a short one is zero-padded — so this has never failed. It is
    // returned rather than `expect`ed because it runs inside a handshake,
    // where a panic would drop the connection with nothing to report.
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|e| ChallengeError {
        message: e.to_string(),
    })?;
    mac.update(&challenge_message(nonce, timestamp));
    Ok(mac.finalize().into_bytes().to_vec())
}

/// The application error codes the server closes a connection with.
///
/// They travel in the QUIC CONNECTION_CLOSE frame, so the client can tell
/// "you never authenticated" apart from "your code was rejected" — the
/// difference between a misconfigured client and a wrong TOTP code.
///
/// One definition, for the reason the rest of this module is one definition:
/// a code changed on one side and not the other is a client that reports a
/// mysterious connection loss instead of the reason it was given one.
pub mod close_code {
    /// No AUTH_START arrived within the handshake deadline: the server requires
    /// 2FA the client did not perform.
    pub const REQUIRED: u32 = 2;
    /// The handshake ran, but the client is unknown or its code was rejected.
    pub const REJECTED: u32 = 3;
    /// The peer already holds as many connections as it is allowed, so this one
    /// is closed without any traffic being served on it.
    pub const TOO_MANY: u32 = 4;
    /// The server runs a `[peers]` allow-list and this Node ID is not on it.
    /// Sent right after the QUIC handshake, so the client never gets as far as
    /// sending credentials.
    pub const PEER_NOT_ALLOWED: u32 = 5;
    /// The credential this connection authenticated with is gone: `nexapipe
    /// client revoke` struck the client, or the device, out of `[auth]` while
    /// this connection was open. Unlike the four above this does not arrive
    /// during the handshake: a connection has to have authenticated to be
    /// revoked. Five belongs to the allow list above, which is why the numbers
    /// are not adjacent.
    pub const REVOKED: u32 = 6;
}

/// HMAC-SHA256, the hash the challenge is signed with.
type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire format, byte for byte.
    ///
    /// The handshake used to be written down twice, and these strings are what
    /// the other copy produced — dumped from the code as it was before the
    /// move, not from the code as it is now. A message that came out
    /// differently would be a handshake that dies on its first message, and
    /// the only thing that would notice is a peer built against the old
    /// format.
    ///
    /// So this is the whole contract, in one list.
    #[test]
    fn every_message_keeps_its_wire_format() {
        let messages = vec![
            (
                AuthMessage::Start {
                    client_id: "c".to_string(),
                    timestamp: 7,
                    device_id: None,
                    version: None,
                },
                r#"{"type":"AUTH_START","client_id":"c","timestamp":7}"#,
            ),
            (
                AuthMessage::Start {
                    client_id: "c".to_string(),
                    timestamp: 7,
                    device_id: Some("laptop".to_string()),
                    version: None,
                },
                r#"{"type":"AUTH_START","client_id":"c","timestamp":7,"device_id":"laptop"}"#,
            ),
            (
                AuthMessage::Challenge {
                    nonce: vec![1, 2, 3],
                },
                r#"{"type":"AUTH_CHALLENGE","nonce":[1,2,3]}"#,
            ),
            (
                AuthMessage::Response {
                    client_id: "c".to_string(),
                    timestamp: 7,
                    totp_code: "123456".to_string(),
                    signature: vec![9],
                    device_id: None,
                },
                r#"{"type":"AUTH_RESPONSE","client_id":"c","timestamp":7,"totp_code":"123456","signature":[9]}"#,
            ),
            (
                AuthMessage::Response {
                    client_id: "c".to_string(),
                    timestamp: 7,
                    totp_code: "123456".to_string(),
                    signature: vec![9],
                    device_id: Some("laptop".to_string()),
                },
                r#"{"type":"AUTH_RESPONSE","client_id":"c","timestamp":7,"totp_code":"123456","signature":[9],"device_id":"laptop"}"#,
            ),
            (AuthMessage::Ok, r#"{"type":"AUTH_OK"}"#),
            (
                AuthMessage::Failed {
                    reason: "no".to_string(),
                },
                r#"{"type":"AUTH_FAILED","reason":"no"}"#,
            ),
            (
                AuthMessage::EnrollStart {
                    client_id: "c".to_string(),
                    token: SecretString::new("tok".to_string()),
                    device_id: None,
                    public_key: None,
                },
                r#"{"type":"ENROLL_START","client_id":"c","token":"tok"}"#,
            ),
            (
                AuthMessage::EnrollStart {
                    client_id: "c".to_string(),
                    token: SecretString::new("tok".to_string()),
                    device_id: Some("laptop".to_string()),
                    public_key: Some("abcd".to_string()),
                },
                r#"{"type":"ENROLL_START","client_id":"c","token":"tok","device_id":"laptop","public_key":"abcd"}"#,
            ),
            (
                AuthMessage::EnrollIssue {
                    client_id: "c".to_string(),
                    secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                    algorithm: Algorithm::Sha1,
                    digits: 6,
                    period: 30,
                    device_id: None,
                },
                r#"{"type":"ENROLL_ISSUE","client_id":"c","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha1","digits":6,"period":30}"#,
            ),
            (
                AuthMessage::EnrollIssue {
                    client_id: "c".to_string(),
                    secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                    algorithm: Algorithm::Sha1,
                    digits: 6,
                    period: 30,
                    device_id: Some("laptop".to_string()),
                },
                r#"{"type":"ENROLL_ISSUE","client_id":"c","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha1","digits":6,"period":30,"device_id":"laptop"}"#,
            ),
            (
                AuthMessage::EnrollFailed {
                    reason: "no".to_string(),
                },
                r#"{"type":"ENROLL_FAILED","reason":"no"}"#,
            ),
        ];

        for (message, wire) in messages {
            let json = String::from_utf8(message.to_bytes().expect("serializable")).expect("utf-8");
            assert_eq!(json, wire, "the wire format of {message:?} changed");
        }
    }

    /// The tag is what the other side switches on, so the names are part of the
    /// contract with `crates/nexapipe-client/src/auth.rs`, which spells them
    /// out again. A rename here that misses there is a handshake that dies on
    /// the first message.
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
        assert_eq!(
            AuthMessage::from_bytes(json.as_bytes())
                .unwrap()
                .to_bytes()
                .unwrap(),
            start.to_bytes().unwrap()
        );

        let issue = AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Algorithm::Sha1,
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

    /// The credential travels as the plain string it always was.
    ///
    /// The token and the secret are `Secret`s now, and a `Secret` that
    /// serialized differently would break every peer built before it: the
    /// field names and the spelling of the value are the contract, and the
    /// wrapper changes neither.
    #[test]
    fn a_credential_travels_as_the_plain_string_it_always_was() {
        let start = AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("tok".to_string()),
            device_id: None,
            public_key: None,
        };
        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""token":"tok""#), "{json}");

        let issue = AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            device_id: None,
        };
        let json = String::from_utf8(issue.to_bytes().unwrap()).unwrap();
        assert!(json.contains(r#""secret":"JBSWY3DPEHPK3PXP""#), "{json}");
    }

    /// A peer on either side of this change has to be able to talk to one on
    /// the other side, and the whole interop story is one sentence: the field
    /// is absent when it is not being used. A peer that never heard of devices
    /// sends no such key, and this one reads that as the unnamed device.
    #[test]
    fn a_message_from_a_peer_that_never_heard_of_devices_still_parses() {
        let wire = r#"{"type":"AUTH_START","client_id":"client-001","timestamp":1}"#;

        let parsed = AuthMessage::from_bytes(wire.as_bytes()).expect("an old client still parses");
        let AuthMessage::Start {
            client_id,
            timestamp,
            device_id,
            version,
        } = parsed
        else {
            panic!("expected AUTH_START, got {parsed:?}");
        };

        assert_eq!(client_id, "client-001");
        assert_eq!(timestamp, 1);
        assert_eq!(device_id, None, "no name sent is the unnamed device");

        // And it goes back out the way it came in, so the two peers agree on
        // what a handshake between them looks like.
        assert_eq!(
            String::from_utf8(
                AuthMessage::Start {
                    client_id,
                    timestamp,
                    device_id,
                    version,
                }
                .to_bytes()
                .unwrap()
            )
            .unwrap(),
            wire,
        );
    }

    /// The other half of that sentence: an unset device id is left off the
    /// wire entirely rather than sent as `null`, so a peer that does know the
    /// field cannot tell this one apart from an older one — which is what
    /// keeps nobody having to negotiate a version.
    #[test]
    fn an_unnamed_device_sends_no_device_id_at_all() {
        let json = String::from_utf8(
            AuthMessage::Response {
                client_id: "client-001".to_string(),
                timestamp: 1,
                totp_code: "123456".to_string(),
                signature: vec![7],
                device_id: None,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap();

        assert!(!json.contains("device_id"), "{json}");
    }

    /// Every message that can carry one, so a variant added later and given the
    /// field by copy-paste cannot end up with it spelled differently.
    #[test]
    fn a_named_device_survives_the_round_trip() {
        let messages = [
            AuthMessage::Start {
                client_id: "client-001".to_string(),
                timestamp: 1,
                device_id: Some("laptop".to_string()),
                version: None,
            },
            AuthMessage::Response {
                client_id: "client-001".to_string(),
                timestamp: 1,
                totp_code: "123456".to_string(),
                signature: vec![7],
                device_id: Some("laptop".to_string()),
            },
            AuthMessage::EnrollStart {
                client_id: "client-001".to_string(),
                token: SecretString::new("tok".to_string()),
                device_id: Some("laptop".to_string()),
                public_key: None,
            },
            AuthMessage::EnrollIssue {
                client_id: "client-001".to_string(),
                secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                device_id: Some("laptop".to_string()),
            },
        ];

        for message in &messages {
            let bytes = message.to_bytes().expect("serializable");
            let json = String::from_utf8(bytes.clone()).unwrap();
            assert!(json.contains(r#""device_id":"laptop""#), "{json}");

            let back = AuthMessage::from_bytes(&bytes).expect("parses");
            assert_eq!(
                back.to_bytes().unwrap(),
                bytes,
                "a device id must not change shape on the way through"
            );
        }
    }

    /// A device id ends up in the log line for whatever happens to it, so it is
    /// held to what a client id is held to rather than to a rule of its own.
    #[test]
    fn a_device_id_is_refused_the_way_a_client_id_is() {
        assert!(is_presentable_device_id("laptop"));
        assert!(!is_presentable_device_id(""), "empty names nobody");
        assert!(
            !is_presentable_device_id("laptop\r\nINFO: connected"),
            "a trailing CRLF would write the next log line"
        );
        assert!(!is_presentable_device_id(
            &"d".repeat(MAX_DEVICE_ID_LEN + 1)
        ));

        // The two rules really are one rule: whatever is refused for one id is
        // refused for the other.
        for id in ["", "laptop\r\nINFO: connected", &"x".repeat(256)] {
            assert_eq!(is_presentable_device_id(id), is_presentable_client_id(id));
        }
    }

    /// A key offered at enrollment is what the server records and what the
    /// device will sign with, so it has to reach the other side exactly as it
    /// was said: a field that changes shape on the way through is a device
    /// that can never authenticate.
    #[test]
    fn an_enrollment_that_offers_a_key_carries_it_whole() {
        let key = "a1".repeat(32);
        let start = AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("tok".to_string()),
            device_id: Some("phone".to_string()),
            public_key: Some(key.clone()),
        };

        let json = String::from_utf8(start.to_bytes().unwrap()).unwrap();
        assert!(json.contains(&format!(r#""public_key":"{key}""#)), "{json}");

        let back = AuthMessage::from_bytes(json.as_bytes()).expect("parses");
        assert_eq!(back.to_bytes().unwrap(), start.to_bytes().unwrap());
    }

    /// The other half of the absence-means-old-client rule, for enrollment: a
    /// client that has no key — every client built before this field existed —
    /// sends no such key, and what it sends goes back out byte for byte.
    #[test]
    fn an_enrollment_from_a_client_with_no_key_still_parses() {
        let wire = r#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop"}"#;

        let parsed = AuthMessage::from_bytes(wire.as_bytes()).expect("an old client still parses");
        let AuthMessage::EnrollStart { public_key, .. } = parsed else {
            panic!("expected ENROLL_START");
        };
        assert_eq!(public_key, None, "no key sent is a secret-based device");

        assert_eq!(
            String::from_utf8(
                AuthMessage::EnrollStart {
                    client_id: "client-001".to_string(),
                    token: SecretString::new("tok".to_string()),
                    device_id: Some("laptop".to_string()),
                    public_key: None,
                }
                .to_bytes()
                .unwrap()
            )
            .unwrap(),
            wire,
        );
    }

    // ===== The binary form =====

    /// Every message, in every shape it has.
    fn every_message() -> Vec<AuthMessage> {
        vec![
            AuthMessage::Start {
                client_id: "client-001".to_string(),
                timestamp: 7,
                device_id: None,
                version: None,
            },
            AuthMessage::Start {
                client_id: "client-001".to_string(),
                timestamp: 7,
                device_id: Some("laptop".to_string()),
                version: None,
            },
            AuthMessage::Start {
                client_id: "client-001".to_string(),
                timestamp: 7,
                device_id: Some("laptop".to_string()),
                version: Some(VERSION_BINARY),
            },
            AuthMessage::Challenge {
                nonce: (0..32u8).collect(),
            },
            AuthMessage::Response {
                client_id: "client-001".to_string(),
                timestamp: 1_750_000_000,
                totp_code: "123456".to_string(),
                signature: vec![9u8; 32],
                device_id: None,
            },
            AuthMessage::Response {
                client_id: "client-001".to_string(),
                timestamp: 1_750_000_000,
                totp_code: String::new(),
                signature: vec![7u8; 64],
                device_id: Some("laptop".to_string()),
            },
            AuthMessage::Ok,
            AuthMessage::Failed {
                reason: "the credentials were refused".to_string(),
            },
            AuthMessage::EnrollStart {
                client_id: "client-001".to_string(),
                token: SecretString::new("0123456789abcdef".to_string()),
                device_id: None,
                public_key: None,
            },
            AuthMessage::EnrollStart {
                client_id: "client-001".to_string(),
                token: SecretString::new("0123456789abcdef".to_string()),
                device_id: Some("laptop".to_string()),
                public_key: Some("ab".repeat(32)),
            },
            AuthMessage::EnrollIssue {
                client_id: "client-001".to_string(),
                secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                device_id: None,
            },
            AuthMessage::EnrollIssue {
                client_id: "client-001".to_string(),
                secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                algorithm: Algorithm::Sha512,
                digits: 8,
                period: 60,
                device_id: Some("laptop".to_string()),
            },
            AuthMessage::EnrollFailed {
                reason: "the enrollment token was not accepted".to_string(),
            },
        ]
    }

    /// The binary form is the same message.
    ///
    /// Every message goes out in the binary form and comes back as the same
    /// message — and as the same JSON, which is what says the two encoders
    /// are two views of one thing rather than two things that happen to look
    /// alike.
    #[test]
    fn every_message_survives_the_binary_form() {
        for message in every_message() {
            let payload = message
                .to_payload(Format::Binary)
                .expect("the binary form is writable");
            assert_eq!(payload[0], VERSION_BINARY, "the version byte comes first");

            let (back, format) =
                AuthMessage::from_payload(&payload).expect("the binary form is readable");
            assert_eq!(format, Format::Binary);
            assert_eq!(
                back.to_bytes().expect("serializable"),
                message.to_bytes().expect("serializable"),
                "{message:?} came back as something else"
            );
        }
    }

    /// The same for the versioned JSON form.
    #[test]
    fn every_message_survives_the_versioned_json_form() {
        for message in every_message() {
            let payload = message
                .to_payload(Format::Json)
                .expect("the versioned JSON form is writable");
            assert_eq!(payload[0], VERSION_JSON);

            let (back, format) =
                AuthMessage::from_payload(&payload).expect("the versioned JSON form is readable");
            assert_eq!(format, Format::Json);
            assert_eq!(
                back.to_bytes().expect("serializable"),
                message.to_bytes().expect("serializable"),
                "{message:?} came back as something else"
            );
        }
    }

    /// A payload that does not start with a version byte is the JSON form.
    ///
    /// That is what every peer sent before the version byte existed, and it
    /// has to keep working: a JSON message starts with `{`, which is neither
    /// of the two version bytes, so the three are told apart by one look.
    #[test]
    fn a_payload_without_a_version_byte_is_the_json_form() {
        for message in every_message() {
            let payload = message.to_bytes().expect("serializable");
            assert_eq!(payload[0], b'{', "a JSON message starts with a brace");

            let (back, format) =
                AuthMessage::from_payload(&payload).expect("an old peer still parses");
            assert_eq!(format, Format::LegacyJson);
            assert_eq!(
                back.to_bytes().expect("serializable"),
                payload,
                "{message:?} came back as something else"
            );
        }
    }

    /// The binary form is smaller than the JSON, and that is the reason it
    /// exists.
    ///
    /// The two big messages are the ones that carry a nonce and a signature,
    /// and the JSON writes those as arrays of decimal numbers — three bytes
    /// per byte. The numbers here are the ones a real handshake produces.
    #[test]
    fn the_binary_form_is_smaller_than_the_json_one() {
        let handshake = [
            AuthMessage::Start {
                client_id: "client-001".to_string(),
                timestamp: 1_750_000_000,
                device_id: None,
                version: None,
            },
            AuthMessage::Challenge {
                nonce: (0..32u8).collect(),
            },
            AuthMessage::Response {
                client_id: "client-001".to_string(),
                timestamp: 1_750_000_000,
                totp_code: "123456".to_string(),
                signature: (0..32u8).collect(),
                device_id: None,
            },
            AuthMessage::Ok,
        ];

        let json: usize = handshake
            .iter()
            .map(|message| message.to_bytes().expect("serializable").len())
            .sum();
        let binary: usize = handshake
            .iter()
            .map(|message| {
                message
                    .to_payload(Format::Binary)
                    .expect("the binary form is writable")
                    .len()
            })
            .sum();

        assert!(
            binary * 2 < json,
            "the binary form is {binary} bytes against the JSON's {json}"
        );
    }

    /// A payload that is not a message is refused, and it is refused without
    /// a panic and without allocating for a length the peer made up.
    #[test]
    fn a_broken_binary_payload_is_refused() {
        let good = AuthMessage::Challenge {
            nonce: vec![1, 2, 3],
        }
        .to_payload(Format::Binary)
        .expect("writable");

        // Truncated at every length: a payload that ends early is not a
        // message, and none of the cuts may take the process down.
        for cut in 1..good.len() {
            let error = AuthMessage::from_payload(&good[..cut])
                .expect_err("a truncated payload is not a message");
            assert!(
                !error.to_string().is_empty(),
                "the refusal says something: {error}"
            );
        }

        // A type byte nobody knows.
        let mut unknown_type = good.clone();
        unknown_type[1] = 0x7f;
        let error =
            AuthMessage::from_payload(&unknown_type).expect_err("an unknown type is refused");
        assert!(
            error.to_string().contains("unknown message type"),
            "{error}"
        );

        // A flag the message type has no meaning for: refusing it is what
        // stops a future version being read as if the field were absent.
        let mut unknown_flag = good.clone();
        unknown_flag[2] = 0b1000_0000;
        let error =
            AuthMessage::from_payload(&unknown_flag).expect_err("an unknown flag is refused");
        assert!(error.to_string().contains("flags"), "{error}");

        // A length that overruns the payload: the length is the peer's to
        // write, so it is checked before anything is allocated for it.
        let mut overrun = good.clone();
        overrun[3] = 0xff;
        overrun[4] = 0xff;
        let error =
            AuthMessage::from_payload(&overrun).expect_err("an overrunning length is refused");
        assert!(!error.to_string().is_empty(), "{error}");
    }

    /// The algorithm is a closed set, in both forms.
    #[test]
    fn the_algorithm_is_a_closed_set() {
        // A byte that is not one of the three.
        let mut payload = AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            device_id: None,
        }
        .to_payload(Format::Binary)
        .expect("writable");
        // The algorithm is the byte after the type, the flags, the client id
        // and the secret — each of the two strings behind its own length.
        let at = 1 + 1 + 1 + 2 + "client-001".len() + 2 + "JBSWY3DPEHPK3PXP".len();
        payload[at] = 0x09;
        let error =
            AuthMessage::from_payload(&payload).expect_err("an unknown algorithm is refused");
        assert!(error.to_string().contains("algorithm"), "{error}");

        // A name nobody supports, in the JSON form.
        let wire = r#"{"type":"ENROLL_ISSUE","client_id":"client-001","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha-256","digits":6,"period":30}"#;
        let error = AuthMessage::from_payload(wire.as_bytes())
            .expect_err("a name nobody supports is refused");
        assert!(
            error.to_string().contains("sha-256"),
            "the refusal names the value: {error}"
        );
    }

    /// The names are read in any case and written in one.
    ///
    /// The wire has always carried the canonical lowercase name, and the
    /// configuration it comes from is read in any case — so a peer that says
    /// `SHA1` is understood, and the answer is always `sha1`.
    #[test]
    fn an_algorithm_name_is_read_in_any_case() {
        for (said, meant) in [
            ("sha1", Algorithm::Sha1),
            ("SHA1", Algorithm::Sha1),
            ("Sha1", Algorithm::Sha1),
            ("sha256", Algorithm::Sha256),
            ("SHA256", Algorithm::Sha256),
            ("sha512", Algorithm::Sha512),
            ("SHA512", Algorithm::Sha512),
        ] {
            let wire = format!(
                r#"{{"type":"ENROLL_ISSUE","client_id":"client-001","secret":"JBSWY3DPEHPK3PXP","algorithm":"{said}","digits":6,"period":30}}"#
            );
            let (parsed, _) = AuthMessage::from_payload(wire.as_bytes())
                .unwrap_or_else(|e| panic!("{said} parses: {e}"));
            let AuthMessage::EnrollIssue { algorithm, .. } = parsed else {
                panic!("expected ENROLL_ISSUE");
            };
            assert_eq!(algorithm, meant, "{said}");
            assert_eq!(algorithm.name(), said.to_ascii_lowercase());
        }
    }

    /// The announcement is the only thing a message says about the version,
    /// and only the first message says it.
    #[test]
    fn only_the_first_message_announces_a_version() {
        let start = AuthMessage::Start {
            client_id: "client-001".to_string(),
            timestamp: 1,
            device_id: None,
            version: Some(VERSION_BINARY),
        };
        assert_eq!(start.announced_version(), Some(VERSION_BINARY));
        assert_eq!(
            AuthMessage::Ok.announced_version(),
            None,
            "nothing else announces anything"
        );
    }
}
