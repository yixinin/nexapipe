//! The wire formats the nexapipe client and the server share.
//!
//! Two of them live here: the L4 tunnel's, and the authentication handshake's.
//! The second one used to be written down twice — once in the server and once
//! in the client — which is the kind of duplication that costs a handshake
//! when one side grows a field and the other does not. See [`auth`].
//!
//! # Where this fits
//!
//! One inner connection is one QUIC bi-stream. The first byte of a bi-stream picks the
//! handler on the server:
//!
//! ```text
//! 0x16  TLS ClientHello   -> SNI passthrough (server sniffs; a TLS client cannot know our protocol)
//! other  HTTP request     -> HTTP routes
//! 0x05  L4 preface        -> TCP/UDP tunnel (this crate)
//! ```
//!
//! That is what a connection negotiated with the **old** ALPN gets. A
//! connection that names its protocol with ALPN says so at the handshake, and
//! the server knows what it is serving before it reads a byte of it: see
//! [`protocol`]. The old way still works, because a client that predates the
//! ALPNs cannot be made to speak one.
//!
//! Unlike the TLS path, the L4 path is **not** sniffed: the client is our own code, so it
//! states what it wants in a fixed preface instead of the server guessing from payload
//! bytes. That is what makes UDP possible at all — a datagram has no `Host` header.
//!
//! # Preface
//!
//! ```text
//! offset  size  field
//! 0       1     magic   0x05
//! 1       1     version 0x01
//! 2       1     proto   0x01 = TCP, 0x02 = UDP
//! 3       1     host length N (1..=255)
//! 4       N     host, ASCII (punycode for IDN), lower-case after decoding
//! 4+N     2     port, big-endian
//! ```
//!
//! The preface is the *only* thing the server parses. `host` names the route, and the
//! route — not the client — decides which backend address is dialled: a client that
//! holds 2FA credentials must not be able to reach arbitrary addresses through the
//! server.
//!
//! After the preface the stream is:
//!
//! * `TCP` — raw bytes in both directions, exactly like the TLS passthrough path.
//! * `UDP` — [`udp::encode_frame`] / [`udp::decode_frame`] framing, one datagram per
//!   frame, because a byte stream has no message boundaries of its own.
//!
//! # Host patterns
//!
//! The preface carries a host name, and both sides have to agree on what a
//! name means: the client decides whether a name is one it proxies, the
//! server decides whether a name is one a route serves. That agreement is one
//! rule, and it lives here — see [`host_matches`] for the rule itself and for
//! why it used to be three.
//!
//! # First byte back
//!
//! The server answers with exactly one byte, [`Status`], before any payload. A client
//! that has not seen `Ok` must treat the tunnel as failed; a client that got `Ok` owns
//! the stream.
//!
//! # Why the client must announce itself
//!
//! The server used to receive a `CONNECT host:port HTTP/1.1` line from some clients,
//! which nothing on the server side understood: it fell through to the HTTP parser,
//! produced an empty path, matched no route and was forwarded to `default_backend`.
//! A preface that fails to decode is now a loud error instead of a silent default.

pub mod alpn;
pub mod auth;
pub mod deadline;
mod host;
mod preface;
pub mod protocol;
pub mod secret;
mod udp;

pub use alpn::{ALPN_NEXAPIPE, ALPN_NEXAPIPE_ALL, ALPN_NEXAPIPE_LEGACY};
pub use auth::{
    Algorithm, AuthMessage, CodecError, Format, MAX_CLIENT_ID_LEN, MAX_DEVICE_ID_LEN,
    VERSION_BINARY, VERSION_JSON, is_presentable_client_id, is_presentable_device_id,
};
pub use deadline::{HEADER_SECS, STREAM_SECS, TLS_HELLO_SECS};
pub use host::{
    host_and_port, host_matches, host_matches_any, normalize_host, normalize_pattern, pattern_error,
};
pub use preface::{
    L4Proto, MAX_HOST_LEN, MAX_PREFACE_LEN, PREFACE_MAGIC, PREFACE_VERSION, Preface, Status,
    is_l4_preface,
};
pub use secret::{Secret, SecretBytes, SecretString};
pub use udp::{
    FRAME_HEADER_LEN, Frame, MAX_UDP_PAYLOAD, decode_frame, encode_frame, encode_frame_to_vec,
    payload_fits_datagram,
};

use std::fmt;

/// Everything that can go wrong while reading or writing the wire format.
///
/// A decode error is always the peer's fault and always ends the stream: there is no
/// recovery path, and guessing at a half-understood preface is what produced the silent
/// `default_backend` fallback this crate exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// First byte is not [`PREFACE_MAGIC`].
    NotAPreface,
    /// Preface version this build does not implement.
    UnsupportedVersion(u8),
    /// Protocol byte that is neither TCP nor UDP.
    UnknownProto(u8),
    /// Host is empty, too long, or contains bytes that cannot be in a host name.
    InvalidHost,
    /// Port zero: not a meaningful destination.
    InvalidPort,
    /// UDP payload larger than [`MAX_UDP_PAYLOAD`].
    PayloadTooLarge,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::NotAPreface => {
                write!(f, "stream does not start with the L4 preface magic byte")
            }
            ProtoError::UnsupportedVersion(v) => write!(f, "unsupported preface version {v}"),
            ProtoError::UnknownProto(p) => write!(f, "unknown L4 protocol byte {p:#04x}"),
            ProtoError::InvalidHost => write!(f, "invalid host in the L4 preface"),
            ProtoError::InvalidPort => write!(f, "port 0 in the L4 preface"),
            ProtoError::PayloadTooLarge => {
                write!(f, "UDP payload larger than {MAX_UDP_PAYLOAD} bytes")
            }
        }
    }
}

impl std::error::Error for ProtoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_0x05_is_a_preface() {
        assert!(is_l4_preface(PREFACE_MAGIC));
        // The neighbouring dispatchers must not overlap: TLS is 0x16 and no HTTP
        // method starts with 0x05.
        assert!(!is_l4_preface(0x16));
        assert!(!is_l4_preface(b'G'));
        assert!(!is_l4_preface(0x00));
    }

    #[test]
    fn error_messages_name_the_cause() {
        assert!(ProtoError::NotAPreface.to_string().contains("magic"));
        assert!(ProtoError::UnsupportedVersion(2).to_string().contains('2'));
        assert!(ProtoError::UnknownProto(0x07).to_string().contains("0x07"));
    }
}
