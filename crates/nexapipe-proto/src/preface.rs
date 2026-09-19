//! The L4 preface and the status byte the server answers with.

use crate::ProtoError;

/// First byte of every L4 tunnel stream.
///
/// Chosen because nothing else can produce it: an HTTP method never starts with
/// `0x05`, and a TLS record starts with `0x16`. The three dispatchers therefore
/// overlap nowhere.
pub const PREFACE_MAGIC: u8 = 0x05;

/// Preface layout version.
///
/// The server refuses a version it does not implement rather than guessing: a
/// silently misread preface is exactly the failure mode this protocol removes.
pub const PREFACE_VERSION: u8 = 0x01;

/// Longest host name a preface can carry — one length byte.
pub const MAX_HOST_LEN: usize = 255;

/// Largest possible preface. The server bounds its read loop with this, so a hostile
/// peer cannot make it buffer without limit before the preface is complete.
pub const MAX_PREFACE_LEN: usize = 4 + MAX_HOST_LEN + 2;

/// True when `first_byte` announces an L4 tunnel.
pub fn is_l4_preface(first_byte: u8) -> bool {
    first_byte == PREFACE_MAGIC
}

/// Which L4 protocol the stream carries.
///
/// This is only about framing: TCP forwards raw bytes, UDP forwards length-prefixed
/// datagrams. Which backend is dialled is the route's business, not the client's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
}

impl L4Proto {
    pub const fn as_byte(self) -> u8 {
        match self {
            L4Proto::Tcp => 0x01,
            L4Proto::Udp => 0x02,
        }
    }

    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(L4Proto::Tcp),
            0x02 => Some(L4Proto::Udp),
            _ => None,
        }
    }

    /// Short upper-case name, for logs and access log entries.
    pub const fn name(self) -> &'static str {
        match self {
            L4Proto::Tcp => "TCP",
            L4Proto::Udp => "UDP",
        }
    }
}

/// The single byte the server sends before any payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Backend connected (TCP) or socket ready (UDP); the rest of the stream is payload.
    Ok,
    /// No `tcp`/`udp` route serves this host and port. Deliberately distinct from
    /// [`Status::BackendFailed`]: a missing route is a configuration error, not an outage.
    NoRoute,
    /// The route matched but its backend could not be reached.
    BackendFailed,
    /// This connection already carries the maximum number of L4 flows.
    TooManyFlows,
    /// The preface did not decode. The server closes immediately after this.
    BadPreface,
    /// A byte this build does not define. Only ever produced by [`Status::from_byte`].
    Unknown,
}

impl Status {
    pub const fn as_byte(self) -> u8 {
        match self {
            Status::Ok => 0x00,
            Status::NoRoute => 0x01,
            Status::BackendFailed => 0x02,
            Status::TooManyFlows => 0x03,
            Status::BadPreface => 0x04,
            Status::Unknown => 0xff,
        }
    }

    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Status::Ok,
            0x01 => Status::NoRoute,
            0x02 => Status::BackendFailed,
            0x03 => Status::TooManyFlows,
            0x04 => Status::BadPreface,
            _ => Status::Unknown,
        }
    }

    pub const fn is_ok(self) -> bool {
        matches!(self, Status::Ok)
    }

    /// Sentence for a log line or an error message.
    pub const fn describe(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::NoRoute => "no tcp/udp route for this host and port",
            Status::BackendFailed => "could not reach the route's backend",
            Status::TooManyFlows => "too many flows on this connection",
            Status::BadPreface => "malformed L4 preface",
            Status::Unknown => "unrecognised status byte",
        }
    }
}

/// What the client asks for on a fresh bi-stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preface {
    pub proto: L4Proto,
    /// Route key. Lower-cased on decode so a config's `host_pattern` matches whatever
    /// case the client's resolver happened to hand it.
    pub host: String,
    pub port: u16,
}

impl Preface {
    pub fn new(proto: L4Proto, host: impl Into<String>, port: u16) -> Self {
        Preface {
            proto,
            host: host.into(),
            port,
        }
    }

    /// Encoded size in bytes.
    pub fn encoded_len(&self) -> usize {
        4 + self.host.len() + 2
    }

    /// Append the preface to `out`.
    ///
    /// Separated from [`Preface::to_bytes`] so a caller that already has a buffer (the
    /// local proxy writes the preface and the first request into one `write_all`) does
    /// not allocate twice.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        if !is_valid_host(&self.host) {
            return Err(ProtoError::InvalidHost);
        }
        if self.port == 0 {
            return Err(ProtoError::InvalidPort);
        }

        out.reserve(self.encoded_len());
        out.push(PREFACE_MAGIC);
        out.push(PREFACE_VERSION);
        out.push(self.proto.as_byte());
        out.push(self.host.len() as u8);
        out.extend_from_slice(self.host.as_bytes());
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtoError> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a preface from the front of `buf`.
    ///
    /// `Ok(None)` means "not enough bytes yet" and the caller should read more — a
    /// client may write the preface and its first payload in one segment, but it may
    /// equally split the preface across two. `Ok(Some(_))` also reports how many bytes
    /// the preface occupied, so the caller can hand the remainder to the payload path
    /// instead of dropping it.
    pub fn decode(buf: &[u8]) -> Result<Option<(Preface, usize)>, ProtoError> {
        let Some(&first) = buf.first() else {
            return Ok(None);
        };
        if !is_l4_preface(first) {
            return Err(ProtoError::NotAPreface);
        }
        // magic + version + proto + host length
        if buf.len() < 4 {
            return Ok(None);
        }

        let version = buf[1];
        if version != PREFACE_VERSION {
            return Err(ProtoError::UnsupportedVersion(version));
        }
        let proto = L4Proto::from_byte(buf[2]).ok_or(ProtoError::UnknownProto(buf[2]))?;
        let host_len = buf[3] as usize;
        if host_len == 0 {
            return Err(ProtoError::InvalidHost);
        }

        let total = 4 + host_len + 2;
        if buf.len() < total {
            return Ok(None);
        }

        let host_bytes = &buf[4..4 + host_len];
        let host = std::str::from_utf8(host_bytes).map_err(|_| ProtoError::InvalidHost)?;
        if !is_valid_host(host) {
            return Err(ProtoError::InvalidHost);
        }

        let port = u16::from_be_bytes([buf[4 + host_len], buf[5 + host_len]]);
        if port == 0 {
            return Err(ProtoError::InvalidPort);
        }

        Ok(Some((
            Preface {
                proto,
                host: host.to_ascii_lowercase(),
                port,
            },
            total,
        )))
    }
}

/// Host names on the wire are ASCII graphic characters only.
///
/// This rejects space, CR, LF and NUL — the bytes that turn a host name into a forged
/// log line or a split header — while still allowing DNS labels, IPv4 literals and
/// bracketed IPv6 literals. International names must arrive as punycode, which is what
/// a resolver hands out anyway.
fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(host: &str, port: u16) -> Preface {
        Preface::new(L4Proto::Tcp, host, port)
    }

    #[test]
    fn tcp_preface_has_the_documented_bytes() {
        let bytes = tcp("db.iroh.iakl.top", 5432).to_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x05, 0x01, 0x01, 16, // magic, version, proto=tcp, host length
                b'd', b'b', b'.', b'i', b'r', b'o', b'h', b'.', b'i', b'a', b'k', b'l', b'.', b't',
                b'o', b'p', //
                0x15, 0x38, // 5432
            ]
        );
        assert_eq!(bytes.len(), 4 + 16 + 2);
    }

    #[test]
    fn udp_preface_only_differs_in_the_proto_byte() {
        let udp = Preface::new(L4Proto::Udp, "turn.example", 3478)
            .to_bytes()
            .unwrap();
        assert_eq!(udp[2], 0x02);
        let (decoded, len) = Preface::decode(&udp).unwrap().unwrap();
        assert_eq!(len, udp.len());
        assert_eq!(decoded.proto, L4Proto::Udp);
        assert_eq!(decoded.port, 3478);
    }

    #[test]
    fn round_trip_through_decode() {
        for (proto, host, port) in [
            (L4Proto::Tcp, "fn.iroh.iakl.top", 443),
            (L4Proto::Tcp, "10.0.0.50", 5432),
            (L4Proto::Udp, "turn.iroh.iakl.top", 3478),
            (L4Proto::Udp, "a", 1),
            (L4Proto::Udp, "host", 65535),
        ] {
            let original = Preface::new(proto, host, port);
            let bytes = original.to_bytes().unwrap();
            assert_eq!(bytes.len(), original.encoded_len());
            let (decoded, len) = Preface::decode(&bytes).unwrap().unwrap();
            assert_eq!(len, bytes.len());
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn decode_reports_the_payload_left_behind() {
        // A client is free to write the preface and its first payload in one segment.
        // The payload must be reported, not swallowed.
        let mut buf = tcp("db.example", 5432).to_bytes().unwrap();
        let preface_len = buf.len();
        buf.extend_from_slice(b"SELECT 1");

        let (decoded, len) = Preface::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded.host, "db.example");
        assert_eq!(len, preface_len);
        assert_eq!(&buf[len..], b"SELECT 1");
    }

    #[test]
    fn decode_asks_for_more_bytes_instead_of_failing() {
        let bytes = tcp("db.example", 5432).to_bytes().unwrap();
        // Every strict prefix must be "incomplete", never an error and never a
        // half-built preface.
        for cut in 1..bytes.len() {
            assert_eq!(Preface::decode(&bytes[..cut]), Ok(None), "cut at {cut}");
        }
        assert!(Preface::decode(&bytes).unwrap().is_some());
    }

    #[test]
    fn decode_rejects_a_foreign_first_byte() {
        assert_eq!(
            Preface::decode(b"GET / HTTP/1.1"),
            Err(ProtoError::NotAPreface)
        );
        assert_eq!(
            Preface::decode(&[0x16, 0x03, 0x01, 0x00]),
            Err(ProtoError::NotAPreface)
        );
    }

    #[test]
    fn decode_rejects_a_version_it_does_not_know() {
        let mut bytes = tcp("db.example", 5432).to_bytes().unwrap();
        bytes[1] = 0x02;
        assert_eq!(
            Preface::decode(&bytes),
            Err(ProtoError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn decode_rejects_unknown_protocols_and_empty_hosts() {
        let mut bytes = tcp("db.example", 5432).to_bytes().unwrap();
        bytes[2] = 0x07;
        assert_eq!(Preface::decode(&bytes), Err(ProtoError::UnknownProto(0x07)));

        let mut bytes = tcp("db.example", 5432).to_bytes().unwrap();
        bytes[3] = 0;
        assert_eq!(Preface::decode(&bytes), Err(ProtoError::InvalidHost));
    }

    #[test]
    fn decode_rejects_hosts_that_are_not_host_names() {
        // A host name must never be able to carry a newline into a log line.
        for forged in ["a\nb", "a b", "a\0b", "a\r\nGET / HTTP/1.1"] {
            let mut bytes = vec![PREFACE_MAGIC, PREFACE_VERSION, 0x01, forged.len() as u8];
            bytes.extend_from_slice(forged.as_bytes());
            bytes.extend_from_slice(&443u16.to_be_bytes());
            assert_eq!(
                Preface::decode(&bytes),
                Err(ProtoError::InvalidHost),
                "host {forged:?}"
            );
        }
    }

    #[test]
    fn encode_refuses_hosts_that_cannot_be_sent() {
        assert_eq!(tcp("", 443).to_bytes(), Err(ProtoError::InvalidHost));
        assert_eq!(
            tcp(&"a".repeat(256), 443).to_bytes(),
            Err(ProtoError::InvalidHost)
        );
        assert_eq!(tcp("db.example", 0).to_bytes(), Err(ProtoError::InvalidPort));
        // 255 is the last length that fits the single length byte.
        assert!(tcp(&"a".repeat(255), 443).to_bytes().is_ok());
    }

    #[test]
    fn host_is_lower_cased_on_decode() {
        let (decoded, _) = Preface::decode(&tcp("DB.Iroh.Iakl.Top", 5432).to_bytes().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(decoded.host, "db.iroh.iakl.top");
    }

    #[test]
    fn status_round_trips_and_unknown_bytes_are_marked() {
        for status in [
            Status::Ok,
            Status::NoRoute,
            Status::BackendFailed,
            Status::TooManyFlows,
            Status::BadPreface,
        ] {
            assert_eq!(Status::from_byte(status.as_byte()), status);
        }
        assert_eq!(Status::from_byte(0x7f), Status::Unknown);
        assert!(Status::Ok.is_ok());
        assert!(!Status::NoRoute.is_ok());
    }

    #[test]
    fn protocol_bytes_round_trip() {
        assert_eq!(L4Proto::from_byte(L4Proto::Tcp.as_byte()), Some(L4Proto::Tcp));
        assert_eq!(L4Proto::from_byte(L4Proto::Udp.as_byte()), Some(L4Proto::Udp));
        assert_eq!(L4Proto::from_byte(0x03), None);
        assert_eq!(L4Proto::Tcp.name(), "TCP");
    }
}
