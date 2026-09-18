//! Raw byte forwarding for connections the proxy must not parse.
//!
//! TLS is terminated by the backend (Caddy &co), so a `ClientHello` reaching
//! the proxy is not a request this process can act on: the SNI inside it names
//! the route, and the bytes are copied to that route's backend untouched. The
//! proxy holds no key material and never inspects the encrypted traffic.
//!
//! Both entry points feed this module. The iroh path sees the `ClientHello`
//! written by the client's tunnel (`nexapipe-client::local_proxy::
//! handle_tls_tunnel`); the plaintext listener sees one from any local client.
//! Either way the first byte is `0x16`, which is what the dispatchers key on —
//! an HTTP request can never start with it.

use crate::routes::RouteConfig;
use crate::stream_util::{DuplexIroh, copy_both_ways, read_more};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt};

/// TLS record content type: handshake (a `ClientHello` starts with this).
pub const TLS_HANDSHAKE: u8 = 0x16;

/// Handshake message type: `ClientHello`.
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Extension type: `server_name` (RFC 6066).
const EXT_SERVER_NAME: u16 = 0x0000;

/// SNI name type: `host_name`.
const NAME_TYPE_HOST: u8 = 0x00;

/// A `ClientHello` is a few hundred bytes; anything this large is not one, and
/// the cap keeps a hostile peer from making the proxy buffer without bound.
const MAX_HANDSHAKE_LEN: usize = 16 * 1024;

/// How long to wait for the rest of the `ClientHello` before giving up on it.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a backend connection may take to establish.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// True when `first_byte` starts a TLS handshake record.
pub fn is_tls_handshake(first_byte: u8) -> bool {
    first_byte == TLS_HANDSHAKE
}

/// Serve a TLS connection that arrived over an iroh bi-stream.
///
/// `initial` holds the bytes already read from `recv` (at least the first).
pub async fn handle_iroh_stream(
    send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    initial: Vec<u8>,
    config: &RouteConfig,
) -> anyhow::Result<()> {
    let handshake = read_tls_record(&mut recv, initial, HANDSHAKE_TIMEOUT).await?;
    let Some((host, port)) = resolve_backend(config, &handshake).await else {
        return Ok(());
    };

    let mut backend = connect(&host, port).await?;
    backend.write_all(&handshake).await?;

    let client = DuplexIroh::new(send, recv);
    copy_both_ways(client, backend, "TLS passthrough").await?;
    Ok(())
}

/// Serve a TLS connection that arrived on a plain TCP listener.
///
/// `initial` holds the bytes the dispatcher already peeked, if any.
pub async fn handle_tcp_stream(
    mut client: tokio::net::TcpStream,
    initial: Vec<u8>,
    config: &RouteConfig,
) -> anyhow::Result<()> {
    let handshake = read_tls_record(&mut client, initial, HANDSHAKE_TIMEOUT).await?;
    let Some((host, port)) = resolve_backend(config, &handshake).await else {
        return Ok(());
    };

    let mut backend = connect(&host, port).await?;
    backend.write_all(&handshake).await?;

    copy_both_ways(client, backend, "TLS passthrough").await?;
    Ok(())
}

async fn connect(host: &str, port: u16) -> anyhow::Result<tokio::net::TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("timed out connecting to backend {}:{}", host, port))?
        .map_err(|e| anyhow::anyhow!("failed to connect to backend {}:{}: {}", host, port, e))?;

    // The tunnel carries TLS records; Nagle would only add latency here.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Reads until the first TLS record is complete.
///
/// SNI lives inside the `ClientHello`, which a client may spread over several
/// segments, and the proxy cannot pick a backend before it has the whole
/// record. A peer that goes quiet is not an error: whatever arrived is returned
/// and the SNI parse decides what happens next.
async fn read_tls_record<R>(
    reader: &mut R,
    mut buf: Vec<u8>,
    timeout: Duration,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(record_end) = first_record_end(&buf) else {
            if buf.len() > MAX_HANDSHAKE_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS ClientHello header not received",
                ));
            }
            if !read_more(reader, &mut buf, timeout).await? {
                return Ok(buf);
            }
            continue;
        };

        if buf.len() >= record_end {
            return Ok(buf);
        }
        if record_end > MAX_HANDSHAKE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS record larger than a ClientHello can be",
            ));
        }
        if !read_more(reader, &mut buf, timeout).await? {
            return Ok(buf);
        }
    }
}

/// End offset of the first TLS record, once its 5-byte header is available.
fn first_record_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    Some(5 + (((buf[3] as usize) << 8) | (buf[4] as usize)))
}

/// Maps a `ClientHello` to the backend that should terminate it.
///
/// `None` means "nothing to do": no SNI, no passthrough route for it, or an
/// address that cannot be parsed. Every case is logged.
async fn resolve_backend(config: &RouteConfig, handshake: &[u8]) -> Option<(String, u16)> {
    let Some(sni) = extract_sni(handshake) else {
        tracing::debug!("TLS passthrough: no SNI in ClientHello, closing");
        return None;
    };

    let Some(backend) = config.get_passthrough_backend(&sni).await else {
        tracing::warn!(
            "TLS passthrough: no `mode = \"passthrough\"` route for SNI '{}', closing",
            sni
        );
        return None;
    };

    let Some((host, port)) = parse_backend_addr(&backend) else {
        tracing::error!(
            "TLS passthrough: cannot parse backend address '{}' for SNI '{}'",
            backend,
            sni
        );
        return None;
    };

    tracing::debug!("TLS passthrough: SNI '{}' -> {}:{}", sni, host, port);
    Some((host, port))
}

/// Accepts `host:port` or a full URL (`https://caddy:443`).
///
/// The scheme carries no meaning here — passthrough copies bytes and never
/// speaks TLS itself — so it is accepted and ignored, which keeps the backend
/// list in the same shape as the HTTP routes.
fn parse_backend_addr(backend: &str) -> Option<(String, u16)> {
    let backend = backend.trim();
    if backend.is_empty() {
        return None;
    }

    if backend.contains("://") {
        let url = url::Url::parse(backend).ok()?;
        let host = url.host_str()?.to_string();
        let port = url.port_or_known_default()?;
        return Some((host, port));
    }

    match backend.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => port.parse().ok().map(|p| (host.to_string(), p)),
        // A bare host means the TLS port, which is the only thing a
        // passthrough route ever points at.
        _ => Some((backend.to_string(), 443)),
    }
}

/// Extract the SNI host name from a TLS `ClientHello`.
///
/// Layout (RFC 8446 / RFC 6066), all lengths big-endian:
///
/// ```text
/// record:   type(1) version(2) length(2)
/// handshake: type(1) length(3)
///   client_version(2) random(32)
///   session_id:   length(1) + data
///   cipher_suites: length(2) + data
///   compression:  length(1) + data
///   extensions:   length(2) + data
///     extension: type(2) length(2) data
///       server_name: list_length(2) name_type(1) name_length(2) host_name
/// ```
///
/// Returns `None` for anything that does not fit that shape, including a
/// `ClientHello` that carries no `server_name` extension.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    let mut record = Cursor::new(data);
    if record.u8()? != TLS_HANDSHAKE {
        return None;
    }
    record.skip(2)?; // legacy record version
    let record_len = record.u16()? as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    // Handshake header. Its own length is redundant with the record length, so
    // only the type is checked.
    if record.u8()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    record.skip(3)?;

    record.skip(2)?; // client_version
    record.skip(32)?; // random

    let session_id_len = record.u8()? as usize;
    record.skip(session_id_len)?;

    let cipher_suites_len = record.u16()? as usize;
    record.skip(cipher_suites_len)?;

    let compression_len = record.u8()? as usize;
    record.skip(compression_len)?;

    let extensions_len = record.u16()? as usize;
    let mut extensions = Cursor::new(record.take(extensions_len)?);

    while extensions.remaining() >= 4 {
        let ext_type = extensions.u16()?;
        let ext_len = extensions.u16()? as usize;
        let ext_data = extensions.take(ext_len)?;

        if ext_type == EXT_SERVER_NAME {
            let mut sni = Cursor::new(ext_data);
            sni.skip(2)?; // server_name_list length
            let name_type = sni.u8()?;
            let name_len = sni.u16()? as usize;
            let name = sni.take(name_len)?;

            if name_type == NAME_TYPE_HOST {
                return String::from_utf8(name.to_vec()).ok();
            }
        }
    }

    None
}

/// Bounds-checked reader over a byte slice; every getter yields `None` on
/// overrun so the parser is a single chain of `?` with no index arithmetic.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let value = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        let high = self.u8()? as u16;
        let low = self.u8()? as u16;
        Some((high << 8) | low)
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(|_| ())
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but well-formed `ClientHello` carrying `sni`.
    fn client_hello_with_sni(sni: &str, include_extension: bool) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();

        let mut ext_body = Vec::new();
        if include_extension {
            ext_body.extend_from_slice(&0u16.to_be_bytes()); // ext type: server_name
            let entry_len = 1 + 2 + sni_bytes.len();
            ext_body.extend_from_slice(&((2 + entry_len) as u16).to_be_bytes()); // ext length
            ext_body.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list length
            ext_body.push(NAME_TYPE_HOST);
            ext_body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
            ext_body.extend_from_slice(sni_bytes);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(1); // compression_methods length
        body.push(0); // null compression
        body.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_body);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte length
        handshake.extend_from_slice(&body);

        let mut record = vec![TLS_HANDSHAKE, 0x01, 0x00];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let hello = client_hello_with_sni("fn.iroh.iakl.top", true);
        assert_eq!(extract_sni(&hello).as_deref(), Some("fn.iroh.iakl.top"));
    }

    #[test]
    fn returns_none_without_server_name_extension() {
        let hello = client_hello_with_sni("fn.iroh.iakl.top", false);
        assert_eq!(extract_sni(&hello), None);
    }

    #[test]
    fn returns_none_for_truncated_handshake() {
        let hello = client_hello_with_sni("fn.iroh.iakl.top", true);
        // The parser must refuse a partial record rather than read past it: the
        // caller guarantees the full record, this is the second line of defence.
        for cut in 1..hello.len().min(40) {
            assert_eq!(extract_sni(&hello[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn returns_none_for_non_handshake_records() {
        assert_eq!(extract_sni(&[]), None);
        assert_eq!(extract_sni(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), None);
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn parses_backend_addresses() {
        assert_eq!(
            parse_backend_addr("caddy:443"),
            Some(("caddy".to_string(), 443))
        );
        assert_eq!(
            parse_backend_addr("https://caddy:8443"),
            Some(("caddy".to_string(), 8443))
        );
        assert_eq!(
            parse_backend_addr("http://host.docker.internal"),
            Some(("host.docker.internal".to_string(), 80))
        );
        assert_eq!(
            parse_backend_addr("caddy"),
            Some(("caddy".to_string(), 443))
        );
        assert_eq!(parse_backend_addr(""), None);
        assert_eq!(parse_backend_addr("caddy:notaport"), None);
    }

    #[test]
    fn detects_tls_handshake_prefix() {
        assert!(is_tls_handshake(0x16));
        assert!(!is_tls_handshake(b'G'));
        assert!(!is_tls_handshake(0x17));
    }
}
