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

use crate::auth::ClientAcl;
use crate::backend_conn::PortDefault;
use crate::routes::RoutingTable;
use crate::stream_util::{DuplexIroh, copy_both_ways, read_more_by};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// A `ClientHello` is a few hundred bytes; anything this large is not one, and
/// the cap keeps a hostile peer from making the proxy buffer without bound.
const MAX_HANDSHAKE_LEN: usize = 16 * 1024;

// The name inside the `ClientHello`, and the record it arrives in, are read by
// the client as well: it picks the route before the bytes reach the server.
// The reader is the protocol crate's, so the two cannot answer differently
// about the same hello.
pub use nexapipe_proto::tls::{
    HANDSHAKE_CLIENT_HELLO, MAX_HOST_NAME_LEN, NAME_TYPE_HOST, TLS_HANDSHAKE, extract_sni,
    is_tls_handshake,
};

/// Serve a TLS connection that arrived over an iroh bi-stream.
///
/// `initial` holds the bytes already read from `recv` (at least the first).
/// `acl` is the authenticated client's host authorization, if any.
pub async fn handle_iroh_stream(
    send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    initial: Vec<u8>,
    config: &RoutingTable,
    acl: Option<&ClientAcl>,
) -> anyhow::Result<()> {
    // A phase deadline over the ClientHello read: the record header arrives
    // first, then the handshake body, and a peer that sends five bytes and
    // stalls must not hold the stream open. `[timeouts] tls_hello_secs`
    // resolves it; the per-route surface does not reach here, because which
    // route a hello belongs to is only knowable *after* it has been read.
    let handshake =
        read_tls_record(&mut recv, initial, config.timeouts().deadlines.tls_hello).await?;
    let Some((host, port, _session)) = resolve_backend(config, &handshake, acl).await else {
        return Ok(());
    };

    let mut backend = crate::backend_conn::connect(&host, port, config.timeouts().connect).await?;
    backend.write_all(&handshake).await?;
    // Read off the client before the copy below ever saw the stream, so no
    // funnel is going to do it: without this line the ClientHello — the only
    // bytes some connections ever send before being refused SNI-first — never
    // appears in the totals.
    crate::metrics::METRICS.record_bytes_received(handshake.len() as u64);

    let client = DuplexIroh::new(send, recv);
    // The copy waits for **both** directions now, because a half-close is a
    // request and not an ending. That wait is bounded by the copy itself: once
    // one direction ends, the other is given `LINGERING` (30 s) to finish, so a
    // peer that vanished rather than half-closed cannot hold the stream.
    //
    // No whole-flow deadline is imposed here, and that is deliberate. A TLS
    // session is legitimately long-lived — a WebSocket over TLS, an IMAP IDLE
    // connection, a database session — and a passthrough route has no
    // `flow_timeout_secs` for an operator to raise. Passing `l4_flow` here
    // would cap every passthrough session at the default hour, which is a
    // budget this path never asked for and a behaviour change the half-close
    // fix does not need: the lingering bound is what keeps the wait finite.
    copy_tls_session(client, backend).await?;
    Ok(())
}

/// Serve a TLS connection that arrived on a plain TCP listener.
///
/// `initial` holds the bytes the dispatcher already peeked, if any. The
/// plaintext listener has no authenticated client behind it, so no ACL
/// applies — see the module docs of `crate::proxy` for why that listener is
/// loopback-only unless explicitly exposed.
pub async fn handle_tcp_stream(
    mut client: tokio::net::TcpStream,
    initial: Vec<u8>,
    config: &RoutingTable,
) -> anyhow::Result<()> {
    // Same deadline as the iroh path above: `[timeouts] tls_hello_secs`.
    let handshake =
        read_tls_record(&mut client, initial, config.timeouts().deadlines.tls_hello).await?;
    // `_session` is the lease, and it is bound rather than discarded: it is held
    // for the lifetime of this function, which is the lifetime of the copy — so
    // the balancer sees the session while it is running, not only while it is
    // being dialled.
    let Some((host, port, _session)) = resolve_backend(config, &handshake, None).await else {
        return Ok(());
    };

    let mut backend = crate::backend_conn::connect(&host, port, config.timeouts().connect).await?;
    backend.write_all(&handshake).await?;

    // The same copy as the iroh path above, with the same reasoning: the wait
    // after a half-close is bounded by `LINGERING`, and a whole-flow deadline
    // is not imposed on a path whose sessions are meant to be long-lived.
    copy_tls_session(client, backend).await?;
    Ok(())
}

/// The copy both TLS paths make, with the one outcome that is not a failure.
///
/// `copy_both_ways` reports `TimedOut` when the direction that outlived the
/// first one does not finish within `LINGERING`. On this path that is a session
/// that half-closed and then went quiet — a normal end, not a broken
/// connection — and the L4 path reads the same error the same way.
///
/// It can only mean that here: this path passes no whole-flow deadline, so the
/// copy's own `TimedOut` is the only one it can produce. Reporting it as an
/// error would put a line in the log, at `error`, for every session that ended
/// the way a half-closed one is supposed to.
async fn copy_tls_session<A, B>(client: A, backend: B) -> anyhow::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match copy_both_ways(client, backend, "TLS passthrough").await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            tracing::debug!(
                "TLS passthrough: the other direction did not finish after a half-close, closing"
            );
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
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
    // One deadline for the whole record, not one per read: a peer that dribbles
    // a byte at a time restarts a per-read timeout forever, and holding this
    // stream open is the whole cost of the attack.
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let Some(record_end) = first_record_end(&buf) else {
            if buf.len() > MAX_HANDSHAKE_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS ClientHello header not received",
                ));
            }
            if !read_more_by(reader, &mut buf, deadline).await? {
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
        if !read_more_by(reader, &mut buf, deadline).await? {
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
/// `None` means "nothing to do": no SNI, no passthrough route for it, an SNI
/// the client's allowlist does not name, or an address that cannot be parsed.
/// Every case is logged, and every case hangs up the same way — a client
/// cannot tell "not configured" from "not allowed", so it cannot probe which
/// names exist behind the proxy.
/// The third element is the lease, and callers must hold it for as long as they
/// are copying: see [`crate::lb::BackendLease`]. Dropping it early tells the
/// balancer this session is over while the bytes are still flowing.
async fn resolve_backend(
    config: &RoutingTable,
    handshake: &[u8],
    acl: Option<&ClientAcl>,
) -> Option<(String, u16, crate::lb::BackendLease)> {
    let Some(sni) = extract_sni(handshake) else {
        tracing::debug!("TLS passthrough: no SNI in ClientHello, closing");
        return None;
    };

    if let Some(acl) = acl
        && !acl.allows(&sni)
    {
        tracing::warn!(
            "TLS passthrough: SNI '{}' is not allowed for this client, closing",
            sni
        );
        return None;
    }

    // Either refusal hangs up, and the two are not the same event: no route is
    // a name this proxy does not serve, whereas every backend behind the route
    // being down is an outage. `get_passthrough_backend` logs the detail; either
    // way there is nothing to copy bytes to, so nobody gets a TLS handshake.
    //
    // **One lookup, then the check.** The pool rotates on every selection, so a
    // second `get_passthrough_backend` for the same SNI can hand back a
    // different backend than the one that was checked — and on a route with a
    // backend on an allowed port and one on a forbidden port, the check would
    // pass half the time and the flow would go to the other one. It would also
    // spend two steps of the rotation on one session.
    let Some(backend) = config.get_passthrough_backend(&sni).await.backend() else {
        tracing::warn!(
            "TLS passthrough: nothing to forward SNI '{}' to, closing",
            sni
        );
        return None;
    };

    // The port the session is served from, checked against the client's port
    // list when the ACL is strict. The passthrough had no port check at all
    // before: a client limited to one port could reach every service on every
    // name it was allowed, over the SNI path as well as the HTTP one.
    if let Some(acl) = acl
        && let Some(port) = crate::routes::backend_port(backend.url())
        && !acl.allows_backend_port(port)
    {
        tracing::warn!(
            "TLS passthrough: port {port} (the backend for '{}') is not allowed for this client, \
             closing",
            sni
        );
        return None;
    }

    let Some((host, port)) = parse_backend_addr(backend.url()) else {
        tracing::error!(
            "TLS passthrough: cannot parse backend address '{}' for SNI '{}'",
            backend.url(),
            sni
        );
        return None;
    };

    tracing::debug!("TLS passthrough: SNI '{}' -> {}:{}", sni, host, port);
    Some((host, port, backend))
}

/// Accepts `host:port` or a full URL (`https://caddy:443`).
///
/// The scheme carries no meaning here — passthrough copies bytes and never
/// speaks TLS itself — so it is accepted and ignored, which keeps the backend
/// list in the same shape as the HTTP routes.
///
/// A backend that does not name a port gets the scheme's own, and a bare host
/// gets the TLS port: the bytes are forwarded to a listener that terminates
/// TLS, and `https://host` is the HTTPS port. The L4 path reads the same
/// address from the same parser, but refuses the bare-host reading: a raw
/// tunnel has no scheme to take a port from.
///
/// Public because the config check uses it too: the route is dialled with this
/// function, so validating with anything else is how a backend passes at
/// startup and fails on the first connection.
pub fn parse_backend_addr(backend: &str) -> Option<(String, u16)> {
    crate::backend_conn::parse_backend_addr(backend, PortDefault::SchemeOrBare { bare: 443 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RouteMode, Timeouts, TimeoutsConfig};
    use crate::lb::LoadBalancingStrategy;
    use crate::routes::Route;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn the_configured_tls_hello_deadline_closes_a_stalled_hello() {
        // The same observation the l4 idle test makes: `tls_hello_secs` has to
        // reach `read_tls_record`, not merely parse. The bound here used to be
        // a private constant; the key replaces the constant, and this asserts
        // the replacement actually bit — a peer that sends the five record
        // header bytes and then stalls must be dropped on the configured
        // deadline.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut timeouts = Timeouts::resolve(TimeoutsConfig::default());
        timeouts.deadlines.tls_hello = std::time::Duration::from_secs(1);
        let config = RoutingTable::with_timeouts(
            vec![Route::new(
                "app.test",
                "/",
                true,
                vec!["127.0.0.1:1".to_string()],
                LoadBalancingStrategy::RoundRobin,
                RouteMode::Tcp,
                None,
            )],
            timeouts,
        );

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_tcp_stream(stream, Vec::new(), &config).await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // A record header promising 255 bytes of handshake, then silence: the
        // header alone must not hold the read.
        client
            .write_all(&[TLS_HANDSHAKE, 0x03, 0x01, 0x00, 0xff])
            .await
            .unwrap();

        let started = std::time::Instant::now();
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), server).await;
        assert!(
            result.is_ok(),
            "the handler must give up on the configured hello deadline"
        );
        // The deadline surfaces as "no complete hello" — the record reader
        // treats an expired deadline like a stalled end, the truncated hello
        // names no route, and the handler returns. What the key buys is the
        // *when*: one second here, where the constant it replaced held the
        // handler for ten.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the handler must return within the configured hello deadline, took {:?}",
            started.elapsed()
        );
    }

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

        client_hello_with_extension_body(&ext_body)
    }

    /// Wraps a ready-made extensions block into a full `ClientHello`, for the
    /// cases the single-SNI helper cannot spell (several entries, another
    /// entry type).
    fn client_hello_with_extension_body(ext_body: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(1); // compression_methods length
        body.push(0); // null compression
        body.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        body.extend_from_slice(ext_body);

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

    /// The list RFC 6066 allows: an entry of a type this proxy does not read
    /// comes first, and the host name behind it used to be invisible.
    #[test]
    fn reads_the_host_name_behind_another_kind_of_entry() {
        let mut entry = Vec::new();
        // Type 1 is not host_name; the bytes are opaque here.
        entry.push(1);
        entry.extend_from_slice(&3u16.to_be_bytes());
        entry.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        entry.push(NAME_TYPE_HOST);
        entry.extend_from_slice(&("fn.iroh.iakl.top".len() as u16).to_be_bytes());
        entry.extend_from_slice(b"fn.iroh.iakl.top");

        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&0u16.to_be_bytes()); // ext type: server_name
        ext_body.extend_from_slice(&((2 + entry.len()) as u16).to_be_bytes());
        ext_body.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(&entry);

        let hello = client_hello_with_extension_body(&ext_body);
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

    /// Every path through `resolve_backend` writes the SNI to the log, so a
    /// name carrying a newline would let a client append lines of its own to
    /// it. It is dropped here instead of escaped on the way out: a name that
    /// is not a name has no route to reach either.
    #[test]
    fn refuses_a_host_name_that_could_forge_a_log_line() {
        for name in [
            "app.test\r\n2FA: client 'x' enrolled",
            "app.test\n",
            "app\ttest",
            "app test",
            "app.test\u{7f}",
        ] {
            let hello = client_hello_with_sni(name, true);
            assert_eq!(extract_sni(&hello), None, "{name:?}");
        }
    }

    /// `host_name` is ASCII on the wire (RFC 6066), so an internationalised
    /// name arrives as its A-label. Raw UTF-8 is malformed, and accepting it
    /// would leave one host reachable under two spellings.
    #[test]
    fn refuses_a_host_name_that_is_not_ascii() {
        let hello = client_hello_with_sni("caf\u{00e9}.test", true);
        assert_eq!(extract_sni(&hello), None);
    }

    #[test]
    fn refuses_a_host_name_past_the_dns_limit() {
        let long = "a".repeat(MAX_HOST_NAME_LEN + 1);
        let hello = client_hello_with_sni(&long, true);
        assert_eq!(extract_sni(&hello), None);

        let at_limit = "a".repeat(MAX_HOST_NAME_LEN);
        assert_eq!(
            extract_sni(&client_hello_with_sni(&at_limit, true)).as_deref(),
            Some(at_limit.as_str())
        );
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

    /// A restricted client gets nothing for an SNI its allowlist never named —
    /// the same `None` an unconfigured SNI gets, so the refusal cannot be
    /// told apart from "no route" and used as a probe. An on-list SNI reaches
    /// its backend as usual.
    #[tokio::test]
    async fn an_sni_off_the_clients_allowlist_resolves_to_nothing() {
        use crate::auth::ClientAcl;
        use crate::config::RouteMode;
        use crate::lb::LoadBalancingStrategy;
        use crate::routes::{Route, RoutingTable};

        let config = RoutingTable::new(vec![Route::new(
            "fn.iroh.iakl.top",
            "/",
            true,
            vec!["caddy:443".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Passthrough,
            None,
        )]);

        // Off-list: refused, even though a passthrough route exists.
        let acl = ClientAcl::from_hosts(Some(&["other.iakl.top".to_string()]));
        let hello = client_hello_with_sni("fn.iroh.iakl.top", true);
        assert!(resolve_backend(&config, &hello, Some(&acl)).await.is_none());

        // On-list: reaches the route's backend.
        let acl = ClientAcl::from_hosts(Some(&["*.iroh.iakl.top".to_string()]));
        assert_eq!(
            resolve_backend(&config, &hello, Some(&acl))
                .await
                .map(|(host, port, _lease)| (host, port)),
            Some(("caddy".to_string(), 443))
        );

        // No ACL (no 2FA behind the connection): the historical behaviour.
        assert_eq!(
            resolve_backend(&config, &hello, None)
                .await
                .map(|(host, port, _lease)| (host, port)),
            Some(("caddy".to_string(), 443))
        );
    }

    #[test]
    fn detects_tls_handshake_prefix() {
        assert!(is_tls_handshake(0x16));
        assert!(!is_tls_handshake(b'G'));
        assert!(!is_tls_handshake(0x17));
    }

    #[test]
    fn an_ipv6_backend_loses_its_brackets() {
        // With the brackets left on, the resolver is asked for a host called
        // "[::1]" and every connection to this backend fails.
        assert_eq!(
            parse_backend_addr("[::1]:443"),
            Some(("::1".to_string(), 443))
        );
        assert_eq!(
            parse_backend_addr("https://[::1]:8443"),
            Some(("::1".to_string(), 8443))
        );
        assert_eq!(parse_backend_addr("[::1]"), Some(("::1".to_string(), 443)));
    }

    #[test]
    fn a_backend_with_no_address_is_refused() {
        assert_eq!(parse_backend_addr(""), None);
        assert_eq!(parse_backend_addr("   "), None);
    }

    /// An address that refuses the connection: a port that was bound and
    /// released, so nothing is listening on it any more.
    async fn refusing_addr() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn the_dial_tries_the_next_address_when_the_first_refuses() {
        // A backend with two addresses: the first refuses, the second
        // accepts. The dial has to get to the second one — that is what
        // `TcpStream::connect((host, port))` did, and what the hand-written
        // dial has to keep doing.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let accepting = listener.local_addr().unwrap();
        let refused = refusing_addr().await;

        let started = std::time::Instant::now();
        let stream = crate::backend_conn::connect_addrs(
            &[refused, accepting],
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
        .expect("the second address should have been tried");

        assert_eq!(
            stream.peer_addr().unwrap(),
            accepting,
            "the dial should have ended on the address that accepted"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the second address is inside the same deadline, not a new one, took {:?}",
            started.elapsed()
        );
    }
}

#[cfg(test)]
mod review_probe {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A TLS record whose own length is four times the cap is accepted whole.
    #[tokio::test]
    async fn a_record_past_the_cap_is_accepted_whole() {
        let mut record = vec![TLS_HANDSHAKE, 0x03, 0x01, 0xff, 0xff];
        record.extend(std::iter::repeat_n(0u8, 0xffff));
        let (mut writer, mut reader) = tokio::io::duplex(record.len() + 64);
        let task = tokio::spawn(async move {
            read_tls_record(&mut reader, Vec::new(), std::time::Duration::from_secs(5)).await
        });
        writer.write_all(&record).await.unwrap();
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
        // Falsified hypothesis: the record is NOT accepted. The cap is
        // enforced on the record length even though the length check runs
        // after the "already complete" check, because the reads are 4 KiB at
        // a time and the record can never be complete before the check runs.
        let err = out.expect_err("the oversized record must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(MAX_HANDSHAKE_LEN < 5 + 0xffff);
    }
}
