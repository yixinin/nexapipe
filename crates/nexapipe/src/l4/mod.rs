//! The L4 tunnel: TCP and UDP to a route's backend, chosen by an explicit preface.
//!
//! # How a stream gets here
//!
//! `conn::handle_bidi_stream` runs before the HTTP header loop and keys on the first
//! byte: `0x16` is a TLS session (SNI passthrough), `0x05` is an L4 preface (this
//! module), anything else is a request. The L4 client is our own code, so it can state
//! what it wants instead of being sniffed — which is the only way UDP can work, since
//! a datagram carries no `Host` header to route on.
//!
//! # Who picks the backend
//!
//! The client sends a host name and a port; **the route decides the address that is
//! actually dialled** ([`RoutingTable::get_l4_backend`]). A client holding 2FA
//! credentials therefore cannot use the server as an open relay. A host with no
//! `mode = "tcp"` / `mode = "udp"` route gets [`Status::NoRoute`] and the stream ends:
//! there is no fallback, because that is how a mistyped domain ends up quietly
//! talking to an unrelated service.
//!
//! # Handshake
//!
//! ```text
//! client -> 0x05 ver proto host-len host port   (nexapipe_proto::Preface)
//! server -> status byte                         (nexapipe_proto::Status)
//! then payload: raw bytes for TCP, length-prefixed frames for UDP
//! ```
//!
//! The status byte is sent before any payload, so a client can tell "no route" from
//! "backend down" from "connection full" without heuristics.
//!
//! # What the access log says about a flow
//!
//! A flow carries bytes, so the line for one used to say only what the tunnel
//! did with them. The first bytes of a flow usually say more than that — a TLS
//! handshake names the host it wants, a plaintext HTTP exchange says what was
//! asked for and what came back — and `sniff` reads them as they go past, so
//! the line can say it. It reads and does not act: the route was chosen by the
//! preface before a single payload byte arrived.

mod sniff;

use crate::auth::ClientAcl;
use crate::conn::peers::PeerIdentity;
use crate::l4::sniff::{FlowSniffer, Side, SniffReader};
use crate::metrics;
use crate::routes::{BackendLookup, RoutingTable};
use crate::stream_util::{DuplexIroh, copy_both_ways_until, read_more_by};
use nexapipe_proto::{
    Frame, L4Proto, MAX_PREFACE_LEN, PREFACE_MAGIC, Preface, ProtoError, Status, decode_frame,
    encode_frame, payload_fits_datagram,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// How long a client may take to spell out a complete preface.
///
/// A phase deadline, but not one of the six in [`crate::deadline`]: the preface
/// is protocol mechanics on a stream that has already passed the handshake, and
/// the audit's six timeout gaps did not include it. Kept here until it earns a
/// key.
const PREFACE_TIMEOUT: Duration = Duration::from_secs(10);

/// Concurrent L4 flows allowed on one QUIC connection, unless the route says otherwise.
///
/// Deliberately below the transport's `max_concurrent_bidi_streams`: at the transport
/// limit the peer's `open_bi` blocks silently until a slot frees, whereas here the
/// client gets an explicit [`Status::TooManyFlows`] and can fail the flow it is opening
/// instead of hanging.
pub const DEFAULT_MAX_FLOWS_PER_CONNECTION: usize = 256;

/// True when `first_byte` means "this stream is an L4 tunnel".
pub fn is_l4_stream(first_byte: u8) -> bool {
    first_byte == PREFACE_MAGIC
}

/// Counts the L4 flows one QUIC connection is carrying.
///
/// Only the L4 path acquires from it: HTTP requests, WebSocket tunnels and TLS
/// passthrough sessions end on their own schedule and are not what makes the stream
/// limit interesting.
pub struct FlowLimiter {
    current: AtomicUsize,
    max: usize,
}

impl FlowLimiter {
    pub fn new(max: usize) -> Self {
        FlowLimiter {
            current: AtomicUsize::new(0),
            max,
        }
    }

    /// Takes a slot, or returns `None` when the connection is full.
    pub fn try_acquire(self: &Arc<Self>) -> Option<FlowGuard> {
        // A compare-exchange loop rather than fetch_add: the check and the increment
        // have to be one step, or a burst of flows can each observe the same free slot.
        let mut current = self.current.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.current.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(FlowGuard {
                        limiter: self.clone(),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Flows currently open, for tests and diagnostics.
    pub fn current(&self) -> usize {
        self.current.load(Ordering::Acquire)
    }

    pub fn max(&self) -> usize {
        self.max
    }
}

/// Releases one slot when the flow ends, however it ends.
pub struct FlowGuard {
    limiter: Arc<FlowLimiter>,
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.limiter.current.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serve an L4 connection that arrived over an iroh bi-stream.
///
/// `initial` holds the bytes already read from `recv` (at least the first).
/// `acl` is the authenticated client's host authorization, if any.
// See the note on `conn::handle_bidi_stream`: the id is the eighth argument,
// and it travels through here to reach the access log. `who`, the ninth and
// newest, travels the same way — it is the identity the handshake settled on,
// which only the caller of the caller knows.
#[allow(clippy::too_many_arguments)]
pub async fn handle_iroh_stream(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    initial: Vec<u8>,
    config: &RoutingTable,
    limiter: &Arc<FlowLimiter>,
    peer: &str,
    acl: Option<&ClientAcl>,
    request_id: &str,
    // Who the connection authenticated as, for the access log.
    who: Option<&PeerIdentity>,
) -> anyhow::Result<()> {
    serve_stream(
        DuplexIroh::new(send, recv),
        initial,
        config,
        limiter,
        peer,
        acl,
        request_id,
        who,
    )
    .await
}

/// The protocol itself, over any duplex stream.
///
/// Generic on purpose: `tokio::io::duplex` gives a test both ends in one process, so
/// the handshake, the status codes and the UDP framing are covered without an iroh
/// endpoint — the same reason `passthrough` is written this way.
/// `who` is who the connection authenticated as, for the access log — `None`
/// for the plaintext listener, which never runs a handshake.
// Same reason as `handle_iroh_stream` above, one argument further along: the
// two things this hands to the access log, the request id and the identity, are
// both made by the caller of the caller and are only carried through here.
#[allow(clippy::too_many_arguments)]
pub async fn serve_stream<S>(
    stream: S,
    initial: Vec<u8>,
    config: &RoutingTable,
    limiter: &Arc<FlowLimiter>,
    peer: &str,
    acl: Option<&ClientAcl>,
    request_id: &str,
    // Who the connection authenticated as, for the access log. `None` for a
    // flow that came in without a handshake — the plaintext L4 listener.
    who: Option<&PeerIdentity>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = stream;

    let (preface, leftover) = match read_preface(&mut stream, initial).await {
        Ok(value) => value,
        Err(PrefaceFailure::Proto(e)) => {
            // Answer before hanging up: "bad preface" on the wire beats a bare FIN,
            // which the client can only report as a connection error.
            let _ = write_status(&mut stream, Status::BadPreface).await;
            tracing::warn!("L4: rejecting stream from {}: {}", peer, e);
            return Ok(());
        }
        Err(PrefaceFailure::Io(e)) => return Err(e.into()),
    };

    // A client whose allowlist does not name this host is refused exactly the
    // way an unconfigured one is — `NoRoute`, not a distinct status, so the
    // answer cannot be used to probe which hosts exist behind the tunnel.
    //
    // The port is checked here too, and for the same reason: a tunnel preface
    // names the port the client wants, so it is a port this client may or may
    // not reach.
    if let Some(acl) = acl
        && !acl.allows_target(&preface.host, preface.port)
    {
        let _ = write_status(&mut stream, Status::NoRoute).await;
        tracing::warn!(
            "L4 {}: {}:{} is not allowed for this client, closing",
            preface.proto.name(),
            preface.host,
            preface.port
        );
        return Ok(());
    }

    let mode = crate::config::RouteMode::from_l4_proto(preface.proto);
    let started = std::time::Instant::now();
    let target = format!("{}:{}", preface.host, preface.port);

    // The span was opened by the caller with empty fields. A tunnel is not a
    // request, so what goes in them is what the access log records for one:
    // the protocol where a method would be, and the target where a URI would.
    let span = tracing::Span::current();
    // A tunnel's target is a host and a port rather than a URI, so there is
    // nothing to redact in it today; the same redaction is applied anyway,
    // because the day the target grows a query string it should not grow one
    // in the log with it.
    crate::log::record_request_on_span(&span, preface.proto.name(), &target);

    let lookup = config
        .get_l4_backend(&preface.host, preface.port, mode)
        .await;

    let unhealthy = matches!(lookup, BackendLookup::Unavailable);
    let Some(route) = lookup.backend() else {
        // Both refusals end the flow, but with different statuses, because a
        // client can act on the difference: no route is something the request
        // named wrong, whereas a route whose every backend is down is an outage
        // to retry later. Answering `NoRoute` for the second would tell every
        // client its configuration is wrong at the moment it is correct.
        let status = if unhealthy {
            Status::BackendFailed
        } else {
            Status::NoRoute
        };
        // 404 and 503 are what the log and the metrics mean by those names; the
        // wire carries its own vocabulary.
        let logged_as = if unhealthy { 503 } else { 404 };
        let _ = write_status(&mut stream, status).await;
        tracing::warn!(
            "L4 {}: {} for {}, closing",
            preface.proto.name(),
            if unhealthy {
                "every backend behind the route is unhealthy"
            } else {
                "no route of this mode serves it"
            },
            target
        );
        // A flow, not a request: this is a tunnel that stays open for as long
        // as the client wants, so it gets its own counter instead of being
        // counted alongside requests — a rate made of both would be a rate of
        // two different things.
        metrics::METRICS.record_l4_flow(preface.proto.name(), logged_as);
        span.record("status", logged_as as u64);
        crate::log::log_access_flow(
            request_id,
            peer,
            preface.proto.name(),
            &target,
            logged_as,
            0,
            0,
            who,
            // The flow never started, so there is nothing it could have said.
            None,
        );
        return Ok(());
    };

    // Count the flow after the route matched but before dialling: a flow that cannot
    // even be admitted should not consume a backend connection first.
    let Some(_flow) = limiter.try_acquire() else {
        let _ = write_status(&mut stream, Status::TooManyFlows).await;
        tracing::warn!(
            "L4 {}: {} already carries {} flows, refusing {}",
            preface.proto.name(),
            peer,
            limiter.max(),
            target
        );
        metrics::METRICS.record_l4_flow(preface.proto.name(), 429);
        span.record("status", 429u64);
        crate::log::log_access_flow(
            request_id,
            peer,
            preface.proto.name(),
            &target,
            429,
            0,
            0,
            who,
            // The flow never started, so there is nothing it could have said.
            None,
        );
        return Ok(());
    };

    tracing::info!(
        "L4 {}: {} -> backend {} ({})",
        preface.proto.name(),
        target,
        route.backend,
        peer
    );

    let connect_timeout = config.timeouts().connect;
    // Both bounds are per route, and both have a server default: the idle one is
    // the gap between packets, the flow one is how long the flow may last. See
    // `L4Options::flow_timeout` for why they are not the same number. The
    // defaults come from `[timeouts]` (`l4_flow_secs`, `l4_idle_secs`) through
    // the config the connection arrived under, not from here.
    let deadlines = config.timeouts().deadlines;
    // One sniffer for the whole flow, shared by its two ends: what the client
    // said and what the origin answered are one answer between them.
    let sniffer = Arc::new(FlowSniffer::new());
    let result = match preface.proto {
        L4Proto::Tcp => {
            let flow_timeout = route.flow_timeout.unwrap_or(deadlines.l4_flow);
            serve_tcp(
                stream,
                &route.backend,
                leftover,
                connect_timeout,
                flow_timeout,
                &sniffer,
            )
            .await
        }
        L4Proto::Udp => {
            let idle = route.idle_timeout.unwrap_or(deadlines.l4_idle);
            let flow_timeout = route.flow_timeout.unwrap_or(deadlines.l4_flow);
            serve_udp(stream, &route.backend, leftover, idle, flow_timeout).await
        }
    };

    // What the flow said about itself, now that it has said it. `None` for a
    // flow that said nothing this proxy can read, which is most of them.
    let detail = sniffer.verdict();

    match &result {
        Ok(()) => {
            metrics::METRICS.record_l4_flow(preface.proto.name(), 200);
            span.record("status", 200u64);
            crate::log::log_access_flow(
                request_id,
                peer,
                preface.proto.name(),
                &target,
                200,
                started.elapsed().as_millis() as u64,
                0,
                who,
                detail.as_ref(),
            )
        }
        Err(e) => {
            tracing::debug!("L4 {} {} ended: {}", preface.proto.name(), target, e);
            metrics::METRICS.record_l4_flow(preface.proto.name(), 502);
            span.record("status", 502u64);
            crate::log::log_access_flow(
                request_id,
                peer,
                preface.proto.name(),
                &target,
                502,
                started.elapsed().as_millis() as u64,
                0,
                who,
                detail.as_ref(),
            );
        }
    }

    result
}

/// TCP: dial the backend, hand the client its status byte, then copy raw bytes.
///
/// `sniffer` watches the two ends of the flow as the bytes go past, so the
/// access log can say what the flow was; it changes nothing about the flow.
///
/// `flow_timeout` bounds the whole flow rather than the gap between packets: a
/// TCP connection that is being used and one that is being held open by a peer
/// that keeps it technically alive look identical from here, so bounding only the
/// silence would let the second renew itself forever. It is configurable per
/// route because a legitimate long-lived session — an interactive SSH connection,
/// a database session — is meant to outlive any default.
async fn serve_tcp<S>(
    mut stream: S,
    backend: &str,
    leftover: Vec<u8>,
    connect_timeout: Duration,
    flow_timeout: Duration,
    sniffer: &Arc<FlowSniffer>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Some((host, port)) = parse_backend_addr(backend) else {
        let _ = write_status(&mut stream, Status::BackendFailed).await;
        anyhow::bail!("cannot parse backend address {backend:?} as host:port");
    };

    let mut backend_stream = match connect(&host, port, connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            let _ = write_status(&mut stream, Status::BackendFailed).await;
            return Err(e);
        }
    };

    write_status(&mut stream, Status::Ok).await?;

    // The client may have written payload in the same segment as the preface. Those
    // bytes were read off the wire before the backend existed, and dropping them would
    // silently truncate the first request of every client that does this.
    if !leftover.is_empty() {
        backend_stream.write_all(&leftover).await?;
        // Same bytes the same comment above is about, and for the same reason
        // the funnel cannot count them: they were read before it existed.
        crate::metrics::METRICS.record_bytes_received(leftover.len() as u64);
    }

    // And they are the client's first bytes, so the sniffer has to see them
    // like any other: a client that pipelines the preface and its first
    // request is the normal case, not the rare one.
    sniffer.feed(Side::Client, &leftover);

    // The readers below watch what goes through them and hand the same bytes
    // on, so the flow is the same flow with or without the watching.
    let client = SniffReader::new(stream, Arc::clone(sniffer), Side::Client);
    let backend = SniffReader::new(backend_stream, Arc::clone(sniffer), Side::Backend);

    // Bounded as a whole, not only on silence: see `serve_tcp`. The deadline is
    // handed to the copy rather than wrapped around it, so the helper's own
    // half-close still runs when it fires and the client sees an EOF rather than
    // a reset.
    match copy_both_ways_until(client, backend, "L4 TCP", Some(flow_timeout)).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            // `warn`, not `debug`: this fires on a session that was working and
            // is now being cut, which is the one event in this file an operator
            // has to be able to find. `flow_timeout_secs` on the route raises it
            // — the default is meant to be generous, not invisible.
            tracing::warn!(
                "L4 TCP: closing the flow to {host}:{port} on a timeout — either the \
                 whole-flow bound ({flow_timeout:?}) expired, which flow_timeout_secs on the \
                 route raises, or the other end of the copy stopped without finishing and the \
                 copy gave up on it. The debug line says which of the two it was"
            );
        }
        // A real transport failure, which is what the other paths report too.
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// UDP: one flow is one bi-stream, one datagram is one length-prefixed frame.
///
/// `backend` only picks the peer address: a UDP socket has no handshake, so there is
/// nothing to connect to and no way to learn the backend is down. The flow ends when
/// either side goes quiet for `idle`, when it has run for `flow_timeout`, or when
/// the client closes the stream.
async fn serve_udp<S>(
    mut stream: S,
    backend: &str,
    leftover: Vec<u8>,
    idle: Duration,
    flow_timeout: Duration,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Some((host, port)) = parse_backend_addr(backend) else {
        let _ = write_status(&mut stream, Status::BackendFailed).await;
        anyhow::bail!("cannot parse backend address {backend:?} as host:port");
    };

    let target = match resolve_udp_target(&host, port).await {
        Ok(addr) => addr,
        Err(e) => {
            let _ = write_status(&mut stream, Status::BackendFailed).await;
            return Err(e);
        }
    };

    // The socket has to be bound to the target's address family, or `connect` fails on
    // every backend that is not IPv4.
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);

    // A connected UDP socket drops datagrams from anybody else, which keeps an
    // off-path attacker from injecting replies into the tunnel.
    if let Err(e) = socket.connect(target).await {
        let _ = write_status(&mut stream, Status::BackendFailed).await;
        return Err(anyhow::anyhow!(
            "failed to connect UDP socket to {target}: {e}"
        ));
    }

    write_status(&mut stream, Status::Ok).await?;

    tracing::debug!("L4 UDP: {} tunnel open (idle timeout {:?})", target, idle);

    let (mut reader, mut writer) = tokio::io::split(stream);

    // Borrowed, not moved: the send half has to survive the select below so the stream
    // can be finished rather than reset. Each block gets its own `Arc` clone.
    let socket_up = socket.clone();
    let socket_down = socket.clone();
    let mut pending = leftover;

    let client_to_backend = async {
        let mut buf = vec![0u8; 4096];
        // A cursor into `pending`, compacted once per read rather than after
        // every frame: draining moves every byte behind a frame down, so a
        // segment carrying N datagrams cost N memmoves over the whole tail.
        let mut offset = 0usize;

        loop {
            // Drain every complete frame before reading again: one segment can carry
            // several datagrams, and the bytes left over from the preface may already
            // hold one.
            loop {
                match decode_frame(&pending[offset..]) {
                    Frame::Incomplete => break,
                    Frame::Ready { payload, consumed } => {
                        // A datagram larger than a UDP payload cannot be sent
                        // to the backend either: the length prefix is a
                        // `u16`, so a frame can announce more than the
                        // protocol allows. The encoder on the other side
                        // refuses to produce one, so this is a peer that is
                        // not speaking the protocol, and the flow ends rather
                        // than the datagram going out truncated.
                        if !payload_fits_datagram(payload) {
                            tracing::debug!(
                                "L4 UDP: a frame of {} bytes is larger than a datagram, ending the flow",
                                payload.len()
                            );
                            return;
                        }
                        if let Err(e) = socket_up.send(payload).await {
                            tracing::debug!("L4 UDP: backend send failed: {}", e);
                            return;
                        }
                        // The payload, not the frame around it: the 2-byte
                        // length is this tunnel's own framing, and every other
                        // number here counts bytes an application recognises.
                        crate::metrics::METRICS.record_bytes_received(payload.len() as u64);
                        offset += consumed;
                    }
                }
            }

            if offset > 0 {
                pending.drain(..offset);
                offset = 0;
            }

            match tokio::time::timeout(idle, reader.read(&mut buf)).await {
                Ok(Ok(0)) => return,
                Ok(Ok(n)) => pending.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => {
                    tracing::debug!("L4 UDP: client read failed: {}", e);
                    return;
                }
                Err(_) => {
                    tracing::debug!("L4 UDP: no datagram from the client for {:?}", idle);
                    return;
                }
            }
        }
    };

    let backend_to_client = async {
        let mut buf = vec![0u8; 65_536];
        let mut frame = Vec::with_capacity(2048);
        loop {
            let n = match tokio::time::timeout(idle, socket_down.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    // On Windows a connected UDP socket surfaces a port-unreachable ICMP
                    // as an error here, which only means nobody is listening.
                    tracing::debug!("L4 UDP: backend recv failed: {}", e);
                    return;
                }
                Err(_) => {
                    tracing::debug!("L4 UDP: no datagram from the backend for {:?}", idle);
                    return;
                }
            };

            frame.clear();
            if let Err(e) = encode_frame(&buf[..n], &mut frame) {
                // A datagram too large for a frame. There is no way to report it
                // on a stream of datagrams, so it is dropped — but silently
                // dropping is how a 65 508 byte datagram becomes unreachable
                // with nothing in the logs to explain it.
                tracing::debug!("L4 UDP: dropped a {} byte datagram: {}", n, e);
                continue;
            }
            if let Err(e) = writer.write_all(&frame).await {
                tracing::debug!("L4 UDP: client write failed: {}", e);
                return;
            }
            if let Err(e) = writer.flush().await {
                tracing::debug!("L4 UDP: client flush failed: {}", e);
                return;
            }
            // After the flush, like the stream copy does, and counted as the
            // payload rather than the frame: a datagram that never left is not
            // bytes served, and its length prefix is not either.
            crate::metrics::METRICS.record_bytes_sent(n as u64);
        }
    };

    // The first direction to finish ends the flow: a UDP tunnel has no half-close to
    // negotiate, and keeping the other pump alive would only hold a dead socket open.
    //
    // The `idle` inside each pump above bounds the *gap* between datagrams and
    // re-arms on every one, which is right for a UDP flow — it has no protocol
    // end. It is not enough on its own: a peer that sends one datagram every
    // `idle - 1s` keeps both pumps alive indefinitely, so the flow is also
    // bounded as a whole. That is the deadline a slowloris-style peer cannot
    // renew, and without it a flow slot and a task stay pinned for as long as
    // the far side cares to send.
    let flows = async {
        tokio::select! {
            _ = client_to_backend => (),
            _ = backend_to_client => (),
        }
    };
    if tokio::time::timeout(flow_timeout, flows).await.is_err() {
        // `warn` for the same reason as the TCP path: a working session being
        // cut is an event an operator has to be able to find.
        tracing::warn!(
            "L4 UDP: closing the flow to {target} after {flow_timeout:?}, which is the \
             whole-flow bound; raise flow_timeout_secs on the route for longer sessions"
        );
    }

    // Finish the send side so the client sees a clean end of stream instead of a reset.
    let _ = writer.shutdown().await;
    Ok(())
}

/// Dials a backend within `[timeouts] connect_secs`.
///
/// One deadline for every tunnel and every passthrough, because they are the
/// same action: one TCP dial toward one backend. They used to carry three copies
/// of ten seconds, kept in step by whoever happened to look.
async fn connect(host: &str, port: u16, connect_timeout: Duration) -> anyhow::Result<TcpStream> {
    // The name is resolved through the cache, so this dial does not wait for a
    // `getaddrinfo` that the flow before it already paid for. The addresses
    // are then tried in turn, which is what `TcpStream::connect((host, port))`
    // did too.
    // One deadline for the whole thing — the resolution and every address it
    // names — so a backend with many addresses cannot multiply the budget.
    let deadline = tokio::time::Instant::now() + connect_timeout;
    let addrs = tokio::time::timeout_at(deadline, crate::dns::resolve_to(host, port))
        .await
        .map_err(|_| anyhow::anyhow!("timed out resolving backend {host}:{port}"))?
        // The resolver's own words are part of the message the log prints —
        // it prints the top-level message — and the error they came from
        // stays the source of the chain.
        .map_err(|e| {
            let message = format!("cannot resolve backend {host}:{port}: {e}");
            e.context(message)
        })?;

    connect_addrs(&addrs, deadline).await.map_err(|e| {
        let message = format!("failed to connect to backend {host}:{port}: {e}");
        e.context(message)
    })
}

/// Tries the addresses in turn, under one deadline.
///
/// The deadline is handed in rather than computed here: the resolution that
/// produced the addresses is inside the same budget, so a backend with many
/// addresses cannot multiply it.
async fn connect_addrs(
    addrs: &[SocketAddr],
    deadline: tokio::time::Instant,
) -> anyhow::Result<TcpStream> {
    let mut failure = None;
    for addr in addrs {
        match tokio::time::timeout_at(deadline, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                // A tunnel carries data with its own request/response pacing;
                // Nagle would only add latency.
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => failure = Some(anyhow::anyhow!("{addr}: {e}")),
            Err(_) => failure = Some(anyhow::anyhow!("{addr}: timed out")),
        }
    }

    Err(failure.unwrap_or_else(|| anyhow::anyhow!("there was no address to try")))
}

/// The address a UDP flow sends its datagrams to.
///
/// Resolved every time, and not through the cache. A UDP socket has no dial:
/// `connect` on it is local and cannot tell that the peer is gone, so a
/// stale address is not a failed dial — the flow would open, every datagram
/// would go to an address that is no longer there, and nothing would report
/// it. A TCP flow has the opposite property, which is why the TCP paths can
/// use the cache: a stale address is refused and the dial fails loudly.
async fn resolve_udp_target(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    crate::dns::resolve_uncached(host)
        .await
        .map_err(|e| {
            let message = format!("cannot resolve backend {host}:{port}: {e}");
            e.context(message)
        })?
        .into_iter()
        .next()
        .map(|addr| crate::dns::with_port(addr, port))
        .ok_or_else(|| anyhow::anyhow!("backend {host}:{port} resolved to no address"))
}

/// Accepts `host:port` or `scheme://host:port`.
///
/// Unlike the passthrough parser there is no fallback port: an L4 route must state
/// which port it dials, because guessing it would be a silent misconfiguration.
/// `config::validate_backend` rejects a backend that leaves the port out, so failing
/// here means the config was never validated.
fn parse_backend_addr(backend: &str) -> Option<(String, u16)> {
    let backend = backend.trim();
    if backend.is_empty() {
        return None;
    }

    if backend.contains("://") {
        let url = url::Url::parse(backend).ok()?;
        let host = url.host_str()?;
        if host.is_empty() {
            return None;
        }
        return url.port().map(|port| (host.to_string(), port));
    }

    let (host, port) = backend.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    // A configured IPv6 literal is written `[::1]:5432`; the resolver wants it bare,
    // and `Url` already hands it back that way for the `scheme://` spelling.
    let host = host.trim_matches(['[', ']']);
    port.parse().ok().map(|port| (host.to_string(), port))
}

async fn write_status<W>(writer: &mut W, status: Status) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[status.as_byte()]).await?;
    writer.flush().await
}

/// Why a preface could not be read: the peer's fault, or the stream's.
enum PrefaceFailure {
    /// The bytes arrived but are not a preface this build understands.
    Proto(ProtoError),
    /// The stream itself failed or ended before the preface was complete.
    Io(io::Error),
}

/// Reads until a complete preface has arrived, returning it with the bytes after it.
///
/// The preface may be split across segments, and a client may equally send it together
/// with its first payload; both are handled, and the payload is handed back rather than
/// dropped.
async fn read_preface<S>(
    reader: &mut S,
    mut buf: Vec<u8>,
) -> Result<(Preface, Vec<u8>), PrefaceFailure>
where
    S: AsyncRead + Unpin,
{
    // One deadline for the whole preface: a per-read timeout is restarted by
    // every byte, and a peer dribbling this out one byte at a time would hold
    // the flow open for as long as it liked.
    let deadline = tokio::time::Instant::now() + PREFACE_TIMEOUT;

    loop {
        match Preface::decode(&buf) {
            Ok(Some((preface, len))) => {
                let leftover = buf.split_off(len);
                return Ok((preface, leftover));
            }
            Ok(None) => {}
            Err(e) => return Err(PrefaceFailure::Proto(e)),
        }

        // `Preface::decode` only reports "incomplete" while fewer bytes than a maximum
        // preface have arrived, so a hostile peer that never finishes the host name
        // cannot make this loop buffer without bound.
        debug_assert!(buf.len() < MAX_PREFACE_LEN);

        if !read_more_by(reader, &mut buf, deadline)
            .await
            .map_err(PrefaceFailure::Io)?
        {
            return Err(PrefaceFailure::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended or went quiet before the L4 preface was complete",
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteMode;
    use crate::lb::LoadBalancingStrategy;
    use crate::routes::{L4Options, Route};
    use nexapipe_proto::{PREFACE_VERSION, encode_frame_to_vec};
    use std::collections::HashMap;
    use std::net::IpAddr;

    fn tcp_route(host: &str, backend: &str) -> Route {
        Route::new(
            host,
            "/",
            true,
            vec![backend.to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Tcp,
            None,
        )
    }

    fn udp_route(host: &str, backend: &str, idle: Option<Duration>) -> Route {
        Route::new(
            host,
            "/",
            true,
            vec![backend.to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Udp,
            None,
        )
        .with_l4_options(L4Options {
            client_ports: None,
            idle_timeout: idle,
            flow_timeout: None,
        })
    }

    fn config_with(tcp_backend: &str, udp_backend: &str) -> RoutingTable {
        RoutingTable::new(vec![
            tcp_route("db.test", tcp_backend),
            udp_route("turn.test", udp_backend, None),
        ])
    }

    fn limiter() -> Arc<FlowLimiter> {
        Arc::new(FlowLimiter::new(DEFAULT_MAX_FLOWS_PER_CONNECTION))
    }

    fn preface(proto: L4Proto, host: &str, port: u16) -> Vec<u8> {
        Preface::new(proto, host, port).to_bytes().unwrap()
    }

    async fn read_status<R: AsyncRead + Unpin>(reader: &mut R) -> Status {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await.expect("status byte");
        Status::from_byte(byte[0])
    }

    async fn read_udp_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
        let mut header = [0u8; 2];
        reader.read_exact(&mut header).await.expect("frame header");
        let mut body = vec![0u8; u16::from_be_bytes(header) as usize];
        reader.read_exact(&mut body).await.expect("frame body");
        body
    }

    #[tokio::test]
    async fn tcp_flow_carries_bytes_both_ways() {
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });

        let config = config_with(&backend_addr.to_string(), "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        // Preface and first payload in one write, which is what a real client does.
        let mut payload = preface(L4Proto::Tcp, "db.test", 5432);
        payload.extend_from_slice(b"ping");
        client_write.write_all(&payload).await.unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::Ok);

        let mut echoed = [0u8; 4];
        client_read.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        drop(client_write);
        drop(client_read);
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the flow should end with the client")
            .unwrap();
        assert!(outcome.is_ok());
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn a_host_without_a_route_gets_no_route() {
        // The other route's backend is deliberately unreachable: if the lookup
        // served a host it has no route for, this test would fail with
        // BackendFailed instead of NoRoute.
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "not-configured.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
        assert!(task.await.unwrap().is_ok());
    }

    /// A restricted client asking for a host its allowlist never named gets the
    /// same `NoRoute` an unconfigured host gets — a distinct status would let a
    /// compromised client probe which hosts exist behind the tunnel.
    #[tokio::test]
    async fn a_host_off_the_clients_allowlist_answers_no_route() {
        use crate::auth::ClientAcl;

        // The route exists and its backend would answer; only the ACL refuses.
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let acl = ClientAcl::from_hosts(Some(&["elsewhere.test".to_string()]));
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                Some(&acl),
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
        assert!(task.await.unwrap().is_ok());
    }

    /// A client whose port list does not name the port it asked for is refused
    /// the same way one asking for an off-list host is: `NoRoute`, not a
    /// distinct status, so the answer cannot be used to probe which ports are
    /// open behind the tunnel.
    #[tokio::test]
    async fn a_port_off_the_clients_port_list_answers_no_route() {
        use crate::auth::ClientAcl;

        // The route exists and its backend would answer; only the ACL refuses.
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                Some(&acl),
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
        assert!(task.await.unwrap().is_ok());
    }

    /// The list is held against the port the client names, and the route
    /// decides where that service is answered from: `client_ports` only
    /// selects the route, it never decides where the connection goes.
    ///
    /// So the port the client named is the service it reached, and a client
    /// whose list names that port reaches the service. The port the route
    /// answers it from is the route's own business — the list says which
    /// services the client may reach, not how the server reaches them.
    #[tokio::test]
    async fn the_port_the_client_names_is_the_port_the_list_is_held_against() {
        use crate::auth::ClientAcl;

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });

        // The route answers from the backend's own port, and the preface names
        // another one: the port asked for is never the one dialled.
        let config = config_with(&backend_addr.to_string(), "127.0.0.1:1");
        let asked = backend_addr.port().wrapping_add(1).max(1);
        // The list names the port the client asks for, and not the one the
        // route would answer it from.
        let acl = ClientAcl::from_hosts_and_ports(None, Some(&[asked]));
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                Some(&acl),
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "db.test", asked))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::Ok);
        client_write.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client_read.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        drop(client_write);
        drop(client_read);
        task.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    /// The allowlist check happens before the flow limiter too, so a client
    /// probing off-list hosts cannot spend flow slots doing it. An on-list
    /// host is unaffected and reaches its backend as usual.
    #[tokio::test]
    async fn an_allowed_host_reaches_its_backend_under_an_acl() {
        use crate::auth::ClientAcl;

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });

        let config = config_with(&backend_addr.to_string(), "127.0.0.1:1");
        let acl = ClientAcl::from_hosts(Some(&["db.test".to_string()]));
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                Some(&acl),
                "test-request-id",
                // No handshake in this test: the ACL is handed in directly.
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::Ok);
        client_write.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client_read.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        drop(client_write);
        drop(client_read);
        task.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn the_two_l4_modes_never_see_each_other() {
        // The same host name served by a `tcp` route must not answer a UDP flow: the
        // two modes are different services, not two spellings of one.
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Udp, "db.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn the_configured_udp_idle_deadline_closes_a_silent_flow() {
        // The observation this test exists for: `l4_idle_secs` has to reach the
        // flow it names, not merely parse. A key resolved into `Deadlines` and
        // then read by nobody parses, validates and does nothing — which is
        // exactly the shape this wiring arrived in, so the assertion is on the
        // flow's lifetime, not on the config's arithmetic.
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    return;
                };
                let _ = udp.send_to(&buf[..n], from).await;
            }
        });

        // One second of silence closes the flow; the sixty-second default the
        // key overrides would not, so a regression back to the constant fails
        // this on its three-second outer bound.
        let mut timeouts =
            crate::config::Timeouts::resolve(crate::config::TimeoutsConfig::default());
        timeouts.deadlines.l4_idle = Duration::from_secs(1);
        let config = RoutingTable::with_timeouts(
            vec![udp_route("turn.test", &udp_addr.to_string(), None)],
            timeouts,
        );

        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Udp, "turn.test", 3478))
            .await
            .unwrap();
        assert_eq!(read_status(&mut client_read).await, Status::Ok);

        // One round trip proves the flow works, then the client goes silent.
        client_write
            .write_all(&encode_frame_to_vec(b"ping").unwrap())
            .await
            .unwrap();
        assert_eq!(read_udp_frame(&mut client_read).await, b"ping");

        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut [0u8; 1]),
        )
        .await;
        // EOF or an error both count as closed; only a hang fails.
        assert!(
            closed.is_ok(),
            "the flow must close within the configured idle deadline"
        );
        assert!(task.await.unwrap().is_ok());
        echo.abort();
    }

    #[tokio::test]
    async fn an_unreachable_backend_answers_backend_failed() {
        // Port 1 on loopback: nothing listens there, so connect is refused immediately.
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::BackendFailed);
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_preface_from_a_newer_client_answers_bad_preface() {
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&[
                PREFACE_MAGIC,
                PREFACE_VERSION + 1,
                0x01,
                4,
                b'h',
                b'o',
                b's',
                b't',
            ])
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::BadPreface);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn udp_flow_forwards_datagrams_in_both_directions() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            for _ in 0..2 {
                let (n, from) = backend.recv_from(&mut buf).await.unwrap();
                backend.send_to(&buf[..n], from).await.unwrap();
            }
        });

        let config = config_with("127.0.0.1:1", &backend_addr.to_string());
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        // Preface and the first datagram in one write: the datagram must not be lost
        // to the handshake.
        let mut first = preface(L4Proto::Udp, "turn.test", 3478);
        first.extend_from_slice(&encode_frame_to_vec(b"one").unwrap());
        client_write.write_all(&first).await.unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::Ok);
        assert_eq!(read_udp_frame(&mut client_read).await, b"one");

        // A later datagram is framed the same way.
        client_write
            .write_all(&encode_frame_to_vec(b"two").unwrap())
            .await
            .unwrap();
        assert_eq!(read_udp_frame(&mut client_read).await, b"two");

        // Both halves have to go: with `tokio::io::split` each holds an `Arc` to the same
        // stream, so dropping only one of them signals nothing to the peer.
        drop(client_write);
        drop(client_read);
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the flow should end when the client closes")
            .unwrap();
        assert!(outcome.is_ok());
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn udp_flow_ends_when_nobody_sends_anything() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let idle = Duration::from_millis(150);
        let config = RoutingTable::new(vec![udp_route(
            "turn.test",
            &backend_addr.to_string(),
            Some(idle),
        )]);

        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        client
            .write_all(&preface(L4Proto::Udp, "turn.test", 3478))
            .await
            .unwrap();
        assert_eq!(read_status(&mut client).await, Status::Ok);

        // Neither side sends anything after that, so the idle timeout has to be what
        // ends the flow — and the client has to see a clean end of stream, not a reset.
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "the flow must end without payload");

        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the idle timeout should end the flow")
            .unwrap();
        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn a_udp_flow_ends_when_it_has_run_for_its_flow_timeout() {
        // The gap the idle bound cannot close: a peer that keeps a datagram
        // moving faster than `idle` never trips it, so without a bound on the
        // whole flow this datagram loop would hold the slot and the task forever.
        // The idle here is generous and the flow timeout is short, which is the
        // only arrangement in which the flow bound is what ends it.
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let idle = Duration::from_secs(30);
        let flow = Duration::from_millis(300);
        let config = RoutingTable::new(vec![
            Route::new(
                "turn.test",
                "/",
                true,
                vec![backend_addr.to_string()],
                LoadBalancingStrategy::RoundRobin,
                RouteMode::Udp,
                None,
            )
            .with_l4_options(L4Options {
                client_ports: None,
                idle_timeout: Some(idle),
                flow_timeout: Some(flow),
            }),
        ]);

        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        client
            .write_all(&preface(L4Proto::Udp, "turn.test", 3478))
            .await
            .unwrap();
        assert_eq!(read_status(&mut client).await, Status::Ok);

        // Keep sending well inside the idle window for longer than the flow
        // budget, so only the flow deadline can end this.
        let started = std::time::Instant::now();
        let mut kept_alive = 0;
        while started.elapsed() < Duration::from_millis(250) {
            client
                .write_all(&encode_frame_to_vec(b"tick").unwrap())
                .await
                .unwrap();
            kept_alive += 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(kept_alive > 1, "the flow really was still being renewed");

        // And it does end, on the flow budget rather than on anything else.
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
            .await
            .expect("the flow timeout should end the flow");
        assert!(read.is_ok());

        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the flow should have ended on its own")
            .unwrap();
        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn a_full_connection_answers_too_many_flows() {
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let full = Arc::new(FlowLimiter::new(0));
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &full,
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::TooManyFlows);
        assert!(task.await.unwrap().is_ok());
    }

    #[test]
    fn the_flow_limiter_refuses_past_its_ceiling_and_releases_on_drop() {
        let limiter = Arc::new(FlowLimiter::new(2));

        let first = limiter.try_acquire().expect("first flow fits");
        let second = limiter.try_acquire().expect("second flow fits");
        assert_eq!(limiter.current(), 2);
        assert!(
            limiter.try_acquire().is_none(),
            "the third flow must be refused"
        );

        drop(first);
        assert_eq!(limiter.current(), 1);
        let third = limiter.try_acquire().expect("the freed slot is reusable");
        assert_eq!(limiter.max(), 2);
        drop(second);
        drop(third);
        assert_eq!(limiter.current(), 0);
    }

    #[test]
    fn only_the_preface_magic_is_an_l4_stream() {
        assert!(is_l4_stream(PREFACE_MAGIC));
        assert!(!is_l4_stream(0x16));
        assert!(!is_l4_stream(b'G'));
    }

    #[test]
    fn backend_addresses_need_a_port() {
        assert_eq!(
            parse_backend_addr("10.0.0.50:5432"),
            Some(("10.0.0.50".to_string(), 5432))
        );
        assert_eq!(
            parse_backend_addr("tcp://db.internal:5432"),
            Some(("db.internal".to_string(), 5432))
        );
        assert_eq!(
            parse_backend_addr("udp://turn.internal:3478"),
            Some(("turn.internal".to_string(), 3478))
        );
        // No fallback port: an L4 target that does not say which port to dial is a
        // configuration mistake, not something to guess at.
        assert_eq!(parse_backend_addr("db.internal"), None);
        assert_eq!(parse_backend_addr("http://db.internal"), None);
        assert_eq!(parse_backend_addr(":5432"), None);
        assert_eq!(parse_backend_addr(""), None);
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
        let stream = connect_addrs(
            &[refused, accepting],
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("the second address should have been tried");

        assert_eq!(
            stream.peer_addr().unwrap(),
            accepting,
            "the dial should have ended on the address that accepted"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the second address is inside the same deadline, not a new one, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn every_address_is_tried_under_one_deadline() {
        // The deadline has passed: every attempt is over before it starts, so
        // the dial gives up at once instead of waiting once per address.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let accepting = listener.local_addr().unwrap();

        let started = std::time::Instant::now();
        let error = connect_addrs(
            &[accepting, accepting, accepting],
            tokio::time::Instant::now() - Duration::from_secs(1),
        )
        .await
        .expect_err("the deadline has passed");

        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a spent deadline must not be waited for once per address, took {:?}",
            started.elapsed()
        );
        assert!(
            error.to_string().contains("timed out"),
            "the error should say the attempt ran out of time, got {error}"
        );
    }

    #[tokio::test]
    async fn a_dial_to_an_address_that_refuses_says_which_one() {
        let refused = refusing_addr().await;

        let error = connect_addrs(
            &[refused],
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect_err("nothing is listening on that port");

        assert!(
            error.to_string().contains(&refused.to_string()),
            "the error should name the address that failed, got {error}"
        );
    }

    /// A resolver the test can steer.
    ///
    /// A name it knows is answered from the table; anything else is the
    /// system's business, so a test that has it installed cannot disturb the
    /// tests that run beside it.
    struct StubResolver {
        answers: std::sync::Mutex<HashMap<String, Vec<IpAddr>>>,
    }

    impl StubResolver {
        fn new() -> Self {
            Self {
                answers: std::sync::Mutex::new(HashMap::new()),
            }
        }

        /// Changes what the name resolves to, the way a DNS record moves.
        fn set(&self, host: &str, addrs: Vec<IpAddr>) {
            self.answers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(host.to_string(), addrs);
        }
    }

    impl crate::dns::Resolve for StubResolver {
        fn resolve(&self, host: &str) -> Result<Vec<SocketAddr>, crate::dns::ResolveError> {
            let known = self
                .answers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(host)
                .cloned();
            match known {
                Some(addrs) => Ok(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect()),
                // Everything else is the system's business.
                None => crate::dns::SystemResolver.resolve(host),
            }
        }
    }

    /// A UDP flow does not use an address the cache is holding.
    ///
    /// The cache is for the paths that dial: a TCP dial to an address that
    /// has gone away is refused, and the flow fails with it. A UDP flow has
    /// **no dial** — `connect` on a UDP socket is local, so it cannot tell
    /// that the peer is gone — and a datagram sent to an address that is no
    /// longer there is dropped without a word. So a UDP flow resolves its
    /// target every time it opens, and the address the cache is holding is
    /// not the one it uses.
    #[tokio::test]
    async fn a_udp_flow_does_not_use_a_stale_address() {
        // The backend that answers: a UDP echo on the loopback.
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, from) = backend.recv_from(&mut buf).await.unwrap();
            backend.send_to(&buf[..n], from).await.unwrap();
        });

        // The name resolves to an address where nobody is listening, and to
        // the backend after that: the address the cache is holding is one
        // the flow must not use.
        let stub = Arc::new(StubResolver::new());
        stub.set("udp.test", vec![IpAddr::from([127, 0, 0, 2])]);
        let _resolver = crate::dns::swap_resolver(stub.clone());

        // The cache is given the address nobody is listening on, the way a
        // flow that resolved the name a moment ago would have left it.
        let cached = crate::dns::resolve("udp.test")
            .await
            .expect("the name resolves");
        assert_eq!(
            cached,
            vec![SocketAddr::new(IpAddr::from([127, 0, 0, 2]), 0)]
        );

        // And now the name resolves to the backend.
        stub.set("udp.test", vec![IpAddr::from([127, 0, 0, 1])]);

        let backend = format!("udp.test:{}", backend_addr.port());
        let config = RoutingTable::new(vec![udp_route("udp.test", &backend, None)]);
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(
                server,
                Vec::new(),
                &config,
                &limiter(),
                "test",
                None,
                "test-request-id",
                None,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        let mut first = preface(L4Proto::Udp, "udp.test", 3478);
        first.extend_from_slice(&encode_frame_to_vec(b"one").unwrap());
        client_write.write_all(&first).await.unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::Ok);
        // The datagram has to come back from the backend. Before the fix the
        // flow was pointed at the address the cache was holding, so nothing
        // came back and the flow ended instead.
        let echoed = tokio::time::timeout(Duration::from_secs(5), read_udp_frame(&mut client_read))
            .await
            .expect("the echo should come back");
        assert_eq!(echoed, b"one");

        drop(client_write);
        drop(client_read);
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the flow should end when the client closes")
            .unwrap();
        assert!(outcome.is_ok());
        echo.await.unwrap();
    }
}
