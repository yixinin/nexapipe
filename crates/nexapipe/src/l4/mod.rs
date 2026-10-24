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
use crate::conn::limits::{ByteBudget, ByteReservation};
use crate::conn::peers::PeerIdentity;
use crate::l4::sniff::{FlowSniffer, Side, SniffReader};
use crate::metrics;
use crate::routes::{BackendLookup, RoutingTable};
use crate::stream_util::{DuplexIroh, copy_both_ways_until, read_more_by};
use nexapipe_proto::{
    FRAME_HEADER_LEN, Frame, L4Proto, MAX_PREFACE_LEN, MAX_UDP_PAYLOAD, PREFACE_MAGIC, Preface,
    ProtoError, Status, decode_frame, encode_frame, payload_fits_datagram,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

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

/// The buffer a UDP flow receives a datagram into.
///
/// A datagram over IPv4 carries at most [`MAX_UDP_PAYLOAD`] bytes, and the buffer
/// has to hold one of them whole.
const UDP_RECV_BUFFER_BYTES: usize = 64 * 1024;

/// The buffer a UDP flow reads the client's bytes into.
const UDP_SEND_BUFFER_BYTES: usize = 4 * 1024;

/// The buffer a UDP flow frames a datagram in, at its largest.
///
/// A length prefix and a payload a datagram can carry. The buffer is allocated
/// at this size rather than grown into it, so that what the flow holds is what
/// the reservation pays for.
const UDP_FRAME_BUFFER_BYTES: usize = FRAME_HEADER_LEN + MAX_UDP_PAYLOAD;

/// The frame in flight: the bytes of a datagram that has not arrived whole yet.
///
/// The length prefix, the largest payload the prefix can announce, and one
/// read's worth of overshoot — a read can carry the end of a frame and the
/// beginning of the next one, and the frame in flight has to have room for
/// both.
const UDP_PENDING_BUFFER_BYTES: usize =
    FRAME_HEADER_LEN + u16::MAX as usize + UDP_SEND_BUFFER_BYTES;

/// What one UDP flow holds, and what the process is charged for it.
///
/// Four buffers, one flow each, and none of them small. The TCP path charges
/// its copy buffers to the same budget — the ceiling in
/// `[limits] max_body_bytes` says the per-stream copy buffers are charged
/// there too — so this one does too: a peer that opened many UDP flows paid
/// for them in memory the operator's ceiling never knew about, which made the
/// ceiling they configured not the ceiling they got.
///
/// Taken before the first of the four is allocated, so a flow that cannot pay
/// does not run at all.
const UDP_FLOW_BUFFER_BYTES: usize = UDP_RECV_BUFFER_BYTES
    + UDP_SEND_BUFFER_BYTES
    + UDP_FRAME_BUFFER_BYTES
    + UDP_PENDING_BUFFER_BYTES;

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
            serve_udp(
                stream,
                &route.backend,
                leftover,
                idle,
                flow_timeout,
                crate::conn::limits::body_budget(),
            )
            .await
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

    let mut backend_stream = match crate::backend_conn::connect(&host, port, connect_timeout).await
    {
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
    budget: &Arc<ByteBudget>,
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
    let bind_addr = udp_bind_addr(&target);

    serve_udp_flow(
        stream,
        target,
        &bind_addr,
        leftover,
        idle,
        flow_timeout,
        budget,
    )
    .await
}

/// The address a UDP flow's socket is bound to.
///
/// The wildcard address of the target's family, and nothing else: the socket
/// is a client socket, so it binds to a port the kernel picks and sends from
/// wherever it happens to be.
fn udp_bind_addr(target: &SocketAddr) -> String {
    if target.is_ipv4() {
        "0.0.0.0:0".to_string()
    } else {
        "[::]:0".to_string()
    }
}

/// The flow itself, once the target and the address to bind it to are known.
///
/// The bind address is a parameter rather than derived here, because the bind
/// is the one step of the flow that can fail for reasons of its own — a host
/// with IPv6 disabled, an exhausted descriptor table — and a step that cannot
/// be reached cannot be tested.
async fn serve_udp_flow<S>(
    mut stream: S,
    target: SocketAddr,
    bind_addr: &str,
    leftover: Vec<u8>,
    idle: Duration,
    flow_timeout: Duration,
    budget: &Arc<ByteBudget>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // The buffers this flow holds are paid for before the first of them
    // exists. A flow that cannot afford them does not run: the budget exists
    // to refuse, not to warn, and a flow refused here never takes a socket
    // either.
    //
    // Held in a named binding rather than dropped at once: a `_` would give
    // the bytes back while the buffers they pay for are still alive.
    let _reservation = match ByteReservation::take_buffers(budget, UDP_FLOW_BUFFER_BYTES) {
        Ok(reservation) => reservation,
        Err(e) => {
            let _ = write_status(&mut stream, Status::BackendFailed).await;
            return Err(e);
        }
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
    // The frame in flight, in a buffer of the size the reservation pays for.
    // Allocated once rather than grown into: a frame is decoded and drained
    // as soon as it is complete, so what is left between two reads is at most
    // one incomplete frame, and the buffer never has to grow past that.
    let mut pending = Vec::with_capacity(UDP_PENDING_BUFFER_BYTES);
    pending.extend_from_slice(&leftover);

    let client_to_backend = async {
        let mut buf = vec![0u8; UDP_SEND_BUFFER_BYTES];
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
                Ok(Ok(n)) => {
                    // The buffer the frame in flight is held in is paid for by
                    // the reservation, and it has room for one frame and the
                    // read that completes it. A client that sends more than
                    // that without the frame ever being complete is not
                    // speaking the protocol.
                    if pending.len() + n > UDP_PENDING_BUFFER_BYTES {
                        tracing::debug!(
                            "L4 UDP: the client sent more than a frame without completing it"
                        );
                        return;
                    }
                    pending.extend_from_slice(&buf[..n]);
                }
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
        let mut buf = vec![0u8; UDP_RECV_BUFFER_BYTES];
        let mut frame = Vec::with_capacity(UDP_FRAME_BUFFER_BYTES);
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
///
/// The same parser the passthrough uses reads it, with the other reading of
/// what a backend without a port means — see
/// [`crate::backend_conn::PortDefault`].
fn parse_backend_addr(backend: &str) -> Option<(String, u16)> {
    crate::backend_conn::parse_backend_addr(backend, crate::backend_conn::PortDefault::Required)
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
mod tests;

#[cfg(test)]
mod flow_tests {
    use super::*;
    use crate::config::RouteMode;
    use crate::lb::LoadBalancingStrategy;
    use crate::routes::Route;

    /// What one UDP flow holds: the buffer a datagram is received into, the
    /// one the client's bytes are read into, the one a datagram is framed in,
    /// and the frame in flight a client dribbling a maximal frame makes the
    /// process hold.
    ///
    /// Written out here rather than read from the code, so that the test pins
    /// the figure instead of agreeing with whatever the code happens to say.
    const FLOW_BUFFER_BYTES: usize = 65_536 + 4_096 + 65_509 + 69_633;

    fn udp_route(host: &str, backend: &str) -> Route {
        Route::new(
            host,
            "/",
            true,
            vec![backend.to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Udp,
            None,
        )
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

    /// A UDP flow is charged to the process byte budget.
    ///
    /// The TCP path charges its copy buffers to the same budget — the ceiling
    /// in `[limits] max_body_bytes` says the per-stream copy buffers are
    /// charged there too — so a UDP flow that holds a 64 KiB receive buffer
    /// per flow and is charged nothing is a flow whose memory the operator's
    /// ceiling never sees.
    #[tokio::test]
    async fn a_udp_flow_is_charged_to_the_process_byte_budget() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = backend.recv_from(&mut buf).await else {
                    return;
                };
                let _ = backend.send_to(&buf[..n], from).await;
            }
        });

        let config = RoutingTable::new(vec![udp_route("turn.test", &backend_addr.to_string())]);
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

        // The flow is open, so the process is holding its buffers right now.
        // The budget is the process's, so another test in this binary may be
        // holding bytes of its own: what is asserted is that the flow's own
        // charge is there, not an exact figure.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while crate::conn::limits::body_budget().held() < FLOW_BUFFER_BYTES {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the UDP flow holds {FLOW_BUFFER_BYTES} bytes of buffers and the process byte \
                 budget does not see one of them"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        drop(client_write);
        drop(client_read);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        echo.abort();
    }

    /// The charge is exact, and the bytes are given back when the flow ends.
    ///
    /// A budget of its own rather than the process's, so that the figure can
    /// be asserted exactly: the process's is shared with every other flow in
    /// this binary.
    #[tokio::test]
    async fn a_udp_flow_pays_for_its_buffers_and_gives_them_back() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = backend.recv_from(&mut buf).await else {
                    return;
                };
                let _ = backend.send_to(&buf[..n], from).await;
            }
        });

        let budget = Arc::new(ByteBudget::new(FLOW_BUFFER_BYTES));
        let flow_budget = budget.clone();
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_udp_flow(
                server,
                backend_addr,
                "0.0.0.0:0",
                Vec::new(),
                Duration::from_secs(30),
                Duration::from_secs(60),
                &flow_budget,
            )
            .await
        });

        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).await.unwrap();
        assert_eq!(Status::from_byte(byte[0]), Status::Ok);

        // The flow is open, so the buffers exist and the budget is holding
        // them.
        assert_eq!(
            budget.held(),
            FLOW_BUFFER_BYTES,
            "the flow is not charged for the buffers it holds"
        );

        // The client closes, the flow ends, and the bytes come back.
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert_eq!(
            budget.held(),
            0,
            "the bytes of a flow that ended are still charged"
        );
        echo.abort();
    }

    /// A flow that cannot pay for its buffers is refused, and refused with a
    /// status the client can act on.
    ///
    /// The budget exists to refuse, not to warn: a flow that ran anyway would
    /// hold memory the operator's ceiling says the process may not hold.
    #[tokio::test]
    async fn a_udp_flow_that_cannot_pay_for_its_buffers_is_refused() {
        // One byte short of what the flow holds.
        let budget = Arc::new(ByteBudget::new(FLOW_BUFFER_BYTES - 1));
        let flow_budget = budget.clone();
        let (mut client, server) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            serve_udp_flow(
                server,
                "127.0.0.1:9".parse().unwrap(),
                "0.0.0.0:0",
                Vec::new(),
                Duration::from_secs(30),
                Duration::from_secs(60),
                &flow_budget,
            )
            .await
        });

        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).await.unwrap();
        assert_eq!(
            Status::from_byte(byte[0]),
            Status::BackendFailed,
            "a flow that cannot pay is not answered with a status the client can act on"
        );
        assert!(
            task.await.unwrap().is_err(),
            "a refused flow reports success"
        );
        assert_eq!(budget.held(), 0, "a refused flow holds bytes");
    }
}
