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
//! actually dialled** ([`RouteConfig::get_l4_backend`]). A client holding 2FA
//! credentials therefore cannot use the server as an open relay. A host with no
//! `mode = "tcp"` / `mode = "udp"` route gets [`Status::NoRoute`] and the stream ends:
//! there is no fallback to `default_backend`, because that is how a mistyped domain
//! ends up quietly talking to an unrelated service.
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

use crate::routes::RouteConfig;
use crate::stream_util::{DuplexIroh, copy_both_ways, read_more};
use nexapipe_proto::{
    Frame, L4Proto, MAX_PREFACE_LEN, PREFACE_MAGIC, Preface, ProtoError, Status, decode_frame,
    encode_frame,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// How long a client may take to spell out a complete preface.
const PREFACE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a backend connection may take to establish.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a UDP flow may sit idle before it is torn down, unless the route sets
/// `idle_timeout_secs`. Kept well above a typical DNS or database keep-alive interval.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
pub async fn handle_iroh_stream(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    initial: Vec<u8>,
    config: &RouteConfig,
    limiter: &Arc<FlowLimiter>,
    peer: &str,
) -> anyhow::Result<()> {
    serve_stream(DuplexIroh::new(send, recv), initial, config, limiter, peer).await
}

/// The protocol itself, over any duplex stream.
///
/// Generic on purpose: `tokio::io::duplex` gives a test both ends in one process, so
/// the handshake, the status codes and the UDP framing are covered without an iroh
/// endpoint — the same reason `passthrough` is written this way.
pub async fn serve_stream<S>(
    stream: S,
    initial: Vec<u8>,
    config: &RouteConfig,
    limiter: &Arc<FlowLimiter>,
    peer: &str,
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

    let mode = crate::config::RouteMode::from_l4_proto(preface.proto);
    let started = std::time::Instant::now();
    let target = format!("{}:{}", preface.host, preface.port);

    let Some(route) = config
        .get_l4_backend(&preface.host, preface.port, mode)
        .await
    else {
        let _ = write_status(&mut stream, Status::NoRoute).await;
        tracing::warn!(
            "L4 {}: no `mode = {:?}` route for {}, closing",
            preface.proto.name(),
            mode,
            target
        );
        crate::log::log_access(peer, preface.proto.name(), &target, 404, 0, 0);
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
        crate::log::log_access(peer, preface.proto.name(), &target, 429, 0, 0);
        return Ok(());
    };

    tracing::info!(
        "L4 {}: {} -> backend {} ({})",
        preface.proto.name(),
        target,
        route.backend,
        peer
    );

    let result = match preface.proto {
        L4Proto::Tcp => serve_tcp(stream, &route.backend, leftover).await,
        L4Proto::Udp => {
            let idle = route.idle_timeout.unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT);
            serve_udp(stream, &route.backend, leftover, idle).await
        }
    };

    match &result {
        Ok(()) => crate::log::log_access(
            peer,
            preface.proto.name(),
            &target,
            200,
            started.elapsed().as_millis() as u64,
            0,
        ),
        Err(e) => {
            tracing::debug!("L4 {} {} ended: {}", preface.proto.name(), target, e);
            crate::log::log_access(
                peer,
                preface.proto.name(),
                &target,
                502,
                started.elapsed().as_millis() as u64,
                0,
            );
        }
    }

    result
}

/// TCP: dial the backend, hand the client its status byte, then copy raw bytes.
async fn serve_tcp<S>(mut stream: S, backend: &str, leftover: Vec<u8>) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Some((host, port)) = parse_backend_addr(backend) else {
        let _ = write_status(&mut stream, Status::BackendFailed).await;
        anyhow::bail!("cannot parse backend address {backend:?} as host:port");
    };

    let mut backend_stream = match connect(&host, port).await {
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
    }

    copy_both_ways(stream, backend_stream, "L4 TCP").await?;
    Ok(())
}

/// UDP: one flow is one bi-stream, one datagram is one length-prefixed frame.
///
/// `backend` only picks the peer address: a UDP socket has no handshake, so there is
/// nothing to connect to and no way to learn the backend is down. The flow ends when
/// either side goes quiet for `idle`, or when the client closes the stream.
async fn serve_udp<S>(
    mut stream: S,
    backend: &str,
    leftover: Vec<u8>,
    idle: Duration,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Some((host, port)) = parse_backend_addr(backend) else {
        let _ = write_status(&mut stream, Status::BackendFailed).await;
        anyhow::bail!("cannot parse backend address {backend:?} as host:port");
    };

    let target = match resolve(&host, port).await {
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
        loop {
            // Drain every complete frame before reading again: one segment can carry
            // several datagrams, and the bytes left over from the preface may already
            // hold one.
            loop {
                match decode_frame(&pending) {
                    Frame::Incomplete => break,
                    Frame::Ready { payload, consumed } => {
                        if let Err(e) = socket_up.send(payload).await {
                            tracing::debug!("L4 UDP: backend send failed: {}", e);
                            return;
                        }
                        pending.drain(..consumed);
                    }
                }
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
            if encode_frame(&buf[..n], &mut frame).is_err() {
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
        }
    };

    // The first direction to finish ends the flow: a UDP tunnel has no half-close to
    // negotiate, and keeping the other pump alive would only hold a dead socket open.
    tokio::select! {
        _ = client_to_backend => (),
        _ = backend_to_client => (),
    }

    // Finish the send side so the client sees a clean end of stream instead of a reset.
    let _ = writer.shutdown().await;
    Ok(())
}

async fn connect(host: &str, port: u16) -> anyhow::Result<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("timed out connecting to backend {host}:{port}"))?
        .map_err(|e| anyhow::anyhow!("failed to connect to backend {host}:{port}: {e}"))?;

    // A tunnel carries data with its own request/response pacing; Nagle would only add
    // latency.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn resolve(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("cannot resolve backend {host}:{port}: {e}"))?
        .next()
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

        if !read_more(reader, &mut buf, PREFACE_TIMEOUT)
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
        })
    }

    fn config_with(tcp_backend: &str, udp_backend: &str) -> RouteConfig {
        RouteConfig::new(
            vec![
                tcp_route("db.test", tcp_backend),
                udp_route("turn.test", udp_backend, None),
            ],
            Some("http://default:80".to_string()),
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
        let task =
            tokio::spawn(
                async move { serve_stream(server, Vec::new(), &config, &limiter(), "test").await },
            );

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
    async fn a_host_without_a_route_gets_no_route_and_never_the_default_backend() {
        // The default backend is deliberately unreachable: if the lookup fell back to
        // it, this test would fail with BackendFailed instead of NoRoute.
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task =
            tokio::spawn(
                async move { serve_stream(server, Vec::new(), &config, &limiter(), "test").await },
            );

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "not-configured.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn the_two_l4_modes_never_see_each_other() {
        // The same host name served by a `tcp` route must not answer a UDP flow: the
        // two modes are different services, not two spellings of one.
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task =
            tokio::spawn(
                async move { serve_stream(server, Vec::new(), &config, &limiter(), "test").await },
            );

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Udp, "db.test", 5432))
            .await
            .unwrap();

        assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn an_unreachable_backend_answers_backend_failed() {
        // Port 1 on loopback: nothing listens there, so connect is refused immediately.
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task =
            tokio::spawn(
                async move { serve_stream(server, Vec::new(), &config, &limiter(), "test").await },
            );

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
            .await
            .unwrap();

        assert_eq!(
            read_status(&mut client_read).await,
            Status::BackendFailed
        );
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_preface_from_a_newer_client_answers_bad_preface() {
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let (client, server) = tokio::io::duplex(4096);
        let task =
            tokio::spawn(
                async move { serve_stream(server, Vec::new(), &config, &limiter(), "test").await },
            );

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
        let task =
            tokio::spawn(
                async move { serve_stream(server, Vec::new(), &config, &limiter(), "test").await },
            );

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
        let config = RouteConfig::new(
            vec![udp_route("turn.test", &backend_addr.to_string(), Some(idle))],
            Some("http://default:80".to_string()),
        );

        let (mut client, server) = tokio::io::duplex(4096);
        let task =
            tokio::spawn(
                async move { serve_stream(server, Vec::new(), &config, &limiter(), "test").await },
            );

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
    async fn a_full_connection_answers_too_many_flows() {
        let config = config_with("127.0.0.1:1", "127.0.0.1:1");
        let full = Arc::new(FlowLimiter::new(0));
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_stream(server, Vec::new(), &config, &full, "test").await
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
}
