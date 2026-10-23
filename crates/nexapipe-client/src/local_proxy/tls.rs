//! A TLS session, carried through the tunnel as bytes.
//!
//! The tunnel does not read it and does not end it: the bytes go to the peer
//! and come back, and the session is the client's and the peer's.

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::ClientError;
use crate::endpoint_group::EndpointGroup;
use crate::flow::{FlowKind, FlowMeta};
use crate::traffic::FlowCounter;

use iroh::endpoint::{RecvStream, SendStream};
use nexapipe_proto::protocol::Protocol;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use super::STREAM_BUF_SIZE;
use super::should_proxy_domain;
use super::tunnel::open_stream_with_retry;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// What a read of the `ClientHello` gave.
enum HelloRead {
    /// More bytes arrived.
    More,
    /// The stream ended.
    Ended,
    /// The read failed.
    Failed,
    /// The deadline passed.
    TimedOut,
}

/// Reads more of the `ClientHello`.
///
/// The deadline is the hello's, and it covers the whole hello rather than
/// each read: a peer that dribbles a byte at a time must not hold the
/// connection open by renewing the deadline on every read.
async fn read_more_of_the_hello<S>(
    stream: &mut S,
    data: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> HelloRead
where
    S: AsyncRead + Unpin,
{
    let mut extra = [0u8; 4096];
    match tokio::time::timeout_at(deadline, stream.read(&mut extra)).await {
        Ok(Ok(0)) => HelloRead::Ended,
        Ok(Ok(n)) => {
            data.extend_from_slice(&extra[..n]);
            HelloRead::More
        }
        Ok(Err(_)) => HelloRead::Failed,
        Err(_) => {
            jni_log!(
                "[DEBUG:local-proxy] TLS ClientHello took longer than its deadline, \
                 closing connection"
            );
            HelloRead::TimedOut
        }
    }
}

/// How long the tunnel waits for the other direction after one of them ends.
///
/// A half-close is a request, not an ending: the peer that shut down its write
/// side is done sending, and the answer that follows still has to arrive. So
/// the tunnel does not end when the first direction does — it ends when the
/// second one does.
///
/// The bound is what keeps an abandoned tunnel from holding its slot. A peer
/// that vanished is indistinguishable from one that half-closed — both arrive
/// as a clean end of stream — and without a bound the tunnel would wait for an
/// answer that is never coming, holding a stream slot and a backend connection
/// for as long as the whole-flow deadline allows.
///
/// Thirty seconds is the same order nginx uses for the same problem
/// (`lingering_time`), and it is the bound the server's own TLS passthrough
/// gives the direction that outlives the first.
const LINGERING: Duration = Duration::from_secs(30);

/// How long the tunnel may be silent, in both directions at once, before it ends.
///
/// The window is over **both** directions: a quiet direction does not end a
/// tunnel the other one is still using. A client that only listens to a stream
/// the backend keeps pushing has nothing to say, and the gap in its direction
/// must not end the session — what counts is whether anything moved at all.
///
/// The value is the crate's own budget for an established session
/// ([`crate::deadline::Deadlines::stream`]): long by design, because silence
/// is normal in a TLS session, and there so that a copy loop cannot hold its
/// resources for the life of the process rather than to shape traffic.
fn idle_window() -> Duration {
    crate::deadline::Deadlines::default().stream
}

/// The iroh stream pair, seen as one duplex stream.
///
/// The copy below is written over byte streams rather than over the tunnel's
/// own types, so the same shape can be driven over an in-memory pair under
/// test. The server has the same wrapper in `stream_util::DuplexIroh`.
struct BackendStream {
    send: SendStream,
    recv: RecvStream,
}

impl BackendStream {
    /// The pair, as one duplex stream.
    fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for BackendStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for BackendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The iroh send stream's shutdown is its FIN: the peer reads an end
        // of stream rather than a reset.
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

/// Which way the bytes of one direction travel.
#[derive(Clone, Copy)]
enum Leg {
    /// From the client into the tunnel.
    ClientToIroh,
    /// From the tunnel back to the client.
    IrohToClient,
}

impl Leg {
    /// The direction, in the words the log uses.
    fn label(self) -> &'static str {
        match self {
            Leg::ClientToIroh => "client->iroh",
            Leg::IrohToClient => "iroh->client",
        }
    }

    /// Counts the bytes that crossed this direction.
    ///
    /// The two directions land in one total, and each in the counter that
    /// says which way its bytes went.
    fn record(self, counter: &FlowCounter, bytes: u64) {
        match self {
            Leg::ClientToIroh => counter.record_sent(bytes),
            Leg::IrohToClient => counter.record_received(bytes),
        }
    }
}

/// How one direction of the tunnel ended.
#[derive(Clone, Copy)]
enum DirectionEnd {
    /// The peer's write side closed: a half-close, or a peer that vanished —
    /// the two arrive the same way, and the tunnel cannot tell them apart.
    Finished,
    /// The transport failed on the way in.
    ReadFailed,
    /// The transport failed on the way out.
    WriteFailed,
    /// Nothing moved in either direction for a whole idle window.
    Idle,
}

impl DirectionEnd {
    /// The reason, in the words the log uses.
    ///
    /// The two directions fail on different peers, so the reason names the
    /// peer that failed rather than the direction.
    fn reason(self, leg: Leg) -> &'static str {
        match (self, leg) {
            (DirectionEnd::Finished, Leg::ClientToIroh) => "client_finished",
            (DirectionEnd::Finished, Leg::IrohToClient) => "backend_finished",
            (DirectionEnd::ReadFailed, Leg::ClientToIroh) => "client_read_error",
            (DirectionEnd::ReadFailed, Leg::IrohToClient) => "backend_read_error",
            (DirectionEnd::WriteFailed, Leg::ClientToIroh) => "backend_write_error",
            (DirectionEnd::WriteFailed, Leg::IrohToClient) => "client_write_error",
            (DirectionEnd::Idle, _) => "idle",
        }
    }
}

/// Milliseconds since the tunnel started.
fn now_millis(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// The tunnel's own clock.
///
/// The three facts it holds belong to the tunnel rather than to one of its
/// directions: when the tunnel started, when something last moved, and how
/// long the tunnel may be silent. Both directions read the same clock, and
/// that is what makes the idle window a window over the two of them together.
struct TunnelClock {
    /// When the tunnel started.
    start: Instant,
    /// When something last moved, in milliseconds since the tunnel started.
    last_traffic: AtomicU64,
    /// How long the tunnel may be silent, in both directions at once.
    idle: Duration,
}

impl TunnelClock {
    /// The clock of a tunnel that starts now.
    fn new(idle: Duration) -> Self {
        Self {
            start: Instant::now(),
            last_traffic: AtomicU64::new(0),
            idle,
        }
    }

    /// The milliseconds since the tunnel started.
    fn now(&self) -> u64 {
        now_millis(self.start)
    }

    /// Records that something moved.
    fn touch(&self) {
        self.last_traffic.store(self.now(), Ordering::Relaxed);
    }

    /// Whether nothing has moved for a whole idle window.
    ///
    /// The window is measured over both directions, so a direction that is
    /// quiet on its own is not the end of anything.
    fn is_idle(&self) -> bool {
        let quiet_for = self
            .now()
            .saturating_sub(self.last_traffic.load(Ordering::Relaxed));
        quiet_for >= self.idle.as_millis() as u64
    }
}

/// Copies one direction of the tunnel until it ends.
///
/// The direction ends when the peer stops sending, when the transport fails,
/// or when nothing has moved in either direction for a whole idle window.
async fn copy_one_way<R, W>(
    reader: &mut R,
    writer: &mut W,
    buf: &mut Vec<u8>,
    counter: &FlowCounter,
    clock: &TunnelClock,
    leg: Leg,
) -> DirectionEnd
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        // The read is bound by the idle window, and the window is measured
        // over both directions: a direction that is quiet on its own is not
        // the end of anything.
        let n = match tokio::time::timeout(clock.idle, reader.read(buf.as_mut_slice())).await {
            Ok(Ok(0)) => return DirectionEnd::Finished,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                jni_log!(
                    "[DEBUG:local-proxy] TLS tunnel {} read error: {}",
                    leg.label(),
                    e
                );
                return DirectionEnd::ReadFailed;
            }
            Err(_) => {
                // This direction has been quiet for a whole window. The
                // tunnel ends when nothing has moved in either direction for
                // that long; until then the other side is still using it.
                if clock.is_idle() {
                    return DirectionEnd::Idle;
                }
                // The other side is still talking: wait for more, with the
                // window measured from now.
                continue;
            }
        };

        clock.touch();
        if let Err(e) = writer.write_all(&buf[..n]).await {
            jni_log!(
                "[DEBUG:local-proxy] TLS tunnel {} write error: {}",
                leg.label(),
                e
            );
            return DirectionEnd::WriteFailed;
        }
        leg.record(counter, n as u64);
    }
}

/// The tunnel's two directions, over byte streams.
///
/// The two directions are **joined**, not raced. Racing them meant that
/// whichever ended first won and the other was dropped: a client that shut
/// its write side down never saw the backend's last bytes, because the
/// direction carrying them was killed a microsecond after the half-close.
///
/// Each direction shuts the peer's write side down as it ends, so the peer
/// sees a clean end of stream rather than a reset.
async fn forward_tunnel<C, B, F>(
    client: C,
    backend: B,
    mut client_buf: Vec<u8>,
    count_to_backend: FlowCounter,
    count_from_backend: FlowCounter,
    idle: Duration,
    cancelled: F,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = ()>,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);

    // The tunnel's clock: when it started, when something last moved, and how
    // long it may be silent. Both directions write to it, and a direction that
    // has been quiet for a whole window reads it to find out whether the
    // other one is still talking.
    let clock = TunnelClock::new(idle);

    // The two directions, and the half-close that goes with each of them.
    //
    // A half-close is a **request**, not an ending: the peer that shut down
    // its write side is done sending, and the other side has to hear that, or
    // it waits for input that is never coming. So the FIN is sent as soon as
    // the direction ends — not when the whole tunnel does.
    let client_to_iroh = async {
        let end = copy_one_way(
            &mut client_read,
            &mut backend_write,
            &mut client_buf,
            &count_to_backend,
            &clock,
            Leg::ClientToIroh,
        )
        .await;
        // The client is done sending. The tunnel has to hear that, so the
        // far side reads an end of stream rather than a dropped connection.
        let _ = backend_write.shutdown().await;
        end
    };

    let iroh_to_client = async {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        let end = copy_one_way(
            &mut backend_read,
            &mut client_write,
            &mut buf,
            &count_from_backend,
            &clock,
            Leg::IrohToClient,
        )
        .await;
        // The backend is done sending. The client has to hear that: the write
        // side towards the client is shut down, so the client sees an end of
        // stream the way it would see it from a socket.
        let _ = client_write.shutdown().await;
        end
    };

    // The first direction to end starts the clock on the second one.
    //
    // This is what makes the wait bounded. The tunnel ends when both
    // directions have ended, but a direction that never ends — the one whose
    // peer vanished rather than half-closed — is only given `LINGERING` to
    // finish before the tunnel gives up on it.
    let (ended_tx, mut ended_rx) = tokio::sync::mpsc::unbounded_channel::<DirectionEnd>();
    let client_to_iroh = {
        let ended_tx = ended_tx.clone();
        async move {
            let end = client_to_iroh.await;
            let _ = ended_tx.send(end);
            end
        }
    };
    let iroh_to_client = {
        let ended_tx = ended_tx.clone();
        async move {
            let end = iroh_to_client.await;
            let _ = ended_tx.send(end);
            end
        }
    };
    drop(ended_tx);

    // Both directions have to be waited for. A `select!` over them would drop
    // the one that lost the race, and the bytes it was carrying would be lost
    // with it.
    let copying = async { tokio::join!(client_to_iroh, iroh_to_client) };

    tokio::select! {
        (client_end, backend_end) = copying => {
            jni_log!(
                "[DEBUG:local-proxy] TLS tunnel: both directions ended (client to iroh {}, iroh to client {})",
                client_end.reason(Leg::ClientToIroh),
                backend_end.reason(Leg::IrohToClient)
            );
        }
        // One direction ended on its own.
        //
        // A **failure** ends the tunnel at once: the transport is broken and
        // there is nothing to wait for. A **clean end** is a half-close — or a
        // peer that vanished, which arrives the same way — and the other
        // direction may still be delivering, so it is given `LINGERING` to
        // finish before the tunnel gives up on it.
        first = async {
            match ended_rx.recv().await {
                Some(DirectionEnd::ReadFailed) | Some(DirectionEnd::WriteFailed) => {
                    "a direction failed"
                }
                _ => {
                    tokio::time::sleep(LINGERING).await;
                    "the other direction did not finish in time"
                }
            }
        } => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: {}", first);
        }
        _ = cancelled => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: the flow was cancelled");
        }
    }

    // Both write halves, whatever happened: the tunnel is over either way.
    let _ = backend_write.shutdown().await;
    let _ = client_write.shutdown().await;
}

/// Handle a raw TLS tunnel connection via SNI extraction.
///
/// When a client connects to the VPN's virtual proxy IP on port 443, it sends
/// a TLS ClientHello directly (since it doesn't know there's an HTTP proxy in
/// between). This function extracts the SNI hostname from the ClientHello,
/// establishes an iroh tunnel to the appropriate backend, and forwards raw TCP
/// data bidirectionally — no HTTP parsing involved.
pub(crate) async fn handle_tls_tunnel<S>(
    mut stream: S,
    initial_data: Vec<u8>,
    // The buffer the ClientHello was read into, handed over rather than
    // allocated again: a connection holds two 32 KiB buffers — one per
    // direction of the copy loop — rather than three.
    header_buf: Vec<u8>,
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
    // Where the bytes came from; see `handle_local_connection`.
    peer: Option<String>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    jni_log!("[DEBUG:local-proxy] TLS tunnel mode");

    // Ensure we have enough data for the full TLS record (ClientHello)
    // Record header is 5 bytes: content_type(1) + version(2) + length(2)
    //
    // Bounded as a whole rather than per read: the record length is known once
    // the header is in, so this loop's job is to fetch a known number of bytes,
    // and a client that sends the five header bytes and then one byte of record
    // every few seconds would otherwise hold the connection open indefinitely —
    // this read had no bound at all before.
    let mut data = initial_data;
    let hello_deadline =
        tokio::time::Instant::now() + crate::deadline::Deadlines::default().tls_hello;

    // **The record's head first.**
    //
    // The record's length is in its first five bytes, so a hello that has
    // not arrived that far yet cannot be measured — and a first read of one
    // to four bytes used to end the reading there, because the loop that
    // reads the rest was inside the check. The truncated hello was then
    // parsed as if it were the whole one, which is a hello with no name in
    // it, and the session was closed with no retry.
    while data.len() < 5 {
        match read_more_of_the_hello(&mut stream, &mut data, hello_deadline).await {
            HelloRead::More => {}
            HelloRead::Ended | HelloRead::Failed => break,
            HelloRead::TimedOut => return Ok(()),
        }
    }

    if data.len() >= 5 {
        let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
        let total_needed = 5 + record_len;
        while data.len() < total_needed {
            match read_more_of_the_hello(&mut stream, &mut data, hello_deadline).await {
                HelloRead::More => {}
                HelloRead::Ended | HelloRead::Failed => break,
                HelloRead::TimedOut => return Ok(()),
            }
        }
    }

    // Extract SNI from TLS ClientHello
    let sni = match nexapipe_proto::tls::extract_sni(&data) {
        Some(sni) => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: extracted SNI '{}'", sni);
            sni
        }
        None => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: could not extract SNI from ClientHello");
            return Ok(());
        }
    };

    if !should_proxy_domain(&sni, &proxy_domains) {
        jni_log!(
            "[DEBUG:local-proxy] TLS tunnel: SNI '{}' not in proxy domains, closing",
            sni
        );
        return Ok(());
    }

    jni_log!(
        "[DEBUG:local-proxy] TLS tunnel: establishing iroh tunnel for '{}'",
        sni
    );

    // Open a fresh iroh bi-stream and forward the initial TLS ClientHello. If
    // the pooled connection is stale, open_bi / write fails and we retry on a
    // fresh connection.
    jni_log!(
        "[DEBUG:local-proxy] TLS tunnel: forwarding initial {} bytes",
        data.len()
    );
    let (pooled_conn, send, recv) =
        open_stream_with_retry(&endpoint_group, &sni, Some(&data), Protocol::Tls).await?;

    // Same accounting as the HTTP path: the helper already wrote the
    // ClientHello it was handed.
    let flow = pooled_conn.enter_flow(FlowMeta {
        kind: FlowKind::TlsPassthrough,
        target: Some(sni.clone()),
        source: peer.clone(),
    });
    flow.record_sent(data.len() as u64);
    let count_to_backend = flow.counter();
    let count_from_backend = flow.counter();

    // The copy is written over byte streams, so the iroh pair is presented as
    // one duplex stream and the client's socket as another. That is also what
    // makes the shape under test the shape in production.
    let backend = BackendStream::new(send, recv);

    jni_log!("[DEBUG:local-proxy] TLS tunnel: bidirectional forwarding started");
    forward_tunnel(
        stream,
        backend,
        header_buf,
        count_to_backend,
        count_from_backend,
        idle_window(),
        flow.cancelled(),
    )
    .await;

    jni_log!("[DEBUG:local-proxy] TLS tunnel closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// A stream that remembers whether its write half was shut down.
    ///
    /// A FIN and a dropped connection look the same to the reader over an
    /// in-memory pair — both arrive as an end of stream — so the only way to
    /// tell them apart here is to watch the write half.
    struct Probe<T> {
        inner: T,
        shut_down: Arc<AtomicBool>,
    }

    impl<T> Probe<T> {
        /// The stream, and the flag that says whether it was shut down.
        fn new(inner: T) -> (Self, Arc<AtomicBool>) {
            let shut_down = Arc::new(AtomicBool::new(false));
            (
                Self {
                    inner,
                    shut_down: shut_down.clone(),
                },
                shut_down,
            )
        }
    }

    impl<T: AsyncRead + Unpin> AsyncRead for Probe<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncRead::poll_read(Pin::new(&mut self.get_mut().inner), cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for Probe<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            AsyncWrite::poll_write(Pin::new(&mut self.get_mut().inner), cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().inner), cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.as_mut().get_mut();
            this.shut_down.store(true, Ordering::Relaxed);
            AsyncWrite::poll_shutdown(Pin::new(&mut this.inner), cx)
        }
    }

    /// The counters a tunnel records its bytes through.
    fn counters() -> (FlowCounter, FlowCounter) {
        let traffic = Arc::new(crate::traffic::NodeTraffic::new());
        let flow = crate::traffic::Flow::open(traffic);
        let counter = flow.counter();
        (counter.clone(), counter)
    }

    /// A half-closed client still receives the backend's last bytes.
    ///
    /// A half-close is a request, not an ending: the client is done sending,
    /// and the backend's answer still has to arrive. The backend here reads
    /// until the client is done and only then answers, which is the shape of
    /// a protocol carried over a connection the client may half-close.
    ///
    /// The two directions used to be raced, so the one carrying the answer
    /// was dropped the moment the half-close was seen, and the answer never
    /// arrived. Nothing shut a write half down either, so the backend saw
    /// the connection disappear rather than a clean end of stream.
    #[tokio::test]
    async fn a_half_closed_client_still_receives_the_backend_last_bytes() {
        let (mut client_end, client_side) = tokio::io::duplex(1024);
        let (mut backend_end, backend_side) = tokio::io::duplex(1024);
        let (backend_side, backend_fin) = Probe::new(backend_side);

        let (to_backend, from_backend) = counters();
        let tunnel = tokio::spawn(forward_tunnel(
            client_side,
            backend_side,
            vec![0u8; STREAM_BUF_SIZE],
            to_backend,
            from_backend,
            Duration::from_millis(500),
            std::future::pending::<()>(),
        ));

        // The client: sends its request, then shuts its write side down.
        let application = async {
            client_end
                .write_all(b"the request")
                .await
                .expect("the request goes out");
            client_end.shutdown().await.expect("the write side closes");
            let mut answer = Vec::new();
            client_end
                .read_to_end(&mut answer)
                .await
                .expect("the answer arrives");
            answer
        };

        // The backend: reads until the client is done, then answers. The end
        // of the stream it sees has to be a clean one — a reset would mean
        // the tunnel tore the connection down instead of closing it.
        let backend = async {
            let mut request = Vec::new();
            backend_end
                .read_to_end(&mut request)
                .await
                .expect("the request arrives, and the end of the stream with it");
            assert_eq!(
                request, b"the request",
                "the backend did not see the request"
            );
            // The backend may still answer after the client's half-close —
            // that is what a half-close is.
            backend_end
                .write_all(b"the answer")
                .await
                .expect("the answer goes out after the client's half-close");
            backend_end.shutdown().await.expect("the backend closes");
        };

        let (answer, ()) = tokio::join!(application, backend);
        assert_eq!(
            answer, b"the answer",
            "the answer did not survive the half-close"
        );
        assert!(
            backend_fin.load(Ordering::Relaxed),
            "the backend did not see a FIN: the tunnel dropped the connection instead"
        );

        let ended = tokio::time::timeout(Duration::from_secs(5), tunnel).await;
        assert!(ended.is_ok(), "the tunnel never ended");
    }

    /// The backend's bytes are not lost when the client half-closes first.
    ///
    /// The client shuts its write side down before it has said anything, and
    /// the backend answers afterwards. Those bytes have to reach the client:
    /// they are the answer to a session the client is still reading.
    #[tokio::test]
    async fn the_backend_bytes_are_not_lost_when_the_client_half_closes_first() {
        let (mut client_end, client_side) = tokio::io::duplex(1024);
        let (mut backend_end, backend_side) = tokio::io::duplex(1024);
        let (backend_side, backend_fin) = Probe::new(backend_side);

        let (to_backend, from_backend) = counters();
        let tunnel = tokio::spawn(forward_tunnel(
            client_side,
            backend_side,
            vec![0u8; STREAM_BUF_SIZE],
            to_backend,
            from_backend,
            Duration::from_millis(500),
            std::future::pending::<()>(),
        ));

        // The client: half-closes straight away, then reads.
        let application = async {
            client_end.shutdown().await.expect("the write side closes");
            let mut answer = Vec::new();
            client_end
                .read_to_end(&mut answer)
                .await
                .expect("the answer arrives");
            answer
        };

        // The backend: waits for the end of the stream, then answers.
        let backend = async {
            let mut request = Vec::new();
            backend_end
                .read_to_end(&mut request)
                .await
                .expect("the end of the stream arrives");
            assert!(request.is_empty(), "the client had said nothing");
            backend_end
                .write_all(b"the answer")
                .await
                .expect("the answer goes out after the half-close");
            backend_end.shutdown().await.expect("the backend closes");
        };

        let (answer, ()) = tokio::join!(application, backend);
        assert_eq!(
            answer, b"the answer",
            "the answer was lost at the half-close"
        );
        assert!(
            backend_fin.load(Ordering::Relaxed),
            "the backend did not see a FIN: the tunnel dropped the connection instead"
        );

        let ended = tokio::time::timeout(Duration::from_secs(5), tunnel).await;
        assert!(ended.is_ok(), "the tunnel never ended");
    }

    /// A tunnel nobody is using ends on its own.
    ///
    /// The idle window is what ends it: nothing has moved in either direction
    /// for a whole window, so there is nothing left to wait for.
    #[tokio::test]
    async fn a_tunnel_nobody_uses_ends_on_its_own() {
        let (_client_end, client_side) = tokio::io::duplex(1024);
        let (_backend_end, backend_side) = tokio::io::duplex(1024);

        let (to_backend, from_backend) = counters();
        let tunnel = tokio::spawn(forward_tunnel(
            client_side,
            backend_side,
            vec![0u8; STREAM_BUF_SIZE],
            to_backend,
            from_backend,
            Duration::from_millis(100),
            std::future::pending::<()>(),
        ));

        let ended = tokio::time::timeout(Duration::from_secs(5), tunnel).await;
        assert!(ended.is_ok(), "the tunnel never ended");
    }

    /// A quiet direction does not end a tunnel the other one is still using.
    ///
    /// A client that only listens to a stream the backend keeps pushing has
    /// nothing to say, and the gap in its direction must not end the tunnel:
    /// the idle window is measured over both directions, so what counts is
    /// whether anything moved at all.
    #[tokio::test]
    async fn a_quiet_direction_does_not_end_a_tunnel_the_other_one_is_using() {
        let (_client_end, client_side) = tokio::io::duplex(1024);
        let (mut backend_end, backend_side) = tokio::io::duplex(1024);

        let (to_backend, from_backend) = counters();
        let tunnel = tokio::spawn(forward_tunnel(
            client_side,
            backend_side,
            vec![0u8; STREAM_BUF_SIZE],
            to_backend,
            from_backend,
            Duration::from_millis(200),
            std::future::pending::<()>(),
        ));

        // The backend keeps pushing; the client says nothing at all.
        let push = tokio::spawn(async move {
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                backend_end
                    .write_all(b"ping")
                    .await
                    .expect("the backend pushes");
            }
            // And then it stops, so the tunnel can end on its idle window.
            backend_end.shutdown().await.expect("the backend closes");
        });

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !tunnel.is_finished(),
            "a quiet client ended a tunnel the backend was still using"
        );

        let ended = tokio::time::timeout(Duration::from_secs(5), tunnel).await;
        assert!(ended.is_ok(), "the tunnel never ended");
        push.await.expect("the backend finished");
    }
}
