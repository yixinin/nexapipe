//! Byte-stream plumbing shared by the two paths that move opaque bytes.
//!
//! TLS passthrough and the L4 tunnel both end up doing the same two things: presenting
//! an iroh bi-stream as one duplex object, and copying bytes both ways until one side
//! stops. They differ only in what they do *before* that point — SNI sniffing versus
//! preface decoding — so that part stays in each module.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::conn::limits::{ByteBudget, ByteReservation};
use crate::metrics::CopyLeg;

/// Read size for the copy loops. Large enough that a 1400-byte inner segment never
/// needs two syscalls, small enough to stay off the allocator's slow path.
pub const COPY_BUF_SIZE: usize = 16 * 1024;

/// What one copied stream costs the byte budget: one buffer per direction.
///
/// The two directions are two buffers, so a stream costs twice this. It is
/// charged to the budget when the copy starts and given back as each direction
/// ends — see [`copy_both_ways_until_with_budget`].
pub const COPY_BUFFER_BYTES: usize = 2 * COPY_BUF_SIZE;

/// How long the copy waits for the other direction after one of them ends.
///
/// A half-close is a request, not an ending: the peer that shut down its write
/// side is done sending, and the reply that follows still has to arrive. So
/// the copy does not end when the first direction does — it ends when the
/// second one does.
///
/// The bound is what keeps an abandoned connection from holding its slot. A
/// peer that vanished is indistinguishable from one that half-closed — both
/// arrive as a clean end of stream — and without a bound the copy would wait
/// for a reply that is never coming, holding a stream slot and a backend
/// connection for as long as the whole-flow deadline allows.
///
/// Thirty seconds is the same order nginx uses for the same problem
/// (`lingering_time`), and long enough for a backend that is thinking about
/// its answer.
const LINGERING: Duration = Duration::from_secs(30);

/// How one direction of a copy ended.
enum DirectionEnd {
    /// The peer's write side closed. A half-close, or a peer that vanished —
    /// the two arrive the same way, and the copy cannot tell them apart.
    Clean,
    /// The transport failed. The kind is carried along, so the caller can
    /// still tell a timeout from a broken connection.
    Failed(io::ErrorKind, String),
}

/// An iroh bi-stream seen as one duplex stream, so it can be piped like a socket.
///
/// The iroh streams also carry inherent `poll_*` methods with their own error type,
/// which win method resolution; the trait paths below are written out in full so the
/// tokio ones are the ones called.
pub struct DuplexIroh {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

impl DuplexIroh {
    pub fn new(send: iroh::endpoint::SendStream, recv: iroh::endpoint::RecvStream) -> Self {
        DuplexIroh { send, recv }
    }
}

impl AsyncRead for DuplexIroh {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for DuplexIroh {
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
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

/// The reservations one copied stream holds.
///
/// One per direction, because the two directions are two buffers. Each is
/// given back as soon as its own direction ends rather than when the whole
/// copy does: a direction that ends early does not keep its buffer's bytes
/// charged against the process.
struct CopyBuffers {
    client_to_backend: ByteReservation,
    backend_to_client: ByteReservation,
}

impl CopyBuffers {
    /// Takes the reservations for both directions, or refuses the stream.
    ///
    /// **Refused rather than waited for**, and the reason is the one the
    /// stream ceiling gives: a copy that waits for room is a task held open on
    /// a stream slot, which is exactly what the process-wide ceilings exist to
    /// prevent. A stream that cannot pay for its buffers does not run.
    ///
    /// Both are taken before either direction starts, so a stream that cannot
    /// pay for both is refused before a single byte is read.
    fn take(budget: &Arc<ByteBudget>) -> anyhow::Result<Self> {
        // The first reservation is given back if the second does not fit: it
        // is dropped on the way out, which is what the guard is for.
        let client_to_backend = ByteReservation::take_buffers(budget, COPY_BUF_SIZE)?;
        let backend_to_client = ByteReservation::take_buffers(budget, COPY_BUF_SIZE)?;
        Ok(Self {
            client_to_backend,
            backend_to_client,
        })
    }
}

/// Copies bytes in both directions until **both** of them have ended.
///
/// A half-close is a request, not an ending: a peer that shut its write side
/// down is done sending, and the reply that follows still has to arrive. So the
/// copy ends when the second direction ends, not when the first one does — and
/// each direction shuts its own write side down as it finishes, so the peer
/// sees a clean EOF instead of a dropped connection.
///
/// That wait is bounded. A peer that vanished and a peer that half-closed
/// arrive the same way, as a clean end of stream, so once one direction has
/// ended the other is given `LINGERING` to finish before the copy gives up on
/// it.
///
/// The result is `Ok` when both directions ended cleanly. A transport failure
/// is reported as it happened — there is nothing left to wait for once the
/// connection is broken. A copy that gave up on the direction which outlived
/// the first one comes back as `TimedOut`, and a deadline that expires comes
/// back the same way, so the caller can tell "this one was cut" from "this one
/// broke"; either way the half-closes have already run.
///
/// `label` only ever reaches a debug log — it exists so an operator can tell the TLS
/// path from the L4 path when both are in play.
pub async fn copy_both_ways<A, B>(client: A, backend: B, label: &str) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_both_ways_until(client, backend, label, None).await
}

/// [`copy_both_ways`], with a whole-copy deadline.
///
/// The deadline is a third `select!` arm rather than a `timeout` wrapped around the
/// call: wrapping drops this future at expiry, which skips the two `shutdown()` calls
/// below — and those are the ones that turn a finished tunnel into a clean EOF instead
/// of a reset. As an arm it loses the race like any other direction and falls through
/// to the same shutdowns.
pub async fn copy_both_ways_until<A, B>(
    client: A,
    backend: B,
    label: &str,
    deadline: Option<std::time::Duration>,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_both_ways_until_with_budget(
        crate::conn::limits::body_budget(),
        client,
        backend,
        label,
        deadline,
    )
    .await
}

/// [`copy_both_ways_until`], charging the copy buffers to a named budget.
///
/// **The buffers are charged to the byte budget**, because they are the one
/// per-stream allocation the budget did not see. Every direction of every
/// copied stream holds a buffer, and a peer that opened many streams paid for
/// them in memory the operator's ceiling never knew about: the ceiling they
/// configured was not the ceiling they got. So the reservation is taken when
/// the buffers are taken and given back as each direction ends.
///
/// **A stream that cannot pay for its buffers is refused**, before a byte is
/// read and before the backend sees anything. The budget exists to refuse,
/// not to warn. The stream closes cleanly rather than being left half-read:
/// both write halves are shut down, so the peer sees an end of stream rather
/// than a reset, and nothing is left holding a connection.
///
/// The budget is a parameter so a test can have one of its own: the shared
/// one is the process's, and a test that disturbs it disturbs every other
/// test in the process.
pub async fn copy_both_ways_until_with_budget<A, B>(
    budget: &Arc<ByteBudget>,
    client: A,
    backend: B,
    label: &str,
    deadline: Option<std::time::Duration>,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);

    // The buffers are paid for before a byte moves. A stream that cannot
    // afford them does not run at all: there is no half-read stream to
    // clean up, and the peer is told by a clean end of stream.
    let buffers = match CopyBuffers::take(budget) {
        Ok(buffers) => buffers,
        Err(e) => {
            tracing::warn!("{label}: {e}");
            // Both write halves, whatever happened: the peer sees a clean end
            // of stream rather than a reset, and the backend is not left
            // holding a connection nobody will write to.
            let _ = backend_write.shutdown().await;
            let _ = client_write.shutdown().await;
            return Err(io::Error::other(e.to_string()));
        }
    };
    let CopyBuffers {
        client_to_backend: to_backend,
        backend_to_client: to_client,
    } = buffers;

    // Each direction, and the half-close that goes with it.
    //
    // A half-close is a **request**, not an ending: a peer that shut down its
    // write side is done sending, and the other side has to hear that, or it
    // waits for input that is never coming. So the FIN is sent as soon as the
    // direction ends — not when the whole copy does.
    //
    // The two directions are **joined**, not raced. Racing them meant that
    // whichever ended first won and the other was dropped, so a client that
    // wrote its request and then shut down its write side never got the
    // reply: the direction carrying it was killed a microsecond after the
    // half-close, and the connection was reset under the client.
    //
    // The halves are borrowed, not moved, because the shutdown written inside
    // each direction has to run when that direction ends. Shutting them down
    // out here instead would mean waiting for the other direction first,
    // which is the deadlock this arrangement exists to avoid.
    let client_to_backend = async {
        let result = copy_one_way(
            &mut client_read,
            &mut backend_write,
            label,
            CopyLeg::Client,
            to_backend,
        )
        .await;
        // The client is done sending. The backend has to hear that.
        let _ = backend_write.shutdown().await;
        result
    };
    let backend_to_client = async {
        let result = copy_one_way(
            &mut backend_read,
            &mut client_write,
            label,
            CopyLeg::Backend,
            to_client,
        )
        .await;
        // The backend is done sending. The client has to hear that.
        let _ = client_write.shutdown().await;
        result
    };

    // The first direction to end starts the clock on the second one.
    //
    // This is what makes the wait bounded. The copy ends when both directions
    // have ended, but a direction that never ends — the one whose peer
    // vanished rather than half-closed — is only given `LINGERING` to finish
    // before the copy gives up on it. A peer that vanished and a peer that
    // half-closed arrive the same way, and this is what tells them apart.
    //
    // The shorter of the two bounds wins: a copy with a deadline of its own
    // does not wait longer than that after the first direction ended.
    let lingering = match deadline {
        Some(limit) => limit.min(LINGERING),
        None => LINGERING,
    };
    let (ended_tx, mut ended_rx) = tokio::sync::mpsc::unbounded_channel::<DirectionEnd>();
    let client_to_backend = {
        let ended_tx = ended_tx.clone();
        async move {
            let result = client_to_backend.await;
            let end = match &result {
                Ok(()) => DirectionEnd::Clean,
                Err(e) => DirectionEnd::Failed(e.kind(), e.to_string()),
            };
            let _ = ended_tx.send(end);
            result
        }
    };
    let backend_to_client = {
        let ended_tx = ended_tx.clone();
        async move {
            let result = backend_to_client.await;
            let end = match &result {
                Ok(()) => DirectionEnd::Clean,
                Err(e) => DirectionEnd::Failed(e.kind(), e.to_string()),
            };
            let _ = ended_tx.send(end);
            result
        }
    };
    drop(ended_tx);

    let finished = tokio::select! {
        (client_result, backend_result) = async {
            tokio::join!(client_to_backend, backend_to_client)
        } => {
            // The first failure, in the order the two were joined. A clean
            // end in either direction is not a failure: the other one may
            // still be delivering, and it will say so when it is done.
            client_result.and(backend_result)
        }
        // One direction ended on its own.
        //
        // A **failure** ends the copy at once: the transport is broken, and
        // there is nothing to wait for. A **clean end** is a half-close — or
        // a peer that vanished, which arrives the same way — and the other
        // direction may still be delivering, so it is given `lingering` to
        // finish before the copy gives up on it.
        ended = async {
            match ended_rx.recv().await {
                Some(DirectionEnd::Failed(kind, message)) => Err(io::Error::new(kind, message)),
                _ => {
                    tokio::time::sleep(lingering).await;
                    tracing::debug!(
                        "{}: the other direction did not finish within {:?} of the first one ending",
                        label,
                        lingering
                    );
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the other direction did not finish in time",
                    ))
                }
            }
        } => ended,
        // `Some` when a deadline was given, and `pending` forever when it was not:
        // a disabled arm that can still win the race is how this becomes a bug
        // rather than a no-op.
        _ = async {
            match deadline {
                Some(limit) => tokio::time::sleep(limit).await,
                None => std::future::pending().await,
            }
        } => {
            tracing::debug!("{}: copy ended on its deadline", label);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the copy ended on its deadline",
            ))
        }
    };

    // Both write halves, whatever happened: the copy is over either way.
    let _ = backend_write.shutdown().await;
    let _ = client_write.shutdown().await;

    finished
}

/// Copies until `reader` ends. Returns `Ok` on a clean EOF, and the error otherwise.
///
/// `leg` says which way these bytes are going, and therefore which counter they
/// belong in. It replaces the direction string this used to take: the label in
/// the debug lines below and the answer "was this accepted or served" are one
/// fact, and two parameters carrying it could disagree.
///
/// `reservation` pays for the buffer below, and is given back when this
/// direction ends — the same moment the buffer is freed. It is taken once,
/// outside the loop, so the copy itself does not touch the budget.
async fn copy_one_way<R, W>(
    reader: &mut R,
    writer: &mut W,
    label: &str,
    leg: CopyLeg,
    reservation: ByteReservation,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Held in a named binding rather than dropped at once: a `_` would give
    // the bytes back before the buffer they pay for existed.
    let _reservation = reservation;
    let direction = leg.label();
    let mut buf = vec![0u8; COPY_BUF_SIZE];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) => {
                tracing::debug!("{}: {} read failed: {}", label, direction, e);
                return Err(e);
            }
        };

        writer.write_all(&buf[..n]).await.map_err(|e| {
            tracing::debug!("{}: {} write failed: {}", label, direction, e);
            e
        })?;
        // An iroh send stream buffers, so without this the last bytes of a reply can
        // sit in the buffer until the tunnel is torn down. On a TcpStream it is a no-op.
        writer.flush().await.map_err(|e| {
            tracing::debug!("{}: {} flush failed: {}", label, direction, e);
            e
        })?;
        // Counted last, after both have succeeded: a chunk that never left this
        // process was not served to anybody, and reporting it would put bytes
        // in the total that no client ever received.
        crate::metrics::METRICS.record_tunnel_bytes(leg, n as u64);
    }
}

/// Appends one chunk to `buf`; `false` on EOF, timeout or read error.
///
/// A peer that goes quiet is not an error here: the caller decides whether the bytes
/// received so far are enough (SNI parsing) or not (a preface that must be complete).
pub async fn read_more<R>(reader: &mut R, buf: &mut Vec<u8>, timeout: Duration) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    match tokio::time::timeout(timeout, reader.read(&mut chunk)).await {
        Ok(Ok(0)) => Ok(false),
        Ok(Ok(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(false),
    }
}

/// The same, bounded by a deadline for the whole read rather than by one idle
/// gap between chunks.
///
/// A peer that sends a byte just inside the timeout restarts a per-read one
/// every time, which kept a stream slot — and the buffer behind it — alive for
/// as long as it cared to keep dribbling. Anything that waits on a peer to
/// finish saying something wants this one, not [`read_more`].
pub async fn read_more_by<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    match tokio::time::timeout_at(deadline, reader.read(&mut chunk)).await {
        Ok(Ok(0)) => Ok(false),
        Ok(Ok(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Two in-memory pipes: `copy_both_ways` gets one end of each, and the test
    /// plays the client and the backend from the other ends.
    fn pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (client_end, client_side) = duplex(1024);
        let (backend_end, backend_side) = duplex(1024);
        (client_end, backend_end, client_side, backend_side)
    }

    #[tokio::test]
    async fn copies_bytes_in_both_directions() {
        let (mut client_end, mut backend_end, client_side, backend_side) = pair();
        let copy = tokio::spawn(copy_both_ways(client_side, backend_side, "test"));

        client_end.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        backend_end.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        backend_end.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        client_end.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        drop(client_end);
        drop(backend_end);
        copy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn half_closes_the_backend_when_the_client_stops() {
        let (mut client_end, mut backend_end, client_side, backend_side) = pair();
        // Bounded: the copy now waits for the other direction, and here it is
        // the backend that never finishes.
        let copy = tokio::spawn(copy_both_ways_until(
            client_side,
            backend_side,
            "test",
            Some(Duration::from_millis(500)),
        ));

        client_end.write_all(b"hello").await.unwrap();
        drop(client_end);

        // The client's end of stream has to reach the backend as one: everything
        // it sent, then a clean EOF rather than a dropped connection.
        let mut seen = Vec::new();
        backend_end.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"hello");

        // The copy gives up on the silent side rather than waiting for it.
        let returned = tokio::time::timeout(Duration::from_secs(5), copy).await;
        assert!(returned.is_ok(), "the copy never returned");
    }

    /// A half-close reaches the other side, and the reply that follows it
    /// still arrives.
    ///
    /// A TCP half-close is a **request**, not an ending: the peer that shut
    /// down its write side is done sending, and the reply still has to come
    /// back. The two directions used to be raced, so the one carrying the
    /// reply was dropped a microsecond after the half-close, and the
    /// connection was reset under the client.
    ///
    /// This is the shape of a request/response protocol carried over a
    /// connection the client may half-close: the server reads until the
    /// client is done sending, and only then answers.
    #[tokio::test]
    async fn a_half_closed_client_still_receives_the_reply() {
        let (mut client_end, mut backend_end, client_side, backend_side) = pair();

        // The application: writes its request, then half-closes, then reads
        // whatever comes back.
        let application = async {
            client_end
                .write_all(b"the request")
                .await
                .expect("the request goes out");
            client_end.shutdown().await.expect("the write side closes");
            let mut buf = Vec::new();
            client_end
                .read_to_end(&mut buf)
                .await
                .expect("the reply arrives");
            buf
        };

        // The backend: reads until the client is done, then answers.
        let backend = async {
            let mut buf = Vec::new();
            backend_end
                .read_to_end(&mut buf)
                .await
                .expect("the request arrives");
            assert_eq!(buf, b"the request", "the backend did not see the request");
            backend_end
                .write_all(b"the reply")
                .await
                .expect("the reply goes out");
            backend_end.shutdown().await.expect("the backend closes");
        };

        let (copied, (), received) = tokio::join!(
            copy_both_ways_until(client_side, backend_side, "test", None),
            backend,
            application,
        );

        copied.expect("the copy ends cleanly");
        assert_eq!(
            received, b"the reply",
            "the reply did not survive the half-close"
        );
    }

    /// A stream that fails the first read and swallows everything written to it.
    ///
    /// `duplex` cannot produce this: dropping the far end is a clean EOF, and a
    /// transport failure is the case the return value has to tell apart.
    struct Broken;

    impl AsyncRead for Broken {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("broken transport")))
        }
    }

    impl AsyncWrite for Broken {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_client_that_fails_mid_flow_is_reported_as_an_error() {
        let (_backend_end, backend_side) = duplex(1024);
        let result = copy_both_ways(Broken, backend_side, "test").await;
        assert!(
            result.is_err(),
            "a broken transport is not a clean end of stream"
        );
    }

    #[tokio::test]
    async fn a_backend_that_fails_mid_flow_is_reported_as_an_error() {
        let (_client_end, client_side) = duplex(1024);
        let result = copy_both_ways(client_side, Broken, "test").await;
        assert!(
            result.is_err(),
            "a broken transport is not a clean end of stream"
        );
    }

    #[tokio::test]
    async fn half_closes_the_client_when_the_backend_stops() {
        let (mut client_end, mut backend_end, client_side, backend_side) = pair();
        // Bounded: the copy waits for the other direction, and here it is the
        // client that never finishes. A peer that vanished is indistinguishable
        // from one that half-closed, so the bound is what tells them apart.
        let copy = tokio::spawn(copy_both_ways_until(
            client_side,
            backend_side,
            "test",
            Some(Duration::from_millis(500)),
        ));
        backend_end.write_all(b"bye").await.unwrap();
        drop(backend_end);

        let mut seen = Vec::new();
        client_end.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"bye");

        // The copy gives up on the silent side rather than waiting for it.
        let returned = tokio::time::timeout(Duration::from_secs(5), copy).await;
        assert!(returned.is_ok(), "the copy never returned");
    }

    #[tokio::test]
    async fn returns_when_the_far_end_disappears() {
        let (mut client_end, _backend_end, client_side, backend_side) = pair();
        // Bounded: the copy waits for the other direction, and a peer that
        // vanished is indistinguishable from one that half-closed. The
        // deadline is what tells the two apart.
        let copy = tokio::spawn(copy_both_ways_until(
            client_side,
            backend_side,
            "test",
            Some(Duration::from_millis(500)),
        ));

        // The backend is gone mid-flow. What matters is that the copy comes
        // back: a tunnel that keeps a task (and its stream) alive after the far
        // end vanished would leak one per abandoned connection.
        drop(_backend_end);
        let returned = tokio::time::timeout(Duration::from_secs(5), copy).await;
        assert!(returned.is_ok(), "copy_both_ways_until never returned");

        let mut rest = Vec::new();
        let _ = client_end.read_to_end(&mut rest).await;
    }

    /// Which counter each direction lands in.
    ///
    /// Asserted as "at least", not "exactly": these are the process-wide
    /// counters, another test in this binary — an L4 tunnel, say — can be
    /// moving them at the same time. Both legs have to have moved by what this
    /// transfer put through them, and neither may move into the other's
    /// direction, which is the part worth locking down.
    #[tokio::test]
    async fn each_direction_is_counted_on_the_leg_it_crossed() {
        use crate::metrics::METRICS;

        let before = METRICS.snapshot();
        let (mut client_end, mut backend_end, client_side, backend_side) = pair();
        let copy = tokio::spawn(copy_both_ways(client_side, backend_side, "test"));

        client_end.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        backend_end.read_exact(&mut buf).await.unwrap();

        backend_end.write_all(b"pong ").await.unwrap();
        let mut buf = [0u8; 5];
        client_end.read_exact(&mut buf).await.unwrap();

        drop(client_end);
        drop(backend_end);
        copy.await.unwrap().unwrap();

        let after = METRICS.snapshot();
        assert!(
            after.bytes_received - before.bytes_received >= 4,
            "bytes from the client belong in received"
        );
        assert!(
            after.bytes_sent - before.bytes_sent >= 5,
            "bytes from the backend belong in sent"
        );
    }

    #[tokio::test]
    async fn read_more_appends_the_chunk_it_read() {
        let (mut writer, mut reader) = duplex(1024);
        writer.write_all(b"abc").await.unwrap();

        let mut buf = Vec::new();
        let more = read_more(&mut reader, &mut buf, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(more);
        assert_eq!(buf, b"abc");
    }

    #[tokio::test]
    async fn read_more_reports_eof() {
        let (writer, mut reader) = duplex(1024);
        drop(writer);

        let mut buf = Vec::new();
        let more = read_more(&mut reader, &mut buf, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!more);
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn read_more_reports_a_silent_peer_as_false() {
        let (_writer, mut reader) = duplex(1024);

        // Nothing is ever written, so this is the timeout path: a peer that goes
        // quiet is not an error, the caller decides whether what arrived so far
        // is enough.
        let mut buf = Vec::new();
        let more = read_more(&mut reader, &mut buf, Duration::from_millis(50))
            .await
            .unwrap();
        assert!(!more);
        assert!(buf.is_empty());
    }

    /// Waits for `condition` to hold, or gives up.
    ///
    /// The copy takes its buffers as it starts, so a test that wants to see
    /// the charge has to wait for the copy to have run rather than assume it
    /// already has.
    async fn wait_for(mut condition: impl FnMut() -> bool) {
        for _ in 0..100 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the condition never held");
    }

    /// The copy buffers are charged to the budget while the stream is open, and
    /// given back when it ends.
    ///
    /// The copy buffers are the one per-stream allocation the byte budget did
    /// not see: every direction of every copied stream holds one, and a peer
    /// that opened many streams paid for them in memory the operator's ceiling
    /// never knew about.
    #[tokio::test]
    async fn the_copy_buffers_are_charged_to_the_budget() {
        let budget = Arc::new(ByteBudget::new(1024 * 1024));
        let (client_end, backend_end, client_side, backend_side) = pair();

        let charged = budget.clone();
        let copy = tokio::spawn(async move {
            copy_both_ways_until_with_budget(&charged, client_side, backend_side, "test", None)
                .await
        });

        wait_for(|| budget.held() == COPY_BUFFER_BYTES).await;
        assert_eq!(
            budget.held(),
            COPY_BUFFER_BYTES,
            "both directions' buffers are charged while the stream is open"
        );

        // The stream ends.
        drop(client_end);
        drop(backend_end);
        copy.await.unwrap().expect("the copy ends cleanly");

        assert_eq!(
            budget.held(),
            0,
            "the buffers are given back when the stream ends"
        );
    }

    /// A peer that has spent the budget does not get another stream's buffers.
    ///
    /// The budget exists to refuse, not to warn. The stream is refused before
    /// a byte is read, so there is no half-read stream to clean up, and it
    /// closes cleanly rather than being reset under the peer.
    #[tokio::test]
    async fn a_stream_that_cannot_pay_for_its_buffers_is_refused() {
        let budget = Arc::new(ByteBudget::new(1024));
        // The budget is spent: one buffer does not fit into what is left.
        budget
            .try_reserve(1024)
            .expect("the peer has spent the budget");

        let (mut client_end, mut backend_end, client_side, backend_side) = pair();
        client_end.write_all(b"the request").await.unwrap();

        let refused =
            copy_both_ways_until_with_budget(&budget, client_side, backend_side, "test", None)
                .await;
        let error = refused.expect_err("a stream that cannot pay for its buffers is refused");
        assert!(
            error.to_string().contains("copy buffer"),
            "the error says what did not fit: {error}"
        );
        assert_eq!(
            budget.held(),
            1024,
            "a refused stream takes nothing and gives back nothing"
        );

        // The backend saw a clean end of stream and not one byte of the
        // request: the refusal came before anything was read.
        let mut seen = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), backend_end.read_to_end(&mut seen))
            .await
            .expect("the backend's stream ends instead of hanging")
            .expect("the backend's stream ends cleanly");
        assert!(seen.is_empty(), "a refused stream reads nothing: {seen:?}");

        // And the peer saw the same clean end, rather than a reset.
        let mut seen = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client_end.read_to_end(&mut seen))
            .await
            .expect("the peer's stream ends instead of hanging")
            .expect("the peer's stream ends cleanly");
        assert!(
            seen.is_empty(),
            "the peer is told the stream is over, and nothing else: {seen:?}"
        );
    }
}
