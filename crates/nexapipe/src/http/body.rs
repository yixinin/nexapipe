//! The bodies.
//!
//! A request body is read once and may be replayed, a response body is read
//! once and may not, and both are bounded: the ceiling is what stops a peer
//! from holding the process's memory for as long as it likes to send.

use futures_util::{StreamExt, TryStreamExt};

use http_body_util::combinators::UnsyncBoxBody;

use http_body_util::{BodyExt, Full};

use super::*;

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::Idle(idle) => {
                write!(f, "backend sent nothing for {idle:?} mid-body")
            }
            BodyError::Hyper(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BodyError::Idle(_) => None,
            BodyError::Hyper(e) => Some(e),
        }
    }
}

impl From<hyper::Error> for BodyError {
    fn from(e: hyper::Error) -> Self {
        BodyError::Hyper(e)
    }
}

/// The body a proxied response carries.
pub type ProxyBody = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BodyError>;

/// The backend's response body, with the gap between its frames bounded.
///
/// Idle, not a phase deadline: what is bounded is the gap, so it re-arms on
/// every frame — which is what lets an SSE stream or a long transfer stay open
/// for as long as both ends want, while a backend that sent the head and then
/// went silent cannot hold this slot and its backend lease forever. The value
/// comes from `[timeouts] response_idle_secs` through the caller.
///
/// The stream is the body a client is handed, so the failure it reports is
/// the one the client sees: hyper aborts the connection rather than writing a
/// complete-looking response that is missing its tail.
pub(super) fn idle_bounded<B>(
    body: B,
    idle: std::time::Duration,
) -> impl futures_util::Stream<Item = Result<hyper::body::Frame<bytes::Bytes>, BodyError>>
where
    B: hyper::body::Body<Data = bytes::Bytes>,
    B::Error: Into<BodyError>,
{
    let frames = http_body_util::BodyExt::into_data_stream(body).map_ok(hyper::body::Frame::data);
    // `timeout` re-arms on every item, which is the idle semantics wanted
    // here. Both `StreamExt` traits have a `timeout`-shaped surface, so the
    // call is made by its full path rather than by an import.
    let timed = tokio_stream::StreamExt::timeout(frames, idle);
    timed.map(move |item| match item {
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => {
            tracing::warn!("Backend sent nothing for {idle:?} mid-body, ending the response body");
            Err(BodyError::Idle(idle))
        }
    })
}

/// The largest request body this proxy will carry.
///
/// `content-length` is whatever the client says it is, and the limit is
/// checked against that declaration before a byte of the body is read — so
/// this bounds one request whatever the client says it is sending.
///
/// What the process **holds** is a different matter. A body that declares a
/// length is streamed: the bytes are read from the client as the backend asks
/// for them, and only a buffer is held rather than the upload. A body with
/// no length — a chunked one — is read whole, because the proxy re-frames it
/// as one buffer with a length of its own, and this is what bounds that.
///
/// How many such bodies may be held at once is
/// [`ByteBudget`](crate::conn::limits::ByteBudget)'s, which is why a body is
/// only read once it has been given a reservation from it.
pub(super) const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

/// The headers one message names in its own `Connection` header.
///
/// RFC 9110 §7.6.1: the hop-by-hop headers are the fixed list **and** every
/// header the message's `Connection` header names. A header named there is
/// hop-by-hop for that message alone and must not be forwarded — a request
/// that says `Connection: X-Internal-Token` is saying that the header is for
/// this hop only, and forwarding it hands the backend something the client
/// asked not to have forwarded.
///
/// The names belong to the message that carries them: a request's `Connection`
/// names the request's hop-by-hop headers and a response's names the
/// response's. So this is built per message rather than being a property of
/// the filter, and each direction reads its own.
pub(super) struct ConnectionNamed {
    /// The names the `Connection` header gave.
    names: Vec<String>,
}

impl ConnectionNamed {
    /// The names the `Connection` header of these headers gives.
    ///
    /// The value is a comma-separated list of header names, and the header may
    /// appear more than once, so every one of its values is read. The names
    /// are compared without regard to case, as header names are.
    pub(super) fn of(headers: &::http::HeaderMap) -> Self {
        let mut names = Vec::new();
        for value in headers.get_all("connection") {
            // A value that is not text names nothing this proxy could forward:
            // the names it could name are not readable.
            let Ok(value) = value.to_str() else {
                continue;
            };
            for name in value.split(',') {
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                names.push(name.to_string());
            }
        }
        Self { names }
    }

    /// Whether the `Connection` header named this header.
    pub(super) fn names(&self, name: &str) -> bool {
        self.names
            .iter()
            .any(|named| named.eq_ignore_ascii_case(name))
    }
}

/// Whether a request header may be forwarded to the backend.
///
/// Two groups are dropped. Hop-by-hop headers describe one connection, not the
/// message (RFC 7230 6.1): `connection: keep-alive` is about the client's link
/// to this proxy, and forwarding it asks the backend to keep *its* link open
/// for a request that arrived over a different one. `transfer-encoding` is in
/// the same group and has to go: the body is sent with a length of the
/// proxy's own, so a leftover `chunked` would disagree with the framing on
/// the wire.
///
/// `proxy-authorization` is in the same group and is the one that matters most:
/// it is a credential for *this* proxy, and forwarding it hands that credential
/// to a third-party server. `proxy-authenticate` goes with it — it is the
/// challenge this proxy answers, and the backend has no business seeing it.
///
/// `expect: 100-continue` is dropped for a different reason. The expectation
/// is the client's, about the client's link to this proxy, and this proxy
/// does not answer it with a `100` of its own: a client that waits for one
/// before sending its body waits until the body's deadline. Forwarding the
/// header would only tell the backend to wait as well.
///
/// The third group is what the request's own `Connection` header names, and
/// `connection` is the header that names it — see [`ConnectionNamed`].
///
/// The WebSocket handshake does not use this: it is the one request that
/// *must* carry `upgrade` and `connection`, because switching protocols is
/// exactly what it is asking the backend for.
pub(super) fn forwards_request_header(name: &str, connection: &ConnectionNamed) -> bool {
    ![
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "expect",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
        && !connection.names(name)
}

/// A response body that keeps its backend busy until the body is done.
///
/// The lease is what the balancer counts, and a backend that is still
/// streaming a response is still busy with it. A balancer that cannot see
/// that hands the next request to a backend that is already working, which
/// is the whole failure `least_conn` exists to avoid.
///
/// Holding the lease in the body is what makes the count true: the body is
/// dropped when the client has read it — or when the connection goes away
/// instead — and the backend is free again then. The streaming path has
/// always held its lease for the whole flow; this is the same rule on the
/// path that did not.
pub(super) struct LeasedBody {
    pub(super) inner: ProxyBody,
    /// Kept, never read: dropping it is what releases the backend.
    pub(super) _lease: Option<crate::lb::BackendLease>,
}

impl hyper::body::Body for LeasedBody {
    type Data = bytes::Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }
}

/// Why a request body could not be read.
///
/// The three cases are three different answers: a body that is over the limit
/// is too big, a body that ran out of time is late, and a body that could not
/// be read at all is broken. A caller that answers the client says which.
#[derive(Debug)]
pub enum BodyReadError {
    /// The body is over the limit.
    TooLarge { limit: usize },
    /// The body did not finish in time.
    TimedOut { deadline: std::time::Duration },
    /// The body could not be read.
    Failed(anyhow::Error),
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyReadError::TooLarge { limit } => {
                write!(f, "request body is over the {limit} byte limit")
            }
            BodyReadError::TimedOut { deadline } => {
                write!(
                    f,
                    "request body did not finish within {}s",
                    deadline.as_secs()
                )
            }
            BodyReadError::Failed(e) => write!(f, "failed to read the request body: {e}"),
        }
    }
}

impl std::error::Error for BodyReadError {}

impl From<anyhow::Error> for BodyReadError {
    fn from(e: anyhow::Error) -> Self {
        BodyReadError::Failed(e)
    }
}

/// Reads a request body whole, refusing one past `limit` or past what the
/// process can hold at once.
///
/// Returns the reservation as well as the bytes, and the caller has to keep it:
/// dropping it gives the bytes back, so the total the budget reports is what is
/// held *now* rather than what was ever read. A caller that answers the request
/// and returns is exactly the lifetime a buffered body has.
///
/// The size is not known up front — a chunked request says nothing about how
/// much is coming — so the limit has to be enforced while reading rather than
/// by checking a `content-length` header the client is free to understate.
///
/// The deadline over the read is likewise total rather than per frame, so a
/// client that trickles one byte before each expiry renews nothing.
pub(super) async fn read_body_limited<B>(
    body: B,
    limit: usize,
    body_deadline: std::time::Duration,
) -> Result<(bytes::Bytes, crate::conn::limits::ByteReservation), BodyReadError>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut body = body;
    let mut bytes: Vec<u8> = Vec::new();
    // Claimed as the frames arrive rather than up front: see `ByteReservation`.
    let mut reservation = crate::conn::limits::ByteReservation::empty();
    // A deadline over the whole read, not per frame: this is the path the
    // plaintext listener takes, and it had no bound at all, so a client that
    // opened a socket and then sent a byte of body every few seconds held the
    // connection, the task and the buffer indefinitely. The iroh path has always
    // bounded this read; this is the same bound, in one place. The value comes
    // from `[timeouts] body_secs` through the caller, not from here.
    let deadline_at = tokio::time::Instant::now() + body_deadline;
    loop {
        // A `loop` rather than `while let`, so that the deadline's own expiry is
        // told apart from the end of the body.
        let frame =
            match tokio::time::timeout_at(deadline_at, http_body_util::BodyExt::frame(&mut body))
                .await
            {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => {
                    return Err(BodyReadError::TimedOut {
                        deadline: body_deadline,
                    });
                }
            };
        let frame = frame.map_err(|e| {
            BodyReadError::Failed(anyhow::anyhow!("failed to read the request body: {}", e))
        })?;
        // Anything that is not a data frame — trailers — carries no body bytes.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if bytes.len() + data.len() > limit {
            return Err(BodyReadError::TooLarge { limit });
        }
        reservation.grow(data.len())?;
        bytes.extend_from_slice(&data);
    }
    Ok((bytes.into(), reservation))
}

/// What one proxied request came to.
///
/// The streaming path writes the response straight into the QUIC stream, so
/// there is no `Response` left for the caller to inspect; without this the
/// tunnel path — the one every client actually uses — could not be logged at
/// all.
#[derive(Debug, Clone, Copy)]
pub struct ProxySummary {
    pub status: u16,
    /// Response headers plus body payload, excluding chunk framing.
    ///
    /// What reached the client, counted at each successful write rather than
    /// at each byte formatted: a partially streamed response reports the part
    /// that was flushed, not the length it was going to be.
    pub bytes_sent: usize,
}

/// A proxied request that did not finish.
///
/// The streaming path writes as it goes, so by the time something fails the
/// status line — and possibly half the body — is already on the wire. Reporting
/// every failure as a 502 with zero bytes claims a response was never sent when
/// the client is holding part of one, which is the worst possible thing for an
/// access log to say about a request: it points the reader at the backend for a
/// problem that happened after the backend answered. What had arrived when it
/// broke is carried here instead, and is `None` only when nothing had.
#[derive(Debug)]
pub struct ProxyFailure {
    pub error: anyhow::Error,
    pub partial: Option<ProxySummary>,
    /// What may be done about this failure.
    pub retry: Retryability,
}

/// What may be done about a failed attempt.
///
/// The question is never "did it fail" but "may it be tried again", and the
/// answer depends on two things that are easy to confuse:
///
/// - **Did the request reach the backend?** A connection that was refused
///   never carried it, so the backend did not act on it and asking again is
///   free of consequence — whatever the request was.
/// - **Is the request safe to send twice?** A `GET` is. A `POST` that
///   charges a card is not, and the only way to know is what the method says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryability {
    /// The request was never carried to the backend. It may be tried again
    /// whatever it is.
    Always,
    /// The request was carried and no answer came. It may be tried again only
    /// if sending it twice is safe, which is what an idempotent method is.
    IfIdempotent,
    /// Nothing may be tried again: the client already has part of the answer,
    /// or the failure says nothing about the backend.
    Never,
}

// One more argument than clippy allows: the alternative is a struct bundling the
// client with its deadlines, which every caller would have to build in order to
// pass the same two things — see the note on `conn::handle_bidi_stream`.
#[allow(clippy::too_many_arguments)]
/// The body of a request, read once and ready to be sent to a backend.
///
/// Read outside the attempt, because the bytes come off the client's stream
/// and that stream has them only once: a retry that had to read them again
/// would wait for bytes that are never coming.
/// A body that is already in memory, as the client's body type.
pub fn full_body(bytes: bytes::Bytes) -> HttpBody {
    let inner =
        Full::new(bytes).map_err(|never: std::convert::Infallible| -> BoxError { match never {} });
    UnsyncBoxBody::new(inner)
}

/// A body with nothing in it.
///
/// What an answer that is not a body at all carries: a refusal, and a `101` —
/// the upgrade has no body of its own, and the bytes that follow it are the
/// session's.
pub fn empty_body() -> ProxyBody {
    let empty = http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|never: std::convert::Infallible| -> BodyError { match never {} });
    UnsyncBoxBody::new(empty)
}

/// A body that carries these bytes and nothing else.
///
/// The length of such a body is known, so the answer that carries it is
/// framed with a length of its own: the client is never told one length and
/// given another.
pub fn bytes_body(bytes: bytes::Bytes) -> ProxyBody {
    let inner =
        Full::new(bytes).map_err(|never: std::convert::Infallible| -> BodyError { match never {} });
    UnsyncBoxBody::new(inner)
}

/// What the proxy knows about a body that is still on the client's stream.
///
/// Shared between the body the request carries and the request that owns it:
/// the body knows when it has been read, and the owner needs to know that
/// afterwards — a body that has been read cannot be sent a second time, and
/// one that has not can.
#[derive(Debug, Default)]
pub struct BodyState {
    /// Set once a byte has come off the client's stream.
    ///
    /// The head's bytes are not counted: they are in memory, and the request
    /// still holds them, so a retry can send them again. What is gone once
    /// the stream has been read is the rest of the body, and the stream is
    /// the only place it was.
    read: std::sync::atomic::AtomicBool,
    /// Set when the body's deadline expired while it was being read.
    timed_out: std::sync::atomic::AtomicBool,
    /// Set once the body is over: everything the client promised has been
    /// read, or the client stopped sending.
    ///
    /// The answer's deadline runs from this moment, because a backend cannot
    /// answer before it has the body.
    sent: std::sync::atomic::AtomicBool,
}

impl BodyState {
    /// Records that a byte has come off the client's stream.
    pub(crate) fn mark_read(&self) {
        self.read.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records that the body's deadline expired.
    pub(crate) fn mark_timed_out(&self) {
        self.timed_out
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records that the body is over.
    pub(crate) fn mark_sent(&self) {
        self.sent.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the body has been read off the client's stream.
    pub(crate) fn was_read(&self) -> bool {
        self.read.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the body's deadline expired while it was being read.
    pub(crate) fn did_time_out(&self) -> bool {
        self.timed_out.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the body is over.
    pub(crate) fn has_been_sent(&self) -> bool {
        self.sent.load(std::sync::atomic::Ordering::Relaxed)
    }
}
