//! A WebSocket upgrade, carried over the tunnel.
//!
//! # What this is
//!
//! A WebSocket is not a request with a body: it is a request that turns the
//! connection into a conversation once the answer says so. The answer is a
//! `101`, and after it the two ends speak a framing of their own that HTTP
//! knows nothing about.
//!
//! So the upgrade is two things, and this module does both:
//!
//! - The **handshake**: the client's upgrade request goes to the backend
//!   over a connection of its own — a WebSocket holds one connection for the
//!   whole session, so it is not the pooled client — and the backend's answer
//!   comes back. The client gets the same `101`, with the same headers, so
//!   that its `Sec-WebSocket-Accept` is the one the backend agreed to.
//! - The **session**: from then on the two are byte streams, and the bytes
//!   are moved either way until one side stops.
//!
//! The framing is the WebSocket's own and is not touched here: the bytes are
//! moved as they are, and the end of the session is the end of a stream.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::HeaderMap;
use hyper::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::conn::{find_headers_end, now_millis};
use crate::http::body::{ProxyBody, ProxyFailure, Retryability};
use crate::http::client::{BackendClients, BackendStream};
use crate::routes::BackendInfo;

/// How much of a WebSocket's stream is moved at a time.
///
/// The HTTP path coalesces into 64 KiB before it writes; the WebSocket path
/// used to move 8 KiB at a time, which is one QUIC frame and one wake-up for
/// every 8 KiB of the stream.
const WS_COPY_BUFFER: usize = 64 * 1024;

/// The largest refusal body this proxy carries to the client.
///
/// A refusal is an explanation, not a payload: a line of JSON, a short HTML
/// page, a sentence. Sixteen kilobytes is far more than any of those needs,
/// and far less than a body would have to be for carrying it whole to be
/// worth it — and the bound is what stops a backend that answers a refusal
/// with an endless body from holding the connection open.
const MAX_REFUSAL_BODY: usize = 16 * 1024;

/// The longest size line a chunked body may have.
///
/// The line is a number and, maybe, an extension, and neither is worth more
/// than this: a longer line is a framing that cannot be followed, and the
/// body ends where the line stops fitting.
const MAX_CHUNK_SIZE_LINE: usize = 1024;

/// The longest trailer line a chunked body may have.
///
/// The trailers are metadata this proxy does not forward, so a long one is
/// only a framing to be followed — but it is still a line a backend may keep
/// sending, and it is bounded like the head is.
const MAX_TRAILER_LINE: usize = 64 * 1024;

/// What the backend answered to the upgrade.
pub struct Handshake {
    /// The status the backend answered with.
    pub status: u16,
    /// The headers the backend answered with.
    pub headers: HeaderMap,
    /// The bytes that came after the handshake.
    ///
    /// A backend that answers the upgrade and sends frames in the same breath
    /// puts them here, and they belong to the session rather than to the
    /// handshake.
    pub trailing: Vec<u8>,
    /// The backend's stream, for the session itself.
    pub backend: BackendStream,
    /// The body the backend sent with its refusal.
    ///
    /// `None` for the `101`: it has no body, and the bytes after its head
    /// are the session's rather than the refusal's.
    pub refusal: Option<RefusalBody>,
}

impl Handshake {
    /// The `101` the client gets.
    ///
    /// The headers are the backend's, so the `Sec-WebSocket-Accept` the
    /// client checks is the one the backend agreed to.
    pub fn upgrade_response(&self) -> Response<ProxyBody> {
        let mut response = Response::new(crate::http::body::empty_body());
        *response.status_mut() =
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::SWITCHING_PROTOCOLS);
        *response.headers_mut() = self.headers.clone();
        response
    }

    /// The backend's refusal, which the client gets as an ordinary answer.
    ///
    /// The backend did not agree to the upgrade, so there is no session: what
    /// it said is the answer — the status, the headers, and the body, which
    /// is where the reason for the refusal usually is.
    pub fn refusal_response(&self) -> Response<ProxyBody> {
        let mut response = Response::new(self.refusal_body());
        *response.status_mut() =
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_GATEWAY);
        for (name, value) in &self.headers {
            // The framing headers describe the backend's own hop and say
            // nothing about this one: the body below is framed by this
            // proxy, with a length of its own.
            if name.as_str().eq_ignore_ascii_case("content-length")
                || name.as_str().eq_ignore_ascii_case("transfer-encoding")
                || name.as_str().eq_ignore_ascii_case("connection")
            {
                continue;
            }
            response.headers_mut().append(name.clone(), value.clone());
        }
        response
    }

    /// The body the client gets with the refusal.
    ///
    /// A body of a known length is carried by a body that knows its length,
    /// so the answer is framed with that length: the client is never told one
    /// length and given another.
    fn refusal_body(&self) -> ProxyBody {
        let Some(refusal) = &self.refusal else {
            return crate::http::body::empty_body();
        };
        if refusal.bytes.is_empty() || !status_may_have_body(self.status) {
            return crate::http::body::empty_body();
        }
        crate::http::body::bytes_body(refusal.bytes.clone())
    }

    /// How many bytes the refusal's body carries.
    ///
    /// What the client is given, for the access log: a refusal that carries
    /// an explanation sent those bytes, and a log that says it sent none is
    /// a log that cannot say what the client was told.
    pub fn refusal_body_len(&self) -> usize {
        self.refusal
            .as_ref()
            .map_or(0, |refusal| refusal.bytes.len())
    }
}

/// The body a backend sent with its refusal of an upgrade.
///
/// The bytes are the body itself: the framing the backend used — a length,
/// the chunks, the end of the connection — is not part of them, because the
/// client gets the body and not the way it was sent.
pub struct RefusalBody {
    /// The bytes of the body.
    pub bytes: bytes::Bytes,
    /// Whether the body is short of what the backend promised.
    ///
    /// A backend that declared a length and then sent less, or one that was
    /// cut off by the limit or by the deadline, leaves a body that is not the
    /// whole one. The client still gets what arrived — the reason is usually
    /// in it — but the answer does not claim to be more than it is.
    pub truncated: bool,
}

/// Whether the request is an upgrade this module handles.
pub fn is_upgrade(request: &Request<()>) -> bool {
    request
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// The backend's side of the upgrade.
///
/// The request goes to the backend over a connection of its own — a WebSocket
/// holds one connection for the whole session, so it is not the pooled client
/// — and the backend's answer comes back.
pub async fn handshake(
    clients: &BackendClients,
    backend_info: &BackendInfo,
    request: &Request<()>,
    timeouts: crate::config::Timeouts,
) -> Result<Handshake, ProxyFailure> {
    let backend_url = &*backend_info.url;
    let protocol = backend_info.protocol;

    if protocol == crate::config::BackendProtocol::H2c {
        // A WebSocket upgrade is HTTP/1.1. A route that speaks h2c has told
        // the server its backend starts with HTTP/2's connection preface, and
        // there is no way to carry an HTTP/1.1 upgrade on that connection.
        return Err(ProxyFailure::from(anyhow::anyhow!(
            "backend {backend_url} is reached with backend_protocol = \"h2c\", which cannot \
             carry a WebSocket upgrade; use an http:// or https:// backend that speaks HTTP/1.1"
        )));
    }

    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);

    // Not the pooled HTTP client: a WebSocket holds one dedicated connection
    // for the whole session, so this dial is its own, with the same deadline.
    // It is still the same trust store: an https:// backend is reached over a
    // TLS session this process originates and verifies, exactly as the pooled
    // clients do.
    let mut backend_stream = clients
        .connect_stream(backend_url, timeouts.connect)
        .await
        .map_err(|e| ProxyFailure::unanswered(e, Retryability::Always))?;

    let request_buf = build_upgrade_request(request, backend_info, &host);

    backend_stream.write_all(&request_buf).await.map_err(|e| {
        ProxyFailure::unanswered(
            anyhow::anyhow!("failed to write the WebSocket upgrade: {e}"),
            Retryability::Always,
        )
    })?;

    let mut response_buf = Vec::with_capacity(8192);
    let mut trailing = Vec::new();
    let mut read_buf = [0u8; 8192];
    // The handshake response arrives in reads of its own, and the marker is
    // only ever in the part that has not been scanned.
    let mut searched = 0usize;

    let read_handshake = async {
        loop {
            match backend_stream.read(&mut read_buf).await {
                Ok(0) => break,
                Ok(n) => {
                    response_buf.extend_from_slice(&read_buf[..n]);

                    if let Some(pos) = find_headers_end(&response_buf, searched) {
                        let headers_end = pos + 4;
                        if response_buf.len() > headers_end {
                            trailing.extend_from_slice(&response_buf[headers_end..]);
                        }
                        response_buf.truncate(headers_end);
                        break;
                    }

                    searched = response_buf.len().saturating_sub(3);

                    if response_buf.len() > 64 * 1024 {
                        tracing::warn!("WebSocket handshake response too large");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to read from backend stream: {e}");
                    return Err(anyhow::anyhow!(
                        "failed to read the handshake response: {e}"
                    ));
                }
            }
        }
        Ok(())
    };

    match tokio::time::timeout(timeouts.response, read_handshake).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(ProxyFailure::unanswered(e, Retryability::Always));
        }
        Err(_) => {
            return Err(ProxyFailure::unanswered(
                anyhow::anyhow!(
                    "backend {host}:{port} did not answer the WebSocket handshake within {:?}",
                    timeouts.response
                ),
                Retryability::Always,
            ));
        }
    }

    let parsed = crate::http::legacy::parse_http_response_legacy(&response_buf)?;
    let status = parsed.status().as_u16();
    let headers = parsed.headers().clone();

    // The `101` has no body: the bytes after its head are the session's, and
    // they are already in `trailing`.
    if status == 101 {
        return Ok(Handshake {
            status,
            headers,
            trailing,
            backend: backend_stream,
            refusal: None,
        });
    }

    // A refusal has a body, and the body is the point of it: a backend that
    // answers `403` with a JSON explanation says why in the body, and a
    // client that is given the status alone cannot tell what went wrong.
    //
    // The body is read here rather than at the call site because this is the
    // only place that speaks HTTP/1 to a backend by hand: the framing the
    // backend used has to be followed here, and what comes out of it is the
    // body the client gets.
    //
    // The budget is the **response** one. What is read here is the backend's
    // answer, and the answer's budget is the budget of the direction it
    // travels in — the same one every other place that reads a backend's
    // response body uses. The request body budget belongs to the other
    // direction: it says how long a *client* may take to send an upload, and
    // it says nothing about how long a backend may take to explain a refusal.
    // An operator who lowered it because their clients upload small bodies
    // would otherwise find the refusal cut short, and one who left it at the
    // default would find a stalled refusal hold the client's handshake for
    // five minutes.
    let refusal = read_refusal_body(
        status,
        &mut backend_stream,
        &headers,
        trailing,
        timeouts.deadlines.response_idle,
    )
    .await;
    if refusal.truncated {
        tracing::warn!(
            "The backend's refusal of the WebSocket upgrade is short: {} bytes",
            refusal.bytes.len()
        );
    }

    Ok(Handshake {
        status,
        headers,
        // The bytes after the head were the beginning of the body, and the
        // body is now read: there is nothing left over for the session.
        trailing: Vec::new(),
        backend: backend_stream,
        refusal: Some(refusal),
    })
}

/// Reads the body a backend sent with its refusal of an upgrade.
///
/// The body is read by hand, because the proxy is the one that has to follow
/// the backend's framing and then re-frame it for the client: a length, the
/// chunks, or the end of the connection. Whatever the backend used, what the
/// client gets is the body itself — the framing describes the backend's own
/// hop and says nothing about this one.
///
/// The read is bounded twice over: by the size of the body and by the
/// deadline. A declared length is not believed — the limit is checked
/// against the bytes as they arrive — and a body without a length is read
/// until the backend closes the connection, which is what such a body means.
async fn read_refusal_body(
    status: u16,
    stream: &mut BackendStream,
    headers: &HeaderMap,
    trailing: Vec<u8>,
    deadline: Duration,
) -> RefusalBody {
    // A status that has no content has no body: RFC 9110 gives a `1xx`, a
    // `204` and a `304` none, and bytes after one of them are not a body —
    // a client reads them as the next message.
    if !status_may_have_body(status) {
        return RefusalBody {
            bytes: bytes::Bytes::new(),
            truncated: false,
        };
    }

    let mut reader = BodyReader::new(stream, trailing, deadline);
    let (bytes, truncated) = match Framing::of(headers) {
        Framing::Length(len) => read_length(&mut reader, len).await,
        Framing::Chunked => read_chunked(&mut reader).await,
        Framing::UntilClose => read_until_close(&mut reader).await,
    };

    RefusalBody {
        bytes: bytes::Bytes::from(bytes),
        truncated,
    }
}

/// Whether a status may carry a body.
///
/// RFC 9110: a `1xx`, a `204` and a `304` have no content, and bytes after
/// one of them are not a body.
fn status_may_have_body(status: u16) -> bool {
    !matches!(status, 101..=199 | 204 | 304)
}

/// How the backend framed the body of its refusal.
enum Framing {
    /// A length: the body is exactly this many bytes.
    Length(usize),
    /// Chunks: the body is a sequence of chunks, and the framing is not part
    /// of it.
    Chunked,
    /// Neither: the body ends when the connection does.
    UntilClose,
}

impl Framing {
    /// The framing the backend's headers describe.
    ///
    /// The chunking wins over a length: RFC 9110 says a message that carries
    /// both is framed by the chunking, and the chunking is the one that
    /// describes the bytes that are actually there.
    fn of(headers: &HeaderMap) -> Framing {
        if is_chunked(headers) {
            return Framing::Chunked;
        }
        if let Some(len) = content_length(headers) {
            return Framing::Length(len);
        }
        Framing::UntilClose
    }
}

/// Whether the backend said it is sending the body in chunks.
fn is_chunked(headers: &HeaderMap) -> bool {
    headers
        .get_all("transfer-encoding")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .rsplit(',')
                .next()
                .map(str::trim)
                .is_some_and(|last| last.eq_ignore_ascii_case("chunked"))
        })
}

/// The length the backend gave its body, if it gave one that can be read.
///
/// A length that cannot be read, and a message with two lengths that
/// disagree, are both messages whose body cannot be found: they are treated
/// as a body without one.
fn content_length(headers: &HeaderMap) -> Option<usize> {
    let mut lengths: Vec<usize> = Vec::new();
    for value in headers.get_all("content-length") {
        let Ok(value) = value.to_str() else {
            return None;
        };
        let Ok(length) = value.trim().parse::<usize>() else {
            return None;
        };
        lengths.push(length);
    }
    let first = *lengths.first()?;
    if lengths.iter().any(|other| *other != first) {
        return None;
    }
    Some(first)
}

/// Reads a body the backend gave a length for.
///
/// The length is not believed: the limit is checked against the bytes as they
/// arrive, and a body that is shorter than the length it was given is a body
/// that was cut short.
async fn read_length(reader: &mut BodyReader<'_>, len: usize) -> (Vec<u8>, bool) {
    let want = len.min(MAX_REFUSAL_BODY);
    let (bytes, complete) = reader.read_exact(want).await;
    (bytes, !complete || want < len)
}

/// Reads a body that ends when the connection does.
///
/// A body without a length is a body that ends when the connection ends, so
/// the end of the connection is where this one is whole — and it is over the
/// limit or out of time that makes it short.
async fn read_until_close(reader: &mut BodyReader<'_>) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        if reader.pending().is_empty() {
            match reader.fill().await {
                Ok(true) => {}
                Ok(false) => return (body, false),
                Err(_) => return (body, true),
            }
        }
        let room = MAX_REFUSAL_BODY - body.len();
        if room == 0 {
            return (body, true);
        }
        let take = room.min(reader.pending().len());
        body.extend_from_slice(&reader.take(take));
    }
}

/// Reads a chunked body and drops the framing.
///
/// The chunks are how the backend sent the body; the client gets the body.
/// The sizes are read as they come, and the limit is checked against the
/// bytes as they arrive: a chunk that says it is enormous does not make the
/// proxy believe it.
async fn read_chunked(reader: &mut BodyReader<'_>) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let line = match reader.read_line(MAX_CHUNK_SIZE_LINE).await {
            Ok(Some(line)) => line,
            // The end of the connection, or a framing that cannot be
            // followed: the body is short of what it was.
            Ok(None) | Err(_) => return (body, true),
        };
        let Some(size) = chunk_size(&line) else {
            return (body, true);
        };
        if size == 0 {
            // The trailers end the body. They are not forwarded: the client
            // gets the body, and this proxy frames it.
            loop {
                match reader.read_line(MAX_TRAILER_LINE).await {
                    Ok(Some(line)) if line.is_empty() => return (body, false),
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => return (body, true),
                }
            }
        }
        let room = MAX_REFUSAL_BODY - body.len();
        if room == 0 {
            return (body, true);
        }
        let want = size.min(room as u64) as usize;
        let (data, complete) = reader.read_exact(want).await;
        body.extend_from_slice(&data);
        if !complete || want as u64 != size {
            return (body, true);
        }
        // The line ending that ends the chunk.
        let (ending, complete) = reader.read_exact(2).await;
        if !complete || ending.as_slice() != b"\r\n".as_slice() {
            return (body, true);
        }
    }
}

/// The size a chunk's size line says, if it says one.
///
/// The line is the size and, maybe, an extension: `1*HEXDIG [ ";" chunk-ext ]`.
fn chunk_size(line: &[u8]) -> Option<u64> {
    let size = match line.iter().position(|byte| *byte == b';') {
        Some(at) => &line[..at],
        None => line,
    };
    let text = std::str::from_utf8(size).ok()?.trim();
    u64::from_str_radix(text, 16).ok()
}

/// The backend's bytes, read a piece at a time.
///
/// The bytes that came with the head are the first of the body, and they are
/// already read: reading them again would lose them, so they are the
/// reader's first buffer.
struct BodyReader<'a> {
    stream: &'a mut BackendStream,
    /// The bytes that have been read but not used yet.
    buffered: Vec<u8>,
    /// How much of `buffered` has been used.
    used: usize,
    /// When the read runs out of time.
    ///
    /// A phase deadline, taken once: a backend that sends a byte before each
    /// expiry renews nothing.
    deadline: tokio::time::Instant,
}

impl<'a> BodyReader<'a> {
    fn new(stream: &'a mut BackendStream, buffered: Vec<u8>, deadline: Duration) -> Self {
        Self {
            stream,
            buffered,
            used: 0,
            deadline: tokio::time::Instant::now() + deadline,
        }
    }

    /// The bytes that are read but not used yet.
    fn pending(&self) -> &[u8] {
        &self.buffered[self.used..]
    }

    /// Uses up to `n` of the pending bytes.
    fn take(&mut self, n: usize) -> Vec<u8> {
        let end = (self.used + n).min(self.buffered.len());
        let taken = self.buffered[self.used..end].to_vec();
        self.used = end;
        taken
    }

    /// Reads more of the backend's bytes.
    ///
    /// `Ok(true)` is more bytes, `Ok(false)` is the end of the connection, and
    /// an error is the deadline or a broken connection: both end the body.
    async fn fill(&mut self) -> std::io::Result<bool> {
        if self.used == self.buffered.len() {
            self.buffered.clear();
            self.used = 0;
        }
        let mut chunk = [0u8; 8192];
        let read = tokio::time::timeout_at(self.deadline, self.stream.read(&mut chunk)).await;
        match read {
            Ok(Ok(0)) => Ok(false),
            Ok(Ok(n)) => {
                self.buffered.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the backend did not finish the refusal body in time",
            )),
        }
    }

    /// Reads exactly `n` bytes, or as many as there are.
    ///
    /// The second value says whether they were all there: a backend that
    /// promised a length and sent less broke its promise, and the body it
    /// sent is short.
    async fn read_exact(&mut self, n: usize) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(n.min(MAX_REFUSAL_BODY));
        while out.len() < n {
            if self.pending().is_empty() {
                match self.fill().await {
                    Ok(true) => {}
                    Ok(false) => return (out, false),
                    Err(_) => return (out, false),
                }
            }
            let take = (n - out.len()).min(self.pending().len());
            out.extend_from_slice(&self.take(take));
        }
        (out, true)
    }

    /// Reads one line, without its ending.
    ///
    /// `Ok(None)` is the end of the connection before a line; a line longer
    /// than `max` is an error, because a framing that cannot be followed is
    /// not a framing.
    async fn read_line(&mut self, max: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        loop {
            if self.pending().is_empty() {
                match self.fill().await {
                    Ok(true) => {}
                    Ok(false) => {
                        return Ok(if line.is_empty() { None } else { Some(line) });
                    }
                    Err(e) => return Err(e),
                }
            }
            match self.pending().iter().position(|byte| *byte == b'\n') {
                Some(at) => {
                    let mut rest = self.take(at + 1);
                    // The line ending goes with the line: what is left is the
                    // line itself.
                    rest.pop();
                    if rest.last() == Some(&b'\r') {
                        rest.pop();
                    }
                    line.extend_from_slice(&rest);
                    if line.len() > max {
                        return Err(line_too_long());
                    }
                    return Ok(Some(line));
                }
                None => {
                    let pending = self.pending().len();
                    line.extend_from_slice(&self.take(pending));
                    if line.len() > max {
                        return Err(line_too_long());
                    }
                }
            }
        }
    }
}

/// The error a line that cannot be followed is.
fn line_too_long() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "the line is longer than the framing allows",
    )
}

/// How long the session waits for the other direction after one of them ends.
///
/// A half-close is a request, not an ending: the peer that shut down its write
/// side is done sending, and the reply that follows still has to arrive. So
/// the session does not end when the first direction does — it ends when the
/// second one does.
///
/// The bound is what keeps an abandoned session from holding its slot. A peer
/// that vanished is indistinguishable from one that half-closed — both arrive
/// as a clean end of stream — and without a bound the session would wait for
/// a reply that is never coming, holding a stream slot and a backend
/// connection for as long as the whole-flow deadline allows.
///
/// Thirty seconds is the same order nginx uses for the same problem
/// (`lingering_time`), and long enough for a backend that is thinking about
/// its answer.
const LINGERING: Duration = Duration::from_secs(30);

/// The moment no direction has ended yet.
///
/// `now_millis()` counts from the start of the process, so this cannot be a
/// moment it returns.
const NOT_ENDED: u64 = u64::MAX;

/// The session: the client's bytes and the backend's bytes, moved either way.
///
/// The session ends when both directions have ended, or when neither has moved
/// for a whole idle window. A direction that is quiet on its own does not end
/// it: a client that only listens to a feed the backend keeps pushing has
/// nothing to say, and a gap in one direction must not end a session the
/// other direction is still using.
///
/// A half-close is not an ending either. A client that sends its Close frame
/// and shuts its write side down is done sending, and the backend's answer —
/// its own Close frame, echoed back — still has to arrive. So the two
/// directions are joined rather than raced, and each one shuts the peer's
/// write side down as it ends, so the peer sees a clean end of stream rather
/// than a reset.
pub async fn pump(
    client: hyper::upgrade::Upgraded,
    backend: BackendStream,
    trailing: Vec<u8>,
    idle: Duration,
) {
    let client = crate::hyper_io::UpgradedIo::new(client);
    pump_session(client, backend, trailing, idle).await;
}

/// The session, over any pair of byte streams.
///
/// The tunnel's own pair is one of many, so the session is written over
/// streams rather than over the tunnel's types: the shape below — two
/// directions, joined and half-closed — is then the shape under test, and the
/// test drives it over an in-memory pair.
async fn pump_session<C, B>(client: C, backend: B, trailing: Vec<u8>, idle: Duration)
where
    C: AsyncRead + AsyncWrite,
    B: AsyncRead + AsyncWrite,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);

    // The bytes that came after the handshake belong to the session, not to
    // the handshake: they are the backend's first frames.
    if !trailing.is_empty()
        && let Err(e) = client_write.write_all(&trailing).await
    {
        tracing::debug!("WebSocket: writing the backend's first frames failed: {e}");
        return;
    }

    // When the last byte moved on this session, in milliseconds since the
    // epoch. Both directions write to it, and a direction that has been quiet
    // for a whole window reads it to find out whether the other one is still
    // talking.
    let last_traffic = AtomicU64::new(now_millis());

    // When the first direction ended, in milliseconds since the epoch, and
    // `NOT_ENDED` while both are still running. The second direction is given
    // `LINGERING` from that moment on.
    let first_end = AtomicU64::new(NOT_ENDED);

    // The two directions, and the half-close that goes with each of them.
    //
    // A half-close is a **request**, not an ending: the peer that shut down
    // its write side is done sending, and the other side has to hear that, or
    // it waits for input that is never coming. So the FIN is sent as soon as
    // the direction ends — not when the whole session does.
    //
    // The two directions are **joined**, not raced. Racing them meant that
    // whichever ended first won and the other was dropped: a client that
    // sent its Close frame and then shut its write side down never saw the
    // backend's answer, because the direction carrying it was killed a
    // microsecond after the half-close. Nothing shut a write half down
    // either, so the backend saw the connection disappear rather than a
    // clean end of stream.
    let client_to_backend = async {
        let end = copy_one_way(
            &mut client_read,
            &mut backend_write,
            &last_traffic,
            &first_end,
            idle,
            Leg::ClientToBackend,
        )
        .await;
        // The client is done sending. The backend has to hear that.
        let _ = backend_write.shutdown().await;
        // The clock on the other direction starts now: this one is over.
        mark_first_end(&first_end);
        end
    };
    let backend_to_client = async {
        let end = copy_one_way(
            &mut backend_read,
            &mut client_write,
            &last_traffic,
            &first_end,
            idle,
            Leg::BackendToClient,
        )
        .await;
        // The backend is done sending. The client has to hear that.
        let _ = client_write.shutdown().await;
        mark_first_end(&first_end);
        end
    };

    // Both directions have to be waited for. A `select!` here would drop the
    // one that lost the race, and the bytes it was carrying would be lost
    // with it.
    let (client_end, backend_end) = tokio::join!(client_to_backend, backend_to_client);

    // Both write halves, whatever happened: the session is over either way.
    let _ = backend_write.shutdown().await;
    let _ = client_write.shutdown().await;

    tracing::debug!(
        "WebSocket session ended: client to backend {}, backend to client {}",
        client_end.reason(Leg::ClientToBackend),
        backend_end.reason(Leg::BackendToClient),
    );
}

/// Which way the bytes of one direction travel.
#[derive(Clone, Copy)]
enum Leg {
    /// From the client to the backend.
    ClientToBackend,
    /// From the backend to the client.
    BackendToClient,
}

impl Leg {
    /// The name of the direction, for the log lines.
    fn label(self) -> &'static str {
        match self {
            Leg::ClientToBackend => "client to backend",
            Leg::BackendToClient => "backend to client",
        }
    }

    /// Counts the bytes that crossed this direction.
    fn record(self, bytes: u64) {
        match self {
            Leg::ClientToBackend => crate::metrics::METRICS.record_bytes_received(bytes),
            Leg::BackendToClient => crate::metrics::METRICS.record_bytes_sent(bytes),
        }
    }
}

/// How one direction of the session ended.
enum DirectionEnd {
    /// The peer's write side closed: a half-close, or a peer that vanished —
    /// the two arrive the same way, and the session cannot tell them apart.
    Finished,
    /// The transport failed on the way in.
    ReadFailed,
    /// The transport failed on the way out.
    WriteFailed,
    /// Nothing moved in either direction for a whole idle window.
    Idle,
    /// The other direction ended, and this one outlasted the bound.
    Lingering,
}

impl DirectionEnd {
    /// The reason, in the words the log uses.
    ///
    /// The two directions fail on different peers, so the reason names the
    /// peer that failed rather than the direction.
    fn reason(self, leg: Leg) -> &'static str {
        match (self, leg) {
            (DirectionEnd::Finished, Leg::ClientToBackend) => "client_finished",
            (DirectionEnd::Finished, Leg::BackendToClient) => "backend_finished",
            (DirectionEnd::ReadFailed, Leg::ClientToBackend) => "client_read_error",
            (DirectionEnd::ReadFailed, Leg::BackendToClient) => "backend_read_error",
            (DirectionEnd::WriteFailed, Leg::ClientToBackend) => "backend_write_error",
            (DirectionEnd::WriteFailed, Leg::BackendToClient) => "client_write_error",
            (DirectionEnd::Idle, _) => "idle",
            (DirectionEnd::Lingering, _) => "lingering",
        }
    }
}

/// Notes that a direction ended, and says whether it was the first one to do so.
fn mark_first_end(first_end: &AtomicU64) -> bool {
    first_end
        .compare_exchange(
            NOT_ENDED,
            now_millis(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        )
        .is_ok()
}

/// How long this direction may wait for the next chunk.
///
/// The shorter of the two bounds wins: the idle window says how long a
/// direction may be quiet while the session is still alive, and the lingering
/// bound says how long it may wait once the other direction ended. A direction
/// that keeps moving bytes must not be able to hold the session open on its
/// own, so the lingering bound is what the wait is measured against.
fn wait_for(first_end: &AtomicU64, idle: Duration) -> Duration {
    let at = first_end.load(Ordering::Relaxed);
    if at == NOT_ENDED {
        return idle;
    }
    let bound = LINGERING.as_millis() as u64;
    let elapsed = now_millis().saturating_sub(at);
    if elapsed >= bound {
        return Duration::ZERO;
    }
    idle.min(Duration::from_millis(bound - elapsed))
}

/// Copies one direction of the session until it ends.
///
/// The direction ends when the peer stops sending, when the transport fails,
/// when nothing has moved in either direction for a whole idle window, or
/// when the other direction ended and this one outlasted the bound.
async fn copy_one_way<R, W>(
    reader: &mut R,
    writer: &mut W,
    last_traffic: &AtomicU64,
    first_end: &AtomicU64,
    idle: Duration,
    leg: Leg,
) -> DirectionEnd
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; WS_COPY_BUFFER];
    loop {
        // The bound is checked on every pass, not only when the read times
        // out: a direction that keeps moving bytes would otherwise never
        // notice that the other one ended.
        let wait = wait_for(first_end, idle);
        if wait.is_zero() {
            return DirectionEnd::Lingering;
        }
        match tokio::time::timeout(wait, reader.read(&mut buf)).await {
            Ok(Ok(0)) => return DirectionEnd::Finished,
            Ok(Ok(n)) => {
                last_traffic.store(now_millis(), Ordering::Relaxed);
                if let Err(e) = writer.write_all(&buf[..n]).await {
                    tracing::debug!("WebSocket {} write failed: {e}", leg.label());
                    return DirectionEnd::WriteFailed;
                }
                leg.record(n as u64);
            }
            Ok(Err(_)) => return DirectionEnd::ReadFailed,
            Err(_) => {
                // This direction has been quiet for a whole window. The
                // session ends when nothing has moved in either direction
                // for that long; until then the other side is still using
                // it.
                let quiet_for = now_millis().saturating_sub(last_traffic.load(Ordering::Relaxed));
                if quiet_for >= idle.as_millis() as u64 {
                    return DirectionEnd::Idle;
                }
                // The other side is still talking: wait for more, with
                // the window measured from now.
                continue;
            }
        }
    }
}

/// The upgrade request that goes to the backend.
///
/// The path is the backend's own — rewritten by the route, as every other
/// path is — and the `Host` is the client's, so that a backend which routes
/// by name sees the name the client asked for.
fn build_upgrade_request(
    request: &Request<()>,
    backend_info: &BackendInfo,
    backend_host: &str,
) -> Vec<u8> {
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path());
    let path = backend_info.rewritten_path(path);

    let request_line = format!("{} {} HTTP/1.1\r\n", request.method(), path);

    let original_host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.to_string())
        .unwrap_or_else(|| backend_host.to_string());

    let mut request_buf = Vec::new();
    request_buf.extend_from_slice(request_line.as_bytes());
    request_buf.extend_from_slice(b"Host: ");
    request_buf.extend_from_slice(original_host.as_bytes());
    request_buf.extend_from_slice(b"\r\n");

    for (name, value) in request.headers() {
        if name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        if !forwards_upgrade_header(name.as_str()) {
            continue;
        }
        request_buf.extend_from_slice(name.as_str().as_bytes());
        request_buf.extend_from_slice(b": ");
        request_buf.extend_from_slice(value.as_bytes());
        request_buf.extend_from_slice(b"\r\n");
    }
    request_buf.extend_from_slice(b"\r\n");

    request_buf
}

/// Whether a header may be forwarded in an upgrade request.
///
/// The same rule as the HTTP path's, and for the same reason: a hop-by-hop
/// header describes one connection, not the message.
fn forwards_upgrade_header(name: &str) -> bool {
    ![
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "expect",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
}
#[cfg(test)]
mod tests {
    use super::build_upgrade_request;
    use super::pump_session;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A route table whose route rewrites the paths under `pattern`.
    ///
    /// The rewrite is what a route pairs a `path_pattern` with: the paths
    /// that match are served somewhere else, and `{}` in the rewrite is where
    /// the matched part goes.
    fn route_table_with_rewrite(
        pattern: &str,
        rewrite: &str,
    ) -> std::sync::Arc<crate::routes::RoutingTable> {
        let timeouts = crate::config::Timeouts {
            connect: std::time::Duration::from_secs(1),
            response: std::time::Duration::from_secs(1),
            deadlines: crate::deadline::Deadlines::default(),
        };
        let route = crate::routes::Route::new(
            "rewrite.test",
            pattern,
            true,
            vec!["http://127.0.0.1:9".to_string()],
            crate::lb::LoadBalancingStrategy::RoundRobin,
            crate::config::RouteMode::Http,
            Some(rewrite.to_string()),
        );
        std::sync::Arc::new(crate::routes::RoutingTable::with_settings(
            vec![route],
            timeouts,
            crate::config::Retry {
                attempts: 1,
                backoff: std::time::Duration::ZERO,
            },
        ))
    }

    /// A WebSocket upgrade goes out with the route's rewritten path.
    ///
    /// The upgrade is a request like any other, and a route that names a
    /// `path_rewrite` means it for every request it serves. The plaintext
    /// listener answers an upgrade with 426 and never gets that far, so the
    /// tunnel is the only place a WebSocket is served — and it used to
    /// forward the path the client asked for, without the rewrite. A route
    /// that named one therefore looked configured and did nothing for every
    /// WebSocket client.
    #[tokio::test]
    async fn a_websocket_upgrade_goes_out_with_the_rewritten_path() {
        let config = route_table_with_rewrite("/api", "/v2{}");

        let backend_info = config
            .get_backend_with_acl("rewrite.test", "/api/socket", None, None)
            .await
            .backend()
            .expect("a route for the host");

        let request = ::http::Request::builder()
            .method("GET")
            .uri("http://rewrite.test/api/socket")
            .header("host", "rewrite.test")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .body(())
            .expect("a request");

        let request_buf = build_upgrade_request(&request, &backend_info, "127.0.0.1");

        let request_line = String::from_utf8_lossy(&request_buf)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            request_line, "GET /v2/socket HTTP/1.1",
            "the upgrade did not go out with the route's rewritten path"
        );
    }

    /// The upgrade is the point of the request, so `upgrade` and `connection`
    /// have to reach the backend — and a credential for *this* proxy must not.
    #[tokio::test]
    async fn a_websocket_upgrade_carries_the_upgrade_and_not_the_proxy_credential() {
        let config = route_table_with_rewrite("/api", "/v2{}");

        let backend_info = config
            .get_backend_with_acl("rewrite.test", "/api/socket", None, None)
            .await
            .backend()
            .expect("a route for the host");

        let request = ::http::Request::builder()
            .method("GET")
            .uri("http://rewrite.test/api/socket")
            .header("host", "rewrite.test")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("proxy-authorization", "Basic c2VjcmV0")
            .header("proxy-authenticate", "Basic")
            .header("proxy-connection", "keep-alive")
            .body(())
            .expect("a request");

        let request_buf = build_upgrade_request(&request, &backend_info, "127.0.0.1");
        let sent = String::from_utf8_lossy(&request_buf).to_ascii_lowercase();

        assert!(sent.contains("upgrade: websocket"), "{sent}");
        assert!(sent.contains("connection: upgrade"), "{sent}");
        assert!(sent.contains("sec-websocket-key:"), "{sent}");
        for leaked in [
            "proxy-authorization",
            "proxy-authenticate",
            "proxy-connection",
        ] {
            assert!(
                !sent.contains(leaked),
                "{leaked} reached the backend:\n{sent}"
            );
        }
    }

    /// A half-closed client still receives the backend's Close frame.
    ///
    /// A WebSocket close is a half-close: the client sends its Close frame
    /// and shuts its write side down, and the backend's answer — its own
    /// Close frame, echoed back — still has to arrive. The two directions
    /// used to be raced, so the one carrying the answer was dropped the
    /// moment the half-close was seen, and the client never got it. Nothing
    /// shut a write half down either, so the backend saw the connection
    /// disappear rather than a clean end of stream.
    ///
    /// The backend here reads until the client is done, and only then
    /// answers — the shape of a protocol that is carried over a connection
    /// the client may half-close.
    #[tokio::test]
    async fn a_half_closed_client_still_receives_the_close_frame() {
        // Two in-memory pipes: the session gets one end of each, and the test
        // plays the client and the backend from the other ends.
        let (mut client_end, client_side) = tokio::io::duplex(1024);
        let (mut backend_end, backend_side) = tokio::io::duplex(1024);

        let session = tokio::spawn(pump_session(
            client_side,
            backend_side,
            Vec::new(),
            Duration::from_secs(5),
        ));

        // The client: sends its Close frame, then shuts its write side down.
        // That is a half-close, not an ending — the peer may still have an
        // answer on the way.
        let application = async {
            client_end
                .write_all(b"\x88\x00")
                .await
                .expect("the close frame goes out");
            client_end.shutdown().await.expect("the write side closes");
            let mut buf = Vec::new();
            client_end
                .read_to_end(&mut buf)
                .await
                .expect("the echo arrives");
            buf
        };

        // The backend: reads until the client is done, then answers. The end
        // of the stream it sees has to be a clean one — a reset would mean
        // the session tore the connection down instead of closing it.
        let backend = async {
            let mut buf = Vec::new();
            backend_end
                .read_to_end(&mut buf)
                .await
                .expect("the close frame arrives, and the end of the stream with it");
            assert_eq!(buf, b"\x88\x00", "the backend did not see the close frame");
            // The backend may still answer after the client's half-close —
            // that is what a half-close is. A session that tore the
            // connection down instead of closing it fails right here.
            backend_end
                .write_all(b"\x88\x00")
                .await
                .expect("the echo goes out after the client's half-close");
            backend_end.shutdown().await.expect("the backend closes");
        };

        let (received, ()) = tokio::join!(application, backend);
        assert_eq!(
            received, b"\x88\x00",
            "the close echo did not survive the half-close"
        );

        let ended = tokio::time::timeout(Duration::from_secs(5), session).await;
        assert!(ended.is_ok(), "the session never ended");
    }

    /// A session nobody is using ends on its own.
    ///
    /// The idle window is what ends it: nothing has moved in either direction
    /// for a whole window, so there is nothing left to wait for.
    #[tokio::test]
    async fn a_session_nobody_uses_ends_on_its_own() {
        let (_client_end, client_side) = tokio::io::duplex(1024);
        let (_backend_end, backend_side) = tokio::io::duplex(1024);

        let session = tokio::spawn(pump_session(
            client_side,
            backend_side,
            Vec::new(),
            Duration::from_millis(100),
        ));

        let ended = tokio::time::timeout(Duration::from_secs(5), session).await;
        assert!(ended.is_ok(), "the session never ended");
    }

    /// A quiet direction does not end a session the other one is using.
    ///
    /// A client that only listens to a feed the backend keeps pushing has
    /// nothing to say, and the gap in its direction must not end the session:
    /// the idle window is measured over both directions, so what counts is
    /// whether anything moved at all.
    #[tokio::test]
    async fn a_quiet_direction_does_not_end_a_session_the_other_one_is_using() {
        let (_client_end, client_side) = tokio::io::duplex(1024);
        let (mut backend_end, backend_side) = tokio::io::duplex(1024);

        let session = tokio::spawn(pump_session(
            client_side,
            backend_side,
            Vec::new(),
            Duration::from_millis(200),
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
            // And then it stops, so the session can end on its idle window.
            backend_end.shutdown().await.expect("the backend closes");
        });

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !session.is_finished(),
            "a quiet client ended a session the backend was still using"
        );

        let ended = tokio::time::timeout(Duration::from_secs(5), session).await;
        assert!(ended.is_ok(), "the session never ended");
        push.await.expect("the backend finished");
    }
}
