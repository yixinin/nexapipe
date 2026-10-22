use crate::auth::{
    AuthConfig, AuthError, AuthMessage, ClientAcl, DeviceAuth, TotpValidator,
    is_presentable_client_id, is_presentable_device_id,
};
use crate::config::{BackendProtocol, Timeouts};
use crate::config_watcher::save_auth_state;
use crate::http;
use crate::http::BackendClients;
use crate::l4;
use crate::metrics;
use crate::passthrough;
use crate::routes::{BackendInfo, BackendLookup, RoutingTable};
use crate::shutdown::InFlightGuard;
use ::http::Request;
use futures_util::StreamExt;
use iroh::endpoint::{Connection, Incoming};
use nexapipe_proto::auth::Format;
use nexapipe_proto::secret::SecretString;
use peers::{PeerGuard, PeerIdentity, PeerRegistry};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Instrument;

pub mod allow_list;
pub mod limits;
pub mod peers;

use limits::Limiters;

/// How long the server waits for the client to open the 2FA handshake stream.
///
/// A client that has credentials sends AUTH_START right after the QUIC
/// handshake finishes, so in principle this only has to cover one round trip.
/// In practice the deadline also has to absorb the handshake itself: on a slow
/// or relayed link the QUIC handshake plus the client's first stream can take
/// several round trips, and a client that loses this race is closed with
/// `auth_close_code::REQUIRED` — indistinguishable from a client that never had
/// a credential — so it is deliberately generous. Five seconds is still short
/// enough that a peer which completes the QUIC handshake and then sends
/// nothing — one with no 2FA configured — does not keep its connection and the
/// task serving it alive indefinitely.
const AUTH_HANDSHAKE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);

/// How long the server holds a connection open after refusing it, so the
/// AUTH_FAILED it just wrote can reach the client.
///
/// `Rejected` closes the connection the moment this returns, and that close
/// races the bytes carrying the verdict: when the close wins, the client sees
/// "connection lost" instead of "Invalid TOTP code", and cannot tell a wrong
/// client_id from a server that went away. Waiting for the peer — which closes
/// the connection itself once it has read the refusal — removes that guesswork.
///
/// It is deliberately small: this wait happens inside
/// [`AUTH_HANDSHAKE_TIMEOUT`], which still has to cover the three earlier round
/// trips on a slow link.
const AUTH_RESULT_GRACE: tokio::time::Duration = tokio::time::Duration::from_millis(500);

/// The largest AUTH_* message the server accepts.
///
/// The length prefix is the first four bytes of whatever stream arrives first,
/// so it is attacker- and bug-controlled: a client that opens a data stream
/// instead of the auth stream would otherwise make the server allocate up to
/// 4 GiB before reading anything.
const MAX_AUTH_MESSAGE: usize = 64 * 1024;

/// Streams one connection may have in flight at once.
///
/// Every accepted bi-stream spawns a task, and `accept_bi` accepts them as fast
/// as the peer opens them, so without a cap here the task count is the peer's
/// choice. `FlowLimiter` covers L4 flows only; HTTP, WebSocket and passthrough
/// streams take this one. Sized to match the L4 default so the two read as one
/// policy on how much a single connection may ask for.
const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 256;

/// Application error codes the server closes a connection with when 2FA fails.
///
/// These travel in the CONNECTION_CLOSE frame, so a client can read them from
/// its `close_reason()` and tell "you never authenticated" apart from "your code
/// was rejected" — the difference between a misconfigured client and a wrong
/// TOTP code. Keep in sync with `AUTH_REQUIRED_CLOSE_CODE` in
/// `crates/nexapipe-client/src/connection_pool.rs`.
pub(crate) mod auth_close_code {
    /// No AUTH_START arrived within the handshake deadline: the server requires
    /// 2FA the client did not perform.
    pub const REQUIRED: u32 = 2;
    /// The handshake ran, but the client is unknown or its code was rejected.
    pub const REJECTED: u32 = 3;
    /// The peer already holds as many connections as it is allowed, so this one
    /// is closed without any traffic being served on it.
    pub const TOO_MANY: u32 = 4;
    /// The credential this connection authenticated with is gone: `nexapipe
    /// client revoke` struck the client, or the device, out of `[auth]` while
    /// this connection was open. Five belongs to `[peers]` in
    /// [`crate::conn::allow_list`], which is why the numbers are not adjacent.
    pub const REVOKED: u32 = 6;
}

/// The live 2FA state a connection authenticates against.
///
/// The config is shared: every connection reads it to validate, and the ones
/// that fail write their lockout counters back into it. Two files are
/// involved: the configuration, which is the operator's and holds the
/// credentials, and the state file beside it, which holds the counters the
/// server counted. The path is the configuration's — the enrollment flow
/// writes a token into it — and the state path is derived from it.
#[derive(Clone)]
pub struct AuthState {
    config: Arc<tokio::sync::RwLock<AuthConfig>>,
    path: String,
    state_path: String,
    /// How many enrollments have been applied to the live config.
    ///
    /// The configuration watcher reads the file **before** it takes the lock
    /// that guards the live config, and an enrollment that lands in between
    /// would be undone by the merge: it spends a token by changing the live
    /// state and only then writing the change back, so a snapshot taken a
    /// moment earlier still carries the spent token and the pre-enrollment
    /// secret.
    ///
    /// This counter is the witness. It is sampled before the read and compared
    /// under the lock, and the two cannot disagree about what happened — which
    /// holds only because the counter moves **after** the enrollment's write
    /// has landed, still under the lock. A counter bumped at the start of an
    /// enrollment could be sampled by a reload that then read the file before
    /// the write, and the stale snapshot would look current.
    enroll_epoch: Arc<std::sync::atomic::AtomicU64>,
}

impl AuthState {
    /// Wraps a freshly loaded config together with the file it came from.
    pub fn new(config: AuthConfig, path: impl Into<String>) -> Self {
        let path = path.into();
        let state_path = crate::auth::state::path_for(&path)
            .to_string_lossy()
            .into_owned();
        Self {
            config: Arc::new(tokio::sync::RwLock::new(config)),
            path,
            state_path,
            enroll_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// How many enrollments have been applied to the live config so far.
    ///
    /// Sampled before a read of the file and compared under the lock, to see
    /// whether an enrollment landed while the file was being read.
    pub fn enroll_epoch(&self) -> u64 {
        self.enroll_epoch.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Records that an enrollment has been applied to the live config.
    ///
    /// Called under the same lock the enrollment itself holds, and only after
    /// the enrollment's write to the config file has landed: the watcher
    /// samples this before it reads that file, so a bump that came first would
    /// let the read see the file as it was before the enrollment and still
    /// look current.
    pub fn bump_enroll_epoch(&self) {
        self.enroll_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// The shared config to validate against.
    pub fn config(&self) -> &Arc<tokio::sync::RwLock<AuthConfig>> {
        &self.config
    }

    /// The config file the enrollment token is written to.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The state file the runtime counters are persisted to.
    ///
    /// Beside the configuration rather than inside it: the counters are what
    /// the server learned while it was running, and writing them into the
    /// operator's file would move its modification time every time a client
    /// mistyped a code — which the configuration watcher watches, so a
    /// lockout was a configuration reload.
    pub fn state_path(&self) -> &str {
        &self.state_path
    }
}

/// Finds the end of a header block, scanning from `from`.
///
/// `from` is what keeps a head that arrives in many small reads off O(n²):
/// the bytes before it were already scanned on an earlier read, so without it
/// every read rescanned the whole buffer, and a head delivered one segment at
/// a time cost a full pass per segment.
fn find_headers_end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| from + pos)
}

/// The two deadlines an iroh stream starts with.
///
/// The first byte says which protocol a stream carries, and the wait for it
/// is not the HTTP head's: `header_secs` bounds an HTTP request head, and a
/// TLS or L4 client that is slow to speak must not be cut off by it. Those two
/// protocols have their own budgets, and a client on them never sends a
/// request head at all.
///
/// Until the byte arrives the protocol is unknown, so the wait is the longer
/// of the two budgets — the head's, because an HTTP client may take that long
/// to start, and the hello's, because a TLS client may take that long and is
/// not an HTTP client at all. The head itself is still bounded by
/// `header_secs` from the moment the stream opened, so a client that trickles
/// a head renews nothing.
struct StreamBudgets {
    /// The whole request head, from the moment the stream opened.
    head: tokio::time::Instant,
    /// The first byte, which says which protocol this stream carries.
    identify: tokio::time::Instant,
    /// When the stream opened, so the budgets can be reported in seconds.
    open: tokio::time::Instant,
}

impl StreamBudgets {
    fn new(deadlines: &crate::deadline::Deadlines, open: tokio::time::Instant) -> Self {
        Self {
            head: open + deadlines.header,
            identify: open + deadlines.header.max(deadlines.tls_hello),
            open,
        }
    }

    /// How long the first byte may take.
    fn identify_budget(&self) -> std::time::Duration {
        self.identify - self.open
    }

    /// How long the head may take, from the moment the stream opened.
    fn head_budget(&self) -> std::time::Duration {
        self.head - self.open
    }
}

/// What the first bytes of a stream turned out to be.
#[derive(Debug)]
enum StreamHead {
    /// An HTTP request head, and the bytes that arrived with it.
    Request { head: Vec<u8>, body: Vec<u8> },
    /// Not an HTTP request: an L4 preface or a TLS ClientHello. The bytes are
    /// handed on unconsumed, because the client may have sent its first
    /// payload in the same segment.
    Other(Vec<u8>),
    /// The head was over the limit, and this is how large it had grown.
    TooLarge(usize),
    /// The peer went away before the head was finished.
    Incomplete,
}

/// Reads the head of a request off a stream.
///
/// Generic over the reader so that the whole path can be driven from a test
/// with a `duplex` pair, the way the L4 preface is: the rules decided here are
/// worth more than the I/O around them, and the I/O is the part that is hard
/// to reproduce on demand.
///
/// The rules are three, and each of them used to be a different accident:
///
/// * a head over the limit is **refused** — it used to be parsed anyway, with
///   its last line truncated into a header that looked valid;
/// * a head the peer abandoned is **not a request** — it used to be parsed and
///   forwarded, so half a request line became a header;
/// * a head that finished is a request, and the bytes after it are kept.
async fn read_stream_head<R>(
    recv: &mut R,
    budgets: &StreamBudgets,
) -> Result<StreamHead, anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // Doubling on demand, so a head that fits in one read never pays for a
    // bigger buffer while a large one still gets there in a few reallocs.
    // Pre-allocating the 64 KB limit would take that much from every stream.
    let mut buf = Vec::with_capacity(8192);
    let mut read_buf = [0u8; 8192];
    let mut body_data = Vec::new();
    // How much of `buf` has already been scanned for the end of the headers.
    let mut searched = 0usize;

    let header_secs = budgets.head_budget().as_secs();
    let identify_secs = budgets.identify_budget().as_secs();

    // The first read identifies the protocol and is bounded by the budget
    // above; every read after it is part of the head and is bounded by the
    // head's own deadline.
    let mut identifying = true;
    loop {
        let (deadline, secs, what) = if identifying {
            identifying = false;
            (budgets.identify, identify_secs, "first byte")
        } else {
            (budgets.head, header_secs, "request head")
        };
        let read = tokio::time::timeout_at(deadline, recv.read(&mut read_buf)).await;
        match read {
            // Zero bytes is the end of the stream, which is the reader's way of
            // saying the peer is gone.
            Ok(Ok(0)) => return Ok(StreamHead::Incomplete),
            Ok(Ok(n)) => {
                buf.extend_from_slice(&read_buf[..n]);

                // An L4 tunnel says so in its first byte, so it is recognised
                // rather than sniffed, and a TLS session is not a request at
                // all. Both are handed on with the bytes they came with.
                if buf
                    .first()
                    .is_some_and(|b| l4::is_l4_stream(*b) || passthrough::is_tls_handshake(*b))
                {
                    return Ok(StreamHead::Other(buf));
                }

                if let Some(pos) = find_headers_end(&buf, searched) {
                    let headers_end = pos + 4;
                    if buf.len() > headers_end {
                        body_data.extend_from_slice(&buf[headers_end..]);
                    }
                    buf.truncate(headers_end);
                    return Ok(StreamHead::Request {
                        head: buf,
                        body: body_data,
                    });
                }

                // The marker can straddle two reads, so the last three bytes
                // are looked at again; everything before them cannot start a
                // marker that was not already ruled out.
                searched = buf.len().saturating_sub(3);

                if buf.len() > 64 * 1024 {
                    return Ok(StreamHead::TooLarge(buf.len()));
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                return Err(anyhow::anyhow!("no {} within {}s", what, secs));
            }
        }
    }
}

// One more argument than clippy allows, and bundling them into a struct would
// just move the list somewhere else while making every call site build one. The
// id is last because it is the newest thing this stream carries.
#[allow(clippy::too_many_arguments)]
pub async fn handle_bidi_stream(
    mut send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    config: &RoutingTable,
    clients: &BackendClients,
    limiter: &Arc<l4::FlowLimiter>,
    peer: &str,
    acl: Option<Arc<ClientAcl>>,
    request_id: &str,
    // Who the connection authenticated as, for the access log. Empty with 2FA
    // off, and for a library embedder that never built an `AuthState`, which is
    // what the access log prints nothing for.
    who: PeerIdentity,
) -> anyhow::Result<()> {
    let mut recv = recv;

    // A phase deadline over the whole head, taken once and never renewed: a
    // peer that drips one byte before each expiry renews nothing. The bound is
    // `[timeouts] header_secs` through the routes.
    let timeouts = config.timeouts();
    let open = tokio::time::Instant::now();
    let budgets = StreamBudgets::new(&timeouts.deadlines, open);

    let (buf, body_data) = match read_stream_head(&mut recv, &budgets).await {
        Ok(StreamHead::Request { head, body }) => (head, body),

        Ok(StreamHead::Other(bytes)) => {
            // An L4 tunnel says so in its first byte, so it is recognised
            // rather than sniffed. This has to happen before the HTTP header
            // loop: a preface is not a request line, and the client may send
            // its first payload in the same segment, which the bytes already
            // hold and must hand over intact.
            if bytes.first().is_some_and(|b| l4::is_l4_stream(*b)) {
                return l4::handle_iroh_stream(
                    send,
                    recv,
                    bytes,
                    config,
                    limiter,
                    peer,
                    acl.as_deref(),
                    request_id,
                    Some(&who),
                )
                .await;
            }
            // TLS is terminated by the backend, so a ClientHello is not a
            // request: hand the raw bytes (and both halves of the stream) to
            // the passthrough path, which routes on SNI.
            return passthrough::handle_iroh_stream(send, recv, bytes, config, acl.as_deref())
                .await;
        }

        Ok(StreamHead::TooLarge(size)) => {
            // Refused, not served. This used to `break` out of the read loop
            // with a head that was never finished, and the parser below read
            // that as a request: every line of it became a header, the last
            // one with a truncated value, and the request was forwarded to a
            // backend. The log said "headers too large" and the backend was
            // asked anyway.
            tracing::warn!("Request headers too large: {} bytes, refusing", size);
            let mut send = send;
            let written = send
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            let _ = send.finish();
            if written.is_ok() {
                metrics::METRICS.record_request(431, 0);
                crate::log::log_access(request_id, peer, "-", "-", 431, 0, 0, Some(&who));
            }
            return Ok(());
        }

        Ok(StreamHead::Incomplete) => {
            // The peer went away before the head was finished. There is nobody
            // to answer, and what arrived is not a request: the parser would
            // read the lines of a half-written head as headers and forward
            // them.
            tracing::debug!(
                "Stream from {} ended before the request head was complete",
                peer
            );
            return Ok(());
        }

        Err(e) => {
            tracing::warn!("No request head from {}: {}", peer, e);
            return Err(e);
        }
    };

    tracing::debug!("Iroh stream data received - bytes_read: {}", buf.len());

    // A request that does not parse is refused with a status the client can
    // read, rather than a stream that is dropped under it. A malformed
    // request — and a request that names more than one host, which the parser
    // refuses for the same reason — used to leave the client with a reset and
    // nothing in the access log.
    let request = match http::parse_http_request_legacy(&buf) {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!("Refusing a malformed request from {}: {}", peer, e);
            let mut send = send;
            let written = send
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            let _ = send.finish();
            if written.is_ok() {
                metrics::METRICS.record_request(400, 0);
                crate::log::log_access(request_id, peer, "-", "-", 400, 0, 0, Some(&who));
            }
            return Ok(());
        }
    };

    // Everything before the blank line is bytes the client sent, and it is the
    // only place the request head exists as bytes: from here on it is a parsed
    // request, and nobody downstream can say how large it was on the wire.
    // Counted before any routing, so a request whose body never arrives still
    // reports what did — the same trade the access log makes.
    metrics::METRICS.record_bytes_received(buf.len() as u64);

    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(crate::routes::host_and_port);

    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path());

    // No `Host` header — HTTP/1.0, or a malformed request — means no route can
    // be matched, because every route, including a `host_pattern = "*"`
    // catch-all, is selected by host. There is nothing to serve it with.
    // Answered, not raised: no `Host` means nothing to look up, and it is worth
    // no less here than in `http::proxy_request`.
    let lookup: BackendLookup<BackendInfo> = match host {
        Some((h, port)) => {
            config
                .get_backend_with_acl(h, path, port, acl.as_deref())
                .await
        }
        None => BackendLookup::NoRoute,
    };

    // The verdict comes **before** the body is read.
    //
    // A request for a host no route serves has nothing to forward to, and
    // reading its body first is work nobody asked for: up to
    // `MAX_REQUEST_BODY` (64 MiB) per stream, held in memory, for a request
    // that is going to be refused. The bytes that arrived with the head are
    // dropped along with it.
    //
    // The plaintext listener already does it this way round — the lookup,
    // then the body — so the two paths now agree.
    //
    // Which refusal it is decides the status, and nothing else — the writing
    // and the logging below are the same either way. 404: nothing serves this
    // name. 503: the route is there and every backend behind it is down, which
    // is not something the client can fix by asking again for a different host.
    let unavailable = matches!(lookup, BackendLookup::Unavailable);
    let status = if unavailable { 503 } else { 404 };
    let headline = if unavailable {
        "HTTP/1.1 503 Service Unavailable"
    } else {
        "HTTP/1.1 404 Not Found"
    };

    let Some(backend_info) = lookup.backend() else {
        tracing::warn!(
            "Refusing host={:?}: {}, answering {}",
            host,
            if unavailable {
                "no healthy backend behind a route that matches"
            } else {
                "no route matches"
            },
            status
        );
        let mut send = send;
        let written = send
            .write_all(
                format!("{headline}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").as_bytes(),
            )
            .await;
        let _ = send.finish();
        match written {
            Ok(()) => {
                // Counted and logged for either status, and only when the answer
                // reached the client: a refusal nobody received is not a request
                // this instance served.
                metrics::METRICS.record_request(status, 0);
                crate::log::log_access(
                    request_id,
                    peer,
                    request.method().as_str(),
                    request.uri().path(),
                    status,
                    0,
                    0,
                    Some(&who),
                );
            }
            Err(e) => {
                tracing::debug!(
                    "Refusal for host={:?} ({}) could not be written: {}",
                    host,
                    status,
                    e
                );
            }
        }
        return Ok(());
    };

    // The body is read once, before the first attempt: the bytes come off the
    // client's stream, and that stream has them only once. A retry sends the
    // same bytes again, which is only possible because they were kept.
    //
    // A WebSocket upgrade has no body to read: the session starts where the
    // head ends, and the bytes after it are frames.
    let body = if http::is_websocket_request_static(&request) {
        None
    } else {
        match http::read_request_body(&request, &mut recv, body_data, config.timeouts()).await {
            Ok(body) => Some(body),
            Err(failure) => {
                // The request never went anywhere: there is no backend to
                // blame and no answer to give but the refusal.
                tracing::error!("Could not read the request body: {}", failure.error);
                let mut send = send;
                let _ = send.finish();
                return Err(failure.error);
            }
        }
    };

    tracing::debug!(
        "Request: host={:?}, path={} -> backend={}",
        host,
        path,
        backend_info.url
    );
    // The access log has to be fed from here: this is the path every client
    // takes, and the HTTP server on the plaintext listener logs its own.
    let started = std::time::Instant::now();
    let method = request.method().to_string();
    let request_target = request.uri().to_string();

    // The same string the access log and the span use, redacted the same way.
    // This line reaches the general log file, which is the same file the span's
    // fields are rendered into — so a URI logged here unredacted is a query
    // value in that file, and redacting only the span would leave this door
    // open next to it.
    tracing::debug!(
        "Received request: {} {}",
        request.method(),
        crate::log::uri_for_log(&request_target)
    );

    // Filled in on the span the caller opened, which was created before the
    // head was read and so could not know these. `Span::current()` is that
    // span because the caller instruments this future with it; when no
    // subscriber cares, recording is a no-op rather than a cost.
    let span = tracing::Span::current();
    crate::log::record_request_on_span(&span, &method, &request_target);

    // A WebSocket upgrade is a conversation, and half of it cannot be taken
    // back: it is never retried, and it does not go through the loop below.
    let outcome: Result<http::ProxySummary, http::ProxyFailure> =
        if http::is_websocket_request_static(&request) {
            tracing::debug!("WebSocket request detected");
            match handle_websocket_stream(
                send,
                recv,
                &request,
                clients,
                &backend_info,
                config.timeouts(),
            )
            .await
            {
                Ok(summary) => {
                    // The backend answered the upgrade, so it is up.
                    backend_info.report_success();
                    Ok(summary)
                }
                Err(failure) => {
                    // A failed dial or handshake says the backend is
                    // unreachable; a session that dies after the upgrade says
                    // nothing about that. This path is never retried, but the
                    // circuit still learns from the first case.
                    if failure.backend_is_down() {
                        backend_info.report_failure();
                    }
                    Err(failure)
                }
            }
        } else {
            let body = body
                .as_ref()
                .expect("the body of a request that is not a WebSocket is read above");
            let attempts = config.retry().attempts;
            let backoff = config.retry().backoff;
            // The backends that already failed this request. A retry asks
            // somebody else, because the one that just failed is the one most
            // likely to fail again.
            let mut tried: Vec<String> = Vec::new();
            let mut attempt = 0u32;
            let mut backend = backend_info;

            loop {
                let result = http::proxy_to_backend_streaming(
                    clients,
                    config.timeouts(),
                    &request,
                    &backend,
                    body,
                    &mut send,
                    request_id,
                )
                .await;

                let failure = match result {
                    Ok(summary) => {
                        // The backend answered, so it is up: the circuit is
                        // told, and a backend that was out of rotation comes
                        // back into it.
                        backend.report_success();
                        break Ok(summary);
                    }
                    Err(failure) => failure,
                };

                // Only a failure that says the backend is unreachable counts
                // against it. A response that broke halfway is a different
                // thing: the backend did answer.
                if failure.backend_is_down() {
                    backend.report_failure();
                }

                // Two questions, and the failure answers both: may this be
                // tried again at all, and is there another backend to try it
                // on.
                if attempt >= attempts || !failure.retry.may_retry(request.method()) {
                    break Err(failure);
                }
                attempt += 1;

                tracing::warn!(
                    "Request to {} failed ({}); trying another backend ({attempt}/{attempts})",
                    backend.url,
                    failure.error,
                );

                tried.push(backend.url.to_string());
                let next = match host {
                    Some((h, port)) => {
                        config
                            .get_backend_with_acl_excluding(h, path, port, acl.as_deref(), &tried)
                            .await
                    }
                    None => BackendLookup::NoRoute,
                };
                match next.backend() {
                    Some(info) => backend = info,
                    // Nobody else to ask. The failure is the answer: the pool
                    // being empty is a consequence of it, not a new fact.
                    None => break Err(failure),
                }

                if !backoff.is_zero() {
                    tokio::time::sleep(backoff).await;
                }
            }
        };

    let elapsed_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(summary) => {
            metrics::METRICS.record_request(summary.status, elapsed_ms);
            // The same number the log line below prints, taken from the same
            // place, rather than counted again off the wire. `crate::http`
            // knows how much of a response reached the client — it has to, the
            // access log says so — and it counts only what landed, including
            // the partial answer when a stream died mid-body.
            metrics::METRICS.record_bytes_sent(summary.bytes_sent as u64);
            span.record("status", summary.status as u64);
            crate::log::log_access(
                request_id,
                peer,
                &method,
                &request_target,
                summary.status,
                elapsed_ms,
                summary.bytes_sent,
                Some(&who),
            );
            Ok(())
        }
        Err(failure) => {
            // What the client was actually told, when it was told anything. A
            // failure after the head went out is not a 502 — the backend
            // answered and part of the answer arrived — and logging it as one
            // sends whoever reads the log looking for a broken backend.
            let (status, bytes_sent) = match failure.partial {
                Some(partial) => (partial.status, partial.bytes_sent),
                None => (502, 0),
            };
            metrics::METRICS.record_request(status, elapsed_ms);
            // Same source, same reason, including that there may have been no
            // partial answer at all: nothing was served, so nothing is counted.
            metrics::METRICS.record_bytes_sent(bytes_sent as u64);
            span.record("status", status as u64);
            crate::log::log_access(
                request_id,
                peer,
                &method,
                &request_target,
                status,
                elapsed_ms,
                bytes_sent,
                Some(&who),
            );
            Err(failure.error)
        }
    }
}

// Both of these used to be constants, at exactly the values `[timeouts]`
// defaults to. They are not the client's bytes or its own handshake, they are
// the backend's: dialing it, and waiting for it to answer — which is what
// `connect` and `response` already mean for a plain HTTP request. Leaving them
// out would make the same two waits configurable for one kind of request and not
// another, which nobody reading the config could guess.

/// The upgrade request as it goes to the backend.
///
/// The path is the one the route rewrote it to: a route that names a
/// `path_rewrite` means it for every request it serves, and an upgrade is a
/// request too. The plaintext listener answers an upgrade with 426, so this
/// is the only place a WebSocket is ever served — and it used to forward the
/// path the client asked for, without the rewrite.
///
/// The headers are the client's own, minus the `Host`, which is rewritten to
/// the one the client asked for — the backend answers on the name the client
/// used, not on the name it is reached by.
fn build_websocket_upgrade_request(
    req: &Request<()>,
    backend_info: &BackendInfo,
    backend_host: &str,
) -> Vec<u8> {
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());
    let path = backend_info.rewritten_path(path);

    let request_line = format!("{} {} HTTP/1.1\r\n", req.method(), path);

    let original_host = req
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

    for (name, value) in req.headers() {
        if name.as_str().to_lowercase() == "host" {
            continue;
        }
        if !forwards_websocket_header(name.as_str()) {
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

/// Whether a header may be forwarded in a WebSocket upgrade request.
///
/// The hop-by-hop set, except for the two the upgrade is made of: switching
/// protocols is exactly what this request is asking the backend for, so
/// `upgrade` and `connection` have to reach it.
///
/// Everything else goes — the proxy authentication headers most of all,
/// because they are a credential for *this* proxy and the backend has no
/// business seeing them.
fn forwards_websocket_header(name: &str) -> bool {
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

/// How much of a WebSocket's stream is moved at a time.
///
/// The HTTP path coalesces into 64 KiB before it writes; the WebSocket path
/// used to move 8 KiB at a time, which is one QUIC frame and one wake-up for
/// every 8 KiB of the stream.
const WS_COPY_BUFFER: usize = 64 * 1024;

/// The current time in milliseconds, from a fixed base.
///
/// The WebSocket tunnel has to know when the last byte moved, and it has to
/// know it from two tasks at once, so the answer has to fit in an atomic.
///
/// The base is a **monotonic** clock, and it has to be: this measures an
/// interval, and the wall clock can step. A step backwards would suspend the
/// bound — the session would never be found quiet — and a step forwards
/// would end a session that was still carrying traffic.
fn now_millis() -> u64 {
    static BASE: OnceLock<std::time::Instant> = OnceLock::new();
    let base = BASE.get_or_init(std::time::Instant::now);
    base.elapsed().as_millis() as u64
}

/// Returns the status the client was answered with: 101 once the tunnel is up,
/// or whatever the backend answered when it refused the upgrade. Bytes are the
/// handshake response only — once both directions are piped the session has no
/// finite length to report.
async fn handle_websocket_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    req: &Request<()>,
    clients: &BackendClients,
    backend_info: &BackendInfo,
    timeouts: Timeouts,
) -> Result<http::ProxySummary, http::ProxyFailure> {
    let backend_url = &*backend_info.url;
    let protocol = backend_info.protocol;
    let url =
        url::Url::parse(backend_url).map_err(|e| anyhow::anyhow!("invalid backend URL: {}", e))?;

    if protocol == BackendProtocol::H2c {
        // A WebSocket upgrade is HTTP/1.1. A route that speaks h2c has told
        // the server its backend starts with HTTP/2's connection preface, and
        // there is no way to carry an HTTP/1.1 upgrade on that connection.
        return Err(http::ProxyFailure::from(anyhow::anyhow!(
            "backend {backend_url} is reached with backend_protocol = \"h2c\", which cannot \
             carry a WebSocket upgrade; use an http:// or https:// backend that speaks HTTP/1.1"
        )));
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?;
    let port = url.port_or_known_default().unwrap_or(80);

    // Not the pooled HTTP client: a WebSocket holds one dedicated connection
    // for the whole session, so this dial is its own, with the same deadline.
    // It is still the same trust store: an https:// backend is reached over a
    // TLS session this process originates and verifies, exactly as the pooled
    // clients do.
    let mut backend_stream = clients
        .connect_stream(backend_url, timeouts.connect)
        .await
        .map_err(|e| http::ProxyFailure::unanswered(e, http::Retryability::Always))?;

    let request_buf = build_websocket_upgrade_request(req, backend_info, host);

    backend_stream.write_all(&request_buf).await.map_err(|e| {
        http::ProxyFailure::unanswered(
            anyhow::anyhow!("failed to write the WebSocket upgrade: {e}"),
            http::Retryability::Always,
        )
    })?;

    let mut response_buf = Vec::with_capacity(8192);
    let mut trailing_ws_data = Vec::new();
    let mut read_buf = [0u8; 8192];
    // See the request loop: the handshake response arrives in reads of its
    // own, and the marker is only ever in the part that has not been scanned.
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
                            trailing_ws_data.extend_from_slice(&response_buf[headers_end..]);
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
                    tracing::debug!("Failed to read from backend stream: {}", e);
                    return Err(anyhow::anyhow!(
                        "failed to read the handshake response: {}",
                        e
                    ));
                }
            }
        }
        Ok(())
    };

    match tokio::time::timeout(timeouts.response, read_handshake).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(http::ProxyFailure::unanswered(
                e,
                http::Retryability::Always,
            ));
        }
        Err(_) => {
            return Err(http::ProxyFailure::unanswered(
                anyhow::anyhow!(
                    "backend {}:{} did not answer the WebSocket handshake within {:?}",
                    host,
                    port,
                    timeouts.response
                ),
                http::Retryability::Always,
            ));
        }
    }

    let response = http::parse_http_response_legacy(&response_buf)?;
    let handshake_bytes = response_buf.len() + trailing_ws_data.len();
    if response.status().as_u16() == 101 {
        tracing::debug!("WebSocket handshake successful with backend");
        send.write_all(&response_buf).await.map_err(|e| {
            http::ProxyFailure::from(anyhow::anyhow!(
                "failed to write the WebSocket handshake: {e}"
            ))
        })?;
        if !trailing_ws_data.is_empty() {
            tracing::debug!(
                "WebSocket handshake response contained {} trailing bytes",
                trailing_ws_data.len()
            );
            send.write_all(&trailing_ws_data).await.map_err(|e| {
                http::ProxyFailure::from(anyhow::anyhow!(
                    "failed to write the WebSocket handshake: {e}"
                ))
            })?;
        }

        let (backend_read, mut backend_write) = tokio::io::split(backend_stream);

        // How long the session may be **quiet** — with both sides quiet at
        // once. A WebSocket that is idle in one direction is still a
        // WebSocket: a client that only listens to a feed the backend keeps
        // pushing has nothing to say, and a gap in one direction must not end
        // a session the other direction is still using. What ends it is the
        // case the copy loop used to wait for for ever — neither side has
        // moved for a whole window.
        let idle = timeouts.deadlines.response_idle;

        // When the last byte moved on this tunnel, in milliseconds since the
        // epoch. Both directions write to it, and a direction that has been
        // quiet for a whole window reads it to find out whether the other one
        // is still talking.
        let last_traffic = Arc::new(AtomicU64::new(now_millis()));

        let iroh_to_backend = async {
            // **64 KiB**, like the HTTP path's coalescing buffer: the copy
            // loop used to move 8 KiB at a time, which is one QUIC frame and
            // one wake-up for every 8 KiB of a stream.
            let mut buf = vec![0u8; WS_COPY_BUFFER];
            loop {
                match tokio::time::timeout(idle, recv.read(&mut buf)).await {
                    Ok(Ok(None)) => return "iroh_finished",
                    Ok(Ok(Some(n))) => {
                        last_traffic.store(now_millis(), Ordering::Relaxed);
                        if let Err(e) = backend_write.write_all(&buf[..n]).await {
                            tracing::debug!("WebSocket backend write failed: {}", e);
                            return "backend_write_error";
                        }
                        crate::metrics::METRICS.record_bytes_received(n as u64);
                    }
                    Ok(Err(_)) => return "iroh_read_error",
                    Err(_) => {
                        // This direction has been quiet for a whole window. The
                        // session ends when nothing has moved in either
                        // direction for that long; until then the other side is
                        // still using it.
                        let quiet_for =
                            now_millis().saturating_sub(last_traffic.load(Ordering::Relaxed));
                        if quiet_for >= idle.as_millis() as u64 {
                            return "idle";
                        }
                        // The other side is still talking: wait for more, with
                        // the window measured from now.
                        continue;
                    }
                }
            }
        };

        let backend_to_iroh = async {
            let mut buf = vec![0u8; WS_COPY_BUFFER];
            let mut backend_read = backend_read;
            loop {
                match tokio::time::timeout(idle, backend_read.read(&mut buf)).await {
                    Ok(Ok(0)) => return "backend_finished",
                    Ok(Ok(n)) => {
                        last_traffic.store(now_millis(), Ordering::Relaxed);
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            tracing::debug!("WebSocket iroh write failed: {}", e);
                            return "iroh_write_error";
                        }
                        crate::metrics::METRICS.record_bytes_sent(n as u64);
                    }
                    Ok(Err(_)) => return "backend_read_error",
                    Err(_) => {
                        // The same bound as the other direction, and the same
                        // reading of it: a quiet direction does not end a
                        // session the other one is still using.
                        let quiet_for =
                            now_millis().saturating_sub(last_traffic.load(Ordering::Relaxed));
                        if quiet_for >= idle.as_millis() as u64 {
                            return "idle";
                        }
                        continue;
                    }
                }
            }
        };

        let (closed_direction, close_reason) = tokio::select! {
            reason = iroh_to_backend => ("iroh_to_backend", reason),
            reason = backend_to_iroh => ("backend_to_iroh", reason),
        };
        tracing::debug!(
            "WebSocket tunnel closed first by {}, reason: {}",
            closed_direction,
            close_reason
        );
    } else {
        tracing::debug!(
            "WebSocket handshake failed with backend, status: {}",
            response.status()
        );
        send.write_all(&response_buf).await.map_err(|e| {
            http::ProxyFailure::from(anyhow::anyhow!(
                "failed to write the WebSocket handshake: {e}"
            ))
        })?;
        send.finish().map_err(|e| {
            http::ProxyFailure::from(anyhow::anyhow!(
                "failed to finish the WebSocket stream: {e}"
            ))
        })?;

        return Ok(http::ProxySummary {
            status: response.status().as_u16(),
            bytes_sent: response_buf.len(),
        });
    }

    Ok(http::ProxySummary {
        status: 101,
        bytes_sent: handshake_bytes,
    })
}

fn get_connection_type(path: &iroh::endpoint::Path<'_>) -> &'static str {
    if path.is_ip() {
        "Direct"
    } else if path.is_relay() {
        "Relay"
    } else {
        "Unknown"
    }
}

/// Which metrics bucket a path belongs to.
///
/// The same three-way distinction [`get_connection_type`] makes for the log,
/// as the type the counters are keyed by.
fn path_kind(path: &iroh::endpoint::Path<'_>) -> metrics::PathKind {
    if path.is_ip() {
        metrics::PathKind::Direct
    } else if path.is_relay() {
        metrics::PathKind::Relay
    } else {
        metrics::PathKind::Unknown
    }
}

/// Keeps one connection's place in the `connections_by_path` buckets up to
/// date, for as long as the connection lives.
///
/// The ticket is created here and handed back by its `Drop` when this task
/// ends, which is when the path stream ends, which is when the connection is
/// gone: a connection that disappears without a clean close therefore still
/// stops being counted.
async fn track_connection_path(
    conn: Connection,
    initial: metrics::PathKind,
    peer: iroh::EndpointId,
    peers: Arc<PeerRegistry>,
) {
    let mut ticket = metrics::PathTicket::new(initial);

    // Snapshots rather than individual path events: `paths_stream` yields the
    // full current state on every change, so a burst of changes cannot leave
    // the bucket one event behind the way a lagged event stream could.
    let mut stream = conn.paths_stream();
    while let Some(paths) = stream.next().await {
        if let Some(path) = paths.iter().find(|p| p.is_selected()) {
            let kind = path_kind(&path);
            ticket.set(kind);
            // The same fact, in the place that can say *which* peer it is
            // about: a count can tell you two connections are relayed, not
            // that they are these two.
            peers.set_path(&peer, kind);
        }
    }
}

/// Why a 2FA handshake did not produce an authenticated client.
///
/// The difference is what the server closes the connection with, and the client
/// can read it back: [`AuthFailure::NotStarted`] means the client does not know
/// 2FA is required — it never opened the auth stream, so the close is the only
/// way it can ever find out — while [`AuthFailure::Rejected`] means it did
/// authenticate and the credentials were refused.
enum AuthFailure {
    /// No AUTH_START arrived, or the handshake could not be carried out at all.
    NotStarted(String),
    /// The handshake ran and the credentials were refused.
    Rejected(String),
}

/// What one `ENROLL_START` is worth.
///
/// Split out of [`enroll_client`] so the rule can be tested without a
/// connection: acceptance is a question about the config and nothing else, and
/// it is the question the whole invitation scheme rests on.
#[derive(Debug, PartialEq)]
enum EnrollmentVerdict {
    /// The token matches, so the secret may be rotated.
    Accept,
    /// Refused. `counted` says whether this should move the client's lockout
    /// counter along.
    Refuse { counted: bool },
}

impl EnrollmentVerdict {
    fn counted(&self) -> bool {
        matches!(self, EnrollmentVerdict::Refuse { counted: true })
    }
}

/// Decides one enrollment attempt against `cfg`.
///
/// A guess at a token that is actually outstanding is the only thing counted.
/// It is an attempt to spend a credential — the thing a token has to withstand
/// to be worth handing out — and it is what makes the link unguessable rather
/// than merely unshared. Everything else is a guess at nothing: no such client,
/// or one with no token pending. Counting those would let anyone who knows a
/// client id lock that client out of its own authentication by sending it
/// enrollment requests, which is a denial of service handed to a stranger.
///
/// A lockout outranks the token: the client is refused before the comparison
/// runs, so a locked-out client cannot extend its own lockout by retrying, and
/// a wrong code cannot be traded for extra attempts by going through
/// enrollment.
///
/// **What a counted refusal moves is the enrollment's own counter.** A client
/// id is not a secret — it is in the invite link and in whatever the operator
/// pasted into a ticket — so anybody who knows one can send enrollment
/// attempts at a client that is waiting to enroll. Counting those against the
/// client's authentication counter meant the devices that had already enrolled
/// were locked out over a credential they were never sent. The token keeps its
/// ceiling, and the ceiling is paid for by the token.
///
/// A name that is already in the table is refused too. An enrollment token
/// proves the invite reached *someone*, not which device it reached — the name
/// is chosen by the client at enrollment time — so accepting any name turned a
/// copied link into a takeover: enrolling as the name of a device that is
/// already there replaces its credential, which locks the real device out while
/// every log line and the peer list go on showing the real device's name.
/// Rotating one device's credential is the operator's move and has its own
/// `--force`; an enrollment is for a device that is not there yet.
fn enrollment_verdict(
    cfg: &AuthConfig,
    client_id: &str,
    token: &str,
    device: Option<&str>,
) -> EnrollmentVerdict {
    let Some(client) = cfg.clients.get(client_id) else {
        return EnrollmentVerdict::Refuse { counted: false };
    };
    if client.is_locked_out() {
        return EnrollmentVerdict::Refuse { counted: false };
    }
    // The enrollment slot's own lockout, checked the same way. The window
    // belongs to the token: a guess at the token closes the slot for a while,
    // and it does not close the client's authentication — the devices that
    // already hold a credential are not what a stranger is guessing at.
    if client.is_enrollment_locked_out() {
        return EnrollmentVerdict::Refuse { counted: false };
    }
    // An empty token is refused on both sides before the comparison runs.
    // `constant_time_eq` answers true for two empty slices, so a config holding
    // `pending_enrollment = ""` — what an operator naturally writes to "clear"
    // the key — would accept any stranger's empty ENROLL_START and hand them a
    // freshly generated secret, locking out every device already using this
    // client id. The loader refuses that spelling too; this is the runtime half
    // of the same rule, so a reload path that skips validation cannot revive it.
    let Some(expected) = client
        .pending_enrollment
        .as_ref()
        .map(|expected| expected.expose_secret())
        .filter(|expected| !expected.is_empty())
    else {
        return EnrollmentVerdict::Refuse { counted: false };
    };

    if !constant_time_eq(expected.as_bytes(), token.as_bytes()) {
        return EnrollmentVerdict::Refuse { counted: true };
    }
    // Not counted: this is the right token in the wrong hands, not a guess at
    // one. Whoever is holding it is about to be told the same thing every other
    // refusal says.
    if let Some(name) = device
        && client.devices.contains_key(name)
    {
        return EnrollmentVerdict::Refuse { counted: false };
    }
    EnrollmentVerdict::Accept
}

/// What a successful handshake established.
///
/// Carried as both halves because a client id on its own cannot tell two
/// devices of the same client apart, and telling them apart is the only thing
/// a per-device credential is for: what the peer list, the access log and the
/// revocation that closes one device's connections all need to know is whose
/// connection this is, not merely whose client's.
struct AuthenticatedPeer {
    client_id: String,
    /// The device name the peer sent. `None` is the device that has none,
    /// which answered with the client's own secret.
    device: Option<String>,
    acl: ClientAcl,
    /// Keeps the registry entry alive; dropped when the connection ends, which
    /// is what takes it out of `GET /v1/connections`.
    guard: PeerGuard,
    /// Flipped by a reload that dropped the credential this connection
    /// authenticated with. Owned here rather than created by the caller
    /// because of when it has to be created — see [`PeerRegistration`].
    revoked: tokio::sync::watch::Receiver<bool>,
}

/// What a connection needs to put itself in the peer registry, handed to
/// [`perform_authentication`] so that the registration happens *inside* the
/// auth write lock.
///
/// Registering after the lock is dropped leaves a window that a reload fits
/// in. The reload takes the same lock and calls `close_where` over the
/// registry; a connection that is between "verified" and "registered" is not
/// in the registry yet, so it is not found, and it goes on to insert itself
/// with a fresh watch channel that nothing will ever flip. No later reload
/// reaches it either: `removed` and `removed_devices` are recomputed from the
/// diff each time and are never replayed, so a credential revoked in that
/// window keeps serving until the client hangs up on its own.
///
/// Doing both under the lock makes "verified" and "registered" one step that a
/// reload cannot land inside: either the reload's pass runs first and the
/// connection is closed before it is ever served, or the entry is already
/// there and has its channel flipped.
struct PeerRegistration {
    registry: Arc<PeerRegistry>,
    endpoint_id: iroh::EndpointId,
    path: metrics::PathKind,
}

impl PeerRegistration {
    /// Puts the connection in the registry and hands back what keeps it there
    /// and what tells it to stop.
    fn register(self, identity: PeerIdentity) -> (PeerGuard, tokio::sync::watch::Receiver<bool>) {
        let (revoked_tx, revoked_rx) = tokio::sync::watch::channel(false);
        let guard = self
            .registry
            .insert(self.endpoint_id, self.path, identity, revoked_tx);
        (guard, revoked_rx)
    }
}

/// Where an enrollment puts the credential it issues, and what undoing it has
/// to put back.
///
/// This is what makes an enrollment invite worth handing out: the link carries
/// a token, and the first client to present it gets a credential the link never
/// contained while the token is dropped in the same write. A link copied in
/// transit is therefore a credential only until it is used once, instead of
/// until somebody remembers to rotate it.
///
/// Two slots, because a client's own `secret` and its device table are not the
/// same credential and an enrollment names which of the two it is asking about:
/// a device that sends a name wants an entry of its own, and a device that
/// sends none is one that predates the table, for whom the client's `secret` is
/// the only credential there is.
enum EnrollmentSlot {
    /// A named device. The client's `secret` is left alone, so the other
    /// devices keep theirs — which is the whole point of the table.
    Device {
        name: String,
        /// The entry this enrollment replaced, if the device was enrolled
        /// before.
        ///
        /// `None` on the enrollment path, where a name that is already in the
        /// table is refused rather than overwritten — see
        /// [`enrollment_verdict`]. Rotating a device that exists is the
        /// operator's move, `client add --device <name> --force`. What this
        /// carries is what a failed write has to put back.
        previous: Option<DeviceAuth>,
    },
    /// The device that has no name: the client's own `secret`, which is also
    /// what every peer that predates the device table answers with.
    Shared {
        /// The secret this enrollment rotated away.
        previous: SecretString,
    },
}

/// The credential an enrollment is recording, owned: the write that persists
/// it is detached, so it cannot borrow anything from the handshake.
///
/// Three shapes, not two, because there are three places a credential can go: a
/// named device takes either a secret or a key, and the unnamed slot — the
/// client's own `secret`, which every device that names none answers with — is
/// a secret or nothing. That last fact is why a key offered without a device
/// name is refused as unrecordable rather than silently ignored.
#[derive(Clone)]
enum IssuedCredential {
    /// A named device with a secret of its own.
    DeviceSecret { name: String, secret: SecretString },
    /// A named device with a key: it signs each challenge, and `secret` is
    /// empty on the wire because there is no code for it to send.
    ///
    /// The key is the *public* half, so it is a plain string: there is nothing
    /// secret about it.
    DeviceKey { name: String, key: String },
    /// The client's own `secret`, rotated.
    SharedSecret(SecretString),
}

/// Writes the issued credential into the slot this enrollment named, in memory.
///
/// The caller persists it and, if that fails, hands what this returns to
/// [`undo_enrolled_secret`]: a credential that is live in memory but missing
/// from disk is one that silently reverts at the next restart, putting the old
/// one back in service.
fn issue_enrolled_secret(
    cfg: &mut AuthConfig,
    client_id: &str,
    issued: &IssuedCredential,
) -> EnrollmentSlot {
    let Some(client) = cfg.clients.get_mut(client_id) else {
        // Accepted tokens only exist on a client that is in the table, so this
        // is unreachable; a shared slot with nothing to restore keeps the
        // caller's rollback simple rather than making it handle a third case.
        return EnrollmentSlot::Shared {
            previous: SecretString::default(),
        };
    };

    let slot = match issued {
        IssuedCredential::DeviceSecret { name, secret } => EnrollmentSlot::Device {
            previous: client.devices.insert(
                name.clone(),
                DeviceAuth {
                    secret: secret.clone(),
                    public_key: None,
                    created_at: crate::auth::config::default_created_at(),
                    last_used: None,
                },
            ),
            name: name.clone(),
        },
        IssuedCredential::DeviceKey { name, key } => EnrollmentSlot::Device {
            previous: client.devices.insert(
                name.clone(),
                DeviceAuth {
                    secret: SecretString::default(),
                    public_key: Some(key.clone()),
                    created_at: crate::auth::config::default_created_at(),
                    last_used: None,
                },
            ),
            name: name.clone(),
        },
        IssuedCredential::SharedSecret(secret) => EnrollmentSlot::Shared {
            previous: std::mem::replace(&mut client.secret, secret.clone()),
        },
    };
    client.pending_enrollment = None;
    slot
}

/// Puts back what [`issue_enrolled_secret`] replaced, and the token with it.
///
/// The token goes back because the write that would have spent it failed: the
/// link is still the only credential the client has for this enrollment, and
/// dropping it would leave a client that cannot enroll at all.
fn undo_enrolled_secret(cfg: &mut AuthConfig, client_id: &str, slot: EnrollmentSlot, token: &str) {
    let Some(client) = cfg.clients.get_mut(client_id) else {
        return;
    };

    match slot {
        EnrollmentSlot::Device { name, previous } => match previous {
            Some(previous) => {
                client.devices.insert(name, previous);
            }
            None => {
                client.devices.remove(&name);
            }
        },
        EnrollmentSlot::Shared { previous } => client.secret = previous,
    }
    client.pending_enrollment = Some(SecretString::new(token.to_string()));
}

/// The counted refusal: what a wrong guess at a token moves.
///
/// **The enrollment's own counter, and not the client's.** A client id is not
/// a secret — it is in the invite link, in `nexapipe client list` and in
/// whatever the operator pasted into a ticket — so anybody who knows one can
/// send enrollment attempts at a client that is waiting to enroll. Counting
/// those against the client's authentication counter meant a stranger could
/// lock out the devices that had already enrolled, over a credential those
/// devices were never sent. The token keeps its ceiling; the ceiling is paid
/// for by the token.
///
/// Public because it is the rule, and a rule that only one caller can reach
/// is a rule nobody can state: the state file's round trip is checked against
/// this function, so the two cannot drift apart.
pub fn count_enrollment_failure(
    cfg: &mut AuthConfig,
    client_id: &str,
    max_attempts: u32,
    lockout_duration: u64,
) {
    if let Some(client) = cfg.clients.get_mut(client_id) {
        client.record_enrollment_failure(max_attempts, lockout_duration);
    }
}

/// Issues a credential against an enrollment token: a freshly generated secret,
/// or the device key the client offered.
///
/// The secret is rotated rather than handed out as-is, so enrolling is also how
/// a client recovers from a secret that leaked — at the cost of every device
/// already using that client id, which has to scan again.
///
/// `device` is the name the client asked to be issued under. A name means the
/// credential goes into the device table and no other device's is touched;
/// no name is the case above, and the only one that existed before the table.
///
/// `public_key` is the key a device offered to be known by, for a device that
/// will answer with a signature instead of a code. It is only ever recorded for
/// a named device: the entry it goes into is the device's, and the unnamed slot
/// — the client's own shared `secret` — is a string with no key in it.
async fn enroll_client(
    auth: &AuthState,
    client_id: &str,
    token: &str,
    device: Option<&str>,
    public_key: Option<&str>,
    format: Format,
    send: &mut iroh::endpoint::SendStream,
) -> Result<(), AuthFailure> {
    // One reply for every way this can fail, for the same reason AUTH_FAILED
    // has one: whether the token was unknown, already spent or never issued is
    // not information a stranger is owed.
    const REFUSED: &str = "the enrollment token was not accepted";

    let mut cfg = auth.config().write().await;

    // Drop a lockout that has run out before deciding anything, so an expired
    // one does not read as live and its stale counter does not push the client
    // straight back over the threshold.
    if let Some(client) = cfg.clients.get_mut(client_id) {
        client.refresh_lockout();
        client.refresh_enrollment_lockout();
    }

    let verdict = enrollment_verdict(&cfg, client_id, token, device);
    if !matches!(verdict, EnrollmentVerdict::Accept) {
        // The refusal sent on the wire is one string for every reason, so the
        // only place this one is legible is the log — and it is the one an
        // operator can act on, because it names the command that rotates the
        // device properly.
        if let Some(name) = device
            && cfg
                .clients
                .get(client_id)
                .is_some_and(|client| client.devices.contains_key(name))
        {
            tracing::warn!(
                "2FA: enrollment for '{client_id}' refused, device '{name}' already has a \
                 credential; replace it with `nexapipe client add {client_id} --device {name} \
                 --force`"
            );
        }
        if verdict.counted() {
            let (max_attempts, lockout_duration) = (cfg.max_attempts, cfg.lockout_duration);
            count_enrollment_failure(&mut cfg, client_id, max_attempts, lockout_duration);
            let snapshot = cfg.counter_snapshot();
            if let Err(e) = blocking_config_write(auth.state_path().to_string(), move |path| {
                save_auth_state(path, &snapshot)
            })
            .await
            {
                tracing::warn!(
                    "2FA: failed to persist the enrollment lockout for '{}' to {}: {}",
                    client_id,
                    auth.state_path(),
                    e
                );
            }
        }
        drop(cfg);
        write_auth_message(
            send,
            &AuthMessage::EnrollFailed {
                reason: REFUSED.to_string(),
            },
            format,
        )
        .await
        .map_err(AuthFailure::NotStarted)?;
        return Err(AuthFailure::Rejected(format!(
            "enrollment refused for client '{client_id}': {REFUSED}"
        )));
    }

    // Read off the config before the client is borrowed again: the credential
    // issued here has to be generated with what the server will verify against.
    let (algorithm, digits, period) = (
        nexapipe_proto::auth::Algorithm::from(&cfg.algorithm),
        cfg.digits,
        cfg.time_step as u64,
    );

    // What this enrollment records. A key is not generated here — the client
    // holds the private half already, and the server only ever learns the
    // public one — so a key enrollment mints no secret at all.
    //
    // Both ways a request can be unrecordable are settled here, after the
    // verdict so a wrong token is still the thing that gets counted, and before
    // anything is issued so a request that cannot be recorded does not spend
    // the token it came with. Neither is a guess at anything, so the counter
    // does not move, and the reason is spelled out on the wire: unlike the
    // token refusals, one fixed string for every reason, which is about what
    // this server knows and does not say.
    let issued = match public_key {
        None => {
            // Minted as a `Secret`: the credential that is about to be issued
            // is the most valuable thing this process holds, and it is wiped
            // when the enrollment is over.
            let secret = SecretString::new(crate::auth::TotpValidator::generate_secret());
            match device {
                Some(name) => IssuedCredential::DeviceSecret {
                    name: name.to_string(),
                    secret,
                },
                None => IssuedCredential::SharedSecret(secret),
            }
        }
        Some(offered) => {
            let Some(name) = device else {
                return Err(refuse_unrecordable_enrollment(
                    send,
                    client_id,
                    "a public key has to be issued to a named device; the unnamed credential is \
                     the client's own shared secret",
                    format,
                )
                .await);
            };
            let key = match crate::auth::parse_public_key(offered) {
                // Stored in the canonical spelling — lowercase hex — whatever
                // case it arrived in, so the config reads the way every writer
                // of this file writes keys.
                Ok(key) => crate::auth::public_key_hex(&key),
                Err(why) => {
                    let reason = why.to_string();
                    return Err(
                        refuse_unrecordable_enrollment(send, client_id, &reason, format).await,
                    );
                }
            };
            IssuedCredential::DeviceKey {
                name: name.to_string(),
                key,
            }
        }
    };
    let slot = issue_enrolled_secret(&mut cfg, client_id, &issued);

    // Persisted before anything is promised to the client: a credential that is
    // live in memory but missing from disk is one that silently reverts on the
    // next restart, which would put the old one back in service.
    let enrollment_path = auth.path().to_string();
    let enrolled_client = client_id.to_string();
    let persisted = issued.clone();
    if let Err(e) = blocking_config_write(enrollment_path, move |path| match &persisted {
        IssuedCredential::DeviceSecret { name, secret } => {
            crate::config::ProxyConfig::complete_device_enrollment(
                path,
                &enrolled_client,
                name,
                crate::auth::DeviceMaterial::Secret(secret.expose_secret()),
            )
        }
        IssuedCredential::DeviceKey { name, key } => {
            crate::config::ProxyConfig::complete_device_enrollment(
                path,
                &enrolled_client,
                name,
                crate::auth::DeviceMaterial::PublicKey(key),
            )
        }
        IssuedCredential::SharedSecret(secret) => crate::config::ProxyConfig::complete_enrollment(
            path,
            &enrolled_client,
            secret.expose_secret(),
        ),
    })
    .await
    {
        // Roll the in-memory client back, or this process would keep accepting
        // a secret that no longer exists anywhere else.
        undo_enrolled_secret(&mut cfg, client_id, slot, token);
        drop(cfg);
        let reason = format!("enrollment could not be saved: {e}");
        write_auth_message(
            send,
            &AuthMessage::EnrollFailed {
                reason: reason.clone(),
            },
            format,
        )
        .await
        .map_err(AuthFailure::NotStarted)?;
        return Err(AuthFailure::Rejected(reason));
    }

    // The file carries the enrollment now, so this is the moment the watcher
    // has to be able to see it. Still under the lock the enrollment holds: a
    // reload samples the epoch before it reads the file and compares it here,
    // and a bump placed any earlier — before the write — could be sampled by a
    // reload that then read the pre-enrollment file and merged it back over
    // the top of this enrollment.
    auth.bump_enroll_epoch();

    // Presenting the token is proof the invite reached the right hands, so a
    // counter left over from failed guesses is cleared: a client that just
    // enrolled should not be one wrong code away from a lockout it did not
    // earn. The token's own counter is cleared with it — the token has been
    // spent, and the next invite replaces it rather than inheriting the
    // guesses made at this one. Only written when there is something to
    // clear, as above.
    let dirty = cfg.clients.get(client_id).is_some_and(|c| {
        c.failed_attempts != 0
            || c.locked_until.is_some()
            || c.enrollment_failed_attempts != 0
            || c.enrollment_locked_until.is_some()
    });
    if dirty {
        if let Some(client) = cfg.clients.get_mut(client_id) {
            client.record_success();
            client.record_enrollment_success();
        }
        let snapshot = cfg.counter_snapshot();
        if let Err(e) = blocking_config_write(auth.state_path().to_string(), move |path| {
            save_auth_state(path, &snapshot)
        })
        .await
        {
            tracing::warn!(
                "2FA: failed to persist the cleared counter for '{}' to {}: {}",
                client_id,
                auth.state_path(),
                e
            );
        }
    }
    drop(cfg);

    match &issued {
        IssuedCredential::DeviceKey { name, .. } => tracing::info!(
            "2FA: client '{client_id}' enrolled device '{name}' with a public key; it proves \
             itself by signing each challenge, with no TOTP code"
        ),
        IssuedCredential::DeviceSecret { name, .. } => tracing::info!(
            "2FA: client '{client_id}' enrolled device '{name}'; its own secret was left \
             alone, so the other devices keep theirs"
        ),
        IssuedCredential::SharedSecret(_) => tracing::info!(
            "2FA: client '{client_id}' enrolled; its secret was rotated, so every device \
             holding the old one has to scan again"
        ),
    }

    let (secret, device_id) = match &issued {
        IssuedCredential::DeviceSecret { name, secret } => (secret.clone(), Some(name.clone())),
        // An empty secret is how the client is told its key was recorded:
        // there is no seed for it to keep, and from here on every response it
        // sends is a signature.
        IssuedCredential::DeviceKey { name, .. } => (SecretString::default(), Some(name.clone())),
        IssuedCredential::SharedSecret(secret) => (secret.clone(), None),
    };

    write_auth_message(
        send,
        &AuthMessage::EnrollIssue {
            client_id: client_id.to_string(),
            secret,
            algorithm,
            digits,
            period,
            // The name this credential was issued under, which is the name the
            // client has to send back to be checked against it. None when the
            // device named none: it answered with the client's own secret, and
            // a client that predates the table reads that as "the shared one".
            device_id,
        },
        format,
    )
    .await
    .map_err(AuthFailure::NotStarted)
}

/// Ends an enrollment that cannot be recorded, telling the client why.
///
/// The reason goes on the wire, unlike the token refusals', because it is about
/// the request the client itself just sent and not about any state this server
/// holds — repeating it back tells a peer nothing it did not already know.
async fn refuse_unrecordable_enrollment(
    send: &mut iroh::endpoint::SendStream,
    client_id: &str,
    reason: &str,
    format: Format,
) -> AuthFailure {
    if let Err(e) = write_auth_message(
        send,
        &AuthMessage::EnrollFailed {
            reason: reason.to_string(),
        },
        format,
    )
    .await
    {
        return AuthFailure::NotStarted(e);
    }
    AuthFailure::Rejected(format!(
        "enrollment refused for client '{client_id}': {reason}"
    ))
}

/// Compares two byte strings in time that does not depend on where they differ.
///
/// A token is guessed the same way a password is, and an early exit on the
/// first differing byte turns "how long did that take" into "how many
/// characters did I get right".
fn constant_time_eq(expected: &[u8], given: &[u8]) -> bool {
    if expected.len() != given.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(given.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Persists the runtime counters to the state file, without the auth lock.
///
/// The counters are read **at write time** and the file is written with the
/// auth lock released: a write lock held across a disk write stalls every
/// connection that is authenticating, not only the one whose counters are
/// being written.
///
/// The gate orders the writes, so the file always carries the count as of the
/// write that reached it last. Because the counters are read here rather than
/// by the caller, a handshake that counted a failure in between is counted
/// too — the file can lag the in-memory count by the moment between a read
/// and the write, and the in-memory count is the one that decides.
///
/// The lock order is the auth lock and **then** the gate, which is the order
/// the writers that hold the auth lock take them in: [`blocking_config_write`]
/// is called from under the auth write lock, and takes the gate inside it. A
/// writer that took them the other way round would deadlock against one of
/// those — this task holding the gate and waiting for the read lock, that one
/// holding the write lock and waiting for the gate, and neither ever letting
/// go. The read guard is dropped before the disk write, so the lock is held
/// for the snapshot and not for the write.
async fn persist_auth_state(auth: &AuthState) -> anyhow::Result<()> {
    let path = auth.state_path().to_string();
    let config = auth.config().clone();
    let (done, wait) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let cfg = config.read().await;
        let gate = config_write_gate().lock().await;
        let snapshot = cfg.counter_snapshot();
        // The snapshot is what the write needs; the lock it was taken under is
        // not, and a writer should not wait for the disk on top of the gate.
        drop(cfg);
        let result = tokio::task::spawn_blocking(move || save_auth_state(&path, &snapshot)).await;
        drop(gate);
        let _ = done.send(result);
    });

    wait.await
        .map_err(|_| anyhow::anyhow!("the auth state write was abandoned"))?
        .map_err(|e| anyhow::anyhow!("the auth state write did not run: {e}"))?
}

/// Runs a write against the config file without occupying a worker.
///
/// These writes happen while the auth write lock is held, and that is not
/// incidental: the lock is what keeps two connections from persisting
/// overlapping views of the lockout counters, so the IO cannot be moved out
/// from under it. What can be moved is the *thread* it blocks. `std::fs` plus a
/// TOML parse is a syscall and some CPU on whichever thread calls it, and on a
/// tokio worker that stalls every task scheduled behind it — one handshake's
/// write becomes a delay on all of them, and a slow or contended mount turns
/// into handshakes timing out for a reason that has nothing to do with the
/// network. `spawn_blocking` hands it to a thread built for it and leaves the
/// worker free.
///
/// The lock is still held across the await, so this does not change who can
/// write when — only who waits for the disk.
///
/// Detached, and gated by [`config_write_gate`] rather than by the auth lock
/// alone: the caller is bounded by a deadline, and a deadline that fires while
/// a write is on the disk drops not only the result but the lock the write was
/// running under — while the write itself keeps going, because a blocking task
/// cannot be un-spawned. Two writes to one file then overlap and one of them
/// is lost. The gate is taken *inside* the detached task, so it is held for as
/// long as the write takes and not for as long as the caller is patient.
async fn blocking_config_write<T, F>(path: String, write: F) -> anyhow::Result<T>
where
    F: FnOnce(&str) -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    // Named apart from the `path` the closure takes, which it moves.
    let failed_path = path.clone();
    let (done, wait) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let _gate = config_write_gate().lock().await;
        let result = tokio::task::spawn_blocking(move || write(&path)).await;
        // A caller that timed out is not an error worth reporting: the write
        // it asked for has happened, which is what the gate is for.
        let _ = done.send(result);
    });

    let result = wait
        .await
        .map_err(|_| anyhow::anyhow!("the write to {failed_path} was abandoned"))?;
    result.map_err(|e| anyhow::anyhow!("the write to {failed_path} did not run: {e}"))?
}

/// Serialises writes to the config file and to the state file beside it,
/// independently of the caller.
///
/// A `static` because it has to outlive the task that asked for the write: the
/// auth lock is released when a handshake is cancelled, and this is what keeps
/// that cancellation from letting the next write start on top of a running
/// one. The two files have a lock each of their own; this gate is what keeps
/// the two kinds of write from running at the same time, which is no slower
/// than the writes themselves and one thing less to reason about.
fn config_write_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Writes one length-prefixed AUTH_* message.
async fn write_auth_message(
    send: &mut iroh::endpoint::SendStream,
    message: &AuthMessage,
    format: Format,
) -> Result<(), String> {
    let bytes = message
        .to_payload(format)
        .map_err(|e| format!("failed to serialize {}: {}", message_kind(message), e))?;
    let len = bytes.len() as u32;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| format!("failed to send {}: {}", message_kind(message), e))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| format!("failed to send {}: {}", message_kind(message), e))
}

/// The form the answer to a message is in.
///
/// The client that asked is answered in the form it asked in — and, when it
/// announced a version, in that version. Nothing is negotiated and nothing is
/// remembered: the message says what it is, and the answer says the same.
///
/// A version this build does not know is answered in the form the client
/// asked in, which is a form the client can read by definition.
fn reply_format(message: &AuthMessage, asked_in: Format) -> Format {
    message
        .announced_version()
        .and_then(Format::from_version)
        .unwrap_or(asked_in)
}

/// The wire name of a message, for errors that name what was being sent.
fn message_kind(message: &AuthMessage) -> &'static str {
    match message {
        AuthMessage::Start { .. } => "AUTH_START",
        AuthMessage::Challenge { .. } => "AUTH_CHALLENGE",
        AuthMessage::Response { .. } => "AUTH_RESPONSE",
        AuthMessage::Ok => "AUTH_OK",
        AuthMessage::Failed { .. } => "AUTH_FAILED",
        AuthMessage::EnrollStart { .. } => "ENROLL_START",
        AuthMessage::EnrollIssue { .. } => "ENROLL_ISSUE",
        AuthMessage::EnrollFailed { .. } => "ENROLL_FAILED",
    }
}

/// Perform 2FA authentication handshake with a client.
///
/// Protocol:
/// 1. Receive AUTH_START from client
/// 2. Send AUTH_CHALLENGE with nonce
/// 3. Receive AUTH_RESPONSE with TOTP code and an HMAC over the nonce
/// 4. Validate and send AUTH_OK or AUTH_FAILED
///
/// Returns the client id together with its host authorization
/// ([`ClientAcl`]), snapshotted under the same lock that verified the
/// credentials — a reload landing between the two could otherwise turn a
/// client whose entry was just removed into an unrestricted one.
///
/// `registration` is spent the same way: a connection that passes is put in
/// the peer registry before the lock is released, so that the reload which
/// closes revoked credentials and this handshake cannot be interleaved. See
/// [`PeerRegistration`] for the window that moving it out would open.
///
/// The caller bounds this with a deadline, so every read in here has to be
/// cancel-safe: [`read_auth_message`] loops over `RecvStream::read` instead of
/// using `read_exact`.
async fn perform_authentication(
    conn: &Connection,
    auth: &AuthState,
    peer: &str,
    registration: PeerRegistration,
) -> Result<AuthenticatedPeer, AuthFailure> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| AuthFailure::NotStarted(format!("failed to open auth stream: {}", e)))?;

    // Step 1: Receive AUTH_START. A client that is not doing 2FA opens its
    // first data stream here instead, which does not parse as AUTH_START — that
    // is a refusal, not a parse error worth distinguishing in the log.
    let start_bytes = read_auth_message(&mut recv)
        .await
        .map_err(AuthFailure::NotStarted)?;

    // The payload's first byte says which form it is in, and the answers go
    // back in the form the client asked in.
    let (start_msg, start_format) = AuthMessage::from_payload(&start_bytes).map_err(|_| {
        AuthFailure::NotStarted("the first stream is not an AUTH_START".to_string())
    })?;
    let mut format = reply_format(&start_msg, start_format);

    // Checked before the id is used for anything, because the first thing it is
    // used for is being printed: the log line for a refusal, a lockout or an
    // unknown client all carry it, and a peer that names itself with a trailing
    // CRLF writes the rest of that line itself. This is before any secret has
    // been checked, so it is reachable by anyone who can open a stream.
    if let AuthMessage::Start { client_id, .. } | AuthMessage::EnrollStart { client_id, .. } =
        &start_msg
        && !is_presentable_client_id(client_id)
    {
        return Err(AuthFailure::Rejected(
            "client id is not printable ASCII".to_string(),
        ));
    }

    // The same test on the name a device asks to be enrolled under, and refused
    // rather than read as "no name": it becomes a key in the config and the
    // subject of the log line for everything that happens to it, so a name that
    // cannot be printed is one nobody can revoke by hand either. Not counted
    // against the client — a malformed request is not a guess at the token.
    if let AuthMessage::EnrollStart {
        device_id: Some(device_id),
        ..
    } = &start_msg
        && !is_presentable_device_id(device_id)
    {
        return Err(AuthFailure::Rejected(
            "device id is not printable ASCII".to_string(),
        ));
    }

    // Enrollment, when the client asked for it: the token is exchanged for a
    // freshly generated secret ahead of the ordinary handshake, on the same
    // stream — the two messages are read in order here, so a client that
    // enrolled cannot have its AUTH_START mistaken for a data stream.
    let client_id = match start_msg {
        AuthMessage::Start { client_id, .. } => client_id,
        AuthMessage::EnrollStart {
            client_id,
            token,
            device_id,
            public_key,
        } => {
            enroll_client(
                auth,
                &client_id,
                token.expose_secret(),
                device_id.as_deref(),
                public_key.as_deref(),
                format,
                &mut send,
            )
            .await?;

            let start_after_enroll = read_auth_message(&mut recv)
                .await
                .map_err(AuthFailure::NotStarted)?;
            let (start_after_enroll_msg, asked_in) = AuthMessage::from_payload(&start_after_enroll)
                .map_err(|_| {
                    AuthFailure::NotStarted("expected AUTH_START after ENROLL_START".to_string())
                })?;
            // The client may announce its version here, so this message is
            // what settles the form of the answers.
            let answer_format = reply_format(&start_after_enroll_msg, asked_in);
            match start_after_enroll_msg {
                AuthMessage::Start { client_id: id, .. } if id == client_id => {
                    format = answer_format;
                    client_id
                }
                AuthMessage::Start { client_id: id, .. } => {
                    return Err(AuthFailure::Rejected(format!(
                        "AUTH_START names client '{id}' but the enrollment was for '{client_id}'"
                    )));
                }
                _ => {
                    return Err(AuthFailure::NotStarted(
                        "expected AUTH_START after ENROLL_START".to_string(),
                    ));
                }
            }
        }
        _ => {
            return Err(AuthFailure::NotStarted(
                "expected AUTH_START message".to_string(),
            ));
        }
    };

    // Step 2: Send AUTH_CHALLENGE
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let challenge_msg = AuthMessage::Challenge {
        nonce: nonce.clone(),
    };

    write_auth_message(&mut send, &challenge_msg, format)
        .await
        .map_err(AuthFailure::NotStarted)?;

    // Step 3: Receive AUTH_RESPONSE
    let response_bytes = read_auth_message(&mut recv)
        .await
        .map_err(AuthFailure::NotStarted)?;

    let (response_msg, response_format) = AuthMessage::from_payload(&response_bytes)
        .map_err(|_| AuthFailure::NotStarted("expected AUTH_RESPONSE message".to_string()))?;

    let (resp_client_id, resp_device_id, resp_timestamp, signature, totp_code) = match response_msg
    {
        AuthMessage::Response {
            client_id,
            device_id,
            timestamp,
            totp_code,
            signature,
        } => (client_id, device_id, timestamp, signature, totp_code),
        _ => {
            return Err(AuthFailure::NotStarted(
                "expected AUTH_RESPONSE message".to_string(),
            ));
        }
    };

    if resp_client_id != client_id {
        return Err(AuthFailure::Rejected(
            "client ID mismatch in AUTH_RESPONSE".to_string(),
        ));
    }

    // Checked before the name is used for anything, for the reason a client id
    // is: it ends up in the log line for the outcome, and a peer that names
    // itself with a trailing CRLF writes the rest of that line itself. `None`
    // is not a failure to name one — it is the unnamed device, which is what a
    // client with no device table has always been.
    if let Some(name) = resp_device_id.as_deref()
        && !is_presentable_device_id(name)
    {
        return Err(AuthFailure::Rejected(
            "device id is not printable ASCII".to_string(),
        ));
    }

    // Step 4: Verify the response and account for the result under one write
    // lock. The signature binds the response to this connection's challenge and
    // the timestamp keeps it fresh; only then does the TOTP code decide.
    //
    // Verify and record have to share the lock. Split across a read and a write
    // lock, two connections from the same client could both read "not locked
    // out" before either had recorded anything, and the counters would under-
    // count. The lock is held across an HMAC and a TOTP check, both of which
    // are microseconds, so serialising handshakes costs nothing a client can
    // notice.
    let mut cfg = auth.config().write().await;

    // Drop a lockout that has run out before deciding anything, so an expired
    // one does not read as live and its stale counter does not push the client
    // straight back over the threshold.
    if let Some(client) = cfg.clients.get_mut(&client_id) {
        client.refresh_lockout();
    }

    let outcome = TotpValidator::new(&cfg).verify_response(
        &client_id,
        resp_device_id.as_deref(),
        &nonce,
        resp_timestamp,
        &signature,
        &totp_code,
    );

    // Only a wrong TOTP code counts toward the lockout: a skewed clock or a
    // mismatched signature is a refusal, not a failed attempt, and counting
    // those would let whoever replays a captured response lock its rightful
    // owner out.
    //
    // Every branch below ends up sending one AUTH_FAILED whose reason is a
    // single fixed string. A distinct message for "locked out" or "no such
    // client" would make the reason an oracle: anyone could walk a client's
    // counter up to the lockout and, from the change in the reply, learn that
    // the id they guessed exists. The real reason goes to the log instead.
    let mut verified_acl = ClientAcl::unrestricted();
    // Whether the counters changed and the state file has to be written. The
    // write itself happens after the lock is released.
    let mut state_dirty = false;
    let is_valid = match outcome {
        Ok(true) => {
            // Which device this was, if it named one, recorded under the same
            // lock that verified it. This is the stamp `client list` reads to
            // say whether a device is still in use: without it every named
            // device reports "never used" forever, and the one question the
            // device table exists to answer — which of these can be revoked
            // without disconnecting a live one — has nothing to go on.
            let device_stamp_moved = match resp_device_id.as_deref() {
                Some(name) => cfg
                    .clients
                    .get_mut(&client_id)
                    .is_some_and(|client| client.record_device_success(name)),
                None => false,
            };
            // Clear the counters only when there is something to clear, so a
            // healthy client does not turn every connection into a disk write.
            // A named device that moved its stamp is worth one: `unix_now` is
            // whole seconds, so a device reconnecting inside the same second
            // is not.
            let dirty = device_stamp_moved
                || cfg
                    .clients
                    .get(&client_id)
                    .is_some_and(|c| c.failed_attempts != 0 || c.locked_until.is_some());
            if dirty {
                if let Some(client) = cfg.clients.get_mut(&client_id) {
                    client.record_success();
                }
                // The write happens after the lock is released; see
                // `persist_auth_state`.
                state_dirty = true;
            }
            // Snapshot the host authorization while the same lock that verified
            // the credentials still holds: the entry cannot vanish between the
            // two reads, and a connection keeps the ACL it authenticated with
            // even if a reload changes it right after.
            if let Some(client) = cfg.clients.get(&client_id) {
                verified_acl = client.acl();
            }
            true
        }
        Ok(false) => {
            let max_attempts = cfg.max_attempts;
            let lockout_duration = cfg.lockout_duration;
            if let Some(client) = cfg.clients.get_mut(&client_id) {
                client.record_failure(max_attempts, lockout_duration);
            }
            // The write happens after the lock is released; see
            // `persist_auth_state`.
            state_dirty = true;
            false
        }
        Err(e) => {
            match &e {
                AuthError::ClientNotFound => {
                    tracing::warn!("2FA: unknown client '{}' from {}", client_id, peer);
                }
                AuthError::UnknownDevice => {
                    // Printable ASCII, because the name was checked before it
                    // was used for anything — and it is the one thing about
                    // this refusal an operator can act on.
                    tracing::warn!(
                        "2FA: client '{}' from {} names device {:?}, which has no credential: \
                         either it never enrolled or its entry was dropped",
                        client_id,
                        peer,
                        resp_device_id.as_deref()
                    );
                }
                AuthError::InvalidSecret | AuthError::TotpCreationFailed => {
                    tracing::error!(
                        "2FA: client '{}' cannot be validated, the server's auth config is broken: {}",
                        client_id,
                        e
                    );
                }
                AuthError::LockedOut => {
                    tracing::warn!("2FA: client '{}' from {} is locked out", client_id, peer);
                }
                AuthError::WrongSignature => {
                    // Not counted, and worth saying why: a key cannot be
                    // guessed, so there is nothing for the counter to protect
                    // on this path — counting it would only let a peer that
                    // knows the client id and the device name deny the
                    // device's owner service.
                    tracing::warn!(
                        "2FA: response from {} for '{}' carries a signature that does not match \
                         the challenge",
                        peer,
                        client_id
                    );
                }
                AuthError::MalformedSignature => {
                    // Not counted, and worth saying why: the peer sent noise
                    // rather than a wrong credential, so this is not an
                    // attempt at the device.
                    tracing::warn!(
                        "2FA: response from {} for '{}' carries a signature that is not a \
                         signature",
                        peer,
                        client_id
                    );
                }
                AuthError::UnnamedDeviceNotAllowed => {
                    // The one refusal that is a configuration the operator can
                    // change, so it is the one that says which knob.
                    tracing::warn!(
                        "2FA: client '{}' from {} names no device, and this client answers only \
                         to named ones: set unnamed_device_allowed = true under \
                         [auth.clients.{}] to let it use the client's own secret",
                        client_id,
                        peer,
                        client_id
                    );
                }
                _ => {
                    tracing::warn!(
                        "2FA: response from {} for '{}' rejected: {}",
                        peer,
                        client_id,
                        e
                    );
                }
            }
            false
        }
    };
    // Registered here, while the write lock is still held, for the reason given
    // on `PeerRegistration`: a reload takes this same lock and closes the
    // connections whose credential it just dropped, so the entry has to be in
    // the registry before the lock is released or that pass misses it. Nothing
    // is registered on a refusal — a peer that was turned away was never
    // connected, and listing it would answer "who is connected" with peers
    // that were not.
    let registered = is_valid.then(|| {
        registration.register(PeerIdentity {
            client_id: Some(client_id.clone()),
            device: resp_device_id.clone(),
        })
    });

    drop(cfg);

    // The state file is written with the auth lock released. The counters it
    // carries are read at write time, so they are the ones as of now.
    if state_dirty && let Err(e) = persist_auth_state(auth).await {
        tracing::warn!(
            "2FA: failed to persist the auth counters for '{}' to {}: {}",
            client_id,
            auth.state_path(),
            e
        );
    }

    // One fixed string for every refusal, logged apart but sent identically: see
    // the note above the match.
    let fail_reason = "Invalid TOTP code";
    let result_msg = if is_valid {
        AuthMessage::Ok
    } else {
        AuthMessage::Failed {
            reason: fail_reason.to_string(),
        }
    };

    write_auth_message(&mut send, &result_msg, response_format)
        .await
        .map_err(AuthFailure::NotStarted)?;
    send.finish()
        .map_err(|e| AuthFailure::NotStarted(format!("failed to finish auth stream: {}", e)))?;

    // Let a refused client read its verdict before the caller pulls the
    // connection out from under it. A client that has read AUTH_FAILED closes
    // the connection itself, which ends this wait immediately; one that has
    // vanished simply costs the grace period. Whatever the peer sends is
    // discarded — it has already been refused, nothing further is read for
    // meaning.
    if !is_valid {
        let mut buf = [0u8; 256];
        let drain = async {
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) | Ok(None) => break,
                    Ok(Some(_)) => continue,
                    Err(_) => break,
                }
            }
        };
        let _ = tokio::time::timeout(AUTH_RESULT_GRACE, drain).await;
    }

    match registered {
        Some((guard, revoked)) => Ok(AuthenticatedPeer {
            client_id,
            device: resp_device_id,
            acl: verified_acl,
            guard,
            revoked,
        }),
        None => Err(AuthFailure::Rejected(format!(
            "authentication failed for client '{client_id}': {fail_reason}"
        ))),
    }
}

/// Reads one length-prefixed AUTH_* message from the handshake stream.
///
/// The length prefix is whatever the peer sent first, so it is only trusted
/// after the range check: a data stream offered to a 2FA server starts with
/// bytes that would otherwise ask for a gigabyte-sized buffer.
async fn read_auth_message(recv: &mut iroh::endpoint::RecvStream) -> Result<Vec<u8>, String> {
    let len_buf = read_bytes(recv, 4).await?;
    let msg_len = u32::from_le_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;

    if msg_len == 0 || msg_len > MAX_AUTH_MESSAGE {
        return Err(format!("auth message length {} is out of range", msg_len));
    }

    read_bytes(recv, msg_len).await
}

/// Reads exactly `len` bytes, one cancel-safe `read` at a time.
///
/// `RecvStream::read` is cancel-safe and `read_exact` is not, and the handshake
/// runs under a deadline that may drop this future mid-message.
async fn read_bytes(recv: &mut iroh::endpoint::RecvStream, len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        match recv.read(&mut buf[filled..]).await {
            Ok(Some(0)) => break,
            Ok(Some(n)) => filled += n,
            Ok(None) => break,
            Err(e) => return Err(format!("failed to read auth message: {}", e)),
        }
    }
    if filled < len {
        return Err(format!(
            "client closed the auth stream after {} of {} bytes",
            filled, len
        ));
    }
    Ok(buf)
}

pub async fn handle_connection(
    conn: Connection,
    config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    auth_state: Option<AuthState>,
    peers: Arc<PeerRegistry>,
    limiters: Limiters,
) {
    let peer_id = conn.remote_id();
    let peer = peer_id.to_string();
    tracing::info!("New connection from peer: {}", peer_id);

    // One counter for the whole connection: the L4 path hands out a slot per flow and
    // answers `TooManyFlows` once it is full, so a client with many UDP flows fails the
    // one that does not fit instead of blocking inside `open_bi`.
    let limiter = Arc::new(l4::FlowLimiter::new(l4::DEFAULT_MAX_FLOWS_PER_CONNECTION));

    // A second counter covering every stream, not just L4 flows: `accept_bi`
    // below spawns a task per stream whatever the stream turns out to be, and
    // the limiter above is only consulted once the bytes say "L4".
    let stream_slots = Arc::new(tokio::sync::Semaphore::new(
        MAX_CONCURRENT_STREAMS_PER_CONNECTION,
    ));

    let paths = conn.paths();
    let selected_path = paths.iter().find(|p| p.is_selected());
    let initial_kind = match &selected_path {
        Some(path) => {
            tracing::info!("Initial connection type: {}", get_connection_type(path));
            path_kind(path)
        }
        None => {
            tracing::info!("Initial connection type: Unknown (no selected path)");
            metrics::PathKind::Unknown
        }
    };

    // Counted here, where the connection is being served, rather than in the
    // accept loop: a connection refused by the limiter never gets this far and
    // should not appear as one that was served.
    metrics::METRICS.connection_opened();
    // A connection typically starts relayed and becomes direct once hole
    // punching succeeds, so the bucket it belongs to is not decided once. The
    // task owns the ticket and hands it back when the connection ends.
    tokio::spawn(track_connection_path(
        conn.clone(),
        initial_kind,
        peer_id,
        peers.clone(),
    ));

    // ===== 2FA Authentication Handshake =====
    //
    // Resolved before the block, not inside an `if let` condition: the read
    // guard has to be gone by the time `perform_authentication` asks for the
    // write lock, and holding a read guard across that would deadlock the
    // endpoint's own RwLock.
    //
    // `enabled` is read here, once per connection, which is also where a reload
    // that turns 2FA on takes effect: the value is live, so a connection opened
    // after that reload is gated. A connection already carrying a `client_acl`
    // is not re-gated mid-flight — its authorization was decided at its own
    // handshake, the same rule that lets a deleted client finish an open
    // connection.
    let auth = match &auth_state {
        Some(auth) => {
            let enabled = auth.config().read().await.enabled;
            if enabled { Some(auth) } else { None }
        }
        None => None,
    };
    // The authenticated client's host authorization, snapshotted at the
    // handshake and carried by every stream this connection opens. `None`
    // means no 2FA ran, which is the unrestricted case anyway.
    let mut client_acl: Option<Arc<ClientAcl>> = None;
    // Who the connection turned out to be, for the peer list. Filled in only
    // when 2FA ran and passed: with it off there is no handshake, and no
    // identity to report.
    let mut identity = PeerIdentity::default();
    // What keeps the connection in the peer registry, filled in by whichever
    // path registers it: the handshake when 2FA ran, the fallback below when it
    // did not.
    let mut registered: Option<(PeerGuard, tokio::sync::watch::Receiver<bool>)> = None;

    if let Some(auth) = auth {
        let outcome = tokio::time::timeout(
            AUTH_HANDSHAKE_TIMEOUT,
            perform_authentication(
                &conn,
                auth,
                &peer,
                PeerRegistration {
                    registry: peers.clone(),
                    endpoint_id: peer_id,
                    path: initial_kind,
                },
            ),
        )
        .await;
        match outcome {
            Ok(Ok(authenticated)) => {
                tracing::info!(
                    "Client '{}' authenticated successfully from {}",
                    authenticated.client_id,
                    peer_id
                );
                identity = PeerIdentity {
                    client_id: Some(authenticated.client_id.clone()),
                    device: authenticated.device,
                };
                client_acl = Some(Arc::new(authenticated.acl));
                registered = Some((authenticated.guard, authenticated.revoked));
            }
            Ok(Err(AuthFailure::Rejected(reason))) => {
                tracing::warn!("Authentication failed for {}: {}", peer_id, reason);
                conn.close(
                    auth_close_code::REJECTED.into(),
                    b"2FA authentication failed",
                );
                return;
            }
            Ok(Err(AuthFailure::NotStarted(reason))) => {
                // The client never offered credentials, which usually means
                // it has no 2FA configured at all: the close code is what
                // tells it so, since it is not reading anything else.
                tracing::warn!(
                    "Connection from {} refused, 2FA is required: {}",
                    peer_id,
                    reason
                );
                conn.close(auth_close_code::REQUIRED.into(), b"2FA required");
                return;
            }
            Err(_) => {
                tracing::warn!(
                    "Connection from {} refused, no 2FA handshake within {}s",
                    peer_id,
                    AUTH_HANDSHAKE_TIMEOUT.as_secs()
                );
                conn.close(auth_close_code::REQUIRED.into(), b"2FA required");
                return;
            }
        }
    }
    // ===== Authentication Complete =====
    //
    // Listed from here, not from the top of the function: a peer that was
    // refused its handshake never got a connection, and `GET /v1/connections`
    // is asked "who is connected", not "who tried". The path may be corrected a
    // moment later by the tracker above, which keeps following it.
    // The registry keeps its own copy: the identity below is also what every
    // stream of this connection writes into the access log.
    //
    // Its other half is how `client revoke` reaches a connection rather than
    // only the next dial: the config watcher flips it, and the loop below stops
    // serving this peer and hangs up.
    //
    // When 2FA ran, the channel and the guard come from the handshake, which
    // registered this connection while it still held the auth lock. Only a
    // server with 2FA off reaches the fallback, and there is nothing to be
    // revoked there — no credential was checked, so no reload can drop one.
    let (mut revoked_rx, _peer) = match registered {
        Some((guard, revoked)) => (revoked, guard),
        None => {
            let (revoked_tx, revoked_rx) = tokio::sync::watch::channel(false);
            (
                revoked_rx,
                peers.insert(peer_id, initial_kind, identity.clone(), revoked_tx),
            )
        }
    };

    loop {
        // Whichever happens first wins, and a revocation that arrives while a
        // stream is being accepted loses nothing: the connection is closed in
        // the next line whether the accept completed or not.
        let accepted = tokio::select! {
            accepted = conn.accept_bi() => accepted,
            // Either the value changed, or every sender is gone — which can
            // only mean this loop outlived its own registry entry, and both
            // say the same thing: stop serving this peer.
            _ = revoked_rx.changed() => {
                tracing::info!(
                    "Closing {}: its credential is no longer in [auth]",
                    peer_id
                );
                conn.close(auth_close_code::REVOKED.into(), b"credential revoked");
                return;
            }
        };

        match accepted {
            Ok((send, recv)) => {
                // Refused rather than queued: waiting for a slot would only move
                // the unbounded growth into a backlog this loop cannot see, and
                // the peer has to learn that its stream was not served.
                //
                // Two ceilings, checked together and for different reasons: the
                // per-connection one keeps one connection from asking for the
                // whole process's allowance, and the process-wide one keeps a
                // crowd of connections from doing it between them. The process
                // slot is taken first and given back if the connection's own is
                // full, because the reverse order would leave a permit held for
                // a stream that is never served.
                let global_permit = match limiters.streams.try_acquire() {
                    Some(permit) => permit,
                    None => {
                        tracing::warn!(
                            "Refusing a stream from {peer_id}, the server already has {} streams \
                             in flight",
                            limiters.streams.max_global()
                        );
                        let mut send = send;
                        let _ = send.finish();
                        continue;
                    }
                };
                let Ok(permit) = stream_slots.clone().try_acquire_owned() else {
                    drop(global_permit);
                    tracing::warn!(
                        "Connection {} already has {} streams in flight, closing this one",
                        peer_id,
                        MAX_CONCURRENT_STREAMS_PER_CONNECTION
                    );
                    let mut send = send;
                    let _ = send.finish();
                    continue;
                };
                let config_clone = config.clone();
                let clients_clone = clients.clone();
                let limiter_clone = limiter.clone();
                let peer_clone = peer.clone();
                let acl_clone = client_acl.clone();
                // Who the connection turned out to be, for the access log.
                // Cloned per stream rather than shared, because the task owns
                // everything it reads.
                let who_clone = identity.clone();
                // One id per request, and one span wrapping it. Both are made
                // here rather than inside the handler: `method`, `uri` and
                // `status` are not known until the head has been read, and a
                // span opened after that would not cover the part where the
                // request is routed and admitted. The handler fills them in on
                // `Span::current()` as it learns them.
                let request_id = crate::log::next_request_id();
                let span = tracing::info_span!(
                    "request",
                    id = %request_id,
                    method = tracing::field::Empty,
                    uri = tracing::field::Empty,
                    status = tracing::field::Empty,
                );
                tokio::spawn(async move {
                    // Held for the life of the task and released by its Drop, so
                    // a slot frees however the stream ends. Both permits, for the
                    // same reason and in the same way.
                    let _permit = permit;
                    let _global_permit = global_permit;
                    if let Err(e) = handle_bidi_stream(
                        send,
                        recv,
                        &config_clone,
                        &clients_clone,
                        &limiter_clone,
                        &peer_clone,
                        acl_clone,
                        &request_id,
                        who_clone,
                    )
                    .instrument(span)
                    .await
                    {
                        tracing::error!("Failed to handle stream from {}: {}", peer_clone, e);
                    }
                });
            }
            Err(e) => {
                if e.to_string().contains("closed by peer") {
                    tracing::debug!("Connection {} closed by peer", peer_id);
                } else {
                    tracing::warn!("Connection {} stream accept error: {}", peer_id, e);
                }
                break;
            }
        }
    }

    tracing::info!("Connection closed for peer: {}", peer_id);
}

/// `in_flight` is the guard the accept loop took for this connection. It has to
/// travel all the way into the task that serves the connection: the drain at
/// shutdown counts these, and a guard dropped when the accept returns would
/// make it count only connections still being accepted — every established
/// one, including WebSocket sessions and L4 flows, would be invisible to it and
/// cut off the moment the process decided to stop.
pub async fn handle_incoming(
    incoming: Incoming,
    config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    auth_state: Option<AuthState>,
    limiters: Limiters,
    in_flight: InFlightGuard,
    peers: Arc<PeerRegistry>,
) {
    match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => {
                // Checked as soon as the id is known, before the 2FA handshake
                // and before the connection task exists: a peer that has already
                // spent its allowance gets a close frame and nothing else, so
                // opening connections is not a way to make the server work.
                let peer_id = conn.remote_id();
                let Some(guard) = limiters.connections.try_acquire(peer_id) else {
                    // Both ceilings refuse here and the two mean different
                    // things to whoever has to answer the alert: one peer is
                    // over its own allowance, or the process is full. Say
                    // which, or the second reads as the first.
                    let limiter = &limiters.connections;
                    let per_peer = limiter.count(&peer_id);
                    let total = limiter.total();
                    if per_peer >= limiter.max() {
                        tracing::warn!(
                            "Refusing connection from {peer_id}, it already holds {per_peer} of {}",
                            limiter.max()
                        );
                    } else {
                        tracing::warn!(
                            "Refusing connection from {peer_id}, the server is at {total} of {} \
                             concurrent connections",
                            limiter.max_global()
                        );
                    }
                    conn.close(auth_close_code::TOO_MANY.into(), b"too many connections");
                    return;
                };
                tokio::spawn(async move {
                    // Held for as long as the connection is served, and released
                    // by the guard's Drop however this task ends: the limiter
                    // one for the peer's allowance, the in-flight one so a
                    // shutdown knows this connection is still here.
                    let _guard = guard;
                    let _in_flight = in_flight;
                    handle_connection(conn, config, clients, auth_state, peers, limiters).await;
                });
            }
            Err(e) => {
                tracing::error!("Failed to complete connection: {}", e);
            }
        },
        Err(e) => {
            tracing::error!("Failed to accept incoming connection: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthState, EnrollmentSlot, EnrollmentVerdict, IssuedCredential, StreamBudgets, StreamHead,
        blocking_config_write, build_websocket_upgrade_request, constant_time_eq,
        count_enrollment_failure, enrollment_verdict, find_headers_end, issue_enrolled_secret,
        persist_auth_state, read_stream_head, undo_enrolled_secret,
    };
    use crate::auth::{AuthConfig, ClientAuth, DeviceAuth};
    use nexapipe_proto::secret::SecretString;
    use std::collections::HashMap;

    /// The state file carries the counters as of the write, not as of an
    /// earlier moment.
    ///
    /// The write happens with the auth lock released — a lock held across a
    /// disk write stalls every connection that is authenticating, not only the
    /// one whose counters are being written — so the counters are read at
    /// write time. A failure counted between the record and the write is
    /// counted too, which is what "as of the write" means.
    #[tokio::test]
    async fn the_state_file_carries_the_counters_as_of_the_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[auth]\nenabled = true\n\
             [auth.clients.client-001]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n",
        )
        .unwrap();

        let (_, config) = crate::config::ProxyConfig::load_with_auth(path.to_str().unwrap())
            .expect("the config loads");
        let auth = AuthState::new(
            config.expect("the config declares an [auth] section"),
            path.to_str().unwrap(),
        );

        // Two failures, recorded in two separate critical sections — the
        // second one after the first has already been counted.
        for _ in 0..2 {
            let mut cfg = auth.config().write().await;
            cfg.clients
                .get_mut("client-001")
                .expect("the client is there")
                .record_failure(3, 60);
        }

        persist_auth_state(&auth)
            .await
            .expect("the state is written");

        let state = std::fs::read_to_string(dir.path().join("state.toml")).unwrap();
        assert!(
            state.contains("failed_attempts = 2"),
            "the file carries the count as of the write, not as of an earlier moment: {state}"
        );
    }

    /// The budgets a head is read under, loose enough that no test runs into
    /// them by accident.
    fn generous_budgets() -> StreamBudgets {
        let deadlines = crate::deadline::Deadlines {
            header: std::time::Duration::from_secs(30),
            tls_hello: std::time::Duration::from_secs(30),
            ..crate::deadline::Deadlines::default()
        };
        StreamBudgets::new(&deadlines, tokio::time::Instant::now())
    }

    /// A head that is finished, and the bytes that came with it.
    #[tokio::test]
    async fn a_finished_head_is_a_request() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = client
                .write_all(b"GET /x HTTP/1.1\r\nHost: a.example\r\n\r\nBODY")
                .await;
        });

        let head = read_stream_head(&mut server, &generous_budgets())
            .await
            .expect("the head");

        match head {
            StreamHead::Request { head, body } => {
                assert!(head.ends_with(b"\r\n\r\n"), "the head is not finished");
                assert_eq!(body, b"BODY", "the bytes after the head were lost");
            }
            other => panic!("expected a request, got {other:?}"),
        }
    }

    /// A head over the limit is refused, not parsed.
    ///
    /// It used to be parsed: the read loop broke out of it with a head that
    /// was never finished, and the parser read every line of that as a header
    /// — the last one truncated — and the request was forwarded to a backend.
    /// The log said "headers too large" and the backend was asked anyway.
    #[tokio::test]
    async fn a_head_over_the_limit_is_refused() {
        let (mut client, mut server) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            // A request line and then headers that never end.
            let mut bytes = b"GET /x HTTP/1.1\r\n".to_vec();
            while bytes.len() < 128 * 1024 {
                bytes.extend_from_slice(b"X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
            }
            let _ = client.write_all(&bytes).await;
        });

        let head = read_stream_head(&mut server, &generous_budgets())
            .await
            .expect("the head");

        match head {
            StreamHead::TooLarge(size) => assert!(size > 64 * 1024),
            other => panic!("expected the head to be refused, got {other:?}"),
        }
    }

    /// A peer that goes away before the head is finished did not send a
    /// request. It used to be parsed and forwarded anyway, so half a request
    /// line became a header.
    #[tokio::test]
    async fn a_head_the_peer_abandoned_is_not_a_request() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = client
                .write_all(b"GET /x HTTP/1.1\r\nHost: a.example\r\n")
                .await;
            drop(client);
        });

        let head = read_stream_head(&mut server, &generous_budgets())
            .await
            .expect("the head");

        match head {
            StreamHead::Incomplete => {}
            other => panic!("expected no request, got {other:?}"),
        }
    }

    /// The first byte says which protocol a stream carries, and it says it
    /// before any head is looked for. An L4 tunnel never sends a request head,
    /// so waiting for one would hang it.
    #[tokio::test]
    async fn an_l4_preface_is_handed_on_without_waiting_for_a_head() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = client.write_all(&[0x05, 0x01, 0x01, 0x00]).await;
        });

        let head = read_stream_head(&mut server, &generous_budgets())
            .await
            .expect("the head");

        match head {
            StreamHead::Other(bytes) => {
                assert_eq!(
                    bytes,
                    vec![0x05, 0x01, 0x01, 0x00],
                    "the bytes were changed"
                );
            }
            other => panic!("expected the preface to be handed on, got {other:?}"),
        }
    }

    #[test]
    fn a_short_head_budget_does_not_cut_off_a_tls_or_l4_client() {
        // The observation this test exists for: the first byte says which
        // protocol a stream carries, and the wait for it must not be the HTTP
        // head's budget. A short `header_secs` used to close a TLS or an L4
        // stream before it could be classified, which took the tunnel down
        // with it — and neither protocol ever sends a request head, so the
        // head's budget was never the right one for them.
        let deadlines = crate::deadline::Deadlines {
            header: std::time::Duration::from_secs(1),
            tls_hello: std::time::Duration::from_secs(10),
            ..crate::deadline::Deadlines::default()
        };
        let open = tokio::time::Instant::now();
        let budgets = StreamBudgets::new(&deadlines, open);

        assert_eq!(
            budgets.identify_budget(),
            std::time::Duration::from_secs(10),
            "the first byte is bounded by the hello budget, not the head's"
        );
        assert_eq!(
            budgets.head - open,
            std::time::Duration::from_secs(1),
            "the head itself is still bounded by header_secs"
        );
    }

    #[test]
    fn the_default_budgets_leave_an_http_client_the_room_it_had() {
        // The other half: with the defaults the first byte waits exactly as
        // long as it did before, so nothing about an ordinary HTTP client
        // changes.
        let deadlines = crate::deadline::Deadlines::default();
        let open = tokio::time::Instant::now();
        let budgets = StreamBudgets::new(&deadlines, open);

        assert_eq!(budgets.identify_budget(), deadlines.header);
        assert_eq!(budgets.head - open, deadlines.header);
    }

    /// The shape an enrollment takes when the client named a device and offered
    /// no key: a secret of that device's own.
    fn device_secret(name: &str, secret: &str) -> IssuedCredential {
        IssuedCredential::DeviceSecret {
            name: name.to_string(),
            secret: SecretString::new(secret.to_string()),
        }
    }

    /// A write whose caller gave up still happens, and happens *first*.
    ///
    /// The abandoned write is slow on purpose, so the only way the second one
    /// can end up last in the file is for it to have waited: without the gate
    /// the two overlap and whichever reaches the disk last wins, which is a
    /// lockout counter or an issued secret quietly disappearing.
    #[tokio::test]
    async fn an_abandoned_write_still_lands_before_the_next_one() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "start\n").expect("seed the file");
        let slow_path = path.to_string_lossy().into_owned();
        let fast_path = slow_path.clone();

        let abandoned = tokio::spawn(async move {
            let _ = blocking_config_write(slow_path, |path| {
                std::thread::sleep(std::time::Duration::from_millis(300));
                std::fs::write(path, "slow\n").map_err(|e| anyhow::anyhow!("{e}"))
            })
            .await;
        });

        // Give it a start, then walk away the way a cancelled handshake does.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        abandoned.abort();

        blocking_config_write(fast_path, |path| {
            std::fs::write(path, "fast\n").map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await
        .expect("the second write runs");

        let on_disk = std::fs::read_to_string(&path).expect("read the file");
        assert_eq!(on_disk, "fast\n", "the slow write was ordered before it");
    }

    /// The marker only ever appears once a read has brought in its last byte,
    /// and the scan starts where the previous read left off — three bytes back,
    /// because a marker split across two reads has to still be found.
    #[test]
    fn a_header_marker_split_across_reads_is_still_found() {
        let head = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";

        // Everything up to the last three bytes has been scanned already.
        let mut buf = Vec::new();
        let mut searched = 0;
        let mut found = None;
        for chunk in head.chunks(7) {
            buf.extend_from_slice(chunk);
            if let Some(pos) = find_headers_end(&buf, searched) {
                found = Some(pos);
                break;
            }
            searched = buf.len().saturating_sub(3);
        }

        assert_eq!(
            found.map(|pos| pos + 4),
            Some(head.len()),
            "the marker was missed when it arrived in pieces"
        );
    }

    #[test]
    fn a_buffer_without_the_marker_is_not_a_head() {
        assert_eq!(
            find_headers_end(b"GET / HTTP/1.1\r\nHost: a.test\r\n", 0),
            None
        );
        // Nothing to scan: a read that brought no bytes cannot have completed
        // the marker either.
        assert_eq!(find_headers_end(b"", 0), None);
        assert_eq!(find_headers_end(b"\r\n", 40), None);
    }

    /// A config holding one client, with `token` left outstanding for it.
    fn auth_with_pending(token: Option<&str>) -> AuthConfig {
        let mut cfg = AuthConfig::default();
        cfg.clients.insert(
            "alice".to_string(),
            ClientAuth {
                secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                created_at: "0".to_string(),
                allow_hosts: None,
                allow_ports: None,
                allow_ports_strict: false,
                pending_enrollment: token.map(|t| SecretString::new(t.to_string())),
                devices: HashMap::new(),
                unnamed_device_allowed: true,
                last_used: None,
                failed_attempts: 0,
                locked_until: None,
                enrollment_failed_attempts: 0,
                enrollment_locked_until: None,
            },
        );
        cfg
    }

    /// The comparison is what stands between a token and whoever copied the
    /// link, so it has to be right at the boundaries: equal, wrong at the first
    /// byte, wrong at the last, and the wrong length.
    #[test]
    fn token_comparison_only_accepts_an_exact_match() {
        let token = "0123456789abcdef";
        assert!(constant_time_eq(token.as_bytes(), token.as_bytes()));
        assert!(!constant_time_eq(
            token.as_bytes(),
            "1123456789abcdef".as_bytes()
        ));
        assert!(!constant_time_eq(
            token.as_bytes(),
            "0123456789abcdeF".as_bytes()
        ));
        assert!(!constant_time_eq(
            token.as_bytes(),
            "0123456789abcdef0".as_bytes()
        ));
        assert!(!constant_time_eq(token.as_bytes(), b""));
        // Two empty tokens compare equal, which is why a client with no token
        // outstanding must not be enrolled at all rather than compared here.
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn an_outstanding_token_is_accepted() {
        let cfg = auth_with_pending(Some("0123456789abcdef"));
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "0123456789abcdef", None),
            EnrollmentVerdict::Accept
        );
    }

    /// An enrollment that names a device writes that device's own entry and
    /// leaves the client's `secret` alone: the two are different credentials,
    /// and rotating the shared one is what re-enrolls every device at once.
    #[test]
    fn an_enrollment_that_names_a_device_writes_only_its_own_entry() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));
        let shared = cfg.clients["alice"].secret.clone();

        let slot =
            issue_enrolled_secret(&mut cfg, "alice", &device_secret("laptop", "LAPTOPSECRET"));

        let alice = &cfg.clients["alice"];
        assert_eq!(
            alice.secret.expose_secret(),
            shared.expose_secret(),
            "the shared secret was rotated too"
        );
        assert_eq!(alice.devices["laptop"].secret.as_str(), "LAPTOPSECRET");
        assert!(
            alice.pending_enrollment.is_none(),
            "the token was left spendable"
        );
        assert!(matches!(slot, EnrollmentSlot::Device { .. }));
    }

    /// A key enrollment records the key and nothing else: the empty secret is
    /// what keeps the handshake from ever asking this device for a code, so an
    /// entry carrying both would be the one thing the loader refuses to read
    /// back.
    #[test]
    fn a_key_enrollment_records_the_key_and_no_secret() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));
        let key = iroh::SecretKey::generate();
        let spelled = crate::auth::public_key_hex(&key.public());

        let slot = issue_enrolled_secret(
            &mut cfg,
            "alice",
            &IssuedCredential::DeviceKey {
                name: "phone".to_string(),
                key: spelled.clone(),
            },
        );

        let device = &cfg.clients["alice"].devices["phone"];
        assert_eq!(device.public_key.as_deref(), Some(spelled.as_str()));
        assert!(
            device.secret.expose_secret().is_empty(),
            "a key device has no TOTP seed"
        );
        assert!(matches!(slot, EnrollmentSlot::Device { .. }));
    }

    /// The path that existed before there was a table: no name is the device
    /// that has none, and it answers with the client's own `secret`.
    #[test]
    fn an_enrollment_that_names_no_device_rotates_the_clients_secret() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));

        let slot = issue_enrolled_secret(
            &mut cfg,
            "alice",
            &IssuedCredential::SharedSecret(SecretString::new("NEWSECRET".to_string())),
        );

        assert_eq!(cfg.clients["alice"].secret.as_str(), "NEWSECRET");
        assert!(cfg.clients["alice"].devices.is_empty());
        assert!(matches!(slot, EnrollmentSlot::Shared { .. }));
    }

    /// What the rollback is for: a device that was enrolled before keeps the
    /// credential it had, because the write that was to replace it failed and
    /// the new secret exists nowhere but in this process's memory.
    #[test]
    fn a_failed_write_puts_the_device_it_replaced_back() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));
        cfg.clients.get_mut("alice").unwrap().devices.insert(
            "laptop".to_string(),
            DeviceAuth {
                secret: SecretString::new("OLDSECRET".to_string()),
                public_key: None,
                created_at: "0".to_string(),
                last_used: None,
            },
        );

        let slot = issue_enrolled_secret(&mut cfg, "alice", &device_secret("laptop", "NEWSECRET"));
        assert_eq!(
            cfg.clients["alice"].devices["laptop"].secret.as_str(),
            "NEWSECRET"
        );

        undo_enrolled_secret(&mut cfg, "alice", slot, "0123456789abcdef");

        let alice = &cfg.clients["alice"];
        assert_eq!(alice.devices["laptop"].secret.as_str(), "OLDSECRET");
        assert_eq!(
            alice
                .pending_enrollment
                .as_ref()
                .map(|token| token.expose_secret().as_str()),
            Some("0123456789abcdef"),
            "the token is still the client's only way to enroll"
        );
    }

    /// The same, for a device that had no entry: taking back the credential
    /// means removing it, not leaving a device behind that no config on disk
    /// carries.
    #[test]
    fn a_failed_write_takes_back_a_device_that_had_no_entry() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));

        let slot = issue_enrolled_secret(&mut cfg, "alice", &device_secret("phone", "NEWSECRET"));
        undo_enrolled_secret(&mut cfg, "alice", slot, "0123456789abcdef");

        let alice = &cfg.clients["alice"];
        assert!(alice.devices.is_empty(), "{:?}", alice.devices.keys());
    }

    /// The unnamed path rolls back to the secret it rotated away, or this
    /// process would keep accepting a credential that is on no disk.
    #[test]
    fn a_failed_write_puts_the_clients_secret_back() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));
        let shared = cfg.clients["alice"].secret.clone();

        let slot = issue_enrolled_secret(
            &mut cfg,
            "alice",
            &IssuedCredential::SharedSecret(SecretString::new("NEWSECRET".to_string())),
        );
        undo_enrolled_secret(&mut cfg, "alice", slot, "0123456789abcdef");

        assert_eq!(cfg.clients["alice"].secret, shared);
    }

    /// The token is a credential like any other: guessing at it has to cost
    /// the same as guessing a TOTP code, or the link is a slower credential
    /// with no ceiling on how many times it can be tried.
    #[test]
    fn a_wrong_token_is_refused_and_counted() {
        let cfg = auth_with_pending(Some("0123456789abcdef"));
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "0123456789abcde0", None),
            EnrollmentVerdict::Refuse { counted: true }
        );
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "", None),
            EnrollmentVerdict::Refuse { counted: true }
        );
    }

    /// **What the counting costs is the enrollment's own counter.**
    ///
    /// A client id is not a secret: it is in the invite link, in `nexapipe
    /// client list` and in whatever the operator pasted into a ticket. So
    /// anybody who knows one can send enrollment attempts at a client that is
    /// waiting to enroll — and while those attempts were counted against the
    /// client's authentication counter, the devices that had already enrolled
    /// were locked out over a credential they were never sent.
    #[test]
    fn a_wrong_token_is_counted_against_the_enrollment_and_not_the_client() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));

        count_enrollment_failure(&mut cfg, "alice", 5, 300);

        let alice = &cfg.clients["alice"];
        assert_eq!(
            alice.enrollment_failed_attempts, 1,
            "the token's own counter moved"
        );
        assert_eq!(
            alice.failed_attempts, 0,
            "the client's authentication counter did not: a client id is not a secret, and \
             somebody who knows one must not be able to lock the client's own devices out"
        );
        assert_eq!(alice.locked_until, None, "the client is not locked out");
        assert!(!alice.is_locked_out());
    }

    /// The token keeps a ceiling: `max_attempts` wrong guesses close the
    /// enrollment slot for the window, and the right token is refused with it.
    ///
    /// The ceiling is what makes the link unguessable rather than merely
    /// unshared — and it is the enrollment's ceiling, not the client's.
    #[test]
    fn the_token_has_a_ceiling_of_its_own() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));

        for _ in 0..3 {
            count_enrollment_failure(&mut cfg, "alice", 3, 300);
        }

        let alice = &cfg.clients["alice"];
        assert!(alice.is_enrollment_locked_out(), "the slot is closed");
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "0123456789abcdef", None),
            EnrollmentVerdict::Refuse { counted: false },
            "even the right token is refused while the slot is closed"
        );
        assert!(
            !alice.is_locked_out(),
            "the client itself is not locked out: the devices that already enrolled go on \
             authenticating"
        );
        assert_eq!(alice.failed_attempts, 0);
    }

    /// A lockout whose time has run out is cleared, so the first mistake after
    /// it does not close the slot again immediately.
    #[test]
    fn an_expired_enrollment_lockout_is_cleared() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));

        let alice = cfg.clients.get_mut("alice").unwrap();
        alice.enrollment_failed_attempts = 3;
        alice.enrollment_locked_until = Some(1);
        assert!(!alice.is_enrollment_locked_out(), "the window has run out");

        alice.refresh_enrollment_lockout();
        assert_eq!(alice.enrollment_failed_attempts, 0);
        assert_eq!(alice.enrollment_locked_until, None);
    }

    /// A client with no token outstanding is refused without being counted:
    /// counting it would let anyone who knows a client id lock that client out
    /// of its own authentication by sending it enrollment requests.
    #[test]
    fn a_client_with_nothing_pending_is_refused_without_being_counted() {
        let cfg = auth_with_pending(None);
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "0123456789abcdef", None),
            EnrollmentVerdict::Refuse { counted: false }
        );
    }

    #[test]
    fn an_unknown_client_is_refused_without_being_counted() {
        let cfg = auth_with_pending(Some("0123456789abcdef"));
        assert_eq!(
            enrollment_verdict(&cfg, "bob", "0123456789abcdef", None),
            EnrollmentVerdict::Refuse { counted: false }
        );
    }

    /// A locked-out client is refused before the token is looked at, so a
    /// lockout cannot be walked around by enrolling — and retrying does not
    /// push the lockout further out.
    #[test]
    fn a_locked_out_client_is_refused_even_with_the_right_token() {
        let mut cfg = auth_with_pending(Some("0123456789abcdef"));
        cfg.clients.get_mut("alice").unwrap().locked_until = Some(u64::MAX);
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "0123456789abcdef", None),
            EnrollmentVerdict::Refuse { counted: false }
        );
    }

    /// The runtime half of the empty-token rule: `constant_time_eq` answers
    /// true for two empty slices, so a blank token on both sides has to be
    /// refused on the way in rather than compared.
    #[test]
    fn a_blank_pending_token_is_never_accepted() {
        let cfg = auth_with_pending(Some(""));
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "", None),
            EnrollmentVerdict::Refuse { counted: false }
        );
    }

    /// A device that is already in the table keeps its credential.
    ///
    /// The token proves the invite reached someone, not which device it
    /// reached — the name is supplied by the client at enrollment time — so
    /// overwriting the entry handed a device that is already enrolled to
    /// whoever copied the link: the real device is locked out, while the access
    /// log and the peer list go on attributing the connection to it.
    #[test]
    fn an_enrollment_may_not_take_over_a_device_that_is_already_there() {
        let cfg = auth_with_device("laptop", Some("0123456789abcdef"));
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "0123456789abcdef", Some("laptop")),
            EnrollmentVerdict::Refuse { counted: false }
        );
    }

    /// The same table, a name that is not in it: an enrollment is how a device
    /// that is not there yet gets one, and refusing those would make the table
    /// impossible to grow past the first device.
    #[test]
    fn an_enrollment_may_still_add_a_device_that_is_not_there() {
        let cfg = auth_with_device("laptop", Some("0123456789abcdef"));
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "0123456789abcdef", Some("phone")),
            EnrollmentVerdict::Accept
        );
        assert_eq!(
            enrollment_verdict(&cfg, "alice", "0123456789abcdef", None),
            EnrollmentVerdict::Accept
        );
    }

    /// Refused for the right reason: it is not a guess at the token, so it must
    /// not move the lockout counter. Counting it would let whoever is holding a
    /// copied link lock the client out with retries.
    #[test]
    fn taking_over_a_device_is_not_counted_as_a_wrong_token() {
        let cfg = auth_with_device("laptop", Some("0123456789abcdef"));
        assert!(!enrollment_verdict(&cfg, "alice", "0123456789abcdef", Some("laptop")).counted());
    }

    /// A config holding one client, with `token` left outstanding for it and
    /// `device` already enrolled under it.
    fn auth_with_device(device: &str, token: Option<&str>) -> AuthConfig {
        let mut cfg = auth_with_pending(token);
        cfg.clients.get_mut("alice").unwrap().devices.insert(
            device.to_string(),
            DeviceAuth {
                secret: SecretString::new("DEVICESECRET".to_string()),
                public_key: None,
                created_at: "0".to_string(),
                last_used: None,
            },
        );
        cfg
    }

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

        let request_buf = build_websocket_upgrade_request(&request, &backend_info, "127.0.0.1");

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

        let request_buf = build_websocket_upgrade_request(&request, &backend_info, "127.0.0.1");
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
}
