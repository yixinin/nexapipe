use crate::ClientError;
use crate::connection_pool::IrohConnectionPool;
use crate::endpoint_group::{EndpointGroup, PooledConnection};
use crate::flow::{FlowKind, FlowMeta};
use crate::http::{is_websocket_request_static, parse_http_request_legacy};
use iroh::EndpointId;
use iroh::endpoint::{RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

#[cfg(feature = "tracing")]
use tracing;

#[cfg(feature = "jni")]
use crate::jni_log;

/// No-op `jni_log!` for builds without the `jni` feature.
///
/// The format arguments are still *evaluated* (borrowed) inside a dead branch,
/// so the optimiser removes the call but `unused_variables` does not fire on
/// variables that only ever appear inside a log statement.
#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if false {
            let _ = ::std::format_args!($($arg)*);
        }
    };
}

/// Gate for the debug-only WebSocket frame dumps.
///
/// `jni_log!` already skips formatting when `Debug` logging is off, but that only helps if the
/// arguments are cheap. Building a frame preview is not: it hex-escapes up to 256 bytes with
/// one `format!` allocation per non-printable byte, and it used to run on **every** WebSocket
/// chunk in both directions regardless of the log level.
#[cfg(feature = "jni")]
#[inline]
fn debug_log_enabled() -> bool {
    crate::jni::debug_log_enabled()
}

#[cfg(not(feature = "jni"))]
#[inline]
fn debug_log_enabled() -> bool {
    false
}

/// Whether the local proxy may serve `bound`.
///
/// **Loopback only, unless the caller says otherwise.** The local proxy does
/// not authenticate the peer that connects to it: it hands out the tunnel of a
/// connection that has already authenticated, so whoever reaches the port gets
/// the tunnel without a credential. That is the same reason the server's own
/// plaintext listener is loopback-only unless it is explicitly exposed, and
/// the desktop app already refuses a non-loopback address before it reaches
/// this crate.
///
/// `exposed` is the caller's own answer to the same question: a deployment
/// that puts something else in front of the port — a firewall, a container
/// network — says so explicitly rather than by accident.
pub fn may_bind_local_proxy(bound: SocketAddr, exposed: bool) -> bool {
    exposed || bound.ip().is_loopback()
}

/// Where the request line ends, in the bytes of a request's header block.
///
/// The end is the first **line feed**, whether it came with a carriage return
/// or not: a bare LF ends the line for a parser that accepts one, and
/// looking for "\r\n" instead would step over the first header as well — and
/// the header it steps over is the `Host` one, which says which name the
/// request is for. The server substitutes the backend's address for a
/// request that arrives without one, and a request for a name is then served
/// by the wrong site.
///
/// Returns the offset of the line feed, so the line itself ends at
/// `offset + 1`; zero when there is no line feed at all, which is a header
/// block that never had a request line.
fn request_line_end(request: &[u8]) -> usize {
    request.iter().position(|b| *b == b'\n').unwrap_or(0)
}

/// Headers whose value is a credential, and so never belongs in a log.
const SENSITIVE_HEADERS: [&str; 5] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

/// The headers of a request, with the values that carry credentials replaced.
///
/// Logging them whole put `Authorization` and `Cookie` into logcat on every
/// request. Names and non-sensitive values are still what makes a dump useful
/// when debugging, so only the values are dropped.
fn redacted_headers(headers: &::http::HeaderMap) -> String {
    let mut out = String::from("{");
    for (name, value) in headers {
        if SENSITIVE_HEADERS.contains(&name.as_str().to_lowercase().as_str()) {
            out.push_str(&format!("{}: <redacted>, ", name));
        } else {
            out.push_str(&format!("{}: {:?}, ", name, value));
        }
    }
    out.push('}');
    out
}

/// The buffer one copy of a stream reads into.
///
/// **32 KiB**, which is what the server uses for the same job, and about what
/// a socket read fills anyway. The buffer does not decide how fast a stream
/// goes — the copy is a pipeline, and the size of the buffer is the size of
/// one write — but it decides what a connection costs: the local proxy holds
/// one of these while it reads a request, and a tunnel holds two, one per
/// direction.
const STREAM_BUF_SIZE: usize = 32 * 1024;

/// Largest request header the local proxy collects, before it gives up on a
/// peer that never ends one. Same order as the server's own head limit, and
/// far above any real request: what it bounds is a client that keeps the
/// connection open and dribbles bytes into it.
const MAX_REQUEST_HEADER: usize = 64 * 1024;

/// Whether what has been read of a request is over [`MAX_REQUEST_HEADER`].
///
/// The cap is on the header, not on the request: a small header followed by a
/// body of any size is an ordinary upload, so what is measured is what precedes
/// the terminator. Until one arrives, everything read so far is header as far as
/// anyone can tell — which is the case that bounds a peer that never ends one.
fn header_over_limit(request: &[u8], header_end: Option<usize>) -> bool {
    header_end.unwrap_or(request.len()) > MAX_REQUEST_HEADER
}

/// What reading a request head produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderOutcome {
    /// The head is complete, ending at this offset into the buffer.
    Complete(usize),
    /// The connection should be closed: the caller went away, the head went past
    /// its size cap, or the deadline expired. One value rather than three
    /// because every one of them is answered the same way, and a caller that had
    /// to tell them apart would only be able to log the difference.
    Closed,
}

/// Reads a request head up to its `\r\n\r\n`, bounded by one deadline.
///
/// The deadline is a parameter rather than something read from the environment
/// here, for two reasons: the caller has already taken the instant for the first
/// byte and the rest of the head shares it, and a test can then drive this over
/// a `tokio::io::duplex` pair in milliseconds instead of waiting out the
/// production thirty seconds.
///
/// Extracted from the connection handler so the anti-slowloris property is
/// testable on its own. Under the per-read timeout this replaces, a caller
/// sending one byte before each expiry renewed the deadline on every read and
/// was never disconnected — which is precisely what the test below pins.
async fn read_http_header<S>(
    stream: &mut S,
    request_buf: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> HeaderOutcome
where
    S: tokio::io::AsyncRead + Unpin,
{
    // Already complete in what the first read carried, e.g. a header that
    // arrived whole. Checked before any read so a request that needed none is
    // not charged a deadline it did not need.
    let mut header_end = request_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4);

    // The same cap as the loop, applied to what already arrived: a header that
    // came in one read never enters the loop and would escape the limit.
    if header_over_limit(request_buf, header_end) {
        jni_log!("[DEBUG:local-proxy] Request header over the limit, closing connection");
        return HeaderOutcome::Closed;
    }

    let mut temp_buf = vec![0u8; STREAM_BUF_SIZE];
    while header_end.is_none() {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut temp_buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                jni_log!("[DEBUG:local-proxy] Read error: {}", e);
                return HeaderOutcome::Closed;
            }
            Err(_) => {
                jni_log!(
                    "[DEBUG:local-proxy] Request head did not arrive before its deadline, closing \
                     connection"
                );
                return HeaderOutcome::Closed;
            }
        };

        let prev_len = request_buf.len();
        request_buf.extend_from_slice(&temp_buf[..n]);

        // Search for \r\n\r\n, starting a few bytes before the new data: a
        // terminator can straddle two reads.
        let search_start = prev_len.saturating_sub(3);
        if let Some(pos) = request_buf[search_start..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
        {
            header_end = Some(search_start + pos + 4);
        }

        // A peer that keeps sending without ever ending its headers grows this
        // buffer without bound, and the deadline alone does not stop it: it is
        // sending, just not finishing.
        if header_over_limit(request_buf, header_end) {
            jni_log!("[DEBUG:local-proxy] Request header over the limit, closing connection");
            return HeaderOutcome::Closed;
        }
    }

    match header_end {
        Some(pos) => HeaderOutcome::Complete(pos),
        None => {
            jni_log!("[DEBUG:local-proxy] HTTP header end not found, closing connection");
            HeaderOutcome::Closed
        }
    }
}

/// How long the accept loop waits after an error before trying again, and how
/// many it takes before it concludes the listener is not coming back.
const ACCEPT_ERROR_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_millis(100);
const MAX_CONSECUTIVE_ACCEPT_ERRORS: usize = 10;

/// How many connections are served at once.
///
/// Each one holds a [`STREAM_BUF_SIZE`] buffer (sometimes two), so this is what
/// turns an unbounded number of connections into a bounded amount of memory.
/// The same figure the server's `accept_bi` uses, which is not a coincidence:
/// a caller is one connection either way.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// One line per this many refused connections. A refusal is the caller's
/// problem to retry, not a per-connection event worth a log line — and logging
/// every one would let a caller that opens connections in a loop write to the
/// log as fast as it can connect.
const REJECTED_LOG_EVERY: usize = 100;
const STREAM_OPERATION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Number of attempts for opening a fresh iroh bi-stream for a new request.
/// If the pooled connection is stale (already closed by the peer), `open_bi` or
/// the initial `write_all` can fail; we discard that connection and retry with a
/// fresh one instead of failing the whole request.
pub(crate) const OPEN_ATTEMPTS: usize = 3;

#[derive(Clone)]
pub struct LocalProxy {
    listener: Arc<TcpListener>,
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
    stopped: Arc<AtomicBool>,
    /// Wakes the accept loop the moment the proxy is stopped, so it does not
    /// have to give up on `accept()` every 100 ms to find out.
    stop_notify: Arc<Notify>,
    /// The per-connection tasks, so stopping the proxy ends them.
    ///
    /// A handler holds a **borrow** on a pooled connection for as long as its
    /// peer keeps the socket open, which is not this process's decision:
    /// without this a "stopped" proxy would still be holding borrows, and
    /// the connections they ride would stay open.
    connections: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    /// How many of [`MAX_CONCURRENT_CONNECTIONS`] are still free.
    ///
    /// Held here rather than in the accept loop so both constructors get one;
    /// the permits themselves move into the connection tasks, which is what
    /// releases them.
    permits: Arc<Semaphore>,
}

impl LocalProxy {
    /// Binds the local proxy on `listen_addr`.
    ///
    /// **The address has to be a loopback one.** The local proxy does not
    /// authenticate the peer that connects to it: it hands out the tunnel of a
    /// connection that has already authenticated, so whoever reaches the port
    /// gets the tunnel without a credential. A non-loopback bind publishes
    /// that to everyone who can reach the machine, so it is refused here
    /// rather than left to the caller to think about.
    ///
    /// A deployment that puts something else in front of the port — a
    /// firewall, a container network — says so with
    /// [`LocalProxy::new_exposed`], which is the only way to bind
    /// elsewhere.
    pub async fn new(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
    ) -> Result<Self, ClientError> {
        Self::bind(listen_addr, proxy_domains, endpoint_group, false).await
    }

    /// Binds the local proxy on `listen_addr`, even when it is not a loopback
    /// address.
    ///
    /// The explicit opt-in, for a deployment that gates the port with
    /// something else. The same shape as the server's `[server] expose`: a
    /// setting that says "I know, and I have put something in front of it".
    pub async fn new_exposed(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
    ) -> Result<Self, ClientError> {
        Self::bind(listen_addr, proxy_domains, endpoint_group, true).await
    }

    async fn bind(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
        exposed: bool,
    ) -> Result<Self, ClientError> {
        #[cfg(feature = "jni")]
        jni_log!("[DEBUG:local-proxy] Binding to {}", listen_addr);
        let listener = match TcpListener::bind(listen_addr).await {
            Ok(l) => {
                #[cfg(feature = "jni")]
                jni_log!("[DEBUG:local-proxy] Bound successfully to {}", listen_addr);
                l
            }
            Err(e) => {
                #[cfg(feature = "jni")]
                jni_log!(
                    "[DEBUG:local-proxy] Failed to bind to {}: {}",
                    listen_addr,
                    e
                );
                return Err(e.into());
            }
        };
        // Judged by the address the socket actually became, so `0.0.0.0` and
        // `[::]` are caught as what they are rather than as what was asked
        // for — the same rule the server's plaintext listener follows.
        let bound = listener.local_addr()?;
        if !may_bind_local_proxy(bound, exposed) {
            return Err(ClientError::InvalidConfig(format!(
                "the local proxy would bind {bound}, which is reachable from the network, and it \
                 hands out an already-authenticated tunnel to whoever connects. Use a loopback \
                 address, or set `[local_proxy] expose = true` when something else gates the port \
                 (the library's `LocalProxy::new_exposed`)"
            )));
        }
        #[cfg(feature = "tracing")]
        tracing::info!("Local proxy listening on: {}", bound);
        Ok(Self::shared(
            Arc::new(listener),
            endpoint_group,
            proxy_domains,
        ))
    }

    pub async fn new_with_single_pool(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        conn_pool: IrohConnectionPool,
    ) -> Result<Self, ClientError> {
        let listener = TcpListener::bind(listen_addr).await?;
        let bound = listener.local_addr()?;
        if !may_bind_local_proxy(bound, false) {
            return Err(ClientError::InvalidConfig(format!(
                "the local proxy would bind {bound}, which is reachable from the network, and it \
                 hands out an already-authenticated tunnel to whoever connects. Use a loopback \
                 address"
            )));
        }
        let endpoint_group = EndpointGroup::new_with_single_pool(conn_pool).await;
        #[cfg(feature = "tracing")]
        tracing::info!("Local proxy listening on: {}", bound);
        Ok(Self::shared(
            Arc::new(listener),
            Arc::new(endpoint_group),
            proxy_domains,
        ))
    }

    /// The one place the two constructors' shared fields are filled in.
    fn shared(
        listener: Arc<TcpListener>,
        endpoint_group: Arc<EndpointGroup>,
        proxy_domains: Vec<String>,
    ) -> Self {
        report_domain_patterns(&proxy_domains);
        Self {
            listener,
            endpoint_group,
            proxy_domains: Arc::new(proxy_domains),
            stopped: Arc::new(AtomicBool::new(false)),
            stop_notify: Arc::new(Notify::new()),
            connections: Arc::new(std::sync::Mutex::new(Vec::new())),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
        }
    }

    /// The address the proxy is listening on.
    ///
    /// Only known once the listener is bound, which is why it is an accessor
    /// rather than a field: a caller that asked for port 0 — the usual way of
    /// asking for any free port — has to be told which one it got.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(&self) -> Result<(), ClientError> {
        let stopped = self.stopped.clone();
        let listener = self.listener.clone();
        let proxy_domains = self.proxy_domains.clone();
        let endpoint_group = self.endpoint_group.clone();
        let stop_notify = self.stop_notify.clone();
        let permits = self.permits.clone();

        // Refused connections are counted, but only reported every so often: a
        // line each would let a caller that loops over connect() write to the
        // log as fast as it can open sockets.
        let mut rejected = 0usize;

        // Accept errors that are not fatal: a moment with no file descriptors
        // left, say. Counting them keeps the loop from spinning on a listener
        // that is genuinely broken, which is the case the old single-error exit
        // was there for.
        let mut consecutive_accept_errors = 0usize;

        loop {
            if stopped.load(Ordering::Acquire) {
                #[cfg(feature = "tracing")]
                tracing::info!("Local proxy stopping");
                break;
            }

            // `accept()` is cancel safe: a connection it has taken is never
            // handed to another task, so losing this race only means the
            // socket stays in the backlog until the loop comes back for it.
            //
            // `notify_one` — not `notify_waiters` — because a stop that lands
            // in the gap between the flag check and the `notified()` future
            // being created must still be remembered: `notify_one` stores a
            // permit for a waiter that has not arrived yet, `notify_waiters`
            // wakes only the ones already parked and would be lost.
            let accepted = tokio::select! {
                result = listener.accept() => result,
                _ = stop_notify.notified() => {
                    #[cfg(feature = "tracing")]
                    tracing::info!("Local proxy stopping");
                    break;
                }
            };

            match accepted {
                Ok((stream, addr)) => {
                    consecutive_accept_errors = 0;

                    // Refused rather than queued. A caller made to wait would hold
                    // its socket — and the 128 KiB buffer that comes with it — for
                    // as long as the queue takes, which is the memory this cap
                    // exists to bound in the first place.
                    let permit = match permits.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            rejected = rejected.wrapping_add(1);
                            if rejected % REJECTED_LOG_EVERY == 1 {
                                #[cfg(feature = "tracing")]
                                tracing::warn!(
                                    "Refusing a local proxy connection from {}: {} are already \
                                     being served ({} refused so far)",
                                    addr,
                                    MAX_CONCURRENT_CONNECTIONS,
                                    rejected
                                );
                            }
                            // Dropped here, which closes it: no bytes read, no
                            // buffer ever allocated for it.
                            drop(stream);
                            continue;
                        }
                    };

                    #[cfg(feature = "tracing")]
                    tracing::debug!("New connection from: {}", addr);

                    let proxy_domains_clone = proxy_domains.clone();
                    let endpoint_group_clone = endpoint_group.clone();
                    // Named here rather than inside the handler, where it is not
                    // known: a flow listed without where it came from is a row
                    // with a hole in it, and the socket that accepted it is the
                    // only thing that ever knows.
                    let peer = Some(addr.to_string());

                    let handle = tokio::spawn(async move {
                        // Released when the task ends, however it ends: this is
                        // what makes the permit a cap on live connections rather
                        // than on connections ever accepted.
                        let _permit = permit;
                        if let Err(e) = handle_local_connection(
                            stream,
                            proxy_domains_clone,
                            endpoint_group_clone,
                            peer,
                        )
                        .await
                        {
                            #[cfg(feature = "tracing")]
                            tracing::error!("Failed to handle local connection: {}", e);
                        }
                    });
                    self.track_connection(handle);
                }
                Err(e) => {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    #[cfg(feature = "tracing")]
                    tracing::error!("Local proxy accept error: {}", e);

                    // Transient ones — out of file descriptors under a burst of
                    // connections — used to end the loop, leaving the listener
                    // open and nothing accepting from it. Back off and go round
                    // again instead, but not forever.
                    consecutive_accept_errors += 1;
                    if consecutive_accept_errors > MAX_CONSECUTIVE_ACCEPT_ERRORS {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            "Local proxy accept failed {} times in a row, giving up",
                            consecutive_accept_errors
                        );
                        break;
                    }
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            }
        }
        Ok(())
    }

    /// Remember a connection task so [`Self::stop`] can end it.
    fn track_connection(&self, handle: JoinHandle<()>) {
        let Ok(mut connections) = self.connections.lock() else {
            return;
        };
        // A busy proxy would otherwise keep every handle it ever spawned:
        // finished tasks are dropped here as they are noticed, and the rest in
        // `abort_connections`.
        connections.retain(|h| !h.is_finished());
        connections.push(handle);
    }

    fn abort_connections(&self) {
        let Ok(mut connections) = self.connections.lock() else {
            return;
        };
        for handle in connections.drain(..) {
            handle.abort();
        }
    }

    pub fn stop(&self) {
        #[cfg(feature = "tracing")]
        tracing::info!("Stopping local proxy");
        self.stopped.store(true, Ordering::Release);
        self.stop_notify.notify_one();
        // The handlers outlive `run()`: each one holds a pooled connection
        // until its peer closes the socket, which is not a decision this
        // process gets to make. Aborting is what lets a `close_all()` after
        // `run()` actually return those connections.
        self.abort_connections();
    }

    pub async fn close_all(&self) {
        self.endpoint_group.close_all().await;
    }
}

// Only referenced from the `debug_log_enabled()`-gated WebSocket dumps; in non-JNI builds
// that guard is a constant `false`, so the lint sees no live caller.
#[allow(dead_code)]
fn websocket_frame_preview(data: &[u8]) -> String {
    let mut preview = String::new();
    for &b in data.iter().take(256) {
        if b.is_ascii_graphic() || b == b' ' {
            preview.push(b as char);
        } else {
            preview.push_str(&format!("\\x{:02x}", b));
        }
    }
    if data.len() > 256 {
        preview.push_str("...");
    }
    format!("{} bytes: {}", data.len(), preview)
}

fn parse_websocket_frames(buffer: &mut Vec<u8>, frames: &mut Vec<(u8, Vec<u8>)>) {
    let mut pos = 0usize;
    while buffer.len().saturating_sub(pos) >= 2 {
        let b0 = buffer[pos];
        let b1 = buffer[pos + 1];
        let opcode = b0 & 0x0f;
        let masked = b1 & 0x80 != 0;
        let mut payload_len = (b1 & 0x7f) as u64;
        let mut header_len = 2usize;

        if payload_len == 126 {
            if buffer.len() < pos + 4 {
                break;
            }
            payload_len = u16::from_be_bytes([buffer[pos + 2], buffer[pos + 3]]) as u64;
            header_len = 4;
        } else if payload_len == 127 {
            if buffer.len() < pos + 10 {
                break;
            }
            payload_len = u64::from_be_bytes(
                buffer[pos + 2..pos + 10]
                    .try_into()
                    .expect("slice length is 8"),
            );
            header_len = 10;
        }

        if masked {
            header_len += 4;
        }

        let payload_start = pos + header_len;
        let total = match payload_start.checked_add(payload_len as usize) {
            Some(total) => total,
            None => break,
        };
        if total > buffer.len() {
            break;
        }

        let payload = if masked {
            let mask = &buffer[payload_start - 4..payload_start];
            buffer[payload_start..total]
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ mask[i % 4])
                .collect()
        } else {
            buffer[payload_start..total].to_vec()
        };

        frames.push((opcode, payload));
        pos = total;
    }

    if pos > 0 {
        buffer.drain(..pos);
    }
}

/// Open a new iroh bi-stream for `host`, optionally writing `initial_data` as
/// the first bytes of the request/tunnel payload.
///
/// Retries `open_bi` / initial-write failures up to [`OPEN_ATTEMPTS`]
/// times, discarding the stale pooled connection on each failure so the retry
/// gets a fresh connection.
///
/// "Discarding" is the whole point, and it is what the retry buys: a
/// connection whose path died still looks open to QUIC (`close_reason()` stays
/// `None` until the idle timeout expires), so handing one back to the pool
/// hands it to the next attempt — the pool is last-in-first-out — and the
/// request fails [`OPEN_ATTEMPTS`] times on the same dead connection. Dropping
/// the last handle closes it for real, and the next attempt dials again.
///
/// The cost is that a timeout is retried like any other failure, so one
/// request can now wait [`OPEN_ATTEMPTS`] × [`STREAM_OPERATION_TIMEOUT`]
/// before it gives up. Not retrying was worse: a half-open connection then
/// stayed broken for every later request too.
///
/// Shared with [`crate::l4`]: the L4 tunnel needs the same recovery, and the
/// preface it passes as `initial_data` is written by exactly this code path.
pub(crate) async fn open_stream_with_retry(
    endpoint_group: &Arc<EndpointGroup>,
    host: &str,
    initial_data: Option<&[u8]>,
) -> Result<(PooledConnection, SendStream, RecvStream), ClientError> {
    open_stream_with_retry_until(
        endpoint_group,
        host,
        initial_data,
        tokio::time::Instant::now() + STREAM_OPERATION_TIMEOUT * OPEN_ATTEMPTS as u32,
    )
    .await
}

/// [`open_stream_with_retry`], with the caller's deadline.
///
/// **One budget for every attempt.** Each attempt used to have a timeout of
/// its own, and there are three of them, so opening a stream could take a
/// minute and a half — and the caller had three of those as well.
pub(crate) async fn open_stream_with_retry_until(
    endpoint_group: &Arc<EndpointGroup>,
    host: &str,
    initial_data: Option<&[u8]>,
    deadline: tokio::time::Instant,
) -> Result<(PooledConnection, SendStream, RecvStream), ClientError> {
    let mut last_err: Option<ClientError> = None;
    // Whose health each attempt is spent on, kept so that running out of
    // attempts can name the backend that ran out. Recording the failure as it
    // happens would condemn a backend for having been idle: see
    // [`PooledConnection::discard`].
    let mut tried: Vec<EndpointId> = Vec::new();

    for _attempt in 1..=OPEN_ATTEMPTS {
        // The budget is gone: another attempt would time out at once, and the
        // backend it would be spent on is not the one that ran out of time.
        // Stopping here keeps the health accounting honest — a backend that
        // was never dialled must not be recorded as having failed.
        if tokio::time::Instant::now() >= deadline {
            last_err = Some(ClientError::TimeoutError);
            break;
        }

        let pooled_conn = match endpoint_group.get_connection(host).await {
            Ok(conn) => conn,
            Err(e) => {
                // Leaving the loop before every attempt is spent must not lose
                // what those attempts found out. The group that could not offer
                // another connection has itself recorded what it learned about
                // the backend it was reaching for; without this the backends
                // named in `tried` keep every later request dialling them for
                // another full round of attempts first.
                endpoint_group.record_request_failures(&tried);
                return Err(e);
            }
        };
        let tried_node = pooled_conn.node();
        let conn = pooled_conn.conn().clone();

        let (mut send, recv) = match tokio::time::timeout_at(deadline, conn.open_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                jni_log!(
                    "[DEBUG:local-proxy] open_bi failed (attempt {}/{}): {}, retrying on a fresh connection",
                    _attempt,
                    OPEN_ATTEMPTS,
                    e
                );
                last_err = Some(anyhow::anyhow!(e).into());
                tried.extend(tried_node);
                // Closed rather than dropped: another handle is held by the
                // path watcher, so dropping this one would leave the
                // connection open until that task got around to it.
                pooled_conn.discard(b"the connection could not open a stream");
                continue;
            }
            Err(_) => {
                jni_log!(
                    "[DEBUG:local-proxy] open_bi timed out (attempt {}/{}), retrying on a fresh connection",
                    _attempt,
                    OPEN_ATTEMPTS
                );
                // A stream that never opened is a connection that does not
                // work, whether or not QUIC has noticed it yet — the same
                // stale-connection case as the branch above, so it gets the
                // same treatment rather than ending the loop on the first
                // attempt.
                last_err = Some(ClientError::TimeoutError);
                tried.extend(tried_node);
                pooled_conn.discard(b"the connection never opened a stream");
                continue;
            }
        };

        if let Some(data) = initial_data
            && let Err(e) = send.write_all(data).await
        {
            jni_log!(
                "[DEBUG:local-proxy] initial write failed (attempt {}/{}): {}, retrying on a fresh connection",
                _attempt,
                OPEN_ATTEMPTS,
                e
            );
            last_err = Some(e.into());
            tried.extend(tried_node);
            // Same reasoning as the `open_bi` failures: a connection that
            // could not take the first bytes is not one to hand back.
            pooled_conn.discard(b"the connection would not take the first bytes");
            continue;
        }

        return Ok((pooled_conn, send, recv));
    }

    // Every attempt spent and not one served. "Down" is now the most generous
    // reading left, and it is the reading the next request needs: continuing to
    // hand out these backends would spend another three attempts each on
    // connections nobody asked for. The next successful probe clears it.
    endpoint_group.record_request_failures(&tried);

    Err(last_err.unwrap_or_else(|| {
        ClientError::ConnectionError(format!(
            "Failed to open stream to {} after {} attempts",
            host, OPEN_ATTEMPTS
        ))
    }))
}

/// Ends the tasks it holds when it is dropped.
///
/// Dropping a `JoinHandle` detaches its task instead of cancelling it, so a
/// handler that spawns the two halves of a tunnel and is then aborted by
/// [`LocalProxy::stop`] used to leave both halves running: still holding the
/// client socket and the pooled connection the stop was meant to release.
/// The guard dies with the aborted future, and what it does is immediate.
struct TunnelTasks(Vec<tokio::task::AbortHandle>);

impl Drop for TunnelTasks {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

pub(crate) async fn handle_local_connection<S>(
    mut stream: S,
    proxy_domains: Arc<Vec<String>>,
    endpoint_group: Arc<EndpointGroup>,
    // Where the bytes came from, as whatever accepted the socket named it.
    // `None` when the caller has no address to give — a stream that was never
    // a socket, or a caller that never saw one.
    peer: Option<String>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    jni_log!("[DEBUG:local-proxy] New local connection received");

    // Step 1: Read the first chunk of data to determine protocol (HTTP vs TLS)
    //
    // Shares the header budget with the loop below rather than having its own
    // thirty seconds: this is the first read *of* that header, so giving it a
    // separate budget would let a client spend twice the intended time before
    // the first byte of its request line was counted against anything.
    let header_budget = crate::deadline::Deadlines::default().header;
    let first_byte_deadline = tokio::time::Instant::now() + header_budget;
    let mut request_buf = Vec::new();
    let mut temp_buf = vec![0u8; STREAM_BUF_SIZE];

    let n = match tokio::time::timeout_at(first_byte_deadline, stream.read(&mut temp_buf)).await {
        Ok(Ok(0)) => {
            jni_log!("[DEBUG:local-proxy] Empty request, closing connection");
            return Ok(());
        }
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            jni_log!("[DEBUG:local-proxy] Read error: {}", e);
            return Ok(());
        }
        Err(_) => {
            jni_log!("[DEBUG:local-proxy] Read timeout, closing connection");
            return Ok(());
        }
    };

    request_buf.extend_from_slice(&temp_buf[..n]);

    // Check if this is a TLS connection (ClientHello starts with 0x16 = Handshake content type)
    if !request_buf.is_empty() && request_buf[0] == 0x16 {
        jni_log!("[DEBUG:local-proxy] Detected TLS ClientHello, handling as raw tunnel via SNI");
        return handle_tls_tunnel(stream, request_buf, endpoint_group, proxy_domains, peer).await;
    }

    // Step 2: HTTP — read the complete request head (up to \r\n\r\n).
    //
    // `first_byte_deadline`, not a fresh instant: the budget was taken once,
    // before the first read above, and it covers the whole head. Taking it again
    // here would hand the caller two budgets — thirty seconds to send a first
    // byte and thirty more to finish the header — which is exactly the doubling
    // the first read's comment says this avoids.
    //
    // The per-read timeouts this replaces re-armed on each read, so a client
    // sending one byte of `Host:` before each expiry kept the connection, the
    // task and the slot for as long as it liked — the read that arrived *was*
    // the renewal.
    let header_end =
        match read_http_header(&mut stream, &mut request_buf, first_byte_deadline).await {
            HeaderOutcome::Complete(header_end) => header_end,
            HeaderOutcome::Closed => return Ok(()),
        };

    let request = match parse_http_request_legacy(&request_buf[..header_end]) {
        Ok(req) => {
            jni_log!(
                "[DEBUG:local-proxy] Parsed HTTP request: {} {}",
                req.method(),
                req.uri()
            );
            req
        }
        Err(e) => {
            jni_log!("[DEBUG:local-proxy] Failed to parse HTTP request: {}", e);
            jni_log!(
                "[DEBUG:local-proxy] First 16 bytes: {:?}",
                &request_buf[..std::cmp::min(request_buf.len(), 16)]
            );
            return Ok(());
        }
    };

    if request.method().as_str() == "CONNECT" {
        // `CONNECT host:port` is authority-form (RFC 9110 9.3.6). The port used to be
        // dropped here (`uri.split(':').next()`), which is why this branch only ever
        // worked for 443/TLS: everything else reached the server as a request line with
        // no port, matched no route, and was silently forwarded to `default_backend`.
        let target = request.uri().to_string();
        let Some((host, port)) = crate::l4::parse_connect_target(&target) else {
            jni_log!(
                "[DEBUG:local-proxy] CONNECT without a usable host:port: '{}'",
                target
            );
            return write_proxy_error(&mut stream, "400 Bad Request").await;
        };

        if !should_proxy_domain(&host, &proxy_domains) {
            jni_log!(
                "[DEBUG:local-proxy] CONNECT '{}' is not a proxied domain, refusing",
                target
            );
            return write_proxy_error(&mut stream, "403 Forbidden").await;
        }

        // Open the tunnel *before* answering 200. `200 Connection Established` promises
        // that the far side is up, so the client has to still be able to receive an HTTP
        // error when it is not — which is why the answer comes after the L4 handshake
        // and not before it.
        let (pooled_conn, mut send, mut recv) =
            match crate::l4::open_tcp(&endpoint_group, &host, port).await {
                Ok(tunnel) => tunnel,
                Err(e) => {
                    jni_log!(
                        "[DEBUG:local-proxy] CONNECT {}:{} failed: {}",
                        host,
                        port,
                        e
                    );
                    return write_proxy_error(&mut stream, "502 Bad Gateway").await;
                }
            };

        // One tunnel is one flow for as long as this handler lives, however it
        // ends: EOF, either direction failing, or this task being cancelled
        // because the proxy stopped.
        //
        // The counters are the *flow's* rather than the connection's, which is
        // what lets a reader ask how much this connection has moved as opposed
        // to how much the backend has. Two halves of one copy loop each carry a
        // clone of the same guard, so the two directions land in one total.
        let flow = pooled_conn.enter_flow(FlowMeta {
            kind: FlowKind::Connect,
            target: Some(format!("{host}:{port}")),
            source: peer.clone(),
        });
        let count_to_backend = flow.counter();
        let count_from_backend = flow.counter();

        let (mut client_read, mut client_write) = tokio::io::split(stream);
        client_write
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Spawn bidirectional forwarding as separate tasks to keep each
        // task's async state machine small (avoids deep nesting that causes
        // stack overflow on tokio worker threads).
        let mut client_task = tokio::spawn(async move {
            let mut buf = vec![0u8; STREAM_BUF_SIZE];
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => {
                        // The client is done sending. That is a half-close, not
                        // the end of the conversation: the server may still
                        // have a reply on the way, and the reply has to reach
                        // the client.
                        //
                        // Propagated as a FIN, so the server sees what it
                        // would see from a socket whose write side the client
                        // had shut down. Dropping the stream instead would
                        // reset it, and a reset is not a half-close.
                        let _ = send.finish();
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel client_to_iroh write error: {}", e);
                            break;
                        }
                        count_to_backend.record_sent(n as u64);
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Tunnel client_to_iroh read error: {}", e);
                        break;
                    }
                }
            }
        });

        let mut backend_task = tokio::spawn(async move {
            let mut buf = vec![0u8; STREAM_BUF_SIZE];
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) => break,
                    Ok(Some(n)) => {
                        if let Err(e) = client_write.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel iroh_to_client write error: {}", e);
                            break;
                        }
                        if let Err(e) = client_write.flush().await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel iroh_to_client flush error: {}", e);
                            break;
                        }
                        count_from_backend.record_received(n as u64);
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Tunnel iroh_to_client read error: {}", e);
                        break;
                    }
                }
            }
            // The server is done sending. That is a half-close, and the client
            // has to hear it: the write side towards the client is shut down,
            // so the client sees an end of stream the way it would see it
            // from a socket.
            //
            // Without this the client waits for an answer that is not coming.
            // Joining the two directions is right, but joining them is not the
            // same as leaving the client hanging: the direction that ended has
            // to be handed on to the peer. The read side stays open, so a
            // client that still has something to say can say it.
            let _ = client_write.shutdown().await;
        });

        // Lives until this handler returns, and dies with it if it is aborted
        // first — which is the only moment that matters: `stop()` cancels the
        // task running this function, and the two halves above have to go with
        // it or the tunnel outlives the proxy it belongs to.
        let _tasks = TunnelTasks(vec![
            client_task.abort_handle(),
            backend_task.abort_handle(),
        ]);

        // **Both directions, and each of them for as long as it lasts.**
        //
        // A TCP half-close is a request, not an ending: a client that writes
        // its request and then shuts down its write side is saying "I am done
        // sending", and the server's reply still has to arrive. Racing the two
        // directions and aborting the loser dropped that reply on the floor and
        // reset the connection under the client.
        //
        // The bound is the one the copy loop was always meant to have:
        // `STREAM_SECS`, an hour. It matches the server's own `l4_flow`
        // default, so the two ends of the tunnel give up at about the same
        // moment, and it is what keeps a half-closed tunnel from holding its
        // resources for the life of the process.
        let stream_budget = crate::deadline::Deadlines::default().stream;
        tokio::select! {
            _ = async {
                let _ = (&mut client_task).await;
                let _ = (&mut backend_task).await;
            } => (),
            _ = flow.cancelled() => (),
            _ = tokio::time::sleep(stream_budget) => {
                jni_log!(
                    "[DEBUG:local-proxy] CONNECT tunnel to {}:{} ran for {:?} and was abandoned",
                    host,
                    port,
                    stream_budget
                );
            }
        }

        // Both, whichever branch won: the half that is still running is the one
        // that outlived its reason to, and the `TunnelTasks` guard above aborts
        // whatever is left when this handler returns.
        client_task.abort();
        backend_task.abort();

        return Ok(());
    }

    // A request that names more than one host is refused here, the same rule
    // the server applies. The route and the access check read the first `Host`
    // header and the backend would be handed all of them, so the request that
    // is authorised and the request that is served would be two different
    // requests — and the failure showed up as the server's 400, which looks
    // like a proxy bug rather than a request that cannot be answered.
    if request.headers().get_all("host").iter().count() > 1 {
        jni_log!(
            "[local-proxy] refusing a request that names more than one host: {}",
            redacted_headers(request.headers())
        );
        return write_proxy_error(&mut stream, "400 Bad Request").await;
    }

    let mut target_host = None;
    for header in request.headers().get_all("host") {
        if let Ok(h) = header.to_str() {
            // The authority is split the way the server splits it, so
            // `[::1]:8080` keeps its address. An empty port is dropped, as the
            // server drops it: `example.com:` is `example.com`.
            let (h, _port) = nexapipe_proto::host_and_port(h);
            jni_log!("[DEBUG:local-proxy] Found Host header: '{}'", h);
            if should_proxy_domain(h, &proxy_domains) {
                target_host = Some(h.to_string());
                break;
            }
        }
    }

    if target_host.is_none() {
        jni_log!("[DEBUG:local-proxy] No matching Host header found");
        return Ok(());
    }

    let host = target_host.unwrap();
    jni_log!(
        "[DEBUG:local-proxy] Getting connection for domain: '{}'",
        host
    );

    // WebSocket upgrade: rewrite the request line to use an absolute "http://"
    // URI. When a browser connects through a normal HTTP proxy it sends
    // "GET http://host/path HTTP/1.1" (absolute-form request-target per
    // RFC 7230 §5.3.2). The backend uses this to recognize that the stream
    // should be kept alive for bidirectional data flow after the HTTP upgrade,
    // rather than treating it as a one-shot HTTP exchange.
    if is_websocket_request_static(&request) {
        jni_log!("[DEBUG:local-proxy] WebSocket request, rewriting to absolute URI");
        jni_log!(
            "[DEBUG:local-proxy] WebSocket request details: uri={}, host={}, headers={}",
            request.uri(),
            host,
            redacted_headers(request.headers())
        );

        // Find the first line (request line)
        let first_line_end = request_line_end(&request_buf[..header_end]);

        if first_line_end > 0 {
            // The method and the version come from the **parsed** request, not
            // from the bytes: the request line is rebuilt here, and a raw slice
            // of it carries whatever the client put there. A bare LF ends the
            // line for a parser that accepts one, and the rest of it lands in
            // the version token — straight into the request this proxy sends.
            let method = request.method().as_str();
            // `http::Version`'s Debug is the wire spelling — "HTTP/1.1" — and
            // the request line wants exactly that.
            let version = format!("{:?}", request.version());
            {
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                // Use http:// scheme (not ws://) — the backend handles
                // the WebSocket upgrade via the Upgrade header, not the URI
                let absolute_uri = format!("http://{}{}", host, path);
                let new_line = format!("{} {} {}\r\n", method, absolute_uri, version);

                let mut request_to_send =
                    Vec::with_capacity(new_line.len() + header_end - first_line_end);
                request_to_send.extend_from_slice(new_line.as_bytes());
                // Copy the rest of headers (skip the original request line),
                // minus the ones that must not be forwarded. `Upgrade` and
                // `Connection` stay: the upgrade is the point of this request.
                let rest_start = first_line_end + 1; // skip the line feed
                if rest_start < header_end {
                    request_to_send.extend_from_slice(&filter_request_headers(
                        &request_buf[rest_start..header_end],
                        true,
                    ));
                }

                jni_log!(
                    "[DEBUG:local-proxy] Rewrote WebSocket request line: {}",
                    new_line.trim()
                );

                // Open iroh bi-stream and send the modified request
                let (pooled_conn, mut send, mut recv) =
                    open_stream_with_retry(&endpoint_group, &host, Some(&request_to_send)).await?;

                // One tunnel is one flow, and it stays counted until the
                // handler this sits in returns — see the CONNECT branch.
                let flow = pooled_conn.enter_flow(FlowMeta {
                    kind: FlowKind::WebSocket,
                    target: Some(host.clone()),
                    source: peer.clone(),
                });
                flow.record_sent(request_to_send.len() as u64);
                let count_to_backend = flow.counter();
                let count_from_backend = flow.counter();

                let (mut client_read, mut client_write) = tokio::io::split(stream);
                jni_log!(
                    "[DEBUG:local-proxy] WebSocket request sent to iroh: {} bytes",
                    request_to_send.len()
                );

                // Bidirectional forwarding (no send.finish() — keep stream open)
                let client_to_iroh = async move {
                    let mut buf = vec![0u8; STREAM_BUF_SIZE];
                    let mut ws_buffer = Vec::new();
                    loop {
                        match client_read.read(&mut buf).await {
                            Ok(0) => {
                                jni_log!("[DEBUG:local-proxy] WS client EOF");
                                return "client_eof";
                            }
                            Ok(n) => {
                                // Payload, not metadata: it costs a preview to
                                // build and it is the user's traffic, so it is
                                // only worth it while debugging.
                                if debug_log_enabled() {
                                    jni_log!(
                                        "[DEBUG:local-proxy] WS client->iroh: {}",
                                        websocket_frame_preview(&buf[..n])
                                    );
                                }
                                // The buffer only feeds the dumps above, and it
                                // only empties once a whole frame is in it: a
                                // client that sends a frame header and then
                                // nothing would grow it forever, logs or no
                                // logs. So the decode is part of what is
                                // switched off with them.
                                if debug_log_enabled() {
                                    ws_buffer.extend_from_slice(&buf[..n]);
                                    let mut frames = Vec::new();
                                    parse_websocket_frames(&mut ws_buffer, &mut frames);
                                    for (opcode, payload) in frames {
                                        if opcode == 1 || opcode == 8 {
                                            jni_log!(
                                                "[DEBUG:local-proxy] WS client frame decoded (opcode {}): {}",
                                                opcode,
                                                String::from_utf8_lossy(&payload)
                                            );
                                        }
                                    }
                                }
                                if let Err(e) = send.write_all(&buf[..n]).await {
                                    jni_log!("[DEBUG:local-proxy] WS client->backend err: {}", e);
                                    return "client_write_error";
                                }
                                count_to_backend.record_sent(n as u64);
                            }
                            Err(e) => {
                                jni_log!("[DEBUG:local-proxy] WS client read error: {}", e);
                                return "client_read_error";
                            }
                        }
                    }
                };

                let iroh_to_client = async move {
                    let mut buf = vec![0u8; STREAM_BUF_SIZE];
                    let mut first = true;
                    loop {
                        match recv.read(&mut buf).await {
                            Ok(None) => {
                                jni_log!("[DEBUG:local-proxy] WS iroh EOF");
                                return "iroh_eof";
                            }
                            Ok(Some(n)) => {
                                if first {
                                    first = false;
                                    let p = &buf[..std::cmp::min(n, 200)];
                                    if debug_log_enabled() {
                                        jni_log!(
                                            "[DEBUG:local-proxy] WS first response: {}",
                                            String::from_utf8_lossy(p)
                                        );
                                    }
                                }
                                if debug_log_enabled() {
                                    jni_log!(
                                        "[DEBUG:local-proxy] WS iroh->client: {}",
                                        websocket_frame_preview(&buf[..n])
                                    );
                                }
                                if n <= 1024 && debug_log_enabled() {
                                    jni_log!(
                                        "[DEBUG:local-proxy] WS iroh->client decoded: {}",
                                        String::from_utf8_lossy(&buf[..n])
                                    );
                                }
                                if client_write.write_all(&buf[..n]).await.is_err() {
                                    return "client_write_error";
                                }
                                count_from_backend.record_received(n as u64);
                                let _ = client_write.flush().await;
                            }
                            Err(e) => {
                                jni_log!("[DEBUG:local-proxy] WS iroh read error: {}", e);
                                return "iroh_read_error";
                            }
                        }
                    }
                };

                let mut client_task = tokio::spawn(client_to_iroh);
                let mut backend_task = tokio::spawn(iroh_to_client);
                // See the CONNECT branch: this dies with the handler, and with
                // it both halves of the WebSocket tunnel.
                let _tasks = TunnelTasks(vec![
                    client_task.abort_handle(),
                    backend_task.abort_handle(),
                ]);

                let (closed_direction, close_reason) = tokio::select! {
                    result = &mut client_task => {
                        ("client_to_iroh", result.unwrap_or("client_task_panicked"))
                    }
                    result = &mut backend_task => {
                        ("iroh_to_client", result.unwrap_or("backend_task_panicked"))
                    }
                    // Asked to end: not an error, and not one of the two
                    // directions going quiet either.
                    _ = flow.cancelled() => ("closed", "closed_by_request"),
                };

                if closed_direction == "client_to_iroh" {
                    backend_task.abort();
                } else {
                    client_task.abort();
                }
                jni_log!(
                    "[DEBUG:local-proxy] WebSocket tunnel closed first by {} ({})",
                    closed_direction,
                    close_reason
                );

                return Ok(());
            }
        }

        // Fallback: if we couldn't rewrite, just connect normally
        jni_log!("[DEBUG:local-proxy] WebSocket URI rewrite failed, falling back to regular HTTP");
    }

    // Regular HTTP path
    // The hop-by-hop headers go, and so do the cache validation headers that
    // would make the origin answer with a 304 and an empty body.
    let filtered_headers = filter_request_headers(&request_buf[..header_end], false);
    let mut request_to_send = filtered_headers;
    request_to_send.extend_from_slice(&request_buf[header_end..]);

    jni_log!(
        "[DEBUG:local-proxy] Forwarding {} bytes to backend, Host: {}",
        request_to_send.len(),
        host
    );
    let (pooled_conn, mut send, mut recv) =
        open_stream_with_retry(&endpoint_group, &host, Some(&request_to_send)).await?;

    // The helper wrote the request — headers and whatever body had already
    // arrived — before this line was reached. Counting the copy loop alone
    // would therefore be counting everything except a large upload, which for
    // a POST is most of it.
    let flow = pooled_conn.enter_flow(FlowMeta {
        kind: FlowKind::Http,
        target: Some(host.clone()),
        source: peer.clone(),
    });
    flow.record_sent(request_to_send.len() as u64);
    let count_to_backend = flow.counter();
    let count_from_backend = flow.counter();

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    let client_to_backend = async move {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Client to backend write error: {}", e);
                        break;
                    }
                    count_to_backend.record_sent(n as u64);
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Client read error: {}", e);
                    break;
                }
            }
        }
        let _ = send.finish();
    };

    let backend_to_client = async move {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        let mut total_bytes = 0;
        // The preview is only ever read when the debug log is on, so it is only
        // built then: a 1.5 KiB buffer filled for every response, for a log
        // line nobody asked for.
        let mut debug_preview = debug_log_enabled().then(|| Vec::with_capacity(1500));
        let mut response_sent = false;
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    total_bytes += n;
                    if let Some(preview) = debug_preview.as_mut()
                        && !response_sent
                        && preview.len() < 1500
                    {
                        preview.extend_from_slice(&buf[..std::cmp::min(n, 1500 - preview.len())]);
                    }
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Backend to client write error: {}", e);
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Backend to client flush error: {}", e);
                        break;
                    }
                    count_from_backend.record_received(n as u64);
                    if !response_sent {
                        response_sent = true;
                        jni_log!("[DEBUG:local-proxy] Response sent: {} bytes", total_bytes);
                        if let Some(preview) = debug_preview.as_ref()
                            && !preview.is_empty()
                        {
                            jni_log!(
                                "[DEBUG:local-proxy] Response preview: {}",
                                String::from_utf8_lossy(preview)
                            );
                        }
                    }
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Backend read error: {}", e);
                    break;
                }
            }
        }
        if !response_sent && total_bytes > 0 {
            jni_log!(
                "[DEBUG:local-proxy] Response sent (late): {} bytes",
                total_bytes
            );
            if let Some(preview) = debug_preview.as_ref()
                && !preview.is_empty()
            {
                jni_log!(
                    "[DEBUG:local-proxy] Response preview: {}",
                    String::from_utf8_lossy(preview)
                );
            }
        }
    };
    // END regular HTTP closures

    // Regular HTTP request-response handling
    jni_log!("[DEBUG:local-proxy] Detected HTTP request, using request-response mode");
    jni_log!(
        "[DEBUG:local-proxy] Request headers: {}",
        redacted_headers(request.headers())
    );
    let client_task = tokio::spawn(client_to_backend);
    let mut backend_task = tokio::spawn(backend_to_client);
    // See the CONNECT branch: the client half is aborted below on the normal
    // path, and both go when the proxy is stopped mid-request.
    let _tasks = TunnelTasks(vec![
        client_task.abort_handle(),
        backend_task.abort_handle(),
    ]);

    // Wait for the backend response to be fully relayed back to the client
    // (bounded for streaming/long-lived responses). We must NOT wait for the
    // client to close its TCP connection first: HTTP clients routinely keep the
    // connection alive (keep-alive) after reading the response, so client_task
    // would block indefinitely and the iroh connection would never be returned
    // to the pool -- which defeats pre-connect/connection warm-up and leaks
    // pooled connections.
    // The timer and the cancel switch, together: this is the one path here that
    // is bounded by a clock instead of by a peer going quiet, and being asked to
    // end has to be able to cut that short rather than wait out the minute.
    tokio::select! {
        _ = tokio::time::timeout(tokio::time::Duration::from_secs(60), &mut backend_task) => (),
        _ = flow.cancelled() => (),
    }

    // Response has been delivered; stop the client->backend relay so the pooled
    // iroh connection is released immediately. Aborting also closes the client
    // TCP socket (HTTP/1.1 allows the server to close after the response),
    // so a keep-alive client socket can't pin this task.
    client_task.abort();

    jni_log!("[DEBUG:local-proxy] Connection closed");
    Ok(())
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
    if data.len() >= 5 {
        let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
        let total_needed = 5 + record_len;
        let hello_deadline =
            tokio::time::Instant::now() + crate::deadline::Deadlines::default().tls_hello;
        while data.len() < total_needed {
            let mut extra = [0u8; 4096];
            match tokio::time::timeout_at(hello_deadline, stream.read(&mut extra)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => data.extend_from_slice(&extra[..n]),
                Ok(Err(_)) => break,
                Err(_) => {
                    jni_log!(
                        "[DEBUG:local-proxy] TLS ClientHello took longer than its deadline, \
                         closing connection"
                    );
                    return Ok(());
                }
            }
        }
    }

    // Extract SNI from TLS ClientHello
    let sni = match extract_sni_from_client_hello(&data) {
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
    let (pooled_conn, mut send, mut recv) =
        open_stream_with_retry(&endpoint_group, &sni, Some(&data)).await?;

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

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    // Bidirectional raw data forwarding (TCP tunnel)
    let client_to_iroh = async {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        jni_log!(
                            "[DEBUG:local-proxy] TLS tunnel client->iroh write error: {}",
                            e
                        );
                        break;
                    }
                    count_to_backend.record_sent(n as u64);
                }
                Err(e) => {
                    jni_log!("[DEBUG:local-proxy] TLS tunnel client read error: {}", e);
                    break;
                }
            }
        }
    };

    let iroh_to_client = async {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        jni_log!(
                            "[DEBUG:local-proxy] TLS tunnel iroh->client write error: {}",
                            e
                        );
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        jni_log!("[DEBUG:local-proxy] TLS tunnel flush error: {}", e);
                        break;
                    }
                    count_from_backend.record_received(n as u64);
                }
                Err(e) => {
                    jni_log!("[DEBUG:local-proxy] TLS tunnel backend read error: {}", e);
                    break;
                }
            }
        }
    };

    jni_log!("[DEBUG:local-proxy] TLS tunnel: bidirectional forwarding started");
    tokio::select! {
        _ = client_to_iroh => (),
        _ = iroh_to_client => (),
        _ = flow.cancelled() => (),
    }

    jni_log!("[DEBUG:local-proxy] TLS tunnel closed");
    Ok(())
}

/// Extract the SNI (Server Name Indication) hostname from a TLS ClientHello.
///
/// The TLS 1.2/1.3 ClientHello format (simplified):
///   1 byte  content_type (0x16 = Handshake)
///   2 bytes version
///   2 bytes record length
///   --- record data ---
///   1 byte  handshake_type (0x01 = ClientHello)
///   3 bytes handshake length
///   2 bytes client version
///   32 bytes random
///   1 byte  session ID length + data
///   2 bytes cipher suites length + data
///   1 byte  compression methods length + data
///   2 bytes extensions length
///   extensions...
///
/// SNI extension type = 0x0000
fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Must be TLS Handshake content type
    if data[0] != 0x16 {
        return None;
    }

    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    let total_needed = 5 + record_len;
    if data.len() < total_needed {
        return None;
    }

    let mut pos = 5usize;

    // Handshake type: ClientHello (0x01)
    if pos >= data.len() || data[pos] != 0x01 {
        return None;
    }
    pos += 1;

    // Handshake length (3 bytes, big-endian)
    if pos + 3 > data.len() {
        return None;
    }
    let _hs_len =
        ((data[pos] as usize) << 16) | ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
    pos += 3;

    // Skip protocol version (2 bytes) + random (32 bytes)
    pos += 34;
    if pos > data.len() {
        return None;
    }

    // Skip session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos > data.len() {
        return None;
    }

    // Skip cipher suites
    if pos + 1 >= data.len() {
        return None;
    }
    let cipher_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2 + cipher_len;
    if pos > data.len() {
        return None;
    }

    // Skip compression methods
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos > data.len() {
        return None;
    }

    // Extensions
    if pos + 1 >= data.len() {
        return None;
    }
    let ext_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > data.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        let ext_data_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 {
            // server_name (SNI) extension
            if pos + 2 > ext_end {
                return None;
            }
            let _sni_list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            pos += 2;

            if pos + 3 <= ext_end.min(data.len()) {
                let name_type = data[pos];
                pos += 1;
                let name_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                pos += 2;

                if name_type == 0x00 && pos + name_len <= data.len() && pos + name_len <= ext_end {
                    // Read host_name (ASCII/UTF-8 encoded hostname)
                    return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
                }
            }
        }

        pos += ext_data_len;
    }

    None
}

/// The header names a proxy must not forward.
///
/// RFC 9110 §7.6.1: these describe one connection rather than the message, so
/// they belong to the hop the proxy is on and not to the one behind it.
/// `Proxy-Authorization` is the one that matters most here — it is a
/// credential for *this* proxy, and forwarding it hands that credential to a
/// third-party server.
///
/// `Transfer-Encoding` is deliberately **not** in the list. It is hop-by-hop,
/// and the rule says a proxy removes it — but only because the proxy is
/// expected to re-frame the body. This one does not: the client's bytes cross
/// the tunnel verbatim, so removing the header would leave a chunked body
/// with nothing saying it is chunked.
const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// The header block with the fields that must not be forwarded taken out.
///
/// `keep_upgrade` keeps `Upgrade` and `Connection`, which is what the
/// WebSocket request is about: the upgrade is the point of it, and a backend
/// that does not see it does not switch protocols.
///
/// The names `Connection` nominates go as well — RFC 9110 §7.6.1 makes that
/// header a list of the names that are hop-by-hop for this message — so a
/// `Connection: X-Secret` does not carry `X-Secret` on.
///
/// The two cache-validation headers go too: they make the origin answer with
/// a 304 and an empty body, which the proxy has no way to fill.
fn filter_request_headers(block: &[u8], keep_upgrade: bool) -> Vec<u8> {
    let nominated = nominated_hop_by_hop(block);

    // The input always ends with \r\n\r\n (the HTTP header terminator,
    // up to header_end). We iterate over each header line and preserve the
    // original \r\n\r\n terminator, so the body (appended separately) starts
    // at the right position.
    let mut result = Vec::with_capacity(block.len());
    let mut start = 0;

    while let Some(pos) = block[start..].windows(2).position(|w| w == b"\r\n") {
        let line_end = start + pos;
        let line = &block[start..line_end];

        if !is_dropped_header(line, keep_upgrade, &nominated) {
            result.extend_from_slice(line);
            result.extend_from_slice(b"\r\n");
        }

        start = line_end + 2;
    }

    // Loop already preserved the \r\n\r\n terminator — don't add an extra one
    result
}

/// The header names `Connection` nominates as hop-by-hop.
///
/// RFC 9110 §7.6.1: `Connection` lists the names that are hop-by-hop for
/// this message, so a `Connection: X-Secret` means `X-Secret` must not be
/// forwarded either.
fn nominated_hop_by_hop(block: &[u8]) -> Vec<Vec<u8>> {
    let mut nominated = Vec::new();
    let mut start = 0;

    while let Some(pos) = block[start..].windows(2).position(|w| w == b"\r\n") {
        let line_end = start + pos;
        let line = &block[start..line_end];

        if let Some(value) = header_value(line, b"connection") {
            for token in value.split(|b| *b == b',') {
                let token: Vec<u8> = token
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect();
                if !token.is_empty() {
                    nominated.push(token.to_ascii_lowercase());
                }
            }
        }

        start = line_end + 2;
    }

    nominated
}

/// The name of a header line, lower-cased, or `None` when the line is not a
/// header.
///
/// A name with a space in it is not a name: the request line is the one line
/// that can carry a colon without being a header (`GET /a:b HTTP/1.1`), and it
/// is not a header at all.
fn header_name(line: &[u8]) -> Option<Vec<u8>> {
    let colon = line.iter().position(|b| *b == b':')?;
    let name = &line[..colon];
    if name.is_empty() || name.iter().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// The value of a header line, when the line is that header.
fn header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let colon = line.iter().position(|b| *b == b':')?;
    if !line[..colon].eq_ignore_ascii_case(name) {
        return None;
    }
    Some(&line[colon + 1..])
}

/// Whether a header line must not be forwarded.
fn is_dropped_header(line: &[u8], keep_upgrade: bool, nominated: &[Vec<u8>]) -> bool {
    if is_cache_validation_header(line) {
        return true;
    }

    let Some(name) = header_name(line) else {
        return false;
    };

    // The upgrade is the point of a WebSocket request, so it stays there.
    if keep_upgrade && (name == b"upgrade" || name == b"connection") {
        return false;
    }

    if HOP_BY_HOP_HEADERS.iter().any(|hop| name == hop.as_bytes()) {
        return true;
    }

    nominated.iter().any(|token| token == &name)
}

/// Whether a header line is one of the two cache-validation headers.
///
/// **The two names are checked separately**, each against its own length.
/// They are four bytes apart — `if-modified-since:` is eighteen, `if-none-match:`
/// is fourteen — so a single length guard for both would be the length of the
/// longer one, and the shorter header's smallest forms would fall through it:
/// `If-None-Match: *` is sixteen bytes and `If-None-Match: ""` is seventeen.
/// Those are exactly the requests the origin answers with a 304 and an empty
/// body, which is what this is here to prevent.
fn is_cache_validation_header(line: &[u8]) -> bool {
    starts_with_ignore_case(line, b"if-modified-since:")
        || starts_with_ignore_case(line, b"if-none-match:")
}

/// Whether `line` starts with `prefix`, ignoring ASCII case.
///
/// Without allocating: the header name is ASCII, and the comparison is
/// against a fixed prefix.
fn starts_with_ignore_case(line: &[u8], prefix: &[u8]) -> bool {
    line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Answer a `CONNECT` that cannot be served.
///
/// Only valid while the socket is still an HTTP one: once `200 Connection Established`
/// has gone out the socket is a byte tunnel and an HTTP status line would be payload.
/// That is why every refusal — an unusable target, a domain outside the proxy list, a
/// tunnel the server refused — has to be decided before the 200 is written.
async fn write_proxy_error<S>(stream: &mut S, status_line: &str) -> Result<(), ClientError>
where
    S: AsyncWrite + Unpin,
{
    let response =
        format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

pub(crate) fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    crate::domains::should_proxy_domain(host, proxy_domains)
}

/// Say what a list of proxy-domain patterns is worth, once, when a client starts.
///
/// Two kinds of note, and they are not the same kind. A pattern that matches
/// **nothing** is a warning: `*example.com` — a wildcard without the dot —
/// used to be a bare `ends_with` here, so it matched `notexample.com` as well,
/// and the server has always refused the spelling. A pattern that means one
/// name where a reader may expect a whole tree is worth an information line
/// and no more: a bare `example.com` names that host, and `*.example.com`
/// names its subdomains.
pub(crate) fn report_domain_patterns(patterns: &[String]) {
    let notes = crate::domains::domain_notes(patterns);
    for (pattern, why) in &notes.unusable {
        warn(&format!(
            "the proxy-domain pattern \"{pattern}\" matches nothing: {why}"
        ));
    }
    for pattern in &notes.narrowed {
        info(&format!(
            "the proxy-domain pattern \"{pattern}\" names that host only; \"*.{pattern}\" covers \
             its subdomains"
        ));
    }
}

/// A warning the user can read.
///
/// The Android build installs the `log` logger at `Info` and no tracing
/// subscriber, so a `Debug` line never reaches the log and a `tracing` line
/// goes nowhere.
///
/// Crate-wide rather than private to this module: the TUN stack has warnings
/// of its own, and there is no reason for two of them.
#[cfg(feature = "jni")]
pub(crate) fn warn(message: &str) {
    crate::jni::warn_log(message);
}

#[cfg(all(not(feature = "jni"), feature = "tracing"))]
pub(crate) fn warn(message: &str) {
    tracing::warn!("{message}");
}

#[cfg(all(not(feature = "jni"), not(feature = "tracing")))]
pub(crate) fn warn(_message: &str) {}

/// A line of information the user can read, on the same terms as [`warn`].
#[cfg(feature = "jni")]
fn info(message: &str) {
    crate::jni::info_log(message);
}

#[cfg(all(not(feature = "jni"), feature = "tracing"))]
fn info(message: &str) {
    tracing::info!("{message}");
}

#[cfg(all(not(feature = "jni"), not(feature = "tracing")))]
fn info(_message: &str) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoadBalancingStrategy;
    use iroh::Endpoint;
    use iroh::endpoint::presets;
    use std::time::Duration;

    /// A proxy listening on an ephemeral port, with no backends behind it.
    ///
    /// Enough for the accept loop, which in these tests never gets as far as
    /// dialling one. Built through `shared` rather than `new` because the test
    /// needs the address `new` keeps to itself.
    /// The refusal is the constructor's, not only the predicate's.
    ///
    /// A bind that reaches the network has to fail, and it has to fail with a
    /// message that names the way out — the predicate on its own says
    /// nothing about what a caller is supposed to do about it.
    #[tokio::test]
    async fn a_non_loopback_bind_is_refused_by_the_constructor() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        let group = EndpointGroup::new_with_nodes_and_endpoint(
            Vec::new(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .expect("a group with no backend still builds");

        // `0.0.0.0` is the address every interface answers on, and it is what
        // the socket becomes — so the refusal is judged by what was bound
        // rather than by what was asked for.
        let err = match LocalProxy::new("0.0.0.0:0", Vec::new(), Arc::new(group)).await {
            Ok(_) => panic!("a bind that reaches the network is refused"),
            Err(e) => e,
        };
        let message = err.to_string();
        assert!(
            message.contains("expose"),
            "the message has to name the way out of it: {message}"
        );
    }

    /// The same bind, with the opt-in: it is allowed, because that is what
    /// the opt-in is for.
    #[tokio::test]
    async fn the_opt_in_binds_a_non_loopback_address() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        let group = EndpointGroup::new_with_nodes_and_endpoint(
            Vec::new(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .expect("a group with no backend still builds");

        let proxy = LocalProxy::new_exposed("0.0.0.0:0", Vec::new(), Arc::new(group))
            .await
            .expect("the opt-in is the way to bind elsewhere");
        proxy.stop();
    }

    async fn listening_proxy() -> (LocalProxy, std::net::SocketAddr) {
        listening_proxy_for(&[]).await
    }

    /// A proxy that serves the domains it is given, and no backends behind it.
    ///
    /// The domains matter: a request that names one goes on to dial, so a
    /// refusal has to be the client's own rather than the absence of a route.
    async fn listening_proxy_for(domains: &[&str]) -> (LocalProxy, std::net::SocketAddr) {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        let group = EndpointGroup::new_with_nodes_and_endpoint(
            Vec::new(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .expect("a group with no backend still builds");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback listener needs no network");
        let addr = listener
            .local_addr()
            .expect("a bound listener has an address");
        (
            LocalProxy::shared(
                Arc::new(listener),
                Arc::new(group),
                domains.iter().map(|d| d.to_string()).collect(),
            ),
            addr,
        )
    }

    fn spawn_run(proxy: &LocalProxy) -> JoinHandle<Result<(), ClientError>> {
        let proxy = proxy.clone();
        tokio::spawn(async move { proxy.run().await })
    }

    /// The ALPN the tunnel speaks. The same bytes the client uses.
    const ALPN: &[u8] = b"\x05nexapipe";

    /// The host the application asks for.
    const HOST: &str = "db.test";

    /// The port it asks for.
    const PORT: u16 = 5432;

    /// A request that names more than one host is refused here.
    ///
    /// The route and the access check read the first `Host` header and the
    /// backend would be handed all of them, so the request that is authorised
    /// and the request that is served would be two different requests.
    ///
    /// The server refuses it with a 400; refusing it at the client says the
    /// same thing without a round trip, and says it where the user can act on
    /// it — a 400 from the far end looks like a proxy bug.
    #[tokio::test]
    async fn a_request_that_names_more_than_one_host_is_refused() {
        let (proxy, addr) = listening_proxy_for(&["db.test"]).await;
        let runner = spawn_run(&proxy);

        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the proxy is listening");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: db.test\r\nHost: other.test\r\n\r\n")
            .await
            .expect("the request is written");

        let mut answer = Vec::new();
        let _read = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            client.read_to_end(&mut answer),
        )
        .await
        .expect("the client read never returned")
        .expect("the client read failed");

        proxy.stop();
        let _ = runner.await;

        let answer = String::from_utf8_lossy(&answer);
        assert!(
            answer.starts_with("HTTP/1.1 400"),
            "the request was refused with: {answer}"
        );
    }

    /// The far side of the tunnel: a server that waits for the client's
    /// half-close before it answers.
    ///
    /// This is the shape of a request/response protocol carried over a
    /// connection the client may half-close: the server reads until the client
    /// is done sending, and only then writes the reply. The reply cannot be
    /// written before the FIN arrives, because the server does not know the
    /// request is finished until then.
    async fn serve_a_tunnel_that_answers_after_the_fin(endpoint: Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(accepting) = incoming.accept() else {
                    return;
                };
                let Ok(connection) = accepting.await else {
                    return;
                };
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };

                // The L4 preface, then the status byte the client waits for.
                let mut header = [0u8; 4];
                if recv.read_exact(&mut header).await.is_err() {
                    return;
                }
                let mut rest = vec![0u8; usize::from(header[3]) + 2];
                if recv.read_exact(&mut rest).await.is_err() {
                    return;
                }
                if send.write_all(&[0x00]).await.is_err() {
                    return;
                }

                // Read until the client is done sending. This is the half-close
                // the reply depends on.
                let mut buf = vec![0u8; 4096];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(None) | Err(_) => break,
                        Ok(Some(n)) => {
                            if n == 0 {
                                break;
                            }
                        }
                    }
                }

                // Only now the reply.
                let _ = send.write_all(b"the reply").await;
                let _ = send.finish();
                // The connection is held open for a moment. Dropping it here
                // would close the tunnel, and a close discards whatever the
                // peer has not read yet -- the reply included.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            });
        }
    }

    /// The far side of a tunnel that closes: the server accepts, answers the
    /// preface, and then ends the conversation without waiting for anything
    /// from the client.
    ///
    /// This is the shape of a server that has nothing more to say — an origin
    /// that closed the connection, or a tunnel whose budget ran out. The
    /// client has to learn that, the way it learns it from a socket.
    async fn serve_a_tunnel_that_closes(endpoint: Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(accepting) = incoming.accept() else {
                    return;
                };
                let Ok(connection) = accepting.await else {
                    return;
                };
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };

                // The L4 preface, then the status byte the client waits for.
                let mut header = [0u8; 4];
                if recv.read_exact(&mut header).await.is_err() {
                    return;
                }
                let mut rest = vec![0u8; usize::from(header[3]) + 2];
                if recv.read_exact(&mut rest).await.is_err() {
                    return;
                }
                if send.write_all(&[0x00]).await.is_err() {
                    return;
                }

                // And then the conversation is over: a FIN, not a reset.
                let _ = send.finish();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            });
        }
    }

    /// A client that half-closes still receives the reply.
    ///
    /// A TCP half-close is a request, not an ending: a client that writes its
    /// request and then shuts down its write side is saying "I am done
    /// sending", and the server's reply still has to arrive. The two halves of
    /// the copy were raced, and whichever lost was aborted — so the reply was
    /// cut off and the connection reset under the client.
    ///
    /// The far side here waits for the FIN before it answers, so the reply
    /// cannot be out before the half-close: the test fails against the old
    /// code, and it fails in the way that matters — the client never gets the
    /// bytes.
    #[tokio::test]
    async fn a_half_closed_client_still_receives_the_reply() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // The far side.
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the far side binds");
        let server_addr = server.addr();
        tokio::spawn(serve_a_tunnel_that_answers_after_the_fin(server));

        // This side: an endpoint, a pool over it, and the proxy.
        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");
        let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
        let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
            .await
            .expect("the proxy binds");
        let proxy_addr = proxy.local_addr().expect("the proxy's address");
        let runner = spawn_run(&proxy);

        // The application: a tunnel, a request, and then a half-close.
        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .expect("the proxy accepts");
        stream
            .write_all(format!("CONNECT {HOST}:{PORT} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .expect("the CONNECT goes out");
        let mut answer = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream
                .read_exact(&mut byte)
                .await
                .expect("the answer comes");
            answer.push(byte[0]);
            if answer.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            answer.starts_with(b"HTTP/1.1 200"),
            "the tunnel should be established: {:?}",
            String::from_utf8_lossy(&answer)
        );

        stream
            .write_all(b"the request")
            .await
            .expect("the request goes out");
        // The half-close: the client is done sending, and the server has to
        // hear that.
        stream.shutdown().await.expect("the write side closes");

        let mut reply = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_to_end(&mut reply),
        )
        .await;
        assert!(
            read.is_ok(),
            "the reply never arrived: the tunnel was cut off at the half-close"
        );
        assert_eq!(
            reply, b"the reply",
            "the reply did not survive the half-close"
        );

        proxy.stop();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), runner).await;
    }

    /// A tunnel the server closes is closed for the client too.
    ///
    /// The other half of the half-close: a server that ends the conversation
    /// says so with a FIN, and the client has to see it the way it would see
    /// it from a socket — as an end of stream, not as a hang and not as a
    /// reset.
    ///
    /// Joining the two directions is right, but joining them is not the same
    /// as leaving the client waiting: the direction that ended has to be
    /// handed on to the peer, or the peer is left waiting for an answer that
    /// is not coming. The write side towards the client is shut down when
    /// the server's side ends, which is what turns "the server is gone" into
    /// the EOF the client is waiting for — and the read side stays open, so
    /// a client that still has something to say can say it.
    #[tokio::test]
    async fn a_tunnel_the_server_closes_is_closed_for_the_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // The far side: it closes the tunnel.
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the far side binds");
        let server_addr = server.addr();
        tokio::spawn(serve_a_tunnel_that_closes(server));

        // This side: an endpoint, a pool over it, and the proxy.
        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");
        let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
        let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
            .await
            .expect("the proxy binds");
        let proxy_addr = proxy.local_addr().expect("the proxy's address");
        let runner = spawn_run(&proxy);

        // The application: a tunnel, and then it waits for the other end.
        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .expect("the proxy accepts");
        stream
            .write_all(format!("CONNECT {HOST}:{PORT} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .expect("the CONNECT goes out");
        let mut answer = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream
                .read_exact(&mut byte)
                .await
                .expect("the answer comes");
            answer.push(byte[0]);
            if answer.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            answer.starts_with(b"HTTP/1.1 200"),
            "the tunnel should be established: {:?}",
            String::from_utf8_lossy(&answer)
        );

        // The far side closes. The client has to be told.
        let mut rest = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_to_end(&mut rest),
        )
        .await;
        assert!(
            read.is_ok(),
            "the client was never told that the tunnel closed: it is still waiting"
        );
        assert!(
            read.is_ok_and(|r| r.is_ok()),
            "the client saw a reset rather than an end of stream"
        );

        proxy.stop();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), runner).await;
    }

    /// The cap is what turns memory into a bounded quantity: every connection
    /// allocates a `STREAM_BUF_SIZE` buffer, so an accept loop that takes every
    /// caller lets anything on the loopback interface spend this process's
    /// memory one connection at a time.
    ///
    /// The refused socket is closed without a byte being read — it must not be
    /// queued, because a queued caller holds the buffer while it waits.
    #[tokio::test]
    async fn connections_beyond_the_cap_are_refused() {
        use std::time::{Duration, Instant};
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        let (proxy, addr) = listening_proxy().await;
        let runner = spawn_run(&proxy);

        // Hold the whole budget open. A connection that has sent nothing sits in
        // the handler waiting for a request, which is the state being counted.
        let mut held = Vec::with_capacity(MAX_CONCURRENT_CONNECTIONS);
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            held.push(TcpStream::connect(addr).await.expect("the caller connects"));
        }

        // `track_connection` runs straight after each accept, so the number of
        // tracked handles is the number being served. Waiting for it to reach the
        // cap is what makes the next connection a refusal rather than a race.
        let deadline = Instant::now() + Duration::from_secs(10);
        while proxy.connections.lock().unwrap().len() < MAX_CONCURRENT_CONNECTIONS {
            assert!(
                Instant::now() < deadline,
                "the accept loop took only {} of {} connections",
                proxy.connections.lock().unwrap().len(),
                MAX_CONCURRENT_CONNECTIONS
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // One over the budget: closed immediately, with nothing read from it.
        let mut extra = TcpStream::connect(addr).await.expect("the caller connects");
        let mut buf = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(5), extra.read(&mut buf))
            .await
            .expect("a refusal closes the socket instead of leaving it open");
        assert_eq!(
            closed.expect("a refusal is a close, not an error"),
            0,
            "a connection beyond the cap must be closed, not queued"
        );

        // And the budget is released: once a caller hangs up, its slot comes back.
        drop(held.pop());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut probe = TcpStream::connect(addr).await.expect("the caller connects");
            let mut buf = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(200), probe.read(&mut buf)).await {
                // A timeout means the connection was accepted and is waiting for
                // a request: the slot came back.
                Err(_) => break,
                Ok(Ok(0)) => {
                    assert!(
                        Instant::now() < deadline,
                        "no slot was released after a connection ended"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(Ok(n)) => panic!("nothing is ever sent to a fresh connection, got {n} bytes"),
                Ok(Err(e)) => panic!("a fresh connection is not reset: {e}"),
            }
        }

        proxy.stop();
        runner.abort();
    }

    /// A caller that trickles its request head forever is closed, rather than
    /// holding its connection, its task and its slot open indefinitely.
    ///
    /// The shape of this test is the point: a byte goes out well inside the
    /// deadline, over and over, for longer than the deadline itself. Under a
    /// per-read timeout every one of those bytes reset the clock and the read
    /// would still be running at the end; under a phase deadline the instant was
    /// taken once and the trickle renews nothing.
    ///
    /// Drives `read_http_header` over a `duplex` pair rather than a real socket
    /// so the budget can be milliseconds instead of the production thirty
    /// seconds — which is why the deadline is a parameter of that function.
    #[tokio::test]
    async fn a_trickling_request_head_is_closed_rather_than_waited_on() {
        use tokio::io::AsyncWriteExt;

        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let (mut client, mut server) = tokio::io::duplex(4096);

        // A request line that never terminates, so the reader stays in the loop
        // for the whole run.
        let trickle = tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            let mut sends = 0usize;
            // Twice the deadline: comfortably past the point where a per-read
            // timeout would have renewed forever, while each individual send
            // stays inside the budget.
            while started.elapsed() < Duration::from_millis(400) {
                if client.write_all(b"G").await.is_err() {
                    break;
                }
                sends += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            sends
        });

        let mut request_buf = Vec::new();
        let started = std::time::Instant::now();
        let outcome = read_http_header(&mut server, &mut request_buf, deadline).await;

        assert_eq!(
            outcome,
            HeaderOutcome::Closed,
            "a head that trickles past its deadline must be closed, not waited on"
        );
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "it expired on the deadline rather than when the peer stopped: {:?}",
            started.elapsed()
        );

        let sends = trickle.await.unwrap_or(0);
        assert!(
            sends > 1,
            "the test did not actually trickle: {sends} sends"
        );
    }

    /// A head that arrives complete is read as one, and the deadline is not
    /// charged to a request that needed no waiting.
    #[tokio::test]
    async fn a_head_that_arrives_whole_is_complete_at_once() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let (mut client, mut server) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            let _ = client
                .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
                .await;
            // Held open so the read cannot end at EOF and be mistaken for a
            // complete head by accident.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut request_buf = Vec::new();
        match read_http_header(&mut server, &mut request_buf, deadline).await {
            HeaderOutcome::Complete(end) => {
                assert_eq!(
                    &request_buf[..end],
                    b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
                );
            }
            HeaderOutcome::Closed => panic!("a complete head must not be reported as closed"),
        }
    }

    /// `stop()` has to reach a loop that is parked in `accept()`, not one that
    /// happens to look at a flag on the way past: with nothing to wake it, the
    /// task stays on the listener for as long as the process lives.
    #[tokio::test]
    async fn stop_wakes_a_loop_that_is_waiting_for_a_connection() {
        let (proxy, _addr) = listening_proxy().await;
        let runner = spawn_run(&proxy);

        // Long enough that the loop is definitely inside `accept()`.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        proxy.stop();

        assert!(
            tokio::time::timeout(tokio::time::Duration::from_secs(2), runner)
                .await
                .is_ok(),
            "run() never returned after stop()"
        );
    }

    /// The handlers outlive `run()`, so a proxy that only stops the loop would
    /// leave them holding pooled connections. Stopping has to end them too.
    #[tokio::test]
    async fn stop_ends_the_connections_it_accepted() {
        let (proxy, addr) = listening_proxy().await;
        let runner = spawn_run(&proxy);

        // A client that connects and then says nothing: the handler parks in
        // its first read, which is the state that used to survive stop().
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the proxy is listening");

        let tracked = tokio::time::timeout(tokio::time::Duration::from_secs(2), async {
            loop {
                if proxy.connections.lock().unwrap().len() == 1 {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(tracked.is_ok(), "the accepted connection was never tracked");

        proxy.stop();
        assert!(
            tokio::time::timeout(tokio::time::Duration::from_secs(2), runner)
                .await
                .is_ok(),
            "run() never returned after stop()"
        );
        assert!(
            proxy.connections.lock().unwrap().is_empty(),
            "stop() must drop the handles it aborted"
        );

        // Aborting the handler drops its socket, so the peer sees EOF instead
        // of waiting out the handler's read timeout.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(tokio::time::Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("the client read never returned")
            .expect("the client read failed");
        assert_eq!(read, 0, "the handler kept its socket open after stop()");
    }

    /// The cap is on the header, not on the whole request: a short header
    /// followed by a body larger than the cap is an ordinary upload, and used
    /// to be refused for being one.
    #[test]
    fn the_header_limit_ignores_the_body() {
        let mut request = b"POST /upload HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        request.extend(std::iter::repeat_n(b'x', MAX_REQUEST_HEADER * 4));

        let header_end = header_terminator(&request);

        assert!(!header_over_limit(&request, header_end));
    }

    /// A header that arrives whole in one read never enters the read loop, so
    /// the first read is measured as well — otherwise the cap only ever applied
    /// to a header split across two.
    #[test]
    fn an_oversized_header_is_refused_even_when_it_is_complete() {
        let mut request = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        request.extend(std::iter::repeat_n(b'a', MAX_REQUEST_HEADER));
        request.extend_from_slice(b"\r\n\r\n");

        let header_end = header_terminator(&request).expect("the terminator is written above");

        assert!(header_over_limit(&request, Some(header_end)));
    }

    /// Until a terminator arrives, everything read is header as far as anyone
    /// can tell — which is the case that bounds a peer that never ends one.
    #[test]
    fn a_header_that_never_ends_is_still_capped() {
        let request: Vec<u8> = std::iter::repeat_n(b'a', MAX_REQUEST_HEADER + 1).collect();

        assert!(header_over_limit(&request, None));
        assert!(!header_over_limit(&request[..MAX_REQUEST_HEADER], None));
    }

    /// Where the header ends in `request`, if it ends at all.
    fn header_terminator(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
    }

    /// The headers a request keeps, as one string.
    fn kept_headers(request: &[u8]) -> String {
        String::from_utf8(filter_request_headers(request, false)).expect("the headers are ASCII")
    }

    /// The headers a request keeps, as one string, with the upgrade kept.
    fn kept_headers_with_upgrade(request: &[u8]) -> String {
        String::from_utf8(filter_request_headers(request, true)).expect("the headers are ASCII")
    }

    /// A request line that ends with a bare LF still ends there.
    ///
    /// The headers after it are the headers, and the first of them is the
    /// `Host` one — the one that says which name the request is for. A walk
    /// that took the first `\r\n` instead would step over it, and the server
    /// substitutes the backend's address for a request that arrives without
    /// one: a request for a name would then be served by the wrong site.
    #[test]
    fn a_bare_lf_request_line_does_not_take_the_first_header_with_it() {
        let request = b"GET /chat HTTP/1.1\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
        let end = request_line_end(request);

        assert_eq!(
            &request[end + 1..],
            b"Host: example.com\r\nUpgrade: websocket\r\n\r\n",
            "the headers after the request line are still there"
        );
    }

    /// The ordinary spelling, with the carriage return, is the same answer.
    #[test]
    fn a_crlf_request_line_ends_where_it_did() {
        let request = b"GET /chat HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let end = request_line_end(request);

        assert_eq!(
            &request[end + 1..],
            b"Host: example.com\r\n\r\n",
            "the headers after the request line are still there"
        );
    }

    /// The hop-by-hop headers do not cross the tunnel.
    ///
    /// `Proxy-Authorization` is the one that matters most: it is a credential
    /// for *this* proxy, and forwarding it hands it to a third-party server.
    #[test]
    fn the_hop_by_hop_headers_do_not_cross_the_tunnel() {
        let request = b"GET / HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Proxy-Authorization: Basic c2VjcmV0\r\n\
                        Proxy-Authenticate: Basic\r\n\
                        Proxy-Connection: keep-alive\r\n\
                        Keep-Alive: timeout=5\r\n\
                        Te: trailers\r\n\
                        Trailer: Expires\r\n\
                        Accept: */*\r\n\r\n";

        let kept = kept_headers(request).to_ascii_lowercase();

        for header in [
            "proxy-authorization",
            "proxy-authenticate",
            "proxy-connection",
            "keep-alive",
            "te:",
            "trailer:",
        ] {
            assert!(!kept.contains(header), "{header} was forwarded:\n{kept}");
        }
        assert!(kept.contains("host: example.com"), "{kept}");
        assert!(kept.contains("accept: */*"), "{kept}");
    }

    /// `Connection` nominates the names that are hop-by-hop for this message,
    /// so a header it names must not be forwarded either.
    #[test]
    fn a_header_connection_nominates_does_not_cross_the_tunnel() {
        let request = b"GET / HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Connection: X-Secret, close\r\n\
                        X-Secret: the-password\r\n\
                        Accept: */*\r\n\r\n";

        let kept = kept_headers(request);

        assert!(!kept.to_ascii_lowercase().contains("x-secret"), "{kept}");
        assert!(kept.contains("Accept: */*"), "{kept}");
    }

    /// The framing of the body is carried over verbatim, so the header that
    /// describes it stays: a chunked body with nothing saying it is chunked is
    /// a request the backend cannot read.
    #[test]
    fn the_transfer_encoding_stays_because_the_body_stays() {
        let request = b"POST / HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Transfer-Encoding: chunked\r\n\
                        Accept: */*\r\n\r\n";

        let kept = kept_headers(request);

        assert!(
            kept.to_ascii_lowercase().contains("transfer-encoding"),
            "{kept}"
        );
    }

    /// The upgrade is the point of a WebSocket request, so it stays.
    #[test]
    fn the_upgrade_stays_when_the_request_is_one() {
        let request = b"GET /ws HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

        let kept = kept_headers_with_upgrade(request).to_ascii_lowercase();

        assert!(kept.contains("upgrade: websocket"), "{kept}");
        assert!(kept.contains("connection: upgrade"), "{kept}");
        assert!(kept.contains("sec-websocket-key:"), "{kept}");
    }

    /// The request line is not a header, even when it carries a colon: it is
    /// the one line that must survive the filter untouched.
    #[test]
    fn the_request_line_is_not_mistaken_for_a_header() {
        let request = b"GET /a:b HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let kept = kept_headers(request);

        assert!(kept.starts_with("GET /a:b HTTP/1.1\r\n"), "{kept}");
    }

    /// The local proxy hands out the tunnel of a connection that has already
    /// authenticated, so it is loopback-only unless the caller says otherwise.
    #[test]
    fn the_local_proxy_is_loopback_only_unless_the_caller_says_otherwise() {
        let loopback: SocketAddr = "127.0.0.1:8080".parse().expect("an address");
        let v6_loopback: SocketAddr = "[::1]:8080".parse().expect("an address");
        let lan: SocketAddr = "192.168.1.10:8080".parse().expect("an address");
        let any: SocketAddr = "0.0.0.0:8080".parse().expect("an address");
        let any_v6: SocketAddr = "[::]:8080".parse().expect("an address");

        assert!(may_bind_local_proxy(loopback, false));
        assert!(may_bind_local_proxy(v6_loopback, false));

        for bound in [lan, any, any_v6] {
            assert!(
                !may_bind_local_proxy(bound, false),
                "{bound} is reachable from the network"
            );
            assert!(
                may_bind_local_proxy(bound, true),
                "{bound} needs the explicit opt-in"
            );
        }
    }

    /// A conditional request loses the headers that would make the origin
    /// answer with a 304 and an empty body.
    #[test]
    fn a_conditional_request_loses_its_cache_headers() {
        let request = b"GET / HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        If-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT\r\n\
                        If-None-Match: \"a-long-etag-value\"\r\n\
                        Accept: */*\r\n\r\n";

        let kept = kept_headers(request);

        assert!(
            !kept.to_ascii_lowercase().contains("if-modified-since"),
            "{kept}"
        );
        assert!(
            !kept.to_ascii_lowercase().contains("if-none-match"),
            "{kept}"
        );
        assert!(kept.contains("Host: example.com"), "{kept}");
        assert!(kept.contains("Accept: */*"), "{kept}");
    }

    /// The shortest forms of `If-None-Match` are the ones a length guard for
    /// the *longer* header name lets through — and they are exactly the
    /// requests the origin answers with a 304 and an empty body.
    #[test]
    fn the_shortest_if_none_match_is_stripped() {
        for value in ["*", "\"\"", "\"e\""] {
            let request =
                format!("GET / HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: {value}\r\n\r\n");

            let kept = kept_headers(request.as_bytes());

            assert!(
                !kept.to_ascii_lowercase().contains("if-none-match"),
                "`If-None-Match: {value}` is {value:?} — {kept}"
            );
            assert!(kept.contains("Host: example.com"), "{kept}");
        }
    }

    /// The header name is a name, not a string to match exactly: a client that
    /// spells it in another case is still asking for a conditional response.
    #[test]
    fn the_cache_header_is_stripped_whatever_its_case() {
        for name in ["if-none-match", "IF-NONE-MATCH", "If-None-Match"] {
            let request = format!("GET / HTTP/1.1\r\n{name}: *\r\n\r\n");

            let kept = kept_headers(request.as_bytes());

            assert!(
                !kept
                    .to_ascii_lowercase()
                    .contains(name.to_ascii_lowercase().as_str()),
                "{name} was kept: {kept}"
            );
            assert!(kept.starts_with("GET / HTTP/1.1"), "{kept}");
        }
    }

    /// Only the two cache-validation headers are stripped: a header that
    /// merely starts with the same letters is somebody else's.
    #[test]
    fn a_header_that_merely_looks_like_one_is_kept() {
        let request = b"GET / HTTP/1.1\r\n\
                        X-If-None-Match: *\r\n\
                        If-None-Match-Extra: *\r\n\r\n";

        let kept = kept_headers(request);

        assert!(kept.contains("X-If-None-Match: *"), "{kept}");
        assert!(kept.contains("If-None-Match-Extra: *"), "{kept}");
    }
}
