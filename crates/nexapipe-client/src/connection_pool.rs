use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use tokio::sync::{Mutex, watch};
use tokio_stream::StreamExt;

#[cfg(feature = "tracing")]
use tracing;

use crate::ClientError;
use crate::auth::{Enrollment, IssuedCredential, TwoFactorAuth};
use nexapipe_proto::secret::SecretString;

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
/// What a dial produced: the connection and the state its flows share, or
/// the failure that stopped it.
///
/// The state travels with the connection because the waiters for a shared
/// dial each borrow it — a hundred flows on one connection are a hundred
/// borrows, and the pool has to be able to say so.
type DialOutcome = Result<(Connection, Arc<BorrowState>), ClientError>;

const MAX_CONNECTIONS: usize = 10;
const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Idle connections older than this are evicted when a new connection is requested.
const CONNECTION_IDLE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);
/// How many flows may ride one connection at the same time.
///
/// The server counts the L4 flows on a connection and refuses the one that
/// does not fit (`Status::TooManyFlows`), so a client that piles every flow
/// onto one connection runs into a ceiling it cannot see. The pool keeps
/// below that ceiling itself and opens another connection instead.
///
/// The server's ceiling is 256 L4 flows per connection
/// (`DEFAULT_MAX_FLOWS_PER_CONNECTION` in `crates/nexapipe/src/l4/mod.rs`).
/// This number counts **every** flow on the connection — HTTP and L4 alike —
/// so it has to stay below the server's, and it stays below it with room to
/// spare: the two counters are not the same one, and the server's lags by a
/// flow or two while a flow is ending.
const MAX_FLOWS_PER_CONNECTION: usize = 200;
/// Interval of the background watcher that removes closed/stale connections from the pool.
const CONNECTION_CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);
/// How often the round-trip time is re-read.
///
/// A second is quick enough for a figure that reads as "now" and slow enough
/// to be free: iroh keeps the estimate in memory and reading it is a lookup.
const RTT_POLL_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(1);
/// Budget for the connect half of a preconnect.
///
/// Deliberately shorter than [`PRECONNECT_TIMEOUT`]: the caller cancels the whole
/// preconnect at its own deadline, and a cancelled connect reports nothing — so a
/// node that hangs stayed silent, which is exactly the case that needs explaining.
/// With a smaller budget here, the timeout (or iroh's error) surfaces in the log.
const PRECONNECT_CONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(6);

/// How long a freshly established connection is watched for a 2FA refusal when
/// this client has no credentials.
///
/// Only such a client needs it: one with credentials fails the handshake itself
/// and knows at once. Without credentials the QUIC handshake succeeds and
/// nothing else happens, so the server is the only party that knows the
/// connection is unusable — it says so by closing once its own handshake
/// deadline (`AUTH_HANDSHAKE_TIMEOUT` in `crates/nexapipe/src/conn/mod.rs`)
/// passes. This wait covers that deadline plus a round trip, so it has to stay
/// above the server's constant — raising one without the other silently turns
/// "the server requires 2FA" back into "the backend looks unreachable".
const AUTH_REQUIRED_GRACE: tokio::time::Duration = tokio::time::Duration::from_secs(6);

/// Budget for one preconnect / warm-up, covering both of its halves.
///
/// This is the whole of what [`IrohConnectionPool::preconnect`] may spend, not
/// only the connect: [`AUTH_REQUIRED_GRACE`] belongs *inside* the preconnect
/// rather than after it. It used to sit outside, with the connect alone
/// budgeted at 8s, so a backend that took more than two seconds to answer was
/// cancelled in the middle of being observed and reported unreachable for
/// being slow.
///
/// It has to hold both halves. Shortening the observation is its own failure —
/// a backend that demands 2FA starts to look like one that is merely
/// unreachable, with the reason lost — which is why this is the sum and not
/// something tighter.
pub(crate) const PRECONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(12);

/// Both halves have to fit, or the observation is what gets cut.
const _: () = assert!(
    PRECONNECT_TIMEOUT.as_secs()
        >= PRECONNECT_CONNECT_TIMEOUT.as_secs() + AUTH_REQUIRED_GRACE.as_secs()
);

/// The application error code the server closes a connection with when it
/// requires 2FA the client never performed. Must match `auth_close_code::REQUIRED`
/// in `crates/nexapipe/src/conn/mod.rs`.
const AUTH_REQUIRED_CLOSE_CODE: u32 = 2;

/// The application error code the server closes a connection with when a
/// `[peers]` allow-list refuses this Node ID. Must match
/// `PEER_NOT_ALLOWED_CLOSE_CODE` in `crates/nexapipe/src/conn/allow_list.rs`.
///
/// Reached from a different place than the 2FA codes: the server refuses inside
/// the QUIC handshake, so `connect` itself fails rather than a later stream. The
/// preconnect has to read the close reason from that failure to turn "connection
/// lost" into a cause the operator can act on.
const PEER_NOT_ALLOWED_CLOSE_CODE: u32 = 5;

/// How traffic currently reaches a backend: direct, or through a relay.
///
/// iroh keeps several paths open per connection and marks exactly one of them *selected* — the
/// path application data actually takes. That, and not "a direct path exists", decides the
/// label: a connection that has opened a UDP path but still routes over the relay is a relay
/// connection until iroh promotes it.
///
/// This is the **runtime** answer on purpose. The relay URL in the configuration (or in an
/// invite) only names a relay that *may* be used; it says nothing about whether the hole punch
/// succeeded, so a UI must never infer the icon from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// The selected path is a direct UDP path to the backend.
    Direct,
    /// The selected path goes through a relay server.
    Relay,
    /// No path is known: nothing has connected yet, or the connection has no path.
    #[default]
    Unknown,
}

impl LinkKind {
    /// The stable name sent across the JNI and Tauri boundaries.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Unknown => "unknown",
        }
    }

    /// Tolerant by design: this only ever feeds an icon, so an unfamiliar spelling means
    /// [`Self::Unknown`] rather than an error.
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "direct" => Self::Direct,
            "relay" => Self::Relay,
            _ => Self::Unknown,
        }
    }

    /// Reads the kind off a live connection.
    ///
    /// A closed connection has no path left to report, so the caller gets [`Self::Unknown`]
    /// instead of a stale answer.
    pub fn of(conn: &Connection) -> Self {
        if conn.close_reason().is_some() {
            return Self::Unknown;
        }

        let paths = conn.paths();
        for path in paths.iter() {
            if path.is_selected() {
                return if path.is_ip() {
                    Self::Direct
                } else if path.is_relay() {
                    Self::Relay
                } else {
                    Self::Unknown
                };
            }
        }

        // Paths are open but none is selected (the handshake is still settling). A direct path,
        // once opened, is the one iroh will promote, so it outranks an also-open relay path.
        let mut has_relay = false;
        for path in paths.iter() {
            if path.is_ip() {
                return Self::Direct;
            }
            has_relay |= path.is_relay();
        }
        if has_relay {
            Self::Relay
        } else {
            Self::Unknown
        }
    }
}

/// How a backend is reached right now, and how long a round trip takes.
///
/// The two belong together: the round trip is only meaningful for the path
/// that is carrying the traffic, and the path can change under the reading —
/// a direct path that opens replaces a relay one, and with it the latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkStatus {
    /// Whether traffic goes straight to the peer or through a relay.
    pub kind: LinkKind,
    /// The round-trip time of the path carrying the traffic.
    ///
    /// `None` means "not measured": a connection that has just opened has no
    /// sample yet, a closed one has none either, and a path iroh cannot
    /// measure — a relay that does not report — has none at all. It is not a
    /// zero, and a UI must not draw it as one.
    ///
    /// The reading is also `None` while the path still carries quinn's initial
    /// guess rather than a measurement — see [`rtt_of`].
    pub rtt: Option<std::time::Duration>,
}

impl LinkStatus {
    /// Reads both halves off a live connection.
    ///
    /// A closed connection has no path left to report, so the caller gets
    /// [`LinkStatus::default`] rather than a stale answer.
    pub fn of(conn: &Connection) -> Self {
        let kind = LinkKind::of(conn);
        if kind == LinkKind::Unknown {
            return Self::default();
        }
        Self {
            kind,
            rtt: rtt_of(conn),
        }
    }
}

/// The wire form of one link reading: `<endpoint id>=<kind>/<rtt in ms>`.
///
/// The JNI boundary carries the readings in this form and the Kotlin side reads
/// them back: the id, the kind, and the round trip in whole milliseconds.
/// `-` stands for a reading with no sample, so that an unmeasured path is not
/// read as a round trip of zero milliseconds.
///
/// A function of its own so that the form is testable without an endpoint:
/// the Kotlin decoder has its own tests, and the two halves of a contract
/// that only one side tests can drift apart without anything failing.
pub fn encode_link_status(id: &EndpointId, status: &LinkStatus) -> String {
    let rtt = match status.rtt {
        Some(rtt) => rtt.as_millis().to_string(),
        None => "-".to_string(),
    };
    format!("{}={}/{}", id, status.kind.as_str(), rtt)
}

/// The round-trip time of the path carrying the traffic, if it can be read.
///
/// The selected path is the one the traffic takes, so that is the one whose
/// latency is worth showing.
///
/// Two readings are not measurements, and are reported as `None` rather than
/// as a number:
///
/// - **quinn's guess.** The RTT estimator of a path starts at the transport's
///   [`INITIAL_RTT`](crate::transport::INITIAL_RTT) and holds it until the
///   path has something to say. A path selected a moment ago — a direct path
///   that just won hole punching, a relay path that just became the selected
///   one — therefore reads as the guess, which is a number nobody measured.
/// - **anything below a millisecond.** The UI draws whole milliseconds, and a
///   reading that rounds to zero is drawn as a number nobody made.
///
/// The guess is recognised by its value, and quinn leaves it in more than one
/// way. A path validation measures the round trip of its challenge and puts
/// that in its place, which is a measurement of its own and is reported as
/// one; a path opened for the same peer address while another validated path
/// to that address exists starts from that path's conservative estimate rather
/// than from the initial RTT — quinn looks for a validated path on the same
/// network path, so a direct path and a relay path do not seed each other. A
/// round trip that happens to land exactly on the initial RTT is reported as
/// no measurement at all.
fn rtt_of(conn: &Connection) -> Option<std::time::Duration> {
    let paths = conn.paths();
    for path in paths.iter() {
        if path.is_selected() {
            let rtt = conn.rtt(path.id())?;
            return measured_rtt(rtt);
        }
    }
    None
}

/// The round trip of a path, when it is a measurement rather than a guess.
///
/// Split out of [`rtt_of`] so that a reading can be taken off a path the
/// caller names rather than off whichever one is selected now: the two halves
/// of a reading describe one path, and the selection can move under the
/// reading.
fn measured_rtt(rtt: std::time::Duration) -> Option<std::time::Duration> {
    is_measured_rtt(rtt).then_some(rtt)
}

/// Whether `rtt` is a measured round-trip time rather than a guess.
///
/// Split out from [`rtt_of`] so the rule can be tested without a live
/// connection: reading it off a connection needs an endpoint, and the rule is
/// the part that has to be right.
///
/// The rule is the value, so it is exact in one direction only: a round trip
/// that lands exactly on the initial RTT is reported as no measurement.
fn is_measured_rtt(rtt: std::time::Duration) -> bool {
    rtt != crate::transport::INITIAL_RTT && rtt >= std::time::Duration::from_millis(1)
}

/// Why a connection could not be put in the pool.
///
/// The two are different failures and they read differently: one is a
/// connection that was gone before it could be used, the other is a pool
/// with no room left in it.
enum PoolRefusal {
    /// The connection was already closed.
    Closed,
    /// The pool holds as many connections as it may.
    Full,
}

struct PooledConnection {
    conn: Connection,
    /// What the pool and the flows on this connection share.
    ///
    /// The count is here because the pool owns the connection and the flows
    /// **borrow** it, so the pool cannot tell from the handle alone whether
    /// anyone is still on it — and it has to: a connection with a flow on it
    /// is not idle, and closing it would take that flow down with it.
    state: Arc<BorrowState>,
}

impl PooledConnection {
    /// True if the underlying iroh connection is still open (not closed by either side).
    fn is_live(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    /// True if this connection has been sitting in the pool unused for at least
    /// `timeout`.
    fn is_idle_for(&self, timeout: tokio::time::Duration) -> bool {
        self.state.is_idle_for(timeout)
    }
}

/// What the pool and the flows on one connection share: how many flows are
/// riding it, when it was last used, and whether the server has said the
/// connection is full.
///
/// The count is shared because the pool has to be able to tell a connection
/// nobody is using from one that a flow is still riding — and closing the
/// second would take that flow down with it.
///
/// The last-use stamp is shared for the same reason: it is stamped when the
/// **last** borrow goes, which is a moment only the borrower can see. A
/// connection that has just carried a ten-minute flow is fresh for another
/// minute, and a connection that is still carrying one is not idle at all.
#[derive(Debug)]
pub struct BorrowState {
    /// How many flows are on the connection right now.
    borrows: AtomicUsize,
    /// When the connection was last used.
    ///
    /// Not when it was dialled: a connection that is used continuously is
    /// handed out every few seconds, and the idle timeout is about how long
    /// it has been sitting unused — not how old it is. A connection in
    /// constant use is not idle, and a ten-minute-old connection that was
    /// handed out a second ago is not either.
    last_used: StdMutex<tokio::time::Instant>,
    /// Whether the server has refused a flow on this connection because it
    /// was already carrying as many as it allows.
    ///
    /// Set when the server answers `Status::TooManyFlows`, and **not** cleared
    /// when the last flow on the connection ends: the server counts its own
    /// flows, and the flow that was refused is not one of them — so a
    /// connection the server has called full stays out of circulation, and
    /// the next flow is given a connection of its own.
    saturated: AtomicBool,
}

impl BorrowState {
    fn new() -> Self {
        Self {
            borrows: AtomicUsize::new(0),
            last_used: StdMutex::new(tokio::time::Instant::now()),
            saturated: AtomicBool::new(false),
        }
    }

    /// How many flows are on the connection right now.
    fn borrow_count(&self) -> usize {
        self.borrows.load(Ordering::Acquire)
    }

    /// Whether another flow may ride this connection.
    fn has_room(&self) -> bool {
        !self.saturated.load(Ordering::Acquire) && self.borrow_count() < MAX_FLOWS_PER_CONNECTION
    }

    /// Takes a borrow, if there is room for one.
    ///
    /// The check and the count are one atomic step, so two callers cannot
    /// both see the last seat and both take it.
    fn try_borrow(self: &Arc<Self>) -> Option<Borrow> {
        if self.saturated.load(Ordering::Acquire) {
            return None;
        }
        let mut current = self.borrows.load(Ordering::Acquire);
        loop {
            if current >= MAX_FLOWS_PER_CONNECTION {
                return None;
            }
            match self.borrows.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // The connection is in use again, so it is not idle
                    // however long ago it was last used.
                    self.touch();
                    return Some(Borrow {
                        state: Some(self.clone()),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Gives a borrow back.
    ///
    /// The last-use stamp moves when the **last** borrow goes: a connection
    /// that has just carried a flow is fresh for another minute, and the
    /// moment it became idle is a moment only the last borrower sees.
    fn release(&self) {
        let mut current = self.borrows.load(Ordering::Acquire);
        loop {
            if current == 0 {
                // A borrow is given back exactly once, so this cannot
                // happen — and wrapping the counter would hide the bug
                // behind a count of billions.
                debug_assert!(false, "a borrow was given back that was never taken");
                return;
            }
            match self.borrows.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if current == 1 {
                        // The last flow on this connection ended: it is idle
                        // from now on.
                        self.touch();
                    }
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Stamps the connection as used right now.
    fn touch(&self) {
        let mut last_used = self
            .last_used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *last_used = tokio::time::Instant::now();
    }

    /// When the connection was last used.
    fn last_used(&self) -> tokio::time::Instant {
        *self
            .last_used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether the connection has been sitting unused for at least `timeout`.
    fn is_idle_for(&self, timeout: tokio::time::Duration) -> bool {
        is_idle_since(self.last_used(), timeout)
    }

    /// Marks the connection as carrying as many flows as the server allows.
    fn saturate(&self) {
        self.saturated.store(true, Ordering::Release);
    }
}

/// One flow's borrow on a connection.
///
/// The borrow is given back when the guard is dropped, and `Drop` is what
/// covers every way a flow ends: EOF, an error, a cancellation. The guard is
/// the only thing that gives a borrow back, so a borrow cannot be forgotten
/// on one path and given back twice on another.
#[derive(Debug)]
pub struct Borrow {
    /// The state the borrow belongs to.
    ///
    /// `None` once the borrow has been handed on, so that a hand-over does
    /// not give it back a second time.
    state: Option<Arc<BorrowState>>,
}

impl Borrow {
    /// Marks the connection as carrying as many flows as the server allows.
    ///
    /// The server refused a flow with `TooManyFlows`, which is a statement
    /// about the connection rather than about the flow: the pool must stop
    /// handing that connection out, or the next flow is refused the same way.
    pub fn saturate(&self) {
        if let Some(state) = &self.state {
            state.saturate();
        }
    }
}

impl Drop for Borrow {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.release();
        }
    }
}

/// Whether a connection that was last used at `last_used` has been sitting
/// unused for at least `timeout`.
///
/// Free rather than a method, so that the rule can be tested without a live
/// connection: reading it off one needs an endpoint, and the rule is the part
/// that has to be right.
fn is_idle_since(last_used: tokio::time::Instant, timeout: tokio::time::Duration) -> bool {
    last_used.elapsed() >= timeout
}

/// Drops the connections that are closed or idle, closing the idle ones.
///
/// A connection that is only dropped stays open as far as QUIC is concerned:
/// quinn closes a connection when its *last* handle goes away, and the path
/// watcher still holds one, so the socket and the NAT mapping on both sides
/// live on — and the watcher keeps reporting a route for a connection the pool
/// has abandoned.
///
/// The idle ones are closed with a reason, so the peer sees a connection that
/// went away on purpose rather than one that vanished.
fn drop_stale_connections(connections: &mut Vec<PooledConnection>) {
    let mut idle = Vec::new();
    connections.retain(|pooled| {
        if !pooled.is_live() {
            return false;
        }
        // **Idle means nobody is riding it.** The pool owns the connection
        // and the flows borrow it, so a connection that has not been handed
        // out for a minute may still be carrying a flow that opened ten
        // minutes ago and is still running. Closing that would take the flow
        // down with it, so a connection with a flow on it is never idle.
        if pooled.is_idle_for(CONNECTION_IDLE_TIMEOUT) && pooled.state.borrow_count() == 0 {
            idle.push(pooled.conn.clone());
            return false;
        }
        true
    });
    for conn in idle {
        conn.close(0u32.into(), b"idle");
    }
}

/// A connection borrowed from the pool, and the borrow that says how many
/// flows are on it.
///
/// The borrow is given back when this value is dropped, which is what makes
/// the count true: a flow that ends in any way — EOF, an error, a
/// cancellation — drops it.
///
/// The state behind the borrow is shared with the pool's own entry for the
/// connection, so the pool can tell a connection nobody is using from one
/// that a flow is still riding.
pub struct BorrowedConnection {
    /// The connection itself. A cheap clonable handle: iroh's `Connection`
    /// may be cloned to get another handle to the same connection.
    pub conn: Connection,
    /// The borrow this connection is held under.
    pub borrow: Borrow,
}

#[derive(Clone)]
pub struct IrohConnectionPool {
    inner: Arc<IrohConnectionPoolInner>,
}

/// Lock order, observed everywhere: `connections`, then `link_status`, then
/// `ep` — and never nested.
///
/// Nesting is what makes a pool that dials while another task shuts it down
/// deadlock-prone: `link_status` is also taken by the per-connection path
/// watcher, and `ep` by every dial, so holding one while waiting for another
/// turns a slow shutdown into a stall for every request.
struct IrohConnectionPoolInner {
    connections: Mutex<Vec<PooledConnection>>,
    /// The dial that is in progress, if one is.
    ///
    /// Everything that asks for a connection while a dial is running waits
    /// for **that** dial instead of starting one of its own. Without it, a
    /// hundred concurrent flows would each start a dial and a hundred
    /// connections would be made to carry a hundred flows — against a
    /// transport built to carry 1024 bi-streams on one connection.
    dialing: Mutex<Option<watch::Receiver<Option<DialOutcome>>>>,
    ep: Arc<Mutex<Option<Endpoint>>>,
    endpoint_addr: EndpointAddr,
    /// Optional client 2FA credentials. When set, every freshly established
    /// connection is authenticated with the server before it is pooled/used.
    two_factor: Mutex<Option<TwoFactorAuth>>,
    /// A one-time enrollment token to spend on the next connection instead of
    /// presenting credentials — what a `v=2` invite carries. Cleared once it
    /// has bought a secret, which lands in [`Self::two_factor`].
    enrollment: Mutex<Option<Enrollment>>,
    /// The credential the server issued for that token.
    ///
    /// The process can use it for as long as it lives, but the token it came
    /// from is spent: an app that restarts without persisting this has nothing
    /// left to authenticate with. [`IrohConnectionPool::take_issued_credential`]
    /// hands it to whoever stores such things.
    issued: Mutex<Option<TwoFactorAuth>>,
    /// Why the last preconnect failed with "2FA required", when the server said
    /// so: a client without credentials cannot fail the handshake on its own, so
    /// the refusal is only visible as a close, and this hands the reason to
    /// whoever reports the failure. Read (and cleared) by
    /// [`IrohConnectionPool::take_auth_required`].
    auth_required: Mutex<Option<String>>,
    /// Whether this pool created (and therefore owns) its iroh endpoint.
    ///
    /// `new()` binds a dedicated endpoint, so `close_all` must close it.
    /// `new_with_endpoint()` shares a caller-owned endpoint (e.g. the global
    /// ENDPOINT in the Android JNI layer); closing it here would break the
    /// next `nativeStartProxy`/`nativePreconnect` with "Endpoint is closed"
    /// and tear down a running tunnel on proxy restart / reconnect.
    owns_endpoint: bool,
    /// The last observed [`LinkStatus`] for this backend, and the connection it describes.
    ///
    /// A pool hands its connections out to whoever is proxying traffic, so at any moment the
    /// pool itself may hold none — and a UI asking "direct or relay, and how far?" every few
    /// seconds must not be answered with "unknown" just because a request is in flight. The path
    /// watcher writes here; [`IrohConnectionPool::link_status`] reads it whenever no pooled
    /// connection can be asked directly.
    ///
    /// The connection is part of the reading because the reading is about it: a status recorded
    /// for a connection that has since died describes no path at all, and a UI that keeps showing
    /// it shows a route to a backend it cannot reach.
    link_status: Mutex<CachedLinkStatus>,
    /// Which network generation the pool is on.
    ///
    /// Moved by [`IrohConnectionPool::drop_connections`], which is what a
    /// network switch calls. The drop closes every connection the pool
    /// holds, and a flow that is still riding one of them keeps a borrow on
    /// a closed connection — its watcher keeps running, and the reading it
    /// would publish is the one of the network that is gone. A watcher that
    /// notices the generation moved stops publishing, and closes the
    /// connection on its way out.
    epoch: AtomicU64,
}

/// A recorded [`LinkStatus`] and the connection it was recorded for.
#[derive(Default)]
struct CachedLinkStatus {
    /// The connection the status describes, if there is one.
    conn: Option<Connection>,
    /// What the path watcher saw on that connection.
    status: LinkStatus,
}

impl IrohConnectionPool {
    pub async fn new(endpoint_addr: EndpointAddr) -> Result<Self, crate::error::ClientError> {
        let (transport, tuning) = crate::transport::transport_config_with_tuning();
        #[cfg(feature = "tracing")]
        tracing::info!("QUIC transport tuning: {}", tuning.describe());
        // `tuning` is only read by the log line above; keep the binding "used"
        // when `tracing` is off so it is not reported as unused.
        #[cfg(not(feature = "tracing"))]
        let _ = &tuning;
        let ep = Endpoint::builder(presets::N0)
            .transport_config(transport)
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            dialing: Mutex::new(None),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            enrollment: Mutex::new(None),
            issued: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: true,
            link_status: Mutex::new(CachedLinkStatus::default()),
            epoch: AtomicU64::new(0),
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    pub fn new_with_endpoint(ep: Endpoint, endpoint_addr: EndpointAddr) -> Self {
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            dialing: Mutex::new(None),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            enrollment: Mutex::new(None),
            issued: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: false,
            link_status: Mutex::new(CachedLinkStatus::default()),
            epoch: AtomicU64::new(0),
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Self { inner }
    }

    /// The **local** iroh endpoint's own ID — this client's identity on the
    /// network, not the ID of the backend this pool talks to.
    ///
    /// Careful: pools that share a caller-owned endpoint (`new_with_endpoint`)
    /// all report the *same* ID here, because they all use one local endpoint.
    /// Do not use this to tell backends apart; use [`Self::backend_id`].
    ///
    /// Returns the all-zero ID when the endpoint lock is momentarily held or the
    /// endpoint has already been closed.
    pub fn node_id(&self) -> EndpointId {
        match self.inner.ep.try_lock() {
            Ok(ep) => {
                if let Some(e) = ep.as_ref() {
                    e.id()
                } else {
                    EndpointId::from_bytes(&[0u8; 32])
                        .expect("Failed to create default endpoint id")
                }
            }
            Err(_) => {
                EndpointId::from_bytes(&[0u8; 32]).expect("Failed to create default endpoint id")
            }
        }
    }

    /// The **remote** node this pool dials: the configured `server_node_id`.
    ///
    /// Unlike [`Self::node_id`] this is a plain copy of the address the pool was
    /// built with, so it needs no lock, never returns a placeholder, and is
    /// stable across every pool in a group. Pool identity / deduplication must
    /// be based on this.
    pub fn backend_id(&self) -> EndpointId {
        self.inner.endpoint_addr.id
    }

    /// Configure client 2FA credentials. Connections established afterwards
    /// (including preconnect warm-ups) will run the 2FA handshake first.
    ///
    /// **A different identity drops the connections.** A connection is
    /// authenticated as whoever the handshake ran for, and the handshake runs
    /// once per connection — so a connection made under the old credential
    /// keeps serving traffic under the old identity after the credential has
    /// been replaced. The connections are closed when the identity changes.
    ///
    /// The same identity keeps them: a rotated secret is the same account
    /// with a different secret, and dropping the pool for that would close
    /// every connection in flight over a rotation that changes nothing about
    /// who they are.
    pub async fn set_two_factor(&self, auth: Option<TwoFactorAuth>) {
        self.set_credential(auth).await;
    }

    /// Writes the pool's credential, and closes the connections of the
    /// identity that is gone.
    ///
    /// Every write of the credential goes through here. A path that wrote it
    /// directly — the enrollment writes one of its own — would change the
    /// identity without the comparison, and the connections of the old
    /// identity would stay in the pool.
    async fn set_credential(&self, auth: Option<TwoFactorAuth>) {
        let mut slot = self.inner.two_factor.lock().await;
        let changed = identity_changed(slot.as_ref(), auth.as_ref());
        *slot = auth;
        // Released before the connections are touched: the lock order is
        // `connections` first, and nesting the two is what makes a pool that
        // dials while another task shuts it down deadlock-prone.
        drop(slot);

        if changed {
            // The connections were authenticated as the identity that is gone.
            self.drop_connections().await;
        }
    }

    /// Configure a one-time enrollment token instead of credentials: the next
    /// connection spends it and comes back with the real secret in
    /// [`Self::two_factor`].
    ///
    /// What the server issues has to be persisted by the caller — see
    /// [`Self::take_issued_credential`] — because a token can only be spent
    /// once, so a process that forgets the secret cannot enroll again from the
    /// same invite.
    pub async fn set_enrollment(&self, enrollment: Option<Enrollment>) {
        *self.inner.enrollment.lock().await = enrollment;
    }

    /// Takes the credential the server issued when an enrollment token was
    /// spent, and clears it.
    ///
    /// `None` when nothing has been enrolled yet — or when it has already been
    /// taken, which is the normal case: this is read once, after the first
    /// successful connection, by whatever keeps the app's settings.
    pub async fn take_issued_credential(&self) -> Option<IssuedCredential> {
        self.inner
            .issued
            .lock()
            .await
            .take()
            .map(|auth| IssuedCredential {
                client_id: auth.client_id().to_string(),
                secret: SecretString::new(auth.secret_base32()),
                algorithm: auth.algorithm_name().to_string(),
                public_key: auth.public_key_hex(),
                device: auth.device_id().map(str::to_string),
            })
    }

    /// The endpoint to dial from, cloned out of the mutex.
    ///
    /// A copy, not a guard: the QUIC handshake — and the 2FA stream that
    /// follows it — runs for up to [`CONNECTION_TIMEOUT`], and `close_all`
    /// needs the very same lock to close the endpoint. Holding the guard
    /// across the handshake made shutdown lose that race, and the loser is not
    /// the one you want: the JNI layer gives `close_all` eight seconds
    /// (`CLOSE_ALL_TIMEOUT` in `jni.rs`) and then moves on, so the endpoint
    /// stayed open for the rest of the process. `Endpoint` is a handle over
    /// shared state, so cloning costs nothing and still dials from the
    /// endpoint this pool was built with.
    async fn endpoint(&self) -> Option<Endpoint> {
        self.inner.ep.lock().await.clone()
    }

    /// Test-only: whether this pool has credentials configured.
    #[cfg(test)]
    pub(crate) async fn has_two_factor(&self) -> bool {
        self.inner.two_factor.lock().await.is_some()
    }

    /// Test-only: how many flows are riding each pooled connection.
    #[cfg(test)]
    pub(crate) async fn borrow_counts(&self) -> Vec<usize> {
        let connections = self.inner.connections.lock().await;
        connections
            .iter()
            .map(|pooled| pooled.state.borrow_count())
            .collect()
    }

    /// Takes the reason the backend last refused a connection for missing 2FA,
    /// and clears it.
    ///
    /// Only ever set after a preconnect that ended in [`AUTH_REQUIRED_CLOSE_CODE`],
    /// i.e. when the server wants credentials this client does not have.
    pub async fn take_auth_required(&self) -> Option<String> {
        self.inner.auth_required.lock().await.take()
    }

    /// Connect to the backend and run the 2FA handshake when configured.
    /// `timeout` is the budget for the QUIC handshake itself; see
    /// [`PRECONNECT_CONNECT_TIMEOUT`] for why a warm-up uses a tighter one than
    /// [`CONNECTION_TIMEOUT`].
    async fn connect_and_auth(
        &self,
        ep: &Endpoint,
        timeout: tokio::time::Duration,
    ) -> Result<Connection, ClientError> {
        let started = tokio::time::Instant::now();
        let conn = tokio::time::timeout(
            timeout,
            ep.connect(self.inner.endpoint_addr.clone(), ALPN_NEXAPIPE),
        )
        .await
        .map_err(|_| {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "connect to {} timed out after {}s (no QUIC handshake)",
                self.backend_id(),
                timeout.as_secs()
            );
            ClientError::TimeoutError
        })?
        .map_err(|e| {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "connect to {} failed after {:.1}s: {}",
                self.backend_id(),
                started.elapsed().as_secs_f32(),
                e
            );
            #[cfg(not(feature = "tracing"))]
            let _ = started;

            // A `[peers]` allow-list refuses inside the QUIC handshake, so the
            // only place its verdict shows up is the error from `connect`
            // itself — there is no connection left to ask. Turn it into the same
            // actionable sentence the 2FA refusals produce, instead of a bare
            // "connection lost".
            if let Some(reason) = peer_not_allowed_reason(&e) {
                return ClientError::AuthenticationFailed(reason);
            }
            ClientError::ConnectionFailed(e.to_string())
        })?;

        // Enrollment first: a token is spent once and buys the credentials the
        // block below then uses, so it only runs while there are none.
        let enrollment = self.inner.enrollment.lock().await.clone();
        if let Some(enrollment) = enrollment {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "Enrolling with a one-time token as client '{}'",
                enrollment.client_id()
            );
            match enrollment.exchange(&conn).await {
                Ok(issued) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        "Enrollment succeeded for client '{}'; the token is spent",
                        issued.client_id()
                    );
                    // The credential changes here, so it goes through the one
                    // place that writes it: the identity comparison and the
                    // drop of the connections of the identity that is gone
                    // have to happen with it.
                    self.set_credential(Some(issued.clone())).await;
                    *self.inner.enrollment.lock().await = None;
                    *self.inner.issued.lock().await = Some(issued);
                }
                Err(e) => {
                    conn.close(0u32.into(), b"2FA enrollment failed");
                    #[cfg(feature = "tracing")]
                    tracing::warn!("2FA enrollment failed: {}", e);
                    return Err(e);
                }
            }
        }

        let two_factor = self.inner.two_factor.lock().await.clone();
        if let Some(auth) = two_factor {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "Authenticating connection with 2FA as client '{}'",
                auth.client_id()
            );
            if let Err(e) = auth.authenticate(&conn).await {
                conn.close(0u32.into(), b"2FA authentication failed");
                #[cfg(feature = "tracing")]
                tracing::warn!("2FA authentication failed: {}", e);
                return Err(e);
            }
            #[cfg(feature = "tracing")]
            tracing::info!(
                "2FA authentication succeeded for client '{}'",
                auth.client_id()
            );
        }

        Ok(conn)
    }

    /// A connection to carry a flow on.
    ///
    /// **The connection stays in the pool.** A flow borrows a handle to it and
    /// gives it back by dropping the handle; the pool's own handle is what
    /// keeps it alive.
    ///
    /// That is the whole change, and it is small because iroh's `Connection`
    /// is a cheap clonable handle — *"May be cloned to obtain another handle
    /// to the same connection"* — so borrowing one costs a reference count
    /// and nothing else. Before this, a flow **took** the connection out of
    /// the pool and held it until the flow ended, so a hundred concurrent
    /// flows needed a hundred connections and each of them paid for a QUIC
    /// handshake. The transport is built for the opposite: one connection
    /// carries 1024 bi-streams.
    ///
    /// A dial is **shared**: everything that asks while one is in progress
    /// waits for that one rather than starting its own, so a hundred flows
    /// arriving together make one connection between them and not a hundred.
    ///
    /// A connection that is already carrying as many flows as it may is not
    /// handed out again: the pool opens another connection instead, so the
    /// server's own ceiling — the number of L4 flows it allows on one
    /// connection — is never the client's problem.
    pub async fn get_connection(&self) -> Result<BorrowedConnection, crate::error::ClientError> {
        loop {
            // A pooled connection with room for another flow is the cheap
            // answer, and it is the answer the whole change is about.
            if let Some(borrowed) = self.borrow_pooled().await {
                return Ok(borrowed);
            }

            // No connection has room: another one is needed. The dial is
            // shared, so a hundred flows arriving together make one
            // connection between them and not a hundred.
            let (conn, state) = self.dial_shared().await?;

            // The shared dial may have produced a connection that is already
            // full — a hundred flows can join one dial and fill it — so the
            // borrow is taken only if there is room for it, and the loop
            // dials again otherwise.
            if let Some(borrow) = state.try_borrow() {
                return Ok(BorrowedConnection { conn, borrow });
            }
        }
    }

    /// Borrows a pooled connection that has room for another flow.
    ///
    /// The connection with the **fewest** flows on it is the one handed out,
    /// so a hundred flows spread over the connections the pool has instead
    /// of piling onto the newest one.
    async fn borrow_pooled(&self) -> Option<BorrowedConnection> {
        let mut connections = self.inner.connections.lock().await;

        // Drop stale connections before handing one out: anything already
        // closed by the peer, or idle for longer than
        // CONNECTION_IDLE_TIMEOUT.
        drop_stale_connections(&mut connections);

        let pooled = connections
            .iter()
            .filter(|pooled| pooled.state.has_room())
            .min_by_key(|pooled| pooled.state.borrow_count())?;

        // The room was there a moment ago; another flow may have taken the
        // last seat in between, in which case this caller dials.
        let borrow = pooled.state.try_borrow()?;
        Some(BorrowedConnection {
            conn: pooled.conn.clone(),
            borrow,
        })
    }

    /// Dials the backend, sharing the dial with everything that asked for a
    /// connection while it was running.
    ///
    /// One dial, one result: the callers that were waiting when it finished
    /// get that result — the connection, or the failure. That matters most
    /// for the failure: a backend that is down would otherwise be dialled
    /// once per flow, and a hundred flows would spend a hundred dial
    /// timeouts on the same answer.
    async fn dial_shared(
        &self,
    ) -> Result<(Connection, Arc<BorrowState>), crate::error::ClientError> {
        loop {
            let (tx, rx) = watch::channel(None::<DialOutcome>);

            // Take the slot, or join the one that is there.
            let (tx, rx) = {
                let mut dialing = self.inner.dialing.lock().await;
                match dialing.as_ref() {
                    Some(joined) => {
                        // Someone else is dialling. Our sender goes away — so the
                        // channel closes if they do — and we wait on theirs.
                        drop(tx);
                        (None, joined.clone())
                    }
                    None => {
                        *dialing = Some(rx.clone());
                        (Some(tx), rx)
                    }
                }
            };

            // A copy of the receiver, for the cleanup below: the waiting arm
            // takes the original.
            let channel = rx.clone();

            let outcome = match tx {
                Some(tx) => {
                    // We are the dialer.
                    let outcome = self.dial().await;
                    let _ = tx.send(Some(outcome.clone()));
                    Some(outcome)
                }
                None => {
                    // Someone else is dialling: wait for their answer.
                    let mut rx = rx;
                    loop {
                        if let Some(outcome) = (*rx.borrow_and_update()).clone() {
                            break Some(outcome);
                        }
                        if rx.changed().await.is_err() {
                            // The dialer is gone: its channel closed without
                            // an answer. That is a dial that was cancelled —
                            // the proxy stopped, the task was aborted — and
                            // not a failure a dial produced.
                            break None;
                        }
                    }
                }
            };

            // The slot is cleared either way: on success the connection is in the
            // pool and the next caller borrows it, and on failure the next caller
            // tries again rather than being handed a failure that has already been
            // paid for. The callers that were waiting when it failed share that
            // failure — they are watching the same channel.
            self.clear_dial_slot(&channel).await;

            match outcome {
                Some(outcome) => return outcome,
                None => {
                    // The dial this caller was waiting for was cancelled. The
                    // slot is free again, so this caller dials instead of
                    // being handed a failure that no dial ever produced.
                    continue;
                }
            }
        }
    }

    /// Clears the shared-dial slot, if it still holds `channel`.
    ///
    /// The check matters: a slot that another dial has taken in the meantime
    /// belongs to that dial, and clearing it would let two dials run at once.
    async fn clear_dial_slot(&self, channel: &watch::Receiver<Option<DialOutcome>>) {
        let mut dialing = self.inner.dialing.lock().await;
        if let Some(current) = dialing.as_ref()
            && current.same_channel(channel)
        {
            *dialing = None;
        }
    }

    /// Dials the backend and puts the connection in the pool.
    async fn dial(&self) -> Result<(Connection, Arc<BorrowState>), crate::error::ClientError> {
        let ep = self.endpoint().await.ok_or_else(|| {
            crate::error::ClientError::InvalidConfig("Endpoint has been closed".to_string())
        })?;

        let conn = self.connect_and_auth(&ep, CONNECTION_TIMEOUT).await?;
        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone());

        let state = Arc::new(BorrowState::new());
        match self.pool_connection(conn.clone(), state.clone()).await {
            Ok(()) => Ok((conn, state)),
            // The pool is full, so the connection was closed on the spot.
            // Handing it out would be handing out a connection that is
            // already closed.
            Err(PoolRefusal::Full) => Err(ClientError::ConnectionFailed(
                "the connection pool is full".to_string(),
            )),
            Err(PoolRefusal::Closed) => Err(ClientError::ConnectionFailed(
                "the connection was closed as soon as it was established".to_string(),
            )),
        }
    }

    /// How traffic to this backend is currently routed, and how far away it is.
    ///
    /// A pooled connection is asked directly when there is one, because its path list is the
    /// truth right now; otherwise the last value the path watcher recorded is used. Without
    /// that fallback a UI polling while the pool holds no connection at all would read
    /// "unknown" and flap.
    pub async fn link_status(&self) -> LinkStatus {
        let connections = self.inner.connections.lock().await;
        for pooled in connections.iter().rev() {
            if pooled.is_live() {
                let status = LinkStatus::of(&pooled.conn);
                if status.kind != LinkKind::Unknown {
                    return status;
                }
            }
        }
        drop(connections);

        // The cached reading describes the connection it was recorded for: one
        // that has since died describes no path at all, and the UI would keep
        // showing a route to a backend it cannot reach.
        let cached = self.inner.link_status.lock().await;
        match &cached.conn {
            Some(conn) if conn.close_reason().is_none() => cached.status,
            _ => LinkStatus::default(),
        }
    }

    /// How traffic to this backend is currently routed, without the latency.
    ///
    /// The kind on its own, for the callers that only draw an icon.
    pub async fn link_kind(&self) -> LinkKind {
        self.link_status().await.kind
    }

    /// Ensure at least one live connection to the backend is cached in the
    /// pool, establishing one if the pool is empty. Used for pre-connect /
    /// warm-up so the first real request does not pay the QUIC/relay handshake
    /// latency. Returns true if a connection is available in the pool
    /// afterwards.
    pub async fn preconnect(&self) -> bool {
        {
            let connections = self.inner.connections.lock().await;
            if let Some(pooled) = connections.last()
                && pooled.is_live()
            {
                return true;
            }
        }

        // One deadline for the whole preconnect. The observation below is part
        // of it, not a wait that starts once the connect is over: a backend that
        // was merely slow used to be cancelled in the middle of that
        // observation and reported unreachable.
        let started = tokio::time::Instant::now();
        let deadline = started + PRECONNECT_TIMEOUT;

        let conn = {
            let Some(ep) = self.endpoint().await else {
                return false;
            };
            match tokio::time::timeout_at(
                deadline,
                self.connect_and_auth(&ep, PRECONNECT_CONNECT_TIMEOUT),
            )
            .await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("preconnect to {} failed: {}", self.backend_id(), e);
                    #[cfg(not(feature = "tracing"))]
                    let _ = &e;
                    return false;
                }
                Err(_) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("preconnect timed out");
                    return false;
                }
            }
        };

        // A client without credentials never opens the auth stream, so a
        // completed QUIC handshake tells it nothing: whether the connection can
        // ever carry traffic is the server's call, and it answers by closing
        // once its handshake deadline passes. Watch for that instead of
        // reporting a connection the server already refused as a warm one.
        if self.inner.two_factor.lock().await.is_none() {
            // Only what is left of the budget, so the observation is never what
            // pushes the preconnect past it. It still gets the whole grace
            // whenever the connect kept to its own, which is the case that has
            // to work.
            let grace =
                AUTH_REQUIRED_GRACE.min(PRECONNECT_TIMEOUT.saturating_sub(started.elapsed()));
            if let Some(reason) = wait_for_auth_required(&conn, grace).await {
                #[cfg(feature = "tracing")]
                tracing::warn!("preconnect refused by the server: {}", reason);
                #[cfg(not(feature = "tracing"))]
                let _ = &reason;
                *self.inner.auth_required.lock().await = Some(reason);
                return false;
            }
        }

        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone());
        self.pool_connection(conn, Arc::new(BorrowState::new()))
            .await
            .is_ok()
    }

    /// Puts a connection in the pool.
    ///
    /// Called when a connection is **established**, not when a flow ends: the
    /// pool keeps the connection and the flows borrow it, so there is nothing
    /// to give back at the end of a flow.
    ///
    /// Returns why the connection could not be pooled — it was already
    /// closed, or the pool is full. The caller has to know: handing out a
    /// connection that was closed on the spot is handing out a failure.
    async fn pool_connection(
        &self,
        conn: Connection,
        state: Arc<BorrowState>,
    ) -> Result<(), PoolRefusal> {
        // Never pool a connection that has already been closed: handing it out
        // again would just fail on the next request. The background watcher also
        // reaps such connections, but checking here avoids re-inserting them.
        if conn.close_reason().is_some() {
            return Err(PoolRefusal::Closed);
        }

        let mut connections = self.inner.connections.lock().await;
        if connections.len() < MAX_CONNECTIONS {
            connections.push(PooledConnection { conn, state });
            return Ok(());
        }

        // The pool is full, so this one is closed on the spot. Dropping the
        // handle would close it just as surely, but silently: the peer would
        // see a connection that vanished with no reason attached, which is
        // indistinguishable from a crash on this side.
        //
        // **Nothing is riding it**: a connection is pooled the moment it is
        // established, and the flows that borrow it are counted on its entry.
        // The pool holds one connection in practice — the second one only
        // arrives when the first is full or has died — so this is the tail of
        // a tail.
        #[cfg(feature = "tracing")]
        tracing::debug!(
            "Connection pool is full ({}), closing the connection that came back",
            MAX_CONNECTIONS
        );
        conn.close(0u32.into(), b"connection pool full");
        Err(PoolRefusal::Full)
    }

    pub async fn close_all(&self) {
        // Scoped, not held: `endpoint.close()` below is awaited, and keeping
        // `connections` across it would make every request wait on the
        // endpoint's goodbye.
        {
            let mut connections = self.inner.connections.lock().await;
            // Close before clearing: a connection that is only dropped stays
            // open, and the path watcher that still holds it keeps writing the
            // status of a connection this call says is gone — which undoes
            // the reset below within a second.
            for pooled in connections.iter() {
                pooled.conn.close(0u32.into(), b"pool closed");
            }
            connections.clear();
        }
        // Every connection is gone, so the last observed kind describes nothing any more.
        // Leaving it would let the UI keep showing "direct" for a backend it cannot reach.
        //
        // The generation moves with it, under the same lock: a watcher that
        // is about to publish takes this lock too, so the two cannot
        // interleave — a reading of a connection this call says is gone cannot
        // land after the reading was cleared.
        {
            let mut cached = self.inner.link_status.lock().await;
            self.inner.epoch.fetch_add(1, Ordering::AcqRel);
            *cached = CachedLinkStatus::default();
        }

        // Only close the endpoint if this pool owns it (created via `new()`).
        // Pools created via `new_with_endpoint()` share a caller-owned endpoint
        // (e.g. the global ENDPOINT in the Android JNI layer); closing it here
        // would break the next `nativeStartProxy`/`nativePreconnect` with
        // "Endpoint is closed" and tear down a running tunnel on reconnect.
        if !self.inner.owns_endpoint {
            return;
        }

        let mut ep = self.inner.ep.lock().await;
        if let Some(endpoint) = ep.take() {
            #[cfg(feature = "tracing")]
            tracing::info!("Closing iroh endpoint");
            endpoint.close().await;
        }
    }

    /// Closes and forgets every cached connection, leaving the endpoint alone.
    ///
    /// This is what a network switch needs. A connection opened on the previous network is
    /// *not* closed as far as QUIC is concerned — `close_reason()` stays `None` while its path
    /// is dead — so it would sit in the pool looking healthy and be handed to every request
    /// until QUIC gives up on it, which is long after the user has decided the backend is
    /// unreachable. Dropping them here makes the next request dial on the current network.
    ///
    /// Deliberately not [`Self::close_all`]: that also closes an endpoint the pool owns, and a
    /// pool that shares a caller-owned endpoint (the Android JNI shape) must keep it — closing
    /// it would tear down a running tunnel and break every later dial with "Endpoint is
    /// closed".
    pub async fn drop_connections(&self) {
        {
            let mut connections = self.inner.connections.lock().await;
            // Close before clearing: `close()` only marks the connection, so doing it while the
            // pool still owns them is what stops a concurrent `get_connection` from handing one
            // out in between.
            for pooled in connections.iter() {
                pooled.conn.close(0u32.into(), b"network changed");
            }
            connections.clear();
        }
        // Nothing is connected any more, so the last observed kind describes nothing.
        // Leaving it would let a UI keep showing "direct" for a backend it cannot reach.
        //
        // The generation moves with it, under the same lock: a watcher that is
        // about to publish takes this lock too, so the two cannot interleave —
        // a reading of the network that is gone cannot land after the reading
        // was cleared.
        {
            let mut cached = self.inner.link_status.lock().await;
            self.inner.epoch.fetch_add(1, Ordering::AcqRel);
            *cached = CachedLinkStatus::default();
        }
    }
}

/// Whether a credential change is a change of identity.
///
/// A connection is authenticated as whoever the handshake ran for, and the
/// handshake runs once per connection — so a connection made under the old
/// credential keeps serving traffic under the old identity after the
/// credential has been replaced. The connections are closed when the identity
/// changes.
///
/// A rotated secret is the same account with a different secret, and the
/// connections still stand for it: dropping the pool for that would close
/// every connection in flight over a rotation that changes nothing about who
/// they are.
///
/// Split out of [`IrohConnectionPool::set_two_factor`] so the decision can be
/// tested without an endpoint: a connection needs one, a rule does not.
fn identity_changed(before: Option<&TwoFactorAuth>, after: Option<&TwoFactorAuth>) -> bool {
    before.map(|a| a.identity()) != after.map(|a| a.identity())
}

/// Waits for a backend that demands 2FA to say so.
///
/// Returns the reason the server gave when it closes the connection with
/// [`AUTH_REQUIRED_CLOSE_CODE`], and `None` when the connection stays up — or
/// dies for any other reason, which is not what this is looking for.
/// `grace` is however much of the preconnect budget is left rather than
/// [`AUTH_REQUIRED_GRACE`] itself: the caller owns the deadline, so it decides
/// how much of it this wait may spend. Passing the full constant is only right
/// when the connect has kept to its own budget.
async fn wait_for_auth_required(conn: &Connection, grace: tokio::time::Duration) -> Option<String> {
    let closed = tokio::select! {
        _ = tokio::time::sleep(grace) => return None,
        error = conn.closed() => error,
    };

    match closed {
        iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == AUTH_REQUIRED_CLOSE_CODE as u64 =>
        {
            Some(String::from_utf8_lossy(&close.reason).into_owned())
        }
        _ => None,
    }
}

/// The text to show when the server's `[peers]` allow-list refused this Node ID.
///
/// Read off the `connect` failure rather than a connection, because the refusal
/// happens inside the QUIC handshake: `after_handshake` closes with
/// [`PEER_NOT_ALLOWED_CLOSE_CODE`] and the connection is never handed to the
/// client at all. iroh surfaces that as an `ApplicationClosed` carrying the
/// code, so matching on it here is the only place the client can learn why.
fn peer_not_allowed_reason(error: &iroh::endpoint::ConnectError) -> Option<String> {
    let iroh::endpoint::ConnectError::Connection { source, meta: _ } = error else {
        return None;
    };
    let iroh::endpoint::ConnectionError::ApplicationClosed(close) = source else {
        return None;
    };
    if close.error_code.into_inner() != PEER_NOT_ALLOWED_CLOSE_CODE as u64 {
        return None;
    }
    Some(String::from_utf8_lossy(&close.reason).into_owned())
}
/// Whether a watcher that started in `generation` may still publish.
///
/// The pool's generation moves when the network changes, and a watcher whose
/// generation is behind describes a network that is gone: the round trip it
/// would publish is the one of a path that no longer carries anything.
fn may_publish(current: u64, generation: u64) -> bool {
    current == generation
}

/// Watches one connection's paths and records which kind is carrying traffic.
///
/// The initial snapshot matters: right after the handshake iroh has already selected a path
/// (the relay one, usually) and only *later* promotes a direct one. Waiting for the first
/// event would leave the answer at [`LinkKind::Unknown`] for as long as the connection stays
/// on its first path — which, for a backend behind a symmetric NAT, is forever.
fn spawn_path_watcher(inner: Weak<IrohConnectionPoolInner>, conn: Connection) {
    let status = LinkStatus::of(&conn);
    // The generation this connection belongs to. A watcher that outlives its
    // generation has a reading that describes a network that is gone, so it
    // stops publishing when the generation moves.
    let generation = inner
        .upgrade()
        .map(|inner| inner.epoch.load(Ordering::Acquire))
        .unwrap_or_default();
    // `try_lock`, not `lock`: this runs on the caller's task, and a lock held elsewhere must
    // not stall a connection being handed out. Losing the race only costs one stale reading.
    if let Some(inner) = inner.upgrade()
        && let Ok(mut slot) = inner.link_status.try_lock()
    {
        *slot = CachedLinkStatus {
            conn: Some(conn.clone()),
            status,
        };
    }

    tokio::spawn(async move {
        let mut path_events = conn.path_events();
        // The round-trip time moves on its own: iroh re-estimates it from every
        // acknowledgement, and says nothing when it does. A path event is rare —
        // the connection may sit on one path for hours — so the latency is
        // refreshed on a tick instead, or the reading a user sees would be the
        // one the connection happened to have when it opened.
        let mut ticker = tokio::time::interval(RTT_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                event = path_events.next() => {
                    let Some(event) = event else {
                        break;
                    };
                    let iroh::endpoint::PathEvent::Selected { id, remote_addr, .. } = event else {
                        continue;
                    };

                    let kind = if remote_addr.is_ip() {
                        LinkKind::Direct
                    } else if remote_addr.is_relay() {
                        LinkKind::Relay
                    } else {
                        LinkKind::Unknown
                    };

                    let Some(inner) = inner.upgrade() else {
                        // Pool dropped; nobody is left to tell.
                        break;
                    };
                    // The pool moved to another network: this connection is
                    // from the one that is gone, and the reading it would
                    // publish is that network's — the round trip of a path
                    // that no longer carries anything. The connection is
                    // closed on the way out: the drop closes every
                    // connection the pool still holds, and this watcher is
                    // what closes the one it does not — a connection the
                    // pool has let go of must not stay open on the network
                    // that is gone. A closed connection is not pooled again.
                    //
                    // The check is under the lock the reading is written
                    // with, and the drop moves the generation under that
                    // same lock: so the two cannot interleave, and a reading
                    // of the network that is gone cannot land after the
                    // reading was cleared.
                    let mut cached = inner.link_status.lock().await;
                    if !may_publish(inner.epoch.load(Ordering::Acquire), generation) {
                        conn.close(0u32.into(), b"network changed");
                        break;
                    }
                    *cached = CachedLinkStatus {
                        conn: Some(conn.clone()),
                        status: LinkStatus {
                            kind,
                            // The round trip is read off the path the event
                            // named, not off whichever path is selected at the
                            // moment of the read: the two halves of a reading
                            // describe one path, and the selection can move
                            // between the event and the read.
                            //
                            // An unknown kind has no path to measure, which
                            // is how [`LinkStatus::of`] reads it too.
                            rtt: if kind == LinkKind::Unknown {
                                None
                            } else {
                                conn.rtt(id).and_then(measured_rtt)
                            },
                        },
                    };
                }
                _ = ticker.tick() => {
                    let Some(inner) = inner.upgrade() else {
                        // Pool dropped; nobody is left to tell.
                        break;
                    };
                    let status = LinkStatus::of(&conn);
                    if status.kind == LinkKind::Unknown {
                        continue;
                    }
                    // The pool moved to another network: this connection is
                    // from the one that is gone, and the reading it would
                    // publish is that network's — the round trip of a path
                    // that no longer carries anything. The connection is
                    // closed on the way out: the drop closes every
                    // connection the pool still holds, and this watcher is
                    // what closes the one it does not — a connection the
                    // pool has let go of must not stay open on the network
                    // that is gone. A closed connection is not pooled again.
                    //
                    // The check is under the lock the reading is written
                    // with, and the drop moves the generation under that
                    // same lock: so the two cannot interleave, and a reading
                    // of the network that is gone cannot land after the
                    // reading was cleared.
                    let mut cached = inner.link_status.lock().await;
                    if !may_publish(inner.epoch.load(Ordering::Acquire), generation) {
                        conn.close(0u32.into(), b"network changed");
                        break;
                    }
                    *cached = CachedLinkStatus {
                        conn: Some(conn.clone()),
                        status,
                    };
                }
            }
        }
    });
}

/// Spawn a background task that periodically drops closed connections from the
/// pool. It holds only a [`Weak`] reference so it exits once the pool itself is
/// dropped (e.g. on shutdown), and never keeps the pool alive on its own.
fn spawn_cleanup_task(inner: Weak<IrohConnectionPoolInner>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CONNECTION_CLEANUP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(inner) = inner.upgrade() else {
                // Pool dropped; nothing left to clean.
                break;
            };
            let mut connections = inner.connections.lock().await;
            let before = connections.len();
            // Idle as well as closed: `get_connection` already dropped stale
            // entries before handing one out, but nothing else ever ran, so a
            // pool that stopped being used kept its connections — and the
            // sockets, and the NAT mappings on both sides — until then.
            drop_stale_connections(&mut connections);
            let removed = before - connections.len();
            if removed > 0 {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    "Connection pool cleanup: removed {} closed connection(s)",
                    removed
                );
            }
        }
    });
}

pub fn parse_endpoint_addr(
    server_node_id: Option<&str>,
    server_ticket: Option<&str>,
) -> Result<EndpointAddr, crate::error::ClientError> {
    if let Some(node_id_str) = server_node_id {
        let endpoint_id: EndpointId = node_id_str.parse().map_err(|e| {
            crate::error::ClientError::ParseError(format!("Failed to parse server_node_id: {}", e))
        })?;
        Ok(endpoint_id.into())
    } else if let Some(ticket_str) = server_ticket {
        if let Ok(ticket) = ticket_str.parse::<EndpointTicket>() {
            Ok(ticket.into())
        } else {
            let endpoint_id: EndpointId = ticket_str.parse().map_err(|e| {
                crate::error::ClientError::ParseError(format!(
                    "Failed to parse as ticket or node ID: {}",
                    e
                ))
            })?;
            Ok(endpoint_id.into())
        }
    } else {
        Err(crate::error::ClientError::InvalidConfig(
            "Either server_node_id or server_ticket must be provided".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALPN_NEXAPIPE, BorrowState, CONNECTION_IDLE_TIMEOUT, DialOutcome, IrohConnectionPool,
        LinkKind, LinkStatus, MAX_FLOWS_PER_CONNECTION, encode_link_status, identity_changed,
        is_idle_since, is_measured_rtt, may_publish,
    };
    use crate::auth::{Enrollment, TotpAlgorithm, TwoFactorAuth};
    #[cfg(feature = "local-proxy")]
    use crate::endpoint_group::EndpointGroup;
    use iroh::Endpoint;
    use iroh::endpoint::presets;
    use nexapipe_proto::auth::{Algorithm, AuthMessage, Format};
    use nexapipe_proto::secret::SecretString;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::watch;

    /// The far side of a tunnel: answers the preface, and counts the
    /// connections it is given.
    ///
    /// The count is the far side's own, so the number a test reads does not
    /// depend on anything the client says about itself.
    async fn serve_counting(endpoint: Endpoint, accepted: Arc<AtomicUsize>) {
        while let Some(incoming) = endpoint.accept().await {
            // A copy for the task: the counter is shared, the handle is not
            // moved out of the loop.
            let accepted = accepted.clone();
            tokio::spawn(async move {
                let Ok(accepting) = incoming.accept() else {
                    return;
                };
                let Ok(connection) = accepting.await else {
                    return;
                };
                accepted.fetch_add(1, Ordering::Relaxed);

                // One bi-stream per flow.
                loop {
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    tokio::spawn(async move {
                        // The preface: its length is known once the fourth
                        // byte has been read.
                        let mut header = [0u8; 4];
                        if recv.read_exact(&mut header).await.is_err() {
                            return;
                        }
                        let mut rest = vec![0u8; usize::from(header[3]) + 2];
                        if recv.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        // `Ok` — the flow is open.
                        if send.write_all(&[0x00]).await.is_err() {
                            return;
                        }
                        let mut sink = [0u8; 1];
                        let _ = recv.read(&mut sink).await;
                    });
                }
            });
        }
    }

    /// A pool over a loopback endpoint, and the count the far side keeps.
    async fn pool_harness() -> (IrohConnectionPool, Arc<AtomicUsize>) {
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN_NEXAPIPE.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the far side binds");
        let server_addr = server.addr();
        let accepted = Arc::new(AtomicUsize::new(0));
        tokio::spawn(serve_counting(server, accepted.clone()));

        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN_NEXAPIPE.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");
        let pool = IrohConnectionPool::new_with_endpoint(client, server_addr);

        (pool, accepted)
    }

    /// A backend that answers the authentication handshake, and issues a
    /// credential of its own.
    ///
    /// A connection is authenticated when it is made, so a test that wants a
    /// connection of a given identity needs a server that answers the
    /// handshake. This one checks nothing: it issues a challenge and says the
    /// credential is good. The credential it enrolls is one of another
    /// client, so an enrollment changes the identity of the pool.
    async fn auth_backend() -> Endpoint {
        let ep = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN_NEXAPIPE.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the far side binds");
        let server = ep.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let Ok(accepting) = incoming.accept() else {
                        return;
                    };
                    let Ok(conn) = accepting.await else {
                        return;
                    };
                    // One stream at a time: the enrollment and the handshake
                    // that follows it share one stream.
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        while let Some((message, format)) = read_auth_message(&mut recv).await {
                            match message {
                                AuthMessage::EnrollStart { client_id, .. } => {
                                    let issue = AuthMessage::EnrollIssue {
                                        client_id,
                                        secret: SecretString::new(
                                            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
                                        ),
                                        algorithm: Algorithm::Sha1,
                                        digits: 6,
                                        period: 30,
                                        device_id: None,
                                    };
                                    write_auth_message(&mut send, &issue, format).await;
                                }
                                AuthMessage::Start { .. } => {
                                    let challenge = AuthMessage::Challenge {
                                        nonce: vec![1, 2, 3, 4],
                                    };
                                    write_auth_message(&mut send, &challenge, format).await;
                                }
                                AuthMessage::Response { .. } => {
                                    write_auth_message(&mut send, &AuthMessage::Ok, format).await;
                                    break;
                                }
                                _ => break,
                            }
                        }
                    }
                });
            }
        });
        ep
    }

    /// Reads one length-prefixed authentication message.
    async fn read_auth_message(
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Option<(AuthMessage, Format)> {
        let mut len = [0u8; 4];
        recv.read_exact(&mut len).await.ok()?;
        let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
        recv.read_exact(&mut buf).await.ok()?;
        AuthMessage::from_payload(&buf).ok()
    }

    /// Writes one length-prefixed authentication message.
    async fn write_auth_message(
        send: &mut iroh::endpoint::SendStream,
        message: &AuthMessage,
        format: Format,
    ) {
        let bytes = message.to_payload(format).expect("the message serializes");
        send.write_all(&(bytes.len() as u32).to_le_bytes())
            .await
            .expect("the message is written");
        send.write_all(&bytes)
            .await
            .expect("the message is written");
    }

    /// A pool over a backend that answers the authentication handshake.
    async fn auth_pool_harness() -> IrohConnectionPool {
        let server = auth_backend().await;
        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN_NEXAPIPE.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");
        IrohConnectionPool::new_with_endpoint(client, server.addr())
    }

    /// Waits for a connection to be closed, and says whether it was.
    async fn wait_for_close(conn: &iroh::endpoint::Connection) -> bool {
        for _ in 0..50 {
            if conn.close_reason().is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// The credential an enrollment buys goes through the same check.
    ///
    /// The enrollment writes the pool's credential itself, and a write that
    /// skipped the check would change the identity without the pool hearing
    /// about it: the connections of the old identity would carry on as if
    /// nothing had happened.
    #[tokio::test]
    async fn an_enrollment_of_another_identity_closes_the_old_connections() {
        let pool = auth_pool_harness().await;
        pool.set_two_factor(Some(credential(
            "client-001",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            None,
        )))
        .await;

        // A connection of client-001.
        let conn = pool.get_connection().await.expect("the connection is made");

        // The enrollment is only spent on a **new** connection, and the pool
        // hands out the one it has as long as it has room on it. Filling the
        // connection is what makes the next request dial — and the connection
        // it dials is the one that spends the token.
        {
            let connections = pool.inner.connections.lock().await;
            for pooled in connections.iter() {
                pooled
                    .state
                    .borrows
                    .store(MAX_FLOWS_PER_CONNECTION, Ordering::Release);
            }
        }

        // The next dial spends the enrollment token, and the credential it
        // buys belongs to another client.
        pool.set_enrollment(Some(Enrollment::new("client-002", "enrollment-token")))
            .await;
        let next = pool
            .get_connection()
            .await
            .expect("the enrollment connection is made");

        assert_ne!(
            next.conn.stable_id(),
            conn.conn.stable_id(),
            "the enrollment opened a connection of its own"
        );
        assert!(
            wait_for_close(&conn.conn).await,
            "the connection of the identity that is gone was not told the identity changed"
        );
    }

    /// The two ends of a tunnel, and the count the far side keeps.
    #[cfg(feature = "local-proxy")]
    async fn harness() -> (Arc<EndpointGroup>, Arc<AtomicUsize>) {
        let (pool, accepted) = pool_harness().await;
        let group = Arc::new(EndpointGroup::new_with_single_pool(pool).await);

        (group, accepted)
    }

    /// Two concurrent flows share one connection.
    ///
    /// A flow **borrows** a connection from the pool rather than taking it out
    /// of it, so two flows to one backend are one connection and not two. The
    /// far side counts what it is given, which is the number that matters: it
    /// is what the peer sees.
    #[cfg(feature = "local-proxy")]
    #[tokio::test]
    async fn two_concurrent_flows_share_one_connection() {
        let (group, accepted) = harness().await;

        let mut tasks = Vec::new();
        for _ in 0..2 {
            let group = group.clone();
            tasks.push(tokio::spawn(async move {
                crate::l4::open_tcp(&group, "db.test", 5432).await
            }));
        }
        let mut flows = Vec::new();
        for task in tasks {
            flows.push(
                task.await
                    .expect("the task is not cancelled")
                    .expect("the flow opens"),
            );
        }

        assert_eq!(
            accepted.load(Ordering::Relaxed),
            1,
            "two flows to one backend should share one connection"
        );

        // And the connection is still there for the next flow: the flows
        // borrowed it, they did not take it away.
        drop(flows);
        let next = crate::l4::open_tcp(&group, "db.test", 5432)
            .await
            .expect("the next flow opens");
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            1,
            "a flow that ended should not take the connection with it"
        );
        drop(next);
    }

    /// A borrow is given back when it ends — on the pool's own path too.
    ///
    /// The count is shared with the pool, so a caller that borrowed a
    /// connection and dropped it has to leave the count where it was: a
    /// connection nobody is riding may be closed as idle, and one that is
    /// ridden must not be. The count that never comes back down is what
    /// makes a connection look busy for the rest of its life.
    #[tokio::test]
    async fn a_borrow_is_given_back_when_it_ends() {
        let (pool, _accepted) = pool_harness().await;

        let borrowed = pool
            .get_connection()
            .await
            .expect("the connection is borrowed");
        assert_eq!(
            pool.borrow_counts().await,
            vec![1],
            "the borrow is counted while it is held"
        );

        drop(borrowed);
        assert_eq!(
            pool.borrow_counts().await,
            vec![0],
            "the borrow is given back when it ends"
        );
    }

    /// A connection that has just carried a flow is fresh, not stale.
    ///
    /// The idle timeout is about how long a connection has been sitting
    /// **unused**, and the moment it became unused is the moment the last
    /// flow ended — a moment only the borrower can see. A connection that
    /// carried a ten-minute flow and was stamped when it was handed out
    /// would look stale the instant the flow ended, and the next flow would
    /// pay for a fresh handshake.
    ///
    /// The clock is paused so that "a moment ago" and "ten minutes ago" are
    /// exact rather than approximate.
    #[tokio::test(start_paused = true)]
    async fn the_last_borrow_refreshes_the_last_use_stamp() {
        let state = Arc::new(BorrowState::new());
        let borrow = state
            .try_borrow()
            .expect("there is room for one borrow on a fresh connection");

        // Ten minutes of use: the connection is old, and the stamp says so.
        tokio::time::advance(Duration::from_secs(600)).await;
        assert!(
            state.is_idle_for(CONNECTION_IDLE_TIMEOUT),
            "the stamp is ten minutes old while the flow is running"
        );

        // The flow ends.
        drop(borrow);

        assert!(
            !state.is_idle_for(CONNECTION_IDLE_TIMEOUT),
            "a connection whose last flow just ended is fresh again"
        );
    }

    /// A connection that is full is not handed out again.
    ///
    /// The server counts the flows on a connection and refuses the one that
    /// does not fit, so a client that piles every flow onto one connection
    /// runs into a ceiling it cannot see. The pool opens another connection
    /// instead, and hands the flow that does not fit to it.
    #[tokio::test]
    async fn a_full_connection_is_not_handed_out_again() {
        let (pool, accepted) = pool_harness().await;

        let mut borrows = Vec::new();
        for _ in 0..MAX_FLOWS_PER_CONNECTION {
            borrows.push(
                pool.get_connection()
                    .await
                    .expect("the connection is borrowed"),
            );
        }
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            1,
            "the flows share one connection while it has room"
        );

        // The next one does not fit, so it gets a connection of its own.
        let next = pool
            .get_connection()
            .await
            .expect("the connection is borrowed");
        // Give the far side a moment to accept the second connection.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            2,
            "a connection that is full is not handed out again"
        );

        drop(next);
        drop(borrows);
    }

    /// A dial that was cancelled does not poison the next request.
    ///
    /// The shared dial lives in a slot, and a dialer that is dropped takes
    /// its channel with it: the slot is then holding a channel that nobody
    /// will ever answer. The next caller has to dial again rather than be
    /// handed a failure that no dial produced.
    #[tokio::test]
    async fn a_cancelled_dial_does_not_poison_the_next_request() {
        let (pool, _accepted) = pool_harness().await;

        // What a cancelled dial leaves behind: a slot holding a channel whose
        // sender is gone.
        {
            let (tx, rx) = watch::channel(None::<DialOutcome>);
            drop(tx);
            *pool.inner.dialing.lock().await = Some(rx);
        }

        // The next request dials again, and is served.
        let borrowed = pool
            .get_connection()
            .await
            .expect("the next request dials again");
        drop(borrowed);
    }

    /// A credential for `client_id`, optionally naming a device.
    fn credential(client_id: &str, secret: &str, device: Option<&str>) -> TwoFactorAuth {
        let auth = TwoFactorAuth::new(client_id, secret, TotpAlgorithm::SHA1)
            .expect("a valid base32 secret");
        match device {
            Some(device) => auth.with_device(device),
            None => auth,
        }
    }

    /// A different secret under the same name is the same account.
    ///
    /// A rotation changes the seed and nothing else, so the connections that
    /// were authenticated as that account still stand for it — and dropping
    /// the pool would close every request in flight over a rotation.
    #[test]
    fn a_rotated_secret_is_the_same_identity() {
        let before = credential("client-001", "JBSWY3DPEHPK3PXP", None);
        let after = credential("client-001", "KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP", None);

        assert!(!identity_changed(Some(&before), Some(&after)));
    }

    /// A different client is a different account, and the connections
    /// authenticated as the old one are not the new one's.
    #[test]
    fn a_different_client_is_a_different_identity() {
        let before = credential("client-001", "JBSWY3DPEHPK3PXP", None);
        let after = credential("client-002", "JBSWY3DPEHPK3PXP", None);

        assert!(identity_changed(Some(&before), Some(&after)));
    }

    /// A different device of the same client is a different credential, and a
    /// connection authenticated as one device is not the other's.
    #[test]
    fn a_different_device_is_a_different_identity() {
        let before = credential("client-001", "JBSWY3DPEHPK3PXP", Some("laptop"));
        let after = credential("client-001", "JBSWY3DPEHPK3PXP", Some("phone"));

        assert!(identity_changed(Some(&before), Some(&after)));
    }

    /// A named device and the client it belongs to are different identities:
    /// the named one answers with a secret of its own, the unnamed one with
    /// the client's.
    #[test]
    fn a_named_device_is_not_the_client_it_belongs_to() {
        let unnamed = credential("client-001", "JBSWY3DPEHPK3PXP", None);
        let named = credential("client-001", "JBSWY3DPEHPK3PXP", Some("laptop"));

        assert!(identity_changed(Some(&unnamed), Some(&named)));
    }

    /// Going from a credential to none, and from none to a credential, are
    /// both changes.
    #[test]
    fn dropping_or_adding_a_credential_is_a_change() {
        let auth = credential("client-001", "JBSWY3DPEHPK3PXP", None);

        assert!(identity_changed(Some(&auth), None));
        assert!(identity_changed(None, Some(&auth)));
        assert!(!identity_changed(None, None));
    }

    /// A connection is idle since it was last used, not since it was dialled.
    ///
    /// The clock is paused so that "a moment ago" and "61 seconds ago" are
    /// exact rather than approximate.
    #[tokio::test(start_paused = true)]
    async fn a_connection_is_idle_since_it_was_last_used() {
        let now = tokio::time::Instant::now();

        assert!(
            !is_idle_since(now, CONNECTION_IDLE_TIMEOUT),
            "a connection that was just handed back is not idle"
        );

        // Used for ten minutes, and handed back a second ago: the connection is
        // old, and it is not idle. The timeout measures how long the connection
        // has been sitting **unused**, not how old it is.
        let ten_minutes_of_use = tokio::time::Duration::from_secs(600);
        let handed_back_a_second_ago = now - tokio::time::Duration::from_secs(1);
        assert!(
            !is_idle_since(handed_back_a_second_ago, CONNECTION_IDLE_TIMEOUT),
            "a connection that was used for {ten_minutes_of_use:?} and handed back a second ago \
             is not idle"
        );

        assert!(
            is_idle_since(
                now - tokio::time::Duration::from_secs(61),
                CONNECTION_IDLE_TIMEOUT
            ),
            "a connection that has been sitting for longer than the timeout is idle"
        );
    }

    /// A watcher that started before the network changed must not publish: the
    /// reading it holds is the round trip of the network that is gone.
    #[test]
    fn a_watcher_from_an_older_generation_does_not_publish() {
        assert!(
            may_publish(3, 3),
            "the generation the watcher started in may publish"
        );
        assert!(
            !may_publish(4, 3),
            "a generation that moved on may not publish"
        );
    }

    /// quinn's estimator starts every path at the transport's initial RTT and
    /// replaces it once the path has something to say, so a path that was
    /// selected a moment ago reads as that guess. It is a number nobody
    /// measured, and the UI has to be able to say so.
    #[test]
    fn quinns_initial_guess_is_not_a_measurement() {
        // The guess itself is not a measurement.
        assert!(!is_measured_rtt(crate::transport::INITIAL_RTT));
        // A reading that differs from the guess is one.
        assert!(is_measured_rtt(Duration::from_millis(334)));
        assert!(is_measured_rtt(Duration::from_millis(20)));
    }

    /// The UI draws whole milliseconds: a reading that would be drawn as zero
    /// is not a number anybody made either.
    #[test]
    fn a_reading_below_a_millisecond_is_not_drawn_as_zero() {
        assert!(!is_measured_rtt(Duration::from_micros(0)));
        assert!(!is_measured_rtt(Duration::from_micros(999)));
        assert!(is_measured_rtt(Duration::from_millis(1)));
    }

    /// The name crosses the JNI and Tauri boundaries, so the two sides can only stay in sync
    /// if `as_str` and `parse` agree — and an unfamiliar spelling must degrade to `Unknown`
    /// rather than fail, because the value only ever feeds an icon.
    #[test]
    fn link_kind_name_round_trips() {
        for kind in [LinkKind::Direct, LinkKind::Relay, LinkKind::Unknown] {
            assert_eq!(LinkKind::parse(kind.as_str()), kind);
        }
        assert_eq!(LinkKind::parse(""), LinkKind::Unknown);
        assert_eq!(LinkKind::parse("hole-punched"), LinkKind::Unknown);
    }

    #[test]
    fn link_kind_serializes_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&LinkKind::Direct).unwrap(),
            "\"direct\""
        );
        assert_eq!(
            serde_json::to_string(&LinkKind::Relay).unwrap(),
            "\"relay\""
        );
        assert_eq!(
            serde_json::to_string(&LinkKind::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    /// A link with no path is nothing at all — not a direct link with no
    /// latency, which is what a caller would draw as "0 ms".
    #[test]
    fn a_link_with_no_path_has_neither_a_kind_nor_a_latency() {
        let status = LinkStatus::default();
        assert_eq!(status.kind, LinkKind::Unknown);
        assert_eq!(status.rtt, None);
    }

    /// The reading crosses the JNI boundary as `<id>=<kind>/<rtt>`, and the
    /// Kotlin side reads it back. The form is a contract between the two
    /// halves, so it is pinned here: the Kotlin decoder has its own tests,
    /// and a form only one side tests can drift apart without anything
    /// failing.
    #[test]
    fn a_link_reading_carries_the_kind_and_the_round_trip() {
        let id = iroh::SecretKey::generate().public();
        let status = LinkStatus {
            kind: LinkKind::Relay,
            rtt: Some(Duration::from_millis(15)),
        };

        assert_eq!(encode_link_status(&id, &status), format!("{}=relay/15", id));
    }

    /// A reading with no sample says so, rather than saying zero — a zero
    /// would be drawn as a round trip of no time at all.
    #[test]
    fn a_link_reading_without_a_sample_says_so() {
        let id = iroh::SecretKey::generate().public();
        let status = LinkStatus {
            kind: LinkKind::Direct,
            rtt: None,
        };

        assert_eq!(encode_link_status(&id, &status), format!("{}=direct/-", id));
    }
}
