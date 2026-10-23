use iroh::endpoint::presets;
use iroh::endpoint::{ConnectError, ConnectOptions, Connection};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, watch};
use tokio_stream::StreamExt;

#[cfg(feature = "tracing")]
use tracing;

use crate::ClientError;
use crate::auth::{Enrollment, IssuedCredential, TwoFactorAuth};
use nexapipe_proto::protocol::Protocol;

mod borrow;
mod link_status;

// The status of a link and the borrow of a connection are modules of their
// own, and what they hold is still reached through `connection_pool`.
pub use borrow::{Borrow, BorrowState, BorrowedConnection};
use link_status::measured_rtt;
pub use link_status::{LinkKind, LinkStatus, encode_link_status};
use nexapipe_proto::secret::SecretString;
use std::collections::HashMap;

// The ALPN this build speaks, and the one servers built before the prefix
// byte was dropped accept.
//
// The name used to carry a `0x05` prefix byte — the same byte the L4 preface
// starts with — in front of the name. That byte was never part of a length
// encoding; it made the protocol name a nine-byte string that began with a
// control byte, which is a fingerprint on the wire and nothing else. The name
// is now the name.
//
// The constants live in `nexapipe-proto`, which the server links too: the two
// ends have to agree on the name, and a name written down twice is a name
// that eventually differs.
#[cfg(test)]
use nexapipe_proto::ALPN_NEXAPIPE;
use nexapipe_proto::ALPN_NEXAPIPE_LEGACY;

/// The ALPNs this client offers the server.
///
/// **The protocol it wants first**, and the two names a server of another
/// vintage understands beside it: the generic one, which says "the first byte
/// of each stream decides", and the spelling that predates the prefix byte
/// being dropped.
///
/// The order of the *offer* does not decide anything — QUIC's negotiation
/// picks the first of the **accept side's** entries that the peer also
/// offers — so what matters is that the server's list has the per-protocol
/// names in front of the generic one, and that the client offers the one it
/// wants.
pub fn alpns(protocol: Protocol) -> Vec<Vec<u8>> {
    let mut list = vec![protocol.alpn().to_vec()];
    if protocol != Protocol::Legacy {
        list.push(Protocol::Legacy.alpn().to_vec());
    }
    list.push(ALPN_NEXAPIPE_LEGACY.to_vec());
    list
}

/// What a dial produced: the connection and the state its flows share, or
/// the failure that stopped it.
///
/// The state travels with the connection because the waiters for a shared
/// dial each borrow it — a hundred flows on one connection are a hundred
/// borrows, and the pool has to be able to say so.
type DialOutcome = Result<(Connection, Arc<BorrowState>), ClientError>;

/// A connection, and the credential generation it was authenticated under.
///
/// The generation is what says whether the connection still stands for the
/// pool's identity: a credential change moves it, and a connection of an
/// older generation was authenticated as an identity that is gone.
struct Authenticated {
    /// The connection itself.
    conn: Connection,
    /// The generation of the credential the handshake ran for.
    generation: u64,
}

/// How many connections the pool keeps **per protocol**.
///
/// A connection carries one protocol — the one it was opened with — so the
/// ceiling is counted per protocol: a protocol that needs a connection of its
/// own is not refused because another protocol's connections are sitting in the
/// pool. The pool therefore holds at most this many of each protocol, and at
/// most this many times the number of protocols in all.
///
/// It used to be one ceiling for the pool as a whole, which counted the
/// connections of one protocol against another's. A connection opened for HTTP
/// cannot carry an L4 flow, so it cannot stand in for one, and the protocol
/// that needed a connection was refused while the others' connections sat
/// idle.
///
/// Ten per protocol is the same headroom one protocol had before, and the pool
/// reaches the second connection only when the first is full or has died — so
/// this is the tail of a tail, per protocol.
const MAX_CONNECTIONS_PER_PROTOCOL: usize = 10;
const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Idle connections older than this are evicted when a new connection is requested.
const CONNECTION_IDLE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);
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
/// requires 2FA the client never performed.
///
/// The number lives in [`nexapipe_proto::auth::close_code`], which the server
/// links too.
const AUTH_REQUIRED_CLOSE_CODE: u32 = nexapipe_proto::auth::close_code::REQUIRED;

/// The application error code the server closes a connection with when a
/// `[peers]` allow-list refuses this Node ID. The number lives in
/// [`nexapipe_proto::auth::close_code`], which the server links too.
///
/// Reached from a different place than the 2FA codes: the server refuses inside
/// the QUIC handshake, so `connect` itself fails rather than a later stream. The
/// preconnect has to read the close reason from that failure to turn "connection
/// lost" into a cause the operator can act on.
const PEER_NOT_ALLOWED_CLOSE_CODE: u32 = nexapipe_proto::auth::close_code::PEER_NOT_ALLOWED;

/// How many of the pool's connections carry `protocol`.
///
/// The count is per protocol, because a connection carries exactly one: a
/// connection opened for HTTP cannot carry an L4 flow, so the two cannot take
/// each other's place.
fn connections_for(protocol: Protocol, held: impl Iterator<Item = Protocol>) -> usize {
    held.filter(|each| *each == protocol).count()
}

/// Whether the pool will take one more connection for `protocol`.
///
/// A protocol is refused when **its own** connections are at the ceiling, not
/// when the pool as a whole is: the connections of another protocol cannot
/// carry this one's flows, so they cannot stand in for it.
fn may_pool(protocol: Protocol, held: impl Iterator<Item = Protocol>) -> bool {
    connections_for(protocol, held) < MAX_CONNECTIONS_PER_PROTOCOL
}

/// Why a connection could not be put in the pool.
///
/// The three are different failures and they read differently: one is a
/// connection that was gone before it could be used, one is a pool with no
/// room left in it, and one is a connection that belongs to an identity the
/// operator has replaced.
enum PoolRefusal {
    /// The connection was already closed.
    Closed,
    /// The pool holds as many connections of this protocol as it may.
    Full,
    /// The credential was replaced while the connection was being made.
    ///
    /// The connection is authenticated as an identity that is gone, so it
    /// is closed rather than pooled — and the caller is told, because
    /// handing it out would hand out the old identity with it.
    Replaced,
}

struct PooledConnection {
    conn: Connection,
    /// What this connection carries.
    ///
    /// The protocol is chosen at the handshake, so a connection speaks one
    /// thing: a connection that carries HTTP cannot carry an L4 tunnel, and
    /// the pool keeps them apart for the same reason it keeps a connection
    /// per protocol apart in the first place.
    protocol: Protocol,
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
    /// One slot per protocol, because a dial for one protocol is not a dial
    /// for another: a connection carries one thing, and waiting for an HTTP
    /// dial to hand over an L4 connection would be waiting for the wrong
    /// answer.
    dialing: Mutex<HashMap<Protocol, watch::Receiver<Option<DialOutcome>>>>,
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
    /// Which generation of the credential the pool is on.
    ///
    /// Moved by [`IrohConnectionPool::set_credential`], and only when the
    /// **identity** changed: a rotated secret is the same account, and the
    /// connections that stand for it still stand for it.
    ///
    /// It is the answer to "which identity is this pool on?", and a dial
    /// takes it with the credential it authenticates: a connection whose
    /// generation has moved on was authenticated as an identity that is
    /// gone, and it is closed rather than pooled.
    ///
    /// It is not the network generation above, and it is not the same
    /// thing: a network change closes the connections of a path that is
    /// gone, while this says whose name is on the connection.
    credential_generation: AtomicU64,
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
            .alpns(alpns(Protocol::Legacy))
            .transport_config(transport)
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            dialing: Mutex::new(HashMap::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            enrollment: Mutex::new(None),
            issued: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: true,
            link_status: Mutex::new(CachedLinkStatus::default()),
            epoch: AtomicU64::new(0),
            credential_generation: AtomicU64::new(0),
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    pub fn new_with_endpoint(ep: Endpoint, endpoint_addr: EndpointAddr) -> Self {
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            dialing: Mutex::new(HashMap::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            enrollment: Mutex::new(None),
            issued: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: false,
            link_status: Mutex::new(CachedLinkStatus::default()),
            epoch: AtomicU64::new(0),
            credential_generation: AtomicU64::new(0),
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
    /// Every write of the credential goes through here. The enrollment
    /// writes a credential of its own — and it writes it **here**, so that
    /// the identity comparison, the move of the generation and the drop of
    /// the connections of the identity that is gone happen with it.
    async fn set_credential(&self, auth: Option<TwoFactorAuth>) {
        let mut slot = self.inner.two_factor.lock().await;
        let changed = identity_changed(slot.as_ref(), auth.as_ref());
        if changed {
            // **The identity moves with the credential.**
            //
            // A dial reads the generation when it takes the credential and
            // compares it before it pools the connection: a generation that
            // moved in between means the handshake ran for an identity that
            // is gone.
            //
            // The move happens here — under the lock the credential is
            // written under, and before the connections are dropped — so a
            // dial that reads the credential afterwards reads the new
            // generation with it, and a dial that read it before reads the
            // old one.
            self.inner
                .credential_generation
                .fetch_add(1, Ordering::AcqRel);
        }
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
    /// `Self::two_factor`.
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
    /// Only ever set after a preconnect that ended in `AUTH_REQUIRED_CLOSE_CODE`,
    /// i.e. when the server wants credentials this client does not have.
    pub async fn take_auth_required(&self) -> Option<String> {
        self.inner.auth_required.lock().await.take()
    }

    /// Connect to the backend and run the 2FA handshake when configured.
    /// `timeout` is the budget for the QUIC handshake itself; see
    /// [`PRECONNECT_CONNECT_TIMEOUT`] for why a warm-up uses a tighter one than
    /// [`CONNECTION_TIMEOUT`].
    ///
    /// The connection comes back with the generation of the credential it
    /// was authenticated under: the handshake takes as long as the server
    /// takes, and the credential may be replaced while it runs.
    async fn connect_and_auth(
        &self,
        ep: &Endpoint,
        timeout: tokio::time::Duration,
        protocol: Protocol,
    ) -> Result<Authenticated, ClientError> {
        let started = tokio::time::Instant::now();
        // **The protocol this connection is for, first**, and the two generic
        // names beside it: a server that does not know the per-protocol names
        // takes the generic one, which says "the first byte of each stream
        // decides", and a server built before the prefix byte was dropped
        // takes the older spelling.
        //
        // The order of the *offer* does not decide anything — QUIC's
        // negotiation picks the first of the **accept side's** entries that
        // the peer also offers — so what matters is that the server's list
        // has the per-protocol names in front of the generic one, and that
        // the client offers the one it wants.
        //
        // The address lookup and the handshake are both inside the timeout, the way
        // they were when `connect` did the whole thing; `connect_with_opts` splits
        // the two apart, so the block puts them back together.
        let conn = tokio::time::timeout(timeout, async {
            let connecting = ep
                .connect_with_opts(
                    self.inner.endpoint_addr.clone(),
                    protocol.alpn(),
                    ConnectOptions::new().with_additional_alpns(alpns(protocol)[1..].to_vec()),
                )
                .await
                .map_err(ConnectError::from)?;
            connecting.await.map_err(ConnectError::from)
        })
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

        // **What was negotiated**, which is not always what was asked for.
        //
        // A server that does not know the per-protocol names answers with the
        // generic one, and a server built before the prefix byte was dropped
        // answers with the older spelling. Both are served the way they always
        // were — the first byte of each stream decides — so the connection
        // works either way, and the bytes the client writes are the bytes the
        // sniff looks for. It is a real fallback, and an implicit one, so it is
        // worth saying out loud: a server that fell back is a server that is
        // still sniffing.
        if conn.alpn() != protocol.alpn() {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "the server negotiated {:?} rather than {}, and will decide by the first byte",
                String::from_utf8_lossy(conn.alpn()),
                protocol.name()
            );
        }

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

        // **The credential, and the generation it belongs to, together.**
        //
        // The generation is read under the lock the credential is read
        // under, so the two cannot be from different moments: a connection
        // is authenticated as the identity whose generation it carries, and
        // the pool can tell later whether that identity is still the one it
        // is on.
        let (two_factor, generation) = {
            let slot = self.inner.two_factor.lock().await;
            (
                slot.clone(),
                self.inner.credential_generation.load(Ordering::Acquire),
            )
        };
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

        Ok(Authenticated { conn, generation })
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
    pub async fn get_connection(
        &self,
        protocol: Protocol,
    ) -> Result<BorrowedConnection, crate::error::ClientError> {
        loop {
            // A pooled connection with room for another flow is the cheap
            // answer, and it is the answer the whole change is about.
            if let Some(borrowed) = self.borrow_pooled(protocol).await {
                return Ok(borrowed);
            }

            // No connection has room: another one is needed. The dial is
            // shared, so a hundred flows arriving together make one
            // connection between them and not a hundred.
            let (conn, state) = self.dial_shared(protocol).await?;

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
    async fn borrow_pooled(&self, protocol: Protocol) -> Option<BorrowedConnection> {
        let mut connections = self.inner.connections.lock().await;

        // Drop stale connections before handing one out: anything already
        // closed by the peer, or idle for longer than
        // CONNECTION_IDLE_TIMEOUT.
        drop_stale_connections(&mut connections);

        let pooled = connections
            .iter()
            // A connection carries one protocol: the one it was opened with.
            .filter(|pooled| pooled.protocol == protocol)
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
        protocol: Protocol,
    ) -> Result<(Connection, Arc<BorrowState>), crate::error::ClientError> {
        loop {
            let (tx, rx) = watch::channel(None::<DialOutcome>);

            // Take the slot for this protocol, or join the one that is there.
            let (tx, rx) = {
                let mut dialing = self.inner.dialing.lock().await;
                match dialing.get(&protocol) {
                    Some(joined) => {
                        // Someone else is dialling the same protocol. Our
                        // sender goes away — so the channel closes if they do
                        // — and we wait on theirs.
                        drop(tx);
                        (None, joined.clone())
                    }
                    None => {
                        dialing.insert(protocol, rx.clone());
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
                    let outcome = self.dial(protocol).await;
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
            self.clear_dial_slot(protocol, &channel).await;

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
    async fn clear_dial_slot(
        &self,
        protocol: Protocol,
        channel: &watch::Receiver<Option<DialOutcome>>,
    ) {
        let mut dialing = self.inner.dialing.lock().await;
        if let Some(current) = dialing.get(&protocol)
            && current.same_channel(channel)
        {
            dialing.remove(&protocol);
        }
    }

    /// Dials the backend and puts the connection in the pool.
    async fn dial(
        &self,
        protocol: Protocol,
    ) -> Result<(Connection, Arc<BorrowState>), crate::error::ClientError> {
        let ep = self.endpoint().await.ok_or_else(|| {
            crate::error::ClientError::InvalidConfig("Endpoint has been closed".to_string())
        })?;

        let authenticated = self
            .connect_and_auth(&ep, CONNECTION_TIMEOUT, protocol)
            .await?;
        let conn = authenticated.conn.clone();
        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone());

        let state = Arc::new(BorrowState::new());
        match self
            .pool_connection(
                conn.clone(),
                state.clone(),
                protocol,
                authenticated.generation,
            )
            .await
        {
            Ok(()) => Ok((conn, state)),
            // The pool is full, so the connection was closed on the spot.
            // Handing it out would be handing out a connection that is
            // already closed.
            Err(PoolRefusal::Full) => Err(ClientError::ConnectionFailed(
                "the connection pool is full for this protocol".to_string(),
            )),
            Err(PoolRefusal::Closed) => Err(ClientError::ConnectionFailed(
                "the connection was closed as soon as it was established".to_string(),
            )),
            // The credential was replaced while the handshake was running:
            // the connection is authenticated as an identity that is gone,
            // and it was closed rather than pooled.
            Err(PoolRefusal::Replaced) => Err(ClientError::ConnectionFailed(
                "the credential was replaced while the connection was being made".to_string(),
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

        let authenticated = {
            let Some(ep) = self.endpoint().await else {
                return false;
            };
            match tokio::time::timeout_at(
                deadline,
                self.connect_and_auth(&ep, PRECONNECT_CONNECT_TIMEOUT, Protocol::Http),
            )
            .await
            {
                Ok(Ok(authenticated)) => authenticated,
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
        let Authenticated { conn, generation } = authenticated;

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
        self.pool_connection(
            conn,
            Arc::new(BorrowState::new()),
            Protocol::Http,
            generation,
        )
        .await
        .is_ok()
    }

    /// Puts a connection in the pool.
    ///
    /// Called when a connection is **established**, not when a flow ends: the
    /// pool keeps the connection and the flows borrow it, so there is nothing
    /// to give back at the end of a flow.
    ///
    /// `generation` is the generation of the credential the connection was
    /// authenticated under, and it is what says whether the connection still
    /// stands for the pool's identity.
    ///
    /// Returns why the connection could not be pooled — it was already
    /// closed, the pool is full, or the credential it was authenticated
    /// under has been replaced. The caller has to know: handing out a
    /// connection that was closed on the spot is handing out a failure.
    async fn pool_connection(
        &self,
        conn: Connection,
        state: Arc<BorrowState>,
        protocol: Protocol,
        generation: u64,
    ) -> Result<(), PoolRefusal> {
        // Never pool a connection that has already been closed: handing it out
        // again would just fail on the next request. The background watcher also
        // reaps such connections, but checking here avoids re-inserting them.
        if conn.close_reason().is_some() {
            return Err(PoolRefusal::Closed);
        }

        let mut connections = self.inner.connections.lock().await;
        // **Whose identity is this connection?**
        //
        // The generation is compared under the lock that holds the pool, so
        // the comparison and the pooling are one step: a credential that is
        // replaced while the connection is on its way in cannot slip
        // between them.
        //
        // A connection of an older generation was authenticated as an
        // identity that is gone — the credential was replaced while its
        // handshake was running. It is closed rather than pooled: it would
        // carry traffic under an identity the operator has replaced, and
        // handing it out would hand that identity out with it.
        if self.inner.credential_generation.load(Ordering::Acquire) != generation {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "the credential to {} was replaced while the connection was being made; closing it",
                self.backend_id()
            );
            conn.close(0u32.into(), b"the credential was replaced");
            return Err(PoolRefusal::Replaced);
        }
        if may_pool(protocol, connections.iter().map(|pooled| pooled.protocol)) {
            connections.push(PooledConnection {
                conn,
                state,
                protocol,
            });
            return Ok(());
        }

        // This protocol's own connections are at the ceiling, so this one is
        // closed on the spot. Dropping the handle would close it just as
        // surely, but silently: the peer would see a connection that vanished
        // with no reason attached, which is indistinguishable from a crash on
        // this side.
        //
        // **Nothing is riding it**: a connection is pooled the moment it is
        // established, and the flows that borrow it are counted on its entry.
        // The pool holds one connection per protocol in practice — the second
        // one only arrives when the first is full or has died — so this is the
        // tail of a tail.
        #[cfg(feature = "tracing")]
        tracing::debug!(
            "Connection pool is full for {} ({} connections), closing the connection that came back",
            protocol.name(),
            MAX_CONNECTIONS_PER_PROTOCOL
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
mod tests;
