use crate::ClientError;
use crate::auth::{Enrollment, IssuedCredential, TwoFactorAuth};
use crate::connection_pool::{
    Borrow, IrohConnectionPool, LinkKind, LinkStatus, PRECONNECT_TIMEOUT,
};
use crate::flow::{FlowId, FlowMeta, FlowRegistry, FlowView};
use crate::lb::{LoadBalancer, LoadBalancingStrategy, RandomBalancer, RoundRobinBalancer};
use crate::traffic::{self, Flow, NodeTraffic, NodeVolume, TrafficTable};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use nexapipe_proto::protocol::Protocol;
use nexapipe_proto::{normalize_host, normalize_pattern};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

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

/// A connection the group handed out, and the borrow it was handed out under.
///
/// Not `Clone`: a copy would be a second handle on the **same** borrow, and
/// the pool's count of the flows on the connection would then be wrong —
/// the connection would look busy after the flow that held it was gone.
#[derive(Debug)]
pub struct PooledConnection {
    conn: Connection,
    pool_index: usize,
    /// The backend this connection reaches, when somebody is keeping health for
    /// it.
    ///
    /// `None` for a connection nobody is keeping health for, which is a pool
    /// standing on its own rather than one inside an [`EndpointGroup`].
    ///
    /// Carried by the connection so that the caller which spent its attempts on
    /// it can name whose health those attempts were about. Asking the group
    /// afterwards would be asking again, and by then it may have handed somebody
    /// else out; naming the backend at every failure path instead would mean
    /// every one of them knowing how health is recorded.
    node: Option<EndpointId>,
    /// Where to count what this connection carries. Also `None` for a pool
    /// standing on its own — the two are set together and absent together,
    /// because neither means anything about a node nobody is tracking.
    traffic: Option<Arc<NodeTraffic>>,
    /// Where the flows opened through this connection are listed. Set and absent
    /// together with `traffic`, for the same reason: neither means anything about
    /// a node nobody is tracking, and a flow that is counted but not listed is a
    /// list with a hole in it.
    flows: Option<Arc<FlowRegistry>>,
    /// The borrow this connection is held under.
    ///
    /// The pool owns the connection and the flows **borrow** it, so the pool
    /// cannot tell from the handle alone whether anyone is still on it — and
    /// it has to: a connection with a flow on it is not idle, and closing it
    /// would take that flow down with it.
    ///
    /// `None` for a connection that was not borrowed from a pool.
    borrow: Option<Borrow>,
}

impl PooledConnection {
    pub fn new(conn: Connection, pool_index: usize) -> Self {
        Self {
            conn,
            pool_index,
            node: None,
            traffic: None,
            flows: None,
            borrow: None,
        }
    }

    /// A connection whose volume and backend the group keeps track of.
    pub(crate) fn tracked(
        conn: Connection,
        pool_index: usize,
        node: EndpointId,
        traffic: TrafficTable,
        flows: Arc<FlowRegistry>,
        borrow: Borrow,
    ) -> Self {
        Self {
            conn,
            pool_index,
            node: Some(node),
            traffic: Some(traffic::of(&traffic, node)),
            flows: Some(flows),
            borrow: Some(borrow),
        }
    }

    /// Counts `bytes` leaving this machine towards the node this connection
    /// reaches.
    ///
    /// Nothing happens when nothing is being tracked: a pool standing on its
    /// own has no node to charge, and a copy loop should not need to know
    /// whether it is inside a group to count correctly. This is the one call a
    /// copy site makes, and it cannot be pointed at the wrong place: the
    /// connection decided where its bytes go.
    pub fn record_sent(&self, bytes: u64) {
        if let Some(traffic) = &self.traffic {
            traffic.record_sent(bytes);
        }
    }

    /// Counts `bytes` arriving back from that node.
    pub fn record_received(&self, bytes: u64) {
        if let Some(traffic) = &self.traffic {
            traffic.record_received(bytes);
        }
    }

    /// Holds one flow through this connection open until the guard is dropped.
    ///
    /// `meta` is what the caller knows about the flow and this connection does
    /// not: which door the bytes came in by, and — having read the client's
    /// request far enough to know — where they are going. It is read once here
    /// and never again, which is why it is not something the copy loop carries.
    ///
    /// The guard is why this returns a value at all: a flow ends on EOF, on any
    /// of several errors, on being cancelled because the proxy stopped, and on
    /// being asked to end, and only `Drop` covers all of them. See [`Flow`].
    ///
    /// A flow on a connection nobody is tracking is still returned, and still
    /// counts itself out on drop — the caller cannot tell, and does not have to:
    /// recording through a guard with nothing behind it already does nothing,
    /// exactly as [`Self::record_sent`] does for an untracked connection.
    pub fn enter_flow(&self, meta: FlowMeta) -> Flow {
        match (&self.traffic, &self.flows, self.node) {
            (Some(traffic), Some(flows), Some(node)) => {
                Flow::listed(traffic.clone(), flows, node, meta)
            }
            _ => Flow::open(self.traffic.clone().unwrap_or_default()),
        }
    }

    /// The node this connection reaches, when somebody is tracking it.
    pub fn node(&self) -> Option<EndpointId> {
        self.node
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Closes the connection instead of just letting go of it.
    ///
    /// Dropping one handle does not close a connection: it closes when the
    /// last one goes, and a path watcher holds one for as long as it lives, so
    /// a caller that has decided the connection is dead has to say so or it
    /// stays open — still in the pool's address space, still counted, and
    /// still handed to whatever asks next.
    ///
    /// Says nothing about the backend's health, and that is the point. Most of
    /// what reaches here is a connection the peer closed while nothing was
    /// using it — the ordinary case these retry loops exist for, and one that
    /// says nothing about whether the backend itself answers. Condemning it
    /// here would take a healthy backend out of rotation for as long as the
    /// next probe is away, and on the paths with no probe at all, permanently.
    /// The failure worth recording is the one no attempt outlived: see
    /// [`EndpointGroup::record_request_failures`].
    pub fn discard(self, reason: &'static [u8]) {
        self.conn.close(0u32.into(), reason);
    }

    /// Marks the connection as carrying as many flows as the server allows.
    ///
    /// The server refused a flow with `TooManyFlows`, which says something
    /// about the connection rather than about the flow: the pool must stop
    /// handing this connection out, or the next flow is refused the same way.
    pub fn saturate(&self) {
        if let Some(borrow) = &self.borrow {
            borrow.saturate();
        }
    }

    pub fn pool_index(&self) -> usize {
        self.pool_index
    }
}

/// Folds one answer, or one failure, into the health table, logging the changes.
///
/// Two callers, one fact: the background probe asks every backend whether it
/// still answers, and a request that could not be served after spending every
/// attempt it had says the same thing
/// about the same backend. Keeping them in one place is what stops
/// `health_snapshot()` from having two meanings of "down".
///
/// Not reachable from a connection: the two callers are the probe task and the
/// retry loop that ran out of attempts, and both already hold the group.
fn record_outcome(
    health: &Mutex<HashMap<EndpointId, NodeHealth>>,
    backend_id: EndpointId,
    answered: bool,
) {
    let mut health = health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = health.entry(backend_id).or_insert(NodeHealth {
        node: backend_id,
        // Not "unknown": a backend that has not been probed has not answered,
        // and the caller asking is about to be told so.
        reachable: false,
        consecutive_failures: 0,
        last_ok: None,
        last_probe: None,
    });

    let was_reachable = entry.reachable;
    entry.last_probe = Some(Instant::now());

    if answered {
        entry.consecutive_failures = 0;
        entry.last_ok = Some(Instant::now());
        entry.reachable = true;
        if !was_reachable {
            jni_log!("[health] Node {} answers again", backend_id);
            #[cfg(feature = "tracing")]
            tracing::info!("backend {} answers again", backend_id);
        }
        return;
    }

    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    entry.reachable = false;
    // The first failure is news. So is every tenth one — a backend that has
    // been down for an hour has failed a hundred times, and a log line per
    // failure would bury everything else.
    if was_reachable || entry.consecutive_failures % PROBE_REMINDER_EVERY == 1 {
        jni_log!(
            // Not "probes in a row": this counter also counts requests that got
            // nowhere, and calling those probes would make an operator looking
            // into one failed request go and read the probe instead.
            "[health] Node {} did not answer ({} failures in a row)",
            backend_id,
            entry.consecutive_failures
        );
        #[cfg(feature = "tracing")]
        tracing::warn!(
            "backend {} did not answer ({} failures in a row)",
            backend_id,
            entry.consecutive_failures
        );
    }
}

pub struct DomainPools {
    pools: Vec<Arc<IrohConnectionPool>>,
    balancer: Box<dyn LoadBalancer + Sync + Send>,
    /// What the probe last found, shared with the group rather than copied.
    ///
    /// One domain's pools are a subset of the group's backends, and the probe
    /// asks each backend once whoever serves it, so there is one table and
    /// every domain reads it.
    health: Arc<Mutex<HashMap<EndpointId, NodeHealth>>>,
    /// Same sharing, same reason: a backend is charged by whoever served it,
    /// so its counters live with the group and not with this domain.
    traffic: TrafficTable,
    /// Where the flows opened through these pools are listed. Shared with the
    /// group for the same reason the traffic table is: one backend's flows are
    /// one fact, and a domain is only ever a subset of the backends.
    flows: Arc<FlowRegistry>,
}

impl DomainPools {
    pub fn new(
        pools: Vec<Arc<IrohConnectionPool>>,
        strategy: LoadBalancingStrategy,
        health: Arc<Mutex<HashMap<EndpointId, NodeHealth>>>,
        traffic: TrafficTable,
        flows: Arc<FlowRegistry>,
    ) -> Self {
        let balancer: Box<dyn LoadBalancer + Sync + Send> = match strategy {
            LoadBalancingStrategy::RoundRobin => Box::new(RoundRobinBalancer::new()),
            LoadBalancingStrategy::Random => Box::new(RandomBalancer::new()),
        };
        Self {
            pools,
            balancer,
            health,
            traffic,
            flows,
        }
    }

    /// Which backends may be handed out: every one the health table does not
    /// say is down.
    ///
    /// A backend that has never been asked is included — "not asked" is not
    /// "not answering", and refusing on it would leave the group unusable for
    /// the interval before the first probe round and after every restart.
    fn candidates(&self) -> Vec<bool> {
        let health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.pools
            .iter()
            .map(|pool| {
                health
                    .get(&pool.backend_id())
                    .is_none_or(|node| node.reachable)
            })
            .collect()
    }

    /// Which pool serves the next request. Decided here, and only here, because
    /// every caller reaches a backend through this one method.
    ///
    /// A domain with several backends and nothing answering refuses without
    /// dialling: the answer is already known, and a connect timeout would only
    /// deliver this refusal late. A domain with one is handed out anyway —
    /// refusing the only backend there is buys nothing and turns every request
    /// into a failure, which is the rule the server already follows for the
    /// same case.
    fn choose(&self) -> Result<usize, ClientError> {
        if self.pools.is_empty() {
            return Err(ClientError::InvalidConfig(
                "No endpoint pools configured".to_string(),
            ));
        }

        let candidates = self.candidates();
        if let Some(index) = self.balancer.select(&candidates) {
            return Ok(index);
        }

        if self.pools.len() == 1 {
            return Ok(0);
        }

        Err(ClientError::ConnectionFailed(format!(
            "no backend is answering: {}",
            self.node_ids()
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    pub async fn get_connection(
        &self,
        protocol: Protocol,
    ) -> Result<PooledConnection, ClientError> {
        let index = self.choose()?;
        let pool = &self.pools[index];
        let backend_id = pool.backend_id();

        // Said here rather than left to the caller, because this is the only
        // place that knows which backend refused — the caller gets an error
        // without a name in it — and because nobody else says it: the retry
        // loops above only ever observe connections that were handed to them.
        //
        // A backend that cannot be dialled leaves no connection to discover
        // later, so without this line failure to reach one would never reach
        // the health table at all: another request would come along and spend a
        // full connect timeout on the same backend before trying a different
        // one, which is exactly the cost health-aware routing exists to avoid.
        //
        // Counting failure to connect, or to authenticate, as "down" reads as
        // harsh, and it is the same verdict the probe reaches: `preconnect`
        // connects and authenticates too, from the same pool, so nothing here
        // can mark a backend down that the next probe then marks back up.
        //
        // Not `InvalidConfig`, which is the only way this pool reports the
        // endpoint being gone: that is this process having let go of its own
        // side, which every pool says at once on shutdown and which is news
        // about nobody's backend. Calling it "down" would paint the whole node
        // list unreachable each time a tunnel stops.
        match pool.get_connection(protocol).await {
            Ok(borrowed) => Ok(PooledConnection::tracked(
                borrowed.conn,
                index,
                backend_id,
                self.traffic.clone(),
                self.flows.clone(),
                borrowed.borrow,
            )),
            Err(e @ ClientError::InvalidConfig(_)) => Err(e),
            Err(e) => {
                record_outcome(&self.health, backend_id, false);
                Err(e)
            }
        }
    }

    /// The backend node IDs this domain load-balances across (the configured
    /// `server_node_id`s), one per pool.
    pub fn node_ids(&self) -> Vec<EndpointId> {
        self.pools.iter().map(|p| p.backend_id()).collect()
    }
}

pub struct EndpointGroup {
    domains: HashMap<String, Arc<DomainPools>>,
    /// The domains that serve a name by **pattern**, keyed by the name the
    /// pattern covers: `*.example.com` is keyed by `example.com`, and the
    /// catch-all `*` by the empty string.
    ///
    /// An index rather than a scan. The lookup used to walk every configured
    /// domain and ask whether it covered the name, and for a name the
    /// configuration does not name exactly — which is every name a TUN device
    /// asks about — that walk happened on every request and every flow.
    ///
    /// A pattern covers a name when the name ends with the pattern's suffix
    /// **at a label boundary**, so the suffixes worth asking about are the
    /// name's own label-aligned ones: `a.b.example.com`, `b.example.com`,
    /// `example.com`, `com`. The walk below asks exactly those, and the
    /// longest one is the longest pattern that covers the name — the same
    /// answer the scan gave, without the scan.
    wildcards: HashMap<String, Arc<DomainPools>>,
    default_pools: Option<Arc<DomainPools>>,
    /// What the background probe last found, per backend.
    ///
    /// Behind a lock of its own rather than inside the pools because it is not
    /// connection state: a request that is handed a connection never reads it,
    /// and the only writer is the probe task. `std::sync` and not `tokio`: the
    /// critical section is a few map lookups, so there is nothing to yield on,
    /// and `health_snapshot()` then works off a runtime as well as on one.
    ///
    /// Shared rather than owned because the pools read it: which backend serves
    /// a request is decided per domain, and the domain's pools need the answer
    /// the probe wrote for that backend.
    health: Arc<Mutex<HashMap<EndpointId, NodeHealth>>>,
    /// What each backend has carried, and how many flows it carries right now.
    ///
    /// Its own table rather than fields on the pools for the same reason as the
    /// health one: this is not connection state, nothing serving a request reads
    /// it, and it has to outlive every connection. It also has to be readable
    /// from outside the request path entirely — a UI asking how much traffic is
    /// moving is not a request, and does not belong on their critical path.
    ///
    /// Shared rather than owned so a connection can carry the one entry it is
    /// meant to charge. See [`crate::traffic`].
    traffic: TrafficTable,
    /// The flows this group has open right now.
    ///
    /// Beside the traffic table rather than inside it because the two answer
    /// different questions at different depths: one counts bytes per backend,
    /// the other lists connections, and a reader wanting the list is not a
    /// reader wanting the totals. Shared so a connection can list the flows it
    /// opens. See [`crate::flow`].
    flows: Arc<FlowRegistry>,
    /// Set for good by [`Self::close_all`], and read by the probe before it
    /// dials anything.
    ///
    /// Not a shutdown signal for the *task* — the task ends when the group is
    /// dropped and its `Weak` stops upgrading — but for the work: `close_all()`
    /// drops the connections while the group itself is still alive, and a probe
    /// that then ran would dial them all again. That is the state a stopped
    /// tunnel would be left in: idle, and quietly reconnecting.
    probe_stopped: AtomicBool,
}

/// The wildcard patterns of a set of domains, keyed by the name they cover.
///
/// `*.example.com` is keyed by `example.com`, and the catch-all `*` by the
/// empty string. A pattern that is not a wildcard is left out: the lookup
/// finds an exactly-named domain in the map itself, and a pattern that is not
/// a wildcard cannot cover a name that map did not find.
///
/// A pattern that matches nothing is left out too — `*.` is the catch-all in
/// another spelling, and the rule in `nexapipe-proto` refuses it and matches
/// it with nothing. It must not be given the catch-all's own key, which is
/// what it would otherwise be indexed under.
fn wildcards_of(domains: &HashMap<String, Arc<DomainPools>>) -> HashMap<String, Arc<DomainPools>> {
    let mut wildcards = HashMap::new();
    for (pattern, pools) in domains {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // A pattern with an **empty** suffix — `*.` — is the catch-all in
            // another spelling, and the rule in `nexapipe-proto` refuses it
            // and matches it with nothing: a configuration that was never
            // meant to be loaded cannot widen what a client proxies.
            //
            // It is not a wildcard here either, so it is not indexed: the
            // catch-all is keyed by the empty name, and a pattern that
            // matches nothing must not be given that key — it would answer
            // for every host, and it would do so by whichever of the two the
            // map happened to be walked in first.
            if !suffix.is_empty() {
                wildcards.insert(suffix.to_string(), pools.clone());
            }
        } else if pattern == "*" {
            wildcards.insert(String::new(), pools.clone());
        }
    }
    wildcards
}

/// How often each backend is asked whether it still answers.
///
/// Under the pool's own idle timeout (60 s) on purpose. A pool that goes quiet
/// has its connections dropped, so the probe is also what keeps one warm to a
/// backend nobody has talked to for a minute; and it is what finds out a
/// backend died half a minute after it happened instead of at the next request,
/// which is the whole of what this buys.
const PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// How far the first probe (and every following one) may be pushed back.
///
/// Every client of one server that started at the same moment would otherwise
/// probe on the same second, which is a thundering herd for no reason — and
/// without it the probe also runs in lockstep with the pool's 5 s cleanup.
const PROBE_JITTER: Duration = Duration::from_secs(5);

/// Ceiling for a whole preconnect phase, across every pool at once.
///
/// [`PRECONNECT_TIMEOUT`] is what one pool may spend; this is what the phase
/// may. It has to stay above the former or a backend that used its full budget
/// is cut off here instead — counted unreachable for being slow, which is the
/// same confusion the per-pool budget exists to avoid. The slack is for
/// scheduling and for assembling the report, not for more dialling.
pub(crate) const PRECONNECT_PHASE_CAP: Duration =
    PRECONNECT_TIMEOUT.saturating_add(Duration::from_secs(2));

/// A persistently dead backend is reported once, then every this-many probes.
///
/// A backend that has been down for an hour has failed a hundred probes. Saying
/// so a hundred times buries everything else in the log; saying it once hides
/// the fact that it is still down.
const PROBE_REMINDER_EVERY: u32 = 10;

/// What the last probe of one backend found.
#[derive(Debug, Clone)]
pub struct NodeHealth {
    /// The backend this describes.
    pub node: EndpointId,
    /// Whether it answered the last time it was asked.
    pub reachable: bool,
    /// How many failures in a row it has had. Zero since the last success.
    ///
    /// Not only probes: a request that spent every attempt it had without being
    /// served counts too, and reaches this counter from the same place.
    pub consecutive_failures: u32,
    /// When it last answered — `None` when it never has.
    pub last_ok: Option<Instant>,
    /// When it was last asked — `None` before the first probe.
    pub last_probe: Option<Instant>,
}

impl NodeHealth {
    /// How long ago it last answered, if it ever has.
    ///
    /// "It has been down for twenty minutes" is the question a UI actually asks;
    /// a timestamp makes every caller do this subtraction and get the direction
    /// wrong at least once.
    pub fn down_for(&self) -> Option<Duration> {
        self.last_ok.map(|ok| ok.elapsed())
    }
}

/// Every backend's health at one moment, for a UI that polls.
#[derive(Debug, Clone, Default)]
pub struct HealthSnapshot {
    pub nodes: Vec<NodeHealth>,
}

impl HealthSnapshot {
    /// How many backends answered their last probe.
    pub fn reachable(&self) -> usize {
        self.nodes.iter().filter(|n| n.reachable).count()
    }

    /// Whether anything at all answered. False means the tunnel has nowhere to
    /// send anything.
    pub fn any_reachable(&self) -> bool {
        self.reachable() > 0
    }

    /// The backends that did not answer, as a comma-separated list.
    pub fn unreachable_ids(&self) -> String {
        self.nodes
            .iter()
            .filter(|n| !n.reachable)
            .map(|n| n.node.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Which configured backends answered a reachability probe.
///
/// Building an `EndpointGroup` never dials anything: a well-formed but
/// nonexistent `server_node_id` passes every setup call, and only an actual
/// connection attempt reveals that nothing is there. This report is that
/// attempt, per backend, so a caller can refuse to call a start "successful"
/// when it reached no backend at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreconnectReport {
    /// Backend nodes that accepted a connection.
    pub reachable: Vec<EndpointId>,
    /// Backend nodes that refused, were unreachable, or timed out.
    pub unreachable: Vec<EndpointId>,
    /// Backend nodes that answered the QUIC handshake and then refused the
    /// connection because this client has no 2FA credentials.
    ///
    /// A client without credentials cannot fail the 2FA handshake — it never
    /// starts one — so as far as QUIC is concerned these backends are up. They
    /// are listed here as well as in `unreachable`, so the caller can say *why*
    /// a backend that answered is not going to serve anything.
    pub auth_required: Vec<EndpointId>,
}

impl PreconnectReport {
    /// How many distinct backends were probed. Zero means none was configured.
    pub fn total(&self) -> usize {
        self.reachable.len() + self.unreachable.len()
    }

    /// True when at least one configured backend answered.
    pub fn any_reachable(&self) -> bool {
        !self.reachable.is_empty()
    }

    /// True when at least one backend demanded 2FA credentials this client does
    /// not have. Such a backend answers, then refuses to serve anything.
    pub fn any_auth_required(&self) -> bool {
        !self.auth_required.is_empty()
    }

    /// The unreachable backends as a comma-separated list, for error details.
    ///
    /// Empty when everything answered.
    pub fn unreachable_ids(&self) -> String {
        self.unreachable
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl EndpointGroup {
    /// Builds a group that binds its **own** iroh endpoints, one per distinct backend.
    ///
    /// Nothing in this workspace calls it: both UIs build the endpoint themselves (so it can
    /// carry the relay mode and the QUIC tuning) and pass it to
    /// [`Self::new_with_domain_mappings_and_endpoint`]. Prefer that one — an endpoint created
    /// inside here gets iroh's defaults, which means the preset's relay map, no auth token and
    /// a 1.25 MB stream window.
    pub async fn new_with_domain_mappings(
        domain_mappings: Vec<DomainMapping>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
    ) -> Result<Self, ClientError> {
        let mut pool_by_key: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_keys: HashMap<String, Vec<String>> = HashMap::new();

        jni_log!(
            "[DEBUG:endpoint-group] Creating EndpointGroup with {} domain mappings",
            domain_mappings.len()
        );
        for (i, mapping) in domain_mappings.iter().enumerate() {
            let key = mapping.key();
            let domain_key = normalize_pattern(&mapping.domain).into_owned();
            jni_log!(
                "[DEBUG:endpoint-group] Mapping {}: domain='{}', key='{}'",
                i,
                domain_key,
                key
            );

            if !pool_by_key.contains_key(&key) {
                let endpoint_addr = mapping.to_endpoint_addr()?;
                let pool = IrohConnectionPool::new(endpoint_addr).await?;
                pool_by_key.insert(key.clone(), Arc::new(pool));
                jni_log!(
                    "[DEBUG:endpoint-group] Created connection pool for key: {}",
                    key
                );
            }

            domain_to_keys
                .entry(domain_key.clone())
                .or_default()
                .push(key.clone());
            jni_log!(
                "[DEBUG:endpoint-group] Mapping domain '{}' to backend '{}'",
                domain_key,
                key
            );
        }

        // Built here and shared with every pool: the health table is one fact
        // per backend, not one per domain, so it cannot live inside a pool.
        let health = Arc::new(Mutex::new(HashMap::new()));
        let traffic = traffic::table();
        let flows = traffic::flow_registry();

        let mut domains = HashMap::new();
        for (domain, keys) in domain_to_keys {
            jni_log!(
                "[DEBUG:endpoint-group] Domain '{}' maps to backends: {:?}",
                domain,
                keys
            );
            let pools: Vec<Arc<IrohConnectionPool>> = keys
                .into_iter()
                .filter_map(|k| pool_by_key.get(&k).cloned())
                .collect();
            if !pools.is_empty() {
                let domain_pools = Arc::new(DomainPools::new(
                    pools,
                    default_strategy,
                    health.clone(),
                    traffic.clone(),
                    flows.clone(),
                ));
                domains.insert(domain.clone(), domain_pools);
                jni_log!(
                    "[DEBUG:endpoint-group] Created DomainPools for domain '{}'",
                    domain
                );
            }
        }

        jni_log!(
            "[DEBUG:endpoint-group] Final domain map: {:?}",
            domains.keys()
        );

        let default_pools = if let Some(addr) = default_endpoint_addr {
            let pool = IrohConnectionPool::new(addr).await?;
            Some(Arc::new(DomainPools::new(
                vec![Arc::new(pool)],
                default_strategy,
                health.clone(),
                traffic.clone(),
                flows.clone(),
            )))
        } else {
            None
        };

        let wildcards = wildcards_of(&domains);
        Ok(Self {
            domains,
            wildcards,
            default_pools,
            health,
            traffic,
            flows,
            probe_stopped: AtomicBool::new(false),
        })
    }

    pub async fn new_with_nodes_and_endpoint(
        nodes: Vec<NodeConfig>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
        ep: Endpoint,
    ) -> Result<Self, ClientError> {
        let domain_mappings: Vec<DomainMapping> = nodes
            .into_iter()
            .flat_map(|node| node.to_domain_mappings())
            .collect();

        Self::new_with_domain_mappings_and_endpoint(
            domain_mappings,
            default_endpoint_addr,
            default_strategy,
            ep,
        )
        .await
    }

    pub async fn new_with_domain_mappings_and_endpoint(
        domain_mappings: Vec<DomainMapping>,
        default_endpoint_addr: Option<EndpointAddr>,
        default_strategy: LoadBalancingStrategy,
        ep: Endpoint,
    ) -> Result<Self, ClientError> {
        let mut pool_by_key: HashMap<String, Arc<IrohConnectionPool>> = HashMap::new();
        let mut domain_to_keys: HashMap<String, Vec<String>> = HashMap::new();

        jni_log!(
            "[DEBUG:endpoint-group] Creating EndpointGroup (with endpoint) with {} domain mappings",
            domain_mappings.len()
        );
        for (i, mapping) in domain_mappings.iter().enumerate() {
            let key = mapping.key();
            let domain_key = normalize_pattern(&mapping.domain).into_owned();
            jni_log!(
                "[DEBUG:endpoint-group] Mapping {}: domain='{}', key='{}'",
                i,
                domain_key,
                key
            );

            if !pool_by_key.contains_key(&key) {
                let endpoint_addr = mapping.to_endpoint_addr()?;
                let pool = IrohConnectionPool::new_with_endpoint(ep.clone(), endpoint_addr);
                pool_by_key.insert(key.clone(), Arc::new(pool));
                jni_log!(
                    "[DEBUG:endpoint-group] Created connection pool for key: {}",
                    key
                );
            }

            domain_to_keys
                .entry(domain_key.clone())
                .or_default()
                .push(key.clone());
            jni_log!(
                "[DEBUG:endpoint-group] Mapping domain '{}' to backend '{}'",
                domain_key,
                key
            );
        }

        // Built here and shared with every pool: the health table is one fact
        // per backend, not one per domain, so it cannot live inside a pool.
        let health = Arc::new(Mutex::new(HashMap::new()));
        let traffic = traffic::table();
        let flows = traffic::flow_registry();

        let mut domains = HashMap::new();
        for (domain, keys) in domain_to_keys {
            jni_log!(
                "[DEBUG:endpoint-group] Domain '{}' maps to backends: {:?}",
                domain,
                keys
            );
            let pools: Vec<Arc<IrohConnectionPool>> = keys
                .into_iter()
                .filter_map(|k| pool_by_key.get(&k).cloned())
                .collect();
            if !pools.is_empty() {
                let domain_pools = Arc::new(DomainPools::new(
                    pools,
                    default_strategy,
                    health.clone(),
                    traffic.clone(),
                    flows.clone(),
                ));
                domains.insert(domain.clone(), domain_pools);
                jni_log!(
                    "[DEBUG:endpoint-group] Created DomainPools for domain '{}'",
                    domain
                );
            }
        }

        jni_log!(
            "[DEBUG:endpoint-group] Final domain map (with endpoint): {:?}",
            domains.keys()
        );

        let default_pools = if let Some(addr) = default_endpoint_addr {
            let pool = IrohConnectionPool::new_with_endpoint(ep, addr);
            Some(Arc::new(DomainPools::new(
                vec![Arc::new(pool)],
                default_strategy,
                health.clone(),
                traffic.clone(),
                flows.clone(),
            )))
        } else {
            None
        };

        let wildcards = wildcards_of(&domains);
        Ok(Self {
            domains,
            wildcards,
            default_pools,
            health,
            traffic,
            flows,
            probe_stopped: AtomicBool::new(false),
        })
    }

    pub async fn new_with_single_pool(conn_pool: IrohConnectionPool) -> Self {
        let health = Arc::new(Mutex::new(HashMap::new()));
        let traffic = traffic::table();
        let flows = traffic::flow_registry();
        let default_pools = Some(Arc::new(DomainPools::new(
            vec![Arc::new(conn_pool)],
            LoadBalancingStrategy::RoundRobin,
            health.clone(),
            traffic.clone(),
            flows.clone(),
        )));
        Self {
            domains: HashMap::new(),
            wildcards: HashMap::new(),
            default_pools,
            health,
            traffic,
            flows,
            probe_stopped: AtomicBool::new(false),
        }
    }

    /// Configure client 2FA credentials for one backend, leaving every other
    /// pool untouched.
    ///
    /// [`Self::set_two_factor`] writes the same value into every pool, which a
    /// client talking to several servers cannot use: each server has its own
    /// `[auth].clients` entry, and the one shared secret is the reason a second
    /// server either refuses the handshake or has to be given the first one's
    /// key. Credentials are keyed by the configured endpoint ID here, so a
    /// backend left out keeps none at all — and a backend with none never opens
    /// an auth stream, which is what makes a mixed setup (some servers with
    /// 2FA, some without) work.
    ///
    /// Safe to call any time before connections are established.
    pub async fn set_two_factor_for(&self, node_id: &str, auth: Option<TwoFactorAuth>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                if pool.backend_id().to_string() == node_id {
                    pool.set_two_factor(auth.clone()).await;
                }
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                if pool.backend_id().to_string() == node_id {
                    pool.set_two_factor(auth.clone()).await;
                }
            }
        }
    }

    /// Configure client 2FA credentials on every pool in this group.
    /// Safe to call any time before connections are established.
    pub async fn set_two_factor(&self, auth: Option<TwoFactorAuth>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                pool.set_two_factor(auth.clone()).await;
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                pool.set_two_factor(auth.clone()).await;
            }
        }
    }

    /// Configure a one-time enrollment token on every pool, and on one backend
    /// only — see [`Self::set_two_factor_for`] for why a group talking to
    /// several servers needs the per-backend form.
    pub async fn set_enrollment_for(&self, node_id: &str, enrollment: Option<Enrollment>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                if pool.backend_id().to_string() == node_id {
                    pool.set_enrollment(enrollment.clone()).await;
                }
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                if pool.backend_id().to_string() == node_id {
                    pool.set_enrollment(enrollment.clone()).await;
                }
            }
        }
    }

    /// Configure a one-time enrollment token on every pool in this group.
    pub async fn set_enrollment(&self, enrollment: Option<Enrollment>) {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                pool.set_enrollment(enrollment.clone()).await;
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                pool.set_enrollment(enrollment.clone()).await;
            }
        }
    }

    /// The credential the server issued for an enrollment token, from whichever
    /// pool has one, cleared once read.
    ///
    /// A group usually holds one backend per server and only one of them will
    /// have enrolled, so this returns the first it finds rather than a list —
    /// the caller knows which server it just enrolled against.
    pub async fn take_issued_credential(&self) -> Option<IssuedCredential> {
        for pools in self.domains.values() {
            for pool in &pools.pools {
                if let Some(issued) = pool.take_issued_credential().await {
                    return Some(issued);
                }
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                if let Some(issued) = pool.take_issued_credential().await {
                    return Some(issued);
                }
            }
        }
        None
    }

    /// The mapping that serves `host`, by the one rule the proxy uses.
    ///
    /// The same question the membership check asks, asked the same way: the
    /// client tunnels `www.example.com` because `*.example.com` covers it, and
    /// the backend it is sent to is named by that same list. A lookup that
    /// knew only exact names and parent labels would not find the
    /// `*.example.com` mapping at all — the request would go to the default
    /// backend or to none: the two halves of one client disagreeing about a
    /// pattern the configuration spells once.
    ///
    /// The exact name comes first, and a wildcard only after it: a bare
    /// pattern is that name and nothing else, so `example.com` never answers
    /// for `www.example.com`. Where more than one wildcard covers the host,
    /// the most specific one answers — the longest suffix, the way DNS reads
    /// a name.
    fn pools_for(&self, host: &str) -> Option<&Arc<DomainPools>> {
        let host = normalize_host(host);

        if let Some(pools) = self.domains.get(host.as_ref()) {
            return Some(pools);
        }

        // The name's **label-aligned** suffixes, longest first. A pattern
        // `*.example.com` covers the names that end with `example.com` at a
        // label boundary, and those are exactly the suffixes below — so the
        // first one that is in the index is the longest pattern that covers
        // the name, which is the answer the scan gave.
        let mut suffix = host.as_ref();
        while let Some((_, rest)) = suffix.split_once('.') {
            suffix = rest;
            if let Some(pools) = self.wildcards.get(suffix) {
                return Some(pools);
            }
        }
        // The catch-all, `*`, covers everything, and is keyed by nothing.
        self.wildcards.get("")
    }

    pub async fn get_connection(
        &self,
        domain: &str,
        protocol: Protocol,
    ) -> Result<PooledConnection, ClientError> {
        jni_log!(
            "[DEBUG:endpoint-group] Looking up connection for domain: '{}'",
            domain
        );

        if let Some(pools) = self.pools_for(domain) {
            jni_log!(
                "[DEBUG:endpoint-group] Found mapping for domain: '{}'",
                domain
            );
            return pools.get_connection(protocol).await;
        }

        if let Some(default) = &self.default_pools {
            jni_log!(
                "[DEBUG:endpoint-group] Using default pools for domain: '{}'",
                domain
            );
            return default.get_connection(protocol).await;
        }

        jni_log!(
            "[DEBUG:endpoint-group] No endpoint configured for domain: '{}'",
            domain
        );
        Err(ClientError::InvalidConfig(format!(
            "No endpoint configured for domain: {}",
            domain
        )))
    }

    /// Test iroh-level connectivity to each unique backend node, in parallel.
    ///
    /// Unlike the old sequential preconnect, this:
    /// - Deduplicates pools by *backend* node ID (same backend serving several
    ///   domains is tested once) — deliberately not by the pool's local endpoint
    ///   ID, which is identical for every pool when the group shares one
    ///   caller-owned endpoint, and would collapse all backends into a single
    ///   probe
    /// - Runs all connectivity tests in parallel via `JoinSet`
    /// - Applies a per-pool budget of `PRECONNECT_TIMEOUT`, which covers the
    ///   connect and the wait for a 2FA refusal together
    /// - Caps the whole phase at `PRECONNECT_PHASE_CAP`
    ///
    /// This ensures that a single unreachable backend node does not block the
    /// entire connection flow.
    ///
    /// Returns how many nodes answered. Call [`Self::preconnect_report`] when the
    /// caller also needs to name the ones that did not.
    pub async fn preconnect_all(&self) -> usize {
        self.preconnect_report().await.reachable.len()
    }

    /// Probe every unique backend node in parallel and report which answered.
    ///
    /// This is the availability check every entry point shares. Because no setup
    /// call ever dials, a config pointing at a node that does not exist looks
    /// perfectly valid until something connects; callers therefore treat
    /// [`PreconnectReport::any_reachable`] being false as a failed start rather
    /// than reporting a connection that was never established.
    pub async fn preconnect_report(&self) -> PreconnectReport {
        // Collect unique pools by backend node ID. Multiple domains pointing to
        // the same backend share a single connection pool, so we only need to
        // test each backend once.
        let unique_pools = self.unique_pools();
        let seen_nodes: Vec<EndpointId> = unique_pools.iter().map(|(id, _)| *id).collect();

        jni_log!(
            "[preconnect] Testing connectivity to {} unique node(s) in parallel",
            unique_pools.len()
        );

        let mut report = PreconnectReport::default();
        if unique_pools.is_empty() {
            return report;
        }

        // Run connectivity tests in parallel, each capped at PRECONNECT_TIMEOUT.
        let mut join_set = tokio::task::JoinSet::new();
        for (backend_id, pool) in &unique_pools {
            let backend_id = *backend_id;
            let pool = pool.clone();
            join_set.spawn(async move {
                let answered =
                    match tokio::time::timeout(PRECONNECT_TIMEOUT, pool.preconnect()).await {
                        Ok(true) => true,
                        Ok(false) => {
                            jni_log!("[preconnect] Node unreachable (preconnect returned false)");
                            // `jni_log` only reaches logcat; the desktop and the service need
                            // this in their own log — the pool's warning says why.
                            #[cfg(feature = "tracing")]
                            tracing::warn!("preconnect: node {} is unreachable", backend_id);
                            false
                        }
                        Err(_) => {
                            jni_log!(
                                "[preconnect] Node timed out after {}s",
                                PRECONNECT_TIMEOUT.as_secs()
                            );
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                "preconnect: node {} gave no answer within {}s",
                                backend_id,
                                PRECONNECT_TIMEOUT.as_secs()
                            );
                            false
                        }
                    };
                (backend_id, answered)
            });
        }

        // Overall cap: the per-pool budget plus a little slack, so a pool that
        // used its whole budget is still what decided the answer.
        let overall_deadline = tokio::time::Instant::now() + PRECONNECT_PHASE_CAP;
        let mut probed = 0usize;
        while let Ok(result) = tokio::time::timeout_at(overall_deadline, join_set.join_next()).await
        {
            match result {
                Some(Ok((backend_id, true))) => {
                    probed += 1;
                    report.reachable.push(backend_id);
                }
                Some(Ok((backend_id, false))) => {
                    probed += 1;
                    report.unreachable.push(backend_id);
                }
                Some(Err(_e)) => {
                    jni_log!("[preconnect] Task failed");
                }
                None => break, // JoinSet empty
            }
        }

        // A task the overall cap cut off never reported. Count it as unreachable:
        // a backend may only be called usable when it actually answered, and
        // `total()` must still equal the number of configured backends.
        if probed < seen_nodes.len() {
            let mut classified = report.reachable.clone();
            classified.extend(report.unreachable.iter().copied());
            let missing = seen_nodes
                .iter()
                .copied()
                .filter(|id| !classified.contains(id));
            report.unreachable.extend(missing);
        }

        // A backend that answered and then refused the connection leaves the
        // reason on its pool. Collect it so the caller can report "this server
        // wants 2FA" instead of an "unreachable" that hides the real cause.
        for (backend_id, pool) in &unique_pools {
            if let Some(reason) = pool.take_auth_required().await {
                jni_log!("[preconnect] Node {} requires 2FA: {}", backend_id, reason);
                report.auth_required.push(*backend_id);
            }
        }

        // What the probe would have recorded, written now: startup has just
        // dialled every backend, so the group knows which of them answer from
        // the first request instead of from the first probe round, which is up
        // to a whole interval later. A backend that answered the handshake and
        // then asked for 2FA counts as answering — it is reachable, and what it
        // wants is a credential, which is a different thing to go and fix.
        for backend_id in report.reachable.iter().chain(report.auth_required.iter()) {
            self.record_probe(*backend_id, true);
        }
        for backend_id in report
            .unreachable
            .iter()
            .filter(|id| !report.auth_required.contains(id))
        {
            self.record_probe(*backend_id, false);
        }

        jni_log!(
            "[preconnect] Connectivity test done: {}/{} node(s) reachable",
            report.reachable.len(),
            seen_nodes.len()
        );
        report
    }

    /// Starts the periodic health probe.
    ///
    /// One task per group, holding only a [`std::sync::Weak`] reference, so it
    /// ends when the group does — a stopped proxy is not kept alive by the
    /// thing that is watching it. Nothing else stops it; a group that outlives
    /// the probe simply stops being probed, which is the same state as before
    /// it started.
    ///
    /// Not started by the constructors: those return a bare `Self`, and the
    /// probe needs the `Arc` the caller is about to wrap it in. Every long-lived
    /// owner therefore has to call this once, right after building the group.
    pub fn start_health_probe(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            // A full interval before the first round, not the jitter alone.
            // Whoever starts the group probes it once at startup, and a round
            // that landed 0–5 s in would dial the same backends while that one
            // was still dialling them, so both would find the pool empty and
            // each would open a connection the other did not know about.
            let first = tokio::time::Instant::now()
                + PROBE_INTERVAL
                + Duration::from_millis(fastrand::u64(0..PROBE_JITTER.as_millis() as u64));
            let mut interval = tokio::time::interval_at(first, PROBE_INTERVAL);
            // A round that ran long (a backend timing out costs up to
            // PRECONNECT_TIMEOUT) must not queue up a burst of make-up rounds.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                let Some(group) = weak.upgrade() else {
                    break;
                };
                if group.probe_stopped.load(Ordering::SeqCst) {
                    break;
                }
                group.probe_round().await;
                // Dropped here, at the end of the iteration: the strong
                // reference must not survive into the sleep, or the group would
                // never be dropped and this loop never ends.
            }
        });
    }

    /// Asks every backend once, in parallel, and records what each answered.
    ///
    /// In parallel because a dead backend costs the whole probe timeout, and
    /// four of them would then take longer than the interval between rounds.
    async fn probe_round(&self) {
        if self.probe_stopped.load(Ordering::SeqCst) {
            return;
        }
        let mut probing = tokio::task::JoinSet::new();
        for (backend_id, pool) in self.unique_pools() {
            probing.spawn(async move {
                let answered =
                    match tokio::time::timeout(PRECONNECT_TIMEOUT, pool.preconnect()).await {
                        Ok(true) => true,
                        Ok(false) => false,
                        Err(_) => false,
                    };
                (backend_id, answered)
            });
        }
        while let Some(result) = probing.join_next().await {
            // Checked here as well as at the top: a round that is already
            // dialling when the group closes has to stop dialling, and letting
            // the set drop is what aborts the members still in flight.
            if self.probe_stopped.load(Ordering::SeqCst) {
                break;
            }
            if let Ok((backend_id, answered)) = result {
                self.record_probe(backend_id, answered);
            }
        }
    }

    /// Folds one probe result into the group's health.
    fn record_probe(&self, backend_id: EndpointId, answered: bool) {
        record_outcome(&self.health, backend_id, answered);
    }

    /// Says that a request spent every attempt it had on `backends` without
    /// being served by any of them.
    ///
    /// The counterpart to a probe: same table, same one meaning of "down", but
    /// the evidence is stronger, because somebody asked for real and waited.
    ///
    /// Takes the list rather than one backend so that a backend is counted once
    /// however many attempts landed on it: one request that failed is one
    /// failure, not three, and a counter someone reads has to mean one thing.
    ///
    /// Callers reach this through [`PooledConnection::node`] only once every
    /// attempt has failed — never per attempt. That boundary is what keeps an
    /// ordinary stale connection from taking its backend out of rotation: the
    /// retry loops exist precisely because the first attempt often draws a
    /// connection the peer closed while nothing was using it, and the second
    /// one usually succeeds.
    pub fn record_request_failures(&self, backends: &[EndpointId]) {
        let mut counted: Vec<EndpointId> = Vec::with_capacity(backends.len());
        for backend in backends.iter().copied() {
            if counted.contains(&backend) {
                continue;
            }
            record_outcome(&self.health, backend, false);
            counted.push(backend);
        }
    }

    /// Every backend's health as the last probe left it.
    ///
    /// Empty until the first probe has run, which is up to
    /// `PROBE_INTERVAL` plus `PROBE_JITTER` after [`Self::start_health_probe`].
    /// A caller that needs an answer before then wants
    /// [`Self::preconnect_report`], which probes on the spot.
    ///
    /// Sorted by node ID so a UI polling it does not see the entries change
    /// places between two polls.
    pub fn health_snapshot(&self) -> HealthSnapshot {
        let mut nodes: Vec<NodeHealth> = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect();
        nodes.sort_by_key(|n| n.node.to_string());
        HealthSnapshot { nodes }
    }

    /// What each backend has carried since this group was built, and how many
    /// flows are open to it right now.
    ///
    /// Keyed by node, and only contains nodes this group has served something
    /// through: a quiet node is absent rather than zero, which a caller showing
    /// per-node figures has to say rather than leave looking like "down".
    pub fn traffic_snapshot(&self) -> HashMap<EndpointId, NodeVolume> {
        traffic::snapshot(&self.traffic)
    }

    /// The flows this group has open right now, and how many there are in total.
    ///
    /// The count comes back alongside the list rather than being implied by it
    /// because the list is capped — a UI that says "200 of 1 431" is saying
    /// something true, and one that said "200" would be quietly lying about how
    /// busy the tunnel is.
    ///
    /// `limit` is the caller's, not the registry's: only a reader knows how many
    /// rows it can draw, and a fixed cap here would be a second opinion about
    /// somebody else's screen.
    pub fn flow_snapshot(&self, limit: usize) -> (usize, Vec<FlowView>) {
        (self.flows.len(), self.flows.view(limit))
    }

    /// Asks one flow to end.
    ///
    /// `false` when there is no open flow with that id, which covers both "no
    /// such flow" and "it ended while you were reading the list" — a UI polling
    /// every few seconds will sometimes click on a row that has already gone, and
    /// the honest answer is that nothing was asked rather than an error.
    ///
    /// Nothing is removed here. The flow lets go of its own sockets and then
    /// deregisters itself, so a list read immediately afterwards may still show
    /// it for a moment.
    pub fn close_flow(&self, id: FlowId) -> bool {
        self.flows.close(id)
    }

    /// Asks every flow reaching `node` to end, and drops the connections the
    /// pool was keeping for it.
    ///
    /// The connections as well as the flows, because they are not the same
    /// thing: a pool holds idle connections that no flow is using, and ending
    /// the flows while leaving those behind is how a backend that has gone bad
    /// keeps getting handed out. See [`IrohConnectionPool::drop_connections`].
    ///
    /// Returns how many flows were asked, which is the number a UI can show.
    ///
    /// The flows are asked first and the pool is dropped second, and the gap between the two is
    /// accepted rather than waited out: a flow that is still winding down has its connection
    /// checked out, so the drop does not reach it, and the one it hands back a moment later goes
    /// back into the pool. Waiting for every copy loop to notice it has been cancelled would mean
    /// putting a sleep in the middle of a click — and a connection that was carrying traffic a
    /// moment ago is not the stale one this is meant to clear.
    pub async fn close_node_flows(&self, node: &EndpointId) -> usize {
        let asked = self.flows.close_node(node);

        for (backend_id, pool) in self.unique_pools() {
            if &backend_id == node {
                pool.drop_connections().await;
            }
        }

        asked
    }

    /// How traffic is currently reaching each backend, and how far away it is.
    ///
    /// One entry per *distinct backend*, because that is what a link describes — two domains
    /// served by the same node share one connection pool and therefore one answer.
    ///
    /// A backend that has never connected reports [`LinkKind::Unknown`]; the caller decides
    /// whether that means "not connected yet" or "not connected at all". The round-trip time
    /// is `None` until iroh has a sample, which is not the same as zero.
    pub async fn link_statuses(&self) -> Vec<(EndpointId, LinkStatus)> {
        let mut statuses = Vec::new();
        for (backend_id, pool) in self.unique_pools() {
            statuses.push((backend_id, pool.link_status().await));
        }
        statuses
    }

    /// How traffic is currently reaching each backend: direct, or via a relay.
    ///
    /// The kind on its own, for the callers that only draw an icon.
    pub async fn link_kinds(&self) -> Vec<(EndpointId, LinkKind)> {
        self.link_statuses()
            .await
            .into_iter()
            .map(|(id, status)| (id, status.kind))
            .collect()
    }

    /// Closes and forgets every cached connection to every backend, keeping the endpoints.
    ///
    /// Called when the device switched networks: the tunnel itself stays up, but the
    /// connections inside it were opened on the old network and are dead while still looking
    /// open. See [`IrohConnectionPool::drop_connections`] for why they have to be closed
    /// explicitly instead of waiting for QUIC to notice.
    pub async fn drop_connections(&self) {
        let pools = self.unique_pools();
        for (backend_id, pool) in pools {
            pool.drop_connections().await;
            jni_log!(
                "[drop-connections] dropped cached connections to {}",
                backend_id
            );
        }
    }

    /// Every distinct backend in this group, with its pool.
    ///
    /// Deduplicated by *backend* node ID, not by the pool's local endpoint ID: when the group
    /// shares one caller-owned endpoint (the Android JNI shape) every pool reports the same
    /// local ID, and deduplicating on it would collapse all backends into one.
    fn unique_pools(&self) -> Vec<(EndpointId, Arc<IrohConnectionPool>)> {
        let mut seen: Vec<EndpointId> = Vec::new();
        let mut unique: Vec<(EndpointId, Arc<IrohConnectionPool>)> = Vec::new();

        for pool in self.all_pools() {
            let backend_id = pool.backend_id();
            if !seen.contains(&backend_id) {
                seen.push(backend_id);
                unique.push((backend_id, pool.clone()));
            }
        }
        unique
    }

    fn all_pools(&self) -> Vec<&Arc<IrohConnectionPool>> {
        self.domains
            .values()
            .flat_map(|dp| dp.pools.iter())
            .chain(
                self.default_pools
                    .as_ref()
                    .map(|dp| dp.pools.iter())
                    .into_iter()
                    .flatten(),
            )
            .collect()
    }

    /// The backend node IDs configured in this group (one per pool, deduplicated
    /// per domain). These are the servers traffic is dialed to, i.e. the
    /// `server_node_id`s from the client configuration.
    pub fn node_ids(&self) -> Vec<EndpointId> {
        let mut ids = Vec::new();
        for pools in self.domains.values() {
            ids.extend(pools.node_ids());
        }
        if let Some(default) = &self.default_pools {
            ids.extend(default.node_ids());
        }
        ids
    }

    pub async fn close_all(&self) {
        // Before the pools are cleared, not after: the probe reads this, and a
        // round that started before this line must not go on to dial what is
        // being closed underneath it.
        self.probe_stopped.store(true, Ordering::SeqCst);

        for pools in self.domains.values() {
            for pool in &pools.pools {
                pool.close_all().await;
            }
        }
        if let Some(default) = &self.default_pools {
            for pool in &default.pools {
                pool.close_all().await;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainMapping {
    pub domain: String,
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
}

impl DomainMapping {
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, ClientError> {
        crate::connection_pool::parse_endpoint_addr(
            self.server_node_id.as_deref(),
            self.server_ticket.as_deref(),
        )
    }

    pub fn key(&self) -> String {
        if let Some(id) = &self.server_node_id {
            format!("node_id:{}", id)
        } else if let Some(ticket) = &self.server_ticket {
            format!("ticket:{}", ticket)
        } else {
            "unknown".to_string()
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
    pub domains: Vec<String>,
}

impl NodeConfig {
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, ClientError> {
        crate::connection_pool::parse_endpoint_addr(
            self.server_node_id.as_deref(),
            self.server_ticket.as_deref(),
        )
    }

    pub fn key(&self) -> String {
        if let Some(id) = &self.server_node_id {
            format!("node_id:{}", id)
        } else if let Some(ticket) = &self.server_ticket {
            format!("ticket:{}", ticket)
        } else {
            "unknown".to_string()
        }
    }

    pub fn to_domain_mappings(&self) -> Vec<DomainMapping> {
        self.domains
            .iter()
            .map(|domain| DomainMapping {
                domain: domain.clone(),
                server_node_id: self.server_node_id.clone(),
                server_ticket: self.server_ticket.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TotpAlgorithm;
    use iroh::endpoint::presets;

    /// A syntactically valid backend node ID that no endpoint is bound to.
    fn unused_backend_id() -> EndpointId {
        iroh::SecretKey::generate()
            .public()
            .to_string()
            .parse()
            .expect("a generated public key is a valid node ID")
    }

    fn node(backend: EndpointId, domain: &str) -> NodeConfig {
        NodeConfig {
            server_node_id: Some(backend.to_string()),
            server_ticket: None,
            domains: vec![domain.to_string()],
        }
    }

    /// A set of pools with no backend in it, for a test that only asks what
    /// the index does with a pattern.
    fn empty_domain_pools() -> Arc<DomainPools> {
        Arc::new(DomainPools::new(
            Vec::new(),
            LoadBalancingStrategy::RoundRobin,
            Arc::new(Mutex::new(HashMap::new())),
            traffic::table(),
            traffic::flow_registry(),
        ))
    }

    /// Regression guard: the group must report the *configured* backend IDs.
    ///
    /// When every pool shares one caller-owned endpoint (the Android JNI shape),
    /// `IrohConnectionPool::node_id()` answers with the same local endpoint ID
    /// for all of them. Reporting that made `preconnect_all` dedupe every
    /// backend into a single probe, so only one of N nodes was ever checked and
    /// N-1 unreachable nodes went unnoticed.
    #[tokio::test]
    async fn node_ids_are_the_configured_backends_not_the_local_endpoint() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");

        let backend_a = unused_backend_id();
        let backend_b = unused_backend_id();
        assert_ne!(backend_a, backend_b);

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![
                node(backend_a, "a.example.com"),
                node(backend_b, "b.example.com"),
            ],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep.clone(),
        )
        .await
        .expect("a bogus but well-formed node ID must still build a group");

        let ids = group.node_ids();
        assert_eq!(ids.len(), 2, "both backends must be listed: {ids:?}");
        assert!(ids.contains(&backend_a), "{ids:?} is missing {backend_a}");
        assert!(ids.contains(&backend_b), "{ids:?} is missing {backend_b}");
        assert!(
            !ids.contains(&ep.id()),
            "the group reported its local endpoint ID {ids:?} instead of the backends"
        );
    }

    /// Two distinct backends behind two domains must stay two pools, so the
    /// dedup in `preconnect_all` probes each of them.
    #[tokio::test]
    async fn distinct_backends_stay_distinct_pools() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");

        let backend_a = unused_backend_id();
        let backend_b = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![
                node(backend_a, "a.example.com"),
                node(backend_b, "b.example.com"),
            ],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        // One pool per backend, and each domain load-balances over its own pool.
        for (domain, expected) in [("a.example.com", backend_a), ("b.example.com", backend_b)] {
            let pools = group
                .domains
                .get(domain)
                .expect("the domain must have a pool");
            assert_eq!(pools.pools.len(), 1, "{domain} should map to one pool");
            assert_eq!(pools.pools[0].backend_id(), expected);
        }
    }

    /// The backend a host is sent to, or `None` when the group has none for it.
    fn served_by(group: &EndpointGroup, host: &str) -> Option<EndpointId> {
        group
            .pools_for(host)
            .map(|pools| pools.pools[0].backend_id())
    }

    /// A wildcard mapping has to serve the names it covers.
    ///
    /// The client decides `www.example.com` belongs in the tunnel because
    /// `*.example.com` covers it, and the backend it is sent to is named by
    /// that same list. A lookup that knew only exact names would not find the
    /// wildcard mapping, and the request would go to the default backend or
    /// to none.
    #[tokio::test]
    async fn a_wildcard_mapping_serves_the_names_it_covers() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let backend = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![node(backend, "*.example.com")],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        assert_eq!(served_by(&group, "www.example.com"), Some(backend));
        assert_eq!(served_by(&group, "a.b.example.com"), Some(backend));
        // The apex is not under its own wildcard, the way DNS reads it.
        assert_eq!(served_by(&group, "example.com"), None);
    }

    /// A bare mapping is that name and nothing else.
    ///
    /// The lookup used to walk up the labels, so `example.com` answered for
    /// `www.example.com` as well. That is the rule the client used before the
    /// patterns were unified, and it is the rule the server never had.
    #[tokio::test]
    async fn a_bare_mapping_does_not_serve_a_subdomain() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let backend = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![node(backend, "example.com")],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        assert_eq!(served_by(&group, "example.com"), Some(backend));
        assert_eq!(served_by(&group, "www.example.com"), None);
    }

    /// A wildcard and the apex it sits next to are two mappings, and the
    /// wildcard is the one that serves the subdomain.
    ///
    /// The old lookup answered with the apex, because it walked up the labels
    /// — the request went to a backend that was not the one the pattern named.
    #[tokio::test]
    async fn a_wildcard_serves_the_subdomain_rather_than_the_apex() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let apex_backend = unused_backend_id();
        let wildcard_backend = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![
                node(apex_backend, "example.com"),
                node(wildcard_backend, "*.example.com"),
            ],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        assert_eq!(served_by(&group, "example.com"), Some(apex_backend));
        assert_eq!(served_by(&group, "www.example.com"), Some(wildcard_backend));
    }

    /// Where two wildcards cover the same name, the more specific one answers.
    #[tokio::test]
    async fn the_most_specific_wildcard_serves_the_name() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let broad_backend = unused_backend_id();
        let narrow_backend = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![
                node(broad_backend, "*.example.com"),
                node(narrow_backend, "*.www.example.com"),
            ],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        assert_eq!(served_by(&group, "a.example.com"), Some(broad_backend));
        assert_eq!(served_by(&group, "a.www.example.com"), Some(narrow_backend));
    }

    /// A pattern that matches nothing serves nothing.
    ///
    /// `*.` is the catch-all in another spelling, and the rule in
    /// `nexapipe-proto` refuses it and matches it with nothing: a
    /// configuration that was never meant to be loaded cannot widen what a
    /// client proxies. The client warns about the spelling rather than
    /// refusing the configuration, so the pattern does reach the lookup — and
    /// a lookup that keyed a pattern by the name it covers gave `*.` the
    /// catch-all's own key, because the name `*.` covers is the empty one.
    /// A client configured with `*.` alone would have served **every** host.
    #[tokio::test]
    async fn a_pattern_that_matches_nothing_serves_nothing() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let backend = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![node(backend, "*.")],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        assert_eq!(served_by(&group, "example.com"), None);
        assert_eq!(served_by(&group, "www.example.com"), None);
        assert_eq!(served_by(&group, "anything.test"), None);
    }

    /// The catch-all is the catch-all, whatever else is configured.
    ///
    /// The catch-all is filed under the empty name, and `*.` — a pattern that
    /// matches nothing — would have claimed that same key. Which of the two
    /// answered a name then depended on the order the map happened to be
    /// walked in, so the same configuration served different hosts from one
    /// run to the next.
    ///
    /// Each map below is built afresh, and each is walked in its own order,
    /// so the old answer shows itself in at least one of them.
    #[test]
    fn the_catch_alls_key_belongs_to_the_catch_all() {
        let catch_all = empty_domain_pools();
        let unusable = empty_domain_pools();

        for _ in 0..32 {
            let mut domains = HashMap::new();
            domains.insert("*".to_string(), catch_all.clone());
            domains.insert("*.".to_string(), unusable.clone());

            let wildcards = wildcards_of(&domains);
            let filed = wildcards
                .get("")
                .expect("the catch-all is filed under the empty name");
            assert!(
                Arc::ptr_eq(filed, &catch_all),
                "the catch-all's own key was given to a pattern that matches nothing"
            );
        }
    }

    /// The empty name is the catch-all's key, and the catch-all's alone.
    ///
    /// A pattern that matches nothing covers no name at all, so it is filed
    /// under no key — it is not the catch-all, whatever its spelling.
    #[test]
    fn a_pattern_that_matches_nothing_is_filed_under_no_key_at_all() {
        let unusable = empty_domain_pools();

        let mut domains = HashMap::new();
        domains.insert("*.".to_string(), unusable.clone());

        assert!(
            wildcards_of(&domains).is_empty(),
            "a pattern that matches nothing must not be indexed"
        );

        // And the catch-all itself is filed under the empty name.
        let mut domains = HashMap::new();
        domains.insert("*".to_string(), unusable.clone());
        assert!(
            wildcards_of(&domains).contains_key(""),
            "the catch-all is filed under the empty name"
        );
    }

    /// A name written the way DNS writes it — with the trailing dot — is the
    /// same name, and finds the same backend.
    #[tokio::test]
    async fn a_name_with_a_trailing_dot_finds_its_mapping() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let backend = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![node(backend, "example.com")],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        assert_eq!(served_by(&group, "example.com."), Some(backend));
        assert_eq!(served_by(&group, "EXAMPLE.com"), Some(backend));
    }

    /// The two answers have to be the same answer.
    ///
    /// Whether a name belongs in the tunnel and which backend serves it are
    /// two halves of one question, and the configuration spells the pattern
    /// once. A name the rule covers but the lookup cannot find is a name the
    /// client carries and the server has no route for — the failure this
    /// whole change is about.
    #[tokio::test]
    async fn the_backend_lookup_agrees_with_the_membership_rule() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let backend = unused_backend_id();
        let patterns = ["example.com", "*.wild.test"];

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            patterns
                .iter()
                .map(|pattern| node(backend, pattern))
                .collect(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        let patterns: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
        for host in [
            "example.com",
            "www.example.com",
            "a.wild.test",
            "wild.test",
            "notexample.com",
        ] {
            let proxied = crate::domains::should_proxy_domain(host, &patterns);
            let served = group.pools_for(host).is_some();
            assert_eq!(
                proxied, served,
                "{host}: the membership rule and the backend lookup disagree"
            );
        }
    }

    /// Credentials given for one backend must not reach any other.
    ///
    /// `set_two_factor` writes to every pool, so the only way a client can hold
    /// a different key per server is `set_two_factor_for`. If it ever leaks, a
    /// server that has no 2FA at all gets an auth stream it never asked for.
    #[tokio::test]
    async fn per_backend_two_factor_does_not_spill_to_other_backends() {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");

        let backend_a = unused_backend_id();
        let backend_b = unused_backend_id();

        let group = EndpointGroup::new_with_nodes_and_endpoint(
            vec![
                node(backend_a, "a.example.com"),
                node(backend_b, "b.example.com"),
            ],
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        let auth = TwoFactorAuth::new("client-a", "JBSWY3DPEHPK3PXP", TotpAlgorithm::SHA1)
            .expect("a Base32 secret must decode");
        group
            .set_two_factor_for(&backend_a.to_string(), Some(auth))
            .await;

        for (domain, expected) in [("a.example.com", true), ("b.example.com", false)] {
            let pools = group
                .domains
                .get(domain)
                .expect("the domain must have a pool");
            for pool in &pools.pools {
                assert_eq!(
                    pool.has_two_factor().await,
                    expected,
                    "{domain} (backend {}) should{} have credentials",
                    pool.backend_id(),
                    if expected { "" } else { " not" }
                );
            }
        }
    }

    /// A group with no backend must not look like a reachable one: the callers
    /// treat an empty report as a failed start, so `total()` has to be 0 rather
    /// than "all of nothing answered".
    #[tokio::test]
    async fn group_without_backends_reports_nothing_probed() {
        let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
        let group = EndpointGroup::new_with_nodes_and_endpoint(
            Vec::new(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .unwrap();

        let report = group.preconnect_report().await;
        assert_eq!(report.total(), 0);
        assert!(!report.any_reachable());
        assert_eq!(report.unreachable_ids(), "");
    }

    /// The report is what callers put in their error messages, so the summary
    /// must name exactly the backends that failed and nothing else.
    #[test]
    fn report_names_only_the_unreachable_backends() {
        let reached = unused_backend_id();
        let failed = unused_backend_id();

        let report = PreconnectReport {
            reachable: vec![reached],
            unreachable: vec![failed],
            auth_required: Vec::new(),
        };

        assert_eq!(report.total(), 2);
        assert!(report.any_reachable());
        assert!(!report.any_auth_required());
        assert_eq!(report.unreachable_ids(), failed.to_string());
        assert!(!report.unreachable_ids().contains(&reached.to_string()));

        let all_failed = PreconnectReport {
            reachable: Vec::new(),
            unreachable: vec![reached, failed],
            auth_required: Vec::new(),
        };
        assert!(!all_failed.any_reachable());
        assert_eq!(
            all_failed.unreachable_ids(),
            format!("{}, {}", reached, failed)
        );

        // A backend that answers the handshake and then refuses it for missing
        // 2FA is unreachable *and* named as such: the caller's error message
        // has to be able to say why.
        let needs_2fa = PreconnectReport {
            reachable: Vec::new(),
            unreachable: vec![failed],
            auth_required: vec![failed],
        };
        assert!(!needs_2fa.any_reachable());
        assert!(needs_2fa.any_auth_required());
    }

    /// A group with two backends, bound to a local endpoint. Nothing is dialled
    /// by building it, so the tests below decide what each "probe" found.
    async fn group_with(backends: &[EndpointId]) -> EndpointGroup {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        EndpointGroup::new_with_nodes_and_endpoint(
            backends
                .iter()
                .enumerate()
                .map(|(i, id)| node(*id, &format!("backend{i}.example.com")))
                .collect(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .expect("a bogus but well-formed node ID must still build a group")
    }

    /// The snapshot is empty — not "everything is up" — before the first probe:
    /// a caller reading it must not conclude the tunnel is healthy because
    /// nothing has been asked yet.
    #[tokio::test]
    async fn nothing_has_been_probed_yet_is_not_the_same_as_healthy() {
        let backend = unused_backend_id();
        let group = group_with(&[backend]).await;

        let snapshot = group.health_snapshot();
        assert!(snapshot.nodes.is_empty(), "{snapshot:?}");
        assert!(!snapshot.any_reachable(), "{snapshot:?}");
    }

    #[tokio::test]
    async fn one_down_backend_does_not_hide_the_one_that_answers() {
        let up = unused_backend_id();
        let down = unused_backend_id();
        let group = group_with(&[up, down]).await;

        group.record_probe(up, true);
        group.record_probe(down, false);

        let snapshot = group.health_snapshot();
        assert_eq!(snapshot.nodes.len(), 2, "{snapshot:?}");
        assert_eq!(snapshot.reachable(), 1, "{snapshot:?}");
        assert!(snapshot.any_reachable(), "{snapshot:?}");
        assert_eq!(snapshot.unreachable_ids(), down.to_string());

        let up = snapshot
            .nodes
            .iter()
            .find(|n| n.reachable)
            .expect("the answering backend");
        assert_eq!(up.consecutive_failures, 0);
        assert!(up.last_ok.is_some(), "it answered");
        assert!(up.down_for().is_some());

        let down = snapshot
            .nodes
            .iter()
            .find(|n| !n.reachable)
            .expect("the silent backend");
        assert_eq!(down.consecutive_failures, 1);
        assert!(down.last_ok.is_none(), "it never answered");
        assert!(down.down_for().is_none());
    }

    /// What an operator is told: "down for twenty minutes", not "down".
    #[tokio::test]
    async fn a_backend_that_comes_back_resets_its_failure_count() {
        let backend = unused_backend_id();
        let group = group_with(&[backend]).await;

        for _ in 0..3 {
            group.record_probe(backend, false);
        }
        let snapshot = group.health_snapshot();
        assert_eq!(snapshot.nodes[0].consecutive_failures, 3, "{snapshot:?}");
        assert!(!snapshot.any_reachable());

        group.record_probe(backend, true);

        let snapshot = group.health_snapshot();
        assert_eq!(snapshot.nodes[0].consecutive_failures, 0, "{snapshot:?}");
        assert!(snapshot.nodes[0].reachable);
        assert!(snapshot.nodes[0].down_for().is_some());
        assert!(snapshot.any_reachable());
    }

    /// The snapshot is what a UI polls, and entries that change places between
    /// two polls read as backends flapping.
    #[tokio::test]
    async fn the_snapshot_stays_in_one_order() {
        let first = unused_backend_id();
        let second = unused_backend_id();
        let group = group_with(&[second, first]).await;
        group.record_probe(first, true);
        group.record_probe(second, false);

        let ids: Vec<String> = group
            .health_snapshot()
            .nodes
            .iter()
            .map(|n| n.node.to_string())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "the entries are not in a stable order");
        assert_eq!(
            ids,
            group
                .health_snapshot()
                .nodes
                .iter()
                .map(|n| n.node.to_string())
                .collect::<Vec<_>>()
        );
    }

    /// Two backends behind one domain, which is the only shape in which there
    /// is anything to choose between.
    async fn shared_domain_group(backends: &[EndpointId]) -> EndpointGroup {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        EndpointGroup::new_with_nodes_and_endpoint(
            backends
                .iter()
                .map(|backend| node(*backend, "shared.example.com"))
                .collect(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .expect("a bogus but well-formed node ID must still build a group")
    }

    /// The point of probing: a backend that stopped answering stops being
    /// handed out, instead of being found dead by the request that needed it.
    #[tokio::test]
    async fn a_backend_the_probe_found_dead_stops_being_handed_out() {
        let up = unused_backend_id();
        let down = unused_backend_id();
        let group = shared_domain_group(&[up, down]).await;
        group.record_probe(up, true);
        group.record_probe(down, false);

        let pools = group
            .domains
            .get("shared.example.com")
            .expect("both backends serve it");
        assert_eq!(pools.pools.len(), 2, "the domain must see both backends");

        for _ in 0..4 {
            let index = pools.choose().expect("one backend answers");
            assert_eq!(
                pools.pools[index].backend_id(),
                up,
                "the backend that is down was handed out"
            );
        }
    }

    /// "Not asked" is not "not answering": a group that has not probed yet has
    /// to keep serving, or the tunnel would be dead for its first interval.
    #[tokio::test]
    async fn a_backend_that_has_never_been_probed_is_still_handed_out() {
        let group = shared_domain_group(&[unused_backend_id(), unused_backend_id()]).await;

        let pools = group
            .domains
            .get("shared.example.com")
            .expect("the domain must have pools");
        assert!(pools.choose().is_ok(), "nothing has said it is down yet");
    }

    /// The rule the server already follows: with several backends and none of
    /// them answering, refuse at once instead of spending a connect timeout on
    /// delivering the refusal late.
    #[tokio::test]
    async fn a_domain_with_nothing_answering_refuses_before_dialling() {
        let first = unused_backend_id();
        let second = unused_backend_id();
        let group = shared_domain_group(&[first, second]).await;
        group.record_probe(first, false);
        group.record_probe(second, false);

        let pools = group
            .domains
            .get("shared.example.com")
            .expect("the domain must have pools");
        let err = pools.choose().expect_err("nothing answers");
        assert!(err.to_string().contains("no backend is answering"), "{err}");
    }

    /// ...and the exception to it. With one backend there is nothing to choose
    /// between, so refusing would turn every request into a failure and buy
    /// nothing: hand it out and let the request fail loudly.
    #[tokio::test]
    async fn the_only_backend_is_handed_out_even_when_it_is_down() {
        let only = unused_backend_id();
        let group = shared_domain_group(&[only]).await;
        group.record_probe(only, false);

        let pools = group
            .domains
            .get("shared.example.com")
            .expect("the domain must have pools");
        assert_eq!(
            pools.choose().expect("there is nothing to choose between"),
            0
        );
    }

    /// The other half of the same change: a backend a request could not be
    /// served by — after every attempt was spent, not on the first connection
    /// that turned out stale — stops being handed out, while the one nothing
    /// happened to keeps answering.
    #[tokio::test]
    async fn a_request_that_spent_every_attempt_marks_its_backend_down() {
        let up = unused_backend_id();
        let down = unused_backend_id();
        let group = group_with(&[up, down]).await;
        group.record_probe(up, true);
        group.record_probe(down, true);

        group.record_request_failures(&[down]);

        let snapshot = group.health_snapshot();
        let down = snapshot
            .nodes
            .iter()
            .find(|node| node.node == down)
            .expect("it was probed");
        assert!(
            !down.reachable,
            "a request that failed is a backend that is down"
        );
        assert_eq!(down.consecutive_failures, 1);
        assert!(
            snapshot.any_reachable(),
            "the backend that was left alone still answers"
        );
    }

    /// The corollary, and the reason the recording moved out of
    /// [`PooledConnection::discard`]: nothing else got named, so nothing else
    /// changed. A group whose other backend was left alone keeps serving.
    #[tokio::test]
    async fn a_request_failure_leaves_the_other_backend_alone() {
        let up = unused_backend_id();
        let down = unused_backend_id();
        let group = group_with(&[up, down]).await;
        group.record_probe(up, true);
        group.record_probe(down, true);

        group.record_request_failures(&[down]);

        let snapshot = group.health_snapshot();
        let up = snapshot
            .nodes
            .iter()
            .find(|node| node.node == up)
            .expect("it was probed");
        assert!(up.reachable, "only the backend that failed is recorded");
        assert_eq!(up.consecutive_failures, 0);
    }

    /// The one failure `get_connection` can report that is not the backend's.
    ///
    /// Every other failure here means a backend was asked and did not answer,
    /// and so belongs in the health table. This one means there was nothing to
    /// ask with: our own endpoint is gone, which is what shutting a tunnel down
    /// does, and every pool says it at the same moment. Reading it as "the
    /// backend is down" would turn stopping a proxy into a node list where
    /// nothing answers — and restarting would inherit that list.
    #[tokio::test]
    async fn letting_go_of_our_own_endpoint_is_news_about_us() {
        let backend = unused_backend_id();
        // A pool that owns its endpoint, unlike every pool `group_with` builds:
        // ownership is what decides whether `close_all` takes it away. Nothing
        // is ever dialled — the endpoint is gone before anything could try.
        let pool =
            crate::connection_pool::IrohConnectionPool::new(iroh::EndpointAddr::new(backend))
                .await
                .expect("binding a local endpoint needs no network");
        let group = EndpointGroup::new_with_single_pool(pool).await;
        group.record_probe(backend, true);

        group.close_all().await;
        let outcome = group
            .get_connection("whatever.example", Protocol::Http)
            .await;

        assert!(
            outcome.is_err(),
            "there is no endpoint left to dial out from"
        );
        let snapshot = group.health_snapshot();
        let backend = snapshot.nodes.first().expect("it was probed");
        assert!(
            backend.reachable,
            "nothing said the backend stopped answering"
        );
        assert_eq!(backend.consecutive_failures, 0);
    }

    /// One request is one failure. An attempt that landed on the same backend
    /// three times must not grow a counter someone reads as "three things went
    /// wrong", or a number that looked stable would start moving with how the
    /// balancer happened to rotate.
    #[tokio::test]
    async fn repeating_a_backend_in_the_list_counts_it_once() {
        let only = unused_backend_id();
        let group = group_with(&[only]).await;
        group.record_probe(only, true);

        group.record_request_failures(&[only, only, only]);

        let snapshot = group.health_snapshot();
        let only = snapshot
            .nodes
            .iter()
            .find(|node| node.node == only)
            .expect("it was probed");
        assert_eq!(only.consecutive_failures, 1);
    }
}
