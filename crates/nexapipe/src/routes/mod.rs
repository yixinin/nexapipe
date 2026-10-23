use crate::auth::ClientAcl;
use crate::config::{BackendProtocol, CircuitBreaker, Retry, RouteMode, Timeouts};
use crate::lb::{BackendLease, BackendPool, LoadBalancingStrategy};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// The one host-matching rule, and the one place it lives.
//
// It is in `nexapipe-proto` rather than here because the client library links
// the same crate and has to answer the same question: the client decides
// which names it proxies, the server decides which names a route serves, and
// a name the two spell differently is a name the client tunnels and the
// server has no route for. The rule and the drift it replaced are written up
// in `nexapipe_proto::host`.
pub(crate) use nexapipe_proto::{host_matches, normalize_host, normalize_pattern, pattern_error};

/// The host a `Host` header names, with the port taken off.
///
/// `split(':')` is wrong for IPv6 twice over: `[::1]:8080` yields `[`, and a
/// bare `::1` yields the empty string. Either way the host matches no route
/// and every request to it 404s. A bracketed literal keeps its brackets here;
/// [`normalize_host`] drops them.
pub(crate) fn host_without_port(host: &str) -> &str {
    host_and_port(host).0
}

/// The host a `Host` header names, and the port it names if it names one.
///
/// The port is `None` when the header names none: the request did not say
/// which port it wanted, and the proxy routes by host alone, so there is no
/// port to hold against the client that asked.
///
/// Split off the same way [`host_without_port`] takes the port off, so the two
/// cannot disagree about where the host ends.
pub(crate) fn host_and_port(host: &str) -> (&str, Option<u16>) {
    // The rule lives in `nexapipe-proto`, which the client links too: the
    // server routes by what this says and the client decides whether to
    // tunnel by what this says, and the two cannot disagree about where the
    // host ends.
    nexapipe_proto::host_and_port(host)
}

/// The most a path is allowed to add to [`Route::priority`], so that length
/// breaks ties between two routes instead of deciding the winner outright.
const PATH_LENGTH_TIE_BREAK: u32 = 99;

/// The extra knobs only `tcp` / `udp` routes have.
///
/// Kept out of [`Route::new`] so that the many HTTP and passthrough call sites — and
/// their tests — do not have to name two fields they will never use.
#[derive(Debug, Clone, Default)]
pub struct L4Options {
    /// Client ports this route accepts. `None` accepts every port. Only a selector:
    /// it never changes the address that is dialled.
    pub client_ports: Option<Vec<u16>>,
    /// Silence after which a UDP flow is closed. `None` means the server default.
    pub idle_timeout: Option<Duration>,
    /// How long one flow may run before it is closed. `None` means the server
    /// default.
    ///
    /// Separate from `idle_timeout` because the two bound different things: the
    /// idle one is the *gap* between packets and re-arms on each one, which is
    /// what a UDP flow needs, while this one is the whole flow. A peer that
    /// sends one packet just before each idle expiry keeps a flow alive with the
    /// idle bound alone, so the flow is also bounded as a whole.
    ///
    /// Raise it for a long-lived session over the tunnel — an interactive SSH
    /// connection or a database session is meant to outlive any default here.
    pub flow_timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct Route {
    host_pattern: String,
    path_pattern: String,
    path_is_prefix: bool,
    /// Every mode this route serves, in declaration order.
    ///
    /// More than one is the ordinary case for a host that has to answer both a
    /// request and a tunnel: the same `backends` serve whichever of these the
    /// connection turned out to be. Which one a *connection* gets is still
    /// decided before matching, by its first byte.
    modes: Vec<RouteMode>,
    backend_pool: Arc<BackendPool>,
    /// The wire protocol the backends of this route are spoken to.
    ///
    /// Part of the route rather than of the pool, because it is a property of
    /// the hop to the backend and every backend of a route is reached the same
    /// way. See [`crate::config::BackendProtocol`].
    backend_protocol: BackendProtocol,
    path_rewrite: Option<String>,
    l4: L4Options,
}

impl Route {
    // A plain constructor mirroring the `[proxy.routes]` schema in config.toml.
    // Bundling the fields into a params struct would just move the argument list
    // somewhere else, so the lint is silenced here instead.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host_pattern: &str,
        path_pattern: &str,
        path_is_prefix: bool,
        backends: Vec<String>,
        strategy: LoadBalancingStrategy,
        mode: RouteMode,
        path_rewrite: Option<String>,
    ) -> Self {
        Route {
            // The pattern is folded as a pattern, not as a host: a spelling
            // that would fold into the catch-all keeps its own shape, so a
            // route can never end up serving every host.
            host_pattern: normalize_pattern(host_pattern).into_owned(),
            path_pattern: path_pattern.to_string(),
            path_is_prefix,
            modes: vec![mode],
            backend_pool: Arc::new(BackendPool::new(backends, strategy)),
            backend_protocol: BackendProtocol::default(),
            path_rewrite,
            l4: L4Options::default(),
        }
    }

    /// Speak to this route's backends with this protocol.
    ///
    /// A builder rather than another constructor argument: the protocol is
    /// about the hop to the backend, and a route that does not name one speaks
    /// HTTP/1.1 — which is what the default says.
    pub fn with_backend_protocol(mut self, protocol: BackendProtocol) -> Self {
        self.backend_protocol = protocol;
        self
    }

    /// Serve several modes from one route instead of one.
    ///
    /// Replaces rather than extends, because the caller (the config parser) has
    /// already merged what the file said; duplicates collapse, so `mode = "http"`
    /// together with `modes = ["http", "tcp"]` is not two entries. An empty list
    /// is ignored: a route serving nothing would be a silent hole in the table,
    /// and the constructor has already given it exactly one mode.
    pub fn with_modes(mut self, modes: Vec<RouteMode>) -> Self {
        let mut merged: Vec<RouteMode> = Vec::with_capacity(modes.len());
        for mode in modes {
            if !merged.contains(&mode) {
                merged.push(mode);
            }
        }
        if !merged.is_empty() {
            self.modes = merged;
        }
        self
    }

    /// Attach the `tcp` / `udp` knobs. A no-op for the other modes, which have no
    /// use for them.
    pub fn with_l4_options(mut self, options: L4Options) -> Self {
        self.l4 = options;
        self
    }

    /// Host-only match, after [`normalize_host`] has folded both sides.
    ///
    /// The TLS passthrough path selects on SNI, i.e. before a request line
    /// exists, so there is no path to match against.
    pub fn matches_host(&self, host: &str) -> bool {
        self.serves_host(&normalize_host(host))
    }

    /// Host-only match against a host the caller has **already folded**.
    ///
    /// The routes are walked one after another, and every one of them was
    /// folding the same name again — once per route, for every request. The
    /// fold is the caller's, done once for the whole walk.
    pub fn serves_host(&self, host: &str) -> bool {
        host_matches(&self.host_pattern, host)
    }

    /// Match for an L4 flow: the host, plus the optional client-port allow list.
    ///
    /// `client_ports` only decides whether *this* route answers. Where the connection
    /// is then dialled is entirely the route's `backends`, so a client cannot use the
    /// list to steer the tunnel somewhere else.
    pub fn matches_l4(&self, host: &str, port: u16) -> bool {
        self.serves_l4(&normalize_host(host), port)
    }

    /// Match for an L4 flow, against a host the caller has **already folded**.
    ///
    /// The fold is the caller's, done once for the whole walk — see
    /// [`Self::serves_host`]. The port rule lives here, once: the walk calls
    /// this, and [`Self::matches_l4`] is this with the fold put back in, so a
    /// change to the rule cannot leave one of the two behind.
    pub fn serves_l4(&self, host: &str, port: u16) -> bool {
        if !self.serves_host(host) {
            return false;
        }
        match &self.l4.client_ports {
            Some(allowed) => allowed.contains(&port),
            None => true,
        }
    }

    /// `udp` routes only: how long a flow may sit idle.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.l4.idle_timeout
    }

    /// How long one flow on this route may run, if the route says.
    pub fn flow_timeout(&self) -> Option<Duration> {
        self.l4.flow_timeout
    }

    pub fn matches(&self, host: &str, path: &str) -> bool {
        self.serves_request(&normalize_host(host), path)
    }

    /// The match, against a host the caller has **already folded**.
    ///
    /// The fold is the caller's, done once for the whole walk — see
    /// [`Self::serves_host`].
    pub fn serves_request(&self, host: &str, path: &str) -> bool {
        // The host first, and the path only if the host matched: the path is
        // the more expensive half, and a route whose host does not match must
        // not pay for it. Before the fold moved out here the path was
        // compared eagerly for every route, so this order is a change and not
        // the preservation of one.
        if !self.serves_host(host) {
            return false;
        }

        if self.path_is_prefix {
            path_suffix(&self.path_pattern, path).is_some()
        } else {
            path == self.path_pattern
        }
    }

    /// How specific this route is; `best_match` keeps the highest.
    ///
    /// Tiers, not a sum: each one is worth strictly more than everything below
    /// it can add up to. They used to be one number, so a `path_pattern` longer
    /// than 101 characters outweighed an exact host — a route written for `*`
    /// with a long path outranked the route written for the host itself, and
    /// nothing in the logs said so.
    pub fn priority(&self) -> u32 {
        // Three tiers, not two: the bare `*` matches everything, so it has to
        // lose to a `*.suffix` wildcard, which loses to an exact name. Two
        // tiers put the catch-all and a wildcard in the same one, and a tie
        // goes to whichever was declared first — the declaration-order outcome
        // this function exists to rule out.
        let host = if self.host_pattern == "*" {
            0
        } else if self.host_pattern.starts_with('*') {
            1
        } else {
            2
        };
        // Naming the ports it serves makes an L4 route more specific than one
        // that takes every port for the same host. Without this tier,
        // "port 443" and "any port" scored the same and the first one declared
        // won for good, leaving the other route unreachable.
        let ports = u32::from(self.l4.client_ports.is_some());
        let path = u32::from(!self.path_is_prefix);
        // Longest path wins between two otherwise equal routes, which is the
        // point of a prefix match — but only as a tie-break, so it is capped.
        let length = (self.path_pattern.len() as u32).min(PATH_LENGTH_TIE_BREAK);

        host * 10_000 + ports * 1_000 + path * 100 + length
    }

    pub fn host_pattern(&self) -> &str {
        &self.host_pattern
    }

    pub fn path_pattern(&self) -> &str {
        &self.path_pattern
    }

    pub fn path_is_prefix(&self) -> bool {
        self.path_is_prefix
    }

    /// Every mode this route serves, in declaration order.
    pub fn modes(&self) -> &[RouteMode] {
        &self.modes
    }

    /// Whether this route takes part in `mode`'s lookup.
    ///
    /// A route may serve several modes, and which one a connection gets is
    /// decided earlier — by its first byte — so this is a membership test, not a
    /// choice between alternatives.
    pub fn serves(&self, mode: RouteMode) -> bool {
        self.modes.contains(&mode)
    }

    pub fn backend_pool(&self) -> &Arc<BackendPool> {
        &self.backend_pool
    }

    /// The wire protocol this route's backends are spoken to.
    pub fn backend_protocol(&self) -> BackendProtocol {
        self.backend_protocol
    }

    /// Run the circuit on this route's backends with these settings.
    ///
    /// A builder rather than a constructor argument: a pool built in code —
    /// in a test, or by the local proxy — has no circuit, and one built from a
    /// config has the settings the config resolved to.
    pub fn with_circuit_breaker(self, breaker: CircuitBreaker) -> Self {
        self.backend_pool.set_circuit_breaker(breaker);
        self
    }

    /// What makes this the same route across a reload, for the two things that
    /// hang off it: its backend pool and the health probe watching that pool.
    ///
    /// A host alone does not identify a route — two may share one and differ in
    /// path or in the modes they serve, and each carries its own pool. The
    /// backends are part of the key because a pool *is* its backends: change
    /// them and the old pool is no longer the one traffic goes through, even
    /// though the route looks the same.
    pub async fn pool_key(&self) -> String {
        // The strategy is part of what a pool *is*: a pool that hands requests
        // out round-robin and one that picks at random are not the same object,
        // and reusing the first for a route that now asks for the second makes
        // an edit to the config do nothing — silently, and with nothing in the
        // logs to suggest why.
        format!(
            "{}|{}|{:?}|{:?}|{:?}",
            self.host_pattern,
            self.path_pattern,
            self.modes,
            self.backend_pool.strategy(),
            self.backend_pool.backends().await
        )
    }

    pub fn path_rewrite(&self) -> &Option<String> {
        &self.path_rewrite
    }
}

#[derive(Debug, Clone)]
/// What looking up a backend can come back with.
///
/// Two of the three carry nothing, and they are not the same nothing:
///
/// - [`Self::NoRoute`] — this proxy does not serve that name. A **routing**
///   answer: "forward this host" was never configured, so the fix is in
///   `[[routes]]`.
/// - [`Self::Unavailable`] — the name is served, and every backend behind it is
///   currently unhealthy. An **operations** answer: routing is correct and
///   something downstream is down.
///
/// Collapsing the second into the first would be the expensive mistake: the
/// proxy would answer `404` for a healthy route whose backends died, and whoever
/// is reading those codes goes looking in the one file that is already right.
/// That is why this exists rather than `Option`.
pub enum BackendLookup<T> {
    NoRoute,
    Unavailable,
    Found(T),
}

impl<T> BackendLookup<T> {
    /// The backend, and only when there is one to forward to.
    ///
    /// Both refusals map to `None`, so this is the first choice for anything
    /// about the request. A caller that needs to answer them differently asks
    /// [`Self::reason`].
    pub fn backend(self) -> Option<T> {
        match self {
            BackendLookup::Found(value) => Some(value),
            BackendLookup::NoRoute | BackendLookup::Unavailable => None,
        }
    }

    /// Borrowed version of [`Self::backend`].
    pub fn found(&self) -> Option<&T> {
        match self {
            BackendLookup::Found(value) => Some(value),
            BackendLookup::NoRoute | BackendLookup::Unavailable => None,
        }
    }

    pub fn is_found(&self) -> bool {
        self.found().is_some()
    }

    /// `true` when this is a routing question rather than an outage — nothing
    /// here serves that name.
    ///
    /// Ask for this one in a test rather than [`Self::is_not_found`] whenever
    /// what is being pinned is "no route": the two refusals both mean "no
    /// backend", and leaving them collapsed is how a test that used to say "no
    /// route matches" quietly starts passing because the pool was marked down.
    pub fn is_no_route(&self) -> bool {
        matches!(self, BackendLookup::NoRoute)
    }

    /// `true` when there is nothing to forward to, for either reason.
    pub fn is_not_found(&self) -> bool {
        !self.is_found()
    }

    /// Which refusal this is, for a caller that answers them differently.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            BackendLookup::Found(_) => None,
            BackendLookup::NoRoute => Some("no route matches"),
            BackendLookup::Unavailable => Some("no healthy backend behind the route"),
        }
    }
}

pub struct BackendInfo {
    /// The backend's address.
    ///
    /// Shared, so that a request does not copy it: the address belongs to the
    /// pool and does not change.
    pub url: Arc<str>,
    /// The scheme, the host and the port of the address, ready to be joined
    /// to a path.
    ///
    /// Parsed **once**, when the pool was built — a backend does not move,
    /// and parsing it per request is a measurable share of what a request
    /// costs. The error is kept rather than thrown, so that the request path
    /// is where it is reported.
    pub origin: Result<Arc<str>, String>,
    /// The wire protocol this backend is to be spoken to.
    ///
    /// Carried with the address because it is the other half of "where this
    /// request goes": the same address is reached differently depending on
    /// what the route says, and a caller that picked the backend has to pick
    /// the client with it.
    pub protocol: BackendProtocol,
    pub path_rewrite: Option<String>,
    pub path_pattern: String,
    pub path_is_prefix: bool,
    /// Alive for exactly as long as this request is outstanding against that
    /// backend: dropping it is what releases the backend's slot in the balancer,
    /// so nothing reads this field — moving it along with the requests is the
    /// whole point. See [`crate::lb::BackendLease`].
    ///
    /// Taken rather than borrowed, because the work against a backend is not
    /// over when the response head arrives: a body that is still streaming is
    /// a backend that is still busy, and the caller that owns the body is the
    /// one that has to keep the lease until it is dropped.
    _lease: Option<BackendLease>,
}

impl BackendInfo {
    /// Takes the lease out, so the caller can hold it for as long as the work
    /// lasts.
    ///
    /// The lease counts the backend as busy until it is dropped, and the work
    /// is not over when the response head is in: the body may still be
    /// streaming. A caller that keeps the lease with the body is what makes
    /// `least_conn` count what is really in flight.
    pub fn take_lease(&mut self) -> Option<BackendLease> {
        self._lease.take()
    }

    /// The backend answered.
    ///
    /// What the circuit counts. A backend that answers is a backend that is
    /// up, however long it took.
    pub fn report_success(&self) {
        if let Some(lease) = &self._lease {
            lease.record_success();
        }
    }

    /// The backend did not answer.
    ///
    /// What the circuit counts. Only the failures that say the backend is
    /// unreachable are counted — a response that broke halfway says something
    /// else, and the backend did answer.
    pub fn report_failure(&self) {
        if let Some(lease) = &self._lease {
            lease.record_failure();
        }
    }

    /// The path this request is forwarded with, after the route's rewrite.
    ///
    /// A route may say "the paths under `/api` are served as `/v2`", by
    /// pairing a `path_pattern` with a `path_rewrite` that holds a `{}` where
    /// the matched part goes. A request whose path does not match the pattern
    /// is forwarded unchanged.
    ///
    /// The rule lives here, on the one type that carries the three things it
    /// needs, because it used to live in two places and be applied in one of
    /// them. The plaintext listener rewrote the path; the tunnel path did not,
    /// and a route that named a rewrite looked configured and worked against
    /// `curl` and did nothing for every real client.
    pub fn rewritten_path(&self, original_path: &str) -> String {
        let Some(rewrite_pattern) = &self.path_rewrite else {
            return original_path.to_string();
        };
        if self.path_is_prefix {
            // The same predicate the match uses, so the suffix that comes off
            // the front is the one that matched.
            if let Some(suffix) = path_suffix(&self.path_pattern, original_path) {
                return rewrite_pattern.replace("{}", suffix);
            }
        } else if original_path == self.path_pattern {
            return rewrite_pattern.replace("{}", "");
        }
        original_path.to_string()
    }
}

/// The part of `path` that `pattern` does not cover, if it covers any of it.
///
/// A path prefix in the **path** sense: the pattern covers the path when the
/// path is the pattern, or when it continues with a `/`. So `/api` covers
/// `/api` and `/api/x`, and not `/apifoo` — which is what `starts_with` alone
/// would say, and what a path prefix is not.
///
/// The pattern's own trailing slash is normalised away, so `/api/` covers the
/// same paths as `/api` and the path does not need a second slash to match.
///
/// The suffix is what the pattern did not cover, so it is the same string
/// whether the path matched exactly or continued past the pattern — which is
/// what makes the rewrite and the match agree.
///
/// One function, because the match and the rewrite have to agree: a prefix
/// that is not a prefix is a routing surprise either way.
pub(crate) fn path_suffix<'a>(pattern: &str, path: &'a str) -> Option<&'a str> {
    let pattern = pattern.trim_end_matches('/');
    if path == pattern {
        return Some("");
    }
    let rest = path.strip_prefix(pattern)?;
    // Only a segment boundary counts: `/apifoo` is not under `/api`. The
    // separator stays in the suffix: it is part of what the pattern did not
    // cover, and a rewrite of `/v2{}` wants `/v2/users`, not `/v2users`.
    rest.strip_prefix('/')?;
    Some(rest)
}

/// What the L4 tunnel needs in order to serve one flow.
pub struct L4RouteInfo {
    /// The address to dial, and the only address involved: the route decides
    /// it, the client cannot. See [`RoutingTable::get_l4_backend`].
    pub backend: String,
    /// `udp` routes only; `None` means the caller's own default.
    pub idle_timeout: Option<Duration>,
    /// `tcp` and `udp` routes; `None` means the caller's own default.
    ///
    /// How long the whole flow may run, as against the gap between packets that
    /// `idle_timeout` bounds. Separate because a peer can keep a flow alive
    /// forever by sending one packet before each idle expiry.
    pub flow_timeout: Option<Duration>,
    /// Held until this flow finishes, so the balancer knows the slot is still
    /// taken. Nothing reads it; see [`BackendInfo::_lease`].
    _lease: BackendLease,
}

// Hand-written rather than derived, because the lease it carries cannot be
// cloned — it is a count of one — and a `Debug` that printed it would print a
// different number every time someone looked.
impl std::fmt::Debug for L4RouteInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L4RouteInfo")
            .field("backend", &self.backend)
            .field("idle_timeout", &self.idle_timeout)
            .field("flow_timeout", &self.flow_timeout)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// The routing table.
    ///
    /// **The routes are shared.** A lookup that found a route used to copy it
    /// out of the table — three strings and a vector, so four or five heap
    /// allocations for every request that matched — and the copy was thrown
    /// away as soon as the backend was picked. A reference count is the whole
    /// of what a table entry needs to be passed around.
    routes: Arc<RwLock<Vec<Arc<Route>>>>,
    /// How long to wait on a backend, resolved once at startup.
    ///
    /// Held here rather than threaded down to each stream handler because this
    /// object is what every one of them already receives — routing and the
    /// deadlines its choices are carried out under arrive together, so there is
    /// no third thing for every call site in `conn` to remember to pass. It is
    /// not part of the routing table and a reload leaves it alone: changing a
    /// timeout takes a restart, like every key outside `[[routes]]`.
    timeouts: Timeouts,
    /// How often a failed request is tried again, and on which backend.
    ///
    /// Held here rather than threaded down to each handler because this object
    /// is what every one of them already receives, for the same reason the
    /// deadlines are: routing and the rules its choices are carried out under
    /// arrive together. A reload leaves it alone, like every key outside
    /// `[[routes]]`.
    retry: Retry,
}

impl RoutingTable {
    pub fn new(routes: Vec<Route>) -> Self {
        Self {
            routes: Arc::new(RwLock::new(shared(routes))),
            timeouts: Timeouts::default(),
            retry: Retry::default(),
        }
    }

    /// A table whose flows wait on these deadlines rather than the defaults.
    ///
    /// The only construction that matters outside a test: defaults exist so a
    /// table built anywhere else — the local proxy, the tests — behaves exactly
    /// as it did before this field existed.
    pub fn with_timeouts(routes: Vec<Route>, timeouts: Timeouts) -> Self {
        Self {
            routes: Arc::new(RwLock::new(shared(routes))),
            timeouts,
            retry: Retry::default(),
        }
    }

    /// A table whose flows wait on these deadlines and retry like this.
    ///
    /// The only construction that matters outside a test: defaults exist so a
    /// table built anywhere else — the local proxy, the tests — behaves exactly
    /// as it did before this field existed.
    pub fn with_settings(routes: Vec<Route>, timeouts: Timeouts, retry: Retry) -> Self {
        Self {
            routes: Arc::new(RwLock::new(shared(routes))),
            timeouts,
            retry,
        }
    }

    /// The deadlines a flow reaching through this table waits on.
    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// How often a request that failed is tried again.
    pub fn retry(&self) -> Retry {
        self.retry
    }

    /// Backend for an HTTP request. Callers answer
    /// [`BackendLookup::NoRoute`] with `404` and [`BackendLookup::Unavailable`]
    /// with `503` — see the enum for why the two are not one answer.
    pub async fn get_backend(&self, host: &str, path: &str) -> BackendLookup<BackendInfo> {
        self.get_backend_with_acl(host, path, None, None).await
    }

    /// [`Self::get_backend`], preferring a backend that is not on the list.
    ///
    /// The list is the backends an earlier attempt already failed against, and
    /// it is what a retry is built on: the backend that just failed is the one
    /// most likely to fail again.
    pub async fn get_backend_excluding(
        &self,
        host: &str,
        path: &str,
        exclude: &[String],
    ) -> BackendLookup<BackendInfo> {
        self.get_backend_with_acl_excluding(host, path, None, None, exclude)
            .await
    }

    /// [`Self::get_backend`] under a client's authorization.
    ///
    /// One rule beyond the plain lookup: a host the ACL does not list is
    /// refused before any route is consulted, and so is a port the ACL does
    /// list — the refusal is indistinguishable from "no route" — a 404, not a
    /// 403, so a client cannot use the difference to probe which hosts exist
    /// behind the proxy.
    ///
    /// `port` is the port the client named, if it named one. `None` means it
    /// named none, and there is then no port to hold against it.
    pub async fn get_backend_with_acl(
        &self,
        host: &str,
        path: &str,
        port: Option<u16>,
        acl: Option<&ClientAcl>,
    ) -> BackendLookup<BackendInfo> {
        self.get_backend_with_acl_excluding(host, path, port, acl, &[])
            .await
    }

    /// [`Self::get_backend_with_acl`], preferring a backend that is not on the
    /// list.
    pub async fn get_backend_with_acl_excluding(
        &self,
        host: &str,
        path: &str,
        port: Option<u16>,
        acl: Option<&ClientAcl>,
        exclude: &[String],
    ) -> BackendLookup<BackendInfo> {
        if acl.is_some_and(|acl| !acl.allows(host)) {
            tracing::debug!("Host {host} is not allowed for this client, answering 404");
            return BackendLookup::NoRoute;
        }

        // The port half of the same question. Only asked when the client named
        // one: a request that names no port has no port to hold against it.
        if let (Some(acl), Some(port)) = (acl, port)
            && !acl.allows_port(port)
        {
            tracing::debug!("Port {port} is not allowed for this client, answering 404");
            return BackendLookup::NoRoute;
        }

        tracing::debug!("Looking up backend for host={}, path={}", host, path);

        // Only `http` routes take requests. A passthrough route exists so its
        // bytes can be copied to a TLS backend, and that listener is not an
        // HTTP server: letting one match here would send a plain request to a
        // TLS port.
        let matched_route = {
            let routes = self.routes.read().await;
            // The host is folded once for the whole walk, rather than once
            // for every route in it.
            let folded = normalize_host(host);
            best_match(&routes, RouteMode::Http, |route| {
                route.serves_request(&folded, path)
            })
        };

        let Some(route) = matched_route else {
            tracing::debug!("No http route matched: host={host}, path={path} -> 404");
            return BackendLookup::NoRoute;
        };

        // A route matched, so this stopped being a routing question: every
        // backend behind it is down, and dialling one anyway spends a whole
        // connect timeout delivering the refusal the caller can write now.
        let Some(lease) = route.backend_pool().select_backend_excluding(exclude).await else {
            tracing::warn!(
                "Route {}:{} matched host={host} path={path} but no backend is healthy -> 503",
                route.host_pattern(),
                route.path_pattern(),
            );
            return BackendLookup::Unavailable;
        };

        // The port the request is actually **served from** — the backend's,
        // not the one the client named in its `Host` header. A client asking
        // for `https://api.example.com` is served from
        // `http://127.0.0.1:18080`; the port the client named is a virtual
        // one, and the request never reaches it.
        //
        // Only asked when the ACL is strict. Without that, the port list is
        // checked where the client names a port, and this has nothing to add.
        if let Some(acl) = acl
            && let Some(port) = backend_port(lease.url())
            && !acl.allows_backend_port(port)
        {
            tracing::debug!(
                "Port {port} (the backend for {host}) is not allowed for this client, answering 404"
            );
            return BackendLookup::NoRoute;
        }

        tracing::debug!(
            "Selected backend: {} for host={}, path={}",
            lease.url(),
            host,
            path,
        );
        BackendLookup::Found(BackendInfo {
            url: lease.shared_url().clone(),
            origin: lease.origin().clone(),
            protocol: route.backend_protocol(),
            path_rewrite: route.path_rewrite().clone(),
            path_pattern: route.path_pattern().to_string(),
            path_is_prefix: route.path_is_prefix(),
            _lease: Some(lease),
        })
    }

    /// Backend for a raw TLS passthrough connection, selected by SNI.
    ///
    /// Only `mode = "passthrough"` routes take part, so [`BackendLookup::NoRoute`]
    /// means nothing serves this name and the caller hangs up rather than
    /// guessing at a backend. [`BackendLookup::Unavailable`] is reachable too: a
    /// route may serve both `http` and `passthrough`, and then health probes run
    /// against the pool both modes dial into.
    ///
    /// The lease comes back with it rather than only its address, because a TLS
    /// session is exactly the load `least_conn` is counting: copying bytes to a
    /// backend for as long as the client keeps the session open. Handing back a
    /// bare `String` would release it on return and leave every passthrough
    /// session invisible to the balancer.
    pub async fn get_passthrough_backend(&self, sni: &str) -> BackendLookup<BackendLease> {
        let matched_route = {
            let routes = self.routes.read().await;
            // The name is folded once for the whole walk.
            let folded = normalize_host(sni);
            best_match(&routes, RouteMode::Passthrough, |route| {
                route.serves_host(&folded)
            })
        };

        let Some(route) = matched_route else {
            tracing::debug!("No passthrough route matched: sni={sni}, hanging up");
            return BackendLookup::NoRoute;
        };

        // Nothing to copy toward, then: say so where the operator can read it,
        // rather than letting it look like a name nothing serves.
        let Some(lease) = route.backend_pool().select_backend().await else {
            tracing::warn!(
                "Passthrough route {} matched sni={sni} but no backend is healthy; refusing \
                 rather than copying into a connection nobody answers",
                route.host_pattern(),
            );
            return BackendLookup::Unavailable;
        };

        tracing::debug!(
            "Passthrough route matched: sni={}, host={}, backend={}",
            sni,
            route.host_pattern(),
            lease.url()
        );
        BackendLookup::Found(lease)
    }

    /// Backend for one L4 flow, selected by host and port.
    ///
    /// Only `mode`'s own routes take part — a `tcp` lookup never sees a `udp` route and
    /// vice versa — and [`BackendLookup::NoRoute`] means nothing serves this host.
    ///
    /// **There is no fallback.** A `tcp` or `udp` lookup sees only the routes of
    /// its own mode, so a host with none of them is refused: forwarding a
    /// mistyped or unconfigured domain to some other service is exactly the
    /// failure this lookup exists to prevent.
    ///
    /// The two refusals do **not** reach the client as the same status — see
    /// [`BackendLookup`]. A route serving `http` alongside `tcp` is probed on the
    /// pool both modes share, so an L4 flow can find a healthy route whose every
    /// backend is down, and answering `NoRoute` for that would tell the client its
    /// request was misconfigured when what actually happened is that there is
    /// nothing to dial.
    pub async fn get_l4_backend(
        &self,
        host: &str,
        port: u16,
        mode: RouteMode,
    ) -> BackendLookup<L4RouteInfo> {
        debug_assert!(mode.is_l4(), "get_l4_backend called with {mode:?}");

        let matched_route = {
            let routes = self.routes.read().await;
            // The host is folded once for the whole walk.
            let folded = normalize_host(host);
            best_match(&routes, mode, |route| route.serves_l4(&folded, port))
        };

        let Some(route) = matched_route else {
            tracing::debug!("No l4 route matched: host={host}, port={port}, mode={mode:?}");
            return BackendLookup::NoRoute;
        };

        let Some(lease) = route.backend_pool().select_backend().await else {
            tracing::warn!(
                "L4 route {} matched host={host} port={port} ({mode:?}) but no backend is healthy",
                route.host_pattern(),
            );
            return BackendLookup::Unavailable;
        };

        tracing::debug!(
            "L4 route matched: host={}, port={}, mode={:?}, route={}, backend={}",
            host,
            port,
            mode,
            route.host_pattern(),
            lease.url()
        );
        BackendLookup::Found(L4RouteInfo {
            backend: lease.url().to_string(),
            idle_timeout: route.idle_timeout(),
            flow_timeout: route.flow_timeout(),
            _lease: lease,
        })
    }

    /// The whole table, copied out.
    ///
    /// For the admin API and the startup log, not for the request path: a copy
    /// of a route is four or five allocations, and a listing wants the routes
    /// themselves rather than the table's references to them.
    pub async fn routes(&self) -> Vec<Route> {
        self.routes
            .read()
            .await
            .iter()
            .map(|route| (**route).clone())
            .collect()
    }

    /// Swaps the routing table, keeping the pool of every route that is still
    /// the route it was.
    ///
    /// A reload builds brand-new `Route`s from the file, and a brand-new
    /// `BackendPool` with each. Everything that was handed a pool earlier —
    /// above all the health probe, which holds its `Arc` and runs until the
    /// process ends — would then be left holding a pool the routing table no
    /// longer hands out: the probe would keep marking backends up and down
    /// where no traffic can see it, and the live pool would go unprobed, so a
    /// backend that died would stay in rotation until the next restart.
    ///
    /// Carrying the old pool over also keeps its health state. An edit to an
    /// unrelated route is not a reason to decide that every backend is healthy
    /// again.
    ///
    /// `timeouts` is not touched: it was read once at startup, into the HTTP
    /// client and into this table, and a reload is a routing change rather than a
    /// restatement of how long a dial may take.
    pub async fn update_routes(&self, new_routes: Vec<Route>) {
        // **The keys are computed before the lock is taken.** Computing one is
        // an await, and holding the routing table's write lock across an await
        // stops every request in the process: the table is read on the way to
        // every backend, and a read lock waits for a write lock. So a reload
        // that took a moment to work out its keys held the whole server still
        // while it did.
        let mut previous: HashMap<String, Arc<BackendPool>> = HashMap::new();
        {
            let routes = self.routes.read().await;
            for route in routes.iter() {
                previous.insert(route.pool_key().await, route.backend_pool().clone());
            }
        }

        let mut updated = Vec::with_capacity(new_routes.len());
        for mut route in new_routes {
            let key = route.pool_key().await;
            // `remove`, not `get`: two routes can share a key, and each keeps
            // its own pool rather than ending up sharing one.
            if let Some(pool) = previous.remove(&key) {
                route.backend_pool = pool;
            }
            updated.push(Arc::new(route));
        }

        // The write lock is held for the swap and nothing else.
        let mut routes = self.routes.write().await;
        *routes = updated;
        tracing::info!("Routes updated successfully");
    }
}

/// The routes of a table, shared.
///
/// A table hands out references to its routes rather than copies of them, so
/// this is where a list of routes becomes a list of references.
fn shared(routes: Vec<Route>) -> Vec<Arc<Route>> {
    routes.into_iter().map(Arc::new).collect()
}

/// The port a backend is reached on.
///
/// `None` when the backend does not say, and when it does not say, the port is
/// the scheme's default — which is what the URL itself would use.
///
/// **Both spellings are read.** A backend is written as a URL
/// (`http://10.0.0.5:18080`) for an HTTP route, and as a bare `host:port`
/// (`127.0.0.1:443`) for a TLS passthrough — and a bare `host:port` is not a
/// URL at all: `Url::parse` reads `host.docker.internal:8443` as a scheme
/// with no port, and refuses `127.0.0.1:443` outright. So the passthrough's own
/// parser is the one that answers, and it knows both.
pub(crate) fn backend_port(url: &str) -> Option<u16> {
    crate::passthrough::parse_backend_addr(url).map(|(_host, port)| port)
}

/// The port a backend is reached on, in either spelling.
///
/// The two spellings are not the same thing to a URL parser: `http://host:8443`
/// is a URL, and `host:8443` is not one at all — `Url::parse` reads it as a
/// scheme and finds no port, and refuses `127.0.0.1:8443` outright. A TLS
/// passthrough backend is written the second way, so a check that only read
/// URLs would never fire on one.
#[cfg(test)]
mod backend_port_tests {
    use super::backend_port;

    #[test]
    fn a_url_backend_is_read() {
        assert_eq!(backend_port("http://10.0.0.5:18080"), Some(18080));
        assert_eq!(backend_port("https://example.com"), Some(443));
    }

    #[test]
    fn a_bare_host_and_port_is_read() {
        // The spelling a TLS passthrough backend is written in.
        assert_eq!(backend_port("127.0.0.1:8443"), Some(8443));
        assert_eq!(backend_port("host.docker.internal:8443"), Some(8443));
        assert_eq!(backend_port("[::1]:8443"), Some(8443));
    }
}

/// Highest-priority route of `mode` that `matches` accepts.
///
/// Ties keep the first declaration. A route serves only the modes it declares,
/// and which of them a connection uses is decided before matching, by the first
/// byte of the connection — a TLS handshake goes to `Passthrough`, an L4 preface
/// to `Tcp` or `Udp`, anything else to `Http`. One route may declare several
/// modes; a connection still takes exactly one path.
fn best_match(
    routes: &[Arc<Route>],
    mode: RouteMode,
    matches: impl Fn(&Route) -> bool,
) -> Option<Arc<Route>> {
    let mut best: Option<(Arc<Route>, u32)> = None;

    for route in routes.iter() {
        if !route.serves(mode) || !matches(route) {
            continue;
        }

        let priority = route.priority();
        tracing::debug!(
            "Route matched: host={}, path={}, mode={:?}, priority={}",
            route.host_pattern(),
            route.path_pattern(),
            mode,
            priority
        );

        if best
            .as_ref()
            .is_none_or(|(_, best_priority)| priority > *best_priority)
        {
            best = Some((route.clone(), priority));
        }
    }

    best.map(|(route, _)| route)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A strict client is limited by the port the request is **served from**.
    ///
    /// The port the client named is a virtual one: it asked for
    /// `https://api.example.com` and the proxy serves it from
    /// `http://10.0.0.5:18080`. The port that decides what a client can
    /// touch is the backend's, and this is the check that uses it.
    #[tokio::test]
    async fn a_strict_client_is_limited_by_the_backends_port() {
        use crate::auth::ClientAcl;

        let route = http_route("api.iakl.top", &["http://10.0.0.5:18080"]);
        let config = RoutingTable::new(vec![route]);

        // The client may reach 443, and the route's backend is on 18080.
        let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443])).with_strict_ports(true);

        assert!(
            matches!(
                config
                    .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
                    .await,
                BackendLookup::NoRoute
            ),
            "the request is served from a port the client may not reach"
        );
    }

    /// The same client, the same route, and a backend on a port it may reach.
    #[tokio::test]
    async fn a_strict_client_reaches_a_backend_on_a_port_it_may_reach() {
        use crate::auth::ClientAcl;

        let route = http_route("api.iakl.top", &["http://10.0.0.5:443"]);
        let config = RoutingTable::new(vec![route]);

        let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443])).with_strict_ports(true);

        assert!(
            config
                .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
                .await
                .is_found(),
            "the backend is on a port the client may reach"
        );
    }

    /// Without the strict flag, the historical reach is what happens: the port
    /// list is checked against the port the client *named*, and a request that
    /// named none is not checked at all.
    ///
    /// This is the behaviour a deployed configuration was written against, so
    /// it is the default; `allow_ports_strict` is how an operator asks for the
    /// check above.
    #[tokio::test]
    async fn a_client_that_is_not_strict_keeps_its_historical_reach() {
        use crate::auth::ClientAcl;

        let route = http_route("api.iakl.top", &["http://10.0.0.5:18080"]);
        let config = RoutingTable::new(vec![route]);

        let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));

        assert!(
            config
                .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
                .await
                .is_found(),
            "the port list is not checked against the backend's port"
        );
    }

    /// Health says which of several backends to send to, so a pool that has only
    /// one has nothing to decide — and refusing is not "safer" there, it is answering
    /// for every request to a route in order to report that nothing is up. See
    /// [`crate::lb::BackendPool::select_backend`].
    #[tokio::test]
    async fn one_unhealthy_backend_is_still_the_answer() {
        let route = http_route("api.iakl.top", &["http://10.0.0.5:8080"]);
        route
            .backend_pool()
            .set_backend_health("http://10.0.0.5:8080", false)
            .await;
        let config = RoutingTable::new(vec![route]);

        assert!(
            config.get_backend("api.iakl.top", "/").await.is_found(),
            "the one backend behind this route is the only path it has"
        );
    }

    /// The same pool state, one more backend: now the health information means
    /// something, and the lookup has to say "unavailable" rather than hand out a
    /// backend it knows is down. 503 and 404 differ in which file the operator
    /// opens.
    #[tokio::test]
    async fn unhealthy_backends_are_not_confused_with_a_missing_route() {
        let route = http_route(
            "api.iakl.top",
            &["http://10.0.0.5:8080", "http://10.0.0.6:8080"],
        );
        let pool = route.backend_pool().clone();
        pool.set_backend_health("http://10.0.0.5:8080", false).await;
        pool.set_backend_health("http://10.0.0.6:8080", false).await;
        let config = RoutingTable::new(vec![route]);

        assert!(
            matches!(
                config.get_backend("api.iakl.top", "/").await,
                BackendLookup::Unavailable
            ),
            "every backend is down, and the route that matched still exists"
        );
        assert!(
            matches!(
                config.get_backend("nope.iakl.top", "/").await,
                BackendLookup::NoRoute
            ),
            "no route serves this host at all, which is a different answer"
        );
    }

    /// A pool shared by `http` and another mode carries one health state, so the
    /// tunnel and the TLS passthrough see the same refusal as a request does —
    /// which is why all three lookups speak in [`BackendLookup`] rather than
    /// `Option`.
    #[tokio::test]
    async fn the_same_refusal_reaches_the_tunnel_and_the_passthrough() {
        // One route, three modes, one pool — exactly the shape a health probe
        // marks through `http` and the other two dial into.
        let route = http_route("fn.iroh.iakl.top", &["caddy:443", "caddy2:443"]).with_modes(vec![
            RouteMode::Http,
            RouteMode::Passthrough,
            RouteMode::Tcp,
        ]);
        let pool = route.backend_pool().clone();
        let config = RoutingTable::new(vec![route]);
        pool.set_backend_health("caddy:443", false).await;
        pool.set_backend_health("caddy2:443", false).await;

        assert!(matches!(
            config.get_passthrough_backend("fn.iroh.iakl.top").await,
            BackendLookup::Unavailable
        ));
        assert!(matches!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 443, RouteMode::Tcp)
                .await,
            BackendLookup::Unavailable
        ));
    }

    fn http_route(host: &str, backends: &[&str]) -> Route {
        Route::new(
            host,
            "/",
            true,
            backends.iter().map(|b| b.to_string()).collect(),
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            None,
        )
    }

    fn passthrough_route(host: &str, backends: &[&str]) -> Route {
        Route::new(
            host,
            "/",
            true,
            backends.iter().map(|b| b.to_string()).collect(),
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Passthrough,
            None,
        )
    }

    /// The two modes are separate tables: a TLS session is served by the
    /// passthrough route and a plain request by the http one, even when they
    /// share a host name.
    #[tokio::test]
    async fn each_mode_only_sees_its_own_routes() {
        let config = RoutingTable::new(vec![
            passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
            http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]),
            http_route("mt.iroh.iakl.top", &["http://10.0.0.6:9000"]),
        ]);

        assert_eq!(
            config
                .get_passthrough_backend("fn.iroh.iakl.top")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy:443".to_string())
        );
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the http route serves this host")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
        // A host that is only served over plain HTTP has no TLS backend, and
        // the default backend is not a passthrough fallback.
        assert_eq!(
            config
                .get_passthrough_backend("mt.iroh.iakl.top")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            None
        );
        assert!(
            config
                .get_passthrough_backend("unknown.test")
                .await
                .is_no_route()
        );
    }

    /// `modes = ["http", "tcp"]` in the form of a lookup: one route, two tables,
    /// one shared pool.
    ///
    /// This is the configuration a TUN client needs — every one of its flows
    /// arrives as an L4 preface, even on port 80 — and it used to take two
    /// entries, where forgetting the second one cost a runtime `NoRoute`.
    #[tokio::test]
    async fn one_route_may_serve_both_a_request_and_a_tunnel() {
        let config = RoutingTable::new(vec![
            http_route("fn.iroh.iakl.top", &["http://host.docker.internal:15666"])
                .with_modes(vec![RouteMode::Http, RouteMode::Tcp]),
        ]);

        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the route serves this host as a request")
                .url
                .as_ref(),
            "http://host.docker.internal:15666"
        );
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 80, RouteMode::Tcp)
                .await
                .backend()
                .expect("the same route serves this host as a tunnel")
                .backend,
            "http://host.docker.internal:15666"
        );
        // Declaring two modes did not turn the route into a catch-all: udp was
        // never one of them, and there is no default backend to fall back on.
        assert!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 80, RouteMode::Udp)
                .await
                .is_no_route()
        );
    }

    /// One server, four kinds of traffic — the question "can http, https, tcp and udp
    /// run at the same time" in the form of a test.
    ///
    /// They can, because a route belongs to exactly one mode and each lookup only ever
    /// searches its own mode: the same host name may appear four times without the
    /// entries shadowing each other. What decides which one a *connection* gets is the
    /// first byte it arrives with, so a single connection still only ever takes one path
    /// — a TLS `ClientHello` cannot reach the `tcp` route, and an L4 preface cannot reach
    /// `passthrough`, even though both point at the same backend here.
    #[tokio::test]
    async fn one_config_serves_http_https_tcp_and_udp_at_once() {
        let config = RoutingTable::new(vec![
            // https:// reaching the server as raw TLS, routed by SNI.
            passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
            // http:// reaching it as a request, routed by Host.
            http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]),
            // The same https:// service seen through a TUN or a CONNECT tunnel,
            // where the client announces host and port instead of sending TLS.
            l4_route("fn.iroh.iakl.top", RouteMode::Tcp, "caddy:443", None),
            // A UDP service on the same name.
            l4_route("fn.iroh.iakl.top", RouteMode::Udp, "10.0.0.60:3478", None),
        ]);

        // Plain HTTP request.
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the http route serves this host")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
        // TLS session, routed by SNI.
        assert_eq!(
            config
                .get_passthrough_backend("fn.iroh.iakl.top")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy:443".to_string())
        );
        // TCP tunnel, and UDP tunnel.
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 443, RouteMode::Tcp)
                .await
                .backend()
                .unwrap()
                .backend,
            "caddy:443"
        );
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 3478, RouteMode::Udp)
                .await
                .backend()
                .unwrap()
                .backend,
            "10.0.0.60:3478"
        );

        // The two directions of the same claim: the tunnels refuse what they do not
        // serve, while HTTP still has somewhere to go.
        assert!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 3478, RouteMode::Tcp)
                .await
                .is_found(),
            "a tcp route with no client_ports serves every port"
        );
        assert!(
            config
                .get_l4_backend("nothing.iroh.iakl.top", 443, RouteMode::Tcp)
                .await
                .is_no_route()
        );
        // The one thing HTTP does not share with the tunnels: it is the only
        // lookup with no route for this host either, so it says 404.
        assert!(
            config
                .get_backend("nothing.iroh.iakl.top", "/")
                .await
                .is_no_route()
        );
    }

    #[tokio::test]
    async fn passthrough_catch_all_and_exact_host_priority() {
        let config = RoutingTable::new(vec![
            passthrough_route("*", &["caddy:443"]),
            passthrough_route("other.iakl.top", &["caddy-alt:443"]),
        ]);

        assert_eq!(
            config
                .get_passthrough_backend("anything.test")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy:443".to_string())
        );
        // An exact host outranks the wildcard regardless of declaration order.
        assert_eq!(
            config
                .get_passthrough_backend("other.iakl.top")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy-alt:443".to_string())
        );
    }

    fn l4_route(host: &str, mode: RouteMode, backend: &str, ports: Option<&[u16]>) -> Route {
        Route::new(
            host,
            "/",
            true,
            vec![backend.to_string()],
            LoadBalancingStrategy::RoundRobin,
            mode,
            None,
        )
        .with_l4_options(L4Options {
            client_ports: ports.map(|p| p.to_vec()),
            idle_timeout: None,
            flow_timeout: None,
        })
    }

    #[tokio::test]
    async fn l4_lookups_only_see_their_own_mode() {
        let config = RoutingTable::new(vec![
            l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None),
            http_route("web.iroh.iakl.top", &["http://10.0.0.5:8080"]),
        ]);

        let tcp = config
            .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Tcp)
            .await
            .backend()
            .expect("the tcp route should answer");
        assert_eq!(tcp.backend, "10.0.0.50:5432");

        // The tcp route is not reachable as UDP...
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Udp)
                .await
                .is_no_route()
        );
        // ...and an HTTP route is not an L4 target in either mode, while the HTTP path
        // still serves it.
        assert!(
            config
                .get_l4_backend("web.iroh.iakl.top", 80, RouteMode::Tcp)
                .await
                .is_no_route()
        );
        assert!(
            config
                .get_l4_backend("web.iroh.iakl.top", 80, RouteMode::Udp)
                .await
                .is_no_route()
        );
        assert_eq!(
            config
                .get_backend("web.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the http route serves this host")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
    }

    #[tokio::test]
    async fn an_unrouted_host_is_refused() {
        // The other route's backend is a real, working address here. If the
        // lookup served a host it has no route for, a mistyped domain would
        // quietly reach it instead of being refused.
        let config = RoutingTable::new(vec![l4_route(
            "db.iroh.iakl.top",
            RouteMode::Tcp,
            "10.0.0.50:5432",
            None,
        )]);

        assert!(
            config
                .get_l4_backend("typo.iroh.iakl.top", 5432, RouteMode::Tcp)
                .await
                .is_no_route()
        );
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Udp)
                .await
                .is_no_route()
        );
    }

    #[tokio::test]
    async fn client_ports_pick_a_route_without_changing_its_target() {
        let config = RoutingTable::new(vec![
            l4_route(
                "db.iroh.iakl.top",
                RouteMode::Tcp,
                "10.0.0.50:5432",
                Some(&[5432]),
            ),
            l4_route(
                "db.iroh.iakl.top",
                RouteMode::Tcp,
                "10.0.0.51:6432",
                Some(&[6432]),
            ),
        ]);

        // Each port selects its own route, and each route dials its own backend: the
        // client's port is a selector, never the address that is dialled.
        assert_eq!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Tcp)
                .await
                .backend()
                .unwrap()
                .backend,
            "10.0.0.50:5432"
        );
        assert_eq!(
            config
                .get_l4_backend("db.iroh.iakl.top", 6432, RouteMode::Tcp)
                .await
                .backend()
                .unwrap()
                .backend,
            "10.0.0.51:6432"
        );
        // A port no route lists is refused rather than served by the nearest match.
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 9999, RouteMode::Tcp)
                .await
                .is_no_route()
        );
    }

    #[tokio::test]
    async fn without_client_ports_every_port_matches() {
        let config = RoutingTable::new(vec![l4_route(
            "db.iroh.iakl.top",
            RouteMode::Tcp,
            "10.0.0.50:5432",
            None,
        )]);

        for port in [1u16, 443, 5432, 65535] {
            assert_eq!(
                config
                    .get_l4_backend("db.iroh.iakl.top", port, RouteMode::Tcp)
                    .await
                    .backend()
                    .map(|r| r.backend),
                Some("10.0.0.50:5432".to_string()),
                "port {port}"
            );
        }
    }

    #[test]
    fn l4_matching_is_host_then_ports() {
        let exact = l4_route(
            "db.iroh.iakl.top",
            RouteMode::Tcp,
            "10.0.0.50:5432",
            Some(&[5432]),
        );
        assert!(exact.matches_l4("db.iroh.iakl.top", 5432));
        assert!(!exact.matches_l4("db.iroh.iakl.top", 5433));
        assert!(!exact.matches_l4("other.iakl.top", 5432));

        let wildcard = l4_route("*.iroh.iakl.top", RouteMode::Udp, "10.0.0.60:3478", None);
        assert!(wildcard.matches_l4("turn.iroh.iakl.top", 1));
        assert!(!wildcard.matches_l4("iroh.iakl.top.bad.test", 1));
    }

    #[test]
    fn idle_timeouts_travel_with_the_route() {
        let route = Route::new(
            "turn.iroh.iakl.top",
            "/",
            true,
            vec!["10.0.0.60:3478".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Udp,
            None,
        )
        .with_l4_options(L4Options {
            client_ports: None,
            idle_timeout: Some(std::time::Duration::from_secs(120)),
            flow_timeout: None,
        });
        assert_eq!(
            route.idle_timeout(),
            Some(std::time::Duration::from_secs(120))
        );

        // An HTTP route has no L4 knobs, and asking for them must not invent one.
        assert_eq!(http_route("a.test", &["http://b:80"]).idle_timeout(), None);
    }

    /// A path prefix ends at a segment boundary.
    ///
    /// `/api` covers `/api` and `/api/x`. It does not cover `/apifoo`: that
    /// is a different path that happens to start with the same letters, and a
    /// route that serves it is a route that serves more than it says.
    #[test]
    fn a_path_prefix_ends_at_a_segment_boundary() {
        let route = Route::new(
            "app.test",
            "/api",
            true,
            vec!["http://backend:80".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            None,
        );

        assert!(route.matches("app.test", "/api"), "the pattern itself");
        assert!(route.matches("app.test", "/api/x"), "under the pattern");
        assert!(route.matches("app.test", "/api/x/y"), "under the pattern");
        assert!(!route.matches("app.test", "/apifoo"), "mid-segment");
        assert!(!route.matches("app.test", "/apifoo/x"), "mid-segment");
        assert!(!route.matches("app.test", "/other"), "another path");
    }

    /// A trailing slash on the pattern is the same pattern.
    ///
    /// `/api/` and `/api` name the same place, and the path does not need a
    /// second slash in it to match either.
    #[test]
    fn a_trailing_slash_on_the_pattern_is_the_same_pattern() {
        let route = Route::new(
            "app.test",
            "/api/",
            true,
            vec!["http://backend:80".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            None,
        );

        assert!(route.matches("app.test", "/api"), "the pattern itself");
        assert!(route.matches("app.test", "/api/"), "with the slash");
        assert!(route.matches("app.test", "/api/x"), "under the pattern");
        assert!(
            route.matches("app.test", "/api//x"),
            "no second slash needed"
        );
        assert!(!route.matches("app.test", "/apifoo"), "mid-segment");
    }

    /// The rewrite computes the suffix that matched.
    ///
    /// The same predicate the match uses, so the two cannot disagree: a path
    /// the route does not serve is not rewritten either.
    #[tokio::test]
    async fn the_rewrite_computes_the_suffix_that_matched() {
        let config = RoutingTable::new(vec![Route::new(
            "app.test",
            "/api",
            true,
            vec!["http://backend:80".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            Some("/v2{}".to_string()),
        )]);

        let backend = config.get_backend("app.test", "/api/x").await;
        let info = backend.found().expect("the route serves /api/x");

        assert_eq!(
            info.rewritten_path("/api/x"),
            "/v2/x",
            "the suffix is what the pattern did not cover"
        );
        assert_eq!(info.rewritten_path("/api"), "/v2", "the pattern itself");
        assert_eq!(
            info.rewritten_path("/apifoo"),
            "/apifoo",
            "a path this route does not serve is not rewritten"
        );
    }

    /// An exact route is unchanged: it matches one path and rewrites it.
    #[tokio::test]
    async fn an_exact_route_is_unchanged() {
        let config = RoutingTable::new(vec![Route::new(
            "app.test",
            "/api",
            false,
            vec!["http://backend:80".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            Some("/v2".to_string()),
        )]);

        let backend = config.get_backend("app.test", "/api").await;
        let info = backend.found().expect("the route serves /api");

        assert!(info.rewritten_path("/api") == "/v2", "the exact path");
        assert_eq!(
            info.rewritten_path("/api/x"),
            "/api/x",
            "an exact route rewrites nothing else"
        );
    }

    /// An unrouted host has nowhere to go, and says so.
    ///
    /// There is no fallback a config can name any more: a route is the only way
    /// to serve a host, so a mistyped or unknown `Host` is a 404 instead of
    /// quietly reaching whatever service happened to be listed.
    #[tokio::test]
    async fn an_unrouted_host_is_answered_404() {
        let config = RoutingTable::new(vec![http_route(
            "fn.iroh.iakl.top",
            &["http://10.0.0.5:8080"],
        )]);

        assert!(
            config
                .get_backend("typo.iroh.iakl.top", "/")
                .await
                .is_no_route()
        );
        // The routed host is unaffected.
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the http route serves this host")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
    }

    /// `host_pattern = "*"` is how "send everything here" is spelled now.
    ///
    /// It is an ordinary `http` route — same pool, same priority rules, same
    /// lookup — so an exact host still outranks it, and it is not a fallback for
    /// anything else: an SNI or L4 lookup cannot reach it.
    #[tokio::test]
    async fn a_catch_all_route_serves_every_unrouted_host() {
        let config = RoutingTable::new(vec![
            http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
            http_route("*", &["http://10.0.0.9:9000"]),
        ]);

        assert_eq!(
            config
                .get_backend("anything.test", "/")
                .await
                .backend()
                .expect("the catch-all serves what no other route names")
                .url
                .as_ref(),
            "http://10.0.0.9:9000"
        );
        // An exact host still outranks the catch-all.
        assert_eq!(
            config
                .get_backend("api.iakl.top", "/")
                .await
                .backend()
                .expect("the exact route serves this host")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
        // It is an `http` route, not a fallback for the other modes.
        assert!(
            config
                .get_passthrough_backend("anything.test")
                .await
                .is_no_route()
        );
        assert!(
            config
                .get_l4_backend("anything.test", 443, RouteMode::Tcp)
                .await
                .is_no_route()
        );
    }

    /// A restricted client reaches the hosts its allowlist names, and nothing
    /// else — the refusal for a host not on the list is the same 404 an
    /// unrouted host gets, so the difference cannot be used as a probe.
    #[tokio::test]
    async fn a_restricted_client_reaches_only_its_allowed_hosts() {
        use crate::auth::ClientAcl;

        let config = RoutingTable::new(vec![
            http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
            http_route("admin.iakl.top", &["http://10.0.0.9:9090"]),
        ]);
        let acl = ClientAcl::from_hosts(Some(&["api.iakl.top".to_string()]));

        // The allowed host reaches its own route.
        assert_eq!(
            config
                .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
                .await
                .backend()
                .expect("an allowed host reaches its route")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
        // A routed host the allowlist never named is refused, not served.
        assert!(
            config
                .get_backend_with_acl("admin.iakl.top", "/", None, Some(&acl))
                .await
                .is_no_route()
        );
        // So is an unrouted one: being on the allowlist does not conjure a
        // route for a host the server does not serve.
        assert!(
            config
                .get_backend_with_acl("typo.iakl.top", "/", None, Some(&acl))
                .await
                .is_no_route()
        );
    }

    /// A restricted client is served by routes, not by anything unnamed: a host
    /// on the allowlist with no route of its own is a 404, the same one an
    /// unrouted host gets, so the difference cannot be used as a probe.
    #[tokio::test]
    async fn a_restricted_client_needs_a_route_and_not_just_a_host() {
        use crate::auth::ClientAcl;

        let config = RoutingTable::new(vec![
            http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
            http_route("*", &["http://10.0.0.9:9000"]),
        ]);

        // `other.iakl.top` is on the allowlist and has no route of its own; the
        // catch-all matches it, and that is a route like any other, so the
        // allowlist is what decides.
        let acl = ClientAcl::from_hosts(Some(&[
            "api.iakl.top".to_string(),
            "other.iakl.top".to_string(),
        ]));
        assert_eq!(
            config
                .get_backend_with_acl("other.iakl.top", "/", None, Some(&acl))
                .await
                .backend()
                .expect("the allowlist names this host")
                .url
                .as_ref(),
            "http://10.0.0.9:9000"
        );

        // A host the allowlist never named is refused even though the catch-all
        // would serve it for anyone else.
        let narrow = ClientAcl::from_hosts(Some(&["api.iakl.top".to_string()]));
        assert!(
            config
                .get_backend_with_acl("other.iakl.top", "/", None, Some(&narrow))
                .await
                .is_no_route()
        );
        assert!(config.get_backend("other.iakl.top", "/").await.is_found());
    }

    #[test]
    fn host_matching_handles_wildcards() {
        let route = passthrough_route("*.iroh.iakl.top", &["caddy:443"]);
        assert!(route.matches_host("fn.iroh.iakl.top"));
        assert!(route.matches_host(".iroh.iakl.top"));
        assert!(!route.matches_host("iroh.iakl.top.bad.test"));

        let exact = passthrough_route("fn.iroh.iakl.top", &["caddy:443"]);
        assert!(exact.matches_host("fn.iroh.iakl.top"));
        assert!(!exact.matches_host("comfyui.iroh.iakl.top"));
    }

    /// A `Host` header is case-insensitive and may carry a fully-qualified
    /// trailing dot. Both spellings name the host the route was written for, so
    /// neither may slip past it and reach a different service entirely.
    #[tokio::test]
    async fn a_differently_spelled_host_still_reaches_its_route() {
        let config = RoutingTable::new(vec![http_route("api.iakl.top", &["http://10.0.0.5:8080"])]);

        for host in ["API.IAKL.TOP", "Api.Iakl.Top", "api.iakl.top."] {
            assert_eq!(
                config
                    .get_backend(host, "/")
                    .await
                    .backend()
                    .unwrap_or_else(|| panic!("host {host} must reach its route"))
                    .url
                    .as_ref(),
                "http://10.0.0.5:8080",
                "host {host} fell through to the default backend"
            );
        }

        // The pattern side is folded the same way, so a config written with
        // uppercase letters answers the lowercase request.
        let uppercase =
            RoutingTable::new(vec![http_route("API.Iakl.Top", &["http://10.0.0.7:8080"])]);
        assert_eq!(
            uppercase
                .get_backend("api.iakl.top", "/")
                .await
                .backend()
                .expect("the folded pattern matches the lowercase host")
                .url
                .as_ref(),
            "http://10.0.0.7:8080"
        );
    }

    /// The walk folds the host once, before it starts, and the route's own
    /// methods take the host that is already folded.
    ///
    /// A caller that hands one of them an unfolded name gets a quiet `false`
    /// rather than an error, so the precondition is pinned here: it is a fact
    /// about the API and not a comment.
    #[tokio::test]
    async fn the_route_is_asked_about_a_host_that_is_already_folded() {
        let route = http_route("api.iakl.top", &["http://10.0.0.5:8080"]);

        assert!(
            route.serves_host(&normalize_host("API.Iakl.Top.")),
            "the folded name reaches the route"
        );
        assert!(
            !route.serves_host("API.Iakl.Top."),
            "an unfolded name does not match, and says so by not matching"
        );

        assert!(
            route.serves_request(&normalize_host("API.Iakl.Top."), "/"),
            "the request is matched against the folded host too"
        );
        assert!(
            !route.serves_request("API.Iakl.Top.", "/"),
            "an unfolded name does not match the request either"
        );
    }

    /// The lookup-level view of the same rule for SNI and L4 hosts: both feed
    /// `matches_host`, so both are folded.
    #[tokio::test]
    async fn sni_and_l4_hosts_are_folded_the_same_way() {
        let config = RoutingTable::new(vec![
            passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
            l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None),
        ]);

        assert_eq!(
            config
                .get_passthrough_backend("FN.IROH.IAKL.TOP.")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy:443".to_string())
        );
        assert_eq!(
            config
                .get_l4_backend("DB.Iroh.Iakl.Top.", 5432, RouteMode::Tcp)
                .await
                .backend()
                .expect("the folded host reaches the L4 route")
                .backend,
            "10.0.0.50:5432"
        );
    }

    /// A reload keeps the pool of a route that did not change, which is what
    /// lets the health probe already running keep watching the pool traffic
    /// actually goes through.
    #[tokio::test]
    async fn a_reload_keeps_the_pool_of_a_route_that_did_not_change() {
        let config = RoutingTable::new(vec![http_route(
            "fn.iroh.iakl.top",
            &["http://10.0.0.5:8080"],
        )]);
        let before = config
            .routes()
            .await
            .first()
            .expect("one route")
            .backend_pool()
            .clone();

        // A reload of the very same table, which is what an edit to a second
        // route — or to any other section — looks like from here.
        config
            .update_routes(vec![http_route(
                "fn.iroh.iakl.top",
                &["http://10.0.0.5:8080"],
            )])
            .await;

        let after = config
            .routes()
            .await
            .first()
            .expect("one route")
            .backend_pool()
            .clone();

        assert!(
            Arc::ptr_eq(&before, &after),
            "an unchanged route must keep the pool it had, so its health probe stays attached"
        );
    }

    /// The counterpart: a route that now points elsewhere is a different pool,
    /// because a pool *is* the backends it dials.
    #[tokio::test]
    async fn a_route_that_changed_backends_gets_a_new_pool() {
        let config = RoutingTable::new(vec![http_route(
            "fn.iroh.iakl.top",
            &["http://10.0.0.5:8080"],
        )]);
        let before = config
            .routes()
            .await
            .first()
            .expect("one route")
            .backend_pool()
            .clone();

        config
            .update_routes(vec![http_route(
                "fn.iroh.iakl.top",
                &["http://10.0.0.9:8080"],
            )])
            .await;

        let after = config
            .routes()
            .await
            .first()
            .expect("one route")
            .backend_pool()
            .clone();

        assert!(
            !Arc::ptr_eq(&before, &after),
            "new backends mean a new pool, and the old probe has to be stopped"
        );
    }

    /// Two routes on one host, differing only in path, are not the same route
    /// and must not be treated as one — sharing a key would leave one of them
    /// without a health probe.
    #[tokio::test]
    async fn routes_sharing_a_host_are_still_different_routes() {
        let mut route = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
        let same_host_other_path = {
            let mut other = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
            other.path_pattern = "/api".to_string();
            other
        };

        assert_ne!(
            route.pool_key().await,
            same_host_other_path.pool_key().await
        );

        route.path_pattern = "/api".to_string();
        assert_eq!(
            route.pool_key().await,
            same_host_other_path.pool_key().await
        );
    }

    /// A pool is its backends *and* the way it picks between them, so a reload
    /// that changes only the strategy has to be a new pool. Keyed without it,
    /// the old pool was reused and the edit did nothing, with no log line to
    /// say why the traffic still went out the same way.
    #[tokio::test]
    async fn changing_only_the_strategy_is_a_different_pool() {
        let round_robin = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
        let random = Route::new(
            "fn.iroh.iakl.top",
            "/",
            true,
            vec!["http://10.0.0.5:8080".to_string()],
            LoadBalancingStrategy::Random,
            RouteMode::Http,
            None,
        );

        assert_ne!(round_robin.pool_key().await, random.pool_key().await);
    }

    /// The dot is what makes a wildcard a wildcard over *labels*. Without it
    /// the match is a bare `ends_with`, and a host that merely ends in the same
    /// letters — belonging to somebody else — is in.
    #[test]
    fn a_wildcard_stops_at_the_label_boundary() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));

        assert!(
            !host_matches("*.example.com", "notexample.com"),
            "a host that merely ends in the same letters is not under the wildcard"
        );
        assert!(
            !host_matches("*.example.com", "example.com"),
            "the apex is not under its own wildcard, the way DNS reads it"
        );
        assert!(host_matches("*", "anything.at.all"), "`*` is the catch-all");
    }

    /// A `*` with anything but a dot after it matches nothing: it is refused
    /// when the config loads, and whatever slipped past the check must not
    /// quietly match more than it says.
    #[test]
    fn a_wildcard_without_its_dot_matches_nothing() {
        assert!(!host_matches("*iakl.top", "eviliakl.top"));
        assert!(!host_matches("*iakl.top", "iakl.top"));
    }

    #[test]
    fn a_loose_wildcard_is_refused_when_the_config_loads() {
        assert!(pattern_error("*").is_none());
        assert!(pattern_error("*.example.com").is_none());
        assert!(pattern_error("example.com").is_none());

        let why = pattern_error("*iakl.top").expect("*iakl.top must be refused");
        assert!(why.contains("label boundary"), "{why}");
        assert!(
            pattern_error("").is_some(),
            "an empty pattern names nothing"
        );
    }

    /// An IPv6 literal carries colons of its own, so splitting on the first one
    /// does not leave a host behind — it leaves `[`, and every request to that
    /// host 404s.
    #[test]
    fn a_host_header_keeps_an_ipv6_literal_whole() {
        assert_eq!(host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(host_without_port("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(host_without_port("api.example.com:8080"), "api.example.com");
        assert_eq!(host_without_port("api.example.com"), "api.example.com");

        // What the routing table is asked about, brackets dropped.
        assert_eq!(normalize_host(host_without_port("[::1]:8080")), "::1");
        assert_eq!(normalize_host("[::1]"), "::1");
    }

    /// A name may carry more than one trailing dot. Stripping a single one left
    /// `a.example.com..` as `a.example.com.`, which is a different string than
    /// the route it names.
    #[test]
    fn every_trailing_dot_is_dropped() {
        assert_eq!(normalize_host("a.example.com"), "a.example.com");
        assert_eq!(normalize_host("a.example.com."), "a.example.com");
        assert_eq!(normalize_host("a.example.com.."), "a.example.com");
        assert_eq!(normalize_host("A.Example.COM.."), "a.example.com");
    }

    /// The tiers: an exact host outranks a wildcard no matter how long the
    /// wildcard's path is. They used to be one sum, so a path of 102 characters
    /// outweighed the host.
    #[test]
    fn an_exact_host_beats_any_path_length() {
        let long_path = "/".to_string() + &"x".repeat(200);
        let exact = Route::new(
            "api.example.com",
            "/",
            true,
            vec!["a".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            None,
        );
        let wildcard_with_a_long_path = Route::new(
            "*.example.com",
            &long_path,
            true,
            vec!["b".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            None,
        );

        assert!(exact.priority() > wildcard_with_a_long_path.priority());
    }

    /// Two tcp routes for one host: the one that names its ports wins for those
    /// ports, and the other one stays reachable for everything else. With no
    /// tie-break the first declared won for good and the second never matched.
    #[tokio::test]
    async fn a_route_that_names_its_ports_wins_over_one_that_takes_them_all() {
        let every_port = Route::new(
            "ssh.example.com",
            "/",
            true,
            vec!["fallback:22".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Tcp,
            None,
        );
        // Declared second on purpose: declaration order must not decide it.
        let only_443 = Route::new(
            "ssh.example.com",
            "/",
            true,
            vec!["tls-backend:443".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Tcp,
            None,
        )
        .with_l4_options(L4Options {
            client_ports: Some(vec![443]),
            idle_timeout: None,
            flow_timeout: None,
        });

        let config = RoutingTable::new(vec![every_port, only_443]);

        assert_eq!(
            config
                .get_l4_backend("ssh.example.com", 443, RouteMode::Tcp)
                .await
                .backend()
                .expect("port 443 has a route")
                .backend,
            "tls-backend:443"
        );
        // The catch-all is not shadowed: a port it was the only answer for
        // still reaches it.
        assert_eq!(
            config
                .get_l4_backend("ssh.example.com", 22, RouteMode::Tcp)
                .await
                .backend()
                .expect("port 22 falls to the catch-all")
                .backend,
            "fallback:22"
        );
    }

    /// A `*.suffix` wildcard is more specific than the bare `*`, so it wins in
    /// either declaration order. Two tiers put them level and the winner was
    /// whichever came first in the file — the thing tiers are for.
    #[tokio::test]
    async fn a_wildcard_host_beats_the_catch_all_in_either_order() {
        let catch_all = http_route("*", &["http://10.0.0.1:8080"]);
        let wildcard = http_route("*.example.com", &["http://10.0.0.2:8080"]);

        let catch_all_first = RoutingTable::new(vec![catch_all.clone(), wildcard.clone()]);
        assert_eq!(
            catch_all_first
                .get_backend("api.example.com", "/")
                .await
                .backend()
                .expect("the wildcard has a route")
                .url
                .as_ref(),
            "http://10.0.0.2:8080"
        );

        let wildcard_first = RoutingTable::new(vec![wildcard, catch_all]);
        assert_eq!(
            wildcard_first
                .get_backend("api.example.com", "/")
                .await
                .backend()
                .expect("the wildcard has a route")
                .url
                .as_ref(),
            "http://10.0.0.2:8080"
        );

        // The catch-all is not shadowed: it still answers everything else.
        assert_eq!(
            wildcard_first
                .get_backend("elsewhere.test", "/")
                .await
                .backend()
                .expect("the catch-all has a route")
                .url
                .as_ref(),
            "http://10.0.0.1:8080"
        );
    }

    /// The end-to-end shape of the same thing: a request for an IPv6 literal
    /// reaches the route written for that address.
    #[tokio::test]
    async fn a_request_for_an_ipv6_literal_reaches_its_route() {
        let config = RoutingTable::new(vec![http_route("::1", &["http://10.0.0.5:8080"])]);

        assert_eq!(
            config
                .get_backend(host_without_port("[::1]:8080"), "/")
                .await
                .backend()
                .expect("the literal host reaches the route")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
    }
    /// The port a `Host` header names, and the host it names beside it.
    ///
    /// The two are split the same way for every shape: an IPv6 literal keeps
    /// its brackets, and a header that names no port says so rather than
    /// guessing one.
    #[test]
    fn a_host_header_is_split_into_its_host_and_its_port() {
        assert_eq!(host_and_port("api.example.com"), ("api.example.com", None));
        assert_eq!(
            host_and_port("api.example.com:8443"),
            ("api.example.com", Some(8443))
        );
        assert_eq!(
            host_and_port("[::1]:8080"),
            ("[::1]", Some(8080)),
            "the brackets belong to the address and the port follows them"
        );
        assert_eq!(
            host_and_port("[::1]"),
            ("[::1]", None),
            "a literal with no port names no port"
        );
        assert_eq!(
            host_and_port("api.example.com:not-a-port"),
            ("api.example.com", None),
            "a port that does not parse is not a port"
        );
    }

    /// The host and the port are taken apart by one rule, so the two cannot
    /// disagree about where the host ends.
    #[test]
    fn the_host_is_the_same_whether_or_not_the_port_is_read() {
        for header in [
            "api.example.com",
            "api.example.com:8443",
            "[::1]",
            "[::1]:8080",
        ] {
            assert_eq!(
                host_without_port(header),
                host_and_port(header).0,
                "{header} splits one way"
            );
        }
    }

    /// A client that may reach a host on one port only is refused the other,
    /// and the refusal is the same 404 a host it may not reach gets — so the
    /// difference cannot be used to probe what exists.
    #[tokio::test]
    async fn a_port_the_acl_does_not_list_is_refused_the_way_a_host_is() {
        use crate::auth::ClientAcl;

        let config = RoutingTable::new(vec![http_route("api.iakl.top", &["http://10.0.0.5:8080"])]);
        let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));

        assert_eq!(
            config
                .get_backend_with_acl("api.iakl.top", "/", Some(443), Some(&acl))
                .await
                .backend()
                .expect("the port is on the list")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
        assert!(
            config
                .get_backend_with_acl("api.iakl.top", "/", Some(8443), Some(&acl))
                .await
                .is_no_route(),
            "a port the list does not name is refused"
        );
    }

    /// A request that names no port has no port to hold against the client:
    /// the proxy routes by host and ignores the port otherwise.
    #[tokio::test]
    async fn a_request_that_names_no_port_is_not_held_against_the_port_list() {
        use crate::auth::ClientAcl;

        let config = RoutingTable::new(vec![http_route("api.iakl.top", &["http://10.0.0.5:8080"])]);
        let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));

        assert_eq!(
            config
                .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
                .await
                .backend()
                .expect("no port was named, so none is refused")
                .url
                .as_ref(),
            "http://10.0.0.5:8080"
        );
    }
}
