use crate::config::CircuitBreaker;
use rand;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
    /// Fewest requests outstanding to this backend wins; see
    /// [`BackendPool::select_backend`] for what "outstanding" counts and what
    /// happens to the ties.
    LeastConn,
}

/// What is known about a backend that is **not** on the request's path.
///
/// The address and the health flag are not here: both are read on every
/// request, so they sit on the entry beside this, where reading them needs
/// no lock at all. What is left is the bookkeeping — when the backend was
/// last probed and how many times in a row it has failed — which is read by
/// the operator's view and by nobody on the hot path.
#[derive(Debug, Clone, Default)]
pub struct BackendStatus {
    last_check: Option<std::time::Instant>,
    consecutive_failures: usize,
}

impl BackendStatus {
    /// The backend is up.
    pub fn mark_healthy(&mut self) {
        self.consecutive_failures = 0;
        self.last_check = Some(std::time::Instant::now());
    }

    /// The backend is down.
    pub fn mark_unhealthy(&mut self) {
        self.consecutive_failures += 1;
        self.last_check = Some(std::time::Instant::now());
    }

    /// How many times in a row it has failed.
    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }

    /// When it was last probed.
    pub fn last_check(&self) -> Option<std::time::Instant> {
        self.last_check
    }
}

/// The scheme, the host and the port of a backend address, ready to be joined
/// to a path.
///
/// Parsed **once**, when the pool is built. A backend does not move, so the
/// answer does not either, and a `Url::parse` per request is a measurable
/// share of what a request costs.
///
/// The two failures are kept as they were written, because the request path
/// says them and the operator reads them there.
fn origin_of(url: &str) -> Result<Arc<str>, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid backend URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "backend URL missing host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    Ok(Arc::from(
        format!("{}://{host}:{port}", parsed.scheme()).as_str(),
    ))
}

/// One backend in the pool: its health, and how much work it has outstanding.
///
/// The two sit together because choosing between backends needs both, and not
/// behind one lock because they are not read the same way: health changes twice
/// an `interval` from one probe, while the load is touched on every flow. [`Self::in_flight`]
/// is atomic so that releasing it — which happens in a `Drop`, with no chance
/// to await anything — can always happen, and never waits behind a health probe.
#[derive(Debug)]
struct BackendEntry {
    /// The address, kept beside the health status so that the circuit can
    /// name the backend it is talking about without waiting on a lock.
    ///
    /// Shared, so that handing it to a request is a reference count rather
    /// than a copy: the address used to be cloned into every request that
    /// chose this backend.
    url: Arc<str>,
    /// The scheme, the host and the port of the address, ready to be joined
    /// to a path.
    ///
    /// **Parsed once, here**, when the pool is built: a backend does not
    /// move, and a `Url::parse` per request is a measurable share of what a
    /// request costs.
    ///
    /// The error is kept rather than thrown: a backend that cannot be parsed
    /// is reported when a request is built, where the operator can read it.
    origin: Result<Arc<str>, String>,
    /// Whether the backend is healthy.
    ///
    /// An **atomic**, because choosing a backend happens on every request and
    /// it is a read: it used to take the status lock, so a route with one
    /// backend paid a lock round trip per request for a flag.
    healthy: AtomicBool,
    status: RwLock<BackendStatus>,
    in_flight: AtomicUsize,
    /// The circuit this backend's failures are counted on.
    ///
    /// A plain mutex rather than the async lock the health status uses: the
    /// circuit is read and written on every request, and it never waits for
    /// anything.
    circuit: Mutex<CircuitState>,
    /// The settings the circuit runs with.
    ///
    /// Absent means the circuit is off — a pool built in code, rather than
    /// from a config, behaves as it always did. Set once, when the route is
    /// built.
    breaker: OnceLock<CircuitBreaker>,
}

/// Where a backend's circuit stands.
///
/// Two states, not three: a circuit is closed (traffic flows, failures are
/// counted) or open (the backend is out of rotation until the cooldown
/// passes). The trial request that the cooldown allows is not a state of its
/// own — it is a closed circuit that re-opens on the first failure instead of
/// on the fifth, which is the same rule with one fewer step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Closed,
    Open,
}

#[derive(Debug)]
struct CircuitState {
    phase: Phase,
    /// Consecutive failures, reset by a success.
    failures: usize,
    /// When the circuit opened, for the cooldown.
    opened_at: Option<std::time::Instant>,
}

impl CircuitState {
    fn new() -> Self {
        CircuitState {
            phase: Phase::Closed,
            failures: 0,
            opened_at: None,
        }
    }
}

impl BackendEntry {
    fn new(url: String) -> Self {
        let origin = origin_of(&url);
        BackendEntry {
            url: Arc::from(url.as_str()),
            origin: match origin {
                Ok(origin) => Ok(origin),
                Err(reason) => Err(reason),
            },
            healthy: AtomicBool::new(true),
            status: RwLock::new(BackendStatus::default()),
            in_flight: AtomicUsize::new(0),
            circuit: Mutex::new(CircuitState::new()),
            breaker: OnceLock::new(),
        }
    }

    /// The settings the circuit runs with, if it runs with any.
    fn breaker(&self) -> Option<&CircuitBreaker> {
        self.breaker.get()
    }

    /// Whether a request may be sent to this backend right now.
    ///
    /// An open circuit says no until its cooldown has passed. The check does
    /// not change the state: whether the request that gets through is the
    /// trial one is decided by what happens to it.
    fn circuit_allows(&self) -> bool {
        let Some(breaker) = self.breaker() else {
            return true;
        };
        if !breaker.enabled {
            return true;
        }
        let circuit = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
        match circuit.phase {
            Phase::Closed => true,
            Phase::Open => circuit
                .opened_at
                .map(|at| at.elapsed() >= breaker.reset)
                .unwrap_or(true),
        }
    }

    /// The backend answered.
    fn circuit_succeeded(&self) {
        let mut circuit = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
        circuit.phase = Phase::Closed;
        circuit.failures = 0;
        circuit.opened_at = None;
    }

    /// The backend did not answer.
    fn circuit_failed(&self) {
        let Some(breaker) = self.breaker() else {
            return;
        };
        if !breaker.enabled {
            return;
        }
        let mut circuit = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
        circuit.failures += 1;
        // A circuit that is open re-opens on the first failure: the trial
        // request that the cooldown let through failed, and the backend is
        // still down.
        if circuit.phase == Phase::Open || circuit.failures >= breaker.failure_threshold {
            circuit.phase = Phase::Open;
            circuit.opened_at = Some(std::time::Instant::now());
            tracing::warn!(
                "Backend {} failed {} time(s) in a row; it is out of rotation for {:?}",
                self.url,
                circuit.failures,
                breaker.reset
            );
        }
    }
}

/// A backend handed out for one flow.
///
/// Holding this is what makes `least_conn` true: `Drop` is where the backend's
/// load goes back down, so the caller decides when the work counts as finished
/// simply by deciding when to let go. A caller that releases early tells the
/// balancer the work is over; there is no second, mandatory step to forget.
///
/// That freedom has a failure mode — see the tie-breaking note on
/// [`BackendPool::select_backend`] for how the pick degrades rather than
/// stampedes when a lease is released too early.
pub struct BackendLease {
    entry: Arc<BackendEntry>,
}

impl BackendLease {
    /// The scheme, the host and the port of the address, ready to be joined
    /// to a path.
    ///
    /// Parsed once, when the pool was built.
    pub fn origin(&self) -> &Result<Arc<str>, String> {
        &self.entry.origin
    }

    /// The address this flow is to be forwarded to, shared.
    ///
    /// A reference to the pool's own copy, so that handing it to a request
    /// is a reference count and not a copy of the address.
    pub fn shared_url(&self) -> &Arc<str> {
        &self.entry.url
    }

    /// The address this flow is to be forwarded to.
    pub fn url(&self) -> &str {
        // The entry holds the address, so this is a borrow of it: the lease
        // used to keep a copy of its own, which was a heap allocation and a
        // lock read on every request.
        &self.entry.url
    }

    /// The backend answered.
    ///
    /// What the circuit counts: a backend that answers is a backend that is
    /// up, however slowly it answered.
    pub fn record_success(&self) {
        self.entry.circuit_succeeded();
    }

    /// The backend did not answer.
    ///
    /// What the circuit counts: a backend that refuses connections or that
    /// never sends a status line is a backend that is down, and after enough
    /// of those it stops being picked.
    pub fn record_failure(&self) {
        self.entry.circuit_failed();
    }
}

// Hand-written because the useful `Debug` for this is not its fields but what it
// is: an address, and how much work the pool thinks that address has.
impl std::fmt::Debug for BackendLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendLease")
            .field("url", &self.entry.url)
            .field("outstanding", &self.entry.in_flight.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for BackendLease {
    fn drop(&mut self) {
        self.entry.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct BackendPool {
    backends: Vec<Arc<BackendEntry>>,
    strategy: LoadBalancingStrategy,
    /// Where the rotation is, so that two requests do not pick the same
    /// backend.
    ///
    /// **An atomic, not a lock.** The whole of the round-robin's work is one
    /// increment, and it stood under an exclusive write lock — so every
    /// request to this route queued behind every other one for the sake of a
    /// counter, and the queue was an async one. The increment is the only
    /// thing that has to be exclusive, and an atomic increment is exclusive by
    /// itself.
    round_robin_index: Arc<AtomicUsize>,
}

impl BackendPool {
    pub fn new(backends: Vec<String>, strategy: LoadBalancingStrategy) -> Self {
        let backend_statuses = backends
            .into_iter()
            .map(|url| Arc::new(BackendEntry::new(url)))
            .collect();

        BackendPool {
            backends: backend_statuses,
            strategy,
            round_robin_index: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The settings the circuit on every backend of this pool runs with.
    ///
    /// Set once, when the route is built: a pool built in code — a test, the
    /// local proxy — has no circuit at all and behaves as it always did.
    pub fn set_circuit_breaker(&self, breaker: CircuitBreaker) {
        for backend in &self.backends {
            let _ = backend.breaker.set(breaker);
        }
    }

    /// Which backend a `least_conn` pool hands out, from a snapshot of every
    /// healthy backend's outstanding count.
    ///
    /// It takes a snapshot rather than the pool because the minimum and the tie
    /// have to come from the same reading of the counters, and only one reading
    /// can guarantee that — see the caller. Returns the chosen backend's index
    /// and how many backends tied at the least, so the caller can advance its
    /// cursor over the set it chose from.
    ///
    /// `counts` is never empty: a pool with no healthy backend either refuses
    /// or hands out its single entry before reaching here, so the tie — which
    /// always contains whoever holds the minimum, and the minimum comes from
    /// this same slice — is never empty either.
    fn least_conn_pick(counts: &[(usize, usize)], cursor: usize) -> (usize, usize) {
        debug_assert!(
            !counts.is_empty(),
            "a pool with nothing healthy answers before it reaches the balancer"
        );

        let least = counts
            .iter()
            .map(|(_, outstanding)| *outstanding)
            .min()
            .unwrap_or(0);
        let tied: Vec<usize> = counts
            .iter()
            .filter(|(_, outstanding)| *outstanding == least)
            .map(|(index, _)| *index)
            .collect();

        (tied[cursor % tied.len()], tied.len())
    }

    /// A backend to send this flow to, or `None` when the pool has nothing left
    /// to serve.
    ///
    /// One healthy backend is enough to get an answer, and the two unhappy cases
    /// are deliberately answered differently:
    ///
    /// - **Nothing healthy, one backend in the pool.** Handed out anyway. With
    ///   one candidate, health information buys nothing — there is no second
    ///   choice for it to inform — and refusing would take down the only path
    ///   this route has in order to report that the one path is unavailable.
    /// - **Nothing healthy, several backends.** `None`: all of them being down
    ///   *is* the answer, and dialling the first one regardless spends the whole
    ///   connect timeout writing the same `502`/refusal the caller can write now,
    ///   with nothing left to try afterwards.
    ///
    /// `None` from a **pool of one** therefore never happens, and from a pool of
    /// several it is not routeable — which is why callers must not collapse it
    /// into their own "no route" answer. See each caller in
    /// `crate::routes::RoutingTable`.
    pub async fn select_backend(&self) -> Option<BackendLease> {
        self.select_backend_excluding(&[]).await
    }

    /// A backend to send this flow to, preferring one that has not been tried
    /// yet.
    ///
    /// The exclusion list is what a retry is built on: a backend that just
    /// failed is the one most likely to fail again, so the next attempt asks
    /// somebody else — where the route has somebody else. A route with a
    /// single backend has nobody else to ask, and that backend is handed out
    /// again: there is no other answer to give, and a second attempt at the
    /// same backend is still better than none.
    pub async fn select_backend_excluding(&self, exclude: &[String]) -> Option<BackendLease> {
        // **One vector, filtered in place.** It used to be three — the healthy
        // ones, the ones whose circuit is not open, and the ones that have not
        // been tried — and each was a heap allocation on every request.
        let mut healthy_backends: Vec<usize> = Vec::new();
        for (i, b) in self.backends.iter().enumerate() {
            if b.healthy.load(Ordering::Relaxed) {
                healthy_backends.push(i);
            }
        }

        if healthy_backends.is_empty() {
            // A pool of one has nothing to choose between, so health is not
            // information here — it is a single backend that is either up, or
            // the only chance this request has.
            if self.backends.len() == 1 {
                let url = self.backends[0].url.clone();
                tracing::warn!(
                    "Backend {} is the only one behind this route and reports unhealthy; \
                     forwarding anyway, because refusing would answer for every request to it",
                    url
                );
                return Some(self.lease(0).await);
            }

            // Several, all down: the question has an answer now, and it does not
            // improve by dialling one of them.
            tracing::warn!(
                "No healthy backend among {} behind this route; refusing without dialling one",
                self.backends.len()
            );
            return None;
        }

        // The ones whose circuit is not open. A backend that keeps failing is
        // out of rotation until its cooldown passes: the route answers 503
        // rather than dialling a backend that is known to be down, which
        // spends a whole connect timeout to say the same thing.
        //
        // Filtered before the exclusion list, not after: an untried backend
        // whose circuit is open cannot be asked either, and preferring it over
        // a tried backend that is still serving would refuse a request that
        // has somewhere to go.
        let healthy_count = healthy_backends.len();
        healthy_backends.retain(|i| self.backends[*i].circuit_allows());
        if healthy_backends.len() < healthy_count {
            tracing::warn!(
                "{} of {healthy_count} healthy backend(s) behind this route are out of \
                 rotation; the circuit is open on them",
                healthy_count - healthy_backends.len(),
            );
        }
        if healthy_backends.is_empty() {
            // Every healthy backend has an open circuit. That is an answer:
            // the route is configured and nothing behind it is serving.
            return None;
        }

        // The ones that have not been tried yet, when there are any. A pool
        // whose every serving backend is on the list falls back to the whole
        // set, because the alternative is not to try at all.
        //
        // The address is the entry's own, so the comparison does not take the
        // status lock — it used to, once per backend.
        let any_untried = healthy_backends.iter().any(|i| {
            !exclude
                .iter()
                .any(|e| e.as_str() == &*self.backends[*i].url)
        });
        if any_untried {
            healthy_backends.retain(|i| {
                !exclude
                    .iter()
                    .any(|e| e.as_str() == &*self.backends[*i].url)
            });
        } else if !exclude.is_empty() {
            tracing::debug!(
                "Every serving backend behind this route has been tried; trying one of them \
                 again, because there is nobody else to ask"
            );
        }

        let idx = match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                // The counter is the whole of the state, and an atomic
                // increment is the whole of the work: two requests that arrive
                // together get two different numbers, and neither waits for
                // the other.
                let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed);
                healthy_backends[index % healthy_backends.len()]
            }
            LoadBalancingStrategy::Random => {
                let rand_idx = (rand::random::<u64>() % healthy_backends.len() as u64) as usize;
                healthy_backends[rand_idx]
            }
            LoadBalancingStrategy::LeastConn => {
                // Fewest requests outstanding wins. "Outstanding" is counted
                // from the moment a backend is chosen until the flow releases
                // its [`BackendLease`], which is wherever that flow decides the
                // work ended — response written by the HTTP paths, flow copied
                // by the tunnels and passthrough. It counts requests, not
                // sockets: an HTTP backend is reached through a pooled,
                // keep-alive client, and how many connections that pool is
                // holding open is not something this process can see.
                //
                // Ties rotate rather than taking the first index, because almost
                // every tie is "nothing is happening right now" — an idle proxy
                // is all zeroes — and taking the first index would then send
                // every request to the first healthy backend, which is the load
                // this strategy exists to spread. Rotating also means a lease
                // released too early costs a little accuracy instead of all of
                // it: worst case the balance degrades towards round-robin.
                //
                // The counts are read once, into one snapshot, and both the
                // least and the tie come out of it. Reading them twice — once
                // for the least, once for whoever is tied at it — lets a lease
                // released in between empty the tie: the only backend at the
                // least finishes, nothing is at the least any more, and a pool
                // that does have backends divides by a tie of zero.
                let counts: Vec<(usize, usize)> = healthy_backends
                    .into_iter()
                    .map(|i| (i, self.backends[i].in_flight.load(Ordering::Relaxed)))
                    .collect();

                // The tie is broken by the rotation, so that a pool of equal
                // backends does not send everything to the first one. The
                // counter is read and written rather than incremented, because
                // the tie's own size decides where the rotation continues; a
                // request that slips in between loses one step of the
                // rotation and nothing else — the backends it could have
                // chosen are tied.
                let index = self.round_robin_index.load(Ordering::Relaxed);
                let (idx, tied) = Self::least_conn_pick(&counts, index);
                self.round_robin_index
                    .store((index + 1) % tied, Ordering::Relaxed);
                idx
            }
        };

        let selected = self.lease(idx).await;
        let outstanding = self.backends[idx].in_flight.load(Ordering::Relaxed);
        tracing::debug!(
            "Selected backend: {} (strategy={:?}, outstanding={})",
            selected.url(),
            self.strategy,
            outstanding,
        );
        // Some, because reaching here means one was chosen; the `None`s above are
        // the cases where no choice exists at all.
        Some(selected)
    }

    /// Hands out one backend, counting it as outstanding from here until the
    /// lease is dropped.
    async fn lease(&self, idx: usize) -> BackendLease {
        // Indexed rather than looked up: every index handed here came out of
        // this same vector in the caller, and an out-of-range one panics here
        // rather than being quietly read as "no backend available".
        let entry = Arc::clone(&self.backends[idx]);
        entry.in_flight.fetch_add(1, Ordering::Relaxed);
        BackendLease { entry }
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn strategy(&self) -> LoadBalancingStrategy {
        self.strategy
    }

    pub async fn backends(&self) -> Vec<String> {
        let mut result = Vec::new();
        for b in &self.backends {
            result.push(b.url.to_string());
        }
        result
    }

    /// How many requests are outstanding against one backend right now.
    ///
    /// The number `least_conn` balances on, exposed so that what it counts
    /// can be checked rather than taken on trust: a backend that is streaming
    /// a response is busy, and one that answered and is waiting for the next
    /// request is not.
    pub async fn outstanding(&self, url: &str) -> usize {
        let mut count = 0;
        for backend in &self.backends {
            if &*backend.url == url {
                count += backend.in_flight.load(Ordering::Relaxed);
            }
        }
        count
    }

    /// How many backends are healthy right now.
    ///
    /// Reported rather than deduced from [`BackendPool::select_backend`], which
    /// still answers from a pool of one that is down — deliberately, see there —
    /// so "healthy" and "handed out" are not the same question and only this one
    /// answers the healthy half of it.
    pub async fn healthy_count(&self) -> usize {
        let mut count = 0;
        for backend in &self.backends {
            if backend.healthy.load(Ordering::Relaxed) {
                count += 1;
            }
        }
        count
    }

    pub async fn set_backend_health(&self, url: &str, healthy: bool) {
        // Every entry carrying this URL, not the first: a pool is allowed to
        // name the same backend twice, and stopping at the first left the rest
        // healthy forever — so the pool reported a backend as up while half its
        // entries were down and the balancer kept picking them.
        let mut matched = false;
        for backend in &self.backends {
            if &*backend.url != url {
                continue;
            }
            matched = true;
            // The flag first, then the bookkeeping: the flag is what the
            // request path reads, and it is read without a lock.
            backend.healthy.store(healthy, Ordering::Relaxed);
            let mut status = backend.status.write().await;
            if healthy {
                status.mark_healthy();
            } else {
                status.mark_unhealthy();
            }
            tracing::debug!(
                "Backend {} health status: {} (failures: {})",
                url,
                healthy,
                status.consecutive_failures()
            );
        }

        if !matched {
            tracing::debug!("set_backend_health: no backend named {url} in this pool");
        }
    }

    pub async fn get_backend_statuses(&self) -> Vec<(String, bool)> {
        let mut result = Vec::new();
        for b in &self.backends {
            result.push((b.url.to_string(), b.healthy.load(Ordering::Relaxed)));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(backends: &[&str]) -> BackendPool {
        BackendPool::new(
            backends.iter().map(|b| b.to_string()).collect(),
            LoadBalancingStrategy::RoundRobin,
        )
    }

    /// The origin of a backend address: the scheme, the host and the port.
    ///
    /// These are the cases the request path depends on, and each of them
    /// breaks in a way that only shows up at runtime: an IPv6 literal that
    /// loses its brackets makes the URI invalid, and a host that loses its
    /// port makes every request to that backend go to the wrong place.
    #[test]
    fn the_origin_keeps_the_scheme_the_host_and_the_port() {
        assert_eq!(&*origin_of("http://host:8080").unwrap(), "http://host:8080");
        assert_eq!(
            &*origin_of("https://host:8443").unwrap(),
            "https://host:8443"
        );
    }

    /// A backend address with no port is on the port its scheme says.
    ///
    /// `http://host` is port 80, and `https://host` is port 443 — the same
    /// rule `port_or_known_default()` applies, which is the rule the old
    /// expression applied too.
    #[test]
    fn the_origin_fills_in_the_port_of_the_scheme() {
        assert_eq!(&*origin_of("http://host").unwrap(), "http://host:80");
        assert_eq!(&*origin_of("https://host").unwrap(), "https://host:443");
    }

    /// An IPv6 literal keeps its brackets.
    ///
    /// `http://[::1]:8080` is the address of a backend on the loopback, and
    /// the origin has to keep the brackets: `http::Uri` reads
    /// `http://::1:8080` as a host with a port and a path, and the request
    /// never reaches the backend.
    #[test]
    fn the_origin_keeps_the_brackets_of_an_ipv6_literal() {
        assert_eq!(
            &*origin_of("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );
        assert_eq!(
            &*origin_of("http://[2001:db8::1]:80").unwrap(),
            "http://[2001:db8::1]:80"
        );
    }

    /// An address that does not parse is refused, and the reason says why.
    #[test]
    fn the_origin_refuses_an_address_that_does_not_parse() {
        let reason = origin_of("not a url").expect_err("the address does not parse");
        assert!(
            reason.starts_with("invalid backend URL:"),
            "the reason names the parse: {reason}"
        );
    }

    /// An address that names no host is refused, and the reason says why.
    ///
    /// A scheme that is not one of the special ones parses without a host,
    /// so this is the address that reaches the second failure.
    #[test]
    fn the_origin_refuses_an_address_that_names_no_host() {
        let reason = origin_of("custom://").expect_err("the address names no host");
        assert_eq!(reason, "backend URL missing host");
    }

    /// An address of a special scheme with no host does not parse at all.
    ///
    /// `http://` is refused by the parser, not by the host check, and the
    /// reason says so.
    #[test]
    fn the_origin_refuses_an_address_that_does_not_parse_at_all() {
        let reason = origin_of("http://").expect_err("the address does not parse");
        assert!(
            reason.starts_with("invalid backend URL:"),
            "the reason names the parse: {reason}"
        );
    }

    /// Same pool with another strategy. Every test below is about one strategy's
    /// choice, so which one it is should be the only thing spelled at its top.
    fn pool_with(strategy: LoadBalancingStrategy, backends: &[&str]) -> BackendPool {
        BackendPool::new(backends.iter().map(|b| b.to_string()).collect(), strategy)
    }

    #[tokio::test]
    async fn every_entry_carrying_a_url_is_marked_not_just_the_first() {
        let pool = pool(&["http://a:80", "http://a:80"]);
        assert_eq!(pool.healthy_count().await, 2);

        pool.set_backend_health("http://a:80", false).await;

        assert_eq!(
            pool.get_backend_statuses().await,
            vec![
                ("http://a:80".to_string(), false),
                ("http://a:80".to_string(), false),
            ],
            "the second entry stayed healthy, so the balancer kept picking a backend the pool had already given up on"
        );
        assert_eq!(pool.healthy_count().await, 0);
    }

    /// The one backend a route has is the one it serves, health or not: there is
    /// no second candidate for that information to choose between, and refusing
    /// would answer for every request to a route rather than let any through.
    #[tokio::test]
    async fn a_pool_of_one_is_handed_out_though_it_is_unhealthy() {
        let pool = pool(&["http://only:80"]);
        pool.set_backend_health("http://only:80", false).await;
        assert_eq!(pool.healthy_count().await, 0);

        let lease = pool
            .select_backend()
            .await
            .expect("a single backend is the only path this route has");
        assert_eq!(lease.url(), "http://only:80");
    }

    /// Several backends, none healthy: the answer is known before any dialling
    /// happens, so none is attempted. This is a behaviour change — it used to
    /// hand out the first one and let the client wait out a connect timeout.
    #[tokio::test]
    async fn a_pool_with_several_unhealthy_backends_refuses_without_dialling() {
        let pool = pool(&["http://a:80", "http://b:80"]);
        pool.set_backend_health("http://a:80", false).await;
        pool.set_backend_health("http://b:80", false).await;

        assert_eq!(pool.healthy_count().await, 0);
        assert!(
            pool.select_backend().await.is_none(),
            "every backend behind this route is down, so there is nothing to dial"
        );
    }

    /// An empty pool refuses, which cannot come from a config: `build_routes`
    /// rejects a route with no backends. Reached only by a pool built in code.
    #[tokio::test]
    async fn an_empty_pool_refuses() {
        let pool = pool(&[]);
        assert!(pool.select_backend().await.is_none());
    }

    #[tokio::test]
    async fn least_conn_sends_the_next_flow_to_whichever_backend_is_freer() {
        let pool = pool_with(
            LoadBalancingStrategy::LeastConn,
            &["http://a:80", "http://b:80"],
        );

        let busy = pool
            .select_backend()
            .await
            .expect("both backends are idle and healthy");
        // Still held: this backend has one flow against the other one's none.
        assert_eq!(busy.url(), "http://a:80");

        let next = pool
            .select_backend()
            .await
            .expect("a healthy backend remains");
        assert_eq!(
            next.url(),
            "http://b:80",
            "the first backend is still serving the flow it was handed out for"
        );

        // Now the scores are level, and the tie rotates — which is why this is
        // `least_conn` and not "one backend until somebody finishes".
        drop(busy);
        assert_eq!(
            pool.select_backend().await.unwrap().url(),
            "http://a:80",
            "A is free again while B still carries its flow, so A is next"
        );
    }

    /// What keeps `least_conn` from being worse than `RoundRobin`: nearly every
    /// tie is "nothing is running right now", and picking the lowest index would
    /// then send everything to the first backend — the load this strategy exists
    /// to spread.
    #[tokio::test]
    async fn least_conn_rotates_when_nothing_is_outstanding() {
        let pool = pool_with(
            LoadBalancingStrategy::LeastConn,
            &["http://a:80", "http://b:80"],
        );

        let first = pool.select_backend().await.unwrap().url().to_string();
        let second = pool.select_backend().await.unwrap().url().to_string();

        assert_eq!(
            (first.as_str(), second.as_str()),
            ("http://a:80", "http://b:80"),
            "both are idle, so the two picks should not land on the same backend"
        );
    }

    /// A circuit that opens on the second failure and stays open for a minute.
    fn breaker(threshold: usize) -> CircuitBreaker {
        CircuitBreaker {
            enabled: true,
            failure_threshold: threshold,
            reset: std::time::Duration::from_secs(60),
        }
    }

    /// A backend that keeps failing is out of rotation.
    ///
    /// The point of a circuit: the route stops dialling a backend that is
    /// known to be down, and answers instead of spending a connect timeout to
    /// find out what it already knows.
    #[tokio::test]
    async fn a_backend_that_keeps_failing_leaves_the_rotation() {
        let pool = pool(&["http://a:80"]);
        pool.set_circuit_breaker(breaker(2));

        let lease = pool.select_backend().await.expect("a backend");
        lease.record_failure();
        let lease = pool.select_backend().await.expect("a backend");
        lease.record_failure();

        assert!(
            pool.select_backend().await.is_none(),
            "the backend has failed twice in a row, so the circuit is open and it is not picked"
        );
    }

    /// A retry prefers a backend it has not tried, but a backend whose circuit
    /// is open is not a choice at all. When the only untried backend is out,
    /// the retry goes back to one that is still serving instead of refusing.
    #[tokio::test]
    async fn a_retry_does_not_let_an_open_circuit_hide_a_serving_backend() {
        let pool = pool(&["http://a:80", "http://b:80"]);
        pool.set_circuit_breaker(breaker(1));

        let first = pool.select_backend().await.expect("a backend");
        assert_eq!(first.url(), "http://a:80");
        let tried = first.url().to_string();
        drop(first);

        let second = pool.select_backend().await.expect("a backend");
        assert_eq!(second.url(), "http://b:80");
        second.record_failure();
        drop(second);

        let next = pool
            .select_backend_excluding(&[tried])
            .await
            .expect("A is still serving, so the retry has somewhere to go");
        assert_eq!(
            next.url(),
            "http://a:80",
            "the untried backend's open circuit must not hide the tried one that still serves"
        );
    }

    /// One failure is not enough: a backend that blipped once is still a
    /// backend.
    #[tokio::test]
    async fn one_failure_does_not_take_a_backend_out() {
        let pool = pool(&["http://a:80"]);
        pool.set_circuit_breaker(breaker(2));

        let lease = pool.select_backend().await.expect("a backend");
        lease.record_failure();

        assert!(
            pool.select_backend().await.is_some(),
            "one failure is a blip, not a verdict"
        );
    }

    /// A backend that answers is a backend that is up, and the circuit says
    /// so.
    #[tokio::test]
    async fn a_backend_that_answers_closes_the_circuit() {
        let pool = pool(&["http://a:80"]);
        pool.set_circuit_breaker(breaker(2));

        let lease = pool.select_backend().await.expect("a backend");
        lease.record_failure();
        let lease = pool.select_backend().await.expect("a backend");
        lease.record_success();

        // The failure count went back to zero, so the next failure is the
        // first one again and the backend stays in rotation.
        let lease = pool.select_backend().await.expect("a backend");
        lease.record_failure();
        assert!(
            pool.select_backend().await.is_some(),
            "the success reset the count, so one failure does not open the circuit"
        );
    }

    /// An open circuit lets a request through again once the cooldown has
    /// passed: the backend is given a chance to come back.
    #[tokio::test]
    async fn an_open_circuit_lets_a_request_through_after_the_cooldown() {
        let pool = pool(&["http://a:80"]);
        pool.set_circuit_breaker(CircuitBreaker {
            enabled: true,
            failure_threshold: 1,
            reset: std::time::Duration::from_millis(1),
        });

        let lease = pool.select_backend().await.expect("a backend");
        lease.record_failure();
        assert!(pool.select_backend().await.is_none(), "the circuit is open");

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert!(
            pool.select_backend().await.is_some(),
            "the cooldown has passed, so the backend is given another chance"
        );
    }

    /// A pool with no circuit behaves as it always did.
    #[tokio::test]
    async fn a_pool_without_a_circuit_keeps_every_backend() {
        let pool = pool(&["http://a:80"]);

        let lease = pool.select_backend().await.expect("a backend");
        lease.record_failure();
        lease.record_failure();
        lease.record_failure();

        assert!(
            pool.select_backend().await.is_some(),
            "a pool built in code has no circuit, so the backend stays in rotation"
        );
    }

    /// A lease nobody held any more has to have been released, or every later
    /// choice is made against a count that only ever grows.
    #[tokio::test]
    async fn dropping_a_lease_releases_the_backend() {
        let pool = pool_with(
            LoadBalancingStrategy::LeastConn,
            &["http://a:80", "http://b:80"],
        );

        let first = pool.select_backend().await.unwrap();
        drop(first);

        assert_eq!(
            pool.backends
                .iter()
                .map(|b| b.in_flight.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            vec![0, 0],
            "a dropped lease is finished work"
        );
    }

    #[test]
    fn least_conn_pick_takes_the_backend_with_the_least_outstanding() {
        assert_eq!(
            BackendPool::least_conn_pick(&[(0, 3), (1, 1), (2, 7)], 0),
            (1, 1),
            "one backend carries a single flow against three and seven"
        );
    }

    /// Ties rotate, and over the tied set rather than the whole pool: the caller
    /// advances its cursor by the number the pick reports, so three idle
    /// backends are walked in turn instead of the first one taking everything.
    #[test]
    fn least_conn_pick_rotates_through_every_backend_tied_at_the_least() {
        let counts = vec![(0, 0), (1, 0), (2, 0)];

        let picked: Vec<usize> = (0..4)
            .map(|cursor| BackendPool::least_conn_pick(&counts, cursor).0)
            .collect();
        assert_eq!(
            picked,
            vec![0, 1, 2, 0],
            "three idle backends, walked in turn"
        );

        // A unique minimum leaves nothing to rotate, however far the cursor has
        // run — and it reports a tie of one, not of zero.
        assert_eq!(
            BackendPool::least_conn_pick(&[(0, 9), (1, 4), (2, 9)], 41),
            (1, 1)
        );
    }

    /// The pick reads the counters once, so the least and the tie come from the
    /// same slice and whoever holds the least is always in the tie. Reading them
    /// twice let a lease released in between empty it: the only backend at the
    /// least finished, nothing was at the least any more, and a pool that did
    /// have backends divided by zero.
    #[test]
    fn least_conn_pick_always_leaves_something_to_choose_from() {
        let samples: Vec<Vec<(usize, usize)>> = vec![
            vec![(0, 0)],
            vec![(0, 5), (1, 5)],
            vec![(0, 1), (1, 2), (2, 3)],
            vec![(0, 3), (1, 2), (2, 1)],
            vec![(0, 0), (1, 9), (2, 0)],
            vec![(0, 7), (1, 7), (2, 7), (3, 6)],
        ];

        for counts in samples {
            let least = counts
                .iter()
                .map(|(_, outstanding)| *outstanding)
                .min()
                .unwrap();
            // `usize::MAX` included: the cursor is only ever taken modulo the
            // tie, so it must not be able to overflow its way out of one.
            for cursor in [0, 1, 2, 5, usize::MAX] {
                let (index, tied) = BackendPool::least_conn_pick(&counts, cursor);

                assert!(
                    tied >= 1,
                    "a tie of {tied} would divide by zero in the caller: {counts:?}"
                );
                let (_, outstanding) = counts
                    .iter()
                    .find(|(i, _)| *i == index)
                    .expect("the pick is one of the backends it was given");
                assert_eq!(
                    *outstanding, least,
                    "a backend that is not at the least was chosen from {counts:?}"
                );
            }
        }
    }
}
