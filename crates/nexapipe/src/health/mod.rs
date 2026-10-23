use crate::config::BackendProtocol;
use crate::http::BackendClients;
use crate::lb::BackendPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{Duration, sleep};

/// A fraction of `interval` to wait before the first round of probes, so
/// checkers that start together do not stay in lockstep for the life of the
/// process.
///
/// Derived from the clock instead of a random number: it is a scheduling
/// detail, not a security property, and this way it costs no dependency and no
/// shared state. Two checkers get different values because time has moved on
/// between them.
fn startup_jitter(interval: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since_epoch| since_epoch.subsec_nanos() as u128)
        .unwrap_or(0);

    let span = interval.as_nanos().max(1);
    let jitter = (nanos % span).min(u64::MAX as u128) as u64;
    Duration::from_nanos(jitter)
}

/// What a probe does to decide whether a backend answers.
///
/// `Http` is the only mode that can answer a question, so it is the only one
/// that gets asked one: `GET {health_path}`. Everything else gets a TCP
/// connect, which is deliberately a smaller claim — it proves something is
/// listening on the port, and it says nothing about whether the thing behind it
/// works. A TLS listener accepts the connection and is then hung up on mid-
/// handshake, and a UDP backend cannot be probed at all without speaking
/// whatever protocol it serves, so a `udp`-only route gets no probe rather
/// than a fake one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeKind {
    /// `GET` the configured health path.
    ///
    /// The path belongs to this variant and not to the checker, because the TCP
    /// probe has no use for one — carrying it alongside would be a field that
    /// only means something half the time. The protocol is here for the same
    /// reason: it is how the HTTP question is asked, and a TCP probe does not
    /// ask it.
    Http {
        path: String,
        protocol: BackendProtocol,
    },
    /// Connect, then close. Liveness, not health.
    Tcp,
}

/// What one route wants probed: the pool its traffic goes through, and how to
/// ask.
///
/// The two belong together because a probe is only worth running on the pool
/// traffic actually uses, and only in the mode that pool's backends can answer.
/// Carrying them separately is how a reload ends up asking the HTTP question of
/// a backend that never speaks HTTP.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub pool: Arc<BackendPool>,
    pub kind: ProbeKind,
}

pub struct HealthChecker {
    backend_pool: Arc<BackendPool>,
    clients: Arc<BackendClients>,
    interval: Duration,
    timeout: Duration,
    failure_threshold: usize,
    kind: ProbeKind,
    /// Shared with the config watcher so `[health_check] enabled` can be
    /// switched while the process runs: a probe already spawned outlives the
    /// reload that would otherwise have to cancel it, so it is paused instead.
    enabled: Arc<AtomicBool>,
    /// Consecutive failed probes per backend, kept here because a `BackendPool`
    /// only stores the outcome. A backend leaves the pool once this reaches
    /// `failure_threshold` and returns on the first probe that succeeds.
    failures: Mutex<HashMap<String, usize>>,
}

impl HealthChecker {
    pub fn new(
        backend_pool: Arc<BackendPool>,
        clients: Arc<BackendClients>,
        interval: Duration,
        timeout: Duration,
        failure_threshold: usize,
        kind: ProbeKind,
        enabled: Arc<AtomicBool>,
    ) -> Self {
        HealthChecker {
            backend_pool,
            clients,
            interval,
            timeout,
            failure_threshold: failure_threshold.max(1),
            kind,
            failures: Mutex::new(HashMap::new()),
            enabled,
        }
    }

    pub async fn run(self) {
        tracing::info!(
            "Health checker started with interval={:?}, timeout={:?}, threshold={}",
            self.interval,
            self.timeout,
            self.failure_threshold
        );

        // Every checker is spawned as soon as the config is loaded, so without
        // this one server sends a probe per route at the same instant — and
        // then again every `interval`, forever, because nothing ever moves them
        // apart. Waiting a random part of the first interval spreads them.
        let jitter = startup_jitter(self.interval);
        if !jitter.is_zero() {
            tracing::debug!("Health checker waiting {:?} before its first round", jitter);
            sleep(jitter).await;
        }

        loop {
            // Paused, not cancelled: `[health_check] enabled = false` on a
            // reload stops the probing without having to reach into every
            // checker. Being cancelled is a different question — that is what
            // `HealthProbes::stop_stale` does when the route itself is gone.
            if self.enabled.load(Ordering::Relaxed) {
                self.check_all_backends().await;
            }
            sleep(self.interval).await;
        }
    }

    async fn check_all_backends(&self) {
        let backends = self.backend_pool.backends().await;

        // The statuses are read **once** for the round.
        //
        // They used to be read inside the loop, which meant the whole table
        // was read again for every backend in it: a quadratic number of lock
        // reads and string copies for one round of probes, every interval.
        // The table is the same for the whole round — a probe reports, it does
        // not change the state — so one read is the same answer as N of them.
        //
        // The one thing that does change it is this loop's own writes, so the
        // snapshot follows them: a pool is allowed to name the same backend
        // twice, and the second time round the answer has to be the one the
        // first time round left behind, not the one the round started with.
        let mut statuses: HashMap<String, bool> = self
            .backend_pool
            .get_backend_statuses()
            .await
            .into_iter()
            .collect();

        for url in backends {
            let is_healthy = self.check_backend(&url).await;
            let failures = self.record_result(&url, is_healthy);
            let current_healthy = statuses.get(&url).copied();

            if is_healthy {
                if current_healthy == Some(false) {
                    tracing::info!("Backend {} recovered, marking healthy", url);
                    self.backend_pool.set_backend_health(&url, true).await;
                    statuses.insert(url.clone(), true);
                }
                continue;
            }

            // One failed probe proves little, so the count, not the failure,
            // is what empties the pool.
            if failures < self.failure_threshold {
                tracing::debug!(
                    "Backend {} health check failed ({}/{})",
                    url,
                    failures,
                    self.failure_threshold
                );
                continue;
            }

            if current_healthy != Some(false) {
                tracing::warn!(
                    "Backend {} failed {} consecutive health checks, marking unhealthy",
                    url,
                    failures
                );
                self.backend_pool.set_backend_health(&url, false).await;
                statuses.insert(url.clone(), false);
            }
        }
    }

    /// Counts consecutive failures for one backend and returns the new count.
    /// A success resets it, so a backend that flaps once is not punished for a
    /// failure that happened an hour ago.
    fn record_result(&self, url: &str, healthy: bool) -> usize {
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if healthy {
            failures.remove(url);
            0
        } else {
            let count = failures.get(url).copied().unwrap_or(0) + 1;
            failures.insert(url.to_string(), count);
            count
        }
    }

    async fn check_backend(&self, url: &str) -> bool {
        match &self.kind {
            ProbeKind::Http { path, protocol } => self.check_http(url, path, *protocol).await,
            ProbeKind::Tcp => self.check_tcp(url).await,
        }
    }

    /// Connects and closes: is anything listening.
    ///
    /// The backend string is parsed with the same function the passthrough and
    /// L4 paths dial with, so a probe cannot accept a backend the route itself
    /// would fail to connect to — and cannot disagree with it about what the
    /// address is.
    async fn check_tcp(&self, url: &str) -> bool {
        let Some((host, port)) = crate::passthrough::parse_backend_addr(url) else {
            // A backend the route could never dial is not one that answered.
            tracing::error!(
                "Health check for {} cannot be dialled: not a host and a port",
                url
            );
            return false;
        };

        match tokio::time::timeout(
            self.timeout,
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        {
            // Dropped straight away. Anything more would be speaking the
            // protocol, which is the one thing this probe is not doing.
            Ok(Ok(_stream)) => {
                tracing::debug!("Backend {} accepted a connection", url);
                true
            }
            Ok(Err(e)) => {
                tracing::debug!("Backend {} refused a connection: {}", url, e);
                false
            }
            Err(_) => {
                tracing::debug!("Backend {} did not answer a connection", url);
                false
            }
        }
    }

    async fn check_http(&self, url: &str, health_path: &str, protocol: BackendProtocol) -> bool {
        let health_url = format!("{}{}", url, health_path);

        // `health_path` comes from the config, and a character the URI parser
        // rejects used to panic here — which took the whole probe loop down
        // with it and left every backend on this route marked healthy for the
        // rest of the run, with nothing in the log saying why. A backend whose
        // check cannot be built is not one that answered, so it fails.
        let request = match hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(&health_url)
            .header("host", "health-check")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
        {
            Ok(request) => request,
            Err(e) => {
                tracing::error!(
                    "Health check for {} cannot be built from path {:?}: {}",
                    url,
                    health_path,
                    e
                );
                return false;
            }
        };

        let client = self.clients.for_protocol(protocol);
        let request =
            request.map(|body| crate::http::full_body(body.into_inner().unwrap_or_default()));
        match tokio::time::timeout(self.timeout, client.request(request)).await {
            Ok(Ok(response)) => {
                let status = response.status();
                // Treat 2xx and 404 as healthy: some backends don't implement
                // a dedicated health endpoint and return 404 for unknown paths,
                // which still indicates the server is up and responding.
                let healthy = status.is_success() || status.as_u16() == 404;
                // Per-result details stay at debug: the check runs on every tick, so a backend
                // that is down would otherwise log this once per interval. The state changes
                // that actually matter are logged in `check_all_backends`.
                if healthy {
                    tracing::debug!("Backend {} health check passed: {}", url, status);
                } else {
                    tracing::debug!("Backend {} health check failed: {}", url, status);
                }
                healthy
            }
            Ok(Err(e)) => {
                tracing::debug!("Backend {} health check error: {}", url, e);
                false
            }
            Err(_) => {
                tracing::debug!("Backend {} health check timed out", url);
                false
            }
        }
    }
}

/// The probes the process has running, and the pool each one is watching.
///
/// Keyed by a route's [`crate::routes::Route::pool_key`], and the pool is
/// kept beside the handle because that is what separates the two things a
/// reload can find: the route is still there (same pool, leave the probe
/// alone) or the route was rebuilt (new pool, and a probe on the old one is
/// now marking backends up and down where no traffic can see it, while
/// nothing probes the pool traffic actually goes through).
pub struct HealthProbes {
    running: HashMap<String, (Arc<BackendPool>, tokio::task::JoinHandle<()>)>,
}

impl HealthProbes {
    pub fn new() -> Self {
        Self {
            running: HashMap::new(),
        }
    }

    /// Whether a probe for this route is already running.
    pub fn contains(&self, key: &str) -> bool {
        self.running.contains_key(key)
    }

    pub fn is_empty(&self) -> bool {
        self.running.is_empty()
    }

    /// Stops every probe whose route is gone, or whose pool has been replaced.
    ///
    /// A route deleted from the config has no reason to keep being probed, and
    /// one that changed its backends gets a new pool and therefore a new
    /// probe — the old task would otherwise outlive the process's interest in
    /// it, since nothing else owns it.
    pub fn stop_stale(&mut self, wanted: &HashMap<String, ProbeTarget>) {
        let same_pool = |key: &String, pool: &Arc<BackendPool>| {
            wanted
                .get(key)
                .is_some_and(|target| Arc::ptr_eq(&target.pool, pool))
        };
        for (key, (pool, handle)) in self.running.iter() {
            if !same_pool(key, pool) {
                handle.abort();
            }
        }
        self.running.retain(|key, (pool, _)| same_pool(key, pool));
    }

    /// Starts a probe and keeps its handle, so it can be stopped later.
    pub fn spawn(&mut self, key: String, pool: Arc<BackendPool>, checker: HealthChecker) {
        let handle = tokio::spawn(async move { checker.run().await });
        self.running.insert(key, (pool, handle));
    }
}

impl Default for HealthProbes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http;
    use crate::lb::LoadBalancingStrategy;
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A port nothing listens on: the probe fails immediately, with no network
    /// and no server to stand up.
    const DEAD_BACKEND: &str = "http://127.0.0.1:1";

    fn checker(
        pool: Arc<BackendPool>,
        threshold: usize,
        enabled: Arc<AtomicBool>,
    ) -> HealthChecker {
        HealthChecker::new(
            pool,
            Arc::new(
                http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                    .expect("the default trust store is always usable"),
            ),
            Duration::from_millis(10),
            Duration::from_millis(200),
            threshold,
            ProbeKind::Http {
                path: "/health".to_string(),
                protocol: BackendProtocol::Http1,
            },
            enabled,
        )
    }

    /// A checker that asks a port instead of a path, over a pool the caller
    /// built for it.
    fn tcp_checker(pool: Arc<BackendPool>) -> HealthChecker {
        HealthChecker::new(
            pool,
            Arc::new(
                http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                    .expect("the default trust store is always usable"),
            ),
            Duration::from_millis(10),
            Duration::from_millis(500),
            1,
            ProbeKind::Tcp,
            Arc::new(AtomicBool::new(true)),
        )
    }

    fn pool() -> Arc<BackendPool> {
        Arc::new(BackendPool::new(
            vec![DEAD_BACKEND.to_string()],
            LoadBalancingStrategy::RoundRobin,
        ))
    }

    fn target(pool: Arc<BackendPool>, kind: ProbeKind) -> ProbeTarget {
        ProbeTarget { pool, kind }
    }

    fn http_probe() -> ProbeKind {
        ProbeKind::Http {
            path: "/health".to_string(),
            protocol: BackendProtocol::Http1,
        }
    }

    async fn healthy(pool: &BackendPool, url: &str) -> bool {
        pool.get_backend_statuses()
            .await
            .into_iter()
            .find(|(u, _)| u == url)
            .map(|(_, h)| h)
            .unwrap_or(false)
    }

    /// A probe is only worth keeping while its route still wants one on that
    /// same pool: a route that was rebuilt gets a new pool, and a probe left
    /// behind on the old one would keep marking backends up and down where no
    /// traffic can see it, while nothing probes the pool traffic uses.
    #[tokio::test]
    async fn a_probe_is_only_kept_while_its_route_keeps_the_same_pool() {
        let pool = pool();
        let mut probes = HealthProbes::new();
        probes.spawn(
            "key".to_string(),
            pool.clone(),
            checker(pool.clone(), 1, Arc::new(AtomicBool::new(false))),
        );
        assert!(probes.contains("key"));

        // The route is unchanged: same key, same pool, probe stays.
        let mut wanted = HashMap::new();
        wanted.insert("key".to_string(), target(pool.clone(), http_probe()));
        probes.stop_stale(&wanted);
        assert!(probes.contains("key"), "an unchanged route keeps its probe");

        // Same key, but the backends changed and with them the pool: the probe
        // is now watching a pool the routing table no longer hands out.
        let rebuilt = Arc::new(BackendPool::new(
            vec!["http://10.0.0.9:8080".to_string()],
            LoadBalancingStrategy::RoundRobin,
        ));
        wanted.insert("key".to_string(), target(rebuilt, http_probe()));
        probes.stop_stale(&wanted);
        assert!(
            probes.is_empty(),
            "a rebuilt pool means the old probe is stopped"
        );

        // A route deleted from the config has no reason to be probed either.
        probes.spawn(
            "key".to_string(),
            pool.clone(),
            checker(pool.clone(), 1, Arc::new(AtomicBool::new(false))),
        );
        probes.stop_stale(&HashMap::new());
        assert!(probes.is_empty(), "a removed route stops being probed");
    }

    /// Every checker starts when the config loads, so the first round is the
    /// one that lands on every backend at once. The jitter only has to be
    /// somewhere inside the interval — not zero, not the whole thing.
    #[test]
    fn the_first_round_is_spread_over_the_interval() {
        let interval = Duration::from_secs(10);
        let jitter = startup_jitter(interval);
        assert!(
            jitter < interval,
            "{jitter:?} must stay inside {interval:?}"
        );

        // Two checkers built back to back must not agree, or the spreading
        // would have done nothing.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            seen.insert(startup_jitter(interval).as_nanos());
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(seen.len() > 1, "every checker waited the same {seen:?}");
    }

    #[test]
    fn a_zero_interval_waiting_is_not_a_jitter() {
        // Reachable only through a direct call, but the guard is what keeps
        // `run()` from sleeping on an interval that is already zero.
        assert!(startup_jitter(Duration::ZERO).is_zero());
    }

    /// A passthrough or L4 backend answers no HTTP request, so the probe for one
    /// is a connection: something listening is the whole claim it can make.
    #[tokio::test]
    async fn a_tcp_probe_reaches_a_port_that_is_listening() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a local port needs no network");
        let backend = listener.local_addr().unwrap().to_string();

        let pool = Arc::new(BackendPool::new(
            vec![backend.clone()],
            LoadBalancingStrategy::RoundRobin,
        ));
        tcp_checker(pool.clone()).check_all_backends().await;

        assert!(
            healthy(&pool, &backend).await,
            "a port that accepted the connection answers"
        );
    }

    /// The same probe against a port nothing listens on: `127.0.0.1:1` refuses
    /// at once, so this needs no network either.
    #[tokio::test]
    async fn a_tcp_probe_fails_a_port_nothing_listens_on() {
        let backend = "127.0.0.1:1".to_string();
        let pool = Arc::new(BackendPool::new(
            vec![backend.clone()],
            LoadBalancingStrategy::RoundRobin,
        ));
        tcp_checker(pool.clone()).check_all_backends().await;

        assert!(
            !healthy(&pool, &backend).await,
            "a connection nobody accepted is not a backend that answered"
        );
    }

    /// A backend string the route itself could not dial must fail the probe
    /// rather than be skipped: failing is how it reaches the operator.
    #[tokio::test]
    async fn a_tcp_probe_fails_a_backend_that_is_not_an_address() {
        let backend = "not a host and a port".to_string();
        let pool = Arc::new(BackendPool::new(
            vec![backend.clone()],
            LoadBalancingStrategy::RoundRobin,
        ));
        tcp_checker(pool.clone()).check_all_backends().await;

        assert!(
            !healthy(&pool, &backend).await,
            "a backend that cannot be dialled has not answered"
        );
    }

    #[tokio::test]
    async fn one_failed_probe_never_takes_a_backend_out() {
        let pool = pool();
        let checker = checker(pool.clone(), 3, Arc::new(AtomicBool::new(true)));

        checker.check_all_backends().await;

        assert!(
            healthy(&pool, DEAD_BACKEND).await,
            "a single failed probe must not empty the pool"
        );
    }

    #[tokio::test]
    async fn the_threshold_is_what_takes_a_backend_out() {
        let pool = pool();
        let checker = checker(pool.clone(), 2, Arc::new(AtomicBool::new(true)));

        checker.check_all_backends().await;
        assert!(healthy(&pool, DEAD_BACKEND).await);

        checker.check_all_backends().await;
        assert!(
            !healthy(&pool, DEAD_BACKEND).await,
            "two consecutive failures reached the threshold"
        );
    }

    /// A backend that answers the first request and fails the second, so that
    /// a round which probes it twice sees it change state under its own feet.
    ///
    /// The answers are counted, not timed: the first request is answered with
    /// a 200 and every one after it with a 500, so which probe sees which
    /// answer does not depend on how fast the machine is.
    async fn flapping_backend() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a local port needs no network");
        let url = format!("http://{}", listener.local_addr().unwrap());

        let server = tokio::spawn(async move {
            let mut answered = 0u32;
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                answered += 1;
                let status = if answered == 1 {
                    "200 OK"
                } else {
                    "500 Internal Server Error"
                };

                // The request is read before the answer is written: a client
                // that is still writing when the answer arrives would see a
                // reset instead of the status.
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let response =
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        (url, server)
    }

    /// A pool is allowed to name the same backend twice, so one round probes
    /// it twice.
    ///
    /// The status the round reads has to be the status the round itself
    /// wrote: a backend that recovers and fails again inside one round has to
    /// end that round marked unhealthy, because the last probe is the one that
    /// counts. Reading the status once and never updating it left the round
    /// believing the backend was still unhealthy, and the second probe's
    /// failure was dropped on the floor.
    #[tokio::test]
    async fn a_backend_named_twice_ends_the_round_marked_by_its_last_probe() {
        let (backend, _server) = flapping_backend().await;
        let pool = Arc::new(BackendPool::new(
            vec![backend.clone(), backend.clone()],
            LoadBalancingStrategy::RoundRobin,
        ));

        // The round starts with the backend down, so that the first probe —
        // which the server answers — is the one that recovers it.
        pool.set_backend_health(&backend, false).await;

        let checker = checker(pool.clone(), 1, Arc::new(AtomicBool::new(true)));
        checker.check_all_backends().await;

        assert!(
            !healthy(&pool, &backend).await,
            "the second probe failed, so the backend ends the round marked unhealthy"
        );
    }

    /// The same round, with the backend down from the start and staying down:
    /// the status is written once, and the failure is counted once.
    ///
    /// The end of the round is not enough to tell a round that marked the
    /// backend once from a round that marked it twice — both leave it
    /// unhealthy. The pool is asked instead, because the pool is what was
    /// marked: a backend that is marked unhealthy twice in one round is
    /// counted twice, and the count is the transition itself.
    #[tokio::test]
    async fn a_backend_named_twice_is_marked_once_per_round() {
        let backend = DEAD_BACKEND.to_string();
        let pool = Arc::new(BackendPool::new(
            vec![backend.clone(), backend.clone()],
            LoadBalancingStrategy::RoundRobin,
        ));
        let checker = checker(pool.clone(), 1, Arc::new(AtomicBool::new(true)));

        checker.check_all_backends().await;

        assert!(
            !healthy(&pool, &backend).await,
            "a failed probe at the threshold empties the pool"
        );
        assert_eq!(
            pool.backend_failures(&backend).await,
            Some(1),
            "one backend is marked unhealthy once per round, not once per probe of it"
        );
    }

    #[tokio::test]
    async fn disabling_the_check_leaves_the_pool_alone() {
        let pool = pool();
        let enabled = Arc::new(AtomicBool::new(false));
        let checker = checker(pool.clone(), 1, enabled.clone());

        // Through `run`, because that is where the switch lives — the loop never
        // returns, so it is spawned rather than awaited.
        tokio::spawn(async move { checker.run().await });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            healthy(&pool, DEAD_BACKEND).await,
            "a disabled checker must not probe at all"
        );

        // What a reload that turns `[health_check] enabled` back on does.
        enabled.store(true, Ordering::Relaxed);

        // Waited for rather than slept a fixed time through. The loop probes
        // every 10 ms here, but it first waits out a random part of that
        // interval (`startup_jitter`), and a runner slower than the one this
        // was written on can need longer than 150 ms to get one round done —
        // which is what it did on windows-latest the first time the tests ran
        // there. A deadline keeps the assertion, that enabling the check starts
        // probing again, and drops the assumption about how fast the machine
        // is. The 100 ms above stays a sleep: "it never probed" is an absence,
        // and an absence can only be read over a window.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut probed = false;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if !healthy(&pool, DEAD_BACKEND).await {
                probed = true;
                break;
            }
        }
        assert!(probed, "enabling the check starts probing again");
    }

    #[tokio::test]
    async fn a_health_path_that_cannot_be_a_uri_fails_the_probe() {
        // A character the URI parser rejects used to panic here, which took the
        // probe loop down and left every backend on the route marked healthy
        // for the rest of the run.
        let checker = HealthChecker::new(
            pool(),
            Arc::new(
                http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                    .expect("the default trust store is always usable"),
            ),
            Duration::from_millis(10),
            Duration::from_millis(200),
            1,
            ProbeKind::Http {
                path: "/health check".to_string(),
                protocol: BackendProtocol::Http1,
            },
            Arc::new(AtomicBool::new(true)),
        );

        assert!(
            !checker.check_backend(DEAD_BACKEND).await,
            "a check that cannot be built is not one that was answered"
        );
    }
}
