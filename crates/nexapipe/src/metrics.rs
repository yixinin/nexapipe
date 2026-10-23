//! Instance metrics: what this process is doing, in Prometheus text format.
//!
//! # Why the format is written by hand
//!
//! The exposition format is a handful of lines per metric — `# HELP`, `# TYPE`,
//! then one `name{labels} value` per series — and everything behind it here is
//! an atomic integer. A registry crate would add a dependency, a `Cargo.lock`
//! change (CI builds with `--locked`) and an audit surface, to save the writing
//! of a `String`.
//!
//! # What is counted where
//!
//! Requests are recorded at the five places that answer one — three in
//! [`crate::conn`], two in [`crate::proxy`] — and **not** in
//! [`crate::log::log_access`], which looks like the one funnel but is not: the
//! L4 path calls it too, and what it counts there is a *flow*, a tunnel that
//! stays open for as long as the client wants, not a request. Mixing the two
//! would put long-lived flows in the same number as requests and leave both
//! unreadable, so flows have their own counter.
//!
//! Backend health is **not** instrumented at all. The pools already know the
//! answer, so it is read at exposition time from the live routing table; a
//! counter maintained by the probes could only drift from it.
//!
//! # Why latency is a histogram
//!
//! Request duration is exposed as fixed buckets rather than as the sum it used
//! to be, because the mean is the only question a sum answers and it is not the
//! one a proxy gets asked. The boundaries are fixed rather than fitted to what
//! has been served: two scrapes can only be compared if the boundaries are the
//! same in both, and a bucket edge that moves under a dashboard is worse than
//! one that was picked once and left alone.
//!
//! # Where bytes come from
//!
//! Bytes are counted on the **client leg** of every conversation and nowhere
//! else, which is the only place one number can mean one thing across paths
//! this different. `sent` is what reached a client, `received` is what a client
//! handed us.
//!
//! - **An HTTP response is not counted twice.** [`crate::http`] already counts
//!   what it delivered, because the access log prints it, and this module reads
//!   that number off the summary rather than looking at the wire again — two
//!   counts of one transfer are one count waiting to disagree with the other.
//!   What the summary carries includes the response head and any chunk framing,
//!   because that is what the client actually received.
//! - **A request is counted where it is assembled**: the head where it is
//!   parsed, the body as it is read — whole for a buffered body, and as it
//!   arrives for one that is streamed. One refused before its head finished is
//!   not counted, which is also what its access log line reports.
//! - **Tunnels** — TLS passthrough, L4 TCP, WebSocket after the handshake — are
//!   counted in [`crate::stream_util`], and a chunk is recorded only once it has
//!   left this process, so a write that failed reports nothing.
//! - **L4 UDP** keeps its own pair of loops and is counted there. Its framing is
//!   not: a datagram counts as its payload, the way every number here counts
//!   bytes an application would recognise.
//! - **The plaintext listener** records what it served and nothing else. It is a
//!   second entry point of a different shape, and `content-length` was always
//!   all it had.
//!
//! # One process, one set of counters
//!
//! These are process-wide by nature — there is one instance behind one set of
//! numbers — so they live in a `static` rather than being threaded through
//! every call that might want to record something. That is the same shape
//! [`crate::log`] uses for its access logger.
use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// When this process started, set by [`mark_start`].
///
/// `Instant` is monotonic, which is the point: a wall-clock reading would move
/// backwards the moment someone corrects the system clock.
static START: OnceLock<Instant> = OnceLock::new();

/// Records when the process started, so `nexapipe_uptime_seconds` has
/// something to count from. Called once, while the proxy is starting up;
/// before it runs the uptime is reported as zero rather than as a guess.
pub fn mark_start() {
    let _ = START.set(Instant::now());
}

/// Seconds since [`mark_start`], or zero if it has not run.
pub fn uptime_seconds() -> u64 {
    START
        .get()
        .map(|start| start.elapsed().as_secs())
        .unwrap_or(0)
}

/// The counters of one running instance.
pub struct Metrics {
    /// Connections accepted since startup, whatever happened to them.
    connections_total: AtomicU64,
    /// The per-peer connection ceiling the limiter refuses against, published
    /// so a dashboard can show headroom. Written once at startup.
    max_connections_per_peer: AtomicU64,
    /// The process-wide connection ceiling, likewise. `0` means "no global
    /// ceiling", which is how [`ConnectionLimiter::new`] leaves it.
    max_connections_global: AtomicU64,
    /// Connections by the kind of path they were last seen using. The sum of
    /// the three is the number of connections open right now, so there is no
    /// separate active counter that could disagree with it.
    direct: AtomicU64,
    relayed: AtomicU64,
    unknown: AtomicU64,
    /// Requests answered, by status class: `[1xx, 2xx, 3xx, 4xx, 5xx, other]`.
    requests: [AtomicU64; STATUS_CLASSES],
    /// Milliseconds spent answering them, summed.
    request_duration_ms: AtomicU64,
    /// Requests by how long they took: one counter per upper bound in
    /// [`DURATION_BUCKET_LE_MS`], **exclusive** — a request is counted in the
    /// narrowest bound it is under and nowhere else, and Prometheus's
    /// cumulative series is summed while rendering.
    ///
    /// Storing the cumulative counts instead would mean one request touching up
    /// to twelve counters, and a scrape that read between two of those updates
    /// would see a bucket go *down* as `le` rises: `le="10"` at 1 and
    /// `le="25"` at 0. A histogram whose buckets are not monotonic is one
    /// `histogram_quantile` has to repair before it can answer. Summing at
    /// render time cannot produce that, because the running total only ever
    /// grows as the loop walks the bounds.
    /// A request slower than the widest bound lands in none of them, which is
    /// why the `+Inf` series is rendered from the request count instead of
    /// being kept as one more bucket.
    request_duration_buckets: [AtomicU64; DURATION_BUCKETS],
    /// Bytes served to clients. See the module docs for where these come from.
    bytes_sent: AtomicU64,
    /// Bytes accepted from clients.
    bytes_received: AtomicU64,
    /// L4 flows by protocol and status class: `[tcp, udp][class]`.
    flows: [[AtomicU64; STATUS_CLASSES]; L4_PROTOS],
}

/// Status classes a response can fall into: `1xx` through `5xx` plus `other`.
const STATUS_CLASSES: usize = 6;

/// The two L4 protocols: `tcp` and `udp`.
const L4_PROTOS: usize = 2;

/// Label for an L4 flow's protocol, in the order of [`Metrics::flows`].
const L4_LABELS: [&str; L4_PROTOS] = ["tcp", "udp"];

/// Label for a response's status class, in the order of [`Metrics::requests`].
const CLASS_LABELS: [&str; STATUS_CLASSES] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

/// Upper bounds of the request-duration buckets, in milliseconds, ascending.
///
/// Spaced so that both halves of the range someone asks about are covered: a
/// few milliseconds apart while responses are fast enough to argue about, and
/// coarser once a request is slow enough that the difference between 4 and 5
/// seconds is not what anybody is measuring. `+Inf` is deliberately not here.
const DURATION_BUCKET_LE_MS: [u64; DURATION_BUCKETS] =
    [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

/// How many finite buckets [`DURATION_BUCKET_LE_MS`] defines.
///
/// Written out rather than taken from `DURATION_BUCKET_LE_MS.len()`, which
/// would be a cycle: the array's type is spelled with this. The two still
/// cannot drift — an array literal that does not match its declared length
/// does not compile.
const DURATION_BUCKETS: usize = 12;

/// The metrics of this process.
pub static METRICS: Metrics = Metrics::new();

impl Metrics {
    /// Every counter at zero.
    ///
    /// `const` so it can initialise the `static` above: no field may need code
    /// to run, which is why the arrays are written out instead of built by a
    /// loop.
    pub const fn new() -> Self {
        Self {
            connections_total: AtomicU64::new(0),
            max_connections_per_peer: AtomicU64::new(0),
            max_connections_global: AtomicU64::new(0),
            direct: AtomicU64::new(0),
            relayed: AtomicU64::new(0),
            unknown: AtomicU64::new(0),
            requests: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            request_duration_ms: AtomicU64::new(0),
            request_duration_buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            flows: [
                [
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                ],
                [
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                ],
            ],
        }
    }

    /// Records one accepted connection.
    pub fn connection_opened(&self) {
        // Relaxed throughout: these are counters. Nothing is ordered by reading
        // them, and a scrape that lands a millisecond early simply reports the
        // number as it was a millisecond ago.
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records the ceilings the limiter refuses connections against.
    ///
    /// Written once, when the endpoint is built, because that is when the caps
    /// are resolved from the environment. A `usize::MAX` global — the shape
    /// [`ConnectionLimiter::new`](crate::conn::limits::ConnectionLimiter::new)
    /// builds — is published as `0` rather than as 18446744073709551615: a
    /// scrape cannot tell "unlimited" from "a number too large to be a real
    /// limit", and `0` is what a dashboard should divide by
    /// to mean *do not alarm on this one*.
    pub fn record_connection_limits(&self, per_peer: usize, global: usize) {
        let per_peer = u64::try_from(per_peer).unwrap_or(u64::MAX);
        let global = match u64::try_from(global) {
            Ok(n) if n < u64::MAX => n,
            _ => 0,
        };
        self.max_connections_per_peer
            .store(per_peer, Ordering::Relaxed);
        self.max_connections_global.store(global, Ordering::Relaxed);
    }

    /// Records one answered request and how long it took.
    ///
    /// `status` is what the client was actually answered with, which is not
    /// always what the backend replied: a failure after the head went out is
    /// logged with the partial response's status, not as a 502.
    pub fn record_request(&self, status: u16, duration_ms: u64) {
        self.requests[status_class(status)].fetch_add(1, Ordering::Relaxed);
        self.request_duration_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
        // One counter, the narrowest bound that holds the duration. These are
        // exclusive counts and the cumulative series Prometheus wants is summed
        // as the exposition walks the bounds — see the field, and the reason
        // there, for why the addition is not done here.
        //
        // `partition_point` needs the slice sorted, which this const is, and
        // answers with the index of the first entry that is *not* below the
        // duration. Something slower than every bound comes back as the length,
        // so the `get` below answers `None` and the request lands in `+Inf`
        // only — which is what `+Inf` is for.
        let index = DURATION_BUCKET_LE_MS.partition_point(|le| *le < duration_ms);
        if let Some(bucket) = self.request_duration_buckets.get(index) {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records one L4 flow that ended, with the status it was answered with.
    /// `proto` is `"tcp"` or `"udp"`; anything else is counted as `tcp`, which
    /// is the more useful wrong answer of the two.
    pub fn record_l4_flow(&self, proto: &str, status: u16) {
        let proto = match proto.to_ascii_lowercase().as_str() {
            "udp" => 1,
            _ => 0,
        };
        self.flows[proto][status_class(status)].fetch_add(1, Ordering::Relaxed);
    }

    /// Records bytes served to a client.
    pub fn record_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Records bytes accepted from a client.
    pub fn record_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /// Records `n` bytes that crossed one leg of a tunnel.
    pub fn record_tunnel_bytes(&self, leg: CopyLeg, n: u64) {
        match leg {
            CopyLeg::Client => self.record_bytes_received(n),
            CopyLeg::Backend => self.record_bytes_sent(n),
        }
    }

    /// Connections open right now.
    ///
    /// Derived from the path buckets rather than kept separately: two counts of
    /// the same thing is one count waiting to disagree with the other.
    pub fn connections_active(&self) -> u64 {
        self.direct.load(Ordering::Relaxed)
            + self.relayed.load(Ordering::Relaxed)
            + self.unknown.load(Ordering::Relaxed)
    }

    /// Requests answered, every class summed.
    ///
    /// Derived from the class counters rather than counted again: the
    /// histogram's `_count` and its `+Inf` series are both this number, and a
    /// third counter kept alongside them is a counter waiting to disagree.
    fn requests_total(&self) -> u64 {
        self.requests
            .iter()
            .map(|class| class.load(Ordering::Relaxed))
            .sum()
    }

    /// Every counter as values, in the shape the management surface reads.
    ///
    /// Deliberately not a second rendering of [`Metrics::render`]: that one
    /// produces Prometheus text for a scraper, while this one is read by
    /// `nexapipe status` and printed as JSON. The numbers are the same and are
    /// read from the same atomics, so the two cannot disagree; only the shape
    /// differs, and parsing exposition text back into values to get at them
    /// would be the wrong way round.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            connections_total: self.connections_total.load(Ordering::Relaxed),
            connections_active: self.connections_active(),
            connections_direct: self.direct.load(Ordering::Relaxed),
            connections_relayed: self.relayed.load(Ordering::Relaxed),
            connections_unknown: self.unknown.load(Ordering::Relaxed),
            requests_by_class: CLASS_LABELS
                .iter()
                .enumerate()
                .map(|(class, label)| {
                    (
                        (*label).to_string(),
                        self.requests[class].load(Ordering::Relaxed),
                    )
                })
                .collect(),
            request_duration_ms: self.request_duration_ms.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            l4_flows: L4_LABELS
                .iter()
                .enumerate()
                .flat_map(|(proto, proto_label)| {
                    CLASS_LABELS.iter().enumerate().map(move |(class, label)| {
                        (
                            (*proto_label).to_string(),
                            (*label).to_string(),
                            self.flows[proto][class].load(Ordering::Relaxed),
                        )
                    })
                })
                .collect(),
        }
    }

    /// Renders every metric in the Prometheus text exposition format.
    ///
    /// `view` carries what is read from live state rather than counted —
    /// in-flight work and backend health — because those belong to objects this
    /// module has no access to, and passing them in leaves the ownership where
    /// it already is.
    pub fn render(&self, view: &InstanceView) -> String {
        let mut out = String::with_capacity(2048);

        gauge(
            &mut out,
            "nexapipe_up",
            "1 while this instance is serving.",
            1,
        );
        gauge(
            &mut out,
            "nexapipe_uptime_seconds",
            "Seconds since the process started.",
            uptime_seconds(),
        );
        counter(
            &mut out,
            "nexapipe_connections_total",
            "Connections accepted since startup.",
            self.connections_total.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "nexapipe_connections_active",
            "Connections open right now.",
            self.connections_active(),
        );

        // The two ceilings the limiter refuses connections against, so a
        // dashboard can show headroom rather than only the current count.
        // Without them an operator sees "active: 4096" and cannot tell a
        // server at its budget from a server at half of it.
        gauge(
            &mut out,
            "nexapipe_connections_limit_per_peer",
            "Concurrent connections one peer may hold; a connection past this is refused.",
            self.max_connections_per_peer.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "nexapipe_connections_limit_global",
            "Concurrent connections the whole process may hold; a connection past this is refused \
             whatever the peer is at.",
            self.max_connections_global.load(Ordering::Relaxed),
        );

        // One series per path kind under a single HELP and TYPE: that is what
        // makes them one metric with a label instead of three metrics a
        // dashboard has to be told about separately.
        let _ = writeln!(
            out,
            "# HELP nexapipe_connections_by_path Connections by the kind of network path they \
             currently use. Direct means hole punching succeeded; relayed means traffic crosses \
             a relay server."
        );
        let _ = writeln!(out, "# TYPE nexapipe_connections_by_path gauge");
        for (kind, label) in [
            (PathKind::Direct, "direct"),
            (PathKind::Relay, "relayed"),
            (PathKind::Unknown, "unknown"),
        ] {
            let _ = writeln!(
                out,
                "nexapipe_connections_by_path{{kind=\"{label}\"}} {}",
                self.bucket(kind).load(Ordering::Relaxed)
            );
        }

        let _ = writeln!(
            out,
            "# HELP nexapipe_requests_total Requests answered, by status class."
        );
        let _ = writeln!(out, "# TYPE nexapipe_requests_total counter");
        for (index, label) in CLASS_LABELS.iter().enumerate() {
            let _ = writeln!(
                out,
                "nexapipe_requests_total{{status_class=\"{label}\"}} {}",
                self.requests[index].load(Ordering::Relaxed)
            );
        }

        // A histogram rather than the sum this used to be. The sum is still
        // here as `_sum` — the counter it replaced carried the same number
        // under a name a histogram cannot have — but on its own it could only
        // answer "what is the mean", and not one of them is what a proxy gets
        // asked. Buckets are cumulative the way `histogram_quantile` expects:
        // a request is counted in every bound it is under, not in the range it
        // falls into.
        let _ = writeln!(
            out,
            "# HELP nexapipe_request_duration_ms How long requests took to answer, in milliseconds."
        );
        let _ = writeln!(out, "# TYPE nexapipe_request_duration_ms histogram");
        // Cumulative, summed from the exclusive counts as the bounds are walked
        // out, so every series is at least the one before it however many
        // requests land mid-scrape.
        let mut cumulative = 0u64;
        for (index, le) in DURATION_BUCKET_LE_MS.iter().enumerate() {
            cumulative += self.request_duration_buckets[index].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "nexapipe_request_duration_ms_bucket{{le=\"{le}\"}} {cumulative}"
            );
        }
        // Every request is inside `+Inf`, including one slower than the widest
        // finite bound, so this series is the request count rather than a
        // bucket of its own — as is `_count`, for the same reason.
        //
        // Clamped to what the bounds above have counted: `record_request` raises
        // the class counter first and the bucket second, both relaxed, so on a
        // weakly ordered machine a scrape can read the second without the first
        // and count fewer requests than the buckets hold. Read that way, `+Inf`
        // and `_count` would come out below the widest finite bound — exactly
        // the descending series the exclusive counts are stored to avoid.
        let requests = self.requests_total().max(cumulative);
        let _ = writeln!(
            out,
            "nexapipe_request_duration_ms_bucket{{le=\"+Inf\"}} {requests}"
        );
        let _ = writeln!(
            out,
            "nexapipe_request_duration_ms_sum {}",
            self.request_duration_ms.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "nexapipe_request_duration_ms_count {requests}");

        // One metric with a label rather than two counters: they are the same
        // number seen from either side, and a dashboard should be able to ask
        // for both without being told there are two.
        let _ = writeln!(
            out,
            "# HELP nexapipe_traffic_bytes_total Bytes that crossed the client leg of a \
             connection. Sent reached the client; received came from it."
        );
        let _ = writeln!(out, "# TYPE nexapipe_traffic_bytes_total counter");
        for (label, value) in [
            ("sent", self.bytes_sent.load(Ordering::Relaxed)),
            ("received", self.bytes_received.load(Ordering::Relaxed)),
        ] {
            let _ = writeln!(
                out,
                "nexapipe_traffic_bytes_total{{direction=\"{label}\"}} {value}"
            );
        }

        let _ = writeln!(
            out,
            "# HELP nexapipe_l4_flows_total L4 flows that ended, by protocol and status."
        );
        let _ = writeln!(out, "# TYPE nexapipe_l4_flows_total counter");
        for (proto, classes) in L4_LABELS.iter().zip(self.flows.iter()) {
            for (index, label) in CLASS_LABELS.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "nexapipe_l4_flows_total{{proto=\"{proto}\",status_class=\"{label}\"}} {}",
                    classes[index].load(Ordering::Relaxed)
                );
            }
        }

        gauge(
            &mut out,
            "nexapipe_backends_up",
            "Backends currently in rotation.",
            view.backends_up as u64,
        );
        gauge(
            &mut out,
            "nexapipe_backends_down",
            "Backends taken out of rotation by failed health checks.",
            view.backends_down as u64,
        );
        gauge(
            &mut out,
            "nexapipe_in_flight",
            "Connections the process is still holding, which a shutdown waits for.",
            view.in_flight as u64,
        );

        let _ = writeln!(
            out,
            "# HELP nexapipe_build_info One series identifying the build."
        );
        let _ = writeln!(out, "# TYPE nexapipe_build_info gauge");
        let _ = writeln!(
            out,
            "nexapipe_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );

        out
    }

    fn bucket(&self, kind: PathKind) -> &AtomicU64 {
        match kind {
            PathKind::Direct => &self.direct,
            PathKind::Relay => &self.relayed,
            PathKind::Unknown => &self.unknown,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Every counter of one instance, as values rather than as exposition text.
///
/// Produced by [`Metrics::snapshot`] for `GET /v1/status`.
pub struct Snapshot {
    /// Connections accepted since startup, whatever happened to them.
    pub connections_total: u64,
    /// Connections open right now.
    pub connections_active: u64,
    /// Of those, the ones whose path is a direct UDP address.
    pub connections_direct: u64,
    /// Of those, the ones crossing a relay.
    pub connections_relayed: u64,
    /// Of those, the ones with no path selected yet.
    pub connections_unknown: u64,
    /// Requests answered, as `(status class, count)`.
    pub requests_by_class: Vec<(String, u64)>,
    /// Milliseconds spent answering them, summed.
    pub request_duration_ms: u64,
    /// Bytes served to clients, counted on the client leg. See the module docs.
    pub bytes_sent: u64,
    /// Bytes accepted from clients, counted the same way.
    pub bytes_received: u64,
    /// L4 flows that ended, as `(protocol, status class, count)`.
    pub l4_flows: Vec<(String, String, u64)>,
}

/// What is read from live state at exposition time rather than counted.
pub struct InstanceView {
    pub in_flight: usize,
    pub backends_up: usize,
    pub backends_down: usize,
}

/// How a connection reaches its peer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathKind {
    /// Hole punching succeeded: packets go straight to the peer's address.
    Direct,
    /// Traffic crosses a relay server.
    Relay,
    /// No path is selected yet, or it is neither of the above.
    Unknown,
}

/// One connection's place in the `connections_by_path` buckets.
///
/// Held by the task that follows a connection's path events and given back by
/// its `Drop`: a connection ends in more ways than it has returns — peer gone,
/// stream error, task cancelled — and a `Drop` is the one thing that cannot be
/// forgotten at any of them.
pub struct PathTicket {
    metrics: &'static Metrics,
    kind: PathKind,
}

impl PathTicket {
    /// Counts one connection on [`METRICS`].
    pub fn new(kind: PathKind) -> Self {
        Self::on(&METRICS, kind)
    }

    /// Counts one connection on `metrics`. Split out so a test can count on a
    /// static of its own instead of sharing the process-wide one with whatever
    /// else is running.
    pub fn on(metrics: &'static Metrics, kind: PathKind) -> Self {
        metrics.bucket(kind).fetch_add(1, Ordering::Relaxed);
        Self { metrics, kind }
    }

    /// Moves the connection to another bucket, because the path it uses
    /// changed. A connection typically starts relayed and becomes direct once
    /// hole punching succeeds, and counting it in both buckets would report
    /// two connections where there is one.
    pub fn set(&mut self, kind: PathKind) {
        if kind != self.kind {
            self.metrics
                .bucket(self.kind)
                .fetch_sub(1, Ordering::Relaxed);
            self.metrics.bucket(kind).fetch_add(1, Ordering::Relaxed);
            self.kind = kind;
        }
    }
}

impl Drop for PathTicket {
    fn drop(&mut self) {
        self.metrics
            .bucket(self.kind)
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Which leg of a tunnel a copied chunk came from.
///
/// A copy loop knows which way it is pumping but not what that means to anyone
/// counting, so it hands the leg back instead of deciding. `stream_util` is
/// generic over two *streams* and deliberately not over what they are: passing
/// this is how the answer stays "bytes from a client" rather than "bytes from
/// whichever argument came first".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CopyLeg {
    /// Read off the client: bytes this process accepted.
    Client,
    /// Read off the backend: bytes this process serves to the client.
    Backend,
}

impl CopyLeg {
    /// How this leg names itself in a debug log.
    pub fn label(self) -> &'static str {
        match self {
            Self::Client => "client->backend",
            Self::Backend => "backend->client",
        }
    }
}

/// Which of [`CLASS_LABELS`] a status belongs to.
///
/// `1xx` through `5xx` by the hundreds digit. Anything else — a status of `0`
/// where nothing was answered at all, or a code outside the ranges HTTP
/// defines — lands in `other` rather than being forced into a bucket it is not
/// in.
fn status_class(status: u16) -> usize {
    match status / 100 {
        1 => 0,
        2 => 1,
        3 => 2,
        4 => 3,
        5 => 4,
        _ => 5,
    }
}

fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counters for one test, so a test that moves a connection between buckets
    /// cannot see what another test is doing.
    static TEST_METRICS: Metrics = Metrics::new();

    /// Nothing live, for the tests that only read counters.
    fn empty_view() -> InstanceView {
        InstanceView {
            in_flight: 0,
            backends_up: 0,
            backends_down: 0,
        }
    }

    /// A status class has to survive the statuses the server can actually
    /// produce, including the ones that are not HTTP: the L4 path answers with
    /// a status byte of its own, and `0` is what a request nobody answered is
    /// logged with.
    #[test]
    fn every_status_lands_in_a_class() {
        assert_eq!(CLASS_LABELS[status_class(101)], "1xx");
        assert_eq!(CLASS_LABELS[status_class(200)], "2xx");
        assert_eq!(CLASS_LABELS[status_class(404)], "4xx");
        assert_eq!(CLASS_LABELS[status_class(502)], "5xx");
        assert_eq!(CLASS_LABELS[status_class(0)], "other");
        assert_eq!(CLASS_LABELS[status_class(600)], "other");
    }

    /// The exposition format is line-based and a scraper is strict about it:
    /// every metric needs a `# TYPE`, and a labelled one carries its label on
    /// every series.
    #[test]
    fn every_metric_is_declared_before_it_is_used() {
        let metrics = Metrics::new();
        let view = InstanceView {
            in_flight: 0,
            backends_up: 0,
            backends_down: 0,
        };
        let body = metrics.render(&view);

        for name in [
            "nexapipe_up",
            "nexapipe_uptime_seconds",
            "nexapipe_connections_total",
            "nexapipe_connections_active",
            "nexapipe_connections_by_path",
            "nexapipe_requests_total",
            "nexapipe_request_duration_ms",
            "nexapipe_traffic_bytes_total",
            "nexapipe_l4_flows_total",
            "nexapipe_backends_up",
            "nexapipe_backends_down",
            "nexapipe_in_flight",
            "nexapipe_build_info",
        ] {
            assert!(
                body.contains(&format!("# TYPE {name} ")),
                "{name} has no # TYPE line in:\n{body}"
            );
        }

        assert!(body.contains("nexapipe_connections_by_path{kind=\"direct\"} 0"));
        assert!(body.contains("nexapipe_connections_by_path{kind=\"relayed\"} 0"));
        assert!(body.contains("nexapipe_requests_total{status_class=\"2xx\"} 0"));
        assert!(body.contains("nexapipe_traffic_bytes_total{direction=\"sent\"} 0"));
        assert!(body.contains("nexapipe_traffic_bytes_total{direction=\"received\"} 0"));
        assert!(body.contains("nexapipe_l4_flows_total{proto=\"udp\",status_class=\"4xx\"} 0"));
        assert!(body.contains("nexapipe_request_duration_ms_bucket{le=\"1\"} 0"));
        assert!(body.contains("nexapipe_request_duration_ms_bucket{le=\"+Inf\"} 0"));
        assert!(body.contains("nexapipe_request_duration_ms_sum 0"));
        assert!(body.contains("nexapipe_request_duration_ms_count 0"));
    }

    /// The two directions are separate numbers about the same transfer, so each
    /// has to accumulate without touching the other — otherwise "how much did
    /// we serve" and "how much did we take" would be answers to one question.
    #[test]
    fn the_two_directions_count_independently_and_cumulatively() {
        let metrics = Metrics::new();
        assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), 0);

        metrics.record_bytes_sent(1200);
        metrics.record_bytes_sent(300);
        metrics.record_bytes_received(64);

        assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), 1500);
        assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 64);
    }

    /// A tunnel reports its two legs as the two directions, which is the whole
    /// reason [`CopyLeg`] exists: the loop that knows the direction is not the
    /// place that knows what it means.
    #[test]
    fn a_tunnels_two_legs_land_in_the_two_directions() {
        let metrics = Metrics::new();
        metrics.record_tunnel_bytes(CopyLeg::Client, 40);
        metrics.record_tunnel_bytes(CopyLeg::Backend, 9000);

        assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 40);
        assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), 9000);

        assert_eq!(CopyLeg::Client.label(), "client->backend");
        assert_eq!(CopyLeg::Backend.label(), "backend->client");
    }

    /// A request is counted in its own class and nowhere else, which is the only
    /// way "how many 5xx" stays a number someone can act on.
    #[test]
    fn a_request_is_counted_once_in_its_own_class() {
        let metrics = Metrics::new();
        metrics.record_request(200, 12);
        metrics.record_request(502, 3);

        assert_eq!(
            metrics.requests[status_class(200)].load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.requests[status_class(502)].load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.requests[status_class(404)].load(Ordering::Relaxed),
            0
        );
        assert_eq!(metrics.request_duration_ms.load(Ordering::Relaxed), 15);
    }

    /// A bucket is cumulative: one request of 7 ms is inside `le="10"` and every
    /// bound above it, and outside `le="5"`. A bucket that counted only its own
    /// range would not fail — `histogram_quantile` would answer with the wrong
    /// quantile and nothing would say so.
    #[test]
    fn a_duration_is_counted_in_every_bound_it_is_under() {
        let metrics = Metrics::new();
        metrics.record_request(200, 7);

        let body = metrics.render(&empty_view());

        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"5\"} 0"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"10\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"25\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"10000\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"+Inf\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_count 1"),
            "{body}"
        );
    }

    /// Two requests in different bounds, and the counters hold each of them
    /// once: the buckets are stored exclusive and summed on the way out.
    ///
    /// Storing the cumulative counts instead would put the 7 ms request in
    /// eleven counters, and a scrape reading between two of those updates would
    /// see a bucket go down as `le` rises — `le="10"` at one, `le="25"` at
    /// zero — which is not a histogram `histogram_quantile` can read. Summing
    /// as the bounds are walked cannot do that, whatever lands mid-scrape.
    #[test]
    fn a_request_lands_in_one_bucket_and_the_series_is_cumulative_on_the_way_out() {
        let metrics = Metrics::new();
        metrics.record_request(200, 7);
        metrics.record_request(200, 300);

        let stored: Vec<u64> = metrics
            .request_duration_buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .collect();
        assert_eq!(
            stored.iter().sum::<u64>(),
            2,
            "each request belongs to one bucket: {stored:?}"
        );

        let body = metrics.render(&empty_view());
        let mut previous = 0;
        for le in DURATION_BUCKET_LE_MS {
            let series = format!("nexapipe_request_duration_ms_bucket{{le=\"{le}\"}} ");
            let value: u64 = body
                .lines()
                .find_map(|line| line.strip_prefix(&series))
                .and_then(|rest| rest.trim().parse().ok())
                .unwrap_or_else(|| panic!("no {series}series in {body}"));
            assert!(
                value >= previous,
                "le=\"{le}\" is {value}, less than the bound before it"
            );
            previous = value;
        }
        assert_eq!(previous, 2, "the widest bound holds both requests: {body}");
    }

    /// A request slower than the widest finite bound is still counted. It is
    /// inside `+Inf` and inside nothing else, and letting it fall out of the
    /// histogram entirely would leave `_count` disagreeing with
    /// `nexapipe_requests_total`.
    #[test]
    fn a_duration_past_the_widest_bound_is_still_counted() {
        let metrics = Metrics::new();
        let past = DURATION_BUCKET_LE_MS[DURATION_BUCKETS - 1] + 1;
        metrics.record_request(200, past);
        metrics.record_request(200, 3);

        let body = metrics.render(&empty_view());

        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"10000\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"+Inf\"} 2"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_count 2"),
            "{body}"
        );
        assert!(
            body.contains(&format!("nexapipe_request_duration_ms_sum {}", past + 3)),
            "{body}"
        );
    }

    /// `+Inf` and `_count` are the request count, and they may never come out
    /// below the widest finite bucket. `record_request` raises the class counter
    /// before the bucket and both are relaxed, so a scrape racing a record can
    /// read the bucket without the count that came with it. That window is far
    /// too narrow to hit on purpose, so the state is written by hand instead:
    /// three requests counted in a bucket, none of them in a class yet.
    #[test]
    fn the_request_count_is_never_below_the_widest_bound() {
        let metrics = Metrics::new();
        metrics.request_duration_buckets[0].store(3, Ordering::Relaxed);

        let body = metrics.render(&empty_view());

        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"10000\"} 3"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_bucket{le=\"+Inf\"} 3"),
            "{body}"
        );
        assert!(
            body.contains("nexapipe_request_duration_ms_count 3"),
            "{body}"
        );
    }

    /// A connection that changes path stays counted once: relayed, then direct,
    /// is one connection, not two — and it stops being counted when it ends,
    /// however it ends.
    #[test]
    fn a_connection_that_changes_path_is_still_counted_once() {
        let mut ticket = PathTicket::on(&TEST_METRICS, PathKind::Relay);
        assert_eq!(TEST_METRICS.connections_active(), 1);

        ticket.set(PathKind::Direct);
        assert_eq!(TEST_METRICS.connections_active(), 1);

        drop(ticket);
        assert_eq!(TEST_METRICS.connections_active(), 0);
    }
}
