//! The names this process has resolved, and how long the answer holds.
//!
//! Every L4 flow and every TLS passthrough dials a backend by **name**, and
//! the name was resolved again for every one of them. The resolution is a
//! `getaddrinfo` on a blocking thread, and it sits on the critical path of
//! the flow: the client waits for the flow to be open before it sends
//! anything, and the server cannot open the flow before it knows where the
//! backend is.
//!
//! So the answers are cached, for a while.
//!
//! # What is cached, and for how long
//!
//! A name that resolved is remembered for `POSITIVE_TTL`, and a name that
//! does **not** exist is remembered for `NEGATIVE_TTL` — much shorter,
//! because a name that failed is often a backend that has just come up, and
//! the next flow should find it.
//!
//! A resolver that could not answer at all — a timeout, a SERVFAIL, an
//! unreachable DNS server — is not remembered: the answer may be there in a
//! moment, and a remembered failure would keep the backend unreachable for
//! the whole negative TTL. The resolver's own message is what the flow fails
//! with, so a typo in the config and a DNS outage do not look the same in
//! the log.
//!
//! The cache holds **addresses, not flows**: it answers "where is this name",
//! and every flow still opens its own connection to it. A cached address that
//! has gone away fails the TCP dial like any other, and the flow fails with
//! it.
//!
//! # Why the port is not part of the key
//!
//! A DNS answer is about the name. The port is the caller's, and it is added
//! when the address is used — so `db.test:5432` and `db.test:5433` share one
//! resolution.
//!
//! # What is not cached
//!
//! The resolution itself is not cached while it is in progress: two flows
//! that arrive together and both find the cache empty do not both start a
//! `getaddrinfo`. The second one waits for the first and takes its outcome —
//! the same addresses, or the same failure.
//!
//! # The UDP path
//!
//! A UDP flow resolves its target every time it opens, and not through this
//! cache. A UDP socket has no dial: `connect` on it is local, so a stale
//! address is not a failed dial — the flow opens, every datagram goes to an
//! address that is no longer there, and nothing anywhere reports it. The
//! cache is for the TCP paths, where a stale address is refused and the dial
//! fails loudly.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

/// How long a name that resolved stays resolved.
const POSITIVE_TTL: Duration = Duration::from_secs(30);

/// How long a name that does not exist stays non-existent.
///
/// Short on purpose: a name that failed is often a backend that has just come
/// up, and the flow after that should find it.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// The most names the cache holds.
///
/// The key space is the configuration — the backends a deployment names — so
/// this is generous. It is a bound and not a promise: when it is reached the
/// names nobody has asked about for the longest time go first.
const MAX_ENTRIES: usize = 1024;

/// The messages the system resolver uses for a name that does not exist.
///
/// `getaddrinfo` has one error for "no such name" and another for "the
/// resolver could not answer", and the standard library hands both on as the
/// same `io::Error`: on Unix with the kind `Other` and only the message to
/// tell them apart, on Windows with a message of its own. An error whose
/// message is not one of these is treated as transient, because the cost of
/// that mistake is one name looked up again, while the cost of the other
/// mistake is a backend that stays unreachable for the whole negative TTL.
///
/// The texts are lower-cased, because the platforms do not spell the same
/// resolver error the same way: glibc says "No address associated with
/// hostname" where macOS says "no address associated with hostname".
const NOT_FOUND_MESSAGES: &[&str] = &[
    // glibc and musl.
    "name or service not known",
    "name does not resolve",
    // macOS and the BSDs.
    "nodename nor servname provided",
    // A name that exists but has no address record.
    "no address associated with hostname",
    // Windows.
    "no such host is known",
];

/// Why a name did not resolve.
///
/// The two cases are kept apart because the cache keeps them apart: a name
/// that does not exist is remembered briefly, while a resolver that could
/// not answer is not remembered at all.
#[derive(Debug, Clone)]
pub enum ResolveError {
    /// The name does not exist. The answer is final enough to remember.
    NotFound {
        /// The resolver's own error.
        source: Arc<io::Error>,
    },
    /// The resolver could not answer right now. The answer may be there in a
    /// moment, so it is not remembered.
    Transient {
        /// The resolver's own error.
        source: Arc<io::Error>,
    },
}

impl ResolveError {
    /// The name does not exist.
    fn not_found(source: io::Error) -> Self {
        ResolveError::NotFound {
            source: Arc::new(source),
        }
    }

    /// The resolver could not answer right now.
    fn transient(source: io::Error) -> Self {
        ResolveError::Transient {
            source: Arc::new(source),
        }
    }

    /// Whether the answer is final enough to remember.
    fn is_not_found(&self) -> bool {
        matches!(self, ResolveError::NotFound { .. })
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::NotFound { source } => {
                write!(f, "the name does not exist: {source}")
            }
            ResolveError::Transient { source } => {
                write!(f, "the resolver could not answer: {source}")
            }
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResolveError::NotFound { source } => Some(source.as_ref()),
            ResolveError::Transient { source } => Some(source.as_ref()),
        }
    }
}

/// Where the addresses come from.
///
/// Injectable so that the cache can be tested without a network, and so that
/// a test can count how many resolutions actually happened.
pub trait Resolve: Send + Sync {
    /// The addresses `host` resolves to.
    ///
    /// The port is **zero**: a DNS answer is about the name, and the port is
    /// the caller's. The rest of the address is kept as it is — in particular
    /// the scope id of a link-local IPv6 address, which is what says which
    /// interface it belongs to. Reducing an answer to a bare `IpAddr` loses
    /// that, and a backend on `fe80::1%lo0` becomes unreachable: the same
    /// address on two interfaces is two addresses.
    ///
    /// `Ok` with an empty list means the name does not exist. `Err` says why
    /// the resolver could not answer, and the two are remembered differently:
    /// see [`ResolveError`].
    fn resolve(&self, host: &str) -> Result<Vec<SocketAddr>, ResolveError>;
}

/// The system resolver, called on a blocking thread.
///
/// `getaddrinfo` blocks, and the flow that asked for the address is waiting
/// for it — so it does not run on a worker.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<SocketAddr>, ResolveError> {
        // Port 0: the port is not part of a DNS answer, and it is added when
        // the address is used. The scope id of a link-local IPv6 address is
        // part of the answer and is kept.
        match (host, 0u16).to_socket_addrs() {
            Ok(addrs) => Ok(addrs.collect()),
            Err(e) => Err(classify(e)),
        }
    }
}

/// The resolver the process resolves names through.
///
/// In a build that is not a test it is the system's. In a test build it is
/// the one the test put in place — see [`swap_resolver`] — and the system
/// resolver is what is left when the test takes it away again.
struct ProcessResolver;

impl Resolve for ProcessResolver {
    fn resolve(&self, host: &str) -> Result<Vec<SocketAddr>, ResolveError> {
        #[cfg(test)]
        {
            if let Some(resolver) = test_resolver() {
                return resolver.resolve(host);
            }
        }
        SystemResolver.resolve(host)
    }
}

/// The resolver a test put in the process's place.
///
/// It is `None` unless a test put one there, and the test that put one there
/// takes it away again when it is done.
#[cfg(test)]
static TEST_RESOLVER: Mutex<Option<Arc<dyn Resolve>>> = Mutex::new(None);

/// The resolver a test put in the process's place, if there is one.
#[cfg(test)]
fn test_resolver() -> Option<Arc<dyn Resolve>> {
    TEST_RESOLVER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Puts a resolver in the process's place, until the guard is dropped.
///
/// The guard puts the old one back, so a test that has a resolver in place
/// does not leave it there for the tests that run beside it.
#[cfg(test)]
pub(crate) struct ResolverGuard {
    previous: Option<Arc<dyn Resolve>>,
}

#[cfg(test)]
impl Drop for ResolverGuard {
    fn drop(&mut self) {
        let mut current = TEST_RESOLVER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = self.previous.take();
    }
}

/// Puts a resolver in the process's place, until the guard is dropped.
#[cfg(test)]
pub(crate) fn swap_resolver(resolver: Arc<dyn Resolve>) -> ResolverGuard {
    let mut current = TEST_RESOLVER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = current.replace(resolver);
    ResolverGuard { previous }
}

/// Says whether a resolver failure means "this name does not exist" or "the
/// resolver could not answer right now".
fn classify(error: io::Error) -> ResolveError {
    let message = error.to_string();
    let lowered = message.to_lowercase();
    let not_found = error.kind() == io::ErrorKind::NotFound
        || NOT_FOUND_MESSAGES
            .iter()
            .any(|known| lowered.contains(*known));
    if not_found {
        ResolveError::not_found(error)
    } else {
        ResolveError::transient(error)
    }
}

/// The answer the cache holds.
enum Answer {
    /// The addresses the name resolves to.
    Addresses(Vec<SocketAddr>),
    /// Why the name does not resolve.
    Failure(ResolveError),
}

/// What the cache knows about a name.
struct Entry {
    /// The answer itself.
    answer: Answer,
    /// When the answer stops being true.
    expires_at: Instant,
    /// When the name was last asked about.
    ///
    /// A number and not an `Instant`, so that a hit can say "this one is
    /// still the hottest" without taking the write lock: the cache hands its
    /// answers out under a read lock, and the hot path must not have to
    /// write.
    last_used: AtomicU64,
}

impl Entry {
    /// The addresses, or the reason there are none.
    fn answer(&self) -> Result<Vec<SocketAddr>, ResolveError> {
        match &self.answer {
            Answer::Addresses(addrs) => Ok(addrs.clone()),
            Answer::Failure(e) => Err(e.clone()),
        }
    }

    /// Says that the name was just asked about.
    fn touch(&self) {
        self.last_used.store(used_at(), Ordering::Relaxed);
    }
}

/// When the cache was created, so that "how recently" is a number that can
/// be compared.
static STARTED: LazyLock<Instant> = LazyLock::new(Instant::now);

/// How recently something was used, as a number that can be compared.
///
/// Nanoseconds since the cache was created: about five centuries' worth, so
/// the number cannot wrap.
fn used_at() -> u64 {
    STARTED.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

/// A resolution that is running right now.
///
/// The `OnceCell` runs its initializer once: the callers that arrive while
/// the resolution runs wait for it and get its outcome.
struct Flight {
    outcome: tokio::sync::OnceCell<Result<Vec<SocketAddr>, ResolveError>>,
}

/// Forgets the flight when the resolution is over, however it ends.
struct FlightGuard<'a> {
    cache: &'a DnsCache,
    host: String,
    flight: Arc<Flight>,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        self.cache.end_flight(&self.host, &self.flight);
    }
}

/// A cache of resolved names.
pub struct DnsCache {
    entries: RwLock<HashMap<String, Arc<Entry>>>,
    /// The resolutions that are running right now, one per name.
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    resolver: Arc<dyn Resolve>,
    positive_ttl: Duration,
    negative_ttl: Duration,
    max_entries: usize,
}

impl DnsCache {
    /// A cache that resolves through `resolver`.
    ///
    /// `max_entries` bounds the table: when it is reached, the names nobody
    /// has asked about for the longest time go first.
    pub fn new(
        resolver: Arc<dyn Resolve>,
        positive_ttl: Duration,
        negative_ttl: Duration,
        max_entries: usize,
    ) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
            resolver,
            positive_ttl,
            negative_ttl,
            max_entries,
        }
    }

    /// The addresses `host` resolves to, from the cache when the answer still
    /// holds.
    ///
    /// A name that is not in the cache — or whose answer has expired — is
    /// resolved and remembered.
    pub async fn resolve(&self, host: &str) -> anyhow::Result<Vec<SocketAddr>> {
        if let Some(entry) = self.lookup(host) {
            return entry.answer().map_err(anyhow::Error::from);
        }

        // One resolution per name at a time. A caller that arrives while the
        // resolution is running waits for it and takes its outcome — the same
        // addresses, or the same failure — instead of starting a lookup of
        // its own.
        let flight = self.flight(host);
        // The flight is forgotten when the resolution is over, however it
        // ends: a caller that is cancelled must not leave behind a name that
        // can never be resolved again.
        let _guard = FlightGuard {
            cache: self,
            host: host.to_string(),
            flight: flight.clone(),
        };
        let outcome = flight.outcome.get_or_init(|| self.resolve_once(host)).await;
        outcome.clone().map_err(anyhow::Error::from)
    }

    /// The addresses `host` resolves to, for a dial toward `port`.
    ///
    /// The port is the caller's: it is not part of the DNS answer and it is
    /// not part of the cache's key. The rest of the address is the answer's
    /// own, and is kept — in particular the scope id of a link-local IPv6
    /// address, which is what says which interface it belongs to.
    pub async fn resolve_to(&self, host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        Ok(self
            .resolve(host)
            .await?
            .into_iter()
            .map(|addr| with_port(addr, port))
            .collect())
    }

    /// The addresses `host` resolves to, right now, without the cache.
    ///
    /// The UDP path uses this. A UDP flow has no dial, so a stale address is
    /// not a failed dial: the flow opens, every datagram goes to an address
    /// that is no longer there, and nothing reports it. A UDP flow therefore
    /// resolves its target every time it opens, the way it did before the
    /// cache existed.
    pub async fn resolve_uncached(&self, host: &str) -> anyhow::Result<Vec<SocketAddr>> {
        let resolver = self.resolver.clone();
        let name = host.to_string();
        match tokio::task::spawn_blocking(move || resolver.resolve(&name)).await {
            Ok(Ok(addrs)) => Ok(addrs),
            Ok(Err(e)) => Err(anyhow::Error::from(e)),
            Err(e) => Err(anyhow::anyhow!("the resolver did not run: {e}")),
        }
    }

    /// The resolution itself, and what is remembered about it.
    async fn resolve_once(&self, host: &str) -> Result<Vec<SocketAddr>, ResolveError> {
        // The answer may have arrived while this caller waited for the
        // flight.
        if let Some(entry) = self.lookup(host) {
            return entry.answer();
        }

        let resolver = self.resolver.clone();
        let name = host.to_string();
        let resolved = match tokio::task::spawn_blocking(move || resolver.resolve(&name)).await {
            Ok(resolved) => resolved,
            Err(e) => {
                return Err(ResolveError::transient(io::Error::other(format!(
                    "the resolver did not run: {e}"
                ))));
            }
        };

        match resolved {
            Ok(addrs) if !addrs.is_empty() => {
                self.remember(host, Answer::Addresses(addrs.clone()), self.positive_ttl);
                Ok(addrs)
            }
            Ok(_) => {
                // The resolver answered, and the answer was "no such name".
                let error = ResolveError::not_found(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{host} does not exist"),
                ));
                self.remember(host, Answer::Failure(error.clone()), self.negative_ttl);
                Err(error)
            }
            Err(error) => {
                if error.is_not_found() {
                    // Remembered, but only briefly: a name that does not
                    // exist is often a backend that has just come up.
                    self.remember(host, Answer::Failure(error.clone()), self.negative_ttl);
                }
                // A resolver that could not answer is not remembered at all:
                // the answer may be there in a moment, and a remembered
                // failure would keep the backend unreachable for the whole
                // negative TTL.
                Err(error)
            }
        }
    }

    /// The cached answer for `host`, if it is one and it still holds.
    fn lookup(&self, host: &str) -> Option<Arc<Entry>> {
        let entries = self.read();
        let entry = entries.get(host)?.clone();
        drop(entries);
        if entry.expires_at <= Instant::now() {
            return None;
        }
        entry.touch();
        Some(entry)
    }

    /// Remembers an answer about `host`.
    fn remember(&self, host: &str, answer: Answer, ttl: Duration) {
        self.store(
            host,
            Entry {
                answer,
                expires_at: Instant::now() + ttl,
                last_used: AtomicU64::new(used_at()),
            },
        );
    }

    /// Remembers an answer.
    fn store(&self, host: &str, entry: Entry) {
        let mut entries = self.write();
        if entries.len() >= self.max_entries {
            evict(&mut entries, self.max_entries);
        }
        entries.insert(host.to_string(), Arc::new(entry));
    }

    /// The flight for `host`, or a new one.
    fn flight(&self, host: &str) -> Arc<Flight> {
        let mut flights = self.flights.lock().unwrap_or_else(|p| p.into_inner());
        flights
            .entry(host.to_string())
            .or_insert_with(|| {
                Arc::new(Flight {
                    outcome: tokio::sync::OnceCell::new(),
                })
            })
            .clone()
    }

    /// Forgets the flight for `host`, if it is this one.
    fn end_flight(&self, host: &str, flight: &Arc<Flight>) {
        let mut flights = self.flights.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(current) = flights.get(host)
            && Arc::ptr_eq(current, flight)
        {
            flights.remove(host);
        }
    }

    /// The read lock, and a poisoned one is still a lock.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Arc<Entry>>> {
        self.entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The write lock, and a poisoned one is still a lock.
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Arc<Entry>>> {
        self.entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Makes room in a full table.
///
/// The expired answers go first — they are worth nothing. What is left is
/// bound by how recently the name was asked about: the name nobody has asked
/// about for the longest time is the one that goes, so a name that is asked
/// about often does not push the others out.
fn evict(entries: &mut HashMap<String, Arc<Entry>>, max_entries: usize) {
    let now = Instant::now();
    entries.retain(|_, entry| entry.expires_at > now);
    if entries.len() < max_entries {
        return;
    }
    // Still full: make room for one more, and drop the names that were
    // asked about the longest time ago.
    let to_drop = entries.len() + 1 - max_entries;
    let mut by_age: Vec<(String, u64)> = entries
        .iter()
        .map(|(name, entry)| (name.clone(), entry.last_used.load(Ordering::Relaxed)))
        .collect();
    by_age.sort_by_key(|(_, used)| *used);
    for (name, _) in by_age.into_iter().take(to_drop) {
        entries.remove(&name);
    }
}

/// The cache this process resolves names through.
static CACHE: LazyLock<DnsCache> = LazyLock::new(|| {
    DnsCache::new(
        Arc::new(ProcessResolver),
        POSITIVE_TTL,
        NEGATIVE_TTL,
        MAX_ENTRIES,
    )
});

/// The same address, on another port.
///
/// The port is the caller's and the answer does not carry one. The rest of
/// the address is the answer's own and is kept: in particular the scope id of
/// a link-local IPv6 address, which is what says which interface it belongs
/// to. A link-local address without it is unreachable.
pub(crate) fn with_port(addr: SocketAddr, port: u16) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(*v4.ip(), port)),
        SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(
            *v6.ip(),
            port,
            v6.flowinfo(),
            v6.scope_id(),
        )),
    }
}

/// The addresses `host` resolves to.
///
/// Cached, and the answer is what the last resolution said until it expires.
pub async fn resolve(host: &str) -> anyhow::Result<Vec<SocketAddr>> {
    CACHE.resolve(host).await
}

/// The addresses `host` resolves to, for a dial toward `port`.
///
/// The port is the caller's: it is not part of the DNS answer and it is not
/// part of the cache's key.
pub async fn resolve_to(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    CACHE.resolve_to(host, port).await
}

/// The addresses `host` resolves to, right now, without the cache.
///
/// The UDP path uses this, and the module doc says why.
pub async fn resolve_uncached(host: &str) -> anyhow::Result<Vec<SocketAddr>> {
    CACHE.resolve_uncached(host).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::atomic::AtomicUsize;

    /// What the test resolver answers with.
    #[derive(Clone)]
    enum Answer {
        Addresses(Vec<SocketAddr>),
        /// The name does not exist.
        NotFound,
        /// The resolver could not answer.
        Transient,
    }

    /// A resolver that answers from a table and counts what it was asked.
    struct Counting {
        answers: Mutex<HashMap<String, Answer>>,
        calls: AtomicUsize,
        /// How long a resolution takes, so that two callers really do
        /// overlap.
        delay: Duration,
    }

    impl Counting {
        fn new(answers: HashMap<String, Answer>) -> Self {
            Self {
                answers: Mutex::new(answers),
                calls: AtomicUsize::new(0),
                delay: Duration::ZERO,
            }
        }

        fn slow(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        /// Changes what the resolver answers, the way a DNS record moves.
        fn set(&self, host: &str, answer: Answer) {
            self.answers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(host.to_string(), answer);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Resolve for Counting {
        fn resolve(&self, host: &str) -> Result<Vec<SocketAddr>, ResolveError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            let answer = self
                .answers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(host)
                .cloned();
            match answer {
                Some(Answer::Addresses(addrs)) => Ok(addrs),
                Some(Answer::Transient) => Err(ResolveError::transient(io::Error::other(
                    "temporary failure in name resolution",
                ))),
                Some(Answer::NotFound) => Err(ResolveError::not_found(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{host} does not exist"),
                ))),
                // A name the table does not mention resolves: the tests that
                // care about a name that does not exist say so in the table.
                None => Ok(vec![socket(9)]),
            }
        }
    }

    /// An address the table answers with.
    fn socket(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::from([10, 0, 0, last]), 0)
    }

    /// A link-local IPv6 address on an interface, the way a resolver answers
    /// it: the scope id is what says which interface it belongs to.
    fn link_local(scope_id: u32) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            "fe80::1"
                .parse::<std::net::Ipv6Addr>()
                .expect("a literal address"),
            0,
            0,
            scope_id,
        ))
    }

    /// The scope id of an address, or zero for one that has none.
    fn scope_of(addr: &SocketAddr) -> u32 {
        match addr {
            SocketAddr::V4(_) => 0,
            SocketAddr::V6(v6) => v6.scope_id(),
        }
    }

    fn addresses(host: &str, last: u8) -> HashMap<String, Answer> {
        HashMap::from([(host.to_string(), Answer::Addresses(vec![socket(last)]))])
    }

    fn cache(resolver: Arc<Counting>) -> DnsCache {
        DnsCache::new(
            resolver,
            Duration::from_secs(30),
            Duration::from_secs(5),
            1024,
        )
    }

    #[tokio::test]
    async fn the_second_resolution_is_answered_from_the_cache() {
        let resolver = Arc::new(Counting::new(addresses("db.test", 1)));
        let cache = cache(resolver.clone());

        let first = cache.resolve("db.test").await.expect("the name resolves");
        let second = cache.resolve("db.test").await.expect("the name resolves");

        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert_eq!(
            resolver.calls(),
            1,
            "the second resolution should not have gone to the resolver"
        );
    }

    #[tokio::test]
    async fn a_name_that_did_not_resolve_is_remembered_briefly() {
        let resolver = Arc::new(Counting::new(HashMap::from([(
            "nowhere.test".to_string(),
            Answer::NotFound,
        )])));
        let cache = cache(resolver.clone());

        assert!(cache.resolve("nowhere.test").await.is_err());
        assert!(cache.resolve("nowhere.test").await.is_err());

        assert_eq!(
            resolver.calls(),
            1,
            "a name that does not exist should be remembered too, so the same answer is not paid for twice"
        );
    }

    #[tokio::test]
    async fn a_resolver_that_could_not_answer_is_not_remembered() {
        let resolver = Arc::new(Counting::new(HashMap::from([(
            "db.test".to_string(),
            Answer::Transient,
        )])));
        let cache = cache(resolver.clone());

        assert!(cache.resolve("db.test").await.is_err());
        assert!(cache.resolve("db.test").await.is_err());

        assert_eq!(
            resolver.calls(),
            2,
            "a resolver that could not answer must not be remembered: the answer may be \
             there in a moment, and a remembered failure would keep the backend \
             unreachable for the whole negative TTL"
        );
    }

    #[tokio::test]
    async fn the_resolver_message_survives_the_failure() {
        let resolver = Arc::new(Counting::new(HashMap::from([(
            "db.test".to_string(),
            Answer::Transient,
        )])));
        let cache = cache(resolver);

        let error = cache
            .resolve("db.test")
            .await
            .expect_err("the resolver could not answer");

        let chain: Vec<String> = error.chain().map(|cause| cause.to_string()).collect();
        assert!(
            chain
                .iter()
                .any(|message| message.contains("temporary failure in name resolution")),
            "the resolver's own message should be in the chain, got {chain:?}"
        );
    }

    /// The two resolver failures the cache tells apart are told apart by the
    /// words the resolver used, and the words are read the way the platforms
    /// spell them.
    #[test]
    fn a_name_that_does_not_exist_is_not_a_resolver_that_could_not_answer() {
        // The words the platforms use for "no such name".
        for message in [
            "failed to lookup address information: nodename nor servname provided, or not known",
            "failed to lookup address information: Name or service not known",
            "failed to lookup address information: no address associated with hostname",
            "failed to lookup address information: No such host is known.",
        ] {
            assert!(
                classify(io::Error::other(message)).is_not_found(),
                "{message:?} should mean that the name does not exist"
            );
        }

        // And the words they use for a resolver that could not answer.
        for message in [
            "failed to lookup address information: Temporary failure in name resolution",
            "failed to lookup address information: server misbehaving",
            "failed to lookup address information: Non-recoverable failure in name resolution",
        ] {
            assert!(
                !classify(io::Error::other(message)).is_not_found(),
                "{message:?} should mean that the resolver could not answer"
            );
        }
    }

    #[tokio::test]
    async fn a_link_local_address_keeps_its_interface() {
        // The scope id is what says which interface a link-local IPv6 address
        // belongs to: the same address on two interfaces is two addresses, and
        // an address without it cannot be reached at all. The old code
        // resolved the name and kept only the address, so the interface was
        // lost and a backend on `fe80::1%lo0` became unreachable.
        let resolver = Arc::new(Counting::new(HashMap::from([(
            "link.test".to_string(),
            Answer::Addresses(vec![link_local(7)]),
        )])));
        let cache = cache(resolver.clone());

        let first = cache.resolve("link.test").await.expect("the name resolves");
        assert_eq!(
            scope_of(&first[0]),
            7,
            "the interface must survive the resolution"
        );

        // And it must survive being remembered and handed out again.
        let second = cache.resolve("link.test").await.expect("the name resolves");
        assert_eq!(
            scope_of(&second[0]),
            7,
            "the interface must survive the cache"
        );
        assert_eq!(
            resolver.calls(),
            1,
            "the second resolution should not have gone to the resolver"
        );

        // And it must reach the dial, with the port the caller asked for.
        let addrs = cache
            .resolve_to("link.test", 8080)
            .await
            .expect("the name resolves");
        assert_eq!(addrs.len(), 1);
        assert_eq!(scope_of(&addrs[0]), 7, "the interface must reach the dial");
        assert_eq!(addrs[0].port(), 8080, "the caller's port must be used");
    }

    #[tokio::test]
    async fn an_expired_answer_is_resolved_again() {
        let resolver = Arc::new(Counting::new(addresses("db.test", 1)));
        let cache = DnsCache::new(
            resolver.clone(),
            Duration::from_millis(0),
            Duration::from_millis(0),
            1024,
        );

        cache.resolve("db.test").await.expect("the name resolves");
        cache.resolve("db.test").await.expect("the name resolves");

        assert_eq!(
            resolver.calls(),
            2,
            "an answer that has expired should not be used"
        );
    }

    #[tokio::test]
    async fn the_port_is_added_when_the_address_is_used() {
        let resolver = Arc::new(Counting::new(addresses("db.test", 7)));
        let cache = cache(resolver);

        let addrs = cache
            .resolve_to("db.test", 5432)
            .await
            .expect("the name resolves");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 5432);
    }

    #[tokio::test]
    async fn two_resolutions_that_arrive_together_share_one_lookup() {
        let resolver =
            Arc::new(Counting::new(addresses("db.test", 1)).slow(Duration::from_millis(50)));
        let cache = Arc::new(cache(resolver.clone()));

        let (first, second) = tokio::join!(cache.resolve("db.test"), cache.resolve("db.test"));

        assert_eq!(
            first.expect("the name resolves"),
            second.expect("the name resolves")
        );
        assert_eq!(
            resolver.calls(),
            1,
            "the second caller should have waited for the first one instead of \
             starting a lookup of its own"
        );
    }

    #[tokio::test]
    async fn the_uncached_resolution_ignores_the_cache() {
        let resolver = Arc::new(Counting::new(addresses("db.test", 1)));
        let cache = cache(resolver.clone());

        let cached = cache.resolve("db.test").await.expect("the name resolves");
        assert_eq!(cached, vec![socket(1)]);

        // The record moves.
        resolver.set("db.test", Answer::Addresses(vec![socket(2)]));

        let fresh = cache
            .resolve_uncached("db.test")
            .await
            .expect("the name resolves");
        assert_eq!(
            fresh,
            vec![socket(2)],
            "the uncached resolution must not answer from the cache"
        );

        let still_cached = cache.resolve("db.test").await.expect("the name resolves");
        assert_eq!(
            still_cached,
            vec![socket(1)],
            "the uncached resolution must not fill the cache either"
        );
        assert_eq!(resolver.calls(), 2);
    }

    #[tokio::test]
    async fn a_full_table_drops_the_cold_names_and_keeps_the_hot_ones() {
        let resolver = Arc::new(Counting::new(HashMap::new()));
        let cache = DnsCache::new(
            resolver.clone(),
            Duration::from_secs(30),
            Duration::from_secs(5),
            4,
        );

        for name in ["one.test", "two.test", "three.test", "four.test"] {
            cache.resolve(name).await.expect("the name resolves");
        }
        // "one.test" is asked about again, so it is the hottest of the four.
        cache.resolve("one.test").await.expect("the name resolves");
        // A fifth name does not fit any more.
        cache.resolve("five.test").await.expect("the name resolves");

        let entries = cache.read();
        assert!(
            entries.contains_key("one.test"),
            "the name that was asked about most recently should have survived"
        );
        assert!(
            !entries.contains_key("two.test"),
            "the name that was not asked about for the longest should have gone"
        );
        assert!(
            entries.contains_key("five.test"),
            "the name that made the table overflow should be in it"
        );
        assert!(
            entries.len() <= 4,
            "the table should not grow past its bound, it holds {}",
            entries.len()
        );
    }

    #[tokio::test]
    async fn an_expired_entry_is_dropped_before_a_live_one() {
        let resolver = Arc::new(Counting::new(HashMap::from([
            ("gone1.test".to_string(), Answer::NotFound),
            ("gone2.test".to_string(), Answer::NotFound),
            ("live1.test".to_string(), Answer::Addresses(vec![socket(1)])),
            ("live2.test".to_string(), Answer::Addresses(vec![socket(2)])),
        ])));
        // The negative TTL is zero, so the names that do not exist are
        // expired the moment they are stored.
        let cache = DnsCache::new(resolver.clone(), Duration::from_secs(30), Duration::ZERO, 4);

        assert!(cache.resolve("gone1.test").await.is_err());
        assert!(cache.resolve("gone2.test").await.is_err());
        cache
            .resolve("live1.test")
            .await
            .expect("the name resolves");
        cache
            .resolve("live2.test")
            .await
            .expect("the name resolves");
        // The table is full now, and this name does not fit.
        cache.resolve("new.test").await.expect("the name resolves");

        let entries = cache.read();
        assert!(
            !entries.contains_key("gone1.test"),
            "an expired entry is worth nothing and goes first"
        );
        assert!(
            entries.contains_key("live1.test"),
            "a live entry must not be dropped to make room for an expired one"
        );
        assert!(entries.contains_key("live2.test"));
        assert!(entries.contains_key("new.test"));
        assert!(entries.len() <= 4);
    }
}
