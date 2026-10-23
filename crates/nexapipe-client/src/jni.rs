use crate::auth::{DeviceKey, Enrollment, TotpAlgorithm, TwoFactorAuth};
use crate::discovery::DiscoveryMode;
use crate::relay::RelayModeSpec;
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
use crate::tun_proxy::TunProxy;
use crate::{DomainMapping, EndpointGroup, IrohConnectionPool, LoadBalancingStrategy, NodeConfig};
use iroh::Endpoint;
use iroh::dns::{DnsError, DnsResolver, NameserverConfig, Resolver, TxtRecordData};
use iroh::endpoint::presets;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::{Env, EnvUnowned, Outcome};
use nexapipe_proto::secret::SecretString;
// Only `native_init` reads the Android context, and only on Android. Gated to
// match: an ungated import is an unused-import warning on every other `jni`
// build, which is what the release archives are.
#[cfg(target_os = "android")]
use ndk_context;
use once_cell::sync::{Lazy, OnceCell};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
// The TUN descriptor's ownership is taken in `start_tun_proxy`, which is the
// Android half of the tunnel. Gated to match that function: an ungated
// import is an unused-import warning on every other build, which is what the
// release archives are.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
use std::os::fd::FromRawFd;
use std::panic;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static ENDPOINT: Mutex<Option<Endpoint>> = Mutex::new(None);
static STATE: OnceCell<Arc<Mutex<ProxyState>>> = OnceCell::new();
// 2FA config: Kotlin injects (client_id, secret, algorithm) via nativeSetTwoFactor before startup.
//
// The secret is a `SecretString`: this table lives for as long as the process
// does, and the seed in it is a working credential — it is wiped when the
// entry is replaced or cleared, rather than being left in the heap for the
// allocator to hand out again.
static TWO_FACTOR: Mutex<Option<(String, SecretString, String)>> = Mutex::new(None);

/// One endpoint's TOTP credentials, as Kotlin filed them: client id, secret,
/// algorithm, and the device the secret was issued to.
///
/// The last field is what decides whether a handshake claims a device name, so
/// it travels with the triple rather than being read from `DEVICE_ID` at apply
/// time: a pair issued to the client has to keep answering as the client.
///
/// The secret is a [`SecretString`], for the reason the table above gives.
type NodeCredential = (String, SecretString, String, Option<String>);

// 2FA credentials per backend, keyed by endpoint ID. Kotlin registers one entry
// per endpoint that carries 2FA (nativeSetTwoFactorForNode); a backend without
// an entry keeps none, so it never opens an auth stream. That is what lets one
// client talk to several servers with different secrets — the single global
// TWO_FACTOR above cannot express it.
static NODE_TWO_FACTOR: Lazy<Mutex<HashMap<String, NodeCredential>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
// One-time enrollment tokens per backend, keyed by endpoint ID. An entry here means the
// endpoint has no credentials yet: the token is spent by the first connection, which comes
// back with the secret Kotlin then persists. Kept apart from NODE_TWO_FACTOR because a node
// holding a token must not present it as its TOTP secret.
//
// The token is a `SecretString`: an unspent invitation is a credential, and
// this table holds it for as long as the process lives.
static NODE_ENROLLMENT: Lazy<Mutex<HashMap<String, (String, SecretString)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
// One device key per backend, keyed by endpoint ID.
//
// A key is the device's own credential rather than a copy of the server's: the
// private half never leaves the device and the server holds only the public
// one, so what Kotlin registers here is what an enrollment offers and what
// every later handshake signs with. Kept apart from `NODE_TWO_FACTOR` because
// the two travel together and mean different things — the credential record
// says *which* client and *which* device this is, the key says *how* it proves
// itself, and a node can have one without the other: a key with no device name
// yet is one that is about to enroll.
static NODE_DEVICE_KEYS: Lazy<Mutex<HashMap<String, iroh::SecretKey>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// The name this install answers as, injected once by Kotlin
/// (`nativeSetDeviceId`) rather than per credential.
///
/// One name for the whole install, because the device is the phone and not the
/// server. It names **enrollments only** — see `two_factor_auth` for why every
/// other credential answers unnamed — and it is set from its own entry point
/// rather than as one more argument on the calls that already exist, so a
/// Kotlin side that has never heard of devices keeps calling them as it does
/// and simply enrolls as the unnamed one.
static DEVICE_ID: Mutex<Option<String>> = Mutex::new(None);

// Generation counter: incremented each time nativeStopProxy releases the endpoint.
// nativeStartIroh compares this before/after bind(); if a stop happened in between, the late
// new endpoint is discarded to avoid a stray bind reviving an already-released tunnel.
static ENDPOINT_GEN: AtomicU64 = AtomicU64::new(0);

// System DNS servers passed down from Kotlin. iroh's internal JNI path for reading system DNS
// fails (Null pointer in call_method obj argument), and falling back to Google DNS is unstable
// domestically. Kotlin obtains these from ConnectivityManager.getLinkProperties().dnsServers
// and injects them; nativeStartIroh uses them to build the DnsResolver, bypassing iroh's
// broken JNI path.
static CUSTOM_DNS_SERVERS: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

// Pre-resolved IP overrides for iroh infrastructure domains (dns.iroh.link, *.relay.n0.iroh.link).
// The GFW drops UDP DNS responses for iroh.link domains, causing hickory resolution to time out.
// Kotlin pre-resolves these via the system DNS (which may use DoT/Private DNS to bypass the GFW)
// and passes them to Rust to store in this map. OverrideResolver returns the pre-resolved IPs for
// these domains directly; all other domains still go through hickory + the system DNS servers.
static DNS_OVERRIDES: Lazy<Mutex<HashMap<String, Vec<IpAddr>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Per-query timeout used when OverrideResolver delegates to DnsResolver.
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

// BoxFuture compatibility type, matching the return type of the iroh::dns::Resolver trait
// (n0_future::boxed::BoxFuture, i.e. futures_lite::future::Boxed =
// Pin<Box<dyn Future<Output = T> + Send + 'static>>).
// Must be 'static: the Future returned by Resolver methods cannot borrow self, so clone any
// needed data inside the method body.
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
type BoxIter<T> = Box<dyn Iterator<Item = T> + Send + 'static>;

// Per-stage timeouts. Discovery of STUN/relay/DNS can be slow on weak networks; these timeouts ensure we return failure instead of blocking forever when stuck.
const IROH_BIND_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
const START_PROXY_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(15);
const CLOSE_ALL_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(8);
/// Pre-connect / warm-up timeout for establishing iroh connections to all backends.
///
/// Derived from what the phase itself allows rather than written down: at a flat
/// 15s it left one second for a phase that may now spend fourteen, so a
/// start-up that legitimately used its budget was cancelled here instead of by
/// the pools that were still working. The slack covers setting the proxy up
/// around the probe.
const PRECONNECT_TIMEOUT: tokio::time::Duration =
    crate::endpoint_group::PRECONNECT_PHASE_CAP.saturating_add(tokio::time::Duration::from_secs(6));

// Why "pinned" exists at all, and why it is the default: iroh otherwise picks a home relay from
// the 4 N0 relays by latency, and here aps1-1 (Asia-Pacific) and euc1-1 (Europe) measure
// similarly, so iroh keeps flip-flopping between them. Each home-relay switch forces the
// connections routed through relay (WebSocket, etc.) to drop and reconnect. The URL itself is
// `crate::relay::PINNED_RELAY_URL`; DNS still pre-resolves aps1-1's IP on the Kotlin side via
// resolveIrohDnsOverrides and injects it into OverrideResolver.

// Relay configuration: mode and custom URL from Kotlin settings.
// "pinned" = aps1-1 (the default), "default" = iroh default (all N0 relays),
// "disabled" = no relay at all, "custom" = user-provided URL.
// An empty mode means nothing has been injected yet, which falls back to "pinned".
// A mode that is set but unusable is an error: see `crate::relay`.
static RELAY_MODE: Mutex<String> = Mutex::new(String::new());
static CUSTOM_RELAY_URL: Mutex<String> = Mutex::new(String::new());
// Bearer token for a `custom` relay that asks for one. Only ever read together with the two
// above; never logged.
//
// A `SecretString`, and a `Lazy` because a `Secret` cannot be built in a
// `static` initializer: the token is a credential, and it is wiped when the
// entry is replaced or the process ends.
static RELAY_AUTH_TOKEN: Lazy<Mutex<SecretString>> =
    Lazy::new(|| Mutex::new(SecretString::default()));

// Whether this endpoint may use n0's address lookup, from Kotlin settings.
// "n0" = the default (a Node ID is looked up through dns.iroh.link), "none" =
// no lookup at all, and a peer then has to bring an address of its own.
// An empty value means nothing has been injected yet, which falls back to "n0".
static DISCOVERY_MODE: Mutex<String> = Mutex::new(String::new());

// Reason behind the last failed native call, so Kotlin can read it back.
//
// The start entry points return a bare `jint` and therefore cannot carry a message. Without this
// the caller could not tell "the port is already in use" from "the configured node ID does not
// parse" and guessed the former for both: a malformed endpoint ID (e.g. 65 hex characters, an odd
// length) looked like a port conflict, burned 10 ports x 3 attempts, and finally reported
// "Failed to start proxy on ports 8080..8089" — a message that named neither the node nor the
// real cause.
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// Result code for a failure the caller must not retry: the configuration itself is wrong, so the
/// next port would fail identically, and [`LAST_ERROR`] holds a message meant for the user.
const RESULT_CONFIG_ERROR: jint = -2;

/// Reported when a backend accepted the connection and then refused it because
/// this client never performed the 2FA handshake. The credentials are missing
/// here, not on the server, so the message has to say where to add them.
const AUTH_REQUIRED_MESSAGE: &str =
    "the server requires 2FA, but this client has no 2FA credentials configured";

fn set_last_error(message: impl Into<String>) {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = Some(message.into());
    }
}

fn clear_last_error() {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = None;
    }
}

/// Runs `body` with a panic caught, turning one into `None`.
///
/// Unwinding out of an `extern "system"` frame is a native crash on Android,
/// not a Java exception, so every entry point that drives the runtime — and
/// that is most of them, since a start or a stop blocks on it — has to catch.
/// The entry points wrap their whole body in this and answer with whatever the
/// function returns on failure.
fn catching_panic<T, F>(what: &str, body: F) -> Option<T>
where
    F: FnOnce() -> T,
{
    match panic::catch_unwind(panic::AssertUnwindSafe(body)) {
        Ok(value) => Some(value),
        Err(_) => {
            // `jni_log!` is a macro, so it is not in scope this early in the
            // file; this is the same call it would make.
            android_log(log::Level::Error, &format!("[WARN:jni] {what} panicked"));
            set_last_error(format!("{what} panicked"));
            None
        }
    }
}

fn take_last_error() -> Option<String> {
    match LAST_ERROR.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    }
}

/// Parse a node ID with the same parser the connection path uses.
///
/// Returns the parser's reason on failure. Checking up front means a bad ID is reported before any
/// port is bound, instead of surfacing as a bind failure from inside endpoint-group construction.
fn node_id_error(node_id: &str) -> Option<String> {
    node_id
        .parse::<iroh::EndpointId>()
        .err()
        .map(|e| e.to_string())
}

/// First configured endpoint that does not parse, as a message for the user.
///
/// Mirrors `parse_endpoint_addr` (which reads `server_node_id` first, then `server_ticket`), so a
/// problem is caught here — before any port is bound — instead of surfacing as a bind failure from
/// inside endpoint-group construction.
fn first_invalid_node_id(
    domain_mappings: &[DomainMapping],
    nodes: &[NodeConfig],
) -> Option<String> {
    for mapping in domain_mappings {
        if let Some(node_id) = mapping.server_node_id.as_deref() {
            if let Some(reason) = node_id_error(node_id) {
                return Some(format!(
                    "Invalid endpoint ID '{node_id}' for domain '{}': {reason}. \
                     Endpoint IDs are 64 hexadecimal characters.",
                    mapping.domain
                ));
            }
        }
    }
    for node in nodes {
        if let Some(node_id) = node.server_node_id.as_deref() {
            if let Some(reason) = node_id_error(node_id) {
                return Some(format!(
                    "Invalid endpoint ID '{node_id}': {reason}. \
                     Endpoint IDs are 64 hexadecimal characters."
                ));
            }
        }
    }
    None
}

struct ProxyState {
    conn_pool: Option<IrohConnectionPool>,
    endpoint_group: Option<Arc<EndpointGroup>>,
    nodes: Vec<NodeConfig>,
    domain_mappings: Vec<DomainMapping>,
    domains: Vec<String>,
    // TUN proxy (smoltcp user-space TCP/IP stack). Present only when the Android tun-proxy feature is enabled.
    #[cfg(all(feature = "tun-proxy", target_os = "android"))]
    tun_proxy: Option<TunProxy>,
}

fn get_runtime() -> Option<&'static Runtime> {
    RUNTIME.get_or_try_init(|| Runtime::new()).ok()
}

fn get_endpoint() -> Option<Endpoint> {
    ENDPOINT.lock().ok()?.clone()
}

fn get_state() -> Option<&'static Arc<Mutex<ProxyState>>> {
    STATE.get()
}

fn init_state() -> &'static Arc<Mutex<ProxyState>> {
    STATE.get_or_init(|| {
        Arc::new(Mutex::new(ProxyState {
            conn_pool: None,
            endpoint_group: None,
            nodes: Vec::new(),
            domain_mappings: Vec::new(),
            domains: Vec::new(),
            #[cfg(all(feature = "tun-proxy", target_os = "android"))]
            tun_proxy: None,
        }))
    })
}

#[cfg(feature = "jni")]
#[cfg(target_os = "android")]
pub(crate) fn android_log(level: log::Level, msg: &str) {
    log::log!(level, "{}", msg);
}

#[cfg(feature = "jni")]
#[cfg(not(target_os = "android"))]
pub(crate) fn android_log(_level: log::Level, msg: &str) {
    eprintln!("{}", msg);
}

#[cfg(feature = "jni")]
#[inline]
pub fn debug_log_enabled() -> bool {
    log::log_enabled!(log::Level::Debug)
}

#[cfg(feature = "jni")]
#[inline]
pub fn debug_log(msg: &str) {
    android_log(log::Level::Debug, msg);
}

/// A warning the Android build can show.
///
/// The Android logger is installed at `Info`, so a `Debug` line is dropped
/// before it is ever formatted — and the Android build has no tracing
/// subscriber to fall back on. A warning nobody can read is not a warning,
/// so this one goes through the `log` crate at `Warn`.
#[cfg(feature = "jni")]
pub(crate) fn warn_log(msg: &str) {
    android_log(log::Level::Warn, msg);
}

/// A line of information the Android build can show, on the same terms as
/// [`warn_log`].
#[cfg(feature = "jni")]
pub(crate) fn info_log(msg: &str) {
    android_log(log::Level::Info, msg);
}

/// Debug log that is a no-op when the `log` level filter is below `Debug`.
///
/// The guard matters: without it every call site formatted its arguments into a `String`
/// before the level was ever consulted, so the proxy paid a heap allocation per packet even
/// with logging disabled.
#[cfg(feature = "jni")]
#[macro_export]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if $crate::jni::debug_log_enabled() {
            $crate::jni::debug_log(&format!($($arg)*))
        }
    };
}

/// Runs `body` with a temporary `Env`, answering `failure` when it failed or
/// panicked.
///
/// jni 0.22 hands the environment to a closure rather than handing it over, and
/// the `ErrorPolicy`s it ships with answer `Default` when that closure fails.
/// For a `jint` that is `0` — the value every entry point here returns for
/// success — so a panic would reach Kotlin as "started fine", which is worse
/// than the native crash it replaces. Failure is worth saying out loud, so the
/// value to answer with is passed in: -1, or a null string.
fn with_env_or<T, F>(unowned_env: &mut EnvUnowned<'_>, failure: T, body: F) -> T
where
    F: FnOnce(&mut Env<'_>) -> T,
{
    let outcome = unowned_env.with_env(|env| -> jni::errors::Result<T> { Ok(body(env)) });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(e) => {
            jni_log!("[WARN:jni] a JNI call failed: {e}");
            failure
        }
        Outcome::Panic(_) => {
            // The hook `nativeInit` installs has already logged the message and
            // the location. All this has to do is stop the unwind from leaving
            // the frame, which on Android is a native crash rather than
            // something the JVM can report.
            jni_log!("[WARN:jni] a native method panicked");
            failure
        }
    }
}

/// Custom DNS Resolver that wraps the hickory resolver and returns pre-resolved IPs for specific domains.
///
/// The GFW drops UDP DNS responses for `iroh.link` domains, causing hickory resolution to time out.
/// This resolver returns Kotlin's pre-resolved IPs directly for domains in `DNS_OVERRIDES`
/// (Kotlin uses the system DNS, which may go through DoT/Private DNS to bypass the GFW); all other
/// domains still go through hickory.
struct OverrideResolver {
    inner: DnsResolver,
    overrides: HashMap<String, Vec<IpAddr>>,
    nameservers: Vec<SocketAddr>,
}

impl OverrideResolver {
    fn new(nameservers: Vec<SocketAddr>, overrides: HashMap<String, Vec<IpAddr>>) -> Self {
        let inner = if nameservers.is_empty() {
            DnsResolver::new()
        } else {
            // `NameserverConfig` keeps its fields private, so the port has to
            // be re-applied after the protocol constructor defaults it to 53.
            DnsResolver::builder()
                .add_nameserver_configs(
                    nameservers
                        .iter()
                        .map(|a| NameserverConfig::udp(a.ip()).with_port(a.port())),
                )
                .build()
        };
        Self {
            inner,
            overrides,
            nameservers,
        }
    }

    /// The addresses an override holds for `host`, if it holds any.
    ///
    /// The name is folded before the lookup: iroh asks for the fully-qualified
    /// spelling — every relay hostname it dials ends in a dot — and an override
    /// stored without the dot would otherwise never be found, and the query
    /// would fall through to the resolver the override exists to avoid.
    fn override_for(&self, host: &str) -> Option<&Vec<IpAddr>> {
        self.overrides.get(&crate::domains::fold_domain(host))
    }
}

impl fmt::Debug for OverrideResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverrideResolver")
            .field(
                "override_domains",
                &self.overrides.keys().collect::<Vec<_>>(),
            )
            .field("nameservers", &self.nameservers)
            .finish()
    }
}

impl Resolver for OverrideResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        if let Some(ips) = self.override_for(&host) {
            let ipv4s: Vec<Ipv4Addr> = ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(*v4),
                    _ => None,
                })
                .collect();
            if !ipv4s.is_empty() {
                jni_log!(
                    "[DEBUG:jni] DNS override hit for {} -> {} IPv4 addrs",
                    host,
                    ipv4s.len()
                );
                return Box::pin(
                    async move { Ok(Box::new(ipv4s.into_iter()) as BoxIter<Ipv4Addr>) },
                );
            }
        }
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_ipv4(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let ipv4s: Vec<Ipv4Addr> = result
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect();
            Ok(Box::new(ipv4s.into_iter()) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        if let Some(ips) = self.override_for(&host) {
            let ipv6s: Vec<Ipv6Addr> = ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(*v6),
                    _ => None,
                })
                .collect();
            if !ipv6s.is_empty() {
                jni_log!(
                    "[DEBUG:jni] DNS override hit for {} -> {} IPv6 addrs",
                    host,
                    ipv6s.len()
                );
                return Box::pin(
                    async move { Ok(Box::new(ipv6s.into_iter()) as BoxIter<Ipv6Addr>) },
                );
            }
        }
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_ipv6(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let ipv6s: Vec<Ipv6Addr> = result
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(v6),
                    _ => None,
                })
                .collect();
            Ok(Box::new(ipv6s.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_txt(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let v: Vec<TxtRecordData> = result.collect();
            Ok(Box::new(v.into_iter()) as BoxIter<TxtRecordData>)
        })
    }

    fn clear_cache(&self) {
        self.inner.clear_cache();
    }

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(OverrideResolver::new(
            self.nameservers.clone(),
            self.overrides.clone(),
        ))
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeInit(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| native_init(env))
}

fn native_init(env: &mut Env<'_>) -> jint {
    // Only the Android half needs the environment; elsewhere the parameter is
    // accepted so the entry point can be written once.
    #[cfg(not(target_os = "android"))]
    let _ = env;

    #[cfg(target_os = "android")]
    {
        // The VM this thread is attached to, asked for through `Env` rather
        // than read out of the JNI function table by hand: 0.22's `sys`
        // bindings group those slots by the JNI version they arrived in, so
        // there is no flat `GetJavaVM` field to call any more.
        //
        // `JavaVM::singleton()` would read tidier but it is still empty at this
        // point — jni records the VM the first time it hands out an `Env`, and
        // this runs before anything has. Going through `Env` is what fills it.
        //
        // Still checked rather than unwrapped: a null VM handed to the context
        // is a crash the first time anything logs, and this runs before there
        // is a logger to say so.
        if let Ok(vm) = env.get_java_vm() {
            let raw_vm = vm.get_raw();
            if !raw_vm.is_null() {
                // SAFETY: `raw_vm` is the VM this thread is attached to, which
                // is what ndk_context wants; it outlives the process.
                unsafe {
                    ndk_context::initialize_android_context(raw_vm as *mut _, std::ptr::null_mut());
                }
            }
        }
        // `Info` by default, not `Debug`: the debug logs along the data path
        // print request headers and payload previews, and logcat is readable
        // by anything with adb. Raise the level here to bring them back, and
        // only on a build you are debugging.
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("NexaVpnService"),
        );
    }

    // Chained rather than installed: whatever hook the host process already had
    // — the JVM's, or another library's — is still the one that decides what a
    // panic does to the process. `set_hook` on its own deletes it, so a host
    // that crash-reports through its own hook would silently stop reporting.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let msg = match panic_info.payload().downcast_ref::<&str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => s.as_str(),
                None => "Unknown panic",
            },
        };
        let location = panic_info
            .location()
            .map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        jni_log!("RUST PANIC: {}{}", msg, location);
        previous_hook(panic_info);
    }));

    // Four workers left two cores idle on every modern phone and made the TUN pump,
    // the QUIC driver and the smoltcp runner compete for the same threads. Scale with the
    // device instead, but keep a floor (4) and a ceiling (8) so a 16-core phone does not
    // spread the data path across enough threads to hurt cache locality.
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(4, 8);
    let rt = Builder::new_multi_thread()
        .thread_name("nexapipe-worker")
        .worker_threads(worker_threads)
        .enable_all()
        .build();
    jni_log!(
        "[DEBUG:jni] tokio runtime worker_threads={}",
        worker_threads
    );

    match rt {
        Ok(rt) => {
            let _ = RUNTIME.set(rt);
        }
        Err(e) => {
            jni_log!("Failed to create tokio runtime: {}", e);
            return -1;
        }
    }
    let _ = init_state();
    0
}

/// Kotlin obtains the system DNS from ConnectivityManager.getLinkProperties().dnsServers and
/// passes it as a comma-separated IP string (e.g. "192.168.1.1,8.8.8.8"). This function parses it
/// into SocketAddr (port fixed to 53, UDP) and stores it in CUSTOM_DNS_SERVERS. nativeStartIroh
/// reads it before bind. Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDnsServers(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    dns_servers: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        set_dns_servers(env, dns_servers)
    })
}

fn set_dns_servers(env: &mut Env<'_>, dns_servers: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetDnsServers");
        env.exception_clear();
        return -1;
    }

    let dns_str = match dns_servers.try_to_string(env) {
        Ok(s) => s,
        Err(_) => {
            jni_log!("Failed to get DNS servers string from JNI");
            return -1;
        }
    };

    // Parse the comma-separated IP list. Kotlin passes bare IPs (no port), so we always append port 53.
    let servers: Vec<SocketAddr> = dns_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
        .collect();

    jni_log!(
        "[DEBUG:jni] nativeSetDnsServers: parsed {} servers from '{}'",
        servers.len(),
        dns_str
    );

    match CUSTOM_DNS_SERVERS.lock() {
        Ok(mut guard) => {
            *guard = servers;
        }
        Err(_) => {
            jni_log!("Failed to lock CUSTOM_DNS_SERVERS mutex");
            return -1;
        }
    }
    0
}

/// Kotlin pre-resolves iroh infrastructure domains (dns.iroh.link, *.relay.n0.iroh.link) via the
/// system DNS (which may use DoT/Private DNS to bypass the GFW) and passes them in the format
/// "domain=ip1,ip2;domain2=ip3,ip4". This function parses and stores them in DNS_OVERRIDES.
/// OverrideResolver returns the pre-resolved IPs directly for these domains, bypassing hickory's
/// UDP DNS queries (the GFW drops UDP DNS responses for iroh.link domains).
/// This lets pkarr resolve (HTTPS to dns.iroh.link/pkarr/`<z32>`) reach iroh's pkarr server and fetch
/// the target node's EndpointInfo (relay URL + direct addr), even if DNS TXT is blocked by the GFW.
/// Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDnsOverride(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    overrides: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| set_dns_override(env, overrides))
}

fn set_dns_override(env: &mut Env<'_>, overrides: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetDnsOverride");
        env.exception_clear();
        return -1;
    }

    let overrides_str = match overrides.try_to_string(env) {
        Ok(s) => s,
        Err(_) => {
            jni_log!("Failed to get DNS overrides string from JNI");
            return -1;
        }
    };

    // Parse the "domain=ip1,ip2;domain2=ip3,ip4" format.
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for entry in overrides_str.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(2, '=');
        let domain = match parts.next() {
            Some(d) => crate::domains::fold_domain(d),
            None => continue,
        };
        if domain.is_empty() {
            continue;
        }
        let ips_str = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        let ips: Vec<IpAddr> = ips_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        if ips.is_empty() {
            jni_log!(
                "[DEBUG:jni] nativeSetDnsOverride: no valid IPs for domain '{}'",
                domain
            );
            continue;
        }
        jni_log!(
            "[DEBUG:jni] nativeSetDnsOverride: {} -> {} IPs {:?}",
            domain,
            ips.len(),
            ips
        );
        map.insert(domain, ips);
    }

    jni_log!(
        "[DEBUG:jni] nativeSetDnsOverride: parsed {} override entries from '{}'",
        map.len(),
        overrides_str
    );

    match DNS_OVERRIDES.lock() {
        Ok(mut guard) => {
            *guard = map;
        }
        Err(_) => {
            jni_log!("Failed to lock DNS_OVERRIDES mutex");
            return -1;
        }
    }
    0
}

/// Configure the relay mode, custom URL and, for a relay that asks for one, the bearer token.
/// relay_mode: "pinned"/"default"/"disabled"/"custom". relay_url and relay_auth_token are only
/// used when relay_mode="custom".
/// Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetRelayConfig(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    relay_mode: JString,
    relay_url: JString,
    relay_auth_token: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        set_relay_config(env, relay_mode, relay_url, relay_auth_token)
    })
}

/// Configure whether this endpoint may use n0's address lookup.
///
/// discovery_mode: "n0" (the default — a Node ID is looked up through
/// dns.iroh.link) or "none" (no lookup at all; a peer then has to bring an
/// address of its own, which is what a ticket carries).
///
/// Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDiscoveryMode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    discovery_mode: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        if env.exception_check() {
            jni_log!("JNI exception pending before nativeSetDiscoveryMode");
            env.exception_clear();
            return -1;
        }

        let mode_str = match discovery_mode.try_to_string(env) {
            Ok(s) => s,
            Err(_) => {
                jni_log!("Failed to get discovery_mode string from JNI");
                return -1;
            }
        };

        jni_log!("[DEBUG:jni] nativeSetDiscoveryMode: mode='{mode_str}'");

        if let Ok(mut mode) = DISCOVERY_MODE.lock() {
            *mode = mode_str;
        }
        0
    })
}

fn set_relay_config(
    env: &mut Env<'_>,
    relay_mode: JString,
    relay_url: JString,
    relay_auth_token: JString,
) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetRelayConfig");
        env.exception_clear();
        return -1;
    }

    let mode_str = match relay_mode.try_to_string(env) {
        Ok(s) => s,
        Err(_) => {
            jni_log!("Failed to get relay_mode string from JNI");
            return -1;
        }
    };

    let url_str = relay_url.try_to_string(env).unwrap_or_default();

    let token_str = relay_auth_token.try_to_string(env).unwrap_or_default();

    jni_log!(
        "[DEBUG:jni] nativeSetRelayConfig: mode='{}', url='{}', auth_token={}",
        mode_str,
        url_str,
        if token_str.is_empty() { "none" } else { "set" }
    );

    if let Ok(mut mode) = RELAY_MODE.lock() {
        *mode = mode_str;
    }
    if let Ok(mut url) = CUSTOM_RELAY_URL.lock() {
        *url = url_str;
    }
    if let Ok(mut token) = RELAY_AUTH_TOKEN.lock() {
        *token = SecretString::new(token_str);
    }
    0
}

/// Reads a Java string argument; None when it is null or not valid UTF-8.
fn read_jstring(env: &Env<'_>, s: &JString<'_>) -> Option<String> {
    s.try_to_string(env).ok()
}

/// The name this install answers as, if Kotlin gave it one.
///
/// An empty name is not a name: it is a field left blank, and sending it would
/// have the server refuse the handshake for a reason about printable ASCII
/// rather than about this side.
fn device_id() -> Option<String> {
    DEVICE_ID
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

/// Builds a [`TwoFactorAuth`] from a stored (client id, secret, algorithm) record
/// and, for one that was issued to a device, that device's name.
///
/// An empty secret means "no 2FA", which is how an endpoint that was never
/// given credentials — or whose credentials were cleared — is represented.
///
/// `device` names the device **this secret was issued to**, and is `None` for
/// everything else. It is not filled from the install's own name: what a plain
/// invite carries is the client's secret, filed under the client, and answering
/// with a device name would make the server look that device up and refuse with
/// `UnknownDevice` — a connected pair that worked yesterday, broken by a name
/// neither side asked for. Only a credential a server issued *to* a device is
/// presented as that device, which is exactly when Kotlin knows the name.
///
/// `key` is the device's own Ed25519 key, when it has one. A key is the
/// credential only where the record carries no secret: the server holds either
/// a secret or a public key for a device, never both — `DeviceAuth` in
/// `crates/nexapipe/src/auth/config.rs` refuses an entry with both — so a record
/// that has a secret is one the server issued as a secret, and the key beside it
/// is one it ignored. That matters because the key table is not pruned while the
/// process lives: a key left over from an enrollment that fell back to a secret
/// would otherwise sign for a device the server only knows by secret, and every
/// handshake would be refused while that secret was still valid.
///
/// The name is not optional for a key: a key always names the device it was
/// issued to, and the server refuses a key that names none.
fn two_factor_auth(cfg: &NodeCredential, key: Option<&iroh::SecretKey>) -> Option<TwoFactorAuth> {
    let (client_id, secret, algorithm, device) = cfg;
    let device = device.as_deref().map(str::trim).filter(|d| !d.is_empty());

    if !secret.as_str().trim().is_empty() {
        if key.is_some() {
            jni_log!("2FA: a secret is registered beside a device key; answering with the secret");
        }
        // A name nobody supports is refused rather than downgraded: the node
        // would compute codes the server does not accept, and every attempt
        // would fail with "wrong code".
        let algorithm = match TotpAlgorithm::try_from_name(algorithm) {
            Ok(algorithm) => algorithm,
            Err(e) => {
                jni_log!("2FA auth config invalid: {}", e);
                return None;
            }
        };
        return match TwoFactorAuth::new(client_id, secret.as_str(), algorithm) {
            Ok(auth) => Some(match device {
                Some(name) => auth.with_device(name),
                None => auth,
            }),
            Err(e) => {
                jni_log!("2FA auth config invalid: {}", e);
                None
            }
        };
    }

    // No secret at all, so the key is the credential — the TOTP path would
    // find nothing to build from and the node would answer with nothing.
    if let Some(key) = key {
        let Some(device) = device else {
            // A key with no device name is one that has not enrolled yet: the
            // name is what the server answers with, so before that there is
            // nothing to present — and the enrollment is what is about to
            // happen.
            jni_log!("2FA: a device key is registered without a device name; it enrolls first");
            return None;
        };
        return Some(TwoFactorAuth::with_key(client_id, key.clone(), device));
    }

    None
}

/// Read the 2FA credentials injected by Kotlin and build a TwoFactorAuth; returns None when unset or secret is empty.
fn current_two_factor_auth() -> Option<TwoFactorAuth> {
    let cfg = TWO_FACTOR.lock().map(|g| g.clone()).unwrap_or_default()?;
    two_factor_auth(&(cfg.0, cfg.1, cfg.2, None), None)
}

/// A snapshot of the per-endpoint credentials, so the mutex is not held across
/// the async calls that apply them.
fn node_two_factor_snapshot() -> Vec<(String, NodeCredential)> {
    match NODE_TWO_FACTOR.lock() {
        Ok(map) => map
            .iter()
            .map(|(id, cfg)| (id.clone(), cfg.clone()))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The credentials registered for one endpoint, if any.
fn node_two_factor_for(node_id: &str) -> Option<NodeCredential> {
    NODE_TWO_FACTOR
        .lock()
        .ok()
        .and_then(|map| map.get(node_id).cloned())
}

/// The device key registered for one endpoint, if any.
fn node_device_key_for(node_id: &str) -> Option<iroh::SecretKey> {
    NODE_DEVICE_KEYS
        .lock()
        .ok()
        .and_then(|map| map.get(node_id).cloned())
}

/// Whether this node has credentials, i.e. whether it must not enroll.
///
/// Not `node_two_factor_for(..).is_some()`: an entry whose secret is blank is
/// an entry that produces no `TwoFactorAuth`, so it authenticates with nothing
/// and — read as "has credentials" — never enrolls either. The node then
/// connects with no credential at all against a server that is asking for one.
///
/// A device key counts, but only once the node also names the device it was
/// issued to: the name comes back from the enrollment, so before that the key
/// is an offer rather than a credential, and the node still has to enroll.
fn node_has_two_factor(node_id: &str) -> bool {
    let Some(cfg) = node_two_factor_for(node_id) else {
        return false;
    };
    if !cfg.1.as_str().trim().is_empty() {
        return true;
    }
    let names_a_device = cfg
        .3
        .as_deref()
        .map(str::trim)
        .is_some_and(|name| !name.is_empty());
    names_a_device && node_device_key_for(node_id).is_some()
}

/// A snapshot of the per-endpoint enrollment tokens, so the mutex is not held across the
/// async calls that apply them.
fn node_enrollment_snapshot() -> Vec<(String, (String, SecretString))> {
    match NODE_ENROLLMENT.lock() {
        Ok(map) => map
            .iter()
            .map(|(id, cfg)| (id.clone(), cfg.clone()))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Names this device, once, for every **enrollment** it spends.
///
/// deviceId: printable ASCII without spaces, as `SettingsManager.deviceId()`
/// generates it.
///
/// An enrollment is where a name is asked for: what comes back is filed under
/// it on the server, and `nativeTakeIssuedCredential` hands the name back so
/// Kotlin can keep it beside the secret and send it from then on. Credentials
/// acquired any other way are answered unnamed, because a name the server's
/// table does not carry is refused rather than falling back — see
/// `two_factor_auth` — and the pairs an install already holds were issued to
/// the client, not to a device.
///
/// Must be called before nativeStartProxy. Its own entry point rather than one
/// more argument on the 2FA calls, which already have enough of them and which
/// every credential would then have to answer for itself.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDeviceId(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    device_id: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        if env.exception_check() {
            jni_log!("JNI exception pending before nativeSetDeviceId");
            env.exception_clear();
            return -1;
        }
        let name = read_jstring(env, &device_id).unwrap_or_default();
        jni_log!("[DEBUG:jni] nativeSetDeviceId: {} chars", name.trim().len());
        // A poisoned lock is a failure, not a silent skip. Skipping it left the
        // name unset while this returned 0, so Kotlin believed the device had
        // been named and went on connecting unnamed — which on a server that
        // refuses unnamed peers is a connection that keeps failing for a reason
        // nothing on either side reported.
        let Ok(mut slot) = DEVICE_ID.lock() else {
            jni_log!("[DEBUG:jni] nativeSetDeviceId: the device id lock is poisoned");
            return -1;
        };
        *slot = Some(name);
        0
    })
}

/// Configure the client's 2FA credentials. Must be called before nativeStartProxy.
/// algorithm: "sha1" / "sha256" / "sha512".
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetTwoFactor(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    client_id: JString,
    secret: JString,
    algorithm: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        set_two_factor(env, client_id, secret, algorithm)
    })
}

fn set_two_factor(
    env: &mut Env<'_>,
    client_id: JString,
    secret: JString,
    algorithm: JString,
) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetTwoFactor");
        env.exception_clear();
        return -1;
    }

    let client_id = match read_jstring(env, &client_id) {
        Some(v) => v,
        None => {
            jni_log!("Failed to read client_id in nativeSetTwoFactor");
            return -1;
        }
    };
    let secret = read_jstring(env, &secret).unwrap_or_default();
    let algorithm = read_jstring(env, &algorithm).unwrap_or_else(|| "sha1".to_string());

    jni_log!(
        "[DEBUG:jni] nativeSetTwoFactor: client_id='{}', algorithm='{}', secret={} chars",
        client_id,
        algorithm,
        secret.len()
    );

    if let Ok(mut tf) = TWO_FACTOR.lock() {
        *tf = Some((client_id, SecretString::new(secret), algorithm));
    }
    0
}

/// Configure the 2FA credentials of a single endpoint.
///
/// node_id:   endpoint ID these credentials belong to.
/// client_id: must match the ID configured in that server's [auth.clients].
/// secret:    Base32-encoded TOTP key (generated by `nexapipe --generate-2fa`).
/// algorithm: "sha1" / "sha256" / "sha512".
/// device:    the device this secret was issued to, or empty for one that
///            belongs to the client itself.
///
/// Only the pools of that backend get the credentials; every other endpoint is
/// left alone, so servers that do not share a secret — or that have 2FA turned
/// off altogether — stay reachable. Call `nativeClearNodeTwoFactor` first when
/// re-reading the configuration, otherwise credentials of an endpoint that no
/// longer has any are still applied.
///
/// Must be called before nativeStartProxy.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetTwoFactorForNode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
    client_id: JString,
    secret: JString,
    algorithm: JString,
    device: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        set_two_factor_for_node(env, node_id, client_id, secret, algorithm, device)
    })
}

fn set_two_factor_for_node(
    env: &mut Env<'_>,
    node_id: JString,
    client_id: JString,
    secret: JString,
    algorithm: JString,
    device: JString,
) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetTwoFactorForNode");
        env.exception_clear();
        return -1;
    }

    let node_id = match read_jstring(env, &node_id) {
        Some(v) => v.trim().to_string(),
        None => {
            jni_log!("Failed to read node_id in nativeSetTwoFactorForNode");
            return -1;
        }
    };
    let client_id = match read_jstring(env, &client_id) {
        Some(v) => v,
        None => {
            jni_log!("Failed to read client_id in nativeSetTwoFactorForNode");
            return -1;
        }
    };
    let secret = read_jstring(env, &secret).unwrap_or_default();
    let algorithm = read_jstring(env, &algorithm).unwrap_or_else(|| "sha1".to_string());
    // Empty is not the unnamed device, it is a field nobody filled in, and
    // answering with "" is refused for a reason about printable ASCII rather
    // than about this side.
    let device = read_jstring(env, &device)
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());

    if node_id.is_empty() {
        jni_log!("nativeSetTwoFactorForNode: empty node_id");
        return -1;
    }

    jni_log!(
        "[DEBUG:jni] nativeSetTwoFactorForNode: node='{}', client_id='{}', algorithm='{}', secret={} chars",
        node_id,
        client_id,
        algorithm,
        secret.len()
    );

    if let Ok(mut map) = NODE_TWO_FACTOR.lock() {
        map.insert(
            node_id,
            (client_id, SecretString::new(secret), algorithm, device),
        );
    }
    0
}

/// Mints a device key and hands back its private half, as 64 hex characters.
///
/// The key is generated here rather than in Kotlin because Android's
/// cryptography API has no Ed25519 below API 33, and the app supports API 26.
///
/// The private half is the credential: it is what proves this device to the
/// server, and it never leaves the device. Kotlin seals it at rest and reads
/// it back on every start, and it is what `nativeSetDeviceKeyForNode` takes.
///
/// Returns null when the key could not be handed over, which is a failure
/// rather than a key that proves nothing.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeGenerateDeviceKey(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        let key = DeviceKey::generate();
        let private = key.private_hex();
        jni_log!(
            "[DEBUG:jni] nativeGenerateDeviceKey: public={}",
            key.public_hex()
        );
        match env.new_string(private) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                jni_log!("nativeGenerateDeviceKey: {}", e);
                std::ptr::null_mut()
            }
        }
    })
}

/// Registers the device key of a single endpoint.
///
/// node_id:  endpoint ID this key belongs to.
/// key:      the private half, as 64 hex characters — what
///           `nativeGenerateDeviceKey` handed out.
///
/// A key is offered by the enrollment that spends the node's token, and signs
/// every handshake after it. A node whose enrollment has not happened yet has
/// a key but no device name, and the name is what the server answers with —
/// so the key is an offer until then, not a credential.
///
/// Must be called before nativeStartProxy.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDeviceKeyForNode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
    key: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        if env.exception_check() {
            jni_log!("JNI exception pending before nativeSetDeviceKeyForNode");
            env.exception_clear();
            return -1;
        }
        let node_id = match read_jstring(env, &node_id) {
            Some(v) => v.trim().to_string(),
            None => {
                jni_log!("Failed to read node_id in nativeSetDeviceKeyForNode");
                return -1;
            }
        };
        if node_id.is_empty() {
            jni_log!("nativeSetDeviceKeyForNode: empty node_id");
            return -1;
        }
        let spelled = read_jstring(env, &key).unwrap_or_default();
        let key = match DeviceKey::from_hex(&spelled) {
            Ok(key) => key,
            Err(e) => {
                jni_log!("nativeSetDeviceKeyForNode: {}", e);
                return -1;
            }
        };
        jni_log!(
            "[DEBUG:jni] nativeSetDeviceKeyForNode: node='{}', public={}",
            node_id,
            key.public_hex()
        );
        if let Ok(mut map) = NODE_DEVICE_KEYS.lock() {
            map.insert(node_id, key.secret_key().clone());
        }
        0
    })
}

/// Drops every credential registered with `nativeSetTwoFactorForNode`.
///
/// Read the configuration back through this pair on every connect: without the
/// clear, an endpoint whose 2FA the user just turned off would keep the old
/// credentials for the lifetime of the process and keep opening auth streams
/// the server no longer expects.
/// Registers a one-time enrollment token for a single endpoint.
///
/// node_id:   endpoint ID the token belongs to.
/// client_id: which `[auth.clients]` entry the token is pending for.
/// token:     the token itself, as carried by a `v=2` invite.
///
/// The first connection to that endpoint spends it and answers with the real secret; see
/// `nativeTakeIssuedCredential` for what Kotlin has to do with the answer. A node that
/// already has credentials keeps them and never enrolls, so a token is only ever set for
/// an endpoint that has none.
///
/// Must be called before nativeStartProxy.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetEnrollmentForNode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
    client_id: JString,
    token: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        set_enrollment_for_node(env, node_id, client_id, token)
    })
}

fn set_enrollment_for_node(
    env: &mut Env<'_>,
    node_id: JString,
    client_id: JString,
    token: JString,
) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetEnrollmentForNode");
        env.exception_clear();
        return -1;
    }

    let node_id = match read_jstring(env, &node_id) {
        Some(v) => v.trim().to_string(),
        None => {
            jni_log!("Failed to read node_id in nativeSetEnrollmentForNode");
            return -1;
        }
    };
    let client_id = match read_jstring(env, &client_id) {
        Some(v) => v,
        None => {
            jni_log!("Failed to read client_id in nativeSetEnrollmentForNode");
            return -1;
        }
    };
    let token = read_jstring(env, &token).unwrap_or_default();

    if node_id.is_empty() {
        jni_log!("nativeSetEnrollmentForNode: empty node_id");
        return -1;
    }

    jni_log!(
        "[DEBUG:jni] nativeSetEnrollmentForNode: node='{}', client_id='{}', token={} chars",
        node_id,
        client_id,
        token.len()
    );

    if let Ok(mut map) = NODE_ENROLLMENT.lock() {
        map.insert(node_id, (client_id, SecretString::new(token)));
    }
    0
}

/// Drops every credential — every enrollment token and every device key —
/// registered per endpoint.
///
/// The token and key tables ride along on purpose: they are the same question
/// ("how does this endpoint authenticate?"), and reading the configuration back
/// through one call is what keeps a stale entry from applying to a node that
/// no longer has one.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeClearNodeTwoFactor(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    if let Ok(mut map) = NODE_TWO_FACTOR.lock() {
        map.clear();
    }
    if let Ok(mut map) = NODE_ENROLLMENT.lock() {
        map.clear();
    }
    if let Ok(mut map) = NODE_DEVICE_KEYS.lock() {
        map.clear();
    }
    0
}

/// The credential the server issued for an enrollment token, cleared on read.
///
/// `client_id`, `secret`, `algorithm`, the device name and the public key,
/// newline separated, or null when this run enrolled nothing. Spending a token
/// rotates that client's secret server-side, so this is the only chance to read
/// what it bought: without it the device holds an invite the server has
/// already forgotten and cannot enroll again.
///
/// A credential that is a key has an empty secret and an empty algorithm, and
/// carries its public half in the last line instead — that is how the caller
/// tells the two kinds apart.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeTakeIssuedCredential(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        take_issued_credential(env)
    })
}

fn take_issued_credential(env: &mut Env<'_>) -> jstring {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    // Caught rather than let out of the frame: this blocks on the runtime, and
    // a panic there unwinds through an `extern "system"` boundary, which on
    // Android is a native crash instead of something the JVM can report.
    let issued = match catching_panic("nativeTakeIssuedCredential", || {
        runtime.block_on(async {
            // The endpoint group is where a start with several nodes keeps its pools; the
            // single-pool legacy path keeps the same answer one level down.
            if let Some(state) = get_state() {
                let group = {
                    let guard = match state.lock() {
                        Ok(g) => g,
                        Err(_) => return None,
                    };
                    guard.endpoint_group.clone()
                };
                if let Some(group) = group {
                    if let Some(issued) = group.take_issued_credential().await {
                        return Some(issued);
                    }
                }
                let pool = {
                    let guard = match state.lock() {
                        Ok(g) => g,
                        Err(_) => return None,
                    };
                    guard.conn_pool.clone()
                };
                if let Some(pool) = pool {
                    return pool.take_issued_credential().await;
                }
            }
            None
        })
    }) {
        Some(issued) => issued,
        None => return std::ptr::null_mut(),
    };

    let Some(issued) = issued else {
        return std::ptr::null_mut();
    };
    // Five lines, each of them only since it became a thing: the name the
    // server filed this credential under, which Kotlin has to write down beside
    // it — a secret kept without its name is one that no longer answers — and
    // the public half of the key, which is how Kotlin tells a key credential
    // from a secret one. Both are empty when they do not apply, and a caller
    // that reads three or four lines still reads what it read before.
    let encoded = format!(
        "{}\n{}\n{}\n{}\n{}",
        issued.client_id,
        // The credential leaves the process here — it is on its way to the
        // app's own storage — so this copy is a plain string, and the one
        // that stays behind is wiped with the credential.
        issued.secret.expose_secret(),
        issued.algorithm,
        issued.device.unwrap_or_default(),
        issued.public_key.unwrap_or_default()
    );
    match env.new_string(encoded) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartIroh(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        start_iroh(env)
    })
}

fn start_iroh(env: &mut Env<'_>) -> jstring {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeStartIroh");
        env.exception_clear();
        return std::ptr::null_mut();
    }

    // The reason left behind by an earlier failure is not the reason for this
    // one: the caller reads it after a failed start, and a stale one is a
    // reason for something that did not happen. The attempt below writes its
    // own.
    clear_last_error();

    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    // Fast path: if an endpoint already exists, return immediately. Holds the lock briefly without crossing any await.
    {
        if let Ok(guard) = ENDPOINT.lock() {
            if let Some(ep) = guard.as_ref() {
                let id = ep.id().to_string();
                return match env.new_string(id) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        }
    }

    // Don't hold the ENDPOINT lock during bind() to avoid deadlocking with nativeStopProxy.
    let gen_before = ENDPOINT_GEN.load(Ordering::Acquire);

    // Read the system DNS servers injected by Kotlin plus the pre-resolved iroh infrastructure IPs.
    // Hold the lock briefly to clone, then release immediately, without crossing await.
    let custom_dns: Vec<SocketAddr> = CUSTOM_DNS_SERVERS
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let dns_overrides: HashMap<String, Vec<IpAddr>> =
        DNS_OVERRIDES.lock().map(|g| g.clone()).unwrap_or_default();

    let bind_result: Result<Endpoint, ()> = runtime.block_on(async move {
        // Read the relay config injected by Kotlin (set by nativeSetRelayConfig).
        // An empty mode means Kotlin has not injected one yet -> "pinned", which is what the
        // UI defaults to. Anything else either resolves or is a hard error; no mode is ever
        // silently substituted for the one that was asked for.
        let cfg_mode = RELAY_MODE.lock().map(|g| g.clone()).unwrap_or_default();
        let cfg_url = CUSTOM_RELAY_URL
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let cfg_token = RELAY_AUTH_TOKEN
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let relay =
            match RelayModeSpec::parse(Some(&cfg_mode), Some(&cfg_url), Some(cfg_token.as_str())) {
                Ok(spec) => spec.unwrap_or(RelayModeSpec::Pinned),
                Err(e) => {
                    // The reason is what the user has to act on, and the log
                    // line is behind the debug level: without this the app
                    // says "could not start iroh" and nothing else.
                    set_last_error(format!("invalid relay configuration: {e}"));
                    jni_log!("[iroh] invalid relay configuration: {e}");
                    return Err(());
                }
            };
        if !relay.uses_url() && !cfg_url.is_empty() {
            jni_log!(
                "[iroh] ignoring relay_url {:?}: mode {} does not use one",
                cfg_url,
                cfg_mode
            );
        }
        jni_log!("[iroh] relay: {}", relay.describe());
        // Whether this endpoint may ask n0 where a peer is. It is the one piece
        // of n0's infrastructure a relay setting does not reach, so it gets a
        // setting of its own.
        let cfg_discovery = DISCOVERY_MODE.lock().map(|g| g.clone()).unwrap_or_default();
        // An empty value means nothing has been injected yet, which falls back to "n0" —
        // the same reading an unset setting gets everywhere else. Only a value that
        // names a mode wrongly is an error.
        let discovery = match DiscoveryMode::parse_or_default(&cfg_discovery) {
            Ok(mode) => mode,
            Err(e) => {
                // The reason is what the user has to act on, and the log
                // line is behind the debug level: without this the app says
                // "could not start iroh" and nothing else.
                set_last_error(format!("invalid discovery configuration: {e}"));
                jni_log!("[iroh] invalid discovery configuration: {e}");
                return Err(());
            }
        };
        jni_log!("[iroh] discovery: {}", discovery.describe());
        // Which relay a *peer* may be dialled through. `custom` says this
        // endpoint uses one relay and no other, and that has to hold for the
        // peer too — iroh's `relay_mode` only bounds the relay this endpoint
        // registers with, so a peer naming somebody else's relay would
        // otherwise be dialled through it. A peer named only by a Node ID is
        // dialled while the lookup above is on — the Android app names every
        // peer that way — and refused once the lookup is off.
        let restriction = relay.dial_restriction(discovery);
        if let Some(restriction) = &restriction {
            let covered = restriction.describe();
            jni_log!("[iroh] peers are dialled through {covered}");
        }
        let mut builder = Endpoint::builder(presets::N0)
            .alpns(crate::connection_pool::alpns(
                nexapipe_proto::protocol::Protocol::Legacy,
            ))
            .relay_mode(relay.relay_mode());
        builder = discovery.apply(builder);
        if let Some(restriction) = restriction {
            builder = builder.hooks(restriction);
        }
        // Always wrap hickory with OverrideResolver:
        // - For iroh infrastructure domains in DNS_OVERRIDES (dns.iroh.link, *.relay.n0.iroh.link),
        //   return Kotlin's pre-resolved IPs directly, bypassing the GFW's blocking of iroh.link
        //   UDP DNS responses. This lets pkarr resolve (HTTPS to dns.iroh.link/pkarr/<z32>) reach the
        //   pkarr server and fetch the target node's EndpointInfo; relay domains can also reach the
        //   relay server.
        // - All other domains go through hickory + the system DNS servers (custom_dns).
        //   Even if custom_dns is empty, OverrideResolver internally falls back to DnsResolver::new().
        jni_log!(
            "[DEBUG:jni] Building OverrideResolver: {} DNS servers, {} override domains {:?}",
            custom_dns.len(),
            dns_overrides.len(),
            dns_overrides.keys().collect::<Vec<_>>()
        );
        let override_resolver = OverrideResolver::new(custom_dns.clone(), dns_overrides);
        let dns_resolver = DnsResolver::custom(override_resolver);
        // One inner TCP connection == one QUIC bi-stream, so the per-stream receive window is
        // the throughput ceiling of every proxied connection. iroh's 1.25 MB default caps a
        // 200 ms path at roughly 50 Mbps; see crate::transport for the full rationale.
        let (transport, tuning) = crate::transport::transport_config_with_tuning();
        jni_log!("[DEBUG:jni] QUIC transport tuning: {}", tuning.describe());
        let builder = builder
            .dns_resolver(dns_resolver)
            .transport_config(transport);

        match tokio::time::timeout(IROH_BIND_TIMEOUT, builder.bind()).await {
            Ok(Ok(ep)) => Ok(ep),
            Ok(Err(e)) => {
                // The reason the caller shows the user: "could not start iroh"
                // on its own names nothing they can act on.
                set_last_error(format!("failed to start the iroh endpoint: {e}"));
                jni_log!("Failed to start iroh endpoint: {}", e);
                Err(())
            }
            Err(_) => {
                set_last_error(format!(
                    "the iroh endpoint did not start within {}s",
                    IROH_BIND_TIMEOUT.as_secs()
                ));
                jni_log!(
                    "iroh endpoint bind timed out after {}s",
                    IROH_BIND_TIMEOUT.as_secs()
                );
                Err(())
            }
        }
    });
    let ep = match bind_result {
        Ok(ep) => ep,
        Err(()) => return std::ptr::null_mut(),
    };

    // Re-lock to commit: if a stop happened in between (generation changed), discard the late endpoint;
    // if a concurrent startIroh already wrote one, return its id; otherwise write our own.
    let node_id = match ENDPOINT.lock() {
        Ok(mut guard) => {
            let gen_now = ENDPOINT_GEN.load(Ordering::Acquire);
            if gen_now != gen_before {
                jni_log!("endpoint generation changed during bind, discarding late endpoint");
                drop(ep); // Stray late result of an isolated bind: discard it; don't revive a released tunnel.
                return std::ptr::null_mut();
            }
            if let Some(existing) = guard.as_ref() {
                existing.id().to_string()
            } else {
                let id = ep.id().to_string();
                *guard = Some(ep);
                id
            }
        }
        Err(_) => {
            jni_log!("Failed to lock endpoint mutex on commit");
            return std::ptr::null_mut();
        }
    };

    match env.new_string(node_id) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartProxy(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| start_proxy(env))
}

fn start_proxy(env: &mut Env<'_>) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeStartProxy");
        env.exception_clear();
        return -1;
    }

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            set_last_error("Native runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            set_last_error("Native state not initialized");
            return -1;
        }
    };

    let nodes: Vec<NodeConfig>;
    let domain_mappings: Vec<DomainMapping>;

    {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state mutex (poisoned)");
                return -1;
            }
        };
        nodes = guard.nodes.clone();
        domain_mappings = guard.domain_mappings.clone();
    }

    // Pre-flight: every configured endpoint ID must parse. Checked before anything is bound, so a
    // malformed ID is reported as a malformed ID (and not retried as if the port were taken).
    if let Some(message) = first_invalid_node_id(&domain_mappings, &nodes) {
        jni_log!("[DEBUG:jni] nativeStartProxy rejected: {}", message);
        set_last_error(message);
        return RESULT_CONFIG_ERROR;
    }
    clear_last_error();

    jni_log!("[DEBUG:jni] nativeStartProxy called (no local listener)");

    // Fail fast: refuse to continue when there is no endpoint. Otherwise we'd fall into the
    // "one bind() per node" branch (connection_pool.rs, no timeout, scales with backend count) and
    // reintroduce the hang.
    let ep = match get_endpoint() {
        Some(ep) => ep,
        None => {
            jni_log!("[DEBUG:jni] No iroh endpoint available; call nativeStartIroh first");
            set_last_error("No iroh endpoint available; call nativeStartIroh first");
            return -1;
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move {
            let endpoint_group: EndpointGroup;

            if !domain_mappings.is_empty() {
                jni_log!(
                    "[DEBUG:jni] Using domain_mappings ({} entries)",
                    domain_mappings.len()
                );
                endpoint_group = match tokio::time::timeout(
                    START_PROXY_TIMEOUT,
                    EndpointGroup::new_with_domain_mappings_and_endpoint(
                        domain_mappings,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        ep.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(eg)) => eg,
                    Ok(Err(e)) => {
                        jni_log!("Failed to create endpoint group: {}", e);
                        return Err(format!("Failed to create endpoint group: {}", e));
                    }
                    Err(_) => {
                        jni_log!(
                            "Endpoint group creation timed out after {}s",
                            START_PROXY_TIMEOUT.as_secs()
                        );
                        return Err("Endpoint group creation timed out".to_string());
                    }
                };
            } else if !nodes.is_empty() {
                jni_log!("[DEBUG:jni] Using nodes ({} entries)", nodes.len());

                // The destinations themselves are handed to the TUN proxy
                // separately (nativeStartTunProxy), so only their presence is
                // checked here: a node without a domain is a configuration
                // error either way, and saying so beats coming up "connected"
                // over a tunnel that has nothing to route.
                if nodes.iter().all(|node| node.domains.is_empty()) {
                    jni_log!("No domains configured for nodes");
                    return Err("No domains configured for nodes".to_string());
                }

                endpoint_group = match tokio::time::timeout(
                    START_PROXY_TIMEOUT,
                    EndpointGroup::new_with_nodes_and_endpoint(
                        nodes,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        ep.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(eg)) => eg,
                    Ok(Err(e)) => {
                        jni_log!("Failed to create endpoint group: {}", e);
                        return Err(format!("Failed to create endpoint group: {}", e));
                    }
                    Err(_) => {
                        jni_log!(
                            "Endpoint group creation timed out after {}s",
                            START_PROXY_TIMEOUT.as_secs()
                        );
                        return Err("Endpoint group creation timed out".to_string());
                    }
                };
            } else {
                jni_log!("No nodes or domain mappings configured");
                return Err("No nodes or domain mappings configured".to_string());
            }

            // 2FA: push the Kotlin-injected credentials to the connection group; new connections run the auth handshake first.
            // The global pair goes to every pool first, then each endpoint's own
            // credentials override it. An endpoint with no entry of its own —
            // and an empty secret counts as an explicit "none" — ends up with
            // no credentials, so it never opens an auth stream against a server
            // that does not expect one.
            if let Some(auth) = current_two_factor_auth() {
                endpoint_group.set_two_factor(Some(auth)).await;
            }
            for (node_id, cfg) in node_two_factor_snapshot() {
                // Passed along, not preferred: the key is the credential only
                // where the record has no secret, and `two_factor_auth` is what
                // decides that. A key the server never recorded (an older
                // server ignored the offer) must not shadow the secret it
                // issued instead.
                let key = node_device_key_for(&node_id);
                endpoint_group
                    .set_two_factor_for(&node_id, two_factor_auth(&cfg, key.as_ref()))
                    .await;
            }
            // Enrollment last, and only where no credentials were registered: enrolling
            // rotates that client's secret, so a node that already has one must not spend a
            // token again — every other device enrolled from the same code would be locked
            // out by it.
            for (node_id, (client_id, token)) in node_enrollment_snapshot() {
                if node_has_two_factor(&node_id) {
                    continue;
                }
                // Named where the token is spent, which is the only moment a
                // name means anything: it is what makes the credential that
                // comes back this phone's alone, and enrolling without one is
                // how a device ends up sharing the client's secret — the thing
                // that makes revoking one rotate every other one.
                let name = device_id();
                let enrollment = Enrollment::new(&client_id, token.as_str());
                let enrollment = match &name {
                    Some(name) => enrollment.with_device(name),
                    None => enrollment,
                };
                // A device key is offered here rather than asked for: the server
                // records the public half under the device's name and issues no
                // secret at all, so the private half never has to be anywhere
                // but this device. A server that predates keys ignores the offer
                // and issues a secret as it always has, which is what the
                // credential then is.
                //
                // Only with a name, because the server refuses a key that names
                // no device — and a refusal that reads as a bad token would be a
                // lie: the token was fine and the device had no name.
                let enrollment = match (&name, node_device_key_for(&node_id)) {
                    (Some(_), Some(key)) => enrollment.with_key(key),
                    _ => enrollment,
                };
                endpoint_group
                    .set_enrollment_for(&node_id, Some(enrollment))
                    .await;
                jni_log!("[DEBUG:jni] enrollment armed for node '{}'", node_id);
            }

            let endpoint_group_arc = Arc::new(endpoint_group);

            // The backends are asked whether they still answer, on a timer, for
            // as long as this group is up. A phone changes network far more
            // often than a server does, and without this the group only ever
            // dialled at startup: a backend that went away — or a tunnel that
            // stopped working after a switch to cellular — was noticed by the
            // request that needed it, which on Android is an app that has
            // already timed out.
            endpoint_group_arc.start_health_probe();

            // Deliberately no local TCP listener here. On Android the tunnel is
            // reached through the TUN fd (nativeStartTunProxy) alone; a
            // listener on 127.0.0.1 is reachable by every other app on the
            // device and would hand them an already-authenticated tunnel
            // without anything asking the user. It is not part of the data
            // path, so there is nothing that has to replace it.

            // Write back to state: re-lock and verify it wasn't cleared by a concurrent stop.
            {
                let mut guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        jni_log!("Failed to lock state mutex (poisoned)");
                        return Err("Failed to update state".to_string());
                    }
                };
                if guard.endpoint_group.is_some() {
                    jni_log!(
                        "[DEBUG:jni] State already has an endpoint group (concurrent start/stop), aborting"
                    );
                    return Err("Proxy already running".to_string());
                }
                guard.endpoint_group = Some(endpoint_group_arc);
            }

            Ok(())
        })
    }));

    match result {
        Ok(Ok(_)) => {
            jni_log!("[DEBUG:jni] nativeStartProxy returning success");
            0
        }
        Ok(Err(e)) => {
            jni_log!("[DEBUG:jni] Proxy start error: {}", e);
            let code = if e.contains("Parse error") || e.contains("No nodes or domain mappings") {
                RESULT_CONFIG_ERROR
            } else {
                -1
            };
            set_last_error(e);
            code
        }
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during proxy start");
            set_last_error("Native proxy start panicked");
            -1
        }
    }
}

/// Returns the reason behind the last failed native call, and clears it.
///
/// The start entry points return only an int, so this is how Kotlin learns what actually went
/// wrong (a malformed node ID, an occupied port, ...). Returns null when there is nothing to
/// report.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeTakeLastError(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        read_last_error(env)
    })
}

fn read_last_error(env: &mut Env<'_>) -> jstring {
    let message = match take_last_error() {
        Some(message) => message,
        None => return std::ptr::null_mut(),
    };
    match env.new_string(message) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Validates a node ID with the exact parser the connection path uses.
///
/// Returns null when it parses, otherwise the parser's reason. Callers use this for pre-flight
/// checks and to give immediate feedback while the user edits a node.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeValidateNodeId(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        validate_node_id(env, node_id)
    })
}

fn validate_node_id(env: &mut Env<'_>, node_id: JString) -> jstring {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeValidateNodeId");
        env.exception_clear();
        return std::ptr::null_mut();
    }

    let node_id = match node_id.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let reason = match node_id_error(node_id.trim()) {
        Some(reason) => reason,
        None => return std::ptr::null_mut(),
    };

    match env.new_string(reason) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Pre-connect / warm-up: establish one iroh connection per configured backend
/// and cache it in the connection pool, so the first real request does not pay
/// the QUIC/relay handshake latency. Must be called after `nativeStartProxy`
/// (which creates the `EndpointGroup`). Returns the number of backends warmed,
/// or -1 on error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativePreconnect(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativePreconnect called");

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("[DEBUG:jni] nativePreconnect: runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] nativePreconnect: state not initialized");
            return -1;
        }
    };

    let endpoint_group = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] nativePreconnect: failed to lock state (poisoned)");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!(
                    "[DEBUG:jni] nativePreconnect: endpoint_group is None - call nativeStartProxy first"
                );
                return -1;
            }
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move {
            match tokio::time::timeout(PRECONNECT_TIMEOUT, endpoint_group.preconnect_report()).await
            {
                Ok(report) => {
                    // A backend that answered and then refused the connection
                    // for missing 2FA is counted as unreachable, which on its
                    // own reads like "server down". Say what actually happened:
                    // the credentials are missing on this side.
                    if report.any_auth_required() && !report.any_reachable() {
                        jni_log!("[DEBUG:jni] nativePreconnect: backend requires 2FA");
                        set_last_error(AUTH_REQUIRED_MESSAGE);
                    }
                    report.reachable.len() as jint
                }
                Err(_) => {
                    jni_log!("[DEBUG:jni] nativePreconnect timed out");
                    -1
                }
            }
        })
    }));

    match result {
        Ok(count) => {
            jni_log!(
                "[DEBUG:jni] nativePreconnect finished: {} backend(s) warmed",
                count
            );
            count
        }
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativePreconnect");
            -1
        }
    }
}

/// How each configured backend is currently reached, and how far away it is: one
/// `<endpointId>=<kind>/<rttMs>` entry per backend, joined with `;`, where `kind` is `direct`,
/// `relay` or `unknown` and `rttMs` is the round-trip time in milliseconds, or `-` when iroh has
/// no sample yet.
///
/// This is the *runtime* answer, read off the paths iroh actually selected — not the relay URL
/// from the configuration, which only names a relay that may be used. A backend that has never
/// connected reports `unknown`.
///
/// Returns null when there is no endpoint group yet (nothing was started), so Kotlin can tell
/// "nothing to report" from "asked and answered".
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeLinkKinds(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        link_kinds(env)
    })
}

fn link_kinds(env: &mut Env<'_>) -> jstring {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let endpoint_group = {
        let state = match get_state() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => return std::ptr::null_mut(),
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => return std::ptr::null_mut(),
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move { endpoint_group.link_statuses().await })
    }));

    let statuses = match result {
        Ok(statuses) => statuses,
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativeLinkKinds");
            return std::ptr::null_mut();
        }
    };

    let encoded = statuses
        .iter()
        .map(|(id, status)| crate::connection_pool::encode_link_status(id, status))
        .collect::<Vec<_>>()
        .join(";");

    jni_log!("[DEBUG:jni] nativeLinkKinds: {}", encoded);

    match env.new_string(encoded) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// What each backend has carried, and how many flows are open to it right now: one
/// `<endpointId>=<sent>/<received>/<active>` entry per node, joined with `;`. That is the entry
/// shape [`Java_com_nexa_pipe_IrohProxy_nativeLinkKinds`] already uses, so Kotlin parses both
/// answers the same way and lines them up per node.
///
/// The three numbers are cumulative bytes / open-flow count since this group was built, not
/// rates: a caller wanting a rate has to sample twice. The key is the raw endpoint ID, again as
/// `nativeLinkKinds` reports it. A node the group has carried nothing for is absent rather than
/// zero, which a caller showing per-node figures has to say rather than leave looking like
/// "down". Counters reset when the proxy is stopped and started again, so a drop between two
/// samples is a restart, not negative throughput.
///
/// Sorted by node ID so a UI polling it does not see the entries change places between polls.
///
/// Returns null when there is no endpoint group yet (nothing was started), so Kotlin can tell
/// "nothing to report" from "asked and answered".
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeTraffic(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| traffic(env))
}

fn traffic(env: &mut Env<'_>) -> jstring {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let endpoint_group = {
        let state = match get_state() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => return std::ptr::null_mut(),
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => return std::ptr::null_mut(),
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move { endpoint_group.traffic_snapshot() })
    }));

    let volumes = match result {
        Ok(volumes) => volumes,
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativeTraffic");
            return std::ptr::null_mut();
        }
    };

    let mut entries: Vec<(String, String)> = volumes
        .iter()
        .map(|(id, volume)| {
            (
                id.to_string(),
                format!("{}/{}/{}", volume.sent, volume.received, volume.active),
            )
        })
        .collect();
    // HashMap iteration order is not stable, and a poll that reorders entries reads as nodes
    // moving around in the UI.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let encoded = entries
        .iter()
        .map(|(id, values)| format!("{}={}", id, values))
        .collect::<Vec<_>>()
        .join(";");

    jni_log!("[DEBUG:jni] nativeTraffic: {}", encoded);

    match env.new_string(encoded) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Closes and forgets every cached backend connection, keeping the iroh endpoint.
///
/// This is the Android network-switch recovery step. A connection opened on the previous
/// network is not closed as far as QUIC is concerned — its `close_reason()` is still `None`
/// while its path is dead — so the pool keeps handing it out and every proxied request fails
/// or hangs, even though the tunnel itself was rebuilt correctly. Dropping them makes the next
/// request dial on the current network; `nativePreconnect` then fills the pool again.
///
/// The endpoint is deliberately left alone: it is shared with the running TUN proxy, and
/// rebinding it would pull a working tunnel apart.
///
/// Returns 0 when the connections were dropped, -1 when nothing has been started yet.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeDropConnections(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("[DEBUG:jni] nativeDropConnections: runtime not initialized");
            return -1;
        }
    };

    let endpoint_group = {
        let state = match get_state() {
            Some(s) => s,
            None => {
                jni_log!("[DEBUG:jni] nativeDropConnections: state not initialized");
                return -1;
            }
        };
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] nativeDropConnections: failed to lock state");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!("[DEBUG:jni] nativeDropConnections: no endpoint group yet");
                return -1;
            }
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move { endpoint_group.drop_connections().await })
    }));

    match result {
        Ok(()) => {
            jni_log!("[DEBUG:jni] nativeDropConnections: dropped every cached connection");
            0
        }
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativeDropConnections");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopProxy(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    // The body drives the runtime through three `block_on`s. Unwinding out of
    // an `extern "system"` frame is a native crash on Android rather than
    // something the JVM can turn into an exception, so it is caught here.
    catching_panic("nativeStopProxy", stop_proxy).unwrap_or(-1)
}

fn stop_proxy() -> jint {
    jni_log!("[DEBUG:jni] nativeStopProxy called (proxy-only, keeping iroh endpoint)");

    // Note: this function only stops endpoint_group / conn_pool, and does not touch the global
    // ENDPOINT. This way the connect path can call it before rebuilding the endpoint group
    // without tearing down the endpoint that ensureIrohStarted already built.
    // For a full teardown (including the endpoint), use nativeDestroy.
    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] State not initialized, nothing to stop");
            return 0;
        }
    };

    // Phase 1.5: stop the TUN proxy first (must happen before endpoint_group.close_all()).
    // The TUN proxy's TCP connection tasks hold an Arc<EndpointGroup> clone; closing first would
    // make them access an already-closed connection pool. shutdown() aborts and waits for the
    // tasks to finish, ensuring the fd is closed.
    #[cfg(all(feature = "tun-proxy", target_os = "android"))]
    {
        let tun_proxy = {
            let mut guard = match state.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    // See the note on the lock below: the TUN fd is only closed by
                    // the proxy this is about to take out, so abandoning the
                    // cleanup because another thread once panicked leaves it open
                    // for the life of the process.
                    jni_log!(
                        "[WARN:jni] State lock poisoned, recovering the guard to close the TUN proxy"
                    );
                    poisoned.into_inner()
                }
            };
            guard.tun_proxy.take()
        }; // guard dropped
        if let Some(tp) = tun_proxy {
            if let Some(r) = get_runtime() {
                tp.shutdown(r);
                jni_log!("[DEBUG:jni] TUN proxy shutdown complete");
            } else {
                // No runtime — just abort; Drop will call stop().
                jni_log!("[DEBUG:jni] No runtime, aborting TUN proxy without join");
            }
            // tp dropped here (if not consumed by shutdown)
        }
    }

    // Phase 2: lock state, take the resources out (fields set to None), drop the guard immediately, then enter any block_on.
    let (endpoint_group, conn_pool) = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // A poisoned lock means some thread panicked while holding it,
                // which is exactly when the resources it guards most need
                // closing. Recovering the guard is the only way to reach them:
                // returning here used to leave the endpoint group and the
                // connection pool in place, so the endpoint was never closed
                // and a later start inherited half of a stopped one.
                jni_log!("[WARN:jni] State lock poisoned, recovering the guard to finish the stop");
                poisoned.into_inner()
            }
        };
        jni_log!(
            "[DEBUG:jni] Stop: endpoint_group exists = {}, conn_pool exists = {}",
            guard.endpoint_group.is_some(),
            guard.conn_pool.is_some()
        );
        (guard.endpoint_group.take(), guard.conn_pool.take())
    }; // guard dropped here -- no longer holding the state lock.

    let runtime = get_runtime();

    // Phase 3: close the endpoint group / pool, each with its own timeout, without holding the state lock.
    if let Some(r) = runtime {
        if let Some(group) = endpoint_group.as_ref() {
            let _ = r.block_on(async {
                match tokio::time::timeout(CLOSE_ALL_TIMEOUT, group.close_all()).await {
                    Ok(_) => jni_log!("[DEBUG:jni] endpoint_group close_all done"),
                    Err(_) => jni_log!(
                        "[DEBUG:jni] endpoint_group close_all timed out after {}s",
                        CLOSE_ALL_TIMEOUT.as_secs()
                    ),
                }
            });
        }
        if let Some(pool) = conn_pool.as_ref() {
            let _ = r.block_on(async {
                match tokio::time::timeout(CLOSE_ALL_TIMEOUT, pool.close_all()).await {
                    Ok(_) => jni_log!("[DEBUG:jni] conn_pool close_all done"),
                    Err(_) => jni_log!(
                        "[DEBUG:jni] conn_pool close_all timed out after {}s",
                        CLOSE_ALL_TIMEOUT.as_secs()
                    ),
                }
            });
        }
    }

    jni_log!("[DEBUG:jni] nativeStopProxy returning after cleanup");
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddNode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
    domains: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| add_node(env, node_id, domains))
}

fn add_node(env: &mut Env<'_>, node_id: JString, domains: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeAddNode");
        env.exception_clear();
        return -1;
    }

    let node_id_str = match node_id.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let domains_str = match domains.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let domains_list: Vec<String> = domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if domains_list.is_empty() {
        jni_log!("Warning: Domains list is empty for node: {}", node_id_str);
    }

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    // Re-adding a node updates it instead of appending a second entry. `nodes`
    // becomes one pool per backend, so a duplicate would hand that backend two
    // pools — double the weight in the balancer, two sets of health checks —
    // and the list would grow every time the UI re-applies the same settings.
    if let Some(existing) = guard
        .nodes
        .iter_mut()
        .find(|n| n.server_node_id.as_deref() == Some(node_id_str.as_str()))
    {
        if !domains_list.is_empty() {
            existing.domains = domains_list;
        }
        return 0;
    }

    let node_config = NodeConfig {
        server_node_id: Some(node_id_str),
        server_ticket: None,
        domains: domains_list,
    };

    guard.nodes.push(node_config);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomainMapping(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    domain: JString,
    node_id: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        add_domain_mapping(env, domain, node_id)
    })
}

fn add_domain_mapping(env: &mut Env<'_>, domain: JString, node_id: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeAddDomainMapping");
        env.exception_clear();
        return -1;
    }

    let domain_str = match domain.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let node_id_str = match node_id.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    // A mapping is the pair (domain, node), so re-adding the same pair is not a
    // second route — it is the same one again. Without this the list grew on
    // every re-apply, and every duplicate made the lookup walk further for
    // nothing.
    let already_mapped = guard.domain_mappings.iter().any(|m| {
        m.domain == domain_str && m.server_node_id.as_deref() == Some(node_id_str.as_str())
    });
    if already_mapped {
        return 0;
    }

    let domain_mapping = DomainMapping {
        domain: domain_str,
        server_node_id: Some(node_id_str),
        server_ticket: None,
    };

    guard.domain_mappings.push(domain_mapping);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveNode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| remove_node(env, node_id))
}

fn remove_node(env: &mut Env<'_>, node_id: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeRemoveNode");
        env.exception_clear();
        return -1;
    }

    let node_id_str = match node_id.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    guard
        .nodes
        .retain(|n| n.server_node_id.as_deref() != Some(&node_id_str));
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeClearNodes(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    let state = match get_state() {
        Some(s) => s,
        None => return 0,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    guard.nodes.clear();
    guard.domain_mappings.clear();
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomain(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    domain: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| add_domain(env, domain))
}

fn add_domain(env: &mut Env<'_>, domain: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeAddDomain");
        env.exception_clear();
        return -1;
    }

    let domain_str = match domain.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    if !guard.domains.contains(&domain_str) {
        guard.domains.push(domain_str);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveDomain(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    domain: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| remove_domain(env, domain))
}

fn remove_domain(env: &mut Env<'_>, domain: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeRemoveDomain");
        env.exception_clear();
        return -1;
    }

    let domain_str = match domain.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    guard.domains.retain(|d| d != &domain_str);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeDestroy(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativeDestroy called (full teardown: endpoint + proxy)");
    // Phase 1: briefly lock ENDPOINT, bump the generation and take the endpoint out so the next
    // nativeStartIroh rebuilds it. nativeStartIroh's bind() doesn't hold the ENDPOINT lock, so this
    // won't deadlock against startIroh.
    let endpoint = {
        if let Ok(mut guard) = ENDPOINT.lock() {
            ENDPOINT_GEN.fetch_add(1, Ordering::AcqRel);
            let ep = guard.take();
            jni_log!(
                "[DEBUG:jni] Endpoint released (generation bumped), present={}",
                ep.is_some()
            );
            ep
        } else {
            jni_log!("[DEBUG:jni] Failed to lock ENDPOINT, continuing with proxy cleanup");
            None
        }
    };
    // Phase 2+3: stop the endpoint_group / conn_pool (without touching ENDPOINT).
    let result = Java_com_nexa_pipe_IrohProxy_nativeStopProxy(_env, _class);

    // Phase 4: explicitly close the endpoint. conn_pool.close_all() now only closes the pool's own
    // endpoint (new()); the shared global endpoint is closed here.
    if let Some(ep) = endpoint {
        if let Some(r) = get_runtime() {
            // Caught for the same reason as above: closing blocks on the
            // runtime, and an unwind out of this frame is a crash.
            let _ = catching_panic("nativeDestroy", || {
                r.block_on(async {
                    let _ = tokio::time::timeout(CLOSE_ALL_TIMEOUT, ep.close()).await;
                })
            });
            jni_log!("[DEBUG:jni] Endpoint closed");
        }
    }
    result
}

// ============================================================
// The virtual block — the addresses the tunnel claims
// ============================================================

/// The blocks the tunnel may claim, comma-separated: `198.18.0.0,198.19.0.0,…`.
///
/// The list lives in the client library so both clients walk the same one: the
/// desktop walks it to find a block the host will let it bind, and Android
/// walks it to find a block the network the phone is on will let it claim.
/// Two lists would drift, and a drift here is a tunnel whose two halves claim
/// different addresses.
///
/// Returns null when the answer could not be built, which Kotlin reads as "no
/// list" rather than as an empty one.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeVirtualBlockCandidates(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        let list = crate::virtual_block::TUN_BASE_CANDIDATES
            .iter()
            .map(|base| base.to_string())
            .collect::<Vec<_>>()
            .join(",");
        jni_log!("[DEBUG:jni] nativeVirtualBlockCandidates: {list}");
        match env.new_string(list) {
            Ok(encoded) => encoded.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Sets the block the tunnel claims and reports the addresses inside it.
///
/// `base` is the block's network address (`198.18.0.0`). The answer is a
/// `key=value;key=value` list — the shape the other answers in this file use —
/// naming the block, the interface address, the DNS server, the legacy proxy
/// address and the IPv6 half:
///
/// ```text
/// base=198.18.0.0;network=198.18.0.0/24;interface=198.18.0.1;dns=198.18.0.2;proxy=198.18.0.3;ipv6=fd00:198:18:0::;ipv6Interface=fd00:198:18:0::1
/// ```
///
/// Kotlin configures the VPN's addresses and routes from it, and the Rust side
/// hands out the per-domain addresses from the same block, so the two cannot
/// disagree about which addresses the tunnel claims — a disagreement being a
/// tunnel that comes up and carries nothing.
///
/// A `base` that is not an address is ignored rather than fatal: the block is
/// the caller's decision, and a caller that got it wrong is answered with the
/// block that is actually in use, which is the answer it needs either way.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeVirtualBlock(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    base: JString,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        virtual_block(env, base)
    })
}

#[cfg(all(feature = "tun-proxy", target_os = "android"))]
fn virtual_block(env: &mut Env<'_>, base: JString) -> jstring {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeVirtualBlock");
        env.exception_clear();
        return std::ptr::null_mut();
    }

    match base.try_to_string(env) {
        Ok(text) => match text.trim().parse::<Ipv4Addr>() {
            Ok(address) => crate::virtual_block::set(address),
            Err(e) => jni_log!("[WARN:jni] nativeVirtualBlock: '{text}' is not an address: {e}"),
        },
        Err(e) => {
            jni_log!("[WARN:jni] nativeVirtualBlock: could not read the block: {e}");
            return std::ptr::null_mut();
        }
    }

    let encoded = crate::virtual_block::encoded();
    jni_log!("[DEBUG:jni] nativeVirtualBlock: {encoded}");

    match env.new_string(encoded) {
        Ok(encoded) => encoded.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================
// TUN proxy (smoltcp user-space TCP/IP stack) — Android tun-proxy feature only
// ============================================================

/// Start the TUN proxy: process the TUN fd's TCP/UDP traffic on the Rust side with smoltcp.
///
/// Must be called after `nativeStartProxy` (endpoint_group already created) and after the VPN is
/// established. Kotlin transfers fd ownership to Rust via `ParcelFileDescriptor.detachFd()`.
///
/// Arguments:
/// - `tun_fd`: the TUN file descriptor (return value of detachFd)
/// - `proxy_domains`: comma-separated list of proxied domains
///
/// Returns 0 on success, -1 on failure.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartTunProxy(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    tun_fd: jint,
    proxy_domains: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        start_tun_proxy(env, _class, tun_fd, proxy_domains)
    })
}

/// The body of `nativeStartTunProxy`, split out so the catch has something to
/// wrap and nothing else inside it has to care.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
fn start_tun_proxy(
    env: &mut Env<'_>,
    _class: JClass,
    tun_fd: jint,
    proxy_domains: JString,
) -> jint {
    // The descriptor is ours from this line on. The JNI boundary is where the
    // ownership transfers, and it transfers exactly once: the Kotlin side has
    // detached the descriptor from its `ParcelFileDescriptor` and handed the
    // number over, so this side closes it — on the failure paths, by dropping
    // it; on the success path, by duplicating it and letting the original go.
    //
    // It has to be taken **here**, before the first `return`: every early
    // return below would otherwise leak it, and the Kotlin side must not close
    // it either, because by the time it sees a failure code this function has
    // already taken it.
    if tun_fd < 0 {
        jni_log!("[tun-proxy] nativeStartTunProxy was given an invalid descriptor");
        return -1;
    }
    let tun_fd_raw = tun_fd;
    let tun_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(tun_fd) };

    if env.exception_check() {
        jni_log!("JNI exception pending before nativeStartTunProxy");
        env.exception_clear();
        return -1;
    }

    // Parse the proxied domains (comma-separated).
    let proxy_domains_str = match proxy_domains.try_to_string(env) {
        Ok(s) => s,
        Err(_) => {
            jni_log!("Failed to get proxy_domains string from JNI");
            return -1;
        }
    };
    let proxy_domains_list: Vec<String> = proxy_domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    jni_log!(
        "[DEBUG:jni] nativeStartTunProxy: fd={}, proxy_domains={} items",
        tun_fd_raw,
        proxy_domains_list.len()
    );

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            return -1;
        }
    };

    // Clone the endpoint_group from ProxyState (created by nativeStartProxy).
    let endpoint_group = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for endpoint_group");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!("[DEBUG:jni] endpoint_group is None — nativeStartProxy not called yet?");
                return -1;
            }
        }
    };

    // Read the system DNS server list (set by nativeSetDnsServers).
    let custom_dns_servers = match CUSTOM_DNS_SERVERS.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            jni_log!("Failed to lock CUSTOM_DNS_SERVERS");
            return -1;
        }
    };

    // Check whether a tun_proxy is already running.
    {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for tun_proxy check");
                return -1;
            }
        };
        if guard.tun_proxy.is_some() {
            jni_log!("[DEBUG:jni] TUN proxy already running, stopping old one first");
            drop(guard);
            let _ = stop_tun_proxy();
        }
    }

    // Enter the runtime context (TunProxy::new spawns tasks via tokio::spawn internally).
    let _enter_guard = runtime.enter();

    let tun_proxy = match TunProxy::new(
        tun_fd,
        endpoint_group,
        proxy_domains_list,
        custom_dns_servers,
    ) {
        Ok(tp) => tp,
        Err(e) => {
            jni_log!("[DEBUG:jni] Failed to create TUN proxy: {}", e);
            return -1;
        }
    };

    // Store it in ProxyState.
    {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for tun_proxy storage");
                // tun_proxy dropped → stop() called → tasks aborted + fd closed
                return -1;
            }
        };
        guard.tun_proxy = Some(tun_proxy);
    }

    jni_log!("[DEBUG:jni] nativeStartTunProxy returning success");
    0
}

/// Stop the TUN proxy: abort all background tasks and close the dup'd fd.
///
/// Called by `NexaVpnService.stopVPN()` before closing the TUN fd.
/// `nativeDestroy` also reaches it indirectly via `nativeStopProxy` (Phase 1.5).
///
/// The body is wrapped in `catching_panic` because it is the one TUN entry
/// point with no `with_env_or` around it: `nativeStartTunProxy` gets its unwind
/// barrier from that helper, while this one takes an `EnvUnowned` and does not
/// touch the environment at all. Unwinding out of an `extern "system"` frame is
/// a native crash on Android rather than something the JVM can report, so a
/// panic while joining the runtime's tasks would take the process down on the
/// one path that runs while the user is turning the VPN off.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    match catching_panic("nativeStopTunProxy", stop_tun_proxy) {
        Some(code) => code,
        None => -1,
    }
}

/// The same gate as the entry point above, and it has to be repeated rather
/// than inherited: `cfg` does not propagate into a function body, so a free
/// function that reads `ProxyState::tun_proxy` needs its own. Without it this
/// still compiles for every `jni` build that is not an Android one — which is
/// exactly what the release archives build (`--features jni,local-proxy` on
/// eight non-Android targets), and the combination no CI job compiles.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
fn stop_tun_proxy() -> jint {
    jni_log!("[DEBUG:jni] nativeStopTunProxy called");

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] State not initialized, nothing to stop");
            return 0;
        }
    };

    let tun_proxy = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // The fd this takes out is closed only by dropping or shutting
                // down the proxy, so the guard is recovered rather than the
                // stop abandoned.
                jni_log!(
                    "[WARN:jni] State lock poisoned, recovering the guard to stop the TUN proxy"
                );
                poisoned.into_inner()
            }
        };
        guard.tun_proxy.take()
    }; // guard dropped

    if let Some(tp) = tun_proxy {
        if let Some(r) = get_runtime() {
            tp.shutdown(r);
            jni_log!("[DEBUG:jni] TUN proxy shutdown complete");
        } else {
            jni_log!("[DEBUG:jni] No runtime, aborting TUN proxy without join");
            // tp dropped here → stop() called via Drop
        }
    } else {
        jni_log!("[DEBUG:jni] No TUN proxy to stop");
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An override is stored and looked up under the same name, whatever
    /// spelling either side uses: a name and the same name with a trailing
    /// dot are the same name, and so is the same name in another case.
    ///
    /// The trailing dot is not a corner case: every relay hostname iroh dials
    /// is fully qualified, and it is iroh that asks the resolver for it.
    #[test]
    fn an_override_is_found_however_the_name_is_spelled() {
        assert_eq!(
            crate::domains::fold_domain("APS1-1.relay.n0.iroh.link."),
            crate::domains::fold_domain("aps1-1.relay.n0.iroh.link")
        );
        assert_eq!(
            crate::domains::fold_domain("aps1-1.relay.n0.iroh.link."),
            "aps1-1.relay.n0.iroh.link"
        );
        assert_eq!(
            crate::domains::fold_domain(" dns.iroh.link. "),
            "dns.iroh.link"
        );
    }

    /// The lookup finds an override that was stored under the name without the
    /// dot, when the query carries it: iroh asks for the fully-qualified
    /// spelling, and an override that is not found is an override that does
    /// not exist.
    #[test]
    fn an_override_stored_without_the_dot_is_found_with_it() {
        let mut overrides: HashMap<String, Vec<IpAddr>> = HashMap::new();
        overrides.insert(
            crate::domains::fold_domain("aps1-1.relay.n0.iroh.link"),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        );
        let resolver = OverrideResolver::new(Vec::new(), overrides);

        let qualified = resolver.override_for("aps1-1.relay.n0.iroh.link.");
        let plain = resolver.override_for("aps1-1.relay.n0.iroh.link");
        let other = resolver.override_for("other.example.com");

        assert!(
            qualified.is_some(),
            "the fully-qualified spelling finds the override"
        );
        assert!(plain.is_some(), "the plain spelling finds it too");
        assert!(
            other.is_none(),
            "a name that was never overridden is not overridden"
        );
    }

    /// A key is the credential for a node that has one: the node stores no
    /// secret at all, so the TOTP path would find nothing to build from and
    /// the node would answer with nothing.
    #[test]
    fn a_node_with_a_key_authenticates_with_the_key() {
        let key = DeviceKey::generate();
        let public = key.public_hex();
        let cfg: NodeCredential = (
            "client-001".to_string(),
            SecretString::default(),
            String::new(),
            Some("phone-1a2b3c4d".to_string()),
        );

        let auth = two_factor_auth(&cfg, Some(key.secret_key())).expect("a key is a credential");
        assert_eq!(auth.client_id(), "client-001");
        assert_eq!(auth.device_id(), Some("phone-1a2b3c4d"));
        assert_eq!(
            auth.public_key_hex(),
            Some(public),
            "the credential proves itself with the key that was registered"
        );
    }

    /// A key with no device name is one that has not enrolled yet: the name
    /// is what the server answers with, so before that there is nothing to
    /// present — and the enrollment is what is about to happen.
    #[test]
    fn a_key_without_a_device_name_is_not_a_credential_yet() {
        let key = DeviceKey::generate();
        let cfg: NodeCredential = (
            "client-001".to_string(),
            SecretString::default(),
            String::new(),
            None,
        );

        assert!(
            two_factor_auth(&cfg, Some(key.secret_key())).is_none(),
            "a key that names no device cannot answer a handshake"
        );
    }

    /// The secret path is unchanged: a node with a secret still authenticates
    /// with it, and still answers as the device it was issued to.
    #[test]
    fn a_node_with_a_secret_still_authenticates_with_the_secret() {
        let cfg: NodeCredential = (
            "client-001".to_string(),
            SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            "sha1".to_string(),
            Some("laptop".to_string()),
        );

        let auth = two_factor_auth(&cfg, None).expect("a secret is a credential");
        assert_eq!(auth.client_id(), "client-001");
        assert_eq!(auth.device_id(), Some("laptop"));
        assert_eq!(
            auth.public_key_hex(),
            None,
            "a secret has no key, and that is how the two kinds are told apart"
        );
    }

    /// An empty secret is not a credential: it is how a node that was never
    /// given one is represented, and read as "has credentials" it would
    /// authenticate with nothing.
    #[test]
    fn an_empty_secret_is_no_credential() {
        let cfg: NodeCredential = (
            "client-001".to_string(),
            SecretString::new("  ".to_string()),
            "sha1".to_string(),
            None,
        );
        assert!(two_factor_auth(&cfg, None).is_none());
    }

    /// A secret wins over a key left beside it. The server holds one kind of
    /// credential per device, so a record that carries a secret is one it
    /// issued as a secret: the key was offered, ignored, and never pruned from
    /// the table this side keeps. Signing with it would be refused while the
    /// secret was still valid.
    #[test]
    fn a_stored_secret_wins_over_a_leftover_key() {
        let key = DeviceKey::generate();
        let cfg: NodeCredential = (
            "client-001".to_string(),
            SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            "sha1".to_string(),
            Some("phone-1a2b3c4d".to_string()),
        );

        let auth = two_factor_auth(&cfg, Some(key.secret_key())).expect("a secret is a credential");
        assert_eq!(auth.client_id(), "client-001");
        assert_eq!(auth.device_id(), Some("phone-1a2b3c4d"));
        assert_eq!(
            auth.public_key_hex(),
            None,
            "the handshake answers the secret rather than signing with a key the server never recorded"
        );
    }

    /// The key's "no device name yet" answer must not swallow a secret: the
    /// precedence is decided by the secret alone, and the name only matters to
    /// the key that is not the credential here.
    #[test]
    fn a_secret_answers_even_when_the_key_beside_it_names_no_device() {
        let key = DeviceKey::generate();
        let cfg: NodeCredential = (
            "client-001".to_string(),
            SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            "sha1".to_string(),
            None,
        );

        let auth = two_factor_auth(&cfg, Some(key.secret_key())).expect("a secret is a credential");
        assert_eq!(
            auth.device_id(),
            None,
            "a secret with no device stays unnamed"
        );
        assert_eq!(auth.public_key_hex(), None);
    }

    /// A blank secret is not a secret, so the key is the credential again: the
    /// precedence is "is there a secret", not "does the record have one".
    #[test]
    fn a_key_answers_when_the_secret_beside_it_is_blank() {
        let key = DeviceKey::generate();
        let public = key.public_hex();
        let cfg: NodeCredential = (
            "client-001".to_string(),
            SecretString::new("   ".to_string()),
            String::new(),
            Some("phone-1a2b3c4d".to_string()),
        );

        let auth = two_factor_auth(&cfg, Some(key.secret_key())).expect("a key is a credential");
        assert_eq!(auth.device_id(), Some("phone-1a2b3c4d"));
        assert_eq!(auth.public_key_hex(), Some(public));
    }
}
