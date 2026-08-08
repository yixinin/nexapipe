#[cfg(all(feature = "tun-proxy", target_os = "android"))]
use crate::tun_proxy::TunProxy;
use crate::{
    DomainMapping, EndpointGroup, IrohConnectionPool, LoadBalancingStrategy, LocalProxy, NodeConfig,
};
use iroh::dns::{DnsError, DnsProtocol, DnsResolver, Resolver, TxtRecordData};
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMode, RelayUrl};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use ndk_context;
use once_cell::sync::{Lazy, OnceCell};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static ENDPOINT: Mutex<Option<Endpoint>> = Mutex::new(None);
static STATE: OnceCell<Arc<Mutex<ProxyState>>> = OnceCell::new();

// 代际计数器：每次 nativeStopProxy 释放 endpoint 时自增。nativeStartIroh 在 bind()
// 前后比对该值，若期间发生过 stop 则丢弃迟到的新 endpoint，避免孤立 bind 复活已释放的隧道。
static ENDPOINT_GEN: AtomicU64 = AtomicU64::new(0);

// Kotlin 侧传下来的系统 DNS 服务器列表。iroh 内部通过 JNI 读系统 DNS 会失败
// (Null pointer in call_method obj argument)，回落 Google DNS 在国内不稳定。
// 这里由 Kotlin 从 ConnectivityManager.getLinkProperties().dnsServers 拿到后注入，
// nativeStartIroh 用它构造 DnsResolver，绕开 iroh 的 JNI 失败路径。
static CUSTOM_DNS_SERVERS: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

// iroh 基础设施域名（dns.iroh.link, *.relay.n0.iroh.link）的预解析 IP 覆盖。
// GFW 会丢弃 iroh.link 域名的 UDP DNS 响应，导致 hickory 解析超时。
// Kotlin 侧用系统 DNS（可能走 DoT/Private DNS，绕过 GFW）预解析这些域名，
// 传给 Rust 存入此 map。OverrideResolver 对这些域名直接返回预解析 IP，
// 其他域名仍走 hickory + 系统 DNS 服务器。
static DNS_OVERRIDES: Lazy<Mutex<HashMap<String, Vec<IpAddr>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// OverrideResolver 内部委托 DnsResolver 时的单次查询超时。
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

// BoxFuture 兼容类型，与 iroh::dns::Resolver trait 的返回类型（n0_future::boxed::BoxFuture，
// 即 futures_lite::future::Boxed = Pin<Box<dyn Future<Output = T> + Send + 'static>>）一致。
// 必须 'static：impl Resolver 的方法返回的 Future 不能借用 self，方法体内需 clone 所需数据。
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
type BoxIter<T> = Box<dyn Iterator<Item = T> + Send + 'static>;

// 各阶段超时。弱网下 STUN/relay/DNS 发现可能很慢，这些超时保证卡死时能返回失败而非永久阻塞。
const IROH_BIND_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
const START_PROXY_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(15);
const CLOSE_ALL_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(8);
const PROXY_RUN_JOIN_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_millis(500);
/// Pre-connect / warm-up timeout for establishing iroh connections to all backends.
const PRECONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(15);

/// 固定使用的 relay 服务器（亚太南 aps1-1，新加坡）——国内最近的 N0 relay。
///
/// iroh 默认从 4 个 N0 relay 中按延迟选 home relay，国内环境下 aps1-1(亚太) 和
/// euc1-1(欧洲) 延迟接近，iroh 会在两者间反复切换。每次切换 home relay 会导致
/// 正在通过 relay 路由的连接（WebSocket 等）断线重连。
///
/// 固定到 aps1-1 后 iroh 不会再切换，WS 连接稳定。
/// 副作用：若 aps1-1 宕机则 relay 路径不可用（直连不受影响）。
/// DNS 仍由 Kotlin 侧 resolveIrohDnsOverrides 预解析 aps1-1 的 IP 注入 OverrideResolver。
const PINNED_RELAY_URL: &str = "https://aps1-1.relay.n0.iroh.link.";

struct ProxyState {
    conn_pool: Option<IrohConnectionPool>,
    endpoint_group: Option<Arc<EndpointGroup>>,
    local_proxy: Option<LocalProxy>,
    // 后台 proxy.run() 任务句柄，停止时 abort + await 以确定式释放监听端口。
    proxy_task: Option<JoinHandle<()>>,
    nodes: Vec<NodeConfig>,
    domain_mappings: Vec<DomainMapping>,
    domains: Vec<String>,
    // TUN 代理（smoltcp 用户态 TCP/IP 栈）。仅 Android tun-proxy feature 启用时存在。
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
            local_proxy: None,
            proxy_task: None,
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
#[macro_export]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        $crate::jni::android_log(log::Level::Debug, &format!($($arg)*))
    };
}

/// 自定义 DNS Resolver，包装 hickory 解析器并对指定域名返回预解析的 IP。
///
/// GFW 会丢弃 `iroh.link` 域名的 UDP DNS 响应，导致 hickory 解析超时。
/// 此 resolver 对 `DNS_OVERRIDES` 中的域名直接返回 Kotlin 预解析的 IP
/// （Kotlin 用系统 DNS，可能走 DoT/Private DNS 绕过 GFW），其他域名仍走 hickory。
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
            DnsResolver::builder()
                .with_nameservers(nameservers.iter().map(|a| (*a, DnsProtocol::Udp)))
                .build()
        };
        Self {
            inner,
            overrides,
            nameservers,
        }
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
        if let Some(ips) = self.overrides.get(&host) {
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
        if let Some(ips) = self.overrides.get(&host) {
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
    env: JNIEnv,
    _class: JClass,
) -> jint {
    #[cfg(target_os = "android")]
    {
        unsafe {
            let raw_env = env.get_raw();
            let mut raw_vm = std::ptr::null_mut();
            (**raw_env).GetJavaVM.unwrap()(raw_env, &mut raw_vm);
            ndk_context::initialize_android_context(raw_vm as *mut _, std::ptr::null_mut());
        }
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("NexaVpnService"),
        );
    }

    std::panic::set_hook(Box::new(|panic_info| {
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
    }));

    let rt = Builder::new_multi_thread()
        .thread_name("nexapipe-worker")
        .worker_threads(4)
        .enable_all()
        .build();

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

/// Kotlin 侧通过 ConnectivityManager.getLinkProperties().dnsServers 拿到系统 DNS 后，
/// 以逗号分隔的 IP 字符串传入（如 "192.168.1.1,8.8.8.8"）。本函数解析为 SocketAddr
/// （端口固定 53，UDP），存入 CUSTOM_DNS_SERVERS。nativeStartIroh 会在 bind 前读取。
/// 必须在 nativeStartIroh 之前调用。
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDnsServers(
    mut env: JNIEnv,
    _class: JClass,
    dns_servers: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeSetDnsServers");
        env.exception_clear().unwrap();
        return -1;
    }

    let dns_str = match env.get_string(&dns_servers) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert DNS servers string to UTF-8");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get DNS servers string from JNI");
            return -1;
        }
    };

    // 解析逗号分隔的 IP 地址列表。Kotlin 传的是纯 IP（无端口），统一加 53 端口。
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

/// Kotlin 侧用系统 DNS（可能走 DoT/Private DNS，绕过 GFW）预解析 iroh 基础设施域名
/// （dns.iroh.link, *.relay.n0.iroh.link），以 "domain=ip1,ip2;domain2=ip3,ip4" 格式传入。
/// 本函数解析后存入 DNS_OVERRIDES。OverrideResolver 对这些域名直接返回预解析 IP，
/// 绕过 hickory 的 UDP DNS 查询（GFW 会丢弃 iroh.link 域名的 UDP DNS 响应）。
/// 这样 pkarr resolve（HTTPS to dns.iroh.link/pkarr/<z32>）能连上 iroh 的 pkarr 服务器，
/// 拿到目标节点的 EndpointInfo（relay URL + direct addr），即使 DNS TXT 被 GFW 阻断也无妨。
/// 必须在 nativeStartIroh 之前调用。
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDnsOverride(
    mut env: JNIEnv,
    _class: JClass,
    overrides: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeSetDnsOverride");
        env.exception_clear().unwrap();
        return -1;
    }

    let overrides_str = match env.get_string(&overrides) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert DNS overrides string to UTF-8");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get DNS overrides string from JNI");
            return -1;
        }
    };

    // 解析 "domain=ip1,ip2;domain2=ip3,ip4" 格式。
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for entry in overrides_str.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(2, '=');
        let domain = match parts.next() {
            Some(d) => d.trim().to_lowercase(),
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartIroh(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartIroh");
        env.exception_clear().unwrap();
        return std::ptr::null_mut();
    }

    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    // 快速路径：已有 endpoint 则立即返回。仅短暂持锁，不跨任何 await。
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

    // bind() 期间不持 ENDPOINT 锁，避免 nativeStopProxy 死锁。
    let gen_before = ENDPOINT_GEN.load(Ordering::Acquire);

    // 读取 Kotlin 注入的系统 DNS 服务器 + iroh 基础设施域名预解析 IP。
    // 短暂持锁 clone 后立即释放，不跨 await。
    let custom_dns: Vec<SocketAddr> = CUSTOM_DNS_SERVERS
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let dns_overrides: HashMap<String, Vec<IpAddr>> =
        DNS_OVERRIDES.lock().map(|g| g.clone()).unwrap_or_default();

    let bind_result: Result<Endpoint, ()> = runtime.block_on(async move {
        // 固定 relay 到 aps1-1（亚太南），防止 iroh 在多个 relay 间切换导致 WS 断线。
        // 见 PINNED_RELAY_URL 注释。
        let relay_url: RelayUrl = PINNED_RELAY_URL
            .parse()
            .expect("PINNED_RELAY_URL must be a valid relay URL");
        jni_log!("[iroh] pinning relay to {}", PINNED_RELAY_URL);
        let builder = Endpoint::builder(presets::N0).relay_mode(RelayMode::custom([relay_url]));
        // 始终用 OverrideResolver 包装 hickory：
        // - 对 DNS_OVERRIDES 中的 iroh 基础设施域名（dns.iroh.link, *.relay.n0.iroh.link）
        //   直接返回 Kotlin 预解析的 IP，绕过 GFW 对 iroh.link UDP DNS 响应的阻断。
        //   这样 pkarr resolve（HTTPS to dns.iroh.link/pkarr/<z32>）能连上 pkarr 服务器，
        //   拿到目标节点 EndpointInfo；relay 域名也能连上 relay 服务器。
        // - 其他域名走 hickory + 系统 DNS 服务器（custom_dns）。
        //   即使 custom_dns 为空，OverrideResolver 内部回落 DnsResolver::new()。
        jni_log!(
            "[DEBUG:jni] Building OverrideResolver: {} DNS servers, {} override domains {:?}",
            custom_dns.len(),
            dns_overrides.len(),
            dns_overrides.keys().collect::<Vec<_>>()
        );
        let override_resolver = OverrideResolver::new(custom_dns.clone(), dns_overrides);
        let dns_resolver = DnsResolver::custom(override_resolver);
        let builder = builder.dns_resolver(dns_resolver);

        match tokio::time::timeout(IROH_BIND_TIMEOUT, builder.bind()).await {
            Ok(Ok(ep)) => Ok(ep),
            Ok(Err(e)) => {
                jni_log!("Failed to start iroh endpoint: {}", e);
                Err(())
            }
            Err(_) => {
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

    // 重新加锁提交：若期间发生过 stop（代际变化）则丢弃迟到的 endpoint；
    // 若已有并发 startIroh 写入则返回其 id；否则写入自己的。
    let node_id = match ENDPOINT.lock() {
        Ok(mut guard) => {
            let gen_now = ENDPOINT_GEN.load(Ordering::Acquire);
            if gen_now != gen_before {
                jni_log!("endpoint generation changed during bind, discarding late endpoint");
                drop(ep); // 孤立 bind 的迟到结果：丢弃，不复活已释放的隧道
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
    env: JNIEnv,
    _class: JClass,
    listen_port: jint,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartProxy");
        env.exception_clear().unwrap();
        return -1;
    }

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

    let listen_addr = format!("127.0.0.1:{}", listen_port);
    jni_log!(
        "[DEBUG:jni] nativeStartProxy called for port {}",
        listen_port
    );

    // 失败快速返回：无 endpoint 时拒绝继续。否则会落入「每节点独立 bind()」分支
    // （connection_pool.rs，无超时、按后端数翻倍），重新引入卡死。
    let ep = match get_endpoint() {
        Some(ep) => ep,
        None => {
            jni_log!("[DEBUG:jni] No iroh endpoint available; call nativeStartIroh first");
            return -1;
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move {
            let endpoint_group: EndpointGroup;
            let proxy_domains: Vec<String>;

            if !domain_mappings.is_empty() {
                jni_log!(
                    "[DEBUG:jni] Using domain_mappings ({} entries)",
                    domain_mappings.len()
                );
                proxy_domains = domain_mappings.iter().map(|m| m.domain.clone()).collect();

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
                proxy_domains = nodes
                    .iter()
                    .flat_map(|node| node.domains.iter().cloned())
                    .collect();

                if proxy_domains.is_empty() {
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

            jni_log!("[DEBUG:jni] Creating LocalProxy on {}", listen_addr);
            let endpoint_group_arc = Arc::new(endpoint_group);
            let proxy = match tokio::time::timeout(
                START_PROXY_TIMEOUT,
                LocalProxy::new(&listen_addr, proxy_domains, endpoint_group_arc.clone()),
            )
            .await
            {
                Ok(Ok(p)) => {
                    jni_log!("[DEBUG:jni] LocalProxy created successfully");
                    p
                }
                Ok(Err(e)) => {
                    jni_log!("[DEBUG:jni] Failed to create local proxy: {}", e);
                    return Err(format!("Failed to create local proxy: {}", e));
                }
                Err(_) => {
                    jni_log!(
                        "[DEBUG:jni] LocalProxy creation timed out after {}s",
                        START_PROXY_TIMEOUT.as_secs()
                    );
                    return Err("LocalProxy creation timed out".to_string());
                }
            };

            // clone 一份给后台任务，原始 proxy 留给 state。
            let proxy_for_run = proxy.clone();
            let join_handle = runtime.spawn(async move {
                let proxy_run = match panic::catch_unwind(panic::AssertUnwindSafe(|| async move {
                    proxy_for_run.run().await
                })) {
                    Ok(future) => future,
                    Err(_) => {
                        jni_log!("Proxy run panicked during setup");
                        return;
                    }
                };
                match proxy_run.await {
                    Err(e) => jni_log!("Proxy run failed: {}", e),
                    Ok(_) => jni_log!("Proxy run completed"),
                }
            });

            // 写回 state：重新加锁并校验未被并发 stop 清空，存入 JoinHandle 供确定式回收。
            {
                let mut guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        jni_log!("Failed to lock state mutex (poisoned)");
                        return Err("Failed to update state".to_string());
                    }
                };
                if guard.local_proxy.is_some() || guard.proxy_task.is_some() {
                    jni_log!(
                        "[DEBUG:jni] State already has a proxy (concurrent start/stop), aborting"
                    );
                    // 中止刚启动的任务，避免泄漏
                    join_handle.abort();
                    return Err("Proxy already running".to_string());
                }
                guard.local_proxy = Some(proxy);
                guard.endpoint_group = Some(endpoint_group_arc);
                guard.proxy_task = Some(join_handle);
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
            -1
        }
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during proxy start");
            -1
        }
    }
}

/// Pre-connect / warm-up: establish one iroh connection per configured backend
/// and cache it in the connection pool, so the first real request does not pay
/// the QUIC/relay handshake latency. Must be called after `nativeStartProxy`
/// (which creates the `EndpointGroup`). Returns the number of backends warmed,
/// or -1 on error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativePreconnect(
    _env: JNIEnv,
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
            match tokio::time::timeout(PRECONNECT_TIMEOUT, endpoint_group.preconnect_all()).await {
                Ok(count) => count as jint,
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartProxyLegacy(
    mut env: JNIEnv,
    _class: JClass,
    listen_port: jint,
    target_endpoint_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartProxyLegacy");
        env.exception_clear().unwrap();
        return -1;
    }

    let target_id = match env.get_string(&target_endpoint_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert target endpoint ID to string");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get target endpoint ID from JNI");
            return -1;
        }
    };

    if target_id.is_empty() {
        jni_log!("Target endpoint ID is empty");
        return -1;
    }

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

    let domains: Vec<String> = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state mutex (poisoned)");
                return -1;
            }
        };
        guard.domains.clone()
    };

    let listen_addr = format!("127.0.0.1:{}", listen_port);

    let result = runtime.block_on(async move {
        match crate::connection_pool::parse_endpoint_addr(Some(&target_id), None) {
            Ok(addr) => {
                let pool: IrohConnectionPool;
                if let Some(ep) = get_endpoint() {
                    pool = IrohConnectionPool::new_with_endpoint(ep.clone(), addr);
                } else {
                    match IrohConnectionPool::new(addr).await {
                        Ok(p) => pool = p,
                        Err(e) => {
                            jni_log!("Failed to create connection pool: {}", e);
                            return Err(format!("Failed to create connection pool: {}", e));
                        }
                    }
                }

                match LocalProxy::new_with_single_pool(&listen_addr, domains, pool.clone()).await {
                    Ok(proxy) => {
                        {
                            let mut guard = match state.lock() {
                                Ok(g) => g,
                                Err(_) => {
                                    jni_log!("Failed to lock state mutex (poisoned)");
                                    return Err("Failed to update state".to_string());
                                }
                            };
                            guard.conn_pool = Some(pool);
                        }

                        tokio::spawn(async move {
                            let proxy_run =
                                match panic::catch_unwind(panic::AssertUnwindSafe(|| async move {
                                    proxy.run().await
                                })) {
                                    Ok(future) => future,
                                    Err(_) => {
                                        jni_log!("Proxy run panicked during setup");
                                        return;
                                    }
                                };
                            match proxy_run.await {
                                Err(e) => jni_log!("Proxy run failed: {}", e),
                                Ok(_) => jni_log!("Proxy run completed"),
                            }
                        });

                        Ok(())
                    }
                    Err(e) => {
                        jni_log!("Failed to create local proxy: {}", e);
                        Err(format!("Failed to create local proxy: {}", e))
                    }
                }
            }
            Err(e) => {
                jni_log!("Failed to parse endpoint address: {}", e);
                Err(format!("Failed to parse endpoint address: {}", e))
            }
        }
    });

    match result {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopProxy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativeStopProxy called (proxy-only, keeping iroh endpoint)");

    // 注意：本函数只停止 local_proxy / endpoint_group / conn_pool / proxy_task，
    // 不触碰全局 ENDPOINT。这样 startProxyWithRetries 在重绑端口前调用它时，
    // 不会破坏 ensureIrohStarted 已建立的 endpoint。全量释放（含 endpoint）请用 nativeDestroy。
    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] State not initialized, nothing to stop");
            return 0;
        }
    };

    // Phase 1.5：先停 TUN 代理（必须在 endpoint_group.close_all() 之前）。
    // TUN 代理的 TCP 连接任务持有 Arc<EndpointGroup> 的克隆，若先 close_all 会导致
    // 任务访问已关闭的连接池。shutdown() abort + 等待任务结束，确保 fd 被关闭。
    #[cfg(all(feature = "tun-proxy", target_os = "android"))]
    {
        let tun_proxy = {
            let mut guard = match state.lock() {
                Ok(g) => g,
                Err(_) => {
                    jni_log!("[DEBUG:jni] Failed to lock state for tun_proxy cleanup");
                    return 0;
                }
            };
            guard.tun_proxy.take()
        }; // guard dropped
        if let Some(tp) = tun_proxy {
            if let Some(r) = get_runtime() {
                tp.shutdown(r);
                jni_log!("[DEBUG:jni] TUN proxy shutdown complete");
            } else {
                // 无 runtime — 仅 abort，Drop 会调 stop()
                jni_log!("[DEBUG:jni] No runtime, aborting TUN proxy without join");
            }
            // tp dropped here (if not consumed by shutdown)
        }
    }

    // Phase 2：锁 state，把资源 take 出来（字段置 None），立即 drop guard，再进入任何 block_on。
    let (local_proxy, endpoint_group, conn_pool, proxy_task) = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] Failed to lock state, aborting stop");
                return 0;
            }
        };
        jni_log!(
            "[DEBUG:jni] Stop: endpoint_group exists = {}, conn_pool exists = {}, local_proxy exists = {}, proxy_task exists = {}",
            guard.endpoint_group.is_some(),
            guard.conn_pool.is_some(),
            guard.local_proxy.is_some(),
            guard.proxy_task.is_some()
        );
        (
            guard.local_proxy.take(),
            guard.endpoint_group.take(),
            guard.conn_pool.take(),
            guard.proxy_task.take(),
        )
    }; // guard dropped here —— 不再持有 state 锁

    let runtime = get_runtime();

    // Phase 3a：通知 proxy.run() 退出（AtomicBool）。
    if let Some(proxy) = local_proxy.as_ref() {
        proxy.stop();
        jni_log!("[DEBUG:jni] LocalProxy stopped");
    }

    // Phase 3b：abort + await 后台任务，确定式释放监听端口（不再依赖 100ms 轮询）。
    if let Some(handle) = proxy_task {
        handle.abort();
        if let Some(r) = runtime {
            let _ = r.block_on(async {
                let _ = tokio::time::timeout(PROXY_RUN_JOIN_TIMEOUT, handle).await;
            });
        }
        jni_log!("[DEBUG:jni] Proxy task joined/aborted");
    }

    // Phase 3c：关闭 endpoint group / pool，各自带超时，且不持 state 锁。
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
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
    domains: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddNode");
        env.exception_clear().unwrap();
        return -1;
    }

    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let domains_str = match env.get_string(&domains) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
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
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
    node_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddDomainMapping");
        env.exception_clear().unwrap();
        return -1;
    }

    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
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
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeRemoveNode");
        env.exception_clear().unwrap();
        return -1;
    }

    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
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
    _env: JNIEnv,
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
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddDomain");
        env.exception_clear().unwrap();
        return -1;
    }

    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
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
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeRemoveDomain");
        env.exception_clear().unwrap();
        return -1;
    }

    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
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
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativeDestroy called (full teardown: endpoint + proxy)");
    // Phase 1：短暂锁 ENDPOINT，代际自增并取出 endpoint，使下次 nativeStartIroh 重建。
    // nativeStartIroh 的 bind() 不持 ENDPOINT 锁，故此处不会因 startIroh 卡死而死锁。
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
    // Phase 2+3：停止本地代理 / endpoint_group / conn_pool / proxy_task（不触碰 ENDPOINT）。
    let result = Java_com_nexa_pipe_IrohProxy_nativeStopProxy(_env, _class);

    // Phase 4：显式关闭 endpoint。conn_pool.close_all() 现在只关闭池自建的
    // endpoint（new()），共享的全局 endpoint 由这里负责关闭。
    if let Some(ep) = endpoint {
        if let Some(r) = get_runtime() {
            let _ = r.block_on(async {
                let _ = tokio::time::timeout(CLOSE_ALL_TIMEOUT, ep.close()).await;
            });
            jni_log!("[DEBUG:jni] Endpoint closed");
        }
    }
    result
}

// ============================================================
// TUN 代理（smoltcp 用户态 TCP/IP 栈）— 仅 Android tun-proxy feature
// ============================================================

/// 启动 TUN 代理：用 smoltcp 在 Rust 侧处理 TUN fd 的 TCP/UDP 流量。
///
/// 必须在 `nativeStartProxy` 之后（endpoint_group 已创建）、VPN 建立之后调用。
/// Kotlin 侧通过 `ParcelFileDescriptor.detachFd()` 将 fd 所有权转移给 Rust。
///
/// 参数：
/// - `tun_fd`: TUN 文件描述符（detachFd 返回值）
/// - `proxy_domains`: 逗号分隔的代理域名列表
/// - `captive_portal_domains`: 逗号分隔的 captive portal 校验域名列表
///
/// 返回 0 成功，-1 失败。
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartTunProxy(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    proxy_domains: JString,
    captive_portal_domains: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartTunProxy");
        env.exception_clear().unwrap();
        return -1;
    }

    // 解析代理域名（逗号分隔）
    let proxy_domains_str = match env.get_string(&proxy_domains) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert proxy_domains to UTF-8");
                return -1;
            }
        },
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

    // 解析 captive portal 域名（逗号分隔）
    let portal_domains_str = match env.get_string(&captive_portal_domains) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert captive_portal_domains to UTF-8");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get captive_portal_domains string from JNI");
            return -1;
        }
    };
    let portal_domains_list: Vec<String> = portal_domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    jni_log!(
        "[DEBUG:jni] nativeStartTunProxy: fd={}, proxy_domains={} items, portal_domains={} items",
        tun_fd,
        proxy_domains_list.len(),
        portal_domains_list.len()
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

    // 从 ProxyState 克隆 endpoint_group（nativeStartProxy 已创建）
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

    // 读取系统 DNS 服务器列表（nativeSetDnsServers 已设置）
    let custom_dns_servers = match CUSTOM_DNS_SERVERS.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            jni_log!("Failed to lock CUSTOM_DNS_SERVERS");
            return -1;
        }
    };

    // 检查是否已有 tun_proxy 在运行
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
            let _ = Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy(env, _class);
        }
    }

    // 进入 runtime 上下文（TunProxy::new 内部用 tokio::spawn 启动任务）
    let _enter_guard = runtime.enter();

    let tun_proxy = match TunProxy::new(
        tun_fd as std::os::fd::RawFd,
        endpoint_group,
        proxy_domains_list,
        portal_domains_list,
        custom_dns_servers,
    ) {
        Ok(tp) => tp,
        Err(e) => {
            jni_log!("[DEBUG:jni] Failed to create TUN proxy: {}", e);
            return -1;
        }
    };

    // 存入 ProxyState
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

/// 停止 TUN 代理：abort 所有后台任务，关闭 dup 的 fd。
///
/// 由 `NexaVpnService.stopVPN()` 在关闭 TUN fd 之前调用。
/// `nativeDestroy` 也会通过 `nativeStopProxy` 间接调用（Phase 1.5）。
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
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
            Err(_) => {
                jni_log!("[DEBUG:jni] Failed to lock state for tun_proxy stop");
                return 0;
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
