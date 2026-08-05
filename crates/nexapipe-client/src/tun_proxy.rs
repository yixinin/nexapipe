//! TUN 代理：用 netstack-smoltcp 在 Rust 侧实现用户态 TCP/IP 栈，替代 Kotlin 手写 TCP 栈。
//!
//! 数据流：
//! ```text
//! APP → TUN fd → Rust(AsyncFd) → Stack(Sink: IP 包入)
//!                                  ↓ smoltcp 处理
//!                           ┌──────┴──────┐
//!                      TcpListener    UdpSocket
//!                      (TCP 连接)      (DNS 查询)
//!                           │              │
//!                ┌──────────┤              ├──────────────┐
//!                ↓          ↓              ↓              ↓
//!           10.0.1.3:80,443  10.0.1.4:80   解析域名       非代理域名
//!           (代理流量)       (captive portal)  │              │
//!                │          │              ↓              ↓
//!       handle_local_     返回 204       代理→10.0.1.3   转发真实 DNS
//!       connection        (硬编码响应)    portal→10.0.1.4  (tokio UdpSocket)
//!       (→iroh→后端)
//!                           │
//!                Stack(Stream: IP 包出) → AsyncFd → 写回 TUN fd
//! ```

use crate::ClientError;
use crate::EndpointGroup;
use crate::local_proxy::{handle_local_connection, should_proxy_domain};

#[cfg(feature = "jni")]
use crate::jni_log;

#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {};
}

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener as SmolTcpListener};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, unix::AsyncFd};
use tokio::task::JoinHandle;

// 虚拟 IP 常量 — 必须与 Kotlin 侧 NexaVpnService 的 TUN 配置一致。
// 10.0.1.2 = DNS 服务器（smoltcp UdpSocket 接收 DNS 查询）
// 10.0.1.3 = 代理 IP（TCP 连接走 handle_local_connection → iroh）
// 10.0.1.4 = captive portal IP（TCP 连接返回硬编码 204 响应）
/// DNS 服务器虚拟 IP — 仅用于文档化，与 Kotlin 侧 NexaVpnService.virtualDNSIP 一致。
/// DNS 查询的 dst_addr 即为此 IP，响应时原样用作 src_addr。
#[allow(dead_code)]
const VIRTUAL_DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
const VIRTUAL_PROXY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 3);
const VIRTUAL_CAPTIVE_PORTAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 4);

const TUN_MTU: usize = 1500;
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// TUN 代理：管理 smoltcp 栈和所有后台 pump/acceptor 任务。
///
/// 生命周期：由 `nativeStartTunProxy` 创建，存入 `ProxyState.tun_proxy`。
/// `nativeStopTunProxy` / `nativeDestroy` 调用 `stop()` 终止所有任务。
/// `Drop` 也会调用 `stop()` 作为安全网。
pub struct TunProxy {
    stopped: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

impl TunProxy {
    /// 创建并启动 TUN 代理。
    ///
    /// - `tun_fd`: Kotlin 侧 `ParcelFileDescriptor.detachFd()` 返回的原始 fd。
    ///   本函数会 `dup` 两份（读/写），并关闭原始 fd。
    /// - `endpoint_group`: 从 `ProxyState` 克隆的 `Arc<EndpointGroup>`，用于 iroh 连接。
    /// - `proxy_domains`: 需要代理的域名列表（逗号分隔已解析）。
    /// - `captive_portal_domains`: captive portal 校验域名列表。
    /// - `custom_dns_servers`: 系统 DNS 服务器列表（从 `CUSTOM_DNS_SERVERS` 读取）。
    ///
    /// 内部用 `runtime.spawn()` 启动所有任务，**不 block_on**。
    pub fn new(
        tun_fd: RawFd,
        endpoint_group: Arc<EndpointGroup>,
        proxy_domains: Vec<String>,
        captive_portal_domains: Vec<String>,
        custom_dns_servers: Vec<SocketAddr>,
    ) -> Result<Self, ClientError> {
        // 1. dup fd 两份（读/写），关闭原始 fd
        let fd_read = unsafe { libc::dup(tun_fd) };
        if fd_read < 0 {
            let e = std::io::Error::last_os_error();
            jni_log!("[tun-proxy] dup(read) failed: {}", e);
            return Err(e.into());
        }
        let fd_write = unsafe { libc::dup(tun_fd) };
        if fd_write < 0 {
            let e = std::io::Error::last_os_error();
            jni_log!("[tun-proxy] dup(write) failed: {}", e);
            unsafe { libc::close(fd_read) };
            return Err(e.into());
        }
        // 关闭原始 fd — 我们现在持有两个 dup
        unsafe { libc::close(tun_fd) };

        set_nonblocking(fd_read)?;
        set_nonblocking(fd_write)?;

        jni_log!(
            "[tun-proxy] fd_read={}, fd_write={} (non-blocking)",
            fd_read,
            fd_write
        );

        // 2. 构建 smoltcp 栈
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .mtu(TUN_MTU)
            .build()?;

        let stopped = Arc::new(AtomicBool::new(false));
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        // 3. spawn Runner（驱动 smoltcp 内部处理：重传、超时等）
        if let Some(runner) = runner {
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                match runner.await {
                    Ok(()) => jni_log!("[tun-proxy] smoltcp runner completed"),
                    Err(e) => jni_log!("[tun-proxy] smoltcp runner error: {}", e),
                }
                stopped_clone.store(true, Ordering::Release);
            }));
        }

        // 4. split Stack → (Sink for IP 包入, Stream for IP 包出)
        let (stack_sink, stack_stream) = stack.split();

        // 5. TUN → Stack pump（读 fd → Stack Sink）
        {
            let file = unsafe { std::fs::File::from_raw_fd(fd_read) };
            let async_fd = AsyncFd::new(file)?;
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let async_fd = async_fd;
                let mut sink = stack_sink;
                let mut buf = vec![0u8; TUN_MTU];
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    let mut guard = match async_fd.readable().await {
                        Ok(g) => g,
                        Err(e) => {
                            jni_log!("[tun-proxy] readable() error: {}", e);
                            break;
                        }
                    };
                    // 用 try_io：&File 实现了 Read，可用 get_ref()（不可变守卫只有 get_ref）。
                    // try_io 在 WouldBlock 时自动清除 readiness，无需手动 clear_ready。
                    match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                        Ok(Ok(0)) => {
                            // EOF — TUN fd 被关闭
                            jni_log!("[tun-proxy] TUN read EOF, stopping pump-in");
                            break;
                        }
                        Ok(Ok(n)) => {
                            // n > 0 — 读到 IP 包，送入 smoltcp 栈
                            if let Err(e) = sink.send(buf[..n].to_vec()).await {
                                jni_log!("[tun-proxy] stack send error: {}", e);
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            jni_log!("[tun-proxy] TUN read error: {}", e);
                            break;
                        }
                        Err(_would_block) => {
                            // try_io 已清除 readiness，重等
                            continue;
                        }
                    }
                }
                jni_log!("[tun-proxy] pump-in task exiting");
            }));
        }

        // 6. Stack → TUN pump（Stack Stream → 写 fd）
        {
            let file = unsafe { std::fs::File::from_raw_fd(fd_write) };
            let async_fd = AsyncFd::new(file)?;
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let async_fd = async_fd;
                let mut stream = stack_stream;
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match stream.next().await {
                        Some(Ok(pkt)) => {
                            // 写入 TUN fd，处理 WouldBlock 重试
                            loop {
                                if stopped_clone.load(Ordering::Acquire) {
                                    break;
                                }
                                let mut guard = match async_fd.writable().await {
                                    Ok(g) => g,
                                    Err(e) => {
                                        jni_log!("[tun-proxy] writable() error: {}", e);
                                        break;
                                    }
                                };
                                // 用 try_io：&File 实现了 Write，可用 get_ref()。
                                // try_io 在 WouldBlock 时自动清除 readiness。
                                match guard.try_io(|inner| inner.get_ref().write_all(&pkt)) {
                                    Ok(Ok(())) => break, // 写入成功
                                    Ok(Err(e)) => {
                                        jni_log!("[tun-proxy] TUN write error: {}", e);
                                        break;
                                    }
                                    Err(_would_block) => {
                                        // try_io 已清除 readiness，重试
                                        continue;
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            jni_log!("[tun-proxy] stack stream error: {}", e);
                        }
                        None => {
                            jni_log!("[tun-proxy] stack stream ended, stopping pump-out");
                            break;
                        }
                    }
                }
                jni_log!("[tun-proxy] pump-out task exiting");
            }));
        }

        // 7. TCP acceptor — 接受 smoltcp 产出的 TCP 连接，按目标 IP 分流
        //
        // 注意 netstack-smoltcp 的命名陷阱：TcpListener yields (stream, local_addr, remote_addr)
        // 其中 local_addr = stream.local_addr() = src_addr = IP 包源地址 = 客户端地址
        //      remote_addr = stream.remote_addr() = dst_addr = IP 包目标地址 = 服务器地址(10.0.1.3)
        // 即 local/remote 的语义与标准 TCP 相反！这里用第三元素(remote_addr)判断目标 IP。
        if let Some(tcp_listener) = tcp_listener {
            let eg = endpoint_group.clone();
            let pd = Arc::new(proxy_domains.clone());
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let mut listener: SmolTcpListener = tcp_listener;
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match listener.next().await {
                        Some((stream, _client_addr, server_addr)) => {
                            let dest_ip = server_addr.ip();
                            let dest_port = server_addr.port();
                            jni_log!(
                                "[tun-proxy] TCP accept: dest={}:{}, client={}",
                                dest_ip,
                                dest_port,
                                _client_addr
                            );
                            if dest_ip == IpAddr::V4(VIRTUAL_PROXY_IP) {
                                // 代理流量 → handle_local_connection → iroh
                                let eg = eg.clone();
                                let pd = pd.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_local_connection(stream, pd, eg).await {
                                        jni_log!(
                                            "[tun-proxy] handle_local_connection error: {}",
                                            e
                                        );
                                    }
                                });
                            } else if dest_ip == IpAddr::V4(VIRTUAL_CAPTIVE_PORTAL_IP) {
                                // captive portal 校验：
                                // - port 80 (HTTP): 返回 204 No Content，让系统判定网络已验证
                                // - port 443 (HTTPS): 直接关闭连接。不能发 plain HTTP 204——
                                //   客户端期望 TLS 握手，收到明文 HTTP 会导致 TLS 协议错误，
                                //   Android 可能把 HTTPS 失败解读为 captive portal 拦截 → 感叹号。
                                //   关闭连接让系统回退到 HTTP 校验（port 80 已返回 204）。
                                tokio::spawn(async move {
                                    let mut s = stream;
                                    if dest_port == 80 {
                                        let _ = s
                                            .write_all(
                                                b"HTTP/1.1 204 No Content\r\n\
                                                 Content-Length: 0\r\n\
                                                 Connection: close\r\n\
                                                 \r\n",
                                            )
                                            .await;
                                    }
                                    // port 443 or other: 直接 drop，stream 关闭时发 FIN
                                });
                            } else {
                                jni_log!(
                                    "[tun-proxy] TCP accept: unknown dest {}, ignoring",
                                    dest_ip
                                );
                            }
                        }
                        None => {
                            jni_log!("[tun-proxy] TCP listener stream ended");
                            break;
                        }
                    }
                }
                jni_log!("[tun-proxy] TCP acceptor task exiting");
            }));
        }

        // 8. DNS handler（UDP 53）— 处理 DNS 查询，劫持代理/portal 域名到虚拟 IP
        //
        // 并发处理：每个 DNS 查询 spawn 一个独立 task，避免串行阻塞。
        // 原串行实现在 DNS 转发超时（~1.6s）时会阻塞所有后续查询，导致 APP DNS 超时。
        if let Some(udp_socket) = udp_socket {
            let (udp_rx, udp_tx) = udp_socket.split();
            let proxy_vec = Arc::new(proxy_domains.clone());
            let portal_set: Arc<HashSet<String>> = Arc::new(
                captive_portal_domains
                    .into_iter()
                    .map(|d| d.to_lowercase())
                    .collect(),
            );
            let dns_servers = Arc::new(custom_dns_servers);
            let stopped_clone = stopped.clone();
            // udp_tx 需要 Arc<Mutex> 共享给并发 task
            let tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
            tasks.push(tokio::spawn(async move {
                let mut rx = udp_rx;
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match rx.next().await {
                        Some((data, src_addr, dst_addr)) => {
                            // 并发处理每个 DNS 查询，不阻塞后续查询
                            let tx = tx.clone();
                            let proxy_vec = proxy_vec.clone();
                            let portal_set = portal_set.clone();
                            let dns_servers = dns_servers.clone();
                            tokio::spawn(async move {
                                let response =
                                    handle_dns_query(&data, &proxy_vec, &portal_set, &dns_servers)
                                        .await;
                                if let Some(resp) = response {
                                    // 回送：src=10.0.1.2:53(查询的 dst), dst=客户端(查询的 src)
                                    let mut tx = tx.lock().await;
                                    let _ = tx.send((resp, dst_addr, src_addr)).await;
                                }
                            });
                        }
                        None => {
                            jni_log!("[tun-proxy] UDP stream ended");
                            break;
                        }
                    }
                }
                jni_log!("[tun-proxy] DNS handler task exiting");
            }));
        }

        jni_log!("[tun-proxy] Started with {} tasks", tasks.len());
        Ok(Self { stopped, tasks })
    }

    /// 停止所有后台任务。非阻塞 — abort() 标记任务取消，不等待完成。
    /// 用于 `Drop` 或不需要等待 fd 关闭的场景。
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        for task in &self.tasks {
            task.abort();
        }
        jni_log!("[tun-proxy] Stopped (aborted {} tasks)", self.tasks.len());
    }

    /// Abort 所有任务并等待它们完成（带超时），确保 fd 被关闭后再返回。
    /// 消费 self。在 `nativeStopTunProxy` / `nativeStopProxy` 中使用，
    /// 确保在 endpoint_group.close_all() 之前 TUN 代理的 fd 已释放。
    pub fn shutdown(mut self, runtime: &tokio::runtime::Runtime) {
        self.stopped.store(true, Ordering::Release);
        // 用 mem::take 取出 tasks，避免 E0509（不能从 Drop 类型 move 出字段）
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            task.abort();
            // 等待任务结束（drop future → drop AsyncFd → close fd）
            let _ = runtime.block_on(async {
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
            });
        }
        jni_log!("[tun-proxy] Shutdown complete (all tasks joined)");
        // self dropped here → Drop::drop 调 stop()（幂等，tasks 已空）
    }
}

impl Drop for TunProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

// ============================================================
// 辅助函数
// ============================================================

/// 设置 fd 为非阻塞模式。
fn set_nonblocking(fd: RawFd) -> Result<(), ClientError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

// ============================================================
// DNS 处理 — 移植自 Kotlin NexaVpnService
// ============================================================

/// 处理 DNS 查询，返回 DNS 响应 payload。
///
/// - 代理域名 → 返回 10.0.1.3（A 记录）
/// - captive portal 域名 → 返回 10.0.1.4（A 记录）
/// - iroh 基础设施域名 → 转发到真实 DNS（不在 TUN 内代理）
/// - 其他域名 → 转发到真实 DNS，原样返回响应
async fn handle_dns_query(
    query: &[u8],
    proxy_domains: &Arc<Vec<String>>,
    portal_domains: &Arc<HashSet<String>>,
    dns_servers: &Arc<Vec<SocketAddr>>,
) -> Option<Vec<u8>> {
    let (domain, qtype) = match parse_dns_query(query) {
        Some(d) => d,
        None => return None,
    };
    if domain.is_empty() {
        return None;
    }

    let domain_lower = domain.to_lowercase();

    // iroh 基础设施域名不通过 TUN 代理 — iroh 自身的流量走 addDisallowedApplication
    let is_iroh = domain_lower.ends_with(".iroh.link") || domain_lower.ends_with(".n0.iroh.link");

    let is_portal = portal_domains.contains(&domain_lower);
    let is_proxy = !is_portal && !is_iroh && should_proxy_domain(&domain, proxy_domains);

    if is_portal {
        jni_log!(
            "[tun-proxy] DNS: '{}' -> captive portal IP {}",
            domain,
            VIRTUAL_CAPTIVE_PORTAL_IP
        );
        Some(build_dns_response(query, VIRTUAL_CAPTIVE_PORTAL_IP, qtype))
    } else if is_proxy {
        jni_log!(
            "[tun-proxy] DNS: '{}' -> proxy IP {}",
            domain,
            VIRTUAL_PROXY_IP
        );
        Some(build_dns_response(query, VIRTUAL_PROXY_IP, qtype))
    } else {
        // 转发到真实 DNS
        jni_log!(
            "[tun-proxy] DNS: '{}' -> forwarding to real DNS (qtype={})",
            domain,
            qtype
        );
        forward_dns_query(query, dns_servers).await
    }
}

/// 解析 DNS 查询，返回 (域名, QTYPE)。
/// QTYPE: 1=A, 28=AAAA。解析失败返回 None。
fn parse_dns_query(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 12 {
        return None;
    }

    // DNS header: ID(2) + flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    // 解析 Question section 的域名（length-prefixed labels）
    let mut pos = 12;
    let mut labels: Vec<&str> = Vec::new();

    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 {
            pos += 1; // 跳过 null 终止符
            break;
        }
        // 防止越界
        if pos + 1 + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
        labels.push(label);
        pos += 1 + len;
    }

    // pos 指向 null 字节之后。QTYPE 是紧随其后的 2 字节。
    let qtype = if pos + 2 <= payload.len() {
        u16::from_be_bytes([payload[pos], payload[pos + 1]])
    } else {
        0
    };

    Some((labels.join("."), qtype))
}

/// 构建 DNS 响应：将域名解析为指定的 IPv4 地址。
///
/// - qtype=1 (A): 返回 A 记录 with 4 bytes RDATA
/// - qtype=28 (AAAA) 或其他: 返回空应答（ANCOUNT=0），让客户端回退到 A 查询
fn build_dns_response(query: &[u8], ip: Ipv4Addr, qtype: u16) -> Vec<u8> {
    // 非 A 查询：返回空应答（虚拟 IP 是 IPv4，无法回答 AAAA/MX 等）
    if qtype != 1 {
        return build_empty_dns_response(query);
    }

    let mut response = Vec::with_capacity(query.len() + 16);
    response.extend_from_slice(query);

    // 设置 flags: QR=1, Opcode=0, AA=0, TC=0, RD=1(copied), RA=1
    response[2] = 0x81;
    response[3] = 0x80;
    // ANCOUNT = 1
    response[6] = 0x00;
    response[7] = 0x01;

    // Answer section:
    // Name: 压缩指针 0xC00C → 指向 offset 12（Question section 的域名）
    response.push(0xC0);
    response.push(0x0C);
    // TYPE: A = 1
    response.push(0x00);
    response.push(0x01);
    // CLASS: IN = 1
    response.push(0x00);
    response.push(0x01);
    // TTL: 60 seconds (0x0000003C)
    response.push(0x00);
    response.push(0x00);
    response.push(0x00);
    response.push(0x3C);
    // RDLENGTH: 4 (IPv4)
    response.push(0x00);
    response.push(0x04);
    // RDATA: IP 地址的 4 字节
    response.extend_from_slice(&ip.octets());

    response
}

/// 构建空 DNS 应答：QR=1, RA=1, RCODE=0(NoError), ANCOUNT=0。
/// 用于"查询类型不支持"或"没有匹配类型的地址"。
fn build_empty_dns_response(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    // ANCOUNT = 0
    response[6] = 0x00;
    response[7] = 0x00;
    response
}

/// 将 DNS 查询转发到真实 DNS 服务器，原样返回响应。
///
/// 遍历所有配置的 DNS 服务器，**IPv4 优先**，按地址族绑定 socket
/// （IPv4→0.0.0.0:0，IPv6→[::]:0）。每个服务器单独 800ms 超时，整体 3s 限制。
///
/// 解决：系统 DNS 列表前几个是 IPv6（如 2408:8888::8）导致
/// 绑定 0.0.0.0:0 后 connect() 失败，且原代码只尝试 dns_servers[0] 不会 fallback。
async fn forward_dns_query(query: &[u8], dns_servers: &Arc<Vec<SocketAddr>>) -> Option<Vec<u8>> {
    if dns_servers.is_empty() {
        jni_log!("[tun-proxy] No DNS servers configured, dropping query");
        return None;
    }

    // IPv4 优先：先尝试 IPv4 DNS（更快更可靠），再尝试 IPv6
    let mut ordered: Vec<&SocketAddr> = dns_servers.iter().collect();
    ordered.sort_by_key(|s| !s.is_ipv4() as u8); // false(=IPv4) 排前

    let per_server_timeout = Duration::from_millis(800);

    let result = tokio::time::timeout(DNS_FORWARD_TIMEOUT, async {
        for dns_server in ordered.iter() {
            // 按地址族绑定：IPv4 DNS → 0.0.0.0:0，IPv6 DNS → [::]:0
            let bind_addr = if dns_server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };

            // 每个服务器单独超时，避免卡在不可达的 IPv6 DNS 上
            let server_result = tokio::time::timeout(per_server_timeout, async {
                let sock = tokio::net::UdpSocket::bind(bind_addr).await.ok()?;
                sock.connect(**dns_server).await.ok()?;
                sock.send(query).await.ok()?;
                let mut buf = vec![0u8; 4096];
                let n = sock.recv(&mut buf).await.ok()?;
                Some(buf[..n].to_vec())
            })
            .await;

            match server_result {
                Ok(Some(resp)) => return Some(resp),
                _ => continue,
            }
        }
        None
    })
    .await;

    match result {
        Ok(Some(resp)) => Some(resp),
        Ok(None) => {
            jni_log!(
                "[tun-proxy] DNS forward failed (all {} servers failed)",
                dns_servers.len()
            );
            None
        }
        Err(_) => {
            jni_log!(
                "[tun-proxy] DNS forward timed out after {}s",
                DNS_FORWARD_TIMEOUT.as_secs()
            );
            None
        }
    }
}
