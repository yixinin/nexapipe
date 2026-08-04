# 用 netstack-smoltcp 替换 Android 手写 TCP 栈

## Context

Android 端 `NexaVpnService.kt` 用 ~400 行 Kotlin 手写了一个用户态 TCP/IP 协议栈来处理 TUN 流量。该实现存在多个致命 bug（无 MSS 分段、无重传、窗口固定 4096、FIN 不回 ACK、ConcurrentHashMap 竞态、跨 chunk HTTP 头替换等），导致飞牛 APP 等连接失败/挂死。Windows 端 local-proxy 工作正常（同一份 Rust 代码），证明 iroh 隧道本身无问题。

**方案**：用 `netstack-smoltcp` crate（基于 smoltcp，tun2proxy 的底层库）在 Rust 侧实现完整的 TUN→TCP/IP 栈，Kotlin 侧只负责创建 TUN 接口并传递 fd。smoltcp 的 `TcpStream` 直接对接 `handle_local_connection`（泛型化重构），跳过 localhost TCP 跳转。

## 新架构数据流

```
APP → TUN fd → Rust(AsyncFd) → Stack(Sink: IP包入)
                                 ↓ smoltcp 处理
                          ┌──────┴──────┐
                     TcpListener    UdpSocket
                     (TCP 连接)      (DNS 查询)
                          │              │
              ┌───────────┤              ├──────────────┐
              ↓           ↓              ↓              ↓
         10.0.1.3:80,443  10.0.1.4:80   解析域名       非代理域名
         (代理流量)       (captive portal)  │              │
              │           │              ↓              ↓
     handle_local_     返回 204       代理→10.0.1.3   转发真实 DNS
     connection        (硬编码响应)    portal→10.0.1.4  (tokio UdpSocket)
     (→iroh→后端)
                          │
              Stack(Stream: IP包出) → AsyncFd → 写回 TUN fd
```

## 实现步骤

### Step 1: 添加依赖 (`crates/nexapipe-client/Cargo.toml`)

```toml
[dependencies]
# 新增
netstack-smoltcp = "0.2"
libc = "0.2"
# futures-util 已存在(0.3.32)，用于 StreamExt/SinkExt/split()

[features]
# 新增 feature flag
tun-proxy = ["local-proxy", "dep:netstack-smoltcp", "dep:libc"]
```

### Step 2: 泛型化 `handle_local_connection` (`crates/nexapipe-client/src/local_proxy.rs`)

将签名从 `tokio::net::TcpStream` 改为泛型 `S: AsyncRead + AsyncWrite + Unpin`：

```rust
// 修改前
async fn handle_local_connection(
    mut stream: tokio::net::TcpStream,
    proxy_domains: Arc<Vec<String>>,
    endpoint_group: Arc<EndpointGroup>,
) -> Result<(), ClientError> { ... }

// 修改后
pub(crate) async fn handle_local_connection<S>(
    mut stream: S,
    proxy_domains: Arc<Vec<String>>,
    endpoint_group: Arc<EndpointGroup>,
) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{ ... }  // 函数体不变，只用了 read/write_all/shutdown
```

同样泛型化 `handle_tls_tunnel`（如果它也接受 `TcpStream` 参数）。`LocalProxy::run()` 中调用 `handle_local_connection` 时传入 `tokio::net::TcpStream`（已实现 trait），无需改动。

### Step 3: 新建 `tun_proxy.rs` 模块 (`crates/nexapipe-client/src/tun_proxy.rs`)

核心结构：

```rust
use netstack_smoltcp::{StackBuilder, Stack, TcpListener as SmolTcpListener, UdpSocket};
use futures_util::stream::{StreamExt, SplitSink, SplitStream};
use futures_util::sink::SinkExt;
use tokio::io::unix::AsyncFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinHandle;
use crate::local_proxy::handle_local_connection;
use crate::EndpointGroup;

// 虚拟 IP 常量（与 Kotlin 侧一致）
const VIRTUAL_DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
const VIRTUAL_PROXY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 3);
const VIRTUAL_CAPTIVE_PORTAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 4);

pub struct TunProxy {
    stopped: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

impl TunProxy {
    pub fn new(
        tun_fd: std::os::fd::RawFd,
        endpoint_group: Arc<EndpointGroup>,
        proxy_domains: Vec<String>,
        captive_portal_domains: Vec<String>,
        custom_dns_servers: Vec<SocketAddr>,
    ) -> Result<Self, ClientError> {
        // 1. dup fd + 设非阻塞
        let fd_read = unsafe { libc::dup(tun_fd) };
        let fd_write = unsafe { libc::dup(tun_fd) };
        set_nonblocking(fd_read);
        set_nonblocking(fd_write);

        // 2. 构建 smoltcp 栈
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .mtu(1500)
            .build()?;

        // 3. spawn Runner（驱动 smoltcp 内部处理）
        let runner_handle = runtime.spawn(async move {
            if let Some(r) = runner { r.await; }
        });

        // 4. split Stack → (Sink, Stream)
        let (stack_sink, stack_stream) = stack.split();

        // 5. spawn TUN→Stack pump（读 fd → Stack Sink）
        let pump_in = runtime.spawn(async move {
            let file = unsafe { std::fs::File::from_raw_fd(fd_read) };
            let async_fd = AsyncFd::new(file).unwrap();
            let mut sink = stack_sink;
            let mut buf = vec![0u8; 1500];
            loop {
                let mut guard = async_fd.readable().await.unwrap();
                match guard.try_io(|inner| inner.get_mut().read(&mut buf)) {
                    Ok(Ok(n)) if n > 0 => {
                        let _ = sink.send(buf[..n].to_vec()).await;
                    }
                    _ => {}
                }
            }
        });

        // 6. spawn Stack→TUN pump（Stack Stream → 写 fd）
        let pump_out = runtime.spawn(async move {
            let file = unsafe { std::fs::File::from_raw_fd(fd_write) };
            let async_fd = AsyncFd::new(file).unwrap();
            let mut stream = stack_stream;
            while let Some(Ok(pkt)) = stream.next().await {
                let mut guard = async_fd.writable().await.unwrap();
                let _ = guard.try_io(|inner| inner.get_mut().write_all(&pkt));
            }
        });

        // 7. spawn TCP acceptor
        let tcp_handle = runtime.spawn(async move {
            let mut listener = tcp_listener.unwrap();
            let eg = endpoint_group;
            let pd = Arc::new(proxy_domains);
            while let Some((stream, local_addr, _remote)) = listener.next().await {
                let local_ip = local_addr.ip();
                if local_ip == IpAddr::V4(VIRTUAL_PROXY_IP) {
                    // 代理流量 → handle_local_connection → iroh
                    let eg = eg.clone();
                    let pd = pd.clone();
                    runtime.spawn(async move {
                        let _ = handle_local_connection(stream, pd, eg).await;
                    });
                } else if local_ip == IpAddr::V4(VIRTUAL_CAPTIVE_PORTAL_IP) {
                    // captive portal → 返回 204
                    runtime.spawn(async move {
                        use tokio::io::AsyncWriteExt;
                        let mut s = stream;
                        let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
                    });
                }
                // 其他目标 IP 的 TCP 连接：忽略（不应出现在 10.0.1.0/24 路由中）
            }
        });

        // 8. spawn DNS handler（UDP 53）
        let (udp_rx, udp_tx) = udp_socket.unwrap().split();
        let dns_handle = runtime.spawn(async move {
            let mut rx = udp_rx;
            let mut tx = udp_tx;
            let proxy_set: HashSet<String> = proxy_domains.into_iter().collect();
            let portal_set: HashSet<String> = captive_portal_domains.into_iter().collect();
            let dns_servers = custom_dns_servers;

            while let Some((data, src_addr, dst_addr)) = rx.next().await {
                // dst_addr 应为 10.0.1.2:53
                let response = handle_dns_query(&data, &proxy_set, &portal_set, &dns_servers).await;
                if let Some(resp) = response {
                    // 回送：src=10.0.1.2:53, dst=原 src
                    let _ = tx.send((resp, dst_addr, src_addr)).await;
                }
            }
        });

        Ok(Self {
            stopped: Arc::new(AtomicBool::new(false)),
            tasks: vec![runner_handle, pump_in, pump_out, tcp_handle, dns_handle],
        })
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        for task in &self.tasks {
            task.abort();
        }
    }
}
```

**DNS 处理函数**（移植自 Kotlin `extractDomainAndQtypeFromDNSQuery` / `createDNSResponse`）：

```rust
/// 解析 DNS 查询，返回 DNS 响应 payload。
/// - 代理域名 → 返回 10.0.1.3
/// - captive portal 域名 → 返回 10.0.1.4
/// - 其他域名 → 转发到真实 DNS（custom_dns_servers），原样返回响应
async fn handle_dns_query(
    query: &[u8],
    proxy_domains: &HashSet<String>,
    portal_domains: &HashSet<String>,
    dns_servers: &[SocketAddr],
) -> Option<Vec<u8>> {
    let (domain, qtype) = parse_dns_query(query)?;
    if domain.is_empty() { return None; }

    if portal_domains.contains(&domain) {
        Some(build_dns_response(query, VIRTUAL_CAPTIVE_PORTAL_IP, qtype))
    } else if should_proxy_domain(&domain, proxy_domains) {
        Some(build_dns_response(query, VIRTUAL_PROXY_IP, qtype))
    } else {
        // 转发到真实 DNS
        forward_dns_query(query, dns_servers).await
    }
}
```

`parse_dns_query` 和 `build_dns_response` 直接移植 Kotlin 侧的 `extractDomainAndQtypeFromDNSQuery` 和 `createDNSResponse` 逻辑（~60 行 Rust，解析 DNS wire format）。`forward_dns_query` 用 `tokio::net::UdpSocket` 发送原始查询到 `CUSTOM_DNS_SERVERS[0]:53`，超时 3s，原样返回响应。

### Step 4: 添加 JNI 函数 (`crates/nexapipe-client/src/jni.rs`)

```rust
// ProxyState 新增字段
struct ProxyState {
    // ... 现有字段 ...
    tun_proxy: Option<TunProxy>,  // 新增
}

// 新增 JNI 函数
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartTunProxy(
    mut env: JNIEnv, _class: JClass,
    tun_fd: jint, proxy_port: jint,
    proxy_domains: JString, captive_portal_domains: JString,
) -> jint {
    // 1. 解析参数（fd, port, domains 字符串）
    // 2. 从 ProxyState 获取 endpoint_group (Arc<EndpointGroup>)
    // 3. 读取 CUSTOM_DNS_SERVERS（已有全局变量）
    // 4. 调用 TunProxy::new(fd, endpoint_group, proxy_domains, portal_domains, dns_servers)
    //    — 注意：TunProxy::new 内部用 runtime.spawn() 启动任务，不 block_on
    // 5. 存入 ProxyState.tun_proxy
    // 6. 返回 0 成功 / -1 失败
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy(
    env: JNIEnv, _class: JClass,
) -> jint {
    // 1. 从 ProxyState 取出 tun_proxy
    // 2. 调用 tun_proxy.stop()（abort 所有 task）
    // 3. 设置 tun_proxy = None
}
```

**生命周期集成**：
- `nativeStopTunProxy` 由 `NexaVpnService.stopVPN()` 调用（在关闭 TUN fd 之前）
- `nativeDestroy` 末尾也调 `nativeStopTunProxy` 作为安全网
- `nativeStopProxy` 不触碰 `tun_proxy`（与 endpoint 生命周期分离，遵循现有约定）

### Step 5: Kotlin JNI 声明 (`IrohProxy.kt`)

```kotlin
/**
 * 启动 TUN 代理：用 smoltcp 在 Rust 侧处理 TUN fd 的 TCP/UDP 流量。
 * 必须在 nativeStartProxy 之后、VPN 建立之后调用。
 * tun_fd: ParcelFileDescriptor.detachFd() 返回的原始 fd
 */
external fun nativeStartTunProxy(
    tunFd: Int,
    proxyPort: Int,
    proxyDomains: String,        // 逗号分隔
    captivePortalDomains: String // 逗号分隔
): Int

external fun nativeStopTunProxy(): Int
```

### Step 6: 精简 `NexaVpnService.kt`

**保留**（~200 行）：
- `establishVPN()`：Builder 配置、addAddress、addRoute、addDnsServer、addDisallowedApplication、setUnderlyingNetworks
- `NetworkCallback`：检测 underlyingNetwork
- 前台服务 + 通知
- `startVPN(proxyPort, domains)` / `stopVPN()` 框架

**删除**（~1200 行）：
- 全部 TCP 处理：`handleTCPPacket`、`handleTCPSYN`、`handleTCPData`、`handleTCPFIN`、`handleTCPRST`、`handleTCPACK`、`TcpConnection`、`tcpConnections`、`sendTCPPacket`、`createTCPPacket`、`calculateChecksum`、reader job 逻辑
- 全部 DNS 处理：`handleUDPPacket`、`extractDomainAndQtypeFromDNSQuery`、`createDNSResponse`、`queryRealDNS`、`shouldProxyDomain`、`createUDPPacket`
- Captive portal 服务器：`startCaptivePortalServer`、`stopCaptivePortalServer`（移到 Rust，204 硬编码）
- TUN 读取循环：`startPacketProcessing`、`writeToTun`、`createTunWriterExecutor`
- 所有虚拟 IP 常量（移到 Rust）

**新增**：

```kotlin
private fun establishVPN() {
    // ... Builder 配置（不变）...
    vpnInterface = builder.establish() ?: run {
        isRunning = false; return
    }

    // 将 TUN fd 传给 Rust，启动 smoltcp TUN 代理
    val fd = vpnInterface!!.detachFd()  // 转移 fd 所有权给 Rust
    val proxyDomainsStr = allowedDomains.joinToString(",")
    val portalDomainsStr = captivePortalDomains.joinToString(",")
    val result = IrohProxy.nativeStartTunProxy(fd, proxyPort, proxyDomainsStr, portalDomainsStr)
    if (result != 0) {
        Log.e(TAG, "Failed to start TUN proxy: $result")
        isRunning = false
        return
    }
    // ... 通知 + 前台服务 ...
}

fun stopVPN() {
    isRunning = false
    IrohProxy.nativeStopTunProxy()  // 先停 smoltcp（abort task + 关 fd）
    // vpnInterface 已 detachFd，无需再 close
    // ... 清理通知等 ...
}
```

**注意**：用 `detachFd()` 转移 fd 所有权给 Rust，Rust 侧 `dup` 后使用。`nativeStopTunProxy` 关闭 dup 的 fd，原始 fd 由 Rust 在 `TunProxy::drop` 时关闭。Kotlin 侧不再 close `vpnInterface`。

### Step 7: 更新 `VpnViewModel.kt`

`connect()` 流程基本不变，只是 `NexaVpnService` 启动方式不变（通过 Intent 传递 proxyPort + domains）。`releaseAllResources` 中 `nativeDestroy` 已会调 `nativeStopTunProxy`。

**唯一新增**：`captivePortalDomains` 需要传给 `NexaVpnService`（通过 Intent extra 或共享常量）：

```kotlin
val intent = Intent(context, NexaVpnService::class.java).apply {
    action = NexaVpnService.ACTION_START
    putExtra(NexaVpnService.EXTRA_PROXY_PORT, actualPort)
    putStringArrayListExtra(NexaVpnService.EXTRA_DOMAINS, ArrayList(allDomains))
    // captivePortalDomains 在 NexaVpnService 中硬编码（与 Rust 常量一致）
}
```

### Step 8: 更新 `build_android.bat`

```bat
cargo build --target aarch64-linux-android --features jni,local-proxy,tun-proxy --release
```

### Step 9: 更新 `lib.rs`

```rust
#[cfg(feature = "tun-proxy")]
pub mod tun_proxy;

#[cfg(feature = "tun-proxy")]
pub use tun_proxy::TunProxy;
```

## 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| TCP 栈实现 | netstack-smoltcp (smoltcp) | 纯 Rust，与 nexapipe 技术栈一致，tun2proxy 验证过 |
| TUN→local_proxy 对接 | 直接调用 handle_local_connection（泛型化） | 用户选择，无 localhost TCP 跳转，更高效 |
| DNS 处理 | 移到 Rust（smoltcp UdpSocket） | 单一 TUN fd 无法在 Kotlin/Rust 间共享 |
| TUN fd 包装 | tokio AsyncFd + libc dup | 不加额外 crate，~50 行 wrapper |
| fd 所有权 | detachFd → Rust 拥有 | 避免双 close |
| feature flag | tun-proxy = ["local-proxy", ...] | 不影响桌面端编译 |
| captive portal | Rust 硬编码 204 响应 | 无需 Kotlin 的 ServerSocket |

## 验证

1. **宿主编译检查**：`cargo check -p nexapipe-client --features jni,local-proxy,tun-proxy --no-default-features`
2. **Android 交叉编译**：`build_android.bat` 成功生成 .so
3. **Kotlin 编译**：`ui-android` 下 `.\gradlew.bat :app:compileDebugKotlin`
4. **端到端测试**：
   - 启动 APP → connect → 飞牛 APP 能连接
   - logcat 中看到 smoltcp 的 TCP 连接日志（`[DEBUG:local-proxy] New local connection received`）
   - DNS 查询正确劫持（代理域名 → 10.0.1.3，portal 域名 → 10.0.1.4）
   - WiFi 无感叹号（captive portal 204 生效）
   - 断开/重连正常（`nativeStopTunProxy` → `nativeStartTunProxy` 循环无泄漏）

## 风险与注意事项

1. **`netstack-smoltcp` 的 `Stack::split()`**：`SplitSink`/`SplitStream` 共享 `BiLock`，两个 pump task 间有同步开销。对 VPN 代理场景可接受，若性能不足可改为单 task `select!` 驱动。
2. **`AsyncFd` 的 `try_io` 语义**：`try_io` 返回 `Err(io::Error)`（WouldBlock）时需 clear readiness 后重试。实现时参考 tokio AsyncFd 文档的 canonical pattern。
3. **DNS 解析超时**：`forward_dns_query` 用 `tokio::time::timeout(3s, ...)` 包裹，超时返回 `None`（丢弃查询，客户端会重试）。
4. **`detachFd` 后的 ParcelFileDescriptor**：调用 `detachFd()` 后，`ParcelFileDescriptor` 对象变为无效（fd 已转移），不能再 `close()`。确保 `stopVPN()` 中不 double-close。
5. **smoltcp 的 MTU**：设为 1500（与 TUN 接口一致）。smoltcp 自动处理 TCP MSS = MTU - 40 = 1460。
