# iroh 隧道断线重连健壮性改造

## Context（背景）

`ui-android` 是基于 iroh P2P 协议的 Android VPN 应用。用户反馈：**有时很久无法建立隧道或预连接**，希望加入超时机制——超时后**释放所有资源并重新初始化隧道连接**。

经审查，根因在 **Rust 原生层（`jni.rs`）+ Kotlin 编排层（`VpnViewModel.kt`）** 两处缺陷叠加：

1. `nativeStartIroh` 在 `Endpoint::bind().await`（STUN/relay/DNS 发现，弱网下可卡数分钟）期间持有 `std::sync::Mutex` 互斥锁，且**无超时**。
2. `nativeStopProxy` 末尾 `ENDPOINT.lock()` 会因上述锁被卡住而**永久阻塞**——所以"释放所有资源"在 startIroh 卡死时根本无法执行，正是用户所见症状。
3. `nativeStopProxy` 持有 `state` 互斥锁跨 `block_on(close_all())`，`close_all` 卡住时 state 锁永久占用，后续所有 native 调用死锁。
4. **隐藏致命 bug**：`disconnect()` 调 `nativeStopProxy` 清掉了全局 endpoint，但 `isIrohStarted` 仍为 `true`；下次 `connect()` 跳过 `nativeStartIroh`，`nativeStartProxy` 因 `get_endpoint()` 返回 None 走入「每节点独立 `bind()`」分支（`connection_pool.rs:14`，无超时、按后端数翻倍），把问题 1 重新放大。
5. Kotlin `connect()` 无整体超时、无重试+重置；`connect()`/`disconnect()` 在 `Dispatchers.IO` 上无互斥，存在竞态。
6. `proxy.run()` 任务 fire-and-forget，停止仅靠 100ms 轮询的 `AtomicBool`，端口释放不确定（Kotlin 里用 `delay(500)` 规避）。

目标：超时 → 全量释放 → 重新初始化，且重连可在弱网/卡死场景下可靠完成。

## 方案：Rust + Kotlin 双层修复

### Part 1 — Rust `crates/nexapipe-client/src/jni.rs`

**1.1 新增代际计数器与超时常量**（文件顶部 statics 之后）
```rust
use std::sync::atomic::{AtomicU64, Ordering};
static ENDPOINT_GEN: AtomicU64 = AtomicU64::new(0);
const IROH_BIND_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
const START_PROXY_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(15);
const CLOSE_ALL_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(8);
const PROXY_RUN_JOIN_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_millis(500);
```

**1.2 `ProxyState` 增加 `proxy_task: Option<tokio::task::JoinHandle<()>>`**（同步更新 `init_state` 初值 `None`）。

**1.3 重写 `nativeStartIroh`（jni.rs:117-164）—— 锁不跨 await + 代际守卫**
- 快速路径：仅短暂锁 ENDPOINT 读取已有 endpoint，立即返回其 id。
- `bind()` **不持锁**，包在 `tokio::time::timeout(IROH_BIND_TIMEOUT, …)` 内；超时/出错返回 null。
- bind 前读 `gen_before = ENDPOINT_GEN.load(Acquire)`；bind 后重新锁 ENDPOINT，若 `gen_now != gen_before`（期间发生过 stop）则**丢弃**新 endpoint 返回 null；若已有别人写入则返回其 id；否则写入自己的。`env`（`!Send`）绝不进入 `block_on` 闭包。

**1.4 重写 `nativeStartProxy`（jni.rs:166-348）—— 分阶段超时 + 无 endpoint 即失败 + 存 JoinHandle**
- 克隆 nodes/domain_mappings 出 state 后，若 `get_endpoint()` 为 None 立即返回 -1（堵死问题 4 的 per-pool bind 回退）。
- `EndpointGroup::new_*` 与 `LocalProxy::new` 各包 `tokio::time::timeout(START_PROXY_TIMEOUT, …)`，超时返回 -1。
- state 写回时重新加锁并校验 `local_proxy.is_some()`（防问题：并发 stop 清空后的脏写）。
- `runtime.spawn(proxy.run())` 的 `JoinHandle` 存入 `guard.proxy_task`。

**1.5 重写 `nativeStopProxy`（jni.rs:477-534）—— 三阶段、锁不跨 block_on、代际自增、确定式任务回收**
- Phase 1：短暂锁 ENDPOINT，`ENDPOINT_GEN.fetch_add(1, AcqRel)` 后 `guard.take()`（即使后续 close_all 卡住，endpoint 已释放 → 彻底解决问题 2）。
- Phase 2：锁 state，把 `local_proxy/endpoint_group/conn_pool/proxy_task` 全部 `.take()` 出来（字段置 None），**立即 drop guard**，再进入任何 `block_on`。
- Phase 3a：`local_proxy.stop()` 置 AtomicBool。
- Phase 3b：`proxy_task.abort()` 后 `block_on(timeout(PROXY_RUN_JOIN_TIMEOUT, handle))`（确定式释放监听端口 → 可移除 Kotlin 的 `delay(500)`）。
- Phase 3c：`group.close_all()`、`pool.close_all()` 各包 `timeout(CLOSE_ALL_TIMEOUT, …)`，**不持 state 锁**。
- 全程幂等，`.take()` 对 None 安全；每次 `.lock()` 用 `if let Ok(g)` 处理中毒。

`nativeDestroy` 无需改动（已委托 `nativeStopProxy`）。

### Part 2 — Kotlin `ui-android/.../ui/VpnViewModel.kt`

**2.1 串行化原语**（类顶部 StateFlow 附近）
```kotlin
private val connectionMutex = kotlinx.coroutines.sync.Mutex()
private var connectJob: kotlinx.coroutines.Job? = null
companion object { const val MAX_ATTEMPTS = 3; const val ATTEMPT_TIMEOUT_MS = 60_000L
                   const val DISCONNECT_MUTEX_TIMEOUT_MS = 70_000L
                   val BACKOFF_MS = longArrayOf(0, 1_000, 2_000) }
```

**2.2 新增 `releaseAllResources(context)` —— 唯一「全量拆机」入口**
- `IrohProxy.nativeStopProxy()`（try/catch）
- `isIrohStarted.value = false`、`endpointId.value = ""`（**问题 4 的关键修复**）
- `startService(ACTION_STOP)` 停 VPN 服务
- `isVpnRunning.value = false`
- 每条失败/取消路径都调用它。

**2.3 重写 `connect()`（VpnViewModel.kt:99-213）为重试循环**
- `connectionMutex.tryLock()` 防与 disconnect 并发；存 `connectJob`。
- `for (attempt in 1..MAX_ATTEMPTS)`：`withTimeout(ATTEMPT_TIMEOUT_MS) { ensureIrohStarted(); addDomainMappings(); startProxyWithRetries(); preConnectAll(...) }`；成功则 `startForegroundService`、`isVpnRunning=true`、return。
- 捕获 `TimeoutCancellationException`/`Exception` 记录 `lastError`；`attempt < MAX` 时 `releaseAllResources(context)` 后 `delay(BACKOFF_MS[attempt])`。
- `finally`：复位 `isConnecting`/`connectionStatusText`、`connectionMutex.unlock()`。
- 把原 117-176 抽成 `ensureIrohStarted()`/`addDomainMappings()`/`startProxyWithRetries()`；**移除 `delay(500)`**（Rust 确定式回收端口后不再需要），保留每端口 `delay(200)` 重试。

**2.4 重写 `disconnect()`（VpnViewModel.kt:276-291）**
- `connectJob?.cancel()`（JNI 调用不可中断，但下一挂起点抛 `CancellationException` 跳过剩余步骤）。
- `withTimeoutOrNull(DISCONNECT_MUTEX_TIMEOUT_MS) { connectionMutex.withLock { releaseAllResources(context) } }`；超时则直接 `releaseAllResources`（Rust 已无死锁，安全兜底）。

**2.5 收紧 `preConnect`（VpnViewModel.kt:220-248）**：`withTimeout(15_000)`→`6_000`，`maxRetries=2`→`1`（外层 60s 已封顶总预算）。删除 `preConnectAll` 内重复的 `connectionStatusText` 赋值（line 256）。

### Part 3 — 编译与验证

**3.1 重新编译 .so**：执行 `c:\Users\eason\rust\nexapipe\build_android.bat`（`cargo build --target aarch64-linux-android --features jni,local-proxy --release` + 拷贝到 `app/src/main/jniLibs/arm64-v8a/`）。若 NDK 环境缺失则报告错误并交还用户手动编译。**注意：必须先编译 .so 再测 Kotlin，否则 `delay(500)` 移除会复现端口占用竞态。**

**3.2 顺序**：先落地 Part 1（1.1–1.5 互相依赖，必须一起）并重编 .so；再落地 Part 2。

**3.3 验证矩阵（logcat 过滤 `tag:NexaVpnService / VpnViewModel`）**
1. 正常 连接→断开→重连：断开后 `isIrohStarted` 翻 false，重连日志出现 "Starting iroh first..."。
2. 连接中开飞行模式：~60s 内 attempt 1 超时 → `releaseAllResources` → 重试 → 最终报错而非 `isConnecting` 卡死。
3. startIroh 卡在 bind 时点断开：断开在 ~30s(bind 超时)+~8s(close_all 超时) 内完成；孤立 bind 的迟到结果被丢弃（日志 "endpoint generation changed during bind, discarding"）。
4. 快速反复点连接/断开：`connectionMutex` + `connectJob.cancel()` 不出现 native 调用交错。

## 关键文件
- `c:\Users\eason\rust\nexapipe\crates\nexapipe-client\src\jni.rs`（核心）
- `c:\Users\eason\rust\nexapipe\ui-android\app\src\main\java\com\nexa\pipe\ui\VpnViewModel.kt`（核心）
- `c:\Users\eason\rust\nexapipe\crates\nexapipe-client\src\local_proxy.rs`（run/stop 语义参考，无需改）
- `c:\Users\eason\rust\nexapipe\build_android.bat`（编译入口）

## 复用的既有结构（不重造轮子）
- `LocalProxy::stop()` / `EndpointGroup::close_all()` / `IrohConnectionPool::close_all()`（`local_proxy.rs:135`、`endpoint_group.rs:286`）—— 保留，仅在外层加超时。
- `withTimeout` / `kotlinx.coroutines.sync.Mutex` / `withLock` —— Kotlin 侧直接用。
- `connectionStatusText` StateFlow（VpnViewModel.kt:43）已接 UI，重试状态沿用。

## 超时取值（可后续调整）
| 项 | 值 |
|---|---|
| iroh `bind()` | 30s |
| startProxy 创建阶段 | 15s |
| close_all | 8s |
| proxy.run 回收 | 500ms |
| Kotlin 单次尝试 | 60s |
| preConnect 单域 | 6s × 1 次 |
| 重试次数 | 3（backoff 0/1s/2s） |
