<p align="right">
  <b>简体中文</b> · <a href="README.md">English</a>
</p>

# NexaPipe

把位于 NAT 之后的 HTTP、HTTPS、WebSocket、TCP 与 UDP 服务，通过**一个**
[iroh](https://github.com/n0-computer/iroh) 端点暴露出去 —— **全程不持有证书、
没有控制平面、也不需要租任何服务器。**

一句话：**代理是一条管道，不是一个中间人。** 它读不到自己搬运的内容，不是你必须
信任的某个账号，也不租用别人的机器。代价见[为什么选择 NexaPipe](#为什么选择-nexapipe)。

NexaPipe 是一个 Rust workspace，由四部分组成：

- **`nexapipe`** —— 服务端：一个 L7 反向代理加一条 L4 隧道，通过 iroh/QUIC 接收
  流量并转发到真实后端；也可以直接提供明文 HTTP。TLS 不在这里终止：客户端的会话
  按 SNI 透传，而 `http` 模式里到 `https://` 后端的那一段是本进程作为客户端发起的
  TLS 会话，不是它终止的会话。
- **`nexapipe-client`** —— 客户端库：连接池、域名到节点的路由、本地 HTTP 代理，
  以及基于 smoltcp 的 TUN 代理。以 `rlib`、`cdylib`（Android JNI）和 UniFFI 绑定
  三种形式发布。
- **`nexapipe-proto`** —— L4 隧道的线格式：`0x05` 前导、状态字节与 UDP 分帧。
  零依赖，两侧共用同一份代码，因此不可能对格式产生分歧。
- **两个应用** —— Android 客户端（`ui-android`，TUN/VpnService）与桌面客户端
  （`ui-desktop`，Tauri 2 + Vue 3），都在本仓库内（从原先的独立仓库导入，完整保留
  了 git 历史）。

[工作原理](#工作原理) · [为什么选择](#为什么选择-nexapipe) ·
[嵌入你的应用](#嵌入你的应用) · [目录结构](#目录结构) ·
[快速开始](#快速开始服务端) · [命令行](#命令行) ·
[配置](#配置) · [最小配置](#最小配置) · [TLS](#tls) · [TCP 与 UDP](#tcp-与-udp) ·
[2FA](#2fa-totp) · [端点邀请码](#端点邀请码) ·
[安全边界](#安全边界) ·
[客户端库](#使用客户端库) · [客户端应用](#客户端应用) ·
[开发](#开发) · [贡献](CONTRIBUTING.md) · [路线图](docs/ROADMAP.md) ·
[变更日志](CHANGELOG.md) · [v0.6.1 发布说明](https://open-nexa.github.io/nexapipe/v0.6.1.html)

---

## 工作原理

```
   客户端                        nexapipe 服务端                     你的局域网 / 主机
   ───────                       ───────────────                     ───────────────
   任意 HTTP 客户端 ── TLS ───►  按 SNI 的 passthrough     ── TCP ──►  Caddy :443（证书）
   nexapipe-client  ── QUIC ──►  L7 路由（Host + path）    ── HTTP ──► 后端 A   后端 B
   （本地代理 / TUN）             L4 隧道（tcp / udp）                  :18080  :15432  :3478
```

一条内层 TCP 连接对应一条 QUIC 双向流。这条流承载什么，取决于谁打开了它：一个
HTTP 请求（或 WebSocket 升级）、一个 TLS 会话，或一条 L4 流 —— 裸 TCP 连接或
UDP 流。对于 HTTP，服务端按 `Host` 路由，与普通反向代理完全一致 —— NAT 穿透发生
在底层，对应用和后端都是透明的。

流的**首字节**决定由哪个处理器接手，因此四类流量从不需要靠猜测来区分：

| 首字节 | 处理器 | 章节 |
| --- | --- | --- |
| `0x16` | TLS `ClientHello` → 按 SNI 路由，以字节转发 | [TLS](#tls) |
| `0x05` | L4 前导 → 裸 TCP 或 UDP，发往指定后端 | [TCP 与 UDP](#tcp-与-udp) |
| 其他 | HTTP 请求 | 本页 |

---

## 为什么选择 NexaPipe

三个特性，以及各自的代价 —— 因为天下没有免费的午餐。

- **它永不终止 TLS。** `ClientHello` 按 SNI 匹配后原样复制字节，因此会话在访客与
  你的后端之间端到端运行。代价：不透明的管道无法改写路径、无法基于请求做决策、
  无法探测 `/health`，访问日志记录的是字节数而不是请求行。（`mode = "http"` 是
  例外 —— 那里代理确实会解析请求。见[安全边界](#安全边界)。）
- **没有控制平面。** 一个二进制加一份 `config.toml`；不用注册账号，没有协调服务器，
  也没有第三方掌握着你的节点清单。代价：没有中心化的设备列表、没有远程吊销、没有
  SSO —— 新增客户端意味着编辑配置（运行中的服务端会在数秒内拾取）。
- **没有什么需要租。** 客户端通过 QUIC 直接打洞连到你的端点。代价：打洞大约只对
  90–95% 的连接成功，其余回落中继，所以凡是要依赖的服务都应自建中继 —— 而一旦你
  无论如何都要维护一台公网机器，"不用租服务器"就不再是什么明显优势。

什么情况下不要用它：

- **你的访客无法安装任何东西** —— NexaPipe 需要客户端；托管隧道对任何浏览器都只
  提供一个普通 URL。
- **你需要 SSO、ACL 和审计日志** —— NexaPipe 只认证客户端身份，然后对它开放全部
  路由。
- **一条经过中继的连接不可接受** —— 请用带固定中间机的方案。

---

## 嵌入你的应用

客户端本身是一个库，所以你的应用无需调用外部程序就能访问私有网络 —— 以 `rlib`、
Android JNI 用的 `cdylib`，以及面向 Swift/Kotlin/Python 的 UniFFI 绑定三种形式
发布。见[使用客户端库](#使用客户端库)。

---

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `crates/nexapipe/` | 服务端二进制与库：CLI（`src/main.rs`）、配置、iroh 流处理（`src/conn/`）、HTTP/WebSocket 代理（`src/http/`、`src/proxy/`）、TLS 透传、L4 隧道（`src/l4/`）、路由（`src/routes/`、`src/lb/`）、健康检查、TOTP 2FA（`src/auth/`）。 |
| `crates/nexapipe-client/` | 客户端库（`lib` + `cdylib`）：连接池、域名→节点映射、本地代理、L4 客户端、smoltcp TUN 代理、QUIC 调优、JNI、UniFFI。 |
| `crates/nexapipe-proto/` | L4 线格式：`preface.rs` 与 `udp.rs`。零依赖，因此服务端与客户端都能链接它。 |
| `third_party/smoltcp` | 内置的 smoltcp 0.12，附带序列号下溢 panic 的补丁。通过 `[patch.crates-io]` 接入。不要改动。 |
| `ui-android/` | Android 应用（Kotlin + Compose）。 |
| `ui-desktop/` | Tauri 2 桌面应用（Vue 3 + TypeScript）。 |
| `config.toml.example` | 覆盖全部配置项的示例（服务端 + 客户端，2FA 关闭）。复制成 `config.toml` —— 该文件名已被 gitignore，它是运维者的实际配置。Docker compose 用的是 `config/config.toml`，通过 `NEXAPIPE_CONFIG_DIR=/app/config` 让二进制默认读取。 |
| `config.toml.2fa.example` | 同上，但启用 2FA 并带有 `[auth.clients]` 条目。 |
| `run_android.ps1` | 一键 Android 调试循环（构建 → 安装 → 启动 → logcat）。 |

---

## 快速开始（服务端）

```bash
cargo build --release -p nexapipe

cat > config.toml <<'EOF'               # config.toml 已被 gitignore；这就是一份完整的服务端配置
[[routes]]
host_pattern = "*"
backends = ["http://127.0.0.1:3000"]    # 你想暴露出去的服务
EOF

nexapipe                                # 默认读取 ./config.toml
```

三行就是一个能跑的服务端：一条全捕获路由、一个后端，其余配置全部取默认值。客户端
同样只需要几行，见[最小配置](#最小配置)（那里也列出了每个省略的键默认是什么）。
想要每个配置段都写出来的版本请从 `config.toml.example` 开始，想开启 2FA 则从
`config.toml.2fa.example` 开始。

完全不写这个文件也可以：服务端会自己生成一份最简的 `config.toml`，而不是直接拒绝启动 ——
2FA 开启、没有路由、没有 enrolled 客户端。它是一个供你编辑的起点，还不是能用的服务：

```bash
nexapipe                                # 生成 ./config.toml 并启动
```

在你修改之前，这份文件有两件事成立，且都是偏安全的方向：**没有路由**，所以所有 host
都会得到 404；**没有客户端**，所以在 `[auth] enabled = true` 的情况下谁都连不上。第一个
客户端这样创建：

```bash
nexapipe --generate-invite client-001 --create-client --config config.toml
```

已存在的配置永远不会被重新生成；已存在但解析失败的文件仍然会导致启动失败，而不是被替换掉。

启动时服务端会打印客户端需要的信息：

```
========================================
Proxy Connection Information
========================================
Node ID (stable, for server_node_id): 2f9c...
Ticket (for clients):                 endpoint:...
========================================
```

把 **Node ID**（稳定，但需要发现机制）或 **Ticket**（包含地址，地址变化时它也会变）
交给客户端。

**`[iroh] secret_key` 不需要你手动填。** 它缺失时，服务端会在首次启动时生成一个、
写回 `config.toml` 的 `[iroh]` 段，并从那时起一直使用它 —— 于是 Node ID 从第一次
运行起就是稳定的，无需任何复制粘贴：

```toml
[iroh]
# 由 nexapipe 在首次启动时写入；删掉这一行就会重新生成
secret_key = "8f2a…"
```

写回走的是和 2FA 命令同一条加锁 + 原子替换的路径，所以你的注释和其余配置都会保留。
这次写入在 Unix 上会把文件建成**私有**（`0600`），但权限不再被强制检查：
`0644` 的配置（Docker bind mount 往往就是这样）也能正常启动。代价是文件里的
凭据任何账号都能读到，所以要么保持文件私有，要么按下面的方式把密钥移出配置文件。

有两点值得知道：

- **写坏了的 `secret_key` 会拒绝启动。** 以前只是一条告警加一把临时身份，结果是每次
  重启 Node ID 都变，而日志看上去像是已经处理过了。删掉这一行让它重新生成，或者粘贴
  `--generate-secret` 的输出。
- **写不进去的配置文件仍然会启动**，只是用一把临时身份并给出告警 —— 只读挂载、或者文件
  属于另一个用户，都是很常见的部署方式，在那里拒绝启动比"每次重启都是新 Node ID"更糟。
  这时 Node ID 每次重启都会变。想主动要这个行为、并让服务端完全不碰你的文件，请设置
  `NEXAPIPE_NO_PERSIST_IDENTITY=1`。

Ticket 是另一回事：它固化的是打印时的那组地址，`secret_key` 拦不住它过期，端点搬家后
必须重新生成。想手工生成一把密钥（例如把身份搬到另一台机器）才需要：

```bash
cargo run -p nexapipe -- --generate-secret
```

**密钥也可以完全不放在 config.toml 里。** 把 `[iroh] secret_key_file` 指向一个只装
十六进制密钥的文件 —— 文件缺失时首次启动会自动生成写入（Unix 上 `0600`）；或者用环境
变量让它连文件都不沾：`NEXAPIPE_IROH_SECRET_KEY` 直接装密钥本身，
`NEXAPIPE_IROH_SECRET_KEY_FILE` 装*指向密钥文件的路径*（缺失时同样自动生成）。
密钥一旦来自配置之外，config.toml 就不再是凭据持有者，因此不必设为私有。但同一把
密钥只能有一个来源 —— 值和路径、环境变量和配置、其中之一和 `secret_key` —— 同时
命名多个会被拒绝启动，而不是静默挑一个。

### Docker

```bash
mkdir -p config secrets logs
cp config.toml.example config/config.toml   # config.toml 已被 gitignore
sudo chown -R 1000:1000 config secrets logs # 镜像以 uid 1000 运行
docker compose up -d --build
docker compose exec nexapipe tail -f /app/logs/nexapipe.log
```

`docker-compose.yaml` 挂载的是**目录** `config/`（你的 `config.toml` 就放在里面）、
存放端点身份的 `secrets/` 目录和一个 `logs/` 卷，并把 `NEXAPIPE_LOG_DIR` 指向
logs 卷。`secrets/` 挂载配合 `NEXAPIPE_IROH_SECRET_KEY_FILE=/app/secrets/iroh.key`
使用：端点密钥在首次启动时生成进这个文件（`0600`），因此 `config.toml` 本身不再
持有私钥。`secrets/` 请和 `config/` 一起备份 —— 丢了它意味着下次重启 Node ID 会变，
存过旧 Node ID 的客户端将找不到服务器。同时 compose 还设置
`NEXAPIPE_CONFIG_DIR=/app/config`，让容器里的二进制默认读取
`/app/config/config.toml`，与宿主机看到的 `config/config.toml` 是同一个文件。
`--config` 仍然优先生效，所以运维者随时可以指向任意路径。`host.docker.internal`
已配置好，因此运行在 Docker 宿主机上的后端可以被访问到。已有部署迁移过来只需一条：
`mkdir -p config && mv config.toml config/config.toml`。

镜像以 **uid 1000 运行，不是 root** —— 这个代理不需要特权，而一个从公网可达、
手里握着 2FA 种子和端点身份的服务器不该是 root。上面挂载的三个目录因此必须对该
uid 可写，这正是上面那条 `chown` 的作用：`mkdir` 建出的目录属于执行它的用户，恰好是
uid 1000 只是巧合。**从旧的 root 镜像升级**也要在首次启动前执行同一条命令，而且必须
加 `sudo` —— 旧镜像写下的文件属于 root：

```bash
sudo chown -R 1000:1000 config secrets logs
```

跳过这一步不一定立刻报错：新用户写不了 `config.toml` 会让每次 2FA 计数都更新失败，
而读不了 `iroh.key` 会被**重新生成** —— 那意味着新的 Node ID，存过旧 Node ID 的
客户端将找不到服务器。

镜像也已发布到 GHCR（`linux/amd64` 与 `linux/arm64`），名字与 `docker-compose.yaml`
本地构建的产物相同。想直接运行官方镜像而不是本地构建，先拉取，然后**不要**加 `--build`
启动 —— `--build` 会无视已有镜像，按 `Dockerfile` 重新构建：

```bash
docker pull ghcr.io/open-nexa/nexapipe:latest
docker compose up -d
```

想锁定版本而不是跟随最新版：把两处的 `:latest` 换成 `:0.6.1` 这样的标签，或者在
`docker-compose.override.yml` 里设置 `image:`，以免改动被版本跟踪的文件。`latest`
只跟随正式发布，预发布标签不会占用它。

#### 校验官方镜像

每个发布的镜像都带签名和来源证明（provenance attestation），所以"GHCR 上的镜像
确实是这个仓库构建出来的"是可以自己验证的事，而不是别人告诉你的一句话。签名密钥
由 GitHub 的 OIDC 在发布时临时签发，不落盘保存，也就无法从某个密钥库里被复制走。

```bash
cosign verify ghcr.io/open-nexa/nexapipe:latest \
    --certificate-identity-regexp 'https://github\.com/open-nexa/nexapipe/\.github/workflows/release\.yml@refs/tags/v.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

上面这条 identity 对应的是发布时所用的标签。手工重跑发布时，请把 workflow
dispatch 到标签本身（`Run workflow` 里选择该标签），而不是分支：从分支发起的
运行，证书 identity 是 `refs/heads/<branch>`，这条命令会有意拒绝它。

来源证明说明构建了什么、来自哪个源码版本，它按 digest 查询，而 digest 就是标签
实际指向的内容：

```bash
docker buildx imagetools inspect ghcr.io/open-nexa/nexapipe:latest
gh attestation verify oci://ghcr.io/open-nexa/nexapipe@sha256:<digest> \
    --repo open-nexa/nexapipe
```

这两步都不会改变你拉到的内容 —— 标签还是那个标签。它们是留给那些更愿意验证、
而不是更愿意相信的人的。

#### 修改配置文件

配置文件每 5 秒重新读取一次，改动无需重启 —— 但**凡是会写入这个文件的操作，
都建议在容器内执行**：

```bash
# 用镜像自带的二进制，操作服务端真正在读的那份文件
docker compose exec nexapipe /usr/local/bin/nexapipe \
    --config /app/config/config.toml --generate-invite client-001 --registration
```

在宿主机上直接对这个挂载文件执行同样的命令，问题出在这几处：

- **挂载必须是目录。** 单文件 bind mount 锁定的是容器启动时该路径对应的 inode，
  凡是"写临时文件再 rename"的操作 —— `sed -i`、开了 atomic save 的编辑器、`mv` ——
  都会让容器继续读那个被换走的文件：改动永远进不来，而且**不报任何错**。
  `docker compose restart` 也没用，它不重建挂载；要 `docker compose up -d --force-recreate`。
  compose 里写的 `./config:/app/config` 正是为此 —— 目录挂载每次按名字解析，
  永远看得到当前那个文件；改回 `./config.toml:/app/config/config.toml` 就又把坑请回来了。
- **两个写者，没有锁。** 服务端会重写整个文件，把 `pending_enrollment`
  登记进去。两边的每次写入都是无锁的"读—改—写"，宿主机上的编辑和服务端的落盘
  一旦重叠，就会丢掉其中一次。最坏的情况就是 `pending_enrollment` 令牌：服务端
  从不把它写回，所以输掉这次竞争等于白丢一个邀请码，日志里什么都不留。
  2FA 计数曾经也在这个名单里——每次 2FA 尝试，服务端都要重写整个文件来落盘
  `failed_attempts` / `locked_until` / `last_used`。它们现在住在服务端自己的
  `state.toml` 里，这场竞争也跟着一起没了。
- **宿主机的二进制不是服务端的二进制。** `--generate-invite` 的端点由
  `[iroh] secret_key` 推导，所以 `nexapipe` 若和正在跑的那个不是同一个提交编出来的，
  生成的邀请码会指向一个没人在跑的端点。（"宿主机那份配置缺这个键"曾经也是触发方式之一；
  现在服务端首次启动就会写一个进去，所以这个键总是有的。）
- **权限与属主会被改掉。** 从宿主机重写后，文件可能变成 `0644` 或换了属主：
  这不再阻止服务启动（配置文件权限已不再检查），但任何能读这个文件的账号都能
  拷走里面的凭据，所以应保持文件私有，或把凭据移到旁文件/环境变量。

挂载刻意是**可写**的：服务端会在首次启动时把 `[iroh] secret_key` 写进
`config.toml`，并在每次 2FA 尝试后把计数写回去 —— 挂成 `:ro` 会让锁定期失去持久化、
每次尝试都打一条错误日志，还会让 Node ID 每次重启都变。配置确实只能只读时，请设
`NEXAPIPE_NO_PERSIST_IDENTITY=1`，并在这种情况下手工写死 `[iroh] secret_key`，
至少让身份能保持稳定。

用编辑器改没问题，前提是**原地保存**（`vim` 的默认行为，以及 shell 的 `>`
重定向）。改什么都别假设生效了，去日志里确认一次：

```bash
docker compose logs -f --tail=50 nexapipe | grep -i reload
# Detected config change, reloading...  →  Config reloaded: 3 routes now live
# Config not reloaded, keeping the current routes: ... → 被拒绝，旧路由继续服务
```

### systemd

上面的命令都把服务端留在启动它的那个 shell 的前台。要作为服务运行，先装好二进制
并给它一个账号：

```bash
sudo install -m 0755 target/release/nexapipe /usr/local/bin/nexapipe
sudo useradd --system --shell /usr/sbin/nologin nexapipe
sudo mkdir -p /etc/nexapipe
sudo cp config.toml.example /etc/nexapipe/config.toml
sudo chown -R nexapipe:nexapipe /etc/nexapipe
sudo chmod 700 /etc/nexapipe
# 建议的加固，不再是启动的必要条件。
sudo chmod 600 /etc/nexapipe/config.toml
```

然后写 `/etc/systemd/system/nexapipe.service`：

```ini
[Unit]
Description=NexaPipe server
Documentation=https://github.com/open-nexa/nexapipe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nexapipe
Group=nexapipe
ExecStart=/usr/local/bin/nexapipe --config /etc/nexapipe/config.toml
Restart=on-failure
RestartSec=5s

# 只在文件存在时读取：前面的 `-` 就是「可选」的意思。除
# NEXAPIPE_LOG_DIR 和 NEXAPIPE_MAX_CONNS_PER_PEER 外，iroh 密钥和 relay
# token 也可以从环境变量或旁文件提供，所以只读配置不必携带凭据。
EnvironmentFile=-/etc/nexapipe/nexapipe.env

# ProtectSystem=strict 之下，除这里列出的路径外全部只读。配置目录必须可写，
# 原因见下面第二条。
ReadWritePaths=/etc/nexapipe
LogsDirectory=nexapipe

# 只有 [server] listen_addr 低于 1024 才需要。隧道不占特权端口，而 2FA 开启时
# 非回环监听会被拒绝，所以多数部署这两行都保持注释。
#AmbientCapabilities=CAP_NET_BIND_SERVICE
#CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectProc=invisible
# 带上 AF_UNIX 是因为 backends 里的主机名仍走 C 库的解析器，某些配置下它要连
# 本地套接字：没被列进来的协议族不是一条警告，而是解析失败。
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nexapipe
sudo systemctl status nexapipe
journalctl -u nexapipe -f
```

**用具名账号，而不是 `DynamicUser=yes`。** 这个进程在 `/etc/nexapipe` 下拥有
文件——它要重写的配置，以及首次启动时写在配置旁边的令牌——而动态用户是给「除
systemd 替它建的目录外什么都不拥有」的服务准备的：那个 UID 只为一次启动分配，
之后可能交给另一个服务，所以 systemd 会把 `StateDirectory`、`CacheDirectory`
和 `LogsDirectory` 自行挪到别处。`/etc` 下的凭据文件不在这三者之中。

**配置目录必须保持可写。** 服务端会把已注册设备的密钥写回 `config.toml`，
并在首次启动时在旁边写出 `config.toml.admin-token`。2FA 的计数
（`failed_attempts`、`locked_until`、`last_used`）落在旁边的 `state.toml` 里 ——
那个文件归服务端自己所有，配置不会因为它被重写。首次启动时服务端也会写配置
这个文件 —— 配置里没有 `[iroh] secret_key` 就会补上：所以即使从不注册客户端，目录
也必须可写，否则 Node ID 每次重启都会变。`ReadWritePaths` 只放开这一个目录。
想在不可写的配置下运行，请设 `NEXAPIPE_NO_PERSIST_IDENTITY=1`，代价是 Node ID
无法跨重启保持。

**建议每次改完保持 `0600`、属主 `nexapipe`，但不再强制。** 配置文件权限已
不再检查，所以 `0644` 也能启动；但配置里若带 `[auth]` 密钥、
`[iroh] secret_key` 或 `relay_auth_token`，任何账号都能读走这些凭据。更好的
做法是把它们放进旁文件（仍强制 `0600`）或环境变量。用 root 编辑是最常见的
丢法：改成 `sudo -u nexapipe $EDITOR /etc/nexapipe/config.toml`，或者事后
`chown` + `chmod`。

**改配置不需要 reload。** 文件每 5 秒重读一次；对没有 `ExecReload` 的 unit
执行 `systemctl reload` 只会得到一条警告，什么也不会发生。拒绝错误改动也是
watcher 的职责：解析不了的改动会被记录下来，而已经在服务的路由继续服务。

另有两件与 systemd 无关的事。**打开隧道的 UDP 端口**——设置 `[iroh] bind_port`，
否则端点用的是临时端口，没有端口可写规则。以及 **用能读令牌文件的账号执行
`nexapipe status`**，因为它是从那里读令牌的：

```bash
sudo -u nexapipe nexapipe --config /etc/nexapipe/config.toml status
```

`[log]` 的文件日志与 journal 是两回事，`dir` 默认是相对工作目录的 `./logs`，
而 systemd 下的工作目录是 `/`——所以默认值指向一个该服务建不出来的目录。这不致
命：stderr 上一行，这一次启动没有文件日志。把它指到 unit 拥有的目录：

```toml
[log]
dir = "/var/log/nexapipe"      # 上面的 LogsDirectory=nexapipe 会创建并属主化
```

**上面的 unit 没有在本项目的 CI 里跑过**——`docs/self-hosted-relay.md` 对
relay 那份也是同样的声明。这些指令不是同一时期引入的，systemd 遇到不认识的指令
只是在 journal 里写一行，不会拒绝启动：`ProtectProc=invisible` 需要 247，
`StateDirectory=` 及其所在的 `*Directory=` 一族需要 235，`ProtectSystem=strict`
需要 232。更旧的系统上 unit 照样起来，只是读不懂的保护项静默缺失，
`systemd-analyze verify` 会把它们点出来。

---

## 命令行

| 参数 | 说明 |
| --- | --- |
| `-c, --config <PATH>` | 配置文件（默认 `./config.toml`；`NEXAPIPE_CONFIG_DIR` 可调整）。 |
| `--local-proxy` | 以客户端本地 HTTP 代理运行，而非服务端。 |
| `--generate-secret` | 打印一个新的 iroh 密钥。通常不需要 —— 服务端会在首次启动时自行写入 `[iroh] secret_key`；这条命令用于把身份搬到另一台机器。 |
| `--generate-2fa <CLIENT_ID>` | 生成 TOTP 密钥，写入配置并打印注册用二维码。 |
| `--force` | 配合 `--generate-2fa`：轮换已有客户端的密钥。 |
| `--show-2fa <CLIENT_ID>` | 打印已存在于 `[auth.clients]` 中客户端的二维码。 |
| `--issuer <NAME>` | 认证器应用显示的签发者标签。 |
| `--qr-format <FMT>` | `unicode`（默认）、`plain`、`ascii`、`svg`、`none`。 |
| `--qr-invert` | 反色绘制二维码（深底浅色）。 |
| `--qr-out <PATH>` | 同时把二维码写入文件（`.svg` → SVG，其他 → ASCII）。 |
| `--generate-invite [CLIENT_ID]` | 打印可扫描的 `nexapipe://` 邀请码。带 `CLIENT_ID` 时把 2FA 密钥也放进去；不带时只携带端点与域名。 |
| `--registration` | 配合 `--generate-invite CLIENT_ID`：用一次性注册令牌代替密钥。 |
| `--create-client` | 配合 `--generate-invite CLIENT_ID`：客户端尚不存在时创建它，并在同一次运行中生成并写入其密钥。 |
| `--invite-domains <LIST>` | 邀请码中的域名，逗号分隔（默认：`[local_proxy] proxy_domains`，否则取路由主机名）。 |
| `--invite-name <NAME>` | 与端点一同保存的标签。 |
| `--invite-relay <URL>` | 邀请码中的中继 URL（默认：`[iroh] relay_url`）。 |
| `--endpoint-id <NODE_ID>` | 要对外公布的端点（默认：由 `[iroh] secret_key` 推导）。 |

### `nexapipe client`

管理接口的"写"那一半，以子命令而不是 `POST /v1/clients` 的形式提供：admin token
是一个没有作用域、也没有轮换机制的不透明值，让它能改东西，等于把一个只读接口变成
进入凭据库的入口。每个子命令都在服务端所用的同一把锁下编辑配置文件，运行中的服务
端会在下一次重载时读到改动。

| 命令 | 说明 |
| --- | --- |
| `client list [--json]` | 列出 `[auth.clients]` 中的客户端及其设备。**不打印任何密钥** —— 那件事由 `--show-2fa` 负责。 |
| `client add <CLIENT_ID>` | 签发凭据：写入客户端自己的 `secret`，也就是"未命名设备"所用的那个凭据。已存在时拒绝替换，除非带 `--force`。 |
| `client add <CLIENT_ID> --device <NAME>` | 给单个设备签发凭据，客户端自己的 `secret` 不动 —— 因此已经在用它的设备继续可用。客户端必须先存在。 |
| `client add <CLIENT_ID> --device <NAME> --public-key <HEX>` | 签发**设备密钥**而不是 `secret`：一对 Ed25519 密钥的公钥半边（64 位十六进制）。设备用自己保管的私钥半边为每条质询签名，服务端用这里登记的公钥验证那个签名。不写入任何 `secret`，也无从打印 —— 因为根本没有。见[设备密钥](#设备密钥)。 |
| `client revoke <CLIENT_ID>` | 删除一个客户端及其下所有设备凭据。 |
| `client revoke <CLIENT_ID> --device <NAME>` | 只删除某一个设备的凭据，保留客户端和它的其他设备。 |

```bash
nexapipe client list --config config.toml
nexapipe client add laptop-1 --device laptop --config config.toml
nexapipe client revoke laptop-1 --device laptop --config config.toml
```

吊销是删除而不是改写，因为"条目不存在"正是握手时读作"这个设备没有凭据"的那一
种状态 —— 和一个从未注册过的设备得到的答案相同，所以从外部分不出它经历过什么。

这些命令读写的，是客户端自己的 `secret` 旁边那张 `devices` 表：

```toml
[auth.clients.client-001]
secret = "JBSWY3DPEHPK3PXP"        # 未命名设备所用的那个凭据

[auth.clients.client-001.devices.laptop]
secret = "MFRGGZDFMZTWQ2LK"        # 注册时签发，可单独吊销
created_at = "1723756800"
```

服务端按对端请求的是哪一个来校验：报了名字的设备查自己的条目，没报名字的查客户端的
`secret`。两者都不必手写 —— 注册会自己把设备归档，`client add --device` 则从命令行
签发 —— 一个没有 `devices` 表的客户端，行为与这张表出现之前完全一致。设备也可以
持有设备密钥而不是 `secret` —— 见[设备密钥](#设备密钥)。

---

## 配置

`config.toml` 是服务端与客户端模式的唯一事实来源。所有配置项都是可选的。

文件每 5 秒重新读取一次并**即时生效**：`[[routes]]` 与
`[auth.clients]` 表无需重启；解析或校验失败的配置会被报告并忽略，因此一次只写了一
半的编辑不会把代理搞 down。其余配置在启动时只读取一次，需要重启：
`[server] listen_addr`、`[iroh]`、`[peers]`、`[auth]` 的 TOTP 参数，以及 `[log]`。

`[auth]` 这一段也可以在原本没有的情况下出现：启动时没有该段的服务端，同样会在后续
重载时拾取它的 `clients` 与 `enabled = true`，因此第一次开启 2FA 不需要重启。

有两处改动在运行中的服务端上被刻意做成单向的：`[auth] enabled = true` 会被配置
监视器拾取，但把 2FA 关掉会被拒绝（要禁用请重启）；而 `enabled = true` 与暴露的明文
监听器同时出现则直接被拒绝启动。

### 配置与状态是两个文件

`config.toml` 是运维者的文件：他写的、他读的、他放进版本控制的。而运行中的服务端
学到的东西——某个客户端输错几次密码、锁到什么时候、最后一次出现是什么时候——
不属于这一类，所以它们住在配置**旁边**的 `state.toml` 里，格式相同，客户端与设备
的名字也相同。

```
/etc/nexapipe/
├── config.toml     运维者的文件
├── state.toml      服务端的计数（0600，由服务端写入）
└── config.toml.admin-token
```

状态文件由服务端写，除此之外没有别人写它；配置也不会为了这些计数被重写。这个
分离不只是为了整洁：服务端会盯着配置文件的修改时间，所以一个把计数写回配置的
服务端，会让每一次输错密码都变成一次配置重载——路由重建、健康检查重启，原因
仅仅是陌生人输错了密码。

不需要任何配置。状态文件在客户端第一次输错密码或认证成功时出现，权限是 `0600`。
读不了的状态文件会让服务端拒绝启动：它记着的那些锁状态将无人知晓，硬着头皮启动
等于把每一个都清零。想不要这些锁，删掉它就行。

在状态文件出现之前写的配置依然可用：那三个计数字段仍然从配置里读，所以一直在
那里计数的部署会保住自己的锁，直到状态文件里有了这个客户端的条目为止。它们不再
被写回配置。

### 最小配置

一份完整的**服务端**配置 —— 一条全捕获 `http` 路由指向一个后端：

```toml
[[routes]]
host_pattern = "*"
backends = ["http://127.0.0.1:3000"]
```

一份完整的**客户端**配置（`nexapipe --local-proxy`），把 `127.0.0.1:8081` 变成
一个只隧道转发所列域名的 HTTP 代理：

```toml
[local_proxy]
enabled = true
listen_addr = "127.0.0.1:8081"
proxy_domains = ["app.example.com"]

[[local_proxy.nodes]]
server_node_id = "<服务端打印出来的 Node ID>"
domains = ["app.example.com"]
```

简写省略了什么，以及对应的默认值：

| 省略的键 | 得到的行为 |
| --- | --- |
| `[server] listen_addr` | 不监听明文端口 —— 流量只能经由 iroh 进来 |
| `[iroh] secret_key` | 稳定的 Node ID；不填的话首次启动会自动生成并写进配置。想要旧行为（每次重启都是新 Node ID、且不碰配置文件）请设`NEXAPIPE_NO_PERSIST_IDENTITY=1` |
| `[iroh] relay_mode` | `default`：使用 N0 中继，按延迟挑选 home relay |
| `mode` | `http` |
| `path_pattern` | `/`，前缀匹配 —— 前缀止于路径段边界，因此 `/api` 覆盖 `/api/x`，不覆盖 `/apifoo` |
| `strategy` | `round_robin`（或 `random`，或 `least_conn` —— 优先给当前在途请求最少的后端） |
| `[health_check]` | 开启：每 10 秒 `GET {backend}/health`。后端没有这个端点时会被记为失败，但**只有一个后端的路由仍然照常转发** —— 那里没有第二个可挑的选项 —— 所以那只是日志噪音，不是故障；有多个后端且全部不健康时，直接回 503 且不再拨号。设 `enabled = false` 即可消停。 |
| `[log]` | `./logs` 下的滚动日志 + 控制台输出，查询参数值会被脱敏 |
| `[auth]`、`[peers]` | 不做任何认证 —— 启动时服务端会打印一条警告横幅。本机试用没问题；要拿去面对真正在意的服务时，至少加上 `[peers] allow`（或 2FA）。 |

本节之后的所有内容都是可选的。只有两个键不是：一条路由必须有 `host_pattern` 和
`backends`，一个 `[local_proxy]` 段必须有 `listen_addr` 和 `proxy_domains`。

### 顶层

`debug`（默认 `false`）开启调试日志。

**没有回落。** 没有任何路由的主机，HTTP 请求得到 404，`passthrough`、`tcp`、`udp`
查找则直接拒绝。"把所有请求都发到这里"写成一条全捕获路由 —— `host_pattern = "*"` ——
它和其它路由一样具备负载均衡与健康检查。旧的顶层 `default_backend` 已**移除**：仍然
写着它的配置会在启动时被拒绝，而不是被静默忽略，这样已有配置不会在无人察觉的情况下
从"转发"变成"404"。

通配符只有两种写法：单独的 `*`，或以 `*.` 开头。那个点是标签边界 —— 少了它，
`*.example.com` 会连 `notexample.com` 一起匹配，而后一个域名只是恰好以同样的字母
结尾，属于别人。`*example.com` 这类写法会在启动时被拒绝，`host_pattern` 与客户端的
`allow_hosts` 一视同仁。

**客户端的域名列表用同样的拼写**，所以一份模式可以从一个列表直接抄到另一个：
`app.example.com` 就是那个名字本身，`*.example.com` 是它的子域名而不含名字本身，
`*` 是所有名字。过去两边并不一致 —— 客户端把一个裸域名读成"名字本身加上它的所有
子域名"，而服务端只读成名字本身 —— 于是客户端放进隧道的子域名，是一个服务端根本没有
路由的名字，失败看起来像是隧道坏了。仍带着旧列表的客户端会在启动时的日志里说一次。

### `[server]` —— 直接入口（默认关闭）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `listen_addr` | *未设置 —— 不绑定* | 明文 HTTP 监听器。对该地址发起的 TLS 会话会被透传，而非终止。 |
| `expose` | `false` | `listen_addr` 要指定回环以外的地址时必须为 true。当 `[auth] enabled = true` 时启动会被拒绝。 |

**这个监听器上的任何流量都不经过认证**：2FA 握手运行在 iroh 的 accept 循环里，所以
从这里到达的请求在从未被要求出示凭证的情况下就能抵达路由。不设置 `listen_addr`
（默认值）或保持绑定在 `127.0.0.1`，只用于本机内部；绑定非回环地址还需要
`expose = true`，那会把每一条 `http` 路由和每一个 `passthrough` 后端都暴露给任何能
访问该端口的人。`expose = true` 与 `[auth] enabled = true` 同时出现时**启动会被
拒绝** —— 开着 2FA 时，这个组合读起来像受保护的代理，实际并不是。（旧版本只记一条
警告就照常启动。）

与隧道路径的一个差异：**WebSocket 升级在 iroh 上会被正常代理，在这里则返回
`426 Upgrade Required`** —— 该监听器没有 WebSocket 客户端。需要 WebSocket 的客户端
必须走隧道。

`tls_enabled`、`tls_listen_addr`、`cert_path` 与 `key_path` 仍被接受以便已有的
`config.toml` 能解析，但不再有任何作用，并会在启动时报告 —— 请删除它们并参见
[TLS](#tls)。

### `[iroh]` —— 隧道端点

| 配置项 | 说明 |
| --- | --- |
| `secret_key` | 可选。不填的话服务端会在首次启动时生成一个写进这里，Node ID 无需手动配置即可保持稳定。只有想把身份搬到另一台机器、或配置文件写不进去时才需要手动设置。无法解析的值会拒绝启动。 |
| `bind_port` | 固定 UDP 端口，而非临时端口。 |
| `bind_ipv6` | 同时在该端口上绑定 `[::]`，使端点也能通过 IPv6 应答。IPv4 套接字保留 —— 这是**增加一个**，不是替换；且 IPv6 绑定允许失败，没有 IPv6 的主机仍能启动。未设置 `bind_port` 时此项无效。 |
| `relay_mode` | `pinned` / `default` / `disabled` / `custom`。缺省即 `default`。 |
| `relay_url` | `relay_mode = "custom"` 时使用的中继；只设置它而不设 `relay_mode` 等同于 `custom`。 |
| `relay_auth_token` | 需要鉴权的 `custom` 中继所用的可选 bearer token。 |
| `discovery` | `n0` / `none`。不写即 `n0`。`none` 关掉"把 Node ID 变成地址"的那次查询，于是本端点不会有任何东西到达 `dns.iroh.link` —— 代价是单凭 Node ID 不再能连到它（地址要靠票据带过来）。写了却拼不出来会直接拒绝启动。 |

中继模式：

- **`default`** —— 使用所有 N0 中继，按延迟选择归属中继。它可能在中继之间迁移，
  迁移会切断经由该中继的连接。
- **`pinned`** —— 固定使用一个 N0 中继（`aps1-1`，新加坡）。当中继迁移比稍慢的中继
  更难受时用它。
- **`disabled`** —— 完全不使用中继传输。这比听上去更强：你也无法通过*对端*的中继
  拨号。
- **`custom`** —— 一个你自己运行的中继，且**只用它**：既不作为归属中继，也不作为
  探测目标。把它指向 `*.relay.n0.iroh.link` 形式的 URL 会被拒绝；那类地址请用
  `pinned` 或 `default`。这个模式的另一半 —— 先把那台中继跑起来 —— 写在
  [自建中继](docs/self-hosted-relay.md)。

写了 `relay_mode` 但不可用 —— 例如 `custom` 却没有 URL，或拼写无法识别 —— 会直接
阻止启动，而不是悄悄回落。在不接受 `relay_url` 的模式旁写了 `relay_url` 会被忽略
并记日志。

**还有两个开关把这事做完。** `relay_mode` 管的是中继；Endpoint ID 发现 —— 也就是
把 Node ID 变成"该往哪儿发 QUIC 包"的那次查询 —— 是另一个开关 `discovery = "none"`，
它才是让查询不去 `dns.iroh.link` 的东西。`custom` 客户端还会拒绝经由别人的中继
去拨号对端，所以带着地址的对端只会经由你自己的中继被找到。只凭 Node ID 的对端仍然
需要那次查询才能被找到，所以只要端点仍可能向 n0 询问它在哪里，它就会被拨号 ——
而一旦关掉查询，它会被直接拒绝。
[仍然依赖第三方基础设施的部分](docs/iroh-boundaries.md)
完整写明了这条边界，包括这两个开关各自买到了什么、没买到什么。

### `[[routes]]` —— 路由

```toml
[[routes]]
host_pattern = "comfyui.example.com"
path_pattern = "/"
path_is_prefix = true
strategy = "round_robin"          # 或 "random" / "least_conn"
backends = ["http://192.0.2.20:18188"]
mode = "http"                     # 默认
# path_rewrite = "/api"
# backend_protocol = "h2c"        # 明文 HTTP/2；见下文

[[routes]]
host_pattern = "app.example.com"
mode = "passthrough"              # TLS，按 SNI 路由；见下文 TLS
backends = ["caddy:443"]

[[routes]]
host_pattern = "db.example.com"   # 裸 TCP 服务，任意端口
mode = "tcp"
backends = ["192.0.2.30:15432"]

[[routes]]
host_pattern = "turn.example.com"
mode = "udp"                      # UDP 流，空闲超时以秒计
backends = ["192.0.2.40:13478"]
idle_timeout_secs = 60

# 同一个主机既要应答请求又要承载隧道 —— Android TUN 客户端的常见形态。
# `modes` 可写多个；`mode` 只写一个。
[[routes]]
host_pattern = "app.example.com"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal:18080"]
```

| 模式 | 作用 | 传输安全 |
| --- | --- | --- |
| `http`（默认） | 解析请求，应用 `path_pattern` / `path_rewrite`，然后用共享的 HTTP 客户端重新发起。后端可以是 `http://` 或 `https://`；后者由服务端主动发起并校验 TLS 会话 —— 服务端仍然不持有证书、也不终止任何会话。 | 入口段由 QUIC 加密；服务端到后端这一段，`http://` 后端是**明文 HTTP**，`https://` 后端是 **TLS**。 |
| `passthrough` | 复制字节。路由由 SNI 选择，因此 `path_pattern` 与 `path_rewrite` 不适用，后端也可以是裸 `host:port`。 | 端到端：字节是 TLS，服务端从不终止它，因此客户端校验的是后端自己的证书。见 [TLS](#tls)。 |
| `tcp` | 把裸 TCP 流送到 `backends`，由 L4 前导中的主机名选择。不做 HTTP 解析，不适用 `path_pattern`；通过连接来探测。见 [TCP 与 UDP](#tcp-与-udp)。 | 到服务端为止由 QUIC 加密；之后是隧穿协议的原始字节 —— TLS、SSH 或任何东西都由你自己提供。 |
| `udp` | 承载 UDP 流 —— 每条流一条 QUIC 双向流，每个数据报一帧。选择方式同 `tcp`，另有 `idle_timeout_secs`。 | 到服务端为止由 QUIC 加密；载荷安全由隧穿协议负责（DTLS、WireGuard 等）。 |

没有任何模式会为客户端终止 TLS：从服务端到 `backends` 这一段，加密程度取决于你放上
去的东西，只有 `passthrough` 能让客户端的 TLS 会话一直完整地抵达后端。`http` 模式
里的 `https://` 后端是**本进程作为客户端发起**的 TLS 会话，不是它作为服务端终止的
会话：后端证书按系统根证书加上 `[backends] ca_file` 校验。

`backend_protocol` 只描述到后端这一段。不写时，明文后端用 HTTP/1.1，`https://` 后端
在它支持时通过 ALPN 协商到 HTTP/2。`backend_protocol = "h2c"` 用于带 prior knowledge
的明文 HTTP/2 后端；它与 `https://` 后端一起写会被拒绝 —— 后者通过握手协商 h2。
WebSocket 升级是 HTTP/1.1：`https://` 后端会走 TLS，而 `backend_protocol = "h2c"` 的
路由会明确拒绝 WebSocket，而不是把 HTTP/1.1 升级请求发给一个期待 h2 的后端。

一条路由用 `mode = "..."` 提供**一种**模式，用 `modes = [...]` 提供**多种**模式；
两者可以同时写，路由提供的是并集，重复项会被合并。一条*连接*用哪种模式，仍然由它的
首字节决定，所以一条连接只会走一条路径。

共享同一份 `backends` 列表的代价是：该地址必须同时满足所有声明的模式，而 L4 的规则
更严格 —— **端口必须写出来**（`http://host` 单独用于 `http` 没问题，隐含 80 端口；
一旦加上 `tcp` 就会被拒绝）。一条路由只有一个后端池，所以不同模式需要不同后端时请
写成两条条目。

已移除但仍能解析并被忽略（启动时报告）的路由配置项：`cert_path`、`key_path` 与
`redirect_to_https`。

### `[health_check]` —— 探测 http 后端

```toml
[health_check]
enabled = true     # 默认 true —— 后端无法应答探测时改成 false
interval = 10      # 两轮检查之间的秒数
timeout = 5        # 单次检查超时秒数
threshold = 3      # 连续失败多少次后该后端离开后端池
path = "/health"   # 追加到后端 URL 之后
```

每个 `mode = "http"` 的后端都会被 `GET {backend}{path}` 探测，**连续**失败
`threshold` 次后离开后端池 —— 单次失败永远不会摘除它 —— 第一次探测成功即恢复。
`passthrough` 或 `tcp` 路由通过连接来探测（`passthrough` 会完成 TLS 握手），这只说明
有进程在监听，不说明它能正常工作。只承载 `udp` 的路由不探测：没有可连接的目标，而
编造一个数据报的探测只会报告后端从未给出的回答。

**当你的后端无法提供健康检查端点时，请设 `enabled = false`** —— 静态文件服务器、
设备管理的 Web UI。关闭后所有后端都留在池里、流量照常转发。`enabled` 是热生效的：
重载配置会暂停已经在跑的检查；其余四个键在检查器启动时读取，改动需要重启，或对重载
中出现的新路由立即生效。

`interval`、`timeout`、`threshold` 都至少为 `1`：写 `0` 过去会被静默改成 `1`，而三者
各自的含义都不是任何人想要的 —— 每秒一轮探测、永远无法完成的探测、或一次失败就摘空
后端池。写 `0` 的配置在加载时会被拒绝。

### `[backends]` —— 如何连接 `https://` 后端

```toml
[backends]
ca_file = "/etc/nexapipe/internal-ca.pem"   # 可选
```

`https://` 后端的证书会按机器自己的信任库加上 `ca_file` 中的 PEM 证书校验。这个文件
是**追加**到系统根证书上的，不会替换它们。这里故意没有跳过校验的开关：一个不知道
自己在和谁说话就建立连接的反向代理，任何能应答该名字的人都能把它重定向。机器上
没有可用系统根证书时（例如没有安装 `ca-certificates` 的容器），会回落到 Mozilla
内置根证书，并在日志里说明。

同一份信任库同时用于 HTTP 请求和 WebSocket 升级。到 `https://` 后端的 HTTP/2 通过
ALPN 协商，不需要额外配置。这一段只在启动时读取一次，改动需要重启。

### `[retry]` —— 失败请求的重试

```toml
[retry]
attempts = 2       # 首次尝试之后的额外次数；默认 0（关闭）
backoff_ms = 100   # 两次尝试之间的等待；默认 100
```

重试会向路由要一个**不同的**后端，因为刚刚失败的那个最可能再次失败。只有单个后端
的路由没有别人可问，只能再问它一次。明文监听器和 iroh 隧道的流式路径使用同一套规则。

哪些失败可以重试，取决于失败发生在哪一步：

- **没有到达后端**的请求 —— 连接被拒绝、域名解析失败、TLS 握手失败 —— 无论什么
  方法都可以重试。后端根本没看到它。
- **已经送到后端、随后丢失**的请求，只有幂等方法才能重试。`GET`、`HEAD`、`PUT`、
  `DELETE`、`OPTIONS`、`TRACE` 是；一个会扣款的 `POST` 不是。

已经拿到的应答不会被重试，客户端已经开始接收的响应也不会。WebSocket 是一段会话，
从不重试。`attempts` 是额外尝试次数（2 表示最多三次），上限 16；`backoff_ms` 上限
60000。这一段只在启动时读取一次。

### `[circuit_breaker]` —— 持续失败的后端离开轮转

```toml
[circuit_breaker]
enabled = true          # 默认 true
failure_threshold = 5   # 连续失败多少次后离开；默认 5
reset_secs = 30         # 离开多久；默认 30
```

当 HTTP 请求路径连续看到 `failure_threshold` 次“后端不可达”的失败后，这个后端就不再
被选中。它离开轮转期间，如果一条路由没有任何可服务的后端，会直接回 503，而不是花掉
一整个连接超时去重新确认流量已经证明的事实。`reset_secs` 之后会给它一次试探请求；
一次应答会关闭熔断并把失败计数归零。

健康探测说明的是“上一次有人问它时它什么样”，熔断说明的是“流量自己发现了什么”。
两者回答不同问题，并且同时运行。响应传到一半断掉不算失败 —— 后端已经应答了。计数器
覆盖 HTTP 请求路径，包括隧道的流式路径与 WebSocket 握手；WebSocket 升级成功之后会话
断掉不算。`tcp` 与 `udp` 路由没有请求失败可计，仍然依赖健康探测。`failure_threshold`
上限 1000，`reset_secs` 上限 3600。这一段只在启动时读取一次。

### `[timeouts]` —— 等待后端的时间，以及每个阶段的期限

```toml
[timeouts]
connect_secs = 10        # 默认：10 —— 拨号连接后端的上限秒数
response_secs = 30       # 默认：30 —— 等待后端应答的上限秒数
header_secs = 30         # 默认：30 —— 客户端发完请求头的上限秒数
body_secs = 300          # 默认：300 —— 客户端发完请求体的上限秒数
response_idle_secs = 120 # 默认：120 —— 响应块之间允许的静默秒数
l4_flow_secs = 3600      # 默认：3600 —— 一条 L4 隧道的完整寿命
l4_idle_secs = 60        # 默认：60 —— UDP 数据报之间允许的静默秒数
tls_hello_secs = 10      # 默认：10 —— 读取 TLS ClientHello 的上限秒数
```

所有键的单位都是秒、都可以不写，默认值就是服务端一直以来的行为，所以写上这一段但
什么都不填，什么都不会改变。前两个键只覆盖「与后端打交道的某一步」，**不限制一次
请求能持续多久**：响应头一到，之后的响应体要传多久都不受它们约束。

| 键 | 约束的是什么 | 何时调大 |
| --- | --- | --- |
| `connect_secs` | 拨号。所有「朝一个后端开一条连接」的路径都用它：HTTP 请求（包括 WebSocket 升级）、TLS passthrough 与 `tcp` 隧道。 | 后端在慢链路或丢包严重的链路上 —— 太小会让每个请求都失败，而且表现得像后端挂了。 |
| `response_secs` | 等待后端的应答：状态行；对 WebSocket 而言是升级响应。响应头一到就结束。 | 后端需要先把结果算出来才回答。它同时也是「后端接受连接后一句话不说」这种情况的上限。 |
| `header_secs` | 请求头整个读取过程的阶段期限：开始时取一次、之后不再续期 —— 每到期的前一秒滴一个字节的客户端续不了它。在明文监听器上，它覆盖的是「等到请求头」这整段时间，包含区分 TLS 会话与请求的那一次试探。 | 慢链路上的客户端也要发很大的请求头；它就是「滴漏客户端永远占着一个槽」的解药。 |
| `body_secs` | 请求体整个读取过程的阶段期限；与请求头分开，因为一次大上传本来就该比请求头久。 | 上传又大又慢，而不想把请求头的期限一起拉长时。 |
| `response_idle_secs` | 是空闲超时、不是阶段期限：响应块之间的间隔，每个块到达都会重新计时，在所有转发响应的路径上都一样。SSE 流和长传输可以一直开着，而发了响应头就沉默的后端占不住槽。 | 后端流式输出时块与块之间的间隔本来就长。 |
| `l4_flow_secs` | 一条 L4 隧道（TCP 与 UDP 皆然）的完整寿命的阶段期限 —— 流没有协议层面的结束，这是唯一能挡住对端无限续期的东西。 | 隧道上跑长期存活的 SSH 或数据库会话。路由自己的 `flow_timeout_secs` 可以只覆盖那一条路由。 |
| `l4_idle_secs` | 两个方向上 UDP 数据报之间的空闲上限。 | 某条 UDP 流的数据报之间确实会静默超过一分钟。 |
| `tls_hello_secs` | 读取 TLS `ClientHello` 的阶段期限；过去它完全没有超时。等「这个会话的首字节」的时间取它与 `header_secs` 的较长者，两个监听器都是如此 —— 首字节到达之前协议未知，所以调小 `header_secs` 不该掐断 TLS 会话。 | 慢链路上的客户端一个字节一个字节地发握手。 |

所有键写 `0` 都会在加载时被拒绝，超过 `86400`（一天）同样如此：前者会让被约束的阶段
一打开就关闭，后者是一个永远不会触发的期限。两个后端键的上限更紧，是 `3600`。

一条流的首字节决定它说的是什么协议，而首字节到达之前协议是未知的 —— 所以等它的时间
取 `header_secs` 与 `tls_hello_secs` 中较长者，绝不会只用请求头那一个。因此调小
`header_secs` 不会掐断 TLS 会话或 L4 隧道：两者都不发请求头，各自由自己的键约束。

这些键都在启动时读取一次，改动需要重启。

### `[limits]` —— 整个进程运行时的上限

```toml
[limits]
max_connections_per_peer = 64         # 默认：64 —— 单个对端同时持有的连接数
max_connections_global = 4096         # 默认：4096 —— 所有对端合计的连接数
max_streams_global = 16384            # 默认：16384 —— 在途的流
max_body_bytes = 1073741824           # 默认：1 GiB —— 同时持有的请求体字节
```

所有键都可以不写，默认值就是服务端一直以来的上限，所以写上这一段但什么都不填，什么都
不会改变。

其中两个键回答的是同一个问题的不同尺度，缺一不可。对端 ID 是一把公钥，调用方想造多少
就能造多少：单对端上限挡住一个对端持有成千上万条连接，全局上限挡住**进程**被「有多少个
对端存在」这件事挤爆。两者谁也替代不了谁。`max_streams_global` 是同一个道理往下一层
—— 每条连接都能开出自己的额度，而总量同样是「有多少个对端存在」的乘积。
`max_body_bytes` 约束的是内存：请求体在转发之前是整个读进来的，所以「每个请求 64 MB」
站得住，「每个请求 64 MB 乘以所有在途的流」站不住。

**约束的是哪条路径。** 三个连接与流的上限是记在 **iroh 隧道**上的，因为「对端」只存在于
那里：它们约束的是隧道进来的客户端能占用多少。明文监听器（`[server] listen_addr`）没有
对端可记，也没有自己的上限 —— 它接一条连接就服务一条。`max_body_bytes` 是例外：请求体
由两个监听器共用的同一个读取器读入，所以字节预算对明文监听器同样生效。

所有键写 `0` 都会在启动时被拒绝：上限为 0 会拒掉所有连接，而不是给连接设上限，这属于笔误
而不是配置，而配置文件是运维能读到错误信息的地方。**即使对应的环境变量有值也照样拒绝**
—— 环境变量覆盖的是一个「能用」的值，不是一个「不能用」的值；被环境变量挡住的笔误，要等到
哪天那个变量被撤掉才会露出来。**不认识的键则在加载时就被拒绝**，服务端根本起不来 ——
拼错的限额就是一个静默不生效的限额，进程于是会跑在一个没人写下过的上限里。

生效的上限会在启动时打印出来：

```
Accepting at most 64 concurrent connections per peer, 4096 across the process, 16384 streams across the process, 1073741824 bytes of request bodies across the process
```

在 `[limits]` 出现之前就用来指定这些上限的四个环境变量 ——
`NEXAPIPE_MAX_CONNS_PER_PEER`、`NEXAPIPE_MAX_CONNS`、`NEXAPIPE_MAX_STREAMS`、
`NEXAPIPE_MAX_BODY_BYTES` —— 仍然有效，而且**环境变量优先于配置**：它是运维最后设置
的东西，在容器里往往也是唯一能设置的东西。两边都写了同一个键时，日志里会告警而不是
拒绝启动，所以这种歧义是可见的，而不是无声的。环境变量里用不了的值 —— `0`，或者根本
不是数字 —— 会被忽略并改用默认值，因为 Dockerfile 里一个写坏的环境变量不该让服务端起
不来。

这些键都在启动时读取一次，改动需要重启：在上传进行到一半时改动预算，会让它按一个它从
未被计入的上限来归还字节。

### `[admin]` —— 辅助监听（默认关闭）

```toml
[admin]
listen_addr = "127.0.0.1:9090"   # 不写 => 完全不绑定这个监听

[metrics]
enabled = true                   # 在该监听上提供 /metrics；默认 false
```

第二个监听，回答的是**本实例自身**的问题，而不转发流量：

| 路径 | 认证 | 用途 |
|---|---|---|
| `GET /healthz` | 无 | 只要进程还在服务就返回 `200 ok`。 |
| `GET /metrics` | 无 | Prometheus 文本格式的实例指标，仅在 `[metrics] enabled = true` 时提供。 |
| `GET /v1/status` | token | 运行时长、计数器、后端健康度、各项开关。 |
| `GET /v1/routes` | token | 当前生效的路由表 —— 即最后一次重载之后的内容。 |
| `GET /v1/clients` | token | 有哪些客户端。绝不含它们的密钥。 |
| `GET /v1/connections` | token | 当前连接着的对端。 |
| `GET /v1/health` | token | 后端池，在/不在轮转中。 |

命令行下用 **`nexapipe status`** 读，除配置外无需参数：

```bash
nexapipe status --config config.toml          # 分组输出，给人看
nexapipe status --config config.toml --json   # 单个 JSON 文档，给脚本看
```

它问的是正在运行的进程，而不是重新打开配置文件，所以打印出来的是**已加载**的内容
—— 包括启动之后任何一次重载改动过的部分。

**token 是生成的，不是配置的。** 首次启动时服务端把它写进 `<config>.admin-token`，
权限为仅运行服务的账户可读，并在日志里说明位置。配置里**故意没有** `token` 键：那会
把凭据放进一个你会编辑、复制、提交的文件里，而且回写它会触发监听配置文件 mtime 的
重载。`nexapipe status` 读同一个文件，且绝不创建它 —— 它自己造的 token 服务端并不
认识。要轮换就删掉文件再重启。

`/v1/*` 只回答问题，别的什么也不做。增删凭据走上面的 `nexapipe client add` 与
`client revoke`，它们在服务端所用的同一把锁下编辑这个接口所读的那份配置。admin
token 是一个没有作用域、也没有轮换机制的不透明值，不该被赋予写权限——一个只回答
问题的接口，是没法被说服去改动任何东西的。

`[metrics] enabled` 默认是关的，因为它所依附的监听没有认证：必须**同时**开启它
并绑定地址，才会有东西暴露出来。只开 `enabled` 而没有 `[admin]` 段会记一条警告且
不提供任何内容。监听已起但指标关闭时，`/metrics` 返回 **404 而不是空** —— 指向一个
从未开启指标的部署的采集器，必须能区分"没开"和"还没流量"。

**只允许 loopback，且没有 `expose` 开关。** `[server] expose` 存在是因为明文监听可能
位于另一个做鉴权的组件之后；而这个监听上的任何内容都不该从网络可达 —— 它会说出你的
路由、客户端和后端。绑定非 loopback 地址会在启动时被拒绝。要从别的主机采集，用隧道
（`ssh -L 9090:127.0.0.1:9090 …`）。

**`listen_addr` 不支持热重载** —— 迁移监听等同于重启。这两段里的其余键都只在启动时
读取一次。

完整的重载规则见[重载会应用哪些配置](#重载会应用哪些配置)。

`/metrics` 报告的内容：连接数（累计、当前，以及按路径是直连还是中继分）、按状态码
分类的请求数与耗时毫秒、按协议和状态分类的 L4 流、在/不在轮转中的后端数、仍在处理的
连接数，以及运行时长。后端健康度在渲染页面时从活动的后端池读取，所以重载配置改动了
后端池会在下一次采集时体现。请求与流是分开计的，这是有意的：一条 L4 流是一条想开多久
就开多久的隧道，把它算作请求会把两种不同单位塞进同一个数字。

### `[local_proxy]` —— 客户端模式

```toml
[local_proxy]
enabled = true
listen_addr = "127.0.0.1:8081"
expose = false
proxy_domains = ["app.example.com"]
strategy = "round_robin"

[[local_proxy.nodes]]
server_node_id = ""               # 服务端的稳定 Node ID
domains = ["app.example.com"]
```

同一个域名可以出现在多个节点上，这正是跨多台服务器做负载均衡的方式。
`[local_proxy]` 层级的 `server_ticket` 与 `server_node_id` 仍然可用但已废弃 ——
优先使用 `[[local_proxy.nodes]]`。

`[local_proxy]` 下的 `strategy` 取 `round_robin`（默认）或 `random`。它是在本地代理
持有的**服务器**之间挑选，而 `least_conn` —— 服务端自己的策略，挑的是某条路由中
在途请求最少的后端 —— 不在其中；本地代理遇到它会拒绝启动，而不是悄悄换成别的
均衡方式。

**本地代理不校验连接方**：它直接交出那条已经完成认证的连接的隧道，
因此任何能连上该端口的一方都能在没有凭据的情况下拿到隧道。所以
`listen_addr` 必须写回环地址，非回环地址在启动时会被拒绝 —— 判定依据是
套接字实际绑定的地址，因此 `0.0.0.0` 与 `[::]` 同样会被拦下。
`expose = true` 是显式选择开启，用于端口前面另有防护的部署场景 ——
防火墙、容器网络 —— 含义与 `[server] expose` 相同。

### `[peers]` —— 允许哪些 Node ID 连接

这是最先执行的一道检查：在 QUIC 握手期间、连接被接受之前生效的客户端公钥
白名单。名单外的对端只会收到一个应用错误码为 `5` 的关闭帧，此外什么都没有 ——
不打开任何流，也不占用任何配额。

```toml
[peers]
# 客户端的 Node ID，与应用中显示的完全一致。没有通配符形式：
# 这些是 ed25519 公钥，不是主机名。
allow = [
  "a1b2c3d4e5f6...",
  "0f1e2d3c4b5a...",
]
```

它不是第二重因子，也不替代 2FA：它回答的是*这个 Node ID 是否该出现在这里*，
而 2FA 回答的是*它是谁* —— 所以它是给关闭了 2FA 的服务端准备的开关，两者
可以叠加使用。

- **缺省或省略该键** —— 任何能连到端点的对端都继续进入下一道检查。
- **写错会在启动时失败** —— 不是合法 Node ID 的条目是错误，不会被静默跳过。
- **`allow = []` 会被拒绝** —— 那会把运维者自己锁在服务端之外。
- **目前仅启动时读取**，与 `[iroh]` 一样。

### `[log]`

轮转日志文件加控制台输出。`file`、`dir`、`file_name`、`access_log`、
`rotation`（`daily` / `hourly` / `never`）、`max_size_mb`、`max_files`、
`console`、`redact_query`。`NEXAPIPE_LOG_DIR` 会覆盖 `dir`。

`redact_query`（默认 `true`）会替换访问日志查询串中的取值，保留参数名 —— 令牌、
签名和一次性验证码都在查询参数的值里传递，而日志文件会被轮转、归档并转手。没有
`=` 的参数（`?raw`）是一个标志位，保持原样；路径不处理。设置
`redact_query = false` 可原样记录 URI。

```text
/api/v1/items?token=hunter2&page=2   ->   /api/v1/items?token=<redacted>&page=<redacted>
```

**每个请求都有一个 id。** 32 位十六进制，追加在该请求的访问日志行末尾，并作为
`x-request-id` 返回给客户端 —— 谁要报一个异常的响应，就能直接指出对应的那一行：

```text
203.0.113.9 - - [29/Sep/2026:13:52:04 +0800] "GET /api/v1/items" 200 512 12ms id=3f9ac1…
```

同一个 id 也是包裹该请求的 `request` span 上的一个字段，因此 `tracing` 的输出里
也带着它，连同 `method`、`uri`、`status`。L4 流量与 TLS 透传是隧道而非请求：它们
的 id 出现在访问日志与 span 上，但没有 HTTP 响应可供加头。

**一行日志还说得出这个请求是谁的。** 该连接认证出的客户端与设备追加在行尾，前面的
每一列都不动：

```text
203.0.113.9 - - [29/Sep/2026:13:52:04 +0800] "GET /api/v1/items" 200 512 12ms id=3f9ac1… client=acme device=laptop
```

认证通过但没报名字的设备记作 `device=-` —— 它用的是客户端自己的那个 secret，也就
是该客户端所有未命名设备共用的同一个。从未认证的请求两个字段都没有：关掉 2FA、以及
明文 HTTP 监听器，都不跑握手；让每一行都用 `-` 来回答"这是谁的请求"只是噪音，不是
答案。

**隧道里的流会说自己是什么。** 一条 L4 流携带的是字节，因此它那一行记录的是隧道对
这些字节做了什么。当一条流的头几个字节已经说明了这条流是什么时，行尾会多出相应
的字段 —— TLS 握手请求的名字，或者明文 HTTP 交换的请求行与状态码：

```text
203.0.113.9 - - [29/Sep/2026:13:52:04 +0800] "TCP db.test:5432" 200 0 12ms id=3f9ac1… sni=www.example.com
203.0.113.9 - - [29/Sep/2026:13:52:05 +0800] "TCP api.test:80" 200 0 12ms id=3f9ac1… http="GET /v1/items HTTP/1.1" http_status=404
```

状态列仍然是隧道自己的结果 —— `200` 说的是这条流走通了，不管它背后的源站答了什么
—— 所以读这一列的脚本读到的还是以前读到的那个东西。嗅探到的目标里若带查询串，同样
按其它 URI 的规则脱敏；一条什么也认不出来（SSH、数据库协议）的流则不加字段，而不是
猜一个。

### `[acme]`

已移除。证书现在归后端所有；该配置节仍能解析但会被忽略，并在启动时报告。
见 [TLS](#tls)。

### 重载会应用哪些配置

配置文件被监视，改动无需重启即可生效 —— 但不是每个键都可以。与其把这条规则散落在
上面各节里，这里汇总成一张表：

| 键 | 重载时 |
|---|---|
| `[[routes]]` | 生效。后端会被重新探测；已建立的连接保留其授权时所用的路由。 |
| `[auth]` | 生效，含 `enabled` —— 打开 2FA 会开始对重载之后新建的连接生效。配置文件权限已不再检查；请保持文件私有或把密钥移出。 |
| `[health_check]` | 生效。`enabled` 暂停/恢复探测；其余键对重载新增或改动的路由生效。 |
| `[backends]`、`[retry]`、`[circuit_breaker]` | 需重启：启动时读取一次，与 `[timeouts]` 同理。 |
| `[timeouts]` | 需重启：启动时读取一次，与 `[server] listen_addr` 同理。 |
| `[limits]` | 需重启：启动时读取一次，与 `[timeouts]` 同理。 |
| `[peers] allow` | 目前需重启。 |
| `[iroh]` | 需重启：端点只绑定一次。 |
| `[server] listen_addr` | 需重启 —— 迁移监听等同于重启。 |
| `[admin] listen_addr` | 需重启，原因同上。其余部分是实时的：`/v1/*` 每次请求都读当前的路由、客户端与后端池。 |
| `[metrics] enabled` | 需重启，只在启动时读取一次。 |
| `[log]`、`[local_proxy]` | 需重启。 |

被拒绝的重载会继续用旧配置服务，并在日志里说明原因，所以一个拼写错误不会让正在工作
的实例下线。

---

## TLS

TLS 由**后端**终止，而不是本代理：代理不持有任何证书，也永远看不到一个 `https://`
请求的明文。它唯一主动发起的 TLS 会话，是 `http` 模式中到 `https://` 后端那一段的
客户端一侧 —— 这仍然不是它终止的会话，它也不为任何客户端持有证书。

1. 客户端照常发起 TLS 会话 —— 经由本地 HTTP 代理、TUN，或直接连到
   `[server] listen_addr`。
2. 代理识别出 `ClientHello`：它的首字节是 `0x16`，任何 HTTP 请求都不可能以它开头。
3. SNI 与 `mode = "passthrough"` 路由匹配，该会话的每一个字节都被复制到那条路由的
   后端。

全程不解密，所以 WebSocket、gRPC 与 HTTP/2 都不需要改动即可工作。经 `CONNECT` 或
TUN 到达的 TLS 会话走的是另一条路径：客户端用 L4 前导声明 host 与 port，而不是交出
`ClientHello`，因此它匹配的是 `mode = "tcp"` 路由。所以，一个你希望两种方式都能访问
的域名需要**两种**模式 —— 写成两条条目，或写成一条带
`modes = ["passthrough", "tcp"]` 的条目（当同一个后端同时服务两者时）。见
[TCP 与 UDP](#tcp-与-udp)。

### Caddy

把一条 passthrough 路由指向 Caddy，让 Caddy 持有证书：

```toml
[[routes]]
host_pattern = "app.example.com"
mode = "passthrough"
backends = ["caddy:443"]          # 或 "https://caddy:443"，scheme 会被忽略
```

```caddyfile
{
	email you@example.com
}

*.example.com {
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
	@app   host app.example.com
	@comfy host comfyui.example.com
	reverse_proxy @app   http://host.docker.internal:18080
	reverse_proxy @comfy http://192.0.2.20:18188
}
```

请使用 **DNS-01** 质询：被代理的域名在隧道内部解析为一个回环地址，因此入站的
`HTTP-01` 请求永远到不了 Caddy —— 而 DNS-01 还意味着 Caddy 不需要公网 IP。像
`*.example.com` 这样的通配符让新增子域名不再有成本。官方的 `caddy` 镜像不附带任何
DNS provider：用 `xcaddy` 或 `-builder` 镜像把
`github.com/caddy-dns/cloudflare` 构建进去。

### passthrough 的代价

passthrough 路由是不透明的，因此访问日志记录的是字节数而不是请求行，`/health`
探测不适用，代理也无法改写路径或把 `http://` 重定向到 `https://`。这些工作交给
Caddy，它能看到解密后的请求。普通的 `http://` 路由保留全部能力。

---

## TCP 与 UDP

数据库线协议、MQTT 或 STUN socket、游戏服务器 —— 它们都不说 HTTP 或 TLS，而 UDP
根本不携带主机名，所以无法通过读取载荷字节来路由。L4 隧道也不读取载荷：客户端把
一段**前导**写在双向流的开头，服务端恰好回复一个字节的状态码。它只属于 **iroh**
入口路径 —— 明文 `[server] listen_addr` 监听器对 `0x05` 一无所知：

```text
client → server   0x05  version=0x01  proto(0x01 tcp | 0x02 udp)  len  host  port(u16-be)
server → client   status   0x00 ok       0x01 no route        0x02 backend failed
                           0x03 too many flows                0x04 bad preface
```

`0x05` 既不会开启一个 HTTP 请求，也不会开启一条 TLS 记录，所以三个处理器只差一个
`if` —— 见[工作原理](#工作原理)。在收到 `0x00` 之后：

- **TCP** —— 双向原始字节，与 TLS passthrough 路径完全一致。
- **UDP** —— 每条流一条 QUIC 双向流，数据报以 `u16` 长度前缀分帧，因为字节流本身
  没有消息边界。双向都静默达到 `idle_timeout_secs`（默认 60）的流会被关闭。

### 由服务端决定拨号目标

客户端指定**主机与端口**；由路由决定拨号到哪个地址，而 `backends` 是地址唯一出现
的地方 —— 因此持有有效 2FA 凭证的客户端也无法把服务端当作开放中继使用。L4 查找
**永不回落**：没有 `tcp`/`udp` 路由的主机是一次调用方可以据此行动的拒绝，而不是
一条被悄悄转发到别处的流。

### `client_ports`

一个可选的选择器 —— 路由服务哪些端口 —— 而不是目标：

```toml
[[routes]]
host_pattern = "db.example.com"
mode = "tcp"
backends = ["192.0.2.30:15432"]
client_ports = [15432, 16432]       # 这条路由应答的端口
```

它只决定*哪条*路由与一条流匹配，因此同一个主机可以在不同端口上有 `tcp` 路由、指向
不同后端。不写 `client_ports` 时，所有端口都匹配。

同一主机上两条路由都能匹配一条流时，**写了 `client_ports` 的那条胜出**（胜过"收所有
端口"的那条）。没有这个优先级规则时，先声明的路由会永久胜出、后写的那条永远匹配不上，
与书写顺序无关地失效。

### 代价

L4 流是不透明的：代理不解析它们，因此没有健康检查，也没有路径改写。访问日志会记录
隧道对它们做了什么 —— 而且，当一条流的头几个字节已经说明了这条流是什么时，日志会
一并说明：TLS 握手请求的名字，或者明文 HTTP 交换的请求行与状态码。这只是读了一遍
客户端自己的字节，不做别的事：路由在前言里就定下了，早于任何一个载荷字节到达，所以
日志里写下的任何东西都不可能指向与实际服务这条流的后端不同的后端。

并发按 QUIC 连接计上限 —— 打开过多流的客户端会收到 `0x03 too many flows`。因为一条 UDP
流就是一条双向流，一个 TUN 设备可能同时持有数百条；见[QUIC 调优](#quic-调优)中的
`NEXAPIPE_QUIC_MAX_BIDI_STREAMS`。

### 哪些客户端可以用

| 客户端 | TCP | UDP |
| --- | --- | --- |
| 本地 HTTP 代理（`--local-proxy`、桌面端） | `CONNECT host:port` | — |
| Android TUN | 任意端口 | 任意端口 |
| 桌面 TUN | 任意端口 | — |

TUN 交给应用程序的是**每个域名一个虚拟地址**（Android 上从 `198.18.0.16+` 起，
桌面端从 `198.18.0.2+` 起 —— 具体地址由隧道认领的地址段决定，而两端从同一份候选
列表里挑这一段），所以目的地*就是*域名。全程不做任何嗅探，这正是 UDP 得以可行的
原因。两个地址族都会应答（AAAA 取自 `fd00:198:18::10+`，一个 VPN 自己路由的 ULA
段），因此通过 IPv6 解析出来的名字和通过 IPv4 解析的一样可路由 —— 唯一例外是桌面端
TUN 的网卡拒绝了 IPv6 地址的情况，此时 AAAA 应答为空，解析器回落到 A。

注意这隐含的路由模式：TUN 发往某个域名的流量以 L4 形式到达，所以该域名需要一条
`tcp`（或 `udp`）路由 —— **即使是 80 端口上的明文 HTTP**，因为 TUN 交出的是 IP
报文，客户端在前导里声明主机与端口。因此，一个 TUN 要访问 HTTPS 服务时，是把
`tcp` 路由指向会说 TLS 的后端（`backends = ["caddy:443"]`，与 [TLS 透传](#caddy)
用的是同一个 Caddy，只是明确写出了端口）；`mode = "passthrough"` 保留给那些直接向
代理自身地址发起 `ClientHello` 的客户端。如果同一个后端既要应答 TUN 又要应答普通
请求，在一条条目里用 `modes = ["http", "tcp"]` 说明。

---

## 2FA (TOTP)

当 `[auth] enabled = true` 时，每一条客户端连接都必须在任何流量被代理之前证明
自己的凭证 —— 对 TOTP 是以响应应答，对用密钥注册的设备则是就这条连接的质询
签名（见下文[设备密钥](#设备密钥)）。先讲 TOTP 这一半。

1. 生成密钥与可扫描的二维码。密钥会随打印一同写入 `config.toml` 的
   `[auth.clients]`，所以第 2 步只是把 2FA 打开：

   ```bash
   cargo run -p nexapipe -- --generate-2fa client-001 --qr-format unicode
   ```

2. 确认服务端配置里 `[auth]` 是打开的。该命令会为你添加
   `[auth.clients.client-001]`，但绝不擅自翻转 `enabled` —— 那个开关影响每一个
   客户端，所以由你自己来拨：

   ```toml
   [auth]
   enabled = true
   algorithm = "sha1"      # sha1 | sha256 | sha512
   time_step = 30
   digits = 6
   window = 1
   max_attempts = 5
   lockout_duration = 300

   [auth.clients.client-001]     # 由 --generate-2fa 写入
   secret = "JBSWY3DPEHPK3PXP"
   ```

3. 在客户端上，要么在应用里扫描二维码，要么在 `[local_proxy.two_factor]` 里设置
   凭证：

   ```toml
   [local_proxy.two_factor]
   enabled = true
   client_id = "client-001"
   secret = "JBSWY3DPEHPK3PXP"
   algorithm = "sha1"
   ```

新增和变更的 `[auth.clients]` 条目会被配置监视器即时拾取，新增客户端无需重启；
`[auth] enabled = true` 同样即时生效（对重载之后新建的连接）—— 启动时完全没有
`[auth]` 段的服务端也是如此。TOTP 参数
（`algorithm`、`time_step`、`digits`）在启动时只读取一次，需要重启。见
`config.toml.2fa.example`。

这些密钥是**唯一**把守 iroh 监听器的凭证。配置文件权限已不再强制——`0644`
也能启动——所以保持 `config.toml` 私有（仍建议 `chmod 600 config.toml`）是
运维自己的责任，或者把凭据移到旁文件（`secret_key_file`、
`relay_auth_token_file`、`config.toml.admin-token`）或环境变量
（`NEXAPIPE_IROH_SECRET_KEY`、`NEXAPIPE_IROH_SECRET_KEY_FILE`、
`NEXAPIPE_RELAY_AUTH_TOKEN`）。旁文件本身仍强制 `0600`，否则拒绝加载。没有凭证的
客户端面对要求凭证的服务端同样会被拒绝：QUIC 握手成功，而服务端在握手期限（5 秒）内
没有收到 `AUTH_START` 时会关闭连接。

二维码携带的是标准 `otpauth://` URI，所以任何认证器应用都能导入：

```text
otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP&issuer=NexaPipe&algorithm=SHA1&digits=6&period=30
```

- 在 `[auth]` 下设置 `issuer` 可改变应用显示的标签；`--issuer` 可覆盖单次运行的
  取值。两者默认都是 `NexaPipe`。
- `--show-2fa CLIENT_ID` 可以再次打印已配置客户端的二维码，用于另一台设备。
- 对一个已有密钥的客户端执行 `--generate-2fa` 会打印**那个**密钥而不是生成新的。
  加上 `--force` 可轮换它：所有用旧密钥注册过的设备都必须重新扫描。
- 写入是就地编辑 `config.toml`，保留注释与格式。如果文件无法读取或写入，密钥只会
  被打印出来。
- `algorithm`、`time_step` 与 `digits` 是在*生成二维码*时读取的，而不是扫描时 ——
  设备注册完成后请保持它们稳定。
- **密钥才是凭证，不是那六位数字。** 服务端在查看验证码*之前*先校验响应签名（以
  密钥为密钥的 HMAC-SHA256；用设备密钥注册的设备则是同一段字节上的 Ed25519
  签名）。任何带 `secret=` 的 `nexapipe://` 邀请码与注册二维码都以**明文**携带它
  —— 把两者都当作密码对待（`--qr-out` 在 Unix 上以 `0600` 写入）。

### 设备密钥

设备不一定非要持有共享 `secret`。为一台具名设备登记一对 Ed25519 密钥的**公钥**
半边，私钥半边在设备上生成、从不外送，它就是那台设备用来证明自己的东西：

```bash
nexapipe client add client-001 --device phone --public-key <64 位十六进制> \
  --config config.toml
```

从那以后，这台设备对每一条连接的应答方式是**签名**那条质询（nonce 与时间戳），
而不是回一个验证码；服务端用它持有的公钥验证签名。由此带来三件事：

- **服务端持有的东西无法被重放。** 抄走 `config.toml` 换不来*以那台设备身份*进入
  的方式；而抄走一个 `secret` 就等于抄走了凭证本身。但这不等于完全进不来：文件里
  仍然留着客户端自己的 `secret`，在设成 `unnamed_device_allowed = false` 之前，它
  对任何不报设备名的 peer 都有效。私钥半边从不离开设备，注册时也不例外。
- **连接时不需要任何东西从别处来** —— 握手不依赖存放的种子，也不需要生成验证
  码 —— 这正是无人值守的设备（服务、探针、提权助手）所需要的：没有任何要人去
  应答的提示。
- **错误签名与错误验证码一样计入锁定**，所以密钥设备无法被无限尝试；时间戳
  过期则依旧被拒绝且不计入。

一个设备条目只携带**一种**凭证 —— `secret` 或 `public_key`，不可兼有，且二者
必居其一：两者都在、或两者都无的配置会在加载时被拒绝，而不是在两份凭证之间
被悄悄挑一个。设备是不是基于密钥，由这条条目而非线上协议决定，所以所有仍用
`secret` 的设备，握手与过去逐字节相同；在这一切出现之前写下的配置也照旧加载、
照旧工作。`client list` 会把密钥设备标注为 `key`，`client revoke <id> --device
<name>` 对它与其他设备一视同仁地吊销。

注册也可以签发密钥：基于客户端库构建的客户端可以在花掉一次性令牌时报出一个
公钥（库把它暴露为 `Enrollment::with_key`），服务端记录它并以空的 `secret`
作为应答，此后每条握手都以签名送出（`TwoFactorAuth::with_key`）。属于人的
那一刻仍然留在原处 —— 扫一次邀请码、花掉令牌 —— 所以 TOTP 是注册时的人因，
而不是每条连接上的一个提示。

**两个应用现在正是这样做的。** 一份 v=2 注册邀请码 —— 携带一次性令牌而非
`secret` 的那一种 —— 会在桌面端和 Android 上都用设备自己的密钥完成注册，
全程不问用户任何问题：私钥半边在设备上生成，与其他凭据一道密封存放，
且从不离开本机；公钥半边则是服务端记录下来的那一个，也是应用显示出来的那一个，
因此你能看清服务端上挂着的是哪把密钥。早于密钥机制的服务端会忽略这个提议、
照旧签发 `secret`，所以同一份邀请码对两者都管用；而已经持有 TOTP 密钥的节点
保持原样。邀请码的格式没有变：这是由邀请码的种类决定的，不是由你选了什么决定的。

---

## 端点邀请码

一个二维码可以携带整份客户端配置 —— 端点、域名和 2FA —— 因此注册一台手机是扫一下，
而不是手输三个字段：

```bash
cargo run -p nexapipe -- --generate-invite client-001 --qr-format unicode
```

```text
nexapipe://endpoint/a612…7063?v=1&name=Home&domains=app.example.com,comfyui.example.com
    &relay=https://relay.example&client=client-001&issuer=NexaPipe
    &secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30
```

| 部分 | 含义 |
| --- | --- |
| `endpoint/<node-id>` | 要拨号的端点。`ticket/<ticket>` 则携带一个完整的端点 ticket。 |
| `domains` | 逗号分隔；客户端只代理这些名字。 |
| `name` | 客户端列表中显示的标签。 |
| `relay` | 中继 URL，用于无法直连的端点。 |
| `client` + `secret`/`algorithm`/`digits`/`period` | 2FA 凭证 —— 仅在你传入 `CLIENT_ID` 时出现。 |
| `otpauth` | 上述六个参数的替代形式：一整条 `otpauth://` URI，在扁平形式缺失时使用。 |

不带 `CLIENT_ID` 时，邀请码只携带端点与其域名，别无其他。域名默认取
`[local_proxy] proxy_domains`，其次取 `[[routes]]` 的主机名；端点默认取
`[iroh] secret_key` 的公钥，因此二维码在重启后依然有效。可用
`--invite-domains`、`--invite-name`、`--invite-relay`、`--endpoint-id` 覆盖其中
任何一项。

- 客户端会**忽略它不认识的参数**，因此较新的服务端可以增加字段而不破坏旧版应用。
  严格的是 `v`（必须是 `1` 或 `2`）与 `algorithm` —— 未知的名字是错误，绝不静默
  回落到 SHA1。
- 让二维码保持在约 400 字符以内，以便扫描；超出时命令会给出警告。
- **终端可能把一个完好的二维码画坏。** `unicode` 渲染用半块字符（`▀▄█`）把**两行模块
  压进一行文本**，这只有在终端行高等于字形高度时才成立。带额外行距的终端会把每行字形
  画得比它的格位矮，中间留下空白缝隙。这些缝隙横贯整个码面，扫描器看到的是一摞互不相连
  的横条：数据没坏，但行同步丢了，识别随之失败。链接本身是好的 —— 和二维码下方打印出来的
  是同一条。见 [二维码扫不出来](#二维码扫不出来)。
- 带 `secret=` 的邀请码是**明文密码**，它的二维码渲染同样如此 —— 任何扫到它的人都
  持有该客户端的凭证。
- **吊销曾经等于全部轮换。** 删除 `[auth.clients.client-001]` 这一段，或者
  `--generate-2fa client-001 --force`，仍然会连该客户端下所有已注册设备一起带走。
  报了名字的设备现在可以单独吊销，其余设备不受影响：见
  [`nexapipe client`](#nexapipe-client)。
- 两种吊销都只作用于**之后建立的连接**：握手里拿到的授权是当时的快照，已经通过认证的
  连接会一直用到它自己结束，轮换或删除都不会把它掐断。要立刻断开，重启服务端。

### 二维码扫不出来

一个码在这台机器上能扫、在那台上不能，几乎从来不是链接的问题，而是**终端把它画坏了**。
`unicode` 渲染用半块字符（`▀`、`▄`、`█`）把**两行模块压进一行文本**，所以只有当终端行高
正好等于字形高度时，码面才是连续的。带额外行距的终端会把每行字形画得比它的格位矮，
中间留下一条空白缝隙。这些缝隙横贯整个码面，于是扫描器看到的是一摞互不相连的横条：
数据完好，但行同步丢失，识别失败。

**识别特征：** 你看着打印出来的码完全正常，而同一条链接换个地方就能扫。对截图量一下即可
确认 —— 在码面中部取一条水平扫描线，会看到墨色与白色严格等距交替，而可扫描的二维码没有
这种周期性。

这个问题在 **macOS 终端**上最突出，因为行距大于 1.0 很常见：Terminal.app
（设置 → 配置文件 → 文本）与 iTerm2（Settings → Profiles → Text → Line Spacing）
默认都带有会撑开缝隙的留白。Windows Terminal 的行高等于字形高度，所以同一个码在那里
能扫 —— 最常见的报告正是"同一个 SSH，Windows 上好好的，Mac 上扫不出来"。

按合适的顺序挑一个办法：

1. **把行距设为 1.0。** Terminal.app：设置 → 配置文件 → 文本 → 行距 `1.0`。
   iTerm2：Settings → Profiles → Text → Line Spacing `1.0`。下一次
   `--generate-invite` 打印出来就是连续的。
2. **把二维码写到文件。** `--qr-out invite.svg` 生成像素精确的 SVG，任何终端设置都
   无法扭曲它 —— 用浏览器或预览打开后扫。这在改不了终端时是最佳选择，比如共享会话
   或跳板机。
3. **改用 `--qr-format ascii`。** 每个模块占两个字符宽，符号完全不依赖半块字形的度量。

三条都试过还扫不出来，那就要怀疑链接本身：直接粘贴到客户端的"添加端点"对话框里，
绕开终端。

### 邀请一个尚不存在的客户端（`--create-client`）

`--generate-invite CLIENT_ID` 交出的是某个客户端*已经拥有*的密钥，因此不在
`[auth.clients]` 中的 `CLIENT_ID` 会被拒绝。`--create-client` 把"创建"与"邀请"合为
一次运行 —— 密钥被生成、写入配置并放进邀请码：

```bash
cargo run -p nexapipe -- --generate-invite client-001 --create-client
cargo run -p nexapipe -- --generate-invite client-001 --create-client --registration
```

- **它绝不触碰已存在的客户端。** 对已配置的客户端运行会复用已存的密钥，而不是再生
  成一个 —— 后者会让所有已用第一个密钥注册的设备全部被锁在外面。轮换仍然是显式的
  `--generate-2fa CLIENT_ID --force`。
- **它只补全完全缺失的客户端。** 一个存在但没有 `secret` 的 `[auth.clients.x]` 段
  是坏文件，不是一个待填的空白。
- **它不是独立的"添加客户端"命令** —— 它要求配合 `--generate-invite`，因此密钥只会
  作为即将被交出去的邀请码的一部分而被创建。

由于新密钥是写入 `config.toml` 的，请记住 TOTP 参数在启动时只读取一次：添加到
`[auth.clients]` 下的客户端会被自行拾取（文件每 5 秒被重新读取一次），但改动
`algorithm`、`time_step` 或 `digits` 仍需重启。

### 注册邀请码（`--registration`）

上面那个码的问题在于：只要密钥还在，它就一直是凭证。`--registration` 改为在链接中
放入一个**一次性注册令牌**：

```bash
cargo run -p nexapipe -- --generate-invite client-001 --registration
```

```text
nexapipe://endpoint/a612…7063?v=2&domains=app.example.com&client=client-001
    &enroll=9f2c…c41b
```

第一台连接的设备发送该令牌，服务端回复一个新生成的密钥，并**在同一次写入中烧掉
令牌**，因此一个在传输途中被复制的链接在被使用的瞬间就不再是凭证。一个你从未送达的
链接，通过再生成一个来吊销，这会替换掉尚未使用的令牌。

**注册轮换的是哪一个密钥，取决于设备有没有报名字。** 以具名设备应答的安装 —— 桌面端
取主机名、Android 取设备型号 —— 会被写到 `[auth.clients.<id>.devices.<name>]` 下，
所以只有这台设备的凭据变了，其余设备继续可用。没有报名字的安装则被写到客户端自己的
`secret` 下，而**这一次**才是会连带所有共用它的设备的轮换：它们都必须重新扫描。没有
任何设备会自动重新注册，所以一个在能报名字之前就注册好的设备会一直以"未命名"应答，
直到重新导入邀请 —— 也只有这一件事能改变它。

注册**不会**覆盖一个已经存在的设备名：令牌只证明邀请送到了某个人手里，不能证明送到了
哪台设备，而名字是客户端在注册时自己报的，所以接受任意名字就等于让一个被复制的链接
顶替掉真设备。要换掉已有设备的凭据，用
`nexapipe client add <id> --device <name> --force`。

- `v=2` 是一个**独立的版本号**，因此只认识 `v=1` 的应用会拒绝该码，而不是把它当作
  一个凭证丢失的端点分享来读取。
- 完成注册的设备必须**持久化它被签发的密钥** —— 令牌已被花掉，所以一个持有该邀请码
  重启的应用无法注册两次。两个应用都做到了：桌面端调用 `take_issued_credential`，
  Android 从 `IrohProxy.nativeTakeIssuedCredential()` 读出同样的内容。

扫码功能在 Android 应用中实现（"Add Node" 旁边的 "Scan Invite" 按钮），它只接受
`endpoint/` 形式 —— 它存储的节点只持有 Node ID 而没有地址，所以 ticket 形式的邀请码
会被拒绝。

---

## 安全边界

**明文出现在哪里。** 在 `passthrough` 模式下，哪里都没有：会话在访客与你的后端之间
端到端加密，代理除字节之外什么都不持有。在 `http` 模式下代理会解析请求并重新向
`http://` 后端发起，所以对于那一跳它就是 L7 中间盒 —— 与 nginx 或 Caddy 所处的位置
相同。那最后一跳通常留在同一台主机（`127.0.0.1`）或你自己的局域网内。

**查询串不会被记录。** 访问日志保留参数名，把取值替换为 `<redacted>`
（`[log] redact_query`，默认开启），因为令牌与签名正是在那里传递的。

报告漏洞：开一个 issue，或者如果可以实际利用，直接联系维护者。

---

## 使用客户端库

```toml
[dependencies]
nexapipe-client = { path = "../crates/nexapipe-client", features = ["local-proxy"] }
```

```rust
use std::sync::Arc;

use nexapipe_client::{EndpointGroup, LoadBalancingStrategy, LocalProxy, NodeConfig};

// 一个节点（服务端 Node ID 或完整 Ticket）加上它服务的域名。
let group = EndpointGroup::new_with_nodes(
    vec![NodeConfig {
        server_node_id: Some(server_node_id),
        server_ticket: None,
        domains: vec!["app.example.com".to_string()],
    }],
    None,
    LoadBalancingStrategy::RoundRobin,
)
.await?;

// 127.0.0.1:8081 上的 HTTP 代理，只转发已配置的域名。
let proxy = LocalProxy::new(
    "127.0.0.1:8081",
    vec!["app.example.com".to_string()],
    Arc::new(group),
)
.await?;
proxy.run().await?;   // run() 阻塞；从别处调用 stop() 来结束它
```

同一个 `EndpointGroup` 由本地代理与 TUN 代理共用，因此一个连接池同时服务两者。

### UniFFI 表面

`uniffi` feature 把同一个客户端打包给不是用 Rust 写的应用 —— Swift、Kotlin、
Python。它是一个对象加一个本地代理：

```text
ProxyClient::new(ClientConfig { servers, load_balancing, relay_mode, ... })
    .node_id() .server_ids() .preconnect()
    .link_statuses() .traffic() .flows() .close_flow()
    .send_request(HttpRequest) .send_raw(host, bytes)
    .drop_connections() .close()
LocalProxy::new(client, "127.0.0.1:8081", domains)  ->  .stop()
```

每台服务器带着自己的凭据 —— 节点 ID 或 ticket、它服务的域名，以及一个 TOTP
secret 或一次性注册令牌 —— 因为每台服务器各自有一份 `[auth.clients]` 条目，而
同一个客户端可能既连一台要 2FA 的、也连一台不要的。`link_statuses()` 给出的是
桌面端与 Android 端显示的同一条路径与往返时延。

**TUN 不在其中。** TUN 需要一个包来源和一个包去向 —— Android 上是文件描述符，
iOS 上是 `NEPacketTunnelFlow` —— 两者都跨不过 UniFFI 的边界：UniFFI 传的是值，
而一条活的包流不是值。要隧道本身的应用只能走 C ABI，本 crate 同样会构建它。
能跨过去的是本地代理那半边，因为它是一个套接字、一个端口和一份域名列表。

Cargo feature：

| Feature | 用途 |
| --- | --- |
| `native-certs`（默认） | 使用操作系统的证书存储。 |
| `webpki-roots` | 改为内置 Mozilla 根证书。 |
| `local-proxy` | 本地 HTTP 代理：`CONNECT` 打开一条 L4 TCP 流，直接向它发起的 TLS `ClientHello` 走 SNI 路径。 |
| `tun-proxy` | 面向 TUN fd 的 smoltcp 用户态 TCP/IP 栈，按域名分配虚拟 IP，使一条流自带端口（并让 UDP 成为可能）。隐含 `local-proxy`。 |
| `jni` | 面向 `com.nexa.pipe.IrohProxy` 的 JNI 入口。 |
| `uniffi` | 面向 Swift/Kotlin/Python 的 UniFFI 绑定。 |
| `tracing`（默认） | `tracing` 集成。 |

### QUIC 调优

因为一条内层 TCP 连接就是一条 QUIC 双向流，**每条流的接收窗口**就是每条被代理连接
的吞吐上限 —— iroh 的默认值（1.25 MB）在 200 ms RTT 下把单条连接限制在约 50 Mbps。
`TransportTuning` 会提高它，并且无需重新编译即可覆盖：

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `NEXAPIPE_QUIC_STREAM_WINDOW` | `4194304` | 每条流的接收窗口，字节。 |
| `NEXAPIPE_QUIC_SEND_WINDOW` | `16777216` | 连接级发送窗口，字节。 |
| `NEXAPIPE_QUIC_RECV_WINDOW` | `67108864` | 连接级接收窗口，字节。 |
| `NEXAPIPE_QUIC_INITIAL_MTU` | `0` | `0` 表示保持 iroh 的 1200；否则取 1200..=65535。 |
| `NEXAPIPE_QUIC_KEEPALIVE_MS` | `0` | `0` 表示保持 iroh 的 5 秒。 |
| `NEXAPIPE_QUIC_MAX_BIDI_STREAMS` | `1024` | 一条连接可同时承载的双向流数。库默认值（100）在每条 UDP 流都占用一条流之后就不够用了。 |
| `NEXAPIPE_QUIC_CONGESTION` | `bbr` | 拥塞控制算法：`bbr` 或 `cubic`。BBR 是基于模型的，按瓶颈带宽和最小往返时延的乘积发包，所以长距离路径上的随机丢包不会让窗口缩小；Cubic 把丢包读作拥塞并退让。无法识别的值会告警并保留默认值。 |

绝不要覆盖 iroh 的多路径或 NAT 穿透相关开关 —— 那会破坏打洞。`TUN_MTU` 是 1400，
并且在每一个 TUN 实现中都必须完全一致。

### TUN 调优

用户态协议栈的 **TCP 窗口**同时是两件事：它是每一条穿过 TUN 的连接的吞吐上限，
也是每一条连接的内存开销 —— 协议栈给每个 socket 分配四份这么大的缓冲。默认值是
128 KiB，适合 TUN 上主要的请求—响应型流量。要搬运大块数据的链路需要更大的窗口：

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `NEXAPIPE_TUN_TCP_WINDOW` | `131072` | 每个 socket 的 TCP 窗口，字节。 |

单条连接的稳态速度等于窗口除以往返时延：128 KiB 在 100 ms 下是 1.25 MB/s，在
50 ms 下是 2.5 MB/s，320 KiB 则是它的三倍。该值在协议栈建立时读取一次。Android
没有可用的环境变量，因此始终使用默认值。

---

## 客户端应用

| 应用 | 目录 | 功能 |
| --- | --- | --- |
| Android | [`ui-android`](ui-android/README.md) | VpnService TUN，带 DNS 劫持 + TCP/UDP 重定向；Compose UI；二维码 2FA 导入。 |
| 桌面端 | [`ui-desktop`](ui-desktop/README.md) | Tauri 2 + Vue 3；本地 HTTP 代理或经可选提权服务的系统 TUN（WinTun）；显式的 DNS 策略（`scoped` / `global` / `none`），不会被程序替你改。 |

<table>
  <tr>
    <td align="center"><img src="screenshots/android-disconnected.jpg" width="240" alt="Android 客户端，未连接"><br><sub>Android —— 未连接</sub></td>
    <td align="center"><img src="screenshots/android-connected.jpg" width="240" alt="Android 客户端，已连接到端点"><br><sub>Android —— 已连接</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="screenshots/desktop-disconnected.png" width="400" alt="桌面客户端，代理已停止"><br><sub>桌面端 —— 已停止</sub></td>
    <td align="center"><img src="screenshots/desktop-connected.png" width="400" alt="桌面客户端，代理以 TUN 模式运行"><br><sub>桌面端 —— 运行中（TUN）</sub></td>
  </tr>
</table>

两者都是本仓库中的普通目录（从先前的独立仓库导入时保留了 git 历史），并与服务端从
同一个 tag 发布。

### macOS 首次启动

GitHub Releases 中的桌面端安装包，**在发布流水线持有签名凭据时**会做代码签名与公证；
没有凭据时则不会。已签名并已公证的安装包在从未打开过它的 Mac 上可以直接运行，用户
不会被要求做任何降低安全设置的操作。

没有凭据时安装包未签名，Safari 会给下载的 DMG 以及从中拷贝出来的应用打上
quarantine 标记，导致首次打开时 macOS 提示：

> “nexa” is damaged and can't be opened. You should move it to the Trash.

应用本身没有损坏。安装后执行一次即可：

```bash
xattr -cr /Applications/nexa.app
```

右键 →“打开”无法绕过这条提示；每次重新安装后都需要再执行一次。从源码本地构建
（`build_dmg.sh`）不会带上 quarantine 标记。

#### 打开签名与公证

当仓库里配置了下列凭据时，发布工作流会对 macOS 安装包签名并公证：

| 存放位置 | 名称 | 内容 |
|---|---|---|
| secret | `APPLE_CERTIFICATE` | Developer ID `.p12` 的 base64 |
| secret | `APPLE_CERTIFICATE_PASSWORD` | 该 `.p12` 的密码 |
| secret | `APPLE_APP_SPECIFIC_PASSWORD` | 用于公证的 app 专用密码 |
| variable | `APPLE_SIGNING_IDENTITY` | `Developer ID Application: <名称> (<TEAMID>)` |
| variable | `APPLE_ID` | Apple ID 邮箱 |
| variable | `APPLE_TEAM_ID` | 团队 ID |

证书必须是 “Developer ID Application” 类型，而不是 “Apple Development”：后者无法
公证，而 Apple 要求分发给开发者本人机器之外的软件必须经过公证。从钥匙串导出
`.p12` 并做 base64：

```bash
openssl base64 -A -in /path/to/developer-id.p12 -out certificate-base64.txt
```

证书导入和公证都由 Tauri 完成；工作流只负责把变量交给它，然后在日志里明确说出
产出的安装包是否带有有效签名、Gatekeeper 是否接受它。没有凭据时构建出的安装包
不会有任何签名，这一点会写进任务日志，而不是悄悄发布一个未签名的应用。

**本地**构建时，证书通常已经在你自己的钥匙串里，此时给出身份即可：

```bash
APPLE_SIGNING_IDENTITY="Developer ID Application: <名称> (<TEAMID>)" ./build_dmg.sh
```

---

## 开发

```bash
cargo build                                   # 构建整个 workspace
cargo test --workspace                        # 运行全部测试
cargo clippy --workspace --all-targets        # lint（保持在零警告）
cargo fmt --all -- --check                    # 报告格式漂移
```

**不要**运行 `cargo fmt --all`：代码树在你没有改动的文件里存在既有的格式漂移。只格式化
你自己的文件 —— `rustfmt --edition 2024 <path>` —— 这就够了，因为 `rustfmt` 本身会
顺着 `mod` 声明走。

workspace 构建覆盖不到的分目标检查：

```bash
cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy
cargo ndk -t x86_64   check -p nexapipe-client --features jni,tun-proxy
cd ui-desktop/src-tauri && cargo check
cd ui-android && ./gradlew.bat :app:compileDebugKotlin
```

TUN 栈由 Android 与桌面端共用，只有它基于 fd 的入口是 `cfg(target_os = "android")`，
所以那两行 `cargo ndk` 仍是唯一会对 Android 那一半做类型检查的东西 —— 很容易忘。
两个 ABI 各要一次：应用按 ABI 分别出包，CI 也两个都跑。
`ui-desktop/src-tauri` 是一个独立的 cargo 项目，因此 workspace 的 lint 门禁也覆盖
不到它。

说明：

- workspace 锁定 edition 2024，并通过 `[patch.crates-io]` 内置 smoltcp；请把
  `third_party/` 留在构建上下文中（Docker 已经这么做了）。平台相关代码始终放在
  cargo feature 之后（`jni`、`local-proxy`、`tun-proxy`、`uniffi`）。
- CI（`.github/workflows/ci.yml`）在 Linux 与 macOS 上跑测试；桌面端 crate 在
  Linux、macOS、Windows 上做 `cargo check`。`release.yml` 在打 tag 时覆盖多平台
  构建。含连字符的 tag（`v0.2.0-rc.1`）会作为 GitHub **pre-release** 发布，因此
  永远不会占据 "latest"。
- 行内注释使用英文。

关于接下来要做什么 —— 以及为什么有些东西是刻意不做的 —— 见
[docs/ROADMAP.md](docs/ROADMAP.md)（英文）。

## License

MIT —— 见 [LICENSE](LICENSE)。
