# NexaPipe

Expose HTTP, HTTPS, WebSocket, TCP and UDP services that live behind NAT through
a single [iroh](https://github.com/n0-computer/iroh) endpoint — no public IP, no
port forwarding, no VPN server to rent. One server, one config, four kinds of
traffic; TLS is terminated by your backend, not here.

NexaPipe is a Rust workspace with four parts:

- **`nexapipe`** — the server: an L7 reverse proxy plus an L4 tunnel that accept
  traffic over iroh/QUIC and forward it to your real backends. It can also serve
  plain HTTP directly. TLS is not terminated here — it is passed through to the
  backend, which owns the certificates.
- **`nexapipe-client`** — the client library: connection pooling, domain-to-node
  routing, a local HTTP proxy, and a smoltcp-based TUN proxy. Shipped as an
  `rlib`, a `cdylib` (Android JNI) and a UniFFI binding.
- **`nexapipe-proto`** — the wire format of the L4 tunnel: the `0x05` preface,
  the status byte, and UDP framing. Dependency-free, used by both sides so they
  cannot disagree about it.
- **Apps** — an Android client (`ui-android`, TUN/VpnService) and a desktop
  client (`ui-desktop`, Tauri 2 + Vue 3), both living in their own repositories
  and wired in as git submodules.

[How it works](#how-it-works) · [Layout](#repository-layout) ·
[Quick start](#quick-start-server) · [CLI](#cli) ·
[Configuration](#configuration) · [TLS](#tls) · [TCP & UDP](#tcp--udp) ·
[2FA](#2fa-totp) · [Endpoint invites](#endpoint-invites) ·
[Client library](#using-the-client-library) · [Apps](#client-apps) ·
[Development](#development)

---

## How it works

```
                    ┌─────────────────────── your LAN / host ───────────────────┐
                    │   Caddy :443 ──► backend A        backend B       ...     │
                    │   (certificates) 10.0.0.222:8188 127.0.0.1:15666          │
                    └────────▲───────────────────▲──────────────────▲───────────┘
                             │                   │                  │
                    ┌────────┴───────────────────┴──────────────────┴───────────┐
                    │  nexapipe server                                          │
                    │  · L7 router (Host + path, round_robin / random)          │
                    │  · hyper, WebSocket upgrade, health checks                │
                    │  · L4 passthrough by SNI (TLS bytes copied, never read)   │
                    │  · L4 tunnel (TCP / UDP to a route's backend)             │
                    │  · iroh endpoint, ALPN b"\x05nexapipe"                    │
                    └────────▲───────────────────────────────▲──────────────────┘
                             │                               │
        plain HTTP + TLS     │                               │   QUIC over iroh
        passthrough          │                               │   (hole punched,
        (optional, [server]) │                               │    relay fallback)
                    ┌────────┴───────────┐         ┌─────────┴──────────────────┐
                    │  any HTTP client   │         │  nexapipe-client           │
                    └────────────────────┘         │  · local HTTP proxy        │
                                                   │  · or TUN (Android/desktop)│
                                                   │  · or embedded Rust API    │
                                                   └────────────────────────────┘
```

One inner TCP connection maps to one QUIC bidirectional stream. What a stream
carries depends on who opened it: an HTTP request (or a WebSocket upgrade), a TLS
session, or an L4 flow — a raw TCP connection or a UDP flow. For HTTP the server
routes by `Host` exactly like an ordinary reverse proxy — the NAT traversal
happens underneath and is invisible to both the app and the backend.

The **first byte** of a stream picks the handler, so the four kinds of traffic
never have to be told apart by guessing:

| First byte | Handler | Section |
| --- | --- | --- |
| `0x16` | TLS `ClientHello` → routed by SNI, forwarded as bytes | [TLS](#tls) |
| `0x05` | L4 preface → raw TCP or UDP to a named backend | [TCP & UDP](#tcp--udp) |
| anything else | HTTP request | this page |

---

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/nexapipe/` | Server binary and library. CLI in `src/main.rs`, config in `src/config.rs`, iroh stream handling in `src/conn/`, HTTP/WebSocket proxying in `src/http/` and `src/proxy/`, TLS passthrough in `src/passthrough.rs`, TCP/UDP tunnel in `src/l4/`, shared byte-copying in `src/stream_util.rs`, routing in `src/routes/` and `src/lb/`, health checks in `src/health/`, TOTP 2FA in `src/auth/`. |
| `crates/nexapipe-client/` | Client library (`lib` + `cdylib`). Pool in `connection_pool.rs`, domain→node mapping in `endpoint_group.rs`, local proxy in `local_proxy.rs`, L4 tunnel client in `l4.rs`, smoltcp TUN proxy in `tun_proxy.rs`, TUN virtual-IP mapping in `virtual_ip.rs`, QUIC tuning in `transport.rs`, JNI in `jni.rs`, UniFFI in `uniffi.rs`. |
| `crates/nexapipe-proto/` | The L4 wire format: `preface.rs` (magic, version, host, port, status byte) and `udp.rs` (`u16`-length framing). No dependencies, so the server and the client can both link it. |
| `third_party/smoltcp` | Vendored smoltcp 0.12 with a patch for the sequence-number underflow panic. Wired in through `[patch.crates-io]`. Do not edit. |
| `ui-android/` | Android app (submodule → `yixinin/nexapipe-android`). |
| `ui-desktop/` | Tauri 2 desktop app (submodule → `yixinin/nexapipe-desktop`). |
| `config.toml` | Example server + local-proxy configuration. |
| `run_android.ps1` | One-shot Android debug loop (build → install → launch → logcat). |

---

## Quick start (server)

```bash
cargo build --release -p nexapipe
cargo run -p nexapipe -- --config config.toml
```

On startup the server prints what clients need:

```
========================================
Proxy Connection Information
========================================
Node ID (stable, for server_node_id): 2f9c...
Ticket (for clients):                 endpoint:...
========================================
```

Give clients either the **Node ID** (stable, needs discovery) or the **Ticket**
(contains addresses, changes when they change). Setting `[iroh] secret_key`
keeps the Node ID — and therefore the Ticket — identical across restarts:

```bash
cargo run -p nexapipe -- --generate-secret
```

### Docker

```bash
docker compose up -d --build
docker compose exec nexapipe tail -f /app/logs/nexapipe.log
```

`docker-compose.yaml` mounts your `config.toml` and a `logs/` volume, and points
`NEXAPIPE_LOG_DIR` at the mount. `host.docker.internal` is wired up so backends
running on the Docker host are reachable.

---

## CLI

| Flag | Description |
| --- | --- |
| `-c, --config <PATH>` | Config file (default `config.toml`). |
| `--local-proxy` | Run as a client-side local HTTP proxy instead of a server. |
| `--generate-secret` | Print a new iroh secret key for a stable endpoint identity. |
| `--generate-2fa <CLIENT_ID>` | Generate a TOTP secret and print an enrollment QR code. |
| `--show-2fa <CLIENT_ID>` | Print the QR code of a client already in `[auth.clients]`. |
| `--issuer <NAME>` | Issuer label shown by the authenticator app. |
| `--qr-format <FMT>` | `unicode` (default), `plain`, `ascii`, `svg`, `none`. |
| `--qr-invert` | Draw the QR code light on dark. |
| `--qr-out <PATH>` | Also write the QR code to a file (`.svg` → SVG, else ASCII). |
| `--generate-invite [CLIENT_ID]` | Print a scannable `nexapipe://` invite. With a `CLIENT_ID` the 2FA secret goes in too; without one it carries only the endpoint and its domains. |
| `--invite-domains <LIST>` | Comma-separated domains for the invite (default: `[local_proxy] proxy_domains`, else the route hosts). |
| `--invite-name <NAME>` | Label stored alongside the endpoint. |
| `--invite-relay <URL>` | Relay URL for the invite (default: `[iroh] relay_url`). |
| `--endpoint-id <NODE_ID>` | Endpoint to advertise (default: derived from `[iroh] secret_key`). |

---

## Configuration

`config.toml` is the single source of truth for both the server and the client
mode. Every key is optional.

The file is re-read every 5 seconds and **applied live**: `[[routes]]` and
`default_backend` take effect without a restart, and a config that fails to
parse or validate is reported and ignored so a half-saved edit cannot take the
proxy down. The rest still needs a restart, because it is read once when the
process starts: `[server] listen_addr`, `[iroh] secret_key` / `bind_port` /
relay settings, `[auth]` and `[log]`.

### Top level

```toml
# Where an HTTP request goes when its Host matches no `mode = "http"` route.
# Optional: without it, an unrouted host is answered 404 instead of being
# forwarded somewhere arbitrary. `passthrough`, `tcp` and `udp` lookups never
# use it — they refuse instead.
default_backend = "http://10.0.0.72:15666"
debug = true
```

### `[server]` — direct ingress (optional)

| Key | Default | Notes |
| --- | --- | --- |
| `listen_addr` | `0.0.0.0:8080` | Plain HTTP listener. A TLS session opened against it is passed through, not terminated. |

`tls_enabled`, `tls_listen_addr`, `cert_path` and `key_path` used to configure
in-process TLS termination. They are still accepted so an existing
`config.toml` parses, but they do nothing and are reported at startup — delete
them and see [TLS](#tls).

### `[iroh]` — the tunnel endpoint

| Key | Notes |
| --- | --- |
| `secret_key` | Hex secret key from `--generate-secret`; keeps the Node ID stable. |
| `bind_port` | Fixed UDP port instead of an ephemeral one. |
| `relay_mode` | `disabled` / `default` / `custom`. |
| `relay_url` | Required when `relay_mode = "custom"`. |

### `[[routes]]` — routing

```toml
[[routes]]
host_pattern = "comfyui.iroh.iakl.top"
path_pattern = "/"
path_is_prefix = true
strategy = "round_robin"          # or "random"
backends = ["http://10.0.0.222:8188"]
mode = "http"                     # default
# path_rewrite = "/api"

[[routes]]
host_pattern = "fn.iroh.iakl.top"
mode = "passthrough"              # TLS, routed by SNI; see TLS below
backends = ["caddy:443"]

[[routes]]
host_pattern = "db.iroh.iakl.top" # a raw TCP service, any port
mode = "tcp"
backends = ["10.0.0.50:5432"]

[[routes]]
host_pattern = "turn.iroh.iakl.top"
mode = "udp"                      # UDP flows, idle timeout in seconds
backends = ["10.0.0.60:3478"]
idle_timeout_secs = 60

# One host that has to answer both a request and a tunnel — the ordinary shape
# for an Android TUN client. `modes` takes several; `mode` takes one.
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal:15666"]
```

| Mode | What it does |
| --- | --- |
| `http` (default) | Parses the request, applies `path_pattern` / `path_rewrite`, and re-issues it with the shared HTTP client. Backends must be `http://` — an `https://` backend is rejected at startup. |
| `passthrough` | Copies bytes. The route is selected by SNI, so `path_pattern` and `path_rewrite` do not apply and the backend may be a bare `host:port`. |
| `tcp` | Carries a raw TCP flow to `backends`, selected by the host name in the L4 preface. No HTTP parsing, no `path_pattern`, no health check. See [TCP & UDP](#tcp--udp). |
| `udp` | Carries UDP flows — one QUIC bi-stream per flow, one datagram per frame. Same selection as `tcp`, plus `idle_timeout_secs`. |

A route serves **one** mode with `mode = "..."` and **several** with
`modes = [...]`, sharing one `backends` list:

```toml
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = ["http", "tcp"]           # also reachable as an L4 tunnel
backends = ["http://host.docker.internal:15666"]
```

`mode` and `modes` may be written together — the route serves the union, and
duplicates collapse. Which of them a *connection* uses is still decided by its
first byte, so one connection only ever takes one path.

The cost of sharing one `backends` list is that the address has to satisfy every
declared mode, and the L4 rules are the stricter ones: **the port must be
written out**, because an L4 route dials an address and has nothing to default
to (`http://host` is fine for `http` alone, where 80 is implied, and rejected
once `tcp` is added). Write two entries instead when the modes need different
backends, since a route has exactly one pool.

Removed route keys, still parsed but ignored: `cert_path`, `key_path` and
`redirect_to_https` (let the backend redirect). They are reported at startup.

### `[local_proxy]` — client mode

```toml
[local_proxy]
enabled = true
listen_addr = "127.0.0.1:8081"
proxy_domains = ["fn.iroh.iakl.top"]
strategy = "round_robin"

[[local_proxy.nodes]]
server_node_id = ""               # stable Node ID from the server
domains = ["fn.iroh.iakl.top"]
```

The same domain may appear on several nodes; that is how you load balance across
servers. `server_ticket` and `server_node_id` at the `[local_proxy]` level still
work but are deprecated — prefer `[[local_proxy.nodes]]`.

### `[log]`

Rotating log files plus console output. `file`, `dir`, `file_name`,
`access_log`, `rotation` (`daily` / `hourly` / `never`), `max_size_mb`,
`max_files`, `console`. `NEXAPIPE_LOG_DIR` overrides `dir`.

### `[acme]`

Removed. Certificates belong to the backend now; the section is still parsed but
ignored, and reported at startup. See [TLS](#tls).

---

## TLS

TLS is terminated **by the backend**, never by this proxy: the proxy holds no
certificate and never sees a plaintext byte of an `https://` request.

What happens to a TLS connection:

1. A client opens a TLS session as usual — through the local HTTP proxy, the
   TUN, or straight at `[server] listen_addr`.
2. The proxy recognises the `ClientHello`. Its first byte is `0x16`, which no
   HTTP request can start with, so the two are told apart with a single byte.
3. The SNI is matched against the `mode = "passthrough"` routes, and every byte
   of the session is copied to that route's backend.

Nothing is decrypted, so WebSocket, gRPC, HTTP/2 and plain HTTP over TLS all
work unchanged. No client rebuild is needed: the client tunnels have always
forwarded raw bytes, they simply had nothing to hand them to before.

A TLS session that arrives through `CONNECT` or a TUN takes a different path: the
client announces host and port with the L4 preface instead of handing over a
`ClientHello`, so it is matched by a `mode = "tcp"` route and not by a
`passthrough` one. A domain you want reachable both ways therefore needs **both**
modes — as two entries, or as one with `modes = ["passthrough", "tcp"]` when the
same backend serves them — both pointing at the same TLS-speaking backend. See
[TCP & UDP](#tcp--udp).

### Caddy

Point a passthrough route at Caddy and let it hold the certificates:

```toml
[[routes]]
host_pattern = "fn.iroh.iakl.top"
mode = "passthrough"
backends = ["caddy:443"]          # or "https://caddy:443", the scheme is ignored
```

```caddyfile
{
	email you@example.com
}

*.iroh.iakl.top {
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
	@fn    host fn.iroh.iakl.top
	@comfy host comfyui.iroh.iakl.top
	reverse_proxy @fn    http://host.docker.internal:15666
	reverse_proxy @comfy http://10.0.0.222:8188
}
```

Use the **DNS-01** challenge. The proxied names resolve to a loopback address
inside the tunnel, so an inbound `HTTP-01` request never reaches Caddy — and
DNS-01 also means Caddy needs no public IP, the same property the tunnel has. A
wildcard like `*.iroh.iakl.top` makes new subdomains free. The stock `caddy`
image ships no DNS provider: build one with `github.com/caddy-dns/cloudflare`
via `xcaddy` or a `-builder` image.

### What passthrough costs

A passthrough route is opaque, so the access log records bytes rather than a
request line, `/health` probing does not apply, and the proxy cannot rewrite
paths or redirect `http://` to `https://`. Those move to Caddy, which sees the
decrypted request and does them better. Plain `http://` routes keep everything.

---

## TCP & UDP

Everything above speaks HTTP or TLS. A database wire protocol, an MQTT or STUN
socket, a game server — those are neither, and UDP carries no host name at all,
so nothing can be routed by reading payload bytes.

The L4 tunnel does not read payload bytes. The client writes a **preface** as the
first bytes of a bi-stream and the server answers with exactly one status byte:

```text
client → server   0x05  version=0x01  proto(0x01 tcp | 0x02 udp)  len  host  port(u16-be)
server → client   status   0x00 ok       0x01 no route        0x02 backend failed
                           0x03 too many flows                0x04 bad preface
```

`0x05` starts no HTTP request and no TLS record, so the three handlers are one
`if` apart — see [How it works](#how-it-works). After an `0x00`:

- **TCP** — raw bytes in both directions, exactly like the TLS passthrough path.
- **UDP** — one QUIC bi-stream per flow, datagrams as `u16`-length-prefixed
  frames, because a byte stream has no message boundaries of its own. A flow
  silent in *both* directions for `idle_timeout_secs` (default 60) is closed.

### The server owns the dial target

The client names a **host and a port**; the route decides which address is
dialled. `backends` is the only place an address appears, so a client holding
valid 2FA credentials still cannot use the server as an open relay.

An L4 lookup **never falls back to `default_backend`**. A host with no `tcp`/`udp`
route is a refusal the caller can act on, not a stream quietly forwarded
somewhere else — which is exactly what used to happen when a
`CONNECT host:port` line reached the HTTP parser with an empty path.

### `client_ports`

An optional selector — which ports a route serves — not a destination:

```toml
[[routes]]
host_pattern = "db.iroh.iakl.top"
mode = "tcp"
backends = ["10.0.0.50:5432"]
client_ports = [5432, 6432]       # ports this route answers on
```

It only decides *which* route a flow matches, so one host can have `tcp` routes
on different ports pointing at different backends. It never changes the address
that is dialled. With no `client_ports`, every port matches.

### What it costs

L4 flows are opaque: the access log records bytes rather than a request line, and
there is no health check (probing a `tcp`/`udp` backend with an HTTP request would
be meaningless). Concurrency is bounded per QUIC connection — a client that opens
too many flows gets `0x03 too many flows` instead of silently queueing inside the
endpoint.

Because one UDP flow is one bi-stream, a TUN device can hold several hundred at
once; see `NEXAPIPE_QUIC_MAX_BIDI_STREAMS` under
[QUIC tuning](#quic-tuning).

### Which clients can use it

| Client | TCP | UDP |
| --- | --- | --- |
| Local HTTP proxy (`--local-proxy`, desktop) | `CONNECT host:port` | — |
| Android TUN | any port | any port |
| Desktop TUN | any port | — |

The TUNs hand the application **one virtual address per domain** (`10.0.1.16+` on
Android, `10.0.0.2+` on desktop), so the destination *is* the name and the port on
the packet is the port on the wire. Nothing is sniffed, which is what makes UDP
possible at all.

Note the route mode this implies: traffic a TUN sends to a domain arrives as L4,
so that domain needs a `tcp` (or `udp`) route — **even for plain HTTP on port
80**, because a TUN hands over an IP packet, not an HTTP request, and the client
states the host and port in the preface instead. A TUN reaching an HTTPS service
therefore points a `tcp` route at the TLS-speaking backend —
`backends = ["caddy:443"]`, which is the same Caddy as
[TLS passthrough](#caddy) but with the port stated explicitly. `mode =
"passthrough"` stays for clients that open a `ClientHello` straight at the
proxy's own address.

If the same backend answers a TUN and a plain request, say so in one entry:

```toml
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal:15666"]
```

### Where the L4 tunnel lives

It is part of the **iroh** entry path only. The plain `[server] listen_addr`
listener tells TLS from HTTP by the first byte and knows nothing about `0x05`, so
a preface sent there would be parsed as an HTTP request. All four kinds of
traffic coexist on the iroh endpoint; the plain listener serves HTTP and TLS
passthrough.

---

## 2FA (TOTP)

When `[auth] enabled = true`, every client connection must complete a TOTP
handshake before any traffic is proxied.

1. Generate a secret and a scannable QR code:

   ```bash
   cargo run -p nexapipe -- --generate-2fa client-001 --qr-format unicode
   ```

2. Add the printed secret to the server config:

   ```toml
   [auth]
   enabled = true
   algorithm = "sha1"      # sha1 | sha256 | sha512
   time_step = 30
   digits = 6
   window = 1
   max_attempts = 5
   lockout_duration = 300

   [auth.clients.client-001]
   secret = "JBSWY3DPEHPK3PXP"
   ```

3. On the client, either scan the QR code in the app, or set the credentials in
   `[local_proxy.two_factor]`:

   ```toml
   [local_proxy.two_factor]
   enabled = true
   client_id = "client-001"
   secret = "JBSWY3DPEHPK3PXP"
   algorithm = "sha1"
   ```

Auth settings are read once at startup, so restart the server after adding a
client. See `config.toml.2fa.example`.

The QR code carries a standard `otpauth://` URI, so any authenticator app can
import it, not just the NexaPipe app:

```text
otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP&issuer=NexaPipe&algorithm=SHA1&digits=6&period=30
```

Notes:

- Set `issuer` under `[auth]` to change the label shown by the app; `--issuer`
  overrides it for a single run. Both default to `NexaPipe`.
- An already configured client can be printed again later, for another device:
  `cargo run -p nexapipe -- --show-2fa client-001`.
- `algorithm`, `time_step` and `digits` are read when the QR code is generated,
  not when it is scanned: a client that has already imported the credentials
  keeps the values it was enrolled with, so leave them stable.

---

## Endpoint invites

One QR code can carry a whole client configuration — endpoint, domains and 2FA —
so enrolling a phone is a scan instead of three fields typed by hand:

```bash
cargo run -p nexapipe -- --generate-invite client-001 --qr-format unicode
```

```text
nexapipe://endpoint/a612…7063?v=1&name=Home&domains=fn.iroh.iakl.top,comfyui.iroh.iakl.top
    &relay=https://relay.example&client=client-001&issuer=NexaPipe
    &secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30
```

| Part | Meaning |
| --- | --- |
| `endpoint/<node-id>` | The endpoint to dial. `ticket/<ticket>` carries a full endpoint ticket instead. |
| `domains` | Comma-separated; the client proxies exactly these names. |
| `name` | Label shown in the client's list. |
| `relay` | Relay URL, for an endpoint that is not reachable directly. |
| `client` + `secret`/`algorithm`/`digits`/`period` | 2FA credentials — present only when you pass a `CLIENT_ID`. |
| `otpauth` | Alternative to the six parameters above: a whole `otpauth://` URI, used when the flat form is absent. |

Without a `CLIENT_ID` the invite carries the endpoint and its domains and nothing
else, which is what you want when sharing a server with people who have their own
credentials. Domains default to `[local_proxy] proxy_domains`, then to the
`[[routes]]` hosts; the endpoint defaults to the public key of
`[iroh] secret_key`, so the code stays valid across restarts. Override any of it
with `--invite-domains`, `--invite-name`, `--invite-relay`, `--endpoint-id`.

Two details worth knowing before you build on the format:

- Clients **ignore parameters they do not recognise**, so a newer server can add
  fields without breaking older apps. What is strict is `v` (must be `1`) and
  `algorithm` — an unknown name is an error, never a silent fallback to SHA1,
  because a downgrade would be invisible to the person scanning.
- Keep the code under ~400 characters so it stays easy to scan; the command warns
  when it is longer.

Scanning is implemented in the Android app (the "Scan Invite" button beside "Add
Node"), which accepts the `endpoint/` form only — its stored nodes hold a Node ID
and no addresses, so a ticket invite is refused.

---

## Using the client library

```toml
[dependencies]
nexapipe-client = { path = "../crates/nexapipe-client", features = ["local-proxy"] }
```

```rust
use std::sync::Arc;

use nexapipe_client::{EndpointGroup, LoadBalancingStrategy, LocalProxy, NodeConfig};

// One node (a server Node ID or a full Ticket) plus the domains it serves.
let group = EndpointGroup::new_with_nodes(
    vec![NodeConfig {
        server_node_id: Some(server_node_id),
        server_ticket: None,
        domains: vec!["fn.example.com".to_string()],
    }],
    None,
    LoadBalancingStrategy::RoundRobin,
)
.await?;

// HTTP proxy on 127.0.0.1:8081, forwarding only the configured domains.
let proxy = LocalProxy::new(
    "127.0.0.1:8081",
    vec!["fn.example.com".to_string()],
    Arc::new(group),
)
.await?;
proxy.run().await?;   // run() blocks; call stop() from elsewhere to end it
```

The same `EndpointGroup` is shared by the local proxy and the TUN proxy, so a
single connection pool serves both.

Cargo features:

| Feature | Purpose |
| --- | --- |
| `native-certs` (default) | Use the OS certificate store. |
| `webpki-roots` | Bundle Mozilla roots instead. |
| `local-proxy` | Local HTTP proxy: `CONNECT` opens an L4 TCP flow, and a TLS `ClientHello` opened straight at it goes down the SNI path. |
| `tun-proxy` | smoltcp userspace TCP/IP stack for a TUN fd, with per-domain virtual IPs so a flow carries its own port (and UDP works). Implies `local-proxy`. |
| `jni` | JNI entry points for `com.nexa.pipe.IrohProxy`. |
| `uniffi` | UniFFI bindings for Swift/Kotlin/Python. |
| `tracing` (default) | `tracing` integration. |

### QUIC tuning

Because one inner TCP connection is one QUIC bi-stream, the **per-stream
receive window** is the throughput ceiling of every proxied connection — the
iroh default (1.25 MB) caps a single connection at roughly 50 Mbps at 200 ms
RTT. `TransportTuning` raises it and can be overridden without a rebuild:

| Variable | Default | Meaning |
| --- | --- | --- |
| `NEXAPIPE_QUIC_STREAM_WINDOW` | `4194304` | Per-stream receive window, bytes. |
| `NEXAPIPE_QUIC_SEND_WINDOW` | `16777216` | Connection send window, bytes. |
| `NEXAPIPE_QUIC_INITIAL_MTU` | `0` | `0` keeps iroh's 1200; otherwise 1200..=65535. |
| `NEXAPIPE_QUIC_KEEPALIVE_MS` | `0` | `0` keeps iroh's 5 s. |
| `NEXAPIPE_QUIC_MAX_BIDI_STREAMS` | `1024` | Bi-streams one connection may carry at once. The library default (100) is too low once every UDP flow takes a stream of its own. |

Never override iroh's multipath or NAT-traversal knobs — doing so breaks hole
punching. `TUN_MTU` is 1400 and must be identical in every TUN implementation.

---

## Client apps

| App | Repository | What it does |
| --- | --- | --- |
| Android | [`ui-android`](ui-android/README.md) → `yixinin/nexapipe-android` | VpnService TUN with DNS hijack + TCP/UDP redirect; Compose UI; QR-code 2FA import. |
| Desktop | [`ui-desktop`](ui-desktop/README.md) → `yixinin/nexapipe-desktop` | Tauri 2 + Vue 3; local HTTP proxy or system TUN (WinTun) through an optional elevated service. |

Both are git submodules with their own history — commit inside them separately.

---

## Development

```bash
cargo build                                   # build the workspace
cargo test --workspace                        # run all tests
cargo clippy --workspace --all-targets        # lint (kept at zero warnings)
cargo fmt --all -- --check                    # report formatting drift
```

Do **not** run `cargo fmt --all`: the tree has pre-existing drift in files you
did not touch. Format only your own file — `rustfmt --edition 2024 <path>` —
which is enough because `rustfmt` follows `mod` declarations anyway.

Per-target checks the workspace build cannot cover:

```bash
cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy
cd ui-desktop/src-tauri && cargo check
cd ui-android && ./gradlew.bat :app:compileDebugKotlin
```

The Android TUN module is `cfg(target_os = "android")`, so the host build never
compiles it — that `cargo ndk` line is the only thing that type-checks it, and it
is easy to forget. `ui-desktop/src-tauri` is a separate cargo project, so the
workspace lint gate does not cover it either.

Tests worth running on their own:

```bash
cargo test -p nexapipe-proto                                  # the wire format
cargo test -p nexapipe-client --features local-proxy --lib    # local proxy + L4 client
cargo test -p nexapipe-client --features tun-proxy --lib      # + virtual_ip, runs on any host
```

Notes:

- The workspace pins edition 2024 and vendors smoltcp through
  `[patch.crates-io]`; keep `third_party/` in the build context (Docker already
  does).
- Platform code lives behind cargo features (`jni`, `local-proxy`, `tun-proxy`,
  `uniffi`) — keep it that way. `--all-features` does not build (uniffi 0.25).
- `cargo test --workspace` runs on Windows too, because the Unix-only parts are
  gated: `cfg(unix)` for signal handling, `cfg(target_os = "android")` for the
  TUN module. CI (`.github/workflows/ci.yml`) is Linux-only; `release.yml` covers
  multi-platform builds on tags. `duct` and `nix` are unused dev-dependencies of
  the server crate — leftovers, worth deleting rather than adding to.
- Inline comments are in English.

## License

MIT — see [LICENSE](LICENSE).
