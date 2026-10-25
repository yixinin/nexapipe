# nexapipe-client

The client library for the [nexapipe](https://github.com/open-nexa/nexapipe)
proxy — a way for an application to reach services that live behind NAT,
without a control plane, without an account, and without the proxy ever
terminating TLS.

It ships as an `rlib` for Rust, a `cdylib` for Android (JNI), and a UniFFI
binding for Swift, Kotlin and Python.

## What it does

- **Connection pooling** over an iroh/QUIC endpoint, with the transport tuned
  (per-stream window, congestion controller, MTU) and overridable without a
  rebuild.
- **Domain-to-node routing**: a set of domains, a set of nodes, and the
  decision of which node carries which domain.
- **A local HTTP proxy**: `CONNECT` opens an L4 flow, and a TLS `ClientHello`
  opened straight at it goes down the SNI path.
- **A TUN proxy**: a smoltcp TCP/IP stack with per-domain virtual IPs, so a
  flow carries its own port — and UDP works.

## Using it

```toml
[dependencies]
nexapipe-client = "1.0"
```

```rust
use std::sync::Arc;

use nexapipe_client::{EndpointGroup, LoadBalancingStrategy, LocalProxy, NodeConfig};

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

// An HTTP proxy on 127.0.0.1:8081, forwarding only the configured domains.
let proxy = LocalProxy::new(
    "127.0.0.1:8081",
    vec!["app.example.com".to_string()],
    Arc::new(group),
)
.await?;
proxy.run().await?;   // run() blocks; call stop() from elsewhere to end it
```

### Cargo features

| Feature | Purpose |
| --- | --- |
| `native-certs` (default) | Use the operating system's certificate store. |
| `webpki-roots` | Bundle Mozilla's roots instead. |
| `local-proxy` | The local HTTP proxy: `CONNECT` opens an L4 TCP flow, and a TLS `ClientHello` opened straight at it goes down the SNI path. |
| `tun-proxy` | A smoltcp TCP/IP stack for a TUN fd, with per-domain virtual IPs so a flow carries its own port (and UDP works). Implies `local-proxy`. |
| `jni` | JNI entry points for `com.nexa.pipe.IrohProxy`. |
| `uniffi` | UniFFI bindings for Swift, Kotlin and Python. |
| `tracing` (default) | `tracing` integration. |

### The `tun-proxy` feature needs one line in your `Cargo.toml`

The TUN runs a TCP/IP stack, and every published smoltcp release — 0.12, 0.13
and 0.14 alike — carries a panic in its TCP transmit path: an ACK that arrives
beyond what was sent makes a sequence-number subtraction underflow, and the
stack task dies with it. This repository vendors a patched copy of smoltcp
0.12.0 with that guard in place, and the workspace uses it through a
`[patch.crates-io]` — which, being a workspace setting, does not reach a
consumer.

Until upstream fixes it, a consumer of the `tun-proxy` feature needs that patch
too:

```toml
[patch.crates-io]
smoltcp = { git = "https://github.com/open-nexa/nexapipe", path = "third_party/smoltcp" }
```

What the patch changes, and why, is written down in
[`third_party/smoltcp/PATCHES.md`](https://github.com/open-nexa/nexapipe/blob/main/third_party/smoltcp/PATCHES.md).
The features that do not run the TCP/IP stack — `local-proxy` and the L4 tunnel
— are unaffected.

### Documentation

The page on [docs.rs](https://docs.rs/nexapipe-client) is built with the
`tun-proxy`, `local-proxy`, `jni` and `uniffi` features on, so it carries the
whole crate — the TUN stack, the local proxy, the Android bridge and the
UniFFI bindings, not only the part the default features reach.

## Licence

MIT. See the `LICENSE` file in the package.
