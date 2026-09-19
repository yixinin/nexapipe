# Repository Guidelines

Nexapipe is a Rust workspace: an iroh/QUIC-based proxy server forwarding HTTP/WebSocket traffic to backends, plus a multi-platform client library used by the Android and desktop apps. TLS is terminated by the backend (Caddy &co), not here: the server copies TLS sessions to a passthrough route selected by SNI (`src/passthrough.rs`) and holds no certificates. Raw TCP and UDP flows reach a route's backend through the L4 tunnel, which the client opens with a `0x05` preface stating protocol, host and port (`crates/nexapipe-proto` defines that wire format for both sides; `src/l4/` is the server half, the client's `src/l4.rs` the other).

## Project Structure & Module Organization

- `crates/nexapipe/` — Server binary and library. Entry point `src/main.rs` (clap CLI: `--local-proxy`, `--generate-secret`); config in `src/config.rs`; iroh connection handling in `src/conn/` (which dispatches on a stream's first byte); HTTP/WebSocket proxying in `src/http/` and `src/proxy/`; TLS/byte passthrough in `src/passthrough.rs`; raw TCP/UDP flows in `src/l4/`; shared byte-copying helpers in `src/stream_util.rs`; routing in `src/routes/` and `src/lb/`; health checks in `src/health/`.
- `crates/nexapipe-proto/` — The L4 wire format, dependency-free so both the server and the client link the same code: `preface.rs` (magic/version/proto/host/port plus the status byte) and `udp.rs` (`u16`-length datagram framing). Change it here, never by hand on one side.
- `crates/nexapipe-client/` — Client library (`lib` + `cdylib`). Connection pooling in `connection_pool.rs`, domain-to-endpoint mapping in `endpoint_group.rs`, HTTP/CONNECT/WebSocket tunneling in `local_proxy.rs`, the L4 tunnel client in `l4.rs`, smoltcp-based TUN proxy in `tun_proxy.rs`, per-domain TUN virtual IPs in `virtual_ip.rs`, JNI bindings in `jni.rs`, UniFFI bindings in `uniffi.rs`.
- `ui-android/` — Android app (Kotlin); VPN/TUN orchestration lives in `app/src/main/java/com/nexa/pipe/vpn/NexaVpnService.kt` and calls the Rust client via JNI.
- `ui-desktop/` — Tauri 2 desktop app (Vue 3 + TypeScript, Rust backend in `src-tauri/`).
- Root — workspace `Cargo.toml`, `config.toml`, Dockerfiles, and build scripts (`build_android.bat`, `build_ndk.ps1`, `run_android.ps1`).

## Build, Test, and Development Commands

- `cargo build` — build the workspace.
- `cargo run -p nexapipe -- --config config.toml` — start the server.
- `cargo run -p nexapipe -- --local-proxy` — client local-proxy mode.
- `cargo test --workspace` — run all Rust tests.
- `cargo fmt` and `cargo clippy --workspace` — format and lint.
- Android: `build_android.bat` (NDK build), `ui-android\gradlew.bat :app:compileDebugKotlin`, `run_android.ps1` (install/run on a device).
- Desktop: `cd ui-desktop && npm run tauri:dev` (dev) / `npm run tauri:build` (release).

Host `cargo check` never sees `crates/nexapipe-client/src/tun_proxy.rs` (it is `cfg(target_os = "android")`), so type-check it explicitly after touching the TUN or the L4 client:

```bash
cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy
```

`cargo test -p nexapipe-client --features tun-proxy` still runs on any host: it exercises the platform-independent parts of that feature, today `virtual_ip.rs`.

## Coding Style & Naming Conventions

- Rust edition 2024, default `rustfmt` (4-space indent).
- Rust naming: `snake_case` items, `CamelCase` types, `SCREAMING_SNAKE_CASE` constants; use `anyhow` for errors and gate logging behind `#[cfg(feature = "tracing")]` or the `jni_log!` macro.
- Kotlin: 4-space indent, `camelCase`, follow Android lint.
- Inline comments are mixed Chinese/English; match the file you touch.
- Keep platform code behind features: `jni`, `local-proxy`, `tun-proxy`, `uniffi`.

## Testing Guidelines

- Tests use `#[test]` / `#[tokio::test]`; the server crate's integration tests rely on `duct`, `tempfile`, and `nix` dev-dependencies.
- Name tests descriptively, e.g. `handles_ws_upgrade()`.
- The L4 tests drive `l4::serve_stream` over a `tokio::io::duplex` pair and the client's `l4::open_*` against the same, so a TCP or UDP flow can be tested end to end without an iroh endpoint.
- Run `cargo test --workspace`; for Android changes, compile-verify with `gradlew :app:compileDebugKotlin`.

## Commit & Pull Request Guidelines

- The history uses short generic subjects (e.g. `update`); prefer focused, descriptive messages like `fix(local-proxy): handle CONNECT tunnel close` or `feat(conn): add connection keepalive`.
- Keep one logical change per commit.
- Pull requests: describe what and why, link related issues, and add screenshots/videos for UI or VPN behavior changes.