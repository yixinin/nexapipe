# Repository Guidelines

Nexapipe is a Rust workspace: an iroh/QUIC-based proxy server forwarding HTTP/WebSocket traffic to backends, plus a multi-platform client library used by the Android and desktop apps.

## Project Structure & Module Organization

- `crates/nexapipe/` — Server binary and library. Entry point `src/main.rs` (clap CLI: `--local-proxy`, `--generate-secret`); config in `src/config.rs`; iroh connection handling in `src/conn/`; HTTP/WebSocket proxying in `src/http/` and `src/proxy/`; routing in `src/routes/` and `src/lb/`; health checks in `src/health/`; ACME in `src/acme/`.
- `crates/nexapipe-client/` — Client library (`lib` + `cdylib`). Connection pooling in `connection_pool.rs`, domain-to-endpoint mapping in `endpoint_group.rs`, HTTP/CONNECT/WebSocket tunneling in `local_proxy.rs`, smoltcp-based TUN proxy in `tun_proxy.rs`, JNI bindings in `jni.rs`, UniFFI bindings in `uniffi.rs`.
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

## Coding Style & Naming Conventions

- Rust edition 2024, default `rustfmt` (4-space indent).
- Rust naming: `snake_case` items, `CamelCase` types, `SCREAMING_SNAKE_CASE` constants; use `anyhow` for errors and gate logging behind `#[cfg(feature = "tracing")]` or the `jni_log!` macro.
- Kotlin: 4-space indent, `camelCase`, follow Android lint.
- Inline comments are mixed Chinese/English; match the file you touch.
- Keep platform code behind features: `jni`, `local-proxy`, `tun-proxy`, `uniffi`.

## Testing Guidelines

- Tests use `#[test]` / `#[tokio::test]`; the server crate's integration tests rely on `duct`, `tempfile`, and `nix` dev-dependencies.
- Name tests descriptively, e.g. `handles_ws_upgrade()`.
- Run `cargo test --workspace`; for Android changes, compile-verify with `gradlew :app:compileDebugKotlin`.

## Commit & Pull Request Guidelines

- The history uses short generic subjects (e.g. `update`); prefer focused, descriptive messages like `fix(local-proxy): handle CONNECT tunnel close` or `feat(conn): add connection keepalive`.
- Keep one logical change per commit.
- Pull requests: describe what and why, link related issues, and add screenshots/videos for UI or VPN behavior changes.