# NexaPipe Desktop

Desktop client for [NexaPipe](https://github.com/open-nexa/nexapipe), built with
**Tauri 2** (Rust) and **Vue 3 + TypeScript** (Vite). It connects to a NexaPipe
server over iroh/QUIC and forwards selected domains either through a local HTTP
proxy or through a system TUN interface — no public IP required on the server
side.

This tree is part of the NexaPipe monorepo (`ui-desktop/`), and bugs and feature
requests for the app are filed in the monorepo's issue tracker,
<https://github.com/open-nexa/nexapipe/issues>. Its git history was preserved
when it was imported from the former standalone repository.

---

## Features

- **Two forwarding modes, chosen explicitly**
  - *Local proxy* — HTTP proxy on `127.0.0.1`, routes by `Host`, tunnels
    `CONNECT`, and extracts SNI from the raw ClientHello for TLS.
  - *TUN* — a real tunnel (WinTun on Windows) with its own local DNS server, so
    any application works without per-app proxy configuration.
- **An explicit DNS strategy** — what happens to the machine's own name
  resolution while the tunnel is up: `scoped` (only the configured domains go
  through the tunnel, and the machine's own names keep resolving where they
  did), `global` (every query goes through it), or `none` (the machine's DNS is
  not touched and the tunnel's own resolver waits for a PAC file or a hosts
  entry to point at it). The strategy is never changed for you: a machine that
  cannot be scoped says so rather than having its whole DNS replaced.
- **Optional elevated background service** (`nexa-service`) that owns the TUN
  device; the UI talks to it over a local IPC channel. TUN is only offered when
  the service is installed — nothing is probed and nothing is silently
  downgraded.
- Multi-node configuration: several server nodes, each owning a set of domains;
  `round_robin` or `random` load balancing. The same domain on several nodes is
  load balanced automatically.
- Relay control: `pinned` (default), `default`, `custom` URL (with an optional
  auth token), or `disabled`. No "force relay" switch — iroh 1.0.1 offers no way
  to make it true.
- TOTP 2FA credentials (client id, secret, algorithm).
- Live status, in-app log viewer, service install/uninstall.
- Bilingual UI (English + 简体中文), light/dark theme, self-updater.

---

## Architecture

```
┌──────────────────────────── frontend (Vue 3 + TS) ────────────────────────────┐
│  App.vue · router (Dashboard / Config / Logs / Settings)                       │
│  stores: proxy.ts, config.ts, prefs.ts   composables: useTheme, useLocale, …   │
│  i18n: en (source of truth) + zh-CN      ui: AppShell, SideBar, base/*         │
└─────────────────────────────── invoke() ──────────────────────────────────────┘
                                     │  Tauri IPC
┌──────────────────────────── Rust backend (src-tauri) ─────────────────────────┐
│  lib.rs — #[tauri::command]s: start_proxy, stop_proxy, get_proxy_status,       │
│           get_node_id_display, reveal_node_id, install_service, …              │
│           is_service_running, get_startup_error, get_logs                      │
│  proxy/  — manager, local_proxy, tun_proxy (WinTun), dns, routing, packet      │
│  service/— Windows service, elevation helper, IPC server + client              │
│  depends on nexapipe-client (path dependency on ../../crates)                  │
└───────────────────────────────────────────────────────────────────────────────┘
```

`src-tauri` is **excluded** from the parent Cargo workspace
(`exclude = ["ui-desktop/src-tauri"]`) and builds as its own crate, but it
consumes `crates/nexapipe-client` as a path dependency — so the client library
is shared with the Android app and the CLI.

---

## Prerequisites

| | |
| --- | --- |
| Node.js | 24+ (npm) |
| Rust | stable, plus the platform build tools for Tauri 2 |
| Windows | WebView2 (Tauri), WinTun — `wintun.dll` is bundled from `src-tauri/wintun/bin/amd64/` |
| Linux/macOS | System TUN support (`/dev/net/tun`, `utun`); creating one needs privileges |

---

## Getting started

```bash
npm install
npm run tauri:dev        # dev server on :1420 + Tauri window
```

Other scripts:

| Command | What it does |
| --- | --- |
| `npm run dev` | Vite dev server only. |
| `npm run build` | `vue-tsc --noEmit` then `vite build`. |
| `npm run preview` | Preview the built frontend. |
| `npm run tauri:build` | Build the packaged desktop app (also produces updater artifacts). |
| `npm run lint:i18n` | Fail on missing/unused translation keys. |
| `npm run lint:tokens` | Lint design tokens. |

Rust side, from `src-tauri/`:

```bash
cargo check
cargo clippy
```

---

## Layout

```
src/                     frontend
├── pages/               DashboardPage, ConfigPage, LogsPage, SettingsPage
├── components/          ServiceManager, ProxyStatusControl, base/* (design system)
├── stores/              proxy, config, prefs
├── composables/         useTheme, useLocale, useToast, useConfirm, …
├── i18n/                index.ts + locales/{en,zh-CN}.json
└── api/, types/, utils/

src-tauri/
├── src/
│   ├── lib.rs           Tauri commands and app state
│   ├── main.rs          binary entry point
│   ├── bin/nexa-service.rs   background service executable
│   ├── proxy/           manager, local_proxy, tun_proxy, dns, routing, packet
│   ├── service/         Windows service, elevation, IPC
│   └── status.rs, error.rs
├── wintun/              bundled WinTun driver
├── icons/
└── tauri.conf.json      product name `nexa`, identifier `com.nexa.ui`
```

---

## Commands (frontend → Rust)

| Command | Purpose |
| --- | --- |
| `start_proxy` | Start forwarding. Takes nodes, domains, `local_addr`, `dns_addr`, `upstream_dns`, `load_balancing`, `tun_name`, `use_service`, `use_tun`, relay settings and 2FA settings. |
| `stop_proxy` | Stop forwarding (service or in-process). |
| `get_proxy_status` | `{ running, mode }` for the UI indicator. |
| `get_node_id_display` | The local iroh Node ID, masked. What the UI prints. |
| `reveal_node_id` | The same Node ID in full, for the user to copy. |
| `credential_display` / `reveal_credential` | A stored credential masked, or in full — the same split as the Node ID. |
| `install_service` / `uninstall_service` / `is_service_running` | Manage the elevated background service. |
| `get_startup_error` | Failure captured during startup, if any. |
| `get_logs` | Recent log lines for the Logs page. |
| `is_background_launch` | Whether the machine started the app rather than the user. |
| `set_tray_status` | Writes the connection state onto the tray icon. |

Errors come back as structured `AppError` values with stable codes
(`codes::PROXY_TUN_UNAVAILABLE` and friends) that the frontend translates, so
the UI can say exactly why TUN could not start.

---

## Notes and gotchas

- **TUN needs privileges.** The UI only offers TUN when the service is
  installed; requesting TUN without the ability to create the tunnel returns
  `proxy.tun_unavailable` instead of quietly starting a local proxy.
- **`TUN_MTU` must stay 1400** across every TUN implementation (desktop
  `proxy/tun_proxy.rs`, the Android app, and the client crate's `tun_proxy.rs`).
  Two QUIC datagrams per TCP segment is a large throughput regression.
- **QUIC tuning** lives in `crates/nexapipe-client/src/transport.rs`; any new
  `Endpoint::builder(presets::N0)` must call `.transport_config(...)`, or that
  code path falls back to iroh's 1.25 MB stream window and caps each proxied
  connection around 50 Mbps at 200 ms RTT. Overrides without a rebuild:
  `NEXAPIPE_QUIC_STREAM_WINDOW`, `NEXAPIPE_QUIC_SEND_WINDOW`,
  `NEXAPIPE_QUIC_INITIAL_MTU`, `NEXAPIPE_QUIC_KEEPALIVE_MS`.
- **Logs**: `%APPDATA%/nexa/logs` on Windows and `$XDG_STATE_HOME/nexa/logs`
  (or `~/.local/state/nexa/logs`) for the desktop app on Unix; the service writes
  to `/var/log/nexa-service`. Files rotate daily; `RUST_LOG` controls the level.
- **i18n**: `en` is the source of truth and the fallback. `lint:i18n` fails the
  build on a key that exists in one locale only.
- **App icon on macOS comes from `src-tauri/icons/icon.icns`, and nothing
  regenerates it.** Tauri copies that file into
  `nexa.app/Contents/Resources/icon.icns` byte for byte; the PNG entries in
  `bundle.icon` are for Linux and Windows only. Regenerate from the master art
  whenever the logo changes, or a stale `.icns` ships unnoticed:

  ```bash
  swift scripts/gen-icons.swift src-tauri/icons/nexapipe.png   # --mode full-bleed for a square icon
  ```

  `nexapipe.png` is the 1258×1258 master and must stay at least 1024×1024, or
  the large `.icns` representations get upscaled and the Dock icon turns into a
  blurry smear. The script renders every representation from the master at its
  native size and applies Apple's icon grid (824/1024 content box, continuous
  corners). macOS caches Dock icons aggressively: after rebuilding, touch the
  bundle and, if the old icon persists, run `killall Dock`.

---

## Updates

`tauri.conf.json` is configured with the Tauri updater plugin, pointing at
`https://github.com/open-nexa/nexapipe/releases/latest/download/latest.json`
with signature verification enabled. `npm run tauri:build` produces
`createUpdaterArtifacts` output as part of the bundle.

**The platform configs do not repeat the updater block.** `tauri.conf.json` is
merged with `tauri.macos.conf.json` (and its Windows and Linux siblings) as a
JSON merge patch, and a merge patch **removes** a key whose value is `null` —
so a platform config that repeated `plugins.updater` without a `pubkey` would
work by inheritance today and would quietly drop the key the day somebody
wrote `"pubkey": null` into it. The platform configs therefore say nothing
about the updater at all, and the base config's block is used as it is. The
same rule applies to the rest of the updater settings: they live in one place,
and the platform configs do not shadow them.

---

## License

MIT — see the [LICENSE](https://github.com/open-nexa/nexapipe/blob/main/LICENSE)
in the parent repository.
