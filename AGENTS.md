# Repository Guidelines

Nexapipe is a Rust workspace: an iroh/QUIC-based proxy server forwarding HTTP/WebSocket traffic to backends, plus a multi-platform client library used by the Android and desktop apps. TLS is terminated by the backend (Caddy &co), not here: the server copies TLS sessions to a passthrough route selected by SNI (`src/passthrough.rs`) and holds no certificates. Raw TCP and UDP flows reach a route's backend through the L4 tunnel, which the client opens with a `0x05` preface stating protocol, host and port (`crates/nexapipe-proto` defines that wire format for both sides; `src/l4/` is the server half, the client's `src/l4.rs` the other).

## Project Structure & Module Organization

- `crates/nexapipe/` — Server binary and library. Entry point `src/main.rs` (clap CLI: `--local-proxy`, `--generate-secret`); config in `src/config.rs`; iroh connection handling in `src/conn/` (which dispatches on a stream's first byte); HTTP/WebSocket proxying in `src/http/` and `src/proxy/`; TLS/byte passthrough in `src/passthrough.rs`; raw TCP/UDP flows in `src/l4/`; shared byte-copying helpers in `src/stream_util.rs`; routing in `src/routes/` and `src/lb/`; health checks in `src/health/`.
- `crates/nexapipe-proto/` — The wire format and the rules both sides must agree on, linked by both the server and the client so that a rule is written down once: `preface.rs` (magic/version/proto/host/port plus the status byte), `udp.rs` (`u16`-length datagram framing), `auth.rs` (the handshake, the challenge a response signs and the close codes) and `deadline.rs` (the phase budgets both sides use). Change it here, never by hand on one side.
- `crates/nexapipe-client/` — Client library (`lib` + `cdylib`). Connection pooling in `connection_pool.rs`, domain-to-endpoint mapping in `endpoint_group.rs`, HTTP/CONNECT/WebSocket tunneling in `local_proxy.rs`, the L4 tunnel client in `l4.rs`, smoltcp-based TUN proxy in `tun_proxy.rs`, per-domain TUN virtual IPs in `virtual_ip.rs`, JNI bindings in `jni.rs`, UniFFI bindings in `uniffi_bindings.rs`.
- `ui-android/` — Android app (Kotlin); VPN/TUN orchestration lives in `app/src/main/java/com/nexa/pipe/vpn/NexaVpnService.kt` and calls the Rust client via JNI.
- `ui-desktop/` — Tauri 2 desktop app (Vue 3 + TypeScript, Rust backend in `src-tauri/`).
- Root — workspace `Cargo.toml`, `config.toml`, Dockerfiles, and the per-platform local build scripts (`build_dmg.sh` macOS, `build_deb.sh` Linux, `build_windows.ps1` Windows, `run_android.ps1` Android debug loop). Each mirrors the matching CI job: `--version` reproduces the tag-derived version, and `build_deb.sh` runs the same `verify-deb.sh` check as the Linux CI job.

This is a monorepo: `ui-android/` and `ui-desktop/` are plain directories (their git histories were preserved via `git subtree` when they were imported from the former standalone repos `open-nexa/nexa-android` / `open-nexa/nexa-desktop`), not submodules — commit app changes directly here, alongside the server crates. One tag (e.g. `v0.2.0`) releases the server archives, the desktop bundles and the signed APK together from `.github/workflows/release.yml`.

## Build, Test, and Development Commands

- `cargo build` — build the workspace.
- `cargo run -p nexapipe -- --config config.toml` — start the server.
- `cargo run -p nexapipe -- --local-proxy` — client local-proxy mode.
- `cargo test --workspace` — run all Rust tests.
- `cargo fmt` and `cargo clippy --workspace` — format and lint.
- Android: `run_android.ps1` (cargo-ndk cdylib build with `jni,local-proxy,tun-proxy` + install/run on a device), `ui-android\gradlew.bat :app:compileDebugKotlin`.
- Desktop: `cd ui-desktop && npm run tauri:dev` (dev) / `npm run tauri:build` (release); for a release-like package use `build_dmg.sh` / `build_deb.sh` / `build_windows.ps1` from the root.

`crates/nexapipe-client/src/tun_proxy.rs` is shared by Android (fd entry, `TunProxy::new`) and the desktop (`TunProxy::with_io`); only the fd plumbing is android-gated inside. Host `cargo check -p nexapipe-client --features tun-proxy` covers the shared code, but the Android half still needs an explicit cross-check after touching the TUN or the L4 client:

```bash
cargo ndk -t arm64-v8a --platform 26 check -p nexapipe-client --features jni,local-proxy,tun-proxy
```

`cargo test -p nexapipe-client --features tun-proxy` still runs on any host: it exercises the platform-independent parts of that feature, today `virtual_ip.rs`.

## Coding Style & Naming Conventions

- Rust edition 2024, default `rustfmt` (4-space indent).
- Rust naming: `snake_case` items, `CamelCase` types, `SCREAMING_SNAKE_CASE` constants; use `anyhow` for errors and gate logging behind `#[cfg(feature = "tracing")]` or the `jni_log!` macro.
- Kotlin: 4-space indent, `camelCase`, follow Android lint.
- **English only.** Comments, doc comments, log and error messages, docs, config examples, commit messages and PR descriptions are written in English, even when the conversation with the user is in Chinese.
- The **only** exception is real i18n: `ui-android/app/src/main/res/values-zh-rCN/strings.xml`, `ui-desktop/src/i18n/locales/zh-CN.json`, a language's own name in its own script (the `zh-CN` entry in `ui-desktop/src/i18n/index.ts`, the "Bilingual UI" line in `ui-desktop/README.md`), and code or tests whose point is handling non-ASCII text (the percent-encoding test in `crates/nexapipe/src/auth/otpauth.rs`). Do not add Chinese anywhere else — not in a Rust, Kotlin or Vue comment, not in `README.md` or a CI workflow, not in a log line, not in a `config.toml*` example.
- Keep platform code behind features: `jni`, `local-proxy`, `tun-proxy`, `uniffi`.

## Testing Guidelines

- Tests use `#[test]` / `#[tokio::test]`; the server crate's integration tests spawn the built binary with the `duct` dev-dependency and use `tempfile` for scratch configs.
- Name tests descriptively, e.g. `handles_ws_upgrade()`.
- The L4 tests drive `l4::serve_stream` over a `tokio::io::duplex` pair and the client's `l4::open_*` against the same, so a TCP or UDP flow can be tested end to end without an iroh endpoint.
- Run `cargo test --workspace`; for Android changes, compile-verify with `gradlew :app:compileDebugKotlin`.

## Task Execution Workflow (MANDATORY)

Do not jump straight into edits. For any task that writes something:

1. **Plan first.** Restate the goal, read the relevant code/config, then produce a concrete plan: which files change, what each change does, what could break, and how it will be verified (build/test/lint commands, CI jobs).
2. **Ask before acting.** Present that plan and wait for explicit approval. Surface assumptions, alternatives and risks; when several approaches exist, list them and let the owner choose.
3. **Execute only after approval** and stay inside the agreed scope. Stop and re-ask if the task grows, uncovers a bigger problem, or needs files that were not in the plan. Work happens in a worktree created off the newest `main` (see Git Workflow — Worktrees & Branch Base), never in the main checkout.

No approval is needed for read-only work: answering questions, reading files, searching, explaining code, or producing a report / scan-only listing. Anything that writes, deletes, or has external effects does need it.

## Repositories & GitHub CLI (MANDATORY)

This checkout is a **fork**, and the two remotes are not interchangeable:

- `origin` — the fork `yixinin/nexapipe`. Branches are pushed here, so this is where a pull request's **head** branch lives.
- `upstream` — the project `open-nexa/nexapipe`. Pull requests are opened, reviewed and merged **here**, against `upstream`'s `main`.

A PR therefore spans two repositories: its head branch is in `origin`, the PR itself is in `upstream`. `git push origin <branch>` updates an open PR; `gh pr merge` acts on the upstream PR.

- The `gh` CLI's default repository is set to `open-nexa/nexapipe` for this checkout (`git config remote.origin.gh-resolved`), so `gh pr list`, `gh pr view` and `gh pr checks` work **without** `-R`; passing `-R open-nexa/nexapipe` is still correct and harmless. Asking the fork instead returns an empty list — that is a wrong answer, not "there are no pull requests".
- `gh` is authenticated as `yixinin` with the `repo` scope, so it reads both repositories.
- Before starting work, look for an existing PR on the branch you are about to touch: `gh pr list --state open --json number,title,headRefName`. A branch that already carries an open PR is where a fix belongs (see the PR-fix exception in the worktree rules below), not a new branch.
- `origin/main` and `upstream/main` are usually the same commit, but the fork's `main` can lag. `upstream/main` is the one to branch from.

## Git Safety Rules (MANDATORY)

- **Committing and pushing working branches is allowed.** Once the work is verified, the agent may `git commit` it on its working branch and `git push` that branch to the fork (`origin`), including the head branch of an open PR — the PR itself lives in `upstream` (see Repositories & GitHub CLI). Stage files by name, review `git status` before committing, and never commit secrets.
- **Still ask first** before anything that rewrites or removes shared history or publishes a release: force-push (`--force`, `--force-with-lease`), pushing to `main`, deleting a remote branch or tag, pushing tags, and `gh release ...`.
- Do not run history/discard commands (`git reset --hard`, `git checkout --`, `git clean -fd`, `git stash` without being asked, branch switches that drop work) unless explicitly requested.

## Git Workflow — Worktrees & Branch Base (MANDATORY)

- **Anything that changes code must be done in a dedicated git worktree, never in the main checkout.** The main checkout is `~/rust/nexapipe` and stays on `main`; the worktrees under `.worktrees/` are separate checkouts that happen to live inside it, and the main checkout's own working tree is not one of them. This covers code, docs, configuration and CI files — every write goes through a branch in a worktree. Only read-only work may happen in the main checkout: reading, searching, explaining code, answering questions, producing a report or a scan-only listing.
- **Every new branch is based on the newest `main`.** Do not start from the local `main` ref alone: the fork's `main` regularly lags upstream. Fetch the upstream head and branch off that commit:

  ```bash
  git fetch --no-tags upstream main
  git worktree add .worktrees/<branch> -b <branch> upstream/main
  cd .worktrees/<branch>
  git merge-base --is-ancestor upstream/main HEAD   # verify the branch really sits on newest main
  ```

  The directory path is the branch name verbatim (`v070/audit-fixes` → `.worktrees/v070/audit-fixes`), so two branch names can never land on the same directory. Create the parent directory first: `git worktree add` does not.

  If the `upstream` remote is missing, add it once with `git remote add upstream git@github.com:open-nexa/nexapipe.git`. If the upstream lookup is unreachable, fall back to the fork: run `git fetch --no-tags origin main` and then `git merge --ff-only origin/main` from the local `main` — a fetch only moves `origin/main`, and the local branch is moved by the merge, never by `reset --hard` — then branch off `origin/main`. State explicitly in the reply which commit was used as the base.
- **Worktree location:** `<repo>/.worktrees/<branch>`, with the branch name used verbatim (`v070/audit-fixes` → `.worktrees/v070/audit-fixes`) — inside the repository rather than beside it, so that reading and writing a worktree's files goes through the same file-access path as the rest of the project instead of prompting for a separate permission on every call. `.worktrees/` is listed in `.gitignore` and `.dockerignore`. Keep `<repo>/.workbuddy/` worktrees for throwaway simulations only (merge rehearsals, release-note scratch): those are git-ignored and expire with the task.
- **Point searches and reads at the worktree you are working in.** A search rooted at the repository root does not descend into `.worktrees/`: each worktree is a separate git repository and a hidden directory, and the search tools skip both. The same holds for `.workbuddy/`.
- **Exception — a fix to an open PR reuses that PR's branch and worktree.** When the task is fixing a bug in an existing open PR, work on that PR's own head branch, in that branch's existing worktree. Do not open a fresh branch and do not create a second worktree for it: the fix belongs in the PR that carries the defect, not in a parallel branch that has to be cherry-picked afterwards. Locate the worktree with `git worktree list` before starting, and check `git status` in it — if it holds unrelated uncommitted work, stop and ask instead of mixing the fix into it. The "newest `main`" rule above governs new branches only; a PR branch keeps its own base and history.
- Set the worktree up only after the plan is approved; until then stay read-only.
- **Never delete a worktree on your own initiative**, least of all one holding unpushed commits — ask first. After a reboot, `/private/tmp` is gone, so run `git worktree prune` before rebuilding anything that referenced it.

## Working Files & Plan Documents (MANDATORY)

- **Temporary plan / fix / patch documents written by the agent go to `.workbuddy/` (git-ignored), never into the repository tree** (no `PLAN.md`, `TODO.md`, `docs/*plan*`, `docs/*fix*`, `docs/*patch*`, etc. in tracked paths).
- Only durable, curated docs belong in the repo (e.g. `AGENTS.md`, `CONTRIBUTING.md`, architecture decision records). One-off reasoning and step-by-step plans live in the conversation or `.workbuddy/` and expire with the task.
- Put "why this change" explanations in the commit message or PR description, not in a sidecar plan file.

## Commit & Pull Request Guidelines

- The end-to-end walkthrough — lifecycle, verification by change type, the review loop and the handoff report — is [`docs/agent-contribution.md`](docs/agent-contribution.md). This file states the rules; that one shows the order to apply them in.
- The agent commits and pushes its own verified work on its working branch (see Git Safety Rules) and may open the pull request for that branch once it is pushed. Merging, closing, tagging and releasing stay with the owner.
- The history uses short generic subjects (e.g. `update`); prefer focused, descriptive messages like `fix(local-proxy): handle CONNECT tunnel close` or `feat(conn): add connection keepalive`.
- Keep one logical change per commit.
- Pull requests: describe what and why, link related issues, and add screenshots/videos for UI or VPN behavior changes.