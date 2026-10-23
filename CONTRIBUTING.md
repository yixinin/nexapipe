# Contributing to NexaPipe

Thanks for looking. This document is the short version of how to get from a
clone to a merged change, plus a list of work that is genuinely open.

## Where things live

NexaPipe is one repository: the server workspace, the Android app and the
desktop app (the two app trees were imported from their former standalone
repos with their git history preserved):

| Directory | What it is |
| --- | --- |
| `crates/nexapipe/` | The server: iroh endpoint, L7 router, TLS passthrough, L4 tunnel, 2FA |
| `crates/nexapipe-client/` | The client library (`rlib` + `cdylib` + UniFFI) |
| `crates/nexapipe-proto/` | The wire format and the rules both sides share, linked by both |
| `ui-android/` | Android app (Kotlin + Compose), formerly `open-nexa/nexa-android` |
| `ui-desktop/` | Tauri 2 desktop app (Vue 3), formerly `open-nexa/nexa-desktop` |

A change to the wire format touches `crates/nexapipe-proto/` and **both** sides —
never hand-encode it on one end.

```bash
git clone https://github.com/open-nexa/nexapipe.git
```

## Getting set up

```bash
cargo build                              # the workspace
cargo test --workspace                   # all Rust tests
cargo run -p nexapipe -- --config config.toml
```

`config.toml` is gitignored; start from `config.toml.2fa.example`.

Checks that CI cannot cover, and that are easy to forget:

```bash
cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy
cargo ndk -t x86_64   check -p nexapipe-client --features jni,tun-proxy
cd ui-desktop/src-tauri && cargo check
cd ui-android && ./gradlew.bat :app:compileDebugKotlin
```

`crates/nexapipe-client/src/tun_proxy.rs` is `cfg(target_os = "android")`, so a
host build never compiles it — those `cargo ndk` lines are the only thing that
type-checks it. Both shipped ABIs need one, because the app builds an APK per
ABI. `ui-desktop/src-tauri` is a separate cargo project, so the workspace lint
gate does not cover it either.

## Before you open a pull request

```bash
cargo clippy --workspace --all-targets    # kept at zero warnings
cargo fmt --all -- --check                # report drift only
```

Do **not** run `cargo fmt --all`: the tree has pre-existing drift in files you
did not touch, and a formatting-only diff buries your change. Format your own
file instead —

```bash
rustfmt --edition 2024 <path>
```

Other house rules:

- One logical change per commit, with a descriptive subject —
  `fix(local-proxy): handle CONNECT tunnel close`, not `update`.
- Platform code stays behind cargo features (`jni`, `local-proxy`, `tun-proxy`,
  `uniffi`). The `uniffi` bindings are proc-macro based, so there is no UDL file
  to regenerate; the module is `uniffi_bindings.rs` (a module named `uniffi`
  would shadow the crate of the same name at the crate root).
- `third_party/smoltcp` is vendored with a patch and wired through
  `[patch.crates-io]` in the workspace root `Cargo.toml`. Do not edit it.
  [`third_party/smoltcp/PATCHES.md`](third_party/smoltcp/PATCHES.md) records
  what the patch changes, why, and the steps for dropping it once upstream
  fixes the panic it guards — read it before touching either file.
- Inline comments are in English.
- New behaviour comes with a test; the L4 tests drive `l4::serve_stream` over a
  `tokio::io::duplex` pair, so a TCP or UDP flow can be tested without iroh.

## Contributing with an AI agent

An agent works here on the same terms as anyone else: a plan approved before the
first edit, a branch based on `upstream/main`, and a pull request that says what
it verified and what it did not.

The mandatory rules for agent work are in [`AGENTS.md`](AGENTS.md). The
end-to-end walkthrough — which verification each kind of change owes, how review
rounds work, and what a finished agent pull request has to report — is
[`docs/agent-contribution.md`](docs/agent-contribution.md). Read it if you are
supervising an agent, or if you are one.

## Good first issues

Bounded, real, and each one is useful on its own. Comments welcome before you
start — say which one you are taking.

**1. Drop the hop-by-hop headers a `Connection` header names** —
`forwards_request_header` (`crates/nexapipe/src/http/mod.rs`) drops the fixed
RFC 7230 §6.1 set, which is half of what the RFC asks for: a request that says
`Connection: x-trace` also makes `x-trace` hop-by-hop, and that one is still
forwarded. Parse the `Connection` value and drop what it names, on the way out
as well as on the fixed set. *Small, and the RFC is the whole spec.*

**2. Refuse a DNS compression pointer that points forward** — `parse_dns_query`
in `crates/nexapipe-client/src/tun_proxy.rs` (and its twin in
`ui-desktop/src-tauri/src/proxy/dns.rs`) follows a `0xC0` pointer to any offset
in the packet that is in range and does not loop. RFC 1035 §4.1.4 only allows a
pointer to an *earlier* name, and a question pointing forward can name a domain
that is not there at all. Refuse it the way an out-of-range pointer is already
refused. *Small; the two copies have to stay in step.*

**3. Per-device credentials** — 2FA is one symmetric secret shared by every
device enrolled under a `client_id`, so a single device cannot be revoked and
anyone who scans an invite QR becomes a legitimate client. Moving the primary
credential to the device's own iroh key (with TOTP as an optional second factor)
fixes both. *Hard, and the largest item here.*

**4. Wire UDP on the desktop TUN** — Android carries UDP flows
(`crates/nexapipe-client/src/tun_proxy.rs`); the desktop path in
`ui-desktop/src-tauri/src/proxy/dns.rs` maps addresses but never opens a UDP
flow. *Hard.*

**5. A short demo** — `screenshots/` holds a few stills and the README links
them, but there is no end-to-end walkthrough: one recording of the Android flow
(scan invite → reach a service) and one of the desktop app would do more for the
project than several of the items above. *Easy, and no Rust required.*

## Labels

Mostly so that `good first issue` actually means something. That label is
reserved for work that has a defined outcome, does not need project-wide context
to start, and has someone willing to answer questions on it — like the five
listed above.

| Label | Means |
| --- | --- |
| `good first issue` | Bounded, self-contained, mentorship available |
| `help wanted` | Worth doing, but nobody on the project has time for it |
| `bug` / `enhancement` / `documentation` | Type of work |
| `security` | Touches the boundary described in the README |
| `needs-triage` | Nobody has looked at it yet |
| `area:server` `area:client` `area:proto` `area:android` `area:desktop` | Which component |
| `blocked:needs-decision` | Waiting on a maintainer call, not on code |

GitHub issue forms cannot pick a label from a dropdown answer, so the templates
only set the type (`bug` or `enhancement`); the `area:*` label is applied during
triage, which is also when `needs-triage` comes off. A documentation issue is
re-labelled `documentation`, whatever the template set.

GitHub has no label file in the repository, so they are created through the API:

```bash
gh label create "good first issue" --color 7057ff --description "Bounded, self-contained, mentorship available"
gh label create "help wanted"      --color 008672 --description "Worth doing, no maintainer has time for it"
gh label create "security"         --color b60205 --description "Touches the security boundary"
gh label create "needs-triage"     --color ededed --description "Nobody has looked at it yet"
gh label create "blocked:needs-decision" --color fbca04 --description "Waiting on a maintainer call, not on code"
for a in server client proto android desktop; do
  gh label create "area:$a" --color c5def5 --description "Component: $a"
done
```

## Reporting security issues

See [Security boundary](README.md#security-boundary) for the known gaps. If you
find something exploitable, contact a maintainer directly rather than opening a
public issue.
