# Binary size and performance roadmap

Companion to [`ROADMAP.md`](ROADMAP.md). That document records where the product
is going; this one records how much the shipped artifacts weigh, what we intend
to take out of them, and how we will know whether the performance work actually
helped.

| | |
|---|---|
| Last updated | 2026-10-21 |
| Scope | the desktop app bundle, the Android APK, the server archives, the web assets |
| Status | The size half (§4) has not been done. The performance half (§5) has its three benchmarks, and — since 2026-10-21 — a written result: the measurements are in F1's table, and F2's candidate list has been checked against them. |

Nothing in this document has a date or an owner. It is a statement of what we
intend to change and what we refuse to trade away for it, in the same terms
[`ROADMAP.md`](ROADMAP.md) uses. Items are `S*` (size) or `F*` (faster), and
severity labels (`P0`/`P1`/`P2`) mean severity, not priority — the ordering is
[Sequencing](#sequencing).

**A defect is not a roadmap item.** A 40 MB APK is not broken, it is large. The
line between the two is whether anybody is hurt by it, and for a proxy client
the answer is mostly "a download and some disk", which is why none of this is
`P0`.

---

## 1. What we measured

All figures from this working tree on 2026-10-10. Reproduce with
`cargo build --release -p nexapipe`, `./gradlew assembleDebug` and
`npm run tauri:build`.

| Artifact | Size | Note |
|---|---|---|
| Desktop frontend (`ui-desktop/dist`) | 444 KB | the whole web payload; small enough not to matter |
| Android debug APK | 16.5 MB | `assembleDebug` — unminified, unsigned, and **not** what ships. The release APK is built only by `build-apk` (`release.yml:939`) and has never been weighed |
| Desktop Rust binary | **not measured** | this is itself the finding |
| Server binary | **not measured** | same |
| Android `.so` per ABI | **not measured** | same |

Three of the four shipped artifacts have never had their size written down
anywhere, and no CI job records it (§2). **We are therefore optimizing blind.**
Everything in §4 is written with a confidence level attached, and one of the
first deliverables is measuring properly rather than guessing.

### 1.1 Where the desktop binary's size is decided

`ui-desktop/src-tauri` is excluded from the root workspace
(`Cargo.toml:7`, `exclude = ["ui-desktop/src-tauri"]`) — it is a separate cargo
project that happens to sit in the same repository. So the carefully annotated
tuning at `Cargo.toml:27-35`:

```toml
[profile.release]
opt-level = 3
codegen-units = 1
lto = true
strip = true
```

**applies to the server crates and to the Android `.so`, and to nothing on the
desktop.** `ui-desktop/src-tauri/Cargo.toml` has no `[profile.release]` section at
all (the file ends at line 139, on `[[bin]] nexa-service`). The desktop therefore
builds with cargo's defaults: `lto = false`, `codegen-units = 16`,
`strip = "none"`, `panic = "unwind"`.

That is the single largest size lever in this document, and it costs nothing but
build time to pull.

### 1.2 What the server and the Android library already get right

Worth recording, because it is easy to "fix" these and lose ground:

- **`opt-level = 3` is deliberate.** The comment at `Cargo.toml:29-30` says `"s"`
  puts smoltcp's packet path, the QUIC AEAD and rustls under size optimisation
  and that 3 is the cheapest throughput win available here. We are trading a few
  megabytes for packet throughput on the data path, which is the right side of
  that trade for a proxy. **Do not set `"s"` globally.** If `S3` below shrinks
  the Android `.so`, it does it by cutting dependencies, not by flipping this.
- **`panic = "unwind"`** (`Cargo.toml:28`) is required, not incidental. The
  vendored smoltcp patch (`third_party/smoltcp/PATCHES.md`) is about a panic that
  must not take the process down, and `nexapipe-client` is a `cdylib` loaded
  into somebody else's app, where abort is the host's problem now. **Do not
  change this on the library crate.**
- **One APK per ABI** (`ui-android/app/build.gradle.kts:87-102`), with a comment
  explaining why there is deliberately no universal APK. Already correct.

### 1.3 What is turned off

- **Android release is not minified.** `isMinifyEnabled = false`
  (`ui-android/app/build.gradle.kts:118`), and `proguard-rules.pro` is the
  untouched template — every rule still commented out. R8 is available and
  doing nothing.
- **Android resources are not shrunk.** `isShrinkResources` is not set at all.
- **The Android `.so` is probably not stripped.** It is built by `build-apk`
  (`release.yml:757-793`) from the root workspace, so it inherits
  `strip = true` from `Cargo.toml:35` — but whether that reaches an ELF shared
  object in the NDK toolchain is not something this document verified, and a
  `.so` carrying a symbol table is the largest single thing in the APK either
  way. **This is a hypothesis for S1 to settle, not a finding** — which is
  exactly why §1 lists the `.so` size as unmeasured.

### 1.4 The web assets are fine

444 KB total, and nothing in §4 touches it. Two observations, one of which
corrects a natural misreading:

- `dist/assets/useToast-BtxqVAPm.js` is 152 KB, which looks alarming for a
  toast helper. It is not one. `src/composables/useToast.ts` is **122 lines,
  3.4 KB of source**; the chunk is Vite's default chunking merging in every
  module that was not itself split, and the number that matters is that the
  *entire* frontend is under half a megabyte. There is no problem to fix.
- `vite.config.ts` sets no `manualChunks` and no `build` section at all (the
  file is 32 lines). It works. **Leave it alone** — a 444 KB payload is not
  worth a chunking configuration that can drift.

---

## 2. What we are not measuring today

The gap that makes every other number here unreliable.

- **No size reporting in CI.** `release.yml` contains no `size`, `bytes` or
  `MiB` anywhere; `ci.yml` runs 16 jobs (`fmt`, `clippy`, `test`,
  `windows-test`, `features`, `android-ndk`, `audit`, `secrets`,
  `dependency-review`, `desktop-frontend`, `desktop-check`, `desktop-rust`,
  `desktop-audit`, `android-app`, `android-lint`, `build-image`) and not one
  of them weighs anything. The other three workflows do not either:
  `codeql.yml` scans, `pages.yml` deploys, and `dependency-report.yml` — added
  in `#127` alongside v0.6.0, listing outdated dependency versions — does not
  measure anything either. **Weighing the result is nobody's job.**
- **No benchmarks anywhere.** No `criterion`, no `benches/` directory, no
  `#[bench]`. `ROADMAP.md` §4.4 records this as a known gap
  ("no fuzzing, no benchmarks"); this document gives it a work order.
- **The release artifacts are stale.** `ui-desktop/src-tauri/target/release/bundle/`
  holds `nexa_0.1.0_aarch64.dmg` (dated 2026-10-07, 22 MB) while the
  workspace is at `0.6.0`. Whatever that DMG weighs, it is not what v0.6.0
  ships, and it is why the desktop binary size above is blank rather than
  approximate.

---

## 3. Sequencing

```
  S1  measure everything  ──┬──>  S2  desktop release profile  ──> S4  budget gate
                            └──���─>  S3  Android R8 + strip    ──> S4
                                    F1  criterion baselines     ──> F2  targeted work
```

**S1 comes first and everything else waits for it.** Optimizing without a
measurement is how you spend three days on `hyper-util`'s feature flags and
move the binary by 40 KB. S1 is small, mechanical, and it is what makes S2–S4
and F1–F2 verifiable rather than anecdotal.

S2 and S3 are independent and can proceed in parallel — different repositories,
different manifests, different CI jobs. They are deliberately **separate
commits and separate pull requests**: S2 is near-zero-risk and S3 is the
opposite, and bundling them means an R8 regression rolls back the free win too.

---

## 4. Size

### S1 — Measure everything (P0, blocks all of §4)

- A `size-report` job that records every shipped artifact: server archives per
  target, desktop `.dmg`/`.deb`/`.AppImage`/NSIS installer, both APKs, the
  `.so` per ABI, `dist`. Uploaded as an artifact and summarised into
  `$GITHUB_STEP_SUMMARY`, so a PR can say "this change cost 1.2 MB" instead of
  nothing.
- `cargo bloat --release --crates` on the desktop binary and on
  `nexapipe-client`, recorded in the same job. Until this runs, every claim in
  this document about which dependency is expensive is a hypothesis.
- **Deliverable:** a table in this file, filled in, with the command that
  produced each row. Replacing the blanks in §1.

### S2 — Give the desktop a release profile (P0)

- Add `[profile.release]` to `ui-desktop/src-tauri/Cargo.toml`: `opt-level = 3`,
  `codegen-units = 1`, `lto = "thin"`, `strip = true`, `debug = "none"`.
- `lto = "thin"` rather than `true`, deliberately. Fat LTO on a Tauri binary
  that links a webview shim and a service binary is a long compile for a small
  extra gain; `thin` gets most of the size and nearly all the speed.
- **Expected: −25% to −35%. Confidence: high** — this is the difference between
  cargo's defaults and settings that have been measured widely, not a
  NexaPipe-specific guess. The actual figure must come from S1.
- **The cost is build time, and it is real.** `codegen-units = 1` plus LTO on
  a tree this size is a multi-minute release build. Two consequences to decide
  explicitly rather than discover:
  - The profile applies to `tauri:dev` too, so local iteration slows down. The
    mitigation is a `[profile.dev]` or `tauri:dev --profile` escape hatch; the
    decision is ours, not cargo's.
  - CI desktop jobs get slower. `desktop-rust` already builds the same tree, so
    this lands on every PR.
- **`panic = "abort"` is deliberately excluded.** The desktop runs
  `nexa-service` as a long-lived elevated process; whether a panic in the data
  path should take the service down is a real design question, and answering it
  by accident through a size optimisation is exactly the trade this document
  refuses to make. Revisit under F2, with evidence.

### S3 — Turn on Android shrinking (P1)

- `isMinifyEnabled = true` and `isShrinkResources = true`
  (`ui-android/app/build.gradle.kts:118`).
- Keep rules, written from what the app actually does rather than by trial and
  error:
  - the JNI entry points in `com.nexa.pipe.IrohProxy`, which R8 cannot see are
    called — they are looked up by name from native code. Note that
    `release.yml:794-816` already asserts all fourteen `native*` symbols are
    exported; that check catches a broken *link*, and keep rules are what stop
    R8 removing the Java side.
  - `kotlinx.serialization` classes carrying `@Serializable`.
  - anything reached by name through Compose.
- **Strip the `.so`.** Expected to be worth more than anything R8 does to the
  Kotlin half, and it is a one-line step rather than a keep-rule archaeology
  exercise — run `llvm-strip` over
  `jniLibs/${ABI}/libnexapipe_client.so` in the `build-apk` job, after
  `cargo ndk build` and before `cp`. Keep a `-g` variant as a separate uploaded
  artifact so a native crash is still debuggable. S1 establishes how much of
  the APK this actually is; until it does, "largest single thing" is a guess.
- **Expected: APK −40% to −60%. Confidence: medium**, because the whole figure
  rides on how much Compose and the R8 rules give back. Ship it as its own PR.
- **Verification is the hard part, and it cannot be CI alone.** An R8 build
  that is missing a keep rule installs cleanly and crashes on first use. CI can
  assert the APK builds and that the `.so` is present and exports its symbols;
  it cannot assert the app works. **A device run through VPN start, a proxied
  request, a 2FA gate and the QR scanner is required before release**, and that
  is a manual step this document makes explicit rather than assumes.

### S4 — A size budget (P1, after S1–S3 have landed)

- Freeze the measured sizes as budgets with a tolerance, report-only at first.
- Only after one release has shipped clean against the report-only budget does
  it become a gate. A budget that fails the build on its first day is a budget
  that gets deleted.
- Budgets are **per-artifact and absolute**, not relative to the previous
  commit: a relative one silently permits every release to grow.

### Deliberately not doing

- **`opt-level = "s"` on anything.** See §1.2. It trades throughput on the data
  path for size, which is the wrong direction for a proxy.
- **`panic = "abort"` on `nexapipe-client`.** See §1.2 and S2.
- **A universal APK.** Already reasoned and rejected at
  `build.gradle.kts:83-86`.
- **Bundling only what is reachable.** Tauri already tree-shakes the web
  payload against `dist`, and 444 KB is not worth dynamic import gymnastics.
- **Cutting a dependency to save megabytes** before `cargo bloat` has said which
  one costs what. Guessing here is how a proxy loses a security patch.

---

## 5. Performance

### F1 — Benchmarks before optimizations (P0)

**Landed.** The three benches below exist, run in CI on the same runners, and
are written down in [`benchmarks.md`](benchmarks.md) — what each one measures,
how to run it, and what it deliberately does not measure.

Until F1 lands, every performance claim in this document — including the ones
above — is an expectation, not a result, and we have no way to tell whether a
change helped. F1 has landed since, and its result is the table below; the
claims above that it does not cover are still expectations, and §F1 says which.

Three benches, chosen because they are on the paths that carry user traffic:

| Bench | What it measures | Why it matters |
|---|---|---|
| L4 forward | `l4::serve_stream` over a `tokio::io::duplex` pair, both directions concurrently | the raw copy loop; almost certainly already fast, and worth proving |
| TUN pump | `virtual_ip.rs` and the smoltcp packet path | the per-packet cost on a phone, the platform with the least headroom |
| Forwarding path | end-to-end through `local_proxy.rs` | the only bench that reflects what a user experiences |

`cargo test` already covers correctness on all three paths (`AGENTS.md`,
*Testing Guidelines*). F1 adds throughput and latency percentiles next to it,
with `criterion`, run in CI on the same runners.

#### The result

F1's deliverable was never only the benches. §6 asks for "a written result:
either a documented hotspot, or a documented decision that there is not one",
and until this table existed, neither had been written down. The benches had
been running in CI and their output had been going into an artifact nobody
opened. This is that table.

Measured on 2026-10-21, at `7d24761`, on an Apple M4 (16 GB, macOS 27.0.1) with
`rustc 1.99.1`, over a loopback-only setup (no network needed — see
[`benchmarks.md`](benchmarks.md)). Reproduce with:

```bash
cargo bench --workspace --features nexapipe-client/tun-proxy --locked
```

Criterion's numbers are only meaningful on the machine that produced them, so
the machine is part of the result. `slope` is the regression-based estimate and
the one to trust **where criterion computes one**: `mean` and `median` are
given beside it because they say how much variance there was, and here there
is very little. A bench whose round is short enough for criterion to sample
it in Flat mode has no slope at all — it measures the time of a round rather
than the cost of one iteration — and its median is the number to read.

| Bench | mean | median | slope | What the number says |
|---|---|---|---|---|
| `tun_pump/dns_query` | 174 ns | 172 ns | **174 ns** | A DNS query answered from the virtual address pool is **fast**. The cache path is not a problem |
| `tun_pump/ip_mapping` | 2,217 ns | 2,226 ns | **2,274 ns** | **A hotspot.** The mapping's whole job — an allocation and a reverse lookup — measured against the 7,348 ns per-packet path, for what should be a hash lookup |
| `tun_pump/ip_mapping_concurrent` | — | — | **97 ns** | The same lookup with eight tasks at once. Measured on 2026-10-22, on the same machine; only the slope was written down for this run, so the mean and median are left empty rather than invented |
| `tun_pump/packet_copy` | — | — | **18 ns** | The copy the TUN's inbound path makes for every packet. Measured on 2026-10-22, on the same machine; only the slope was written down for this run |
| `tun_pump/tun_packet` | 7,308 ns | 7,244 ns | **7,348 ns** | The whole TUN path: a packet in, an answer out. The per-packet cost on the platform with the least headroom |
| `l4_forward/tcp_flow` | 41,990 ns | 41,716 ns | **42,059 ns** | One 64 KiB payload's round trip through the copy loop. **The copy loop itself is not the problem** |
| `forwarding_path/connect_tunnel` | 811,219 ns | 805,634 ns | **834,955 ns** | The same 64 KiB over an established tunnel, through the local proxy and a real iroh connection. The rate it moves at, not the cost of opening it |

Two more rows, measured on **2026-10-22** on the same machine and toolchain, for
the connections a client's flows open:

| Bench | mean | median | slope | What the number says |
|---|---|---|---|---|
| `flow_connections/connections` | 1 | 1 | — | **One connection for 100 concurrent flows.** It was **100** — one per flow, because a flow took its connection out of the pool and held it until it ended. A flow **borrows** a connection now: the pool keeps it and the flow holds a handle to it. The count does not move: every sample was exactly 1 |
| `flow_connections/open_flows` | 5.132 ms | 5.133 ms | — | How long those hundred flows take to open. It was **1.050 s** — a second, because a hundred connections were made and each of them paid for a handshake. One connection and a hundred streams is **205 times** faster |

The two `flow_connections` rows have **no slope**: a round of that bench takes
about five milliseconds, so criterion samples it in Flat mode — it measures
the time of a round rather than the cost of one iteration — and a Flat run
computes no regression slope at all. The numbers in the slope column of the
rows above are criterion's linear-regression estimate; these two are read from
its median.

The transport is built for the opposite of what the client used to do with it:
one connection can carry 1024 bi-streams, and the client opened one connection
per flow instead. A flow **borrows** a connection now — the pool keeps it, and
the flow holds a handle to it — so the number of connections a hundred
concurrent flows cost is one. That was the largest single per-flow cost in the
client, and it is now a number rather than a reading of the code.

#### What the numbers say, and what they do not

Two things are worth writing down, because "we measured and it is already fast
enough" is a result only when it is specific about *which* part.

**The copy loops are fine.** `l4_forward` at 42 µs is one 64 KiB payload's
round trip through the copy loop — the flow is established before the clock
starts, so the copy is all that is measured, and 64 KiB through it takes 42 µs.
The hot loop is a `read` → `write_all` → `fetch_add` with a reused buffer. The
candidate list's first item ("buffer sizes in the copy loops") is the one the
numbers do **not** support, and it would have been the wrong first move.

**The per-packet path on a phone is where the work is.** `tun_packet` at 7.3 µs
is the number that decides how much battery the tunnel costs, and
`ip_mapping` at 2.3 µs is 30% of it. That bench measures the mapping's whole
job — an address allocation *and* a reverse lookup — and the allocation is the
expensive half of it: the bench holds more names than the pool has addresses,
so every allocation takes the eviction path, which a steady-state packet does
not. Only the reverse lookup runs on every packet, and it is a `String` clone
and a write to a second `HashMap`.

**And the hotspot is gone.** `ip_mapping` is **291 ns** now, against the
2,274 ns in the table above, and the difference is two things: the mapping
shares a name instead of copying it out of the table on every lookup, and the
eviction scan walks the values it already has instead of looking every address
up in a second map to find the quietest one. The bench holds more names than
the pool has addresses, so every allocation takes that scan — which is why it
was most of the number.

**What the numbers do not cover**, and therefore what is still an expectation
rather than a result: the DNS *forward* path (`tun_pump`'s `dns_query` case
passes an empty resolver list and a proxied domain, so it exercises the
hijack branch and never the forward branch), the idle wake-up rate, the
per-TCP-flow memory, the server's request path, and every part of the server
crate's own request handling — `l4_forward` stops at a `duplex` and never
crosses an iroh hop.

**The client's HTTP request path is no longer on that list.** `local_request`
measures it: the plain HTTP path through the client's local proxy — the head,
the domain check, the rewrite, the bi-stream, and the response back — which
is the path `forwarding_path` does not cover, because that one is the CONNECT
tunnel. Its two numbers, measured on 2026-10-22 on the same machine:
`first_byte` at **100 µs** (the time to the response head) and
`request_response` at **138 µs** (the whole request). The far side of that
bench is an HTTP server over an iroh bi-stream on the same host, not the
server crate's own request handling — so what is now measured is the
client's half of a request, and the server's half is still an expectation.

### F2 — Optimize what the benchmarks show (P2)

**Scheduled, and the schedule is F1's table.** The candidate list below was
written as an expectation, to be confirmed or thrown away by measurement. Two
of its four items are now confirmed, one is refuted, and the list has grown
items the numbers pointed at.

1. **Buffer sizes in the copy loops.** **Refuted by `l4_forward`.** The copy
   loop moves 64 KiB in 42 µs, so it is not where the time is. Left alone.
2. **Allocation on the per-packet path.** **Confirmed, and quantified**:
   `ip_mapping` at 2.3 µs is 30% of `tun_packet`, and the part of it that runs
   per packet is a `String` clone plus a second `HashMap` write.
   **Done**: the mapping shares its names instead of copying them, and keeps
   the "last used" clock beside the name it belongs to, so the eviction scan
   is a walk over values it already has. The bench is at **291 ns**.
3. **`hyper-util` feature flags.** Not measured, and not a throughput item —
   it stays a size lever (S1/S2).
4. **Nothing else.** **No longer true.** The numbers, and a reading of the
   code, added: the per-TCP-flow memory of the smoltcp stack (four 320 KiB
   buffers per flow, and the client never lowers the default); the client's
   per-connection buffer footprint; the server's per-request allocations; and
   the body copy that makes the process-wide byte budget count half of what
   the process actually holds.
5. **Not the QUIC or rustls internals** — those are the vendored, audited,
   already-`opt-level = 3` layers, and nobody in this project is going to
   out-tune `ring` by hand. That one still stands.
6. **The connections a flow costs.** **Added on 2026-10-22, and the largest
   per-flow cost measured so far.** `flow_connections` counts the connections
   the far side is given while a hundred flows are open: it was **100**, one
   per flow, because a flow took its connection out of the pool and held it
   until it ended. Opening those hundred flows took **1.05 s**, each of them
   paying for a handshake — against a transport built to carry 1024 bi-streams
   on one connection.
   **Done**: a flow **borrows** a connection now. The pool keeps it and the
   flow holds a handle to it — iroh's `Connection` is a cheap clonable
   handle — and a dial is shared, so a hundred flows arriving together make
   one connection between them and not a hundred. The count is **1**, and
   opening those hundred flows takes **5.1 ms** instead of **1.05 s**:
   **205 times** faster.
   Two things came with it. A connection that carries a flow is **not idle**,
   so the pool's idle timeout no longer closes it underneath the flow — the
   pool counts the flows riding each connection, and the last-use stamp moves
   when the last of them ends, so a connection that has just carried a
   ten-minute flow is fresh for another minute. And the server counts the
   flows on a connection as well — it refuses the one that does not fit — so
   the client keeps below that ceiling itself and opens another connection
   rather than piling every flow onto one.

### F3 — A performance budget (P2, after F1)

Same shape as S4 and for the same reason: a number that is only reported is
worth having, a number that fails the build before anyone trusts it gets
deleted. Realistically this belongs to whoever has run the benches enough times
to know what normal variance looks like — which is precisely why it is `P2` and
not a stated goal.

---

## 6. How we will know this worked

| Measure | Today | Target |
|---|---|---|
| Desktop binary size | never measured; built with cargo defaults | measured, and −25% or better from S2 alone |
| Android APK size | 16.5 MB unminified debug, release never shrunk | measured on the release artifact, and substantially under today's |
| Android `.so` size | never measured; unstripped | measured, stripped, with a `-g` artifact kept |
| Size regressions | invisible | reported on every PR; failing the build only after a clean release |
| Throughput / latency | three benches in CI, and a result written down on 2026-10-21: one documented hotspot (`ip_mapping`, 2.3 µs, measured against the 7.3 µs per-packet path), one documented decision that there is not one (the copy loops), and the gaps the numbers do not cover listed in F1 | F2's list checked against the numbers, and the gaps closed by benches that do not exist yet |

The last row is the one that matters. A roadmap that only ever adds benchmarks
is a plan to feel better without knowing anything. **"We measured and it is
already fast enough" is a successful outcome of F1**, and it is written here as
one on purpose.

---

## 7. Evidence index

Every claim above was checked against this working tree on 2026-10-10, and the
performance half again on 2026-10-21.
Line numbers drift; the command that reproduces each row is given with it.

| Claim | Where |
|---|---|
| The desktop is outside the root workspace | `Cargo.toml:7` — `exclude = ["ui-desktop/src-tauri"]` |
| The tuned profile exists only for the server and the library | `Cargo.toml:27-35`, next to no `[profile.release]` anywhere in `ui-desktop/src-tauri/Cargo.toml` (file ends at line 139) |
| `opt-level = 3` and `panic = "unwind"` are deliberate | `Cargo.toml:29-30` (the comment says why) and `Cargo.toml:28`; the smoltcp patch rationale is `third_party/smoltcp/PATCHES.md` |
| Android release minification is off | `ui-android/app/build.gradle.kts:118` — `isMinifyEnabled = false`, no `isShrinkResources` anywhere |
| ProGuard rules are the untouched template | `ui-android/app/proguard-rules.pro` — every rule still commented out |
| One APK per ABI, no universal APK | `ui-android/app/build.gradle.kts:83-102` |
| The Android `.so` is built with `jni local-proxy tun-proxy` | `release.yml:786` (`--features "jni local-proxy tun-proxy"`), copied into `jniLibs` at `release.yml:789-791` |
| The JNI surface is fourteen functions, asserted in CI | `release.yml:794-816` |
| Nothing in CI measures size | no `size`/`bytes`/`MiB` in `release.yml`; the 16 jobs in `ci.yml:55-628` plus `codeql.yml`, `pages.yml` and `dependency-report.yml` all do something else |
| Benchmarks exist (as of 2026-10-21) | `crates/nexapipe/benches/l4_forward.rs`, `crates/nexapipe-client/benches/tun_pump.rs`, `crates/nexapipe-client/benches/forwarding_path.rs`; `criterion` in `Cargo.lock`; the `bench` job in `ci.yml` |
| The numbers in F1's table | measured at `7d24761` on 2026-10-21 with `cargo bench --workspace --features nexapipe-client/tun-proxy --locked`, on an Apple M4 / 16 GB / macOS 27.0.1 with `rustc 1.99.1`; the `slope` column of `target/criterion/<group>/<bench>/new/estimates.json` is the source — and the `median` column where that run was in Flat mode, which computes no slope |
| `ip_mapping` is a third of the per-packet path | the same run: `tun_pump/ip_mapping` 2,274 ns against `tun_pump/tun_packet` 7,348 ns — the first bench measures an allocation and a reverse lookup, and only the lookup runs on every packet |
| The frontend is 444 KB and fine | `ui-desktop/dist`, measured with `du -sh`; `vite.config.ts` is 32 lines with no `build` section |
| The 152 KB `useToast` chunk is not a bug | `ui-desktop/src/composables/useToast.ts` is 122 lines / 3.4 KB; Vite's default chunking, and the total is under half a megabyte |
| The local bundle is stale | `ui-desktop/src-tauri/target/release/bundle/dmg/nexa_0.1.0_aarch64.dmg` (dated 2026-10-07, 22 MB) against `version = "0.6.0"` |