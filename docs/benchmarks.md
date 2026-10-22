# Benchmarks

Seven benches, on the paths that carry user traffic. They exist because until
they landed every performance claim in this repository was an expectation
rather than a result — the reasoning behind that is in
[`size-perf-roadmap.md`](size-perf-roadmap.md) §F1.

| Bench | Where | What it measures |
|---|---|---|
| `l4_forward` | `crates/nexapipe/benches/l4_forward.rs` | the copy loop of an L4 flow: bytes from the tunnel to the backend and back |
| `tun_pump` | `crates/nexapipe-client/benches/tun_pump.rs` | the TUN's per-packet cost: the DNS path, the virtual-address bookkeeping, and the whole path with a packet in and an answer out |
| `forwarding_path` | `crates/nexapipe-client/benches/forwarding_path.rs` | the end-to-end path: an application, the local proxy, the tunnel, and the copy loop |
| `local_request` | `crates/nexapipe-client/benches/local_request.rs` | the client's local proxy on a plain HTTP request: the head, the domain check, the rewrite, the stream, and the response back |
| `request_path` | `crates/nexapipe/benches/request_path.rs` | the server's work for one request: the route lookup, the balancer, the URI, and the round trip — and how many allocations it makes |
| `flow_connections` | `crates/nexapipe-client/benches/flow_connections.rs` | how many QUIC connections a hundred concurrent flows open, and how long they take to open |
| `route_lookup` | `crates/nexapipe/benches/route_lookup.rs` | the server's routing table: the walk over the routes, and what taking the one it found costs |
| `domain_match` | `crates/nexapipe-client/benches/domain_match.rs` | the client asking whether a name is one of its own: the walk over the configured list |

And one measurement that is not a bench, because what it measures is memory
and not time: [`tun_flow_memory`](#what-a-flow-costs).

## The most recent result

**[`size-perf-roadmap.md`](size-perf-roadmap.md) §F1 has the table.** Measured on
2026-10-21 on an Apple M4 (16 GB, macOS 27.0.1), `rustc 1.99.1` — the rows that
have changed since are marked:

| Bench | slope | The one-line reading |
|---|---|---|
| `tun_pump/dns_query` | 174 ns | the cache path is fast |
| `tun_pump/ip_mapping` | **291 ns** | **was 2,274 ns** at `7d24761`, before the mapping stopped copying names and scanning two maps: it is a hash lookup now, and the hotspot it was is gone |
| `tun_pump/tun_packet` | 7,348 ns | the whole TUN path, per packet |
| `domain_match/in_the_list` | **467 ns** | was 951 ns before the fold stopped copying names: a walk over 51 patterns, asked for every `CONNECT` and every DNS query |
| `l4_forward/tcp_flow` | 42,059 ns | 64 KiB through the copy loop: the copy loop is not where the time is |
| `forwarding_path/connect_tunnel` | 834,955 ns | the same 64 KiB over an established tunnel: the rate it moves at, not the cost of opening it |

The two `route_lookup` rows were measured on **2026-10-22**, on the same
machine and the same toolchain, and are listed separately because they were
measured on a later day than the table above — and because the fold the
routing table now does moved the numbers they report:

| Bench | slope | The one-line reading |
|---|---|---|
| `route_lookup/a_matching_host` | **134 ns** | the routing table's walk over 51 routes, **and** what taking the route it found costs. **Was 732 ns** when the routing table folded the host once per route rather than once per walk, and **999 ns** before the bench's path pattern was fixed — and that number was a lookup that found *nothing*, so the half it claims to measure was never measured |
| `route_lookup/a_host_nothing_serves` | **76 ns** | the same walk over the same 51 routes for a host no route serves: what the walk costs on its own. The difference between the two rows is what taking the route costs |

The two `tun_pump` rows measured on **2026-10-22**, on the same machine and
the same toolchain, are listed separately because they were measured on a
later day than the table above:

| Bench | slope | The one-line reading |
|---|---|---|
| `tun_pump/ip_mapping_concurrent` | **97 ns** | the same lookup, eight tasks at once. The mapping's lock is an **exclusive** one, so the lookups serialise — and that is cheaper than the alternative: a read lock, tried and measured, came out at 357 ns, because making the clock atomic moves two updates out of the lock and into eight cores contending for the same cache lines |
| `tun_pump/packet_copy` | **18 ns** | the copy the TUN's inbound path makes for every packet — the bytes are read into a buffer that is reused, and the stack is handed a copy, because the frame it takes is a `Vec<u8>` of its own. **It is 0.24% of `tun_packet`**, so the allocation it costs is not worth a buffer pool |

The `packet_copy` figure was measured with an earlier version of that bench,
which also timed the read into the buffer and the free of the frame at the
end of each iteration — neither of which the production path pays at that
point. The bench now times the allocation and the copy alone, so the figure
above is an upper bound for what the path pays.

The two `local_request` rows were measured on **2026-10-22**, on the same
machine and the same toolchain, and are listed separately because they are a
different pair of questions from the rest:
The four rows below were measured on **2026-10-22**, on the same machine and
the same toolchain, and are listed separately because they are a different
pair of questions from the rest:

| Bench | slope | The one-line reading |
|---|---|---|
| `local_request/first_byte` | **100 µs** | the time from "the application sends" to "the response head has arrived": what the application waits before it can start rendering |
| `local_request/request_response` | **138 µs** | the whole request: a connection, the request, the response, and the proxy closing it |
| `request_path/allocations_per_request` | **33** | **33 allocations** for one request, from the route lookup to the response head: the per-request work is not free, and now it has a number. **Was 42** before the balancer stopped taking a lock and the backend's address stopped being parsed again for every request |
| `request_path/request` | **50 µs** | the whole of the server's work for one request, backend round trip included. The interval is wide — 37 to 69 µs — because the round trip goes through the scheduler; the allocation count beside it is the one that does not move |

The two `flow_connections` rows were measured on **2026-10-22**, on the same
machine and the same toolchain. A round of that bench takes about five
milliseconds, so criterion samples it in **Flat** mode — it measures the time
of a round rather than the cost of one iteration — and a Flat run computes
**no slope at all**. The number below is the **median**, which is what the
report shows:

| Bench | median | The one-line reading |
|---|---|---|
| `flow_connections/connections` | **1** | **one connection for 100 concurrent flows.** It was **100** — one per flow — before the client let a flow borrow a connection instead of taking it out of the pool. The count does not move: every sample was exactly 1 |
| `flow_connections/open_flows` | **5.1 ms** | how long those hundred flows take to open. It was **1.05 s** — a second, because a hundred connections were made and each of them paid for a handshake. One connection and a hundred streams is **205 times** faster |

Those numbers are what F2's candidate list is checked against, and the same
section lists the paths the numbers do **not** cover — the DNS forward branch,
the idle wake-up rate, and the per-flow memory — so that what is a
measurement and what is still an expectation stays visible. Both crates' HTTP
request paths are now covered: the client's by `local_request`, the server's by
`request_path`, with the caveat that the latter is the plaintext listener's
path rather than the QUIC tunnel's.

None of them needs a network. The backends are loopback TCP echoes, the TUN
device is a `tokio::io::duplex` pair standing in for the fd, and the two iroh
endpoints the forwarding path needs talk to each other over the loopback
interface. That is deliberate: a bench that needs the internet fails on a
runner without it, and a bench that fails is a bench nobody runs.

## Running them

```bash
# Everything. The client's benches are behind its `tun-proxy` feature, which
# is also what `local-proxy` needs.
cargo bench --workspace --features nexapipe-client/tun-proxy

# The same, without the plots and the HTML report. The flag reaches criterion
# alone now, so it is worth knowing about: a run that only wants the numbers
# does not have to write a report to do it.
cargo bench --workspace --features nexapipe-client/tun-proxy -- --noplot

# One of them.
cargo bench -p nexapipe --bench l4_forward
cargo bench -p nexapipe-client --features tun-proxy --bench tun_pump
cargo bench -p nexapipe-client --features local-proxy --bench forwarding_path
cargo bench -p nexapipe-client --features local-proxy --bench local_request
cargo bench -p nexapipe-client --features local-proxy --bench flow_connections
cargo bench -p nexapipe --bench route_lookup
cargo bench -p nexapipe --bench request_path
cargo bench -p nexapipe-client --bench domain_match
```

The release profile of the root workspace is `opt-level = 3` with LTO, so the
first build takes a while and every run after it is fast.

`cargo bench --workspace` runs the criterion targets and nothing else: the
crates carry no `#[bench]` function, and cargo's default bench target for a
crate is a harness with nothing in it — built and *run* in the release profile,
which is the slowest profile there is. Each crate says so with `bench = false`
on its library and binary targets.

It also means the arguments after `--` reach criterion alone. `--noplot` is a
criterion flag, and the default harness refuses an option it does not know and
exits 101 — which is how the CI job used to fail, on `nexapipe --lib`, before
a single benchmark had run.

Criterion writes its report to `target/criterion/<group>/<bench>/` and prints
the numbers it found. The useful parts are the time per iteration, the
throughput, and — when a baseline exists — the change against it:

```bash
# Record a baseline to compare against later.
cargo bench -p nexapipe --bench l4_forward -- --save-baseline before

# Compare against it.
cargo bench -p nexapipe --bench l4_forward -- --baseline before
```

## What each bench measures, and what it does not

**`l4_forward`** establishes the flow first and starts the clock when the
payload does, so what it measures is the copy loop and not the price of
opening a flow. The handshake is a fixed cost per flow rather than a rate,
and the tests cover what it does.

**`tun_pump`** has five parts, from the inside out:

- `dns_query` — the query the system resolver sends, answered from the
  virtual address pool.
- `ip_mapping` — the bookkeeping behind those answers: one address per
  domain, and the reverse lookup that turns a packet's destination back into
  a name.
- `ip_mapping_concurrent` — the reverse lookup with several tasks doing it at
  once. The mapping's lock is exclusive, so the lookups serialise; the case
  is here because the alternative (a read lock) was measured and is **worse**,
  and the next person to look at the lock should find that rather than
  guess it.
- `packet_copy` — the copy that path makes for every packet on its way in: the
  bytes are read into a buffer that is reused, and the stack is handed a
  **copy**, because the frame it takes is a `Vec<u8>` of its own. It is here
  on its own so that its share of the path is visible, because it is the one
  per-packet cost a reader would think was worth removing.
- `tun_packet` — the whole path, with the query arriving as an IP packet on
  the TUN device and the answer leaving as one. The stack in the middle is
  smoltcp's; what is measured around it is ours.

**`domain_match`** is the client asking whether a name is one of its own — the
question every `CONNECT` and every DNS query asks, answered by walking the
list of names the client was configured with. It is a bench of its own because
that list is the one thing in the client whose length a request pays for.

**`route_lookup`** is the server's routing table: every request asks it which
route serves the request, and the answer is a walk over the routes until one
matches. The backends are never dialled — the bench measures the lookup.

It measures two: a host a route serves, and a host no route serves. The
difference between them is what **taking** the route costs, which is the
balancer's part — the part the walk alone does not include.

The path pattern in the table is `/`, which is the catch-all a route uses to
say "any path". **`/*` is not a wildcard**: `path_suffix` treats it as a
literal `/*` prefix, so a route with it matches no ordinary path at all. The
bench used to use it, which meant it measured a walk that found nothing — and
said otherwise. It now asserts that the lookup matched, so the mistake cannot
come back quietly.

**`forwarding_path`** is the only bench that reflects what a user experiences:
the request crosses the proxy's accept loop, the tunnel handshake, the tunnel
itself and the copy loop on the way back. As with `l4_forward`, the tunnel is
established before the clock starts, so the number is about the traffic over
it rather than the price of opening it. The far side is an iroh endpoint on
the same host that speaks the L4 framing and echoes.

**`local_request`** is the other way a request goes through the same local
proxy: not the CONNECT tunnel, but the plain HTTP path a browser takes when it
is told to use the proxy for ordinary HTTP. That path parses the request head,
finds the `Host` header, checks it against the domains the client proxies,
rewrites the headers it forwards, opens a bi-stream, writes the request, and
copies the response back — none of which is in `forwarding_path`'s numbers,
and all of which happens on every request.

It measures two moments:

- `first_byte` — from the application sending to the response head having
  arrived. This is what the application waits before it can start rendering,
  and it is the part a user feels.
- `request_response` — the whole request, from before the connection is opened
  to after the proxy closes it. The difference between the two is the tail:
  the proxy's end of stream and the application's end of file.

Two things about it are worth knowing before reading its numbers into
something. The proxy closes the connection after every response, so **every
iteration opens one** — a real cost the number includes, and the reason the
bench sets `SO_LINGER` to zero on the application's socket: at bench speed,
tens of thousands of connections per minute would otherwise leave the
operating system's ephemeral ports exhausted and the run would fail
partway through. And the far side is an HTTP server over an iroh bi-stream on
this host — the client's half of a request, and not the server's.

**`request_path`** is the server's own work for one request: the route lookup,
the balancer, the URI the backend is reached at, and the round trip to it. The
backend is a loopback HTTP server and the server's client pools the connection
to it, so what is measured is the request rather than the price of opening a
connection.

It measures two things:

- `request` — the time of one request. The interval is wide, because the
  round trip goes through the scheduler and the machine's own load shows up
  in it.
- `allocations_per_request` — **how many allocations one request makes**,
  counted by a global allocator the bench installs. The count is taken around
  the request alone: the lookup, the balancer, the URI, and the request built
  from them — not the response body, which is a lazy stream, and not anything
  the bench allocated itself.

The second number is the one that does not move. It is reported as a duration
in nanoseconds, so the report reads `49 ns` for a request that made 49
allocations; that is the encoding, and it is deliberate, because the number
belongs in the report next to the times.

It is the server's **plaintext listener** path, driven through
`http::proxy_request`. The QUIC tunnel path reaches the same backend through
`http::proxy_to_backend_streaming` and shares the part of the work this bench
is about — the route lookup, the balancer, the origin and the URI. The two
paths build the backend request through different functions, so the header
copying and the body handling are not shared, and this bench measures the
plaintext one. What the tunnel adds on top is the transport, and the
transport is not what these numbers are about.

**`flow_connections`** is the client asking how many QUIC connections its
flows open. The client keeps a pool of connections to each backend, and a
flow **borrows** one of them: the pool keeps the connection, and the flow
holds a handle to it until the flow ends. iroh's connection handle is a
cheap clone, so a hundred concurrent flows share one connection — and a flow
that ends has nothing to give back. The transport is built for that: one
connection can carry 1024 bi-streams.

It measures two things:

- `connections` — how many connections the far side is given while a hundred
  flows are open. The far side counts its own accepts, so the number does not
  depend on anything the client reports about itself. It comes back as
  nanoseconds, so the report reads `100 ns` for a hundred connections; that
  is the encoding, and it is deliberate.
- `open_flows` — how long those hundred flows take to open. Before a flow
  borrowed its connection, each of them paid for a handshake, so this is what
  the connection count costs.

Each round runs on a **fresh pool**, so a round starts with an empty one and
the count is what that round needed. The bench waits for the count to stop
moving before it reads it — a count that has not moved *yet* looks exactly
like a count that has stopped moving, and the far side accepts in its own
task, so reading too early would report that the round opened no connections
at all.

The count does not move at all: every sample was exactly 100 when a flow
**took** its connection out of the pool, and exactly 1 now that a flow
**borrows** it.

## What a flow costs

The benches above measure time. One thing they do not measure is **memory**,
and the per-flow memory was the largest number in the client: a TCP flow in
the TUN stack owns four buffers of the TCP window, so it cost 1.25 MiB of
address space before it had carried a byte.

`crates/nexapipe-client/examples/tun_flow_memory.rs` measures it. It opens a
number of flows through a real stack — one SYN each, which is all it takes
for the stack to create the socket — and reports what they cost: the bytes
the heap was asked for, and the peak resident set.

```bash
cargo run --release -p nexapipe-client --example tun_flow_memory --features tun-proxy

# How many flows, and the window in bytes.
cargo run --release -p nexapipe-client --example tun_flow_memory --features tun-proxy -- 64 131072
```

**The heap number is the one to compare, and the resident set is the one to
be careful with.** The buffers are zeroes, and the pages behind them are not
resident until something writes to them: an idle flow costs its buffers in
address space, not in pages. A flow that carries traffic pays for the pages
it touches, and then the resident set is the honest number.

Measured on 2026-10-21 on an Apple M4 (macOS 27.0.1), with the window the
client used at the time (320 KiB):

| Flows | Heap | Per flow | Resident growth |
|---|---|---|---|
| 32 | 40.1 MiB | 1,280.6 KiB | 256 KiB |
| 64 | 80.1 MiB | 1,280.9 KiB | 528 KiB |
| 256 | 320.2 MiB | 1,280.7 KiB | 1,728 KiB |

And with 32 flows, at three windows — the per-flow cost is four times the
window, which is the whole point:

| Window | Per flow | 32 flows |
|---|---|---|
| 320 KiB | 1,280.6 KiB | 40.1 MiB |
| 128 KiB | 512.7 KiB | 16.1 MiB |
| 64 KiB | 256.7 KiB | 8.1 MiB |

The client's window is 128 KiB now, and it may hold 64 flows at once, so the
TUN's worst case is **32.1 MiB** — 64 flows at 512.8 KiB each — where it was
**320.2 MiB** before: 256 flows at 1,280.7 KiB each.
## What this is not

- **Not a budget.** Nothing here fails a build when a number gets worse. A
  number that is only reported is worth having; a number that fails the build
  before anyone trusts it gets deleted. The budget is a later step
  (`size-perf-roadmap.md` §F3), and it belongs to whoever has run these
  enough times to know what normal variance looks like.
- **Not a comparison between machines.** Criterion's numbers are only
  meaningful on the machine that produced them. The CI job runs them on the
  same runners every time so that two runs can be compared with each other,
  not so that a number in a log can be compared with a number from a laptop.
- **Not a profile.** These say how long a path takes, not where the time goes.
  When one of them says a path got slower, that is the signal to go and look
  for the reason — with a profiler, not with another bench.

## The rule about what counts as a result

A roadmap that only ever adds benchmarks is a plan to feel better without
knowing anything. **"We measured and it is already fast enough" is a
successful outcome** — and it is a result, because it is the first thing in
this repository that says so with numbers behind it.

**2026-10-21:** that first result has been written down. The table at the top
of this page and F1's table in
[`size-perf-roadmap.md`](size-perf-roadmap.md) are it — one documented hotspot
(`ip_mapping`), one documented decision that the copy loops are not a problem
(`l4_forward`), and a list of the paths the numbers do not reach.

Which is the shape of the rule, now that it has been applied once: **a bench
that runs in CI and whose output nobody reads is not a measurement.** The number
has to be written down somewhere, with the machine it was measured on, or the
roadmap item it justifies stays an expectation.
