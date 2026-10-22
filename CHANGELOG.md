# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
One tag releases everything at once: the server archives, the desktop bundles
and the signed Android APK come out of `.github/workflows/release.yml`.

For what comes next, and for why some things are deliberately not planned, see
[docs/ROADMAP.md](docs/ROADMAP.md).

**The next release is v1.0.0.** The v0.7.0 release planned for this cycle was
cancelled after a review of the project against comparable products; the scope
that replaced it, and the items that were deliberately dropped from it, are
recorded in [§0 of the roadmap](docs/ROADMAP.md#0-the-v100-decision-2026-10-20).
Nothing that shipped in 0.6.1 changes: every configuration key keeps its name
and its meaning.

## [Unreleased]

Nineteen things land in this cycle so far: the device credential can be a **key**
instead of a shared secret, every phase of a proxied exchange now runs under a
deadline the operator can see and raise, backend handling no longer stops at
plain HTTP/1.1 with no second chance — the hop can be encrypted, retried and
circuit-broken — the ceilings the process runs under are now something a
config file can say rather than only an environment variable can, a name is
spelled the same way in a client's list and in the server's routes, a client
can be held to the ports it may reach and not only to the names, both clients
can say how far away the path carrying the traffic is, the desktop app can
stay in the tray instead of ending with its window, the third-party boundary
is two settings now rather than one, the Android app can bring the tunnel back
after a restart, the Android client picks its address block instead of
hard-coding one, the server's runtime state lives in a file of its own beside
the configuration instead of inside it, the desktop says what it does to the
machine's DNS instead of deciding for itself, the access log says what a
tunnelled flow was instead of only what the tunnel did with it, an app that
is not written in Rust can configure a client through the UniFFI surface, the
paths that carry the traffic can be measured instead of assumed, the first
result of those measurements is written down, a route that rewrites the paths
it serves now rewrites them for the tunnel as well, and the Android client's
tunnel descriptor is closed exactly once.
No existing configuration key is removed or renamed, and the ones this cycle
adds — `public_key` under a device entry, the six `[timeouts]` phase keys,
`[limits]`, `[backends] ca_file`, `[retry]`, `[circuit_breaker]`,
`allow_ports` under a client entry and `[iroh] discovery` — are optional, so a
`config.toml` that works on 0.6.1 still loads and behaves as it did: a device
entry that carries a `secret` is checked exactly as before, a `[timeouts]`
section that names none of the new keys leaves every deadline at its default,
and a config with no `[limits]` section runs with the ceilings it always ran
with.
Leaving `[retry]` out keeps one try and no second chance, leaving `[backends]`
out uses the machine's own trust store, and leaving `[circuit_breaker]` out uses
its defaults — which are on. Leaving `allow_ports` out leaves a client with
every port it had, and leaving `[iroh] discovery` out keeps n0's address
lookup, which is what a config written before the key existed does.

### Added

- **Three small things on the server's response path.**
  The **WebSocket's copy loop** moved 8 KiB at a time where the HTTP path
  coalesces into 64 KiB, and it had **no bound at all** -- only the handshake
  was bounded, so a WebSocket whose two sides both went quiet kept a backend
  connection, a task and a stream slot for as long as the process lived. It
  now moves 64 KiB and is bounded by the same `response_idle` deadline the
  HTTP path uses. The bound is on the **session**, not on a side of it: a
  WebSocket that is quiet in one direction is still a WebSocket -- a client
  that only listens to a feed the backend keeps pushing has nothing to say --
  and what ends the session is neither side having moved for a whole window.
  The window is measured with a **monotonic** clock: the wall clock steps with
  NTP and with a machine waking from sleep, and a step forward would end a
  session that was still carrying traffic.
  The copy buffer is 64 KiB of **heap** per direction rather than 8 KiB of
  stack, so a session costs 128 KiB where it cost 16 KiB.
  Every **response header's name** was copied to lower case, once per header
  per response -- for a name that was already lower case, because HTTP header
  names are case-insensitive and the parser folds them.
  The **connection pool's idle reaper** had no clock: the timer that was set
  is the h2 half's, and the pool's own 120-second idle timeout was only
  enforced lazily, at the next checkout. A connection to a backend that
  stopped answering now sits in the pool for 120 seconds and no longer.

- **The server answers the handshake in the form it was asked in.** The
  handshake message has two forms — the JSON one every client already speaks,
  and the binary one — and the payload's first byte says which one it is. The
  server reads all of them: a client that speaks one form and a server that
  speaks another still complete the handshake, and the answers come back in
  the form the client asked in.
  **The client uses the binary form now.** It announces the version it speaks
  inside the first message — the JSON one, where a server that predates the
  version byte ignores the field — and the exchange from the challenge onwards
  is in that form. A client that announces nothing is still answered in the
  JSON it asked for, so an old client keeps working against a new server and a
  new client keeps working against an old one.

- **The authentication handshake has a binary form.** The message the client
  and the server exchange now has two forms: the JSON one every peer already
  speaks, and a binary one that is a third of the size where the bytes are —
  a nonce and a signature are arrays of decimal numbers in JSON, so each byte
  of either costs three. One handshake — a start, a challenge, a response and
  an answer — is 427 bytes of JSON and 124 of binary.
  The binary form is **on the wire for a client that asks for it**: a client
  announces the version it speaks inside its first message, and the exchange
  from the challenge onwards is in that form. A client that announces nothing
  still gets the JSON it asked for, so an old client keeps working against a
  new server and a new client keeps working against an old one.
  A payload's first byte says which form it is in, and a payload that does
  not start with a version byte is the JSON one — which is what every peer
  sent before the version byte existed.
  `algorithm` is a closed type on the wire now: it was a free-form string,
  and a name nobody supports was a name the receiving side had to decide what
  to do with. Its spelling is unchanged — the canonical lowercase one the
  server has always sent.

- **The 2FA handshake is exercised end to end.** Nothing drove
  `perform_authentication` over a stream, so the deadline, the close codes
  and the registration-inside-the-lock rule were covered only by unit tests of
  their pieces. A test now does the whole handshake over a real connection: a
  correct code gets in, a wrong one is refused and the connection is closed
  with the code that says so, a client that does not handshake at all is
  closed with the code that says the handshake was required, and a device
  that proves itself with a key gets in without a code.
- **The UniFFI surface can configure a client.** The `uniffi` feature used to
  export five functions around one server and no credentials, which is not a
  surface an app can build a client on: a real deployment has several servers,
  each with its own `[auth.clients]` entry, and a server with 2FA on refuses a
  client that cannot authenticate. The surface is now one object — servers with
  their domains, their TOTP secret or their one-time enrollment token, the load
  balancing strategy and the relay mode — and it answers what the tunnel is
  doing: the path and round-trip time of every server, what each has carried,
  and the flows that are open. The local proxy is there too, because a socket,
  a port and a domain list cross a language boundary and a packet stream does
  not: **the TUN is not part of it**, and an app that wants the tunnel itself
  has to reach for the C ABI.
- **The access log says what an L4 flow was.** A tunnelled flow carries bytes,
  so its line used to record only what the tunnel did with them — the
  protocol, the target, the outcome, and nothing else. The first bytes of a
  flow usually say more than that: a `ClientHello` names the host it is going
  to, and a plaintext HTTP exchange says what was asked for and what came
  back. The server now reads those bytes as they go past and appends what
  they said to the line — `sni=www.example.com` for a TLS handshake,
  `http="GET /v1/items HTTP/1.1" http_status=404` for a plaintext HTTP one.
  It is a reading and nothing more: the route was chosen by the preface
  before a payload byte arrived, so nothing in the log can name a different
  backend than the one that served the flow, and the status column still holds
  the outcome of the tunnel rather than the answer of the origin behind it. A
  flow that says nothing recognizable gets no field rather than a guess, and a
  query string in a sniffed target is redacted like any other.
- **There are benchmarks.** Three of them, on the paths that carry user
  traffic: the L4 copy loop, the TUN's per-packet cost (the DNS path, the
  virtual-address bookkeeping, and the whole path with a packet in and an
  answer out), and the end-to-end forwarding path through the local proxy.
  None of them needs a network — the backends are loopback echoes, the TUN
  device is a duplex pair standing in for the fd, and the two iroh endpoints
  the forwarding path needs talk to each other over the loopback interface —
  and they run in CI on the same runners as the tests, so two runs can be
  compared with each other. Nothing fails the build when a number gets
  worse: a number that gates a build before anyone trusts it gets deleted.
  What each bench measures, and what it deliberately does not, is written down
  in [`docs/benchmarks.md`](docs/benchmarks.md).
- **The latency of the tunnel, on both clients.** A client already reported
  *how* traffic reaches a backend — directly or through a relay — and now
  reports how far away that path is as well: the round-trip time iroh
  measures for the path carrying the traffic, shown beside the path badge
  on the desktop dashboard and on the Android endpoint screen. The two are
  read from one answer, so they cannot describe different paths, and a path
  iroh has not measured yet shows nothing at all rather than "0 ms" — a
  number nobody measured is not a number.
- **The endpoint's address lookup can be switched off.** `[iroh] discovery` on
  the server — `n0` (the default) or `none` — and the same choice on both
  clients. `none` takes n0's DNS and pkarr lookups off the endpoint, so
  nothing about it reaches `dns.iroh.link`, and the endpoint neither publishes
  its address there nor resolves anyone else's through it. The price is that a
  Node ID alone no longer reaches it: a peer has to bring an address of its
  own, which is what a ticket carries. Hole punching, direct addresses and the
  configured relay are untouched. A value that is present but unknown refuses
  the start rather than falling back to `n0`.
- **A `[limits]` section for the process-wide ceilings.** The connections one peer
  may hold, the connections the whole process may hold, the streams in flight and
  the bytes of request bodies held at once were reachable only through four
  environment variables, so a deployment that described itself in a `config.toml`
  had to describe its own limits somewhere else — and a limit nobody wrote down
  is a limit nobody knows is in force. `[limits]` names all four:
  `max_connections_per_peer` (default 64), `max_connections_global` (4096),
  `max_streams_global` (16384) and `max_body_bytes` (1 GiB). Every key is
  optional and every default is the ceiling the server always used, so a config
  that does not mention the section behaves exactly as it did. A zero is refused
  at startup for every key — a ceiling of 0 would refuse every connection
  rather than bound them — and it is refused even when the matching environment
  variable is set, because the environment overrides a value that works, not
  one that does not. An unknown key is refused at load, before the server
  starts at all, because a misspelled limit is one that silently does not
  apply. The three connection and stream ceilings are counted against the
  iroh tunnel — that is where a peer is — while the byte budget is shared by
  both listeners. The four
  environment variables still work and still win over the
  file, so a deployment that set them keeps the behaviour it had; a key both name
  is a warning in the log rather than a refusal, and the effective ceilings are
  printed at startup. Read once at startup, so editing them takes a restart.
- **Per-device Ed25519 keys.** An entry under
  `[auth.clients.<id>.devices.<name>]` can carry `public_key` — the public
  half of an Ed25519 pair, 64 hex characters — instead of `secret`, and that
  device then proves itself by signing each connection's challenge (the nonce
  and the timestamp) instead of answering with a TOTP code. What the server
  holds is no longer itself a credential: a leaked config yields no way in *as
  that device*, and the private half never leaves the device. It still holds
  the client's own `secret`, though, which answers for any peer that names no
  device until `unnamed_device_allowed = false`. A wrong signature counts
  toward the lockout exactly like a wrong code. A device entry carries exactly
  one of the two — both, or neither, is refused at load.
- **`nexapipe client add <id> --device <name> --public-key <hex>`** registers
  the public half from the shell, with the same replace semantics as the
  secret path (`--force` to rotate); `client list` marks a key device with
  `key`.
- **Enrollment can issue a key.** A client built on the client library can
  offer a public key while it spends its one-shot enrollment token
  (`Enrollment::with_key`); the server records it and answers with an empty
  secret, and the client authenticates every later connection with
  `TwoFactorAuth::with_key`. An older server ignores the offered key and
  issues a secret as before, which the client then uses.
- **Both apps can hold a device key.** A `v=2` registration invite — the one
  that carries a one-shot token instead of a secret — now enrolls the device
  with a key of its own on both the desktop and Android, with nothing asked of
  the user and no change to the invite format. The private half is generated on
  the device, sealed at rest beside the other credentials, and never leaves it;
  the public half is what the server records and what the app displays, so an
  operator can tell which key a server has on file. A server that predates keys
  ignores the offer and issues a secret as before, which the app then uses, so
  the same invite works against both.
- **Six `[timeouts]` keys for the per-phase budgets.** `header_secs`,
  `body_secs`, `response_idle_secs`, `l4_flow_secs`, `l4_idle_secs` and
  `tls_hello_secs` bound, respectively, how long a client may take to send its
  request head (default 30), its request body (300), how silent a response body
  may go between chunks (120), how long an L4 tunnel may run (3600), how idle a
  UDP flow may go (60) and how long a TLS ClientHello may take (10). Every key
  is optional; absent means the default, and the per-route
  `flow_timeout_secs` still overrides `l4_flow_secs` for one route alone. Zero
  is refused at load — a zero deadline closes the phase the moment it opens —
  and so is anything past a day, which is a bound that never fires. A stream's
  first byte says which protocol it carries, and until it arrives the protocol
  is unknown, so the wait for it is the longer of `header_secs` and
  `tls_hello_secs`: a short `header_secs` never cuts off a TLS session or an
  L4 tunnel, neither of which sends a request head at all.
- **Backend TLS and HTTP/2.** A route may name an `https://` backend, and the
  proxy reaches it over a TLS session it originates and verifies — against the
  machine's own roots plus an optional `[backends] ca_file`, with no switch that
  skips the check. The proxy still holds no certificate and still terminates
  nothing; this is the client half of a handshake. HTTP/2 is negotiated through
  ALPN with an `https://` backend that offers it, and
  `backend_protocol = "h2c"` reaches a cleartext backend that speaks HTTP/2 with
  prior knowledge. A WebSocket upgrade uses the same trust store and reaches an
  `https://` backend over TLS as well; an `h2c` route refuses a WebSocket
  because an upgrade is HTTP/1.1. A backend that offers only h2 over TLS can
  serve HTTP requests, but this proxy's WebSocket path is HTTP/1.1 and cannot
  use it.
- **`[retry]` tries a failed request again.** `attempts` (default 0, capped at
  16) is the number of extra attempts and `backoff_ms` (default 100, capped at
  60000) the wait between them. A retry asks the route for a different backend
  where it has one. A request that never reached the backend is retried whatever
  its method is; one that was carried and lost is retried only when it is
  idempotent. An answer, a response already partly received, and a WebSocket are
  never retried. The plaintext listener and the iroh tunnel both apply it.
- **`[circuit_breaker]` takes a failing backend out of rotation.** It is on by
  default: `failure_threshold` consecutive unreachable-backend failures (default
  5, capped at 1000) open the circuit for `reset_secs` (default 30, capped at
  3600), during which a route with nothing else serving answers 503 instead of
  dialling a backend the traffic already showed is down. A trial request after
  the cooldown can close it again, and an answer resets the count. Failures that
  broke halfway are not counted — the backend answered — and TCP/UDP routes keep
  using the health probe rather than a request counter. The HTTP request paths,
  the tunnel's streaming path and a WebSocket handshake all feed the counter; a
  session that dies after the upgrade does not.
- **The Android app can bring the tunnel back after a restart.** A proxy that
  has to be switched on by hand every time the phone is switched on is not an
  always-on proxy, and on a phone that is the difference between a machine
  that is protected and a machine that is not. "Reconnect after a restart"
  brings it back by itself: a `BOOT_COMPLETED` receiver starts the VPN
  service, which waits for a network, builds the tunnel with the same sequence
  a connection the user asked for uses, and establishes it.
  The switch is off until the user turns it on — a proxy that reconnects
  without being asked forwards traffic without being asked.
  Two things it does not do, on purpose. It does not take the VPN slot from
  another app: the boot path never answers the takeover question, because a
  tunnel that quietly revoked somebody else's VPN at seven in the morning
  would be a surprise nobody could prepare for. And it does not enrol an
  endpoint: enrolling spends a token and answers with a credential that has
  to be stored, and a boot has nobody to ask about a device that cannot
  protect one — an endpoint waiting for that waits for the user.
  Android does not promise that the permission a VPN app was given survives a
  restart, so the boot path asks rather than assumes. When the permission is
  gone the tunnel stays down and the settings page says so, rather than
  leaving a switch that is on and nothing that happened.
- **The desktop app can stay in the tray.** Closing the window used to end the
  process, so a proxy that had to be started by hand every time the machine woke
  was not the always-on proxy the settings page promised. The app now has a tray
  icon: the window goes there instead of ending the app, and the icon brings it
  back. "Minimize on close" is on by default, and the switch that was there for
  it now works — on a desktop with no tray it says so and the close button
  keeps ending the app, because a hidden window with nowhere to come back from
  is an app nobody can reach.

- **`allow_ports` limits a client to the services it may reach.** `allow_hosts`
  says which *names* a client may reach, and a name is not a service: a host
  that answers on three ports is one name and three things to reach. The new
  key is the other half of the same question — `allow_ports = [443, 8443]` —
  and the two are independent: a client may be limited to one host and every
  port, or every host and one port.
  Checked where the client names a port. The tunnel preface always names one,
  and an HTTP request's `Host` header may; a request that names no port is not
  checked, because there is no port to hold against it. A TLS passthrough is
  not checked either: the route picks the port and the client never names one.
  What the list separates is the tunnel: the preface names the service the
  client wants, and the route decides where that service is answered from —
  `client_ports` only picks the route, it never decides where the connection
  goes. So the port the preface names is the service the client reached, and
  that is the port the list is held against. The HTTP path routes by host
  alone, so a port named in a `Host` header is checked but is not the port the
  request is served from — two services of one host are told apart by the
  tunnel, not by this list.
  A refusal looks exactly like "no route" — a 404, a `NoRoute`, a hang-up —
  so it cannot be used to probe what is open behind the proxy. Left unset, a
  client keeps the reach it had; an empty list denies every port that is
  checked. The reading `allow_hosts = []` has is the stricter of the two: it
  denies every name, with no path around it, while a port is only denied
  where one is checked.
  a port of zero is refused at startup, because no client ever asks for it.

- **The first benchmark result is written down.** The three benchmarks that
  landed with the cycle have been running in CI since they were added, and
  their output was going into an artifact nobody opened — which is the same
  thing as no measurement at all. The numbers are now in
  [`docs/benchmarks.md`](docs/benchmarks.md) and in §F1 of
  [`docs/size-perf-roadmap.md`](docs/size-perf-roadmap.md), together with the
  machine they were measured on, because a criterion number only means
  something on the machine that produced it.
  The result is one hotspot and one decision that there is no hotspot. The
  virtual-address bookkeeping measures 2.3 µs against the 7.3 µs the whole
  per-packet path takes — a third of it — for what should be a hash lookup,
  and the part of it that runs on every packet is a `String` clone and a
  write to a second `HashMap`. The L4 copy loop is not where the time is: a
  64 KiB payload's round trip through it takes 42 µs, so the candidate list's
  first item — bigger buffers in the copy loops — was the wrong first move
  and is not made.
  The list of what the numbers do **not** cover is written down next to them:
  the DNS forward branch, the idle wake-up rate, the per-flow memory, and
  both crates' HTTP request paths. Those are still expectations, and saying
  so is what keeps the ones that are results honest.
- **The server's request path is measured, and it is counted.** The
  benchmarks that landed with this cycle measured the CONNECT tunnel, the
  TUN's per-packet cost, the server's routing table and the client's own
  name matching. None of them measured what the server does for a request:
  the route lookup, the balancer, the URI the backend is reached at, and the
  round trip to it. That is a benchmark of its own now, and it comes with
  the number the per-request work had never had — **42 allocations** for
  one request, from the lookup to the response head, counted by an
  allocator the bench installs.
  The count is the stable measurement: its interval is 0.2% wide, where the
  time beside it — 50 µs for the whole request, backend round trip
  included — runs from 37 to 69 µs, because the round trip goes through the
  scheduler.
  It is the plaintext listener's path, and the difference is written down
  rather than left out: the QUIC tunnel reaches the same backend through
  another function and shares the part of the work this bench is about -- the
  lookup, the balancer, the origin and the URI -- while the header copying
  and the body handling are its own, and what it adds on top is the
  transport. So the server's own work for a request is a measurement now; the
  transport's share of one is still an expectation.
- **The client's HTTP request path is measured too.** The benchmarks that
  landed with this cycle measured the CONNECT tunnel, the TUN's per-packet
  cost, the server's routing table and the client's own name matching. They
  did not measure the path a browser takes through the local proxy when it
  uses it for ordinary HTTP rather than for a tunnel: the request head is
  parsed, the `Host` header is found and checked against the domains the
  client proxies, the forwarded headers are rewritten, a bi-stream is
  opened, the request is written and the response is copied back. None of
  that was in any of the numbers, and all of it happens on every request.
  It is a benchmark of its own now, with two: **100 µs** from the
  application sending to the response head arriving — the wait before a
  page can start rendering — and **138 µs** for the whole request, from
  before the connection is opened to after the proxy closes it.
  It measures the client's half of a request. The far side of the bench is
  an HTTP server over an iroh bi-stream on the same host, so what the
  server does with the request is still not measured, and the list of what
  is not measured says so.
- **A flow borrows a connection now, instead of taking it out of the pool.**
  The client keeps a pool of connections to each backend, and a flow used to
  take one out of it and hold it until the flow ended — so while a flow was
  running its connection was not in the pool, and a hundred concurrent flows
  needed a hundred connections. The transport is built for the opposite: one
  connection carries 1024 bi-streams.
  A flow **borrows** a connection now. The pool keeps it; the flow holds a
  handle to it, and iroh's connection handle is a cheap clone — *"may be
  cloned to obtain another handle to the same connection"* — so a hundred
  flows share one connection and a flow that ends has nothing to give back.
  A **dial is shared** too: everything that asks for a connection while one
  is in progress waits for that one rather than starting its own, so a
  hundred flows arriving together make one connection between them and not a
  hundred. That matters most when the backend is down: one failed dial is
  paid for once, not once per flow.
  The numbers: a hundred concurrent flows now open **one** connection where
  they opened a hundred, and they open it in **5 milliseconds** where it
  took **1.05 seconds**. Two hundred and five times faster, and a hundred
  fewer handshakes for the peer to make. The number is measured, not read off
  the code: the far side counts its own accepts, so it does not depend on
  anything the client reports about itself, and each round runs on a fresh
  pool so that the count is what that round needed rather than what a
  previous round left behind.
  Three things about it are worth knowing. A connection with a flow on it is
  **not idle**, so the pool's idle timeout no longer closes it underneath
  the flow — the pool counts the flows riding each connection for exactly
  that, and the last-use stamp moves when the last of them ends, so a
  connection that has just carried a ten-minute flow is fresh for another
  minute. The server counts the flows on a connection as well and refuses
  the one that does not fit, so the client keeps below that ceiling itself
  and opens another connection rather than piling every flow onto one; a
  refusal is tried again on a connection of its own instead of failing the
  flow. And a connection that turns out to be broken is closed, which now
  takes the other flows on it down with it; they retry, and they retry on a
  new connection.
- **The routing table's benchmark measures a lookup that matches.** Its 51
  routes all had the path pattern `/*`, which is not a wildcard — it is a
  literal `/*` prefix, and a route with it serves no ordinary path at all.
  The walk went over all 51 routes and ended at the table's end with **no
  route taken**, while the benchmark's name and the documentation both said
  it was measuring what taking the route costs. That half was never
  measured.
  The pattern is `/` now — the catch-all a route uses to say "any path" —
  and the benchmark asserts that the lookup matched, so the mistake cannot
  come back quietly. It measures two things now: **732 ns** for a host a
  route serves, and **533 ns** for a host no route serves. The difference is
  what taking the route costs, which is the balancer's part.
  The number recorded before — 999 ns — was a lookup that found nothing, and
  it is kept in the documentation marked as what it was.

- **The host is folded once per request, not once per route.** The routing
  table walks its routes until one matches, and every route in the walk was
  folding the client's name again — trailing dots off, brackets off, case
  folded — for the same name, over and over. The fold now happens once for
  the whole walk, and the routes are handed the folded name.
  It is the same name every time, so the fold is the same answer every time,
  and doing it once is not a different answer: the HTTP path, the TLS
  passthrough path and the L4 path all fold exactly as they did before, and
  the tests that pin the matching rules still pass unchanged.
  The numbers, from the routing table's own benchmark: a host a route
  serves goes from **732 ns** to **134 ns**, and a host no route serves
  from **533 ns** to **76 ns**.

- **The health check reads the backends' status once a round, not once a
  backend.** The status table was read **inside** the loop that probes the
  backends, so the whole table — every backend's status, and a copy of its
  address — was read again for each backend in it. One round of probes over
  fifty backends read the table two thousand five hundred times, every
  interval, for no reason: a probe reports, it does not change the state, so
  the answer is the same every time it is asked.
  It is read once now, and looked up.

- **Choosing a backend takes no lock, and one allocation instead of three.**
  The balancer's choice happens on every request, and it took the status lock
  once per backend to read whether each was healthy, again to compare the
  addresses, and once more to hand the lease out — and the lease kept a **copy**
  of the address, although the entry already had it. It also built three
  vectors where one would do.
  The address and the health flag now sit on the entry, where reading them
  needs no lock, and the candidates are filtered **in place** rather than
  copied into a new vector at each step. One request makes **39 allocations**
  where it made **42**.
  The health flag is an atomic now, so the operator's view and the request
  path cannot disagree about it: the flag is written once, and both read it.

- **The backend's address is parsed once, not once per request.** Two places
  built the backend's URI for every request, and both parsed the address to
  do it — a `Url::parse`, a copy of the host, and a formatted string. A
  **backend does not move**: its scheme, host and port are fixed when the
  route is configured, and they were being parsed again for every request
  that chose it.
  The origin is now parsed when the pool is built, and the request path
  borrows the answer. The address is **shared** rather than copied, so
  handing it to a request is a reference count.
  One request makes **33 allocations** where it made **42** — nine fewer
  across the balancer's choice and the backend's address, both of which were
  doing per-request work for values that are fixed.
  The errors are the same ones, in the same words: a backend whose address
  does not parse, or names no host, is still reported when the request is
  built, where the operator reads it.
- **Two of the TUN's per-packet costs are measured, and neither is worth
  changing.** The TUN copies every packet once on its way into the network
  stack, because the stack takes a `Vec<u8>` of its own and the buffer the
  bytes were read into is reused. That copy — the allocation and the memcpy
  together — costs **18 ns**, against the **7.3 µs** the whole per-packet path
  takes: **0.24%**. A buffer pool would need a lock of its own, and the lock
  would cost more than the allocation it replaces.
  The reverse lookup takes the mapping's lock **exclusively**, so the lookups
  of several flows serialise. Making it a read lock was tried, and it is
  **worse**: moving the clock and the "last used" out of the (serialising)
  lock puts eight cores on the same two cache lines, and the lookup went from
  **97 ns to 357 ns**. The critical section is far too short for the
  parallelism to pay for the contention.
  Both are benchmarks now, so the numbers are visible rather than assumed —
  and the next person to look at either one finds the measurement instead of
  the guess.

- **The connection-level receive window has a ceiling.** The transport gave
  every stream a 4 MiB receive window and left the **connection's** window at
  `VarInt::MAX` — which is no limit at all. A peer with a thousand streams
  could therefore have 4 GiB of its data in this process, and nothing the
  server does could stop it.
  The connection now has a window of its own: 64 MiB, which is sixteen full
  per-stream windows and carries 320 MB/s over a 200 ms path — more than any
  link this runs over, so it is a ceiling rather than a limit. What it buys
  is that the memory one connection's peer can make this process hold is
  bounded to that window. The bound is per **connection**: a process that
  holds several connections to the same peer holds one window for each, and
  the server's own cap on the connections one peer may open (64 by default)
  multiplies it from the other end, so a peer that spends its whole allowance
  still asks for 4 GiB.
  It is the same tuning the two ends already share, so the client and the
  server move together, and `NEXAPIPE_QUIC_RECV_WINDOW` sets it for whoever
  wants another number.

- **Opening a flow gets one budget, not a timeout per attempt.** Two retry
  loops sat inside each other and each attempt had a timeout of its own, so a
  CONNECT that could not be opened had **nine** thirty-second timeouts to
  spend and could take **six minutes** to say so. The budget is taken once
  now, at the start, and every attempt inside it shares what is left:
  **ninety seconds**, which is what the three outer attempts were each
  reaching for anyway.
  The attempts themselves are unchanged — a dead pooled connection is still
  retried on a fresh one, and a refusal is still final — and so is the
  health accounting.

### Changed

- **The client speaks the binary form of the handshake.** A handshake with a
  server that knows it is 189 bytes instead of 427: the message is a binary
  form with a version byte in front of it, and the bytes that cost three
  bytes each — the nonce and the signature, which the JSON writes as arrays of
  decimal numbers — cost one each.
  **A client against a server that does not know it still works.** The first
  message says which version the client speaks, inside the JSON, where a
  server that predates the version byte drops the field it does not know; the
  answers then come back in the old form and the client answers in the old
  form. The version byte is a discriminator and not a negotiation: a message
  says what it is, and the other end reads it.

- **A key the config file does not know is an error now.** Every section of
  `config.toml` refuses the keys it does not have, and so does the top level:
  `exposee = true` under `[server]` used to be dropped without a word, and the
  server it produced was exactly a server with the key left out — for a key
  that gates reachability, a typo and "off" were the same deployment. The
  error names the key and says what to do about it: remove it, or fix its
  spelling.
  One key is worth naming, because a config can carry it today: `[admin]
  token` is not a key. The admin token is generated into
  `<config>.admin-token`, and that file is the only source of it, so a config
  that names a token is refused rather than parsed and dropped — the operator
  finds out that the token they set is not the token in use, instead of
  finding it out when the management surface answers 401.
  The keys that were *removed* rather than misspelled keep working:
  `tls_enabled`, `tls_listen_addr`, `cert_path` and `key_path` under
  `[server]` — and the same two under a route — are still parsed and still
  warned about, `default_backend` is still refused by name, and `[acme]` is
  still ignored with a warning. The three sections that already refused
  unknown keys (`[auth]`, `[limits]` and `[peers]`) keep refusing them. A
  `config.toml` that only carries keys this build knows loads exactly as it
  did.
- **A guess at a pending enrollment token no longer locks the client out of
  authenticating.** A client id is not a secret: it is in the invite link, in
  `nexapipe client list` and in whatever the operator pasted into a ticket. So
  anybody who knew one could send enrollment attempts at a client that was
  waiting to enroll — and, because those attempts were counted against the
  client's own `failed_attempts`, lock out the devices that had already
  enrolled, over a credential those devices were never sent.
  The token keeps its ceiling: `max_attempts` wrong guesses close the
  enrollment for the lockout window, and the right token is refused with it.
  What changed is which counter pays. The guess moves the enrollment's own
  `enrollment_failed_attempts` and `enrollment_locked_until`; the client's
  `failed_attempts` and `locked_until` stay where they were. The two are
  listed side by side in `GET /v1/clients`, and the enrollment's counter is
  written to `state.toml` beside the client's — so it survives a restart
  without ever touching the credential the devices hold. A successful
  enrollment clears the guesses with the token it spent, and a config reload
  carries the counter the server has been maintaining rather than the file's
  older copy — except when the file carries a new token, which starts with its
  own budget.
  A client whose devices have already enrolled goes on authenticating
  throughout.

- **A route's `path_pattern` is a prefix in the path sense.**
  `path_pattern = "/api"` used to match `/apifoo` as well as `/api/x`: the
  rule was `starts_with`, and a prefix that is not a prefix is a routing
  surprise — whether it matters depends on the deployment, and it is never
  what the pattern says. It now ends at a segment boundary: `/api` covers
  `/api` and `/api/x`, and not `/apifoo`. A trailing slash on the pattern
  (`/api/`) names the same place as `/api`.
  The rewrite follows the same rule, so the suffix it computes is the suffix
  that matched. One consequence worth naming: a rewrite on the root pattern
  (`path_pattern = "/"` with `path_rewrite = "/v2{}"`) used to produce
  `/v2api/users` — the separator was dropped — and produces `/v2/api/users`
  now.
- **The configuration and the runtime state are two files.** `config.toml` is
  the operator's file — what they wrote, what they read, what they keep in
  version control — and it no longer carries what a running server learns.
  The 2FA counters (`failed_attempts`, `locked_until`, `last_used`) move to
  `state.toml` beside it, in the same shape and with the same client and
  device names, and the server writes that file and nobody else does. The
  separation is not only tidiness: the server watches the configuration's
  modification time, so a server that wrote its counters into the
  configuration turned every mistyped code into a configuration reload — the
  routes rebuilt and the health checks restarted, because a stranger typed a
  code wrong. The counters are now written where nothing is watching them.
  Nothing has to be set up: the state file appears the first time a client
  authenticates or mistypes a code, it is `0600`, and a state file that cannot
  be read stops the server from starting — the lockouts it holds would be
  unknown, and starting anyway would reset every one of them. A configuration
  written before the state file existed still works: the three counter keys are
  read from it, so a deployment that was counting there keeps its lockouts
  until the state file has an entry for that client. They are not written back
  there any more, and `config.toml` is never rewritten for them.
- **The desktop says what it does to the machine's DNS, instead of deciding
  for itself.** What happens to a machine's name resolution while the tunnel is
  up is now a setting — `scoped`, `global` or `none` — with `scoped` as the
  default. Scoped points only the configured domains at the tunnel and leaves
  everything else — an internal zone, another tunnel's names — resolving where
  it always did; global points every query at the tunnel; none does not touch
  the machine's DNS at all, and the tunnel's own resolver keeps running for a
  PAC file or a hosts entry to point at.
  **This changes what the desktop does on a machine it cannot scope.** It used
  to fall through to the global hijack — silently replacing the machine's whole
  DNS — whenever the per-domain mechanism was unavailable (a Windows machine
  that takes its NRPT rules from a domain policy, say) or the configured domain
  list could not be named to the operating system at all (a bare `*`, or a name
  without a dot). Now it refuses the tunnel and says why, and the global
  strategy is one setting away for the machine that needs it. A machine that
  could be scoped is unaffected: it was already scoped.
- **The Android client picks its address block instead of hard-coding one.**
  The TUN used to claim `10.0.1.0/24` whatever network it was on, and that is
  the block a great many home routers hand out — on those networks the tunnel
  swallowed the router's own addresses and the device could not reach the
  machine that was serving it. The app now walks the same list of candidate
  blocks the desktop has always used (`198.18.0.0/24` first) and takes the
  first one nothing on the device has claimed, and every address inside it —
  the DNS server, the per-domain answers, the IPv6 half — is derived from that
  block rather than written down on both sides. The list itself now lives in
  the client library, so the two clients cannot drift apart. The desktop's
  layout is untouched: it keeps its own addresses inside the block and its own
  fixed ULA, and only the block and the list are shared.
- **"Launch at startup" writes a real entry.** The switch has been on the
  settings page since the page existed, calling two commands that were never
  registered — so it read `false` and wrote nothing, and looked like a setting
  while behaving like a decoration. It now writes an entry for the platform: a
  value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` on Windows, a
  LaunchAgent in `~/Library/LaunchAgents` on macOS, a `.desktop` file in
  `~/.config/autostart` on Linux. All three are per-user and need no elevation,
  and none of them starts anything at the moment the switch is flipped — the
  platform's own login mechanism reads the entry at the next login, so turning it
  on does not put a second copy of the app on the machine mid-session. The entry
  starts the app with `--background`, which means no window: the app comes up in
  the tray instead of putting a window over whatever the user was doing at
  login.
- **The client's list of names and the server's routes are spelled the same
  way.** A pattern is a name (`app.example.com`), a dotted wildcard
  (`*.example.com` — its subdomains, and not the name itself) or the
  catch-all (`*`), on both sides. Three places used to answer "is this name
  mine?" differently: the server matched a request or a preface against a
  route's `host_pattern` strictly, the client read a bare domain as the name
  *and* every subdomain, and the desktop carried a second copy of the
  client's rule that only applied on some platforms — on Windows a query is
  local-delivered to the app's own DNS server and on macOS and Linux it
  reaches the library's, so the same config answered differently depending on
  the machine. The rule now lives in `nexapipe-proto`, which both sides
  already link.

  **This changes what a bare domain means in a client's list.** `example.com`
  used to mean the name and every subdomain on the client; it means the name
  alone now, which is what the server always read it as. A client that wants
  the subdomains writes `*.example.com`, and a client carrying an older list
  says so in its log, once, at startup. A wildcard without the dot
  (`*example.com`) used to be a bare `ends_with` on the client and matched
  `notexample.com` with it; it matches nothing now, and the server has always
  refused the spelling. The dot-prefixed spelling (`.example.com`) is refused
  as well: it is the suffix form a resolver uses, not a pattern here.
  The client's own lookup of the backend that serves a name follows the same
  rule now: a wildcard mapping serves the names it covers, a bare mapping
  serves its own name alone, and a name written the way DNS writes it — with
  the trailing dot — finds the same backend. A client that configured
  `*.example.com` used to decide that `www.example.com` belonged in the
  tunnel and then fail to find the backend for it, so the request went to the
  default backend or to none.
- **`relay_mode = "custom"` now means it for the peer as well.** A custom
  client dials its peer through the relay you run and nothing else: a peer
  whose address names a different relay is refused, and the refusal says which
  relay the peer named and which one this endpoint uses. Before, iroh's
  `relay_mode` bounded only the relay the endpoint itself registered with, so
  a peer advertising an N0 relay was still dialled through it.

  A peer named only by a Node ID is dialled while the endpoint may still ask
  n0 where that peer is — finding it means asking n0, whose answer may be an
  n0 relay, and that is the operator's own trade to make. With the lookup off
  (`discovery = "none"`) such a peer cannot be reached at all, and it is
  refused rather than pretended for. A deployment that wants the peer reached
  through one relay only needs a ticket, which carries the address, and both
  ends on the same relay.
- **The handshake proves a credential, not necessarily a TOTP secret.** Which
  kind of credential a device has comes from the server's own record, not
  from a wire discriminator, so no message variant or scheme field was added,
  and the handshake of every device that keeps a secret is byte-for-byte
  unchanged.
- **TOTP is the enrollment-time factor.** For a key device no seed reaches
  the device at all; the human moment stays with the invite and the one-shot
  token, and no unattended path has a prompt to answer. Both apps still
  enroll and answer with TOTP secrets — holding a key in the desktop and
  Android UIs is planned for the next release.
- **The per-phase deadlines themselves arrived earlier in this cycle, with the
  process-limits work, and are what the six keys above configure.** Before
  that, a client that trickled one byte before each expiry could hold a
  header read, a body read or an L4 flow open indefinitely; now a phase
  deadline is taken once and never renewed, and only the bounds that are
  *meant* to re-arm — a response's gap between chunks, a UDP flow's
  gap between datagrams — do. The idle bound on a response body now covers the
  plaintext listener too, where a backend that sent its head and then went
  silent used to hold the request open for as long as it liked; such a
  response now fails instead of being truncated quietly, so the client can
  tell a short body from a whole one. On that listener the body is handed on as
  data chunks, so an HTTP/1.1 response trailer is dropped — the streamed iroh
  path has always done the same, and request trailers are not forwarded either.
  One of these is a behaviour change
  worth noticing: an L4 tunnel now closes after an hour of existence even if
  it is busy, so a long-lived SSH or database session over the tunnel needs
  `l4_flow_secs` raised (or a per-route `flow_timeout_secs`).
- **`least_conn` counts a streaming response until it ends.** The lease that
  holds a backend's outstanding count used to be released when the response
  head arrived, so a large download or an SSE feed counted as finished while
  the backend was still working on it and the next request could be sent to an
  already-busy backend. The lease now travels with the body and is released
  when the body is dropped — by the client reading it, or by the connection
  going away. The tunnel path already worked this way; both paths now agree.
- **The circuit breaker is on by default.** A backend that fails five requests
  in a row leaves rotation for thirty seconds even when `[circuit_breaker]` is
  absent. An operator who wants the old behaviour — every
  request dials whichever backend the balancer picked — sets `enabled = false`.
  A single-backend route can therefore answer 503 for up to `reset_secs` after
  five consecutive connect failures, where it used to return 502 each time.

### Fixed

- **The WebSocket request line is rebuilt from the parsed request.** The
  client rebuilt the line it sends from the raw bytes of the one it
  received, and the HTTP version came out of that split — so a request line
  carrying a bare LF put the rest of the line into the version token, and
  the proxy sent a request whose first line a lenient parser would read as
  two. The method and the version come from the parsed request now, where
  both are validated.
- **Replacing a credential no longer leaves the old identity connected.** The
  handshake runs once per connection, so a connection made under the previous
  credential kept serving traffic under the previous identity after the
  credential had been replaced — and the server, which closes a connection
  when it learns the credential is gone, was never told. The pool's
  connections are closed when the identity changes, and kept when only the
  secret was rotated: a rotation is the same account with a different secret,
  and dropping the pool for that would close every request in flight.
- **A UDP frame that announces more than a datagram is refused.** The length
  prefix is a `u16`, so a frame can announce up to 65535 bytes — and a
  datagram over IPv4 cannot carry more than 65507, because the IP header's
  total-length field is sixteen bits wide. The encoder on the other side
  refuses to produce one, so a frame that size is a peer that is not speaking
  the protocol; the rule now lives in the shared framing crate and both ends
  of the tunnel apply it.
- **Revoking one device says what the shared secret still is.** `client revoke
  <id> --device <name>` strikes one device out and leaves the client's own
  secret standing — and that secret is still a credential: a peer that names
  no device answers with it, because `unnamed_device_allowed` is `true` by
  default. The revoke said the secret was untouched; it did not say what that
  means or how to change it. It names the setting now, and when the setting is
  already off it says the untouched secret authenticates no one instead of
  claiming it still does.
- **The comments about the config file's permissions tell the truth.** The
  startup refusal over a world-readable config was removed on purpose
  (ROADMAP §3.5), so that a `0644` bind mount starts — but several comments
  still described it, and one still said the server "refuses to *start*" over
  one. What is left is a warning, and it is there: the config says so itself
  now, in the places that used to claim otherwise.
- **An invite's relay hint has to name a relay this client can reach.** The
  hint was accepted whenever the URL parser accepted it, so `ftp://`,
  `file:///etc/passwd` and a bare `http://` all passed. The scheme, the host
  and the length are checked now, and the n0-operated relays are refused for
  the same reason the configuration refuses them. A code past a hard limit is
  refused rather than parsed.
- **A stream leaves its connection in the pool.** The client's
  `open_bi_stream` returned the two streams and dropped the connection, so
  the pool never saw that connection again: every call dialled a new one, and
  the pool lost a slot each time. The connection now goes back into the pool
  when the exchange is done. The pool's idle stamp is also named after what
  it is — the last use, not the creation.
- **The client refuses a request that names more than one host.** The client
  picked the first `Host` that matched a proxy domain and forwarded the head
  byte for byte, so a request with two `Host` headers reached the server, which
  refused it with a 400 — a failure that looks like a proxy bug rather than a
  request that cannot be answered. The client refuses it now, with the same
  400, before any tunnel is opened.
  The authority is also split the way the server splits it: taking everything
  before the first colon left an IPv6 literal as `[`.
- **A configuration reload reads the file once, and not under the auth
  lock.** The file was read twice — once for the routes and once for the 2FA
  clients — so the two halves could be applied from two different revisions of
  it, and the second read happened while the auth write lock was held: every
  handshake and every lockout write waited for the disk. The reload now takes
  one snapshot, reads it outside the lock, and merges it under. An enrollment
  that lands while the file is being read is noticed and the file is read
  again, so a spent token is never handed out twice.
- **A value the server cannot read is refused.** `algorithm = "sha-512"`,
  `strategy = "round-robin"` and `mode = "pass-through"` were each quietly
  turned into something else: SHA1, round-robin and `http`. Both ends of the
  handshake read the same config, so a name nobody supports does not fail on
  one side and the other — the deployment just runs differently from the one
  in the file, and nothing says so. The three keys are refused now, with an
  error that names the key, the value and the spellings that are accepted.
  Every spelling that has always worked still works.
- **The client refuses an algorithm it does not support.** The client's
  parser matched `sha256` and `sha512` and turned **everything else** into
  SHA1 — `sha-256`, `SHA3-256`, a typo, an empty string. A name that is
  quietly turned into a different algorithm is a silent downgrade: the client
  computes codes the server does not accept, and every attempt fails with
  "wrong code" rather than the algorithm being named once as unsupported.
  The client had a strict parser and a lenient one, and the lenient one was
  the one every configuration path went through; there is one now, and it
  refuses a name nobody supports. The Android client already behaved this
  way, so the two agree.
- **The L4 sniffer reads its buffer once.** Every chunk appended to that
  side's buffer and then re-ran the decision over the **whole** buffer, so a
  peer that opens a flow with something this proxy does not read — an SSH
  banner, a database greeting — and then dribbles it out one byte at a time
  made the sniffer rescan everything it had buffered, on every byte, up to
  16 KiB: 268,451,840 bytes examined for 16,384 bytes of flow. The scan keeps
  its position now, so the cost is linear. The answer does not change: the
  bytes that were scanned and held no line are not looked at again.
- **The desktop's DNS server keeps its sockets.** The desktop had a second
  DNS implementation — its own resolver chain, its own timeouts, its own
  socket handling — and like the client's it built **a new UDP socket for
  every query** it forwarded. It now uses the same shared resolvers, so every
  lookup leaves from the same source port and the NAT mapping the router
  keeps for it is the one that stays. The chain, the order and the windows
  are unchanged.
- **A response is not forwarded with the backend's own hop headers.** The
  tunnel dropped only `transfer-encoding` and `x-request-id`, so
  `connection`, `keep-alive`, `upgrade` and the `proxy-*` headers reached the
  client as the backend wrote them — and a `connection: keep-alive` from the
  backend is about the backend's link to the server, not the client's link to
  it. The whole hop-by-hop set of RFC 9110 §7.6.1 is dropped now.
  A bodyless response is no longer framed either: `204` and `304` were given
  `transfer-encoding: chunked` and a terminating chunk, which RFC 9110 §6.1
  forbids and which leaves a client waiting for the end of a body that is not
  there.
- **The config file's permission rule is said once, and it is a warning.**
  The comment beside the first-run config claimed that the server refuses to
  start over a world-readable config, and that the check was keyed off 2FA
  being on or the file holding a credential. No such check exists: it was
  removed on purpose (ROADMAP §3.5) so that a `0644` bind mount starts, and
  putting it back would undo that decision.
  What was left was a comment that described a gate that is not there, and a
  credential nobody could see: `[auth.clients.*].secret` is a TOTP seed in
  the clear, and anybody who can read the file can generate a valid code.
  The server now says so once, at startup and after a reload, when the config
  holds a credential and the file is readable by anyone but its owner. It
  names the path and the mode. It does not refuse to start.
- **A config that could not be loaded is tried again.** The watcher noticed a
  changed file by its modification time alone, and only a *newer* one: a file
  restored from a backup, checked out by `git`, or written twice inside one
  second was never reloaded. The stamp was also advanced before the reload
  ran, so a file that was read while it was half-written — the common case,
  since the config is saved on every change — was never tried again and the
  server kept the routes it had for ever. The watcher now compares the file's
  time *and* its length, reloads a file that is older as well as a newer one,
  and only remembers a file once it has been loaded successfully. A failed
  load is retried, with a wait that grows so a file that is simply wrong does
  not fill the log.
- **The tunnel answers a request it cannot route before reading its body.**
  A request for a host no route serves had its body read and buffered first —
  up to 64 MiB per stream, held in memory, for a request with no backend to
  go to. Worse, the client waited for the refusal until the body arrived, so
  a client with no body to send waited out the body deadline (60 s) instead
  of being told there was nowhere to send it. The lookup now comes first and
  the body is read only for a request that is going somewhere. The plaintext
  listener already did it this way round.
- **The plaintext listener counts its connections.** Every connection it
  accepted was spawned with no ceiling, so an exposed listener was an unbounded
  number of tasks and file descriptors; only the header timeout bounded a
  single one. The listener now takes a slot from the same process-wide count
  the tunnel takes, and a connection over the ceiling is closed and logged.
  The per-peer cap cannot apply — a plain TCP connection has no peer identity
  — so an exposed listener shares one ceiling with the tunnel rather than
  having one of its own.
- **A route's path rewrite reaches the tunnel.** A route may pair a
  `path_pattern` with a `path_rewrite`, and the rewrite is what the operator
  writes when the service behind the route is not at the path the client asks
  for. The rewrite was applied on the plaintext listener and not on the
  tunnel, which is the path every real client takes: the route looked
  configured, `curl` against the listener saw the rewrite, and nothing else
  did. The rule now lives in one place — the route's own backend — and both
  paths use it, so the two cannot drift apart again.
  A WebSocket upgrade is part of that. The tunnel serves it and the plaintext
  listener answers it with 426, so the tunnel is the only place a WebSocket
  is served at all, and the upgrade went out with the path the client asked
  for rather than the one the route rewrites it to. It goes out with the
  rewritten path now, like every other request the route serves.
- **The Android client's tunnel descriptor is closed exactly once.** The
  descriptor the VPN hands over belongs to the native side from the JNI
  boundary on: it is taken there, before the first thing that can fail, and it
  is closed there on every path out of that function — the successful one and
  the failing ones alike.
  It used to be closed in two places, on two different paths. The native side
  closed it inside the tunnel setup, but only once both halves of the
  read/write pair had been duplicated, so a failure after that point left it
  closed by the native side and closed again by the Kotlin side, which closed
  it on the assumption that a failed call meant the native side had never
  taken it. It had. Between the two closes the number can be handed to
  something else — a socket, a file, another TUN — and the second close then
  closes that instead. On a phone that is an unrelated file in the process,
  and the failure is silent.
  The ownership is now a property of the type rather than of every call site
  remembering to close, and the Kotlin side closes the descriptor only in the
  one case where it is still its own: a native method that was never entered
  at all.

### Security

- **The local proxy does not hand out an authenticated tunnel to the
  network.** The client library bound whatever address it was given, and it
  does not authenticate the peer that connects to it — it hands out the tunnel
  of a connection that has already authenticated. So a non-loopback bind
  published that tunnel to everyone who could reach the machine, and the
  server's `[local_proxy]` section passed the address through without
  checking it. The library refuses a non-loopback address now, the same
  shape as the server's own plaintext listener and as the desktop app's
  `require_loopback`, and `[local_proxy] expose = true` is the explicit
  opt-in for a deployment that puts something else in front of the port.
- **A proxy credential no longer crosses the tunnel.** `Proxy-Authorization`
  is a credential for *this* proxy, and it was forwarded to the backend
  along with the rest of the hop-by-hop headers — on the client's side and on
  the server's, in the WebSocket path as well as the ordinary one. The
  client's bytes cross the tunnel verbatim, so the whole hop-by-hop set goes
  now: `Connection`, `Keep-Alive`, `Proxy-Authenticate`,
  `Proxy-Authorization`, `Proxy-Connection`, `TE`, `Trailer` and `Upgrade`,
  together with whatever `Connection` nominates. `Transfer-Encoding` stays,
  because the body it describes is carried over unchanged.
- **The webview is granted less than it was.** The desktop app's capability
  granted the whole of `core:default`, the whole of `opener:default` and the
  whole of `updater:default` to the renderer, and the renderer used almost
  none of it. Three things came with that:
  - `core:image:allow-from-path` let the renderer read **any image file the
    user can read** — a screenshot, a photo, an exported chart — and hand its
    pixels back over the IPC channel. It is denied now, and nothing in the
    app used it.
  - `opener:default` granted `reveal-item-in-dir` for **any path**, which
    asks the OS file manager to open a directory the renderer names. The
    frontend only ever opens a URL, so the permission is now the one that
    opens a URL and the scope that says which ones.
  - `updater:default` granted the renderer the right to download and install
    an update. The frontend has never called the updater — the app has no
    in-app update button — and the plugin is still registered on the Rust
    side, so nothing about the release machinery changed; only the
    renderer's reach into it is gone.
  `core:default` itself is still granted, and it still brings the path, the
  event, the window, the webview, the app, the resource, the menu and the
  tray defaults with it — the renderer uses the window and the tray ones,
  and the path and the resource defaults are what the rest of the set needs.
  What is gone is the two reaches that mattered: the one into the
  filesystem, and the one into the updater.
  A renderer that can run script is a renderer that can ask for all three,
  and the answer was "yes" to each.
- **A registration code no longer silently replaces a working credential.**
  The Android app asked before an invite overwrote something that worked — but
  the question was asked for a secret and for the relay, and a one-time
  enrollment code was neither: it carries no secret, so it raised no conflict,
  and it was applied with no confirmation at all. The credential the endpoint
  already held went with it, and because the guard in `ProxyConnector` that
  keeps an endpoint from spending a token it already has a credential for
  looks at what the endpoint holds, the drop that came before it defeated the
  guard. A registration code is exactly the artefact a user is primed to
  accept — shared in a chat, pasted by an "operator", one tap from the
  scanner — so this was a credential one accepted code could destroy.
  The rule now names the enrollment, and it is a pure function with tests
  beside it: `ui/InviteConflicts.kt`.
- **The client id no longer reaches the log.** It is half of the 2FA
  credential pair, and the app says so where it logs the other one — but the
  invite import and the enrollment update both wrote it out in full, to the
  on-screen log panel and to logcat. What kind of credential arrived is what
  those lines are about; the id is not in them any more.

- **The certificate verifier and the bundled roots were patched.** Three new
  RustSec advisories landed against crates this tree already carried:
  RUSTSEC-2026-0382 (`rustls-webpki`), RUSTSEC-2026-0381 (`webpki-roots`) and
  RUSTSEC-2026-0383 (`webpki-root-certs`). All three are about the same thing:
  the `emSign` intermediates the root programmes distrusted were still
  accepted, so a certificate chaining to one of them was still trusted. Both
  lockfiles now pin the patched releases — `rustls-webpki` 0.103.16 and
  `webpki-roots`/`webpki-root-certs` 1.0.10 — and nothing else in the tree
  moves.
- **The published image is signed, and says where it came from.** Every image
  released to GHCR now carries a cosign signature made with a key that is
  minted for the release run through GitHub's OIDC — nothing is stored, so
  nothing can be copied out of a secret — and a provenance attestation saying
  what was built and from which source revision. The README says how to check
  both; a tag is still a tag, and none of this changes what a pull gives you.
- **The build no longer follows what it is told to.** Every action in every
  workflow is pinned to a commit SHA rather than a tag, both Dockerfiles build
  with `--locked` against the lockfile in this repository, and their base
  images are pinned by digest rather than by a name that can be moved. A
  compromised upstream action or a re-pushed base image no longer changes
  what a release builds. The tag a hand-triggered release run builds with
  reaches the script as a value rather than as text, so it cannot become
  shell on the way in.
- **`cargo deny` runs over both cargo workspaces.** The licences the
  dependency tree may carry, the registries it may fetch from and the
  duplicate versions it may hold are now a written policy (`deny.toml`) and a
  gate, beside the two `cargo audit` jobs — which watch advisories and
  nothing else. The check found two crates of this repository carrying no
  licence at all; both say MIT now.
- **The credentials are wiped when they go out of scope.** A TOTP seed, an
  enrollment token, a relay bearer, the admin token and the endpoint's own
  private key are now held in a type that zeroes its buffer when it is dropped,
  on both sides: the server's `[auth]` seeds, the admin token and the endpoint
  key, and the client's credentials — including the process-wide tables the
  Android app fills through JNI. The buffers those files are read into are
  wiped with them, so the plaintext of a credential file does not sit in the
  heap after the parse that needed it. Until now the credentials themselves
  were masked in `Debug` but stayed in the heap as plain `String`s, so a core
  dump, a swap file or a read of `/proc/<pid>/mem` handed over every
  credential the process had ever held, long after the handshake that needed
  it. The TOTP validator the library builds is wiped with them, so the second
  copy of the seed inside it is gone as well. The masking that was already
  there is now the default rather than something each field has to remember: a
  struct that derives `Debug` and holds a secret cannot leak it. The copies
  the TOML parsers make of the file are zeroed too: a config file can hold the
  seeds in the clear, and the tree it is parsed into — and the text that tree
  is written back out as — are zeroed as soon as they have served their
  purpose, rather than left in the heap for whatever reads it next. One copy
  of each string on the write path does stay behind: the raw text `toml_edit`
  keeps for the values it parsed, which its private internals do not let a
  caller reach. Nothing about the configuration or the wire format changes —
  a `config.toml` written by this build is the one the previous build wrote,
  and a client built against the old one still talks to a server built against
  the new one.

## [0.6.1] — 2026-10-11

Two configuration keys are added (`[iroh] secret_key_file` and
`relay_auth_token_file`) and none is removed or renamed, so a `config.toml`
that works on 0.6.0 still loads. Five things behave differently without being
configured to:

- A config with no `[iroh] secret_key` gets one generated on the first start
  and written back into `config.toml` — see `### Changed` below.
- A server start with `--config <path>` and no file at `<path>` no longer
  exits with `Config file not found` — it writes a minimal `config.toml`
  instead, so a fresh operator has something to edit — see `### Added`
  below.
- The default `--config` path moves when `NEXAPIPE_CONFIG_DIR` is set —
  see `### Changed` below.
- A `0644` `config.toml` no longer refuses a start or a 2FA-enabling
  reload — config permissions are not checked anymore, see `### Changed`
  below.
- The `[iroh]` identity and relay token can come from the environment or a
  separate file instead of the inline literal — see `### Added` below.

### Changed

- **`config.toml` permissions are no longer checked at start or on reload.**
  The server used to refuse a start (exit 1) when the file was group- or
  world-reachable and held a credential — a TOTP seed, an `[iroh]
  secret_key` or a `relay_auth_token` — and a reload could not turn 2FA on
  against such a file. That gate is gone: a `0644` bind mount starts, which
  is the ordinary Docker arrival mode. The trade-off is on the operator:
  any account that can read the file can copy every credential in it. Keep
  the file private (`chmod 600` remains recommended and the generated file
  is still written `0600`), or move the credentials out, which the new
  sidecar and environment sources exist for. The credential sidecar files
  themselves — `secret_key_file`, `relay_auth_token_file`,
  `NEXAPIPE_IROH_SECRET_KEY_FILE` and `config.toml.admin-token` — are still
  enforced `0600` on Unix and refuse the load otherwise; nothing about
  those checks changed.

- **`NEXAPIPE_CONFIG_DIR` shifts the default `--config` path.** What used
  to be `./config.toml` is now `<dir>/config.toml` whenever the environment
  variable is set, with the variable unset falling back to `./config.toml`.
  The docker setup sets `NEXAPIPE_CONFIG_DIR=/app/config` (matching the
  bind-mount target), so the container picks up `/app/config/config.toml`
  by default and a local dev that omits `--config` keeps the old behaviour.
  `--config` always wins. Operators who want the docker path locally can
  set the variable for one run with `NEXAPIPE_CONFIG_DIR=config nexapipe`;
  operators on the previous default need no change at all.

- **A stable Node ID no longer takes two manual steps.** A config with no
  `[iroh] secret_key` gets one generated on the first start and written back
  into `config.toml`, so the endpoint's identity survives a restart without
  running `--generate-secret` and pasting the result. This is what a client that
  stores `server_node_id` depends on, and skipping it used to leave the server
  on a different Node ID after every restart — silently, since the server came up
  fine and served traffic both times. The write goes through the same locked,
  atomic path as the 2FA commands, so comments and the rest of the config
  survive, and the file lands at `0600` because it now holds a private key.

  Two behaviours come with it, both deliberate: a `secret_key` that does not
  parse **refuses the start** (it used to be a warning and a throwaway
  identity, which looked handled while the Node ID quietly changed every
  restart), and a config that cannot be written **still starts**, on a throwaway
  identity with a warning — a read-only mount or a file owned by another user is
  an ordinary deployment, and refusing there would be worse than the behaviour
  this replaces. `NEXAPIPE_NO_PERSIST_IDENTITY=1` asks for that ephemeral
  identity deliberately and leaves the file untouched.

  Deployments that relied on a fresh Node ID per restart should set that
  variable; everything else needs no change, and `--generate-secret` remains
  for moving an identity between hosts.

- **Docs: the invite QR code renders with correct line spacing on macOS.**
  The generated page used a line-height that collapsed the code block on
  Safari; it now carries an explicit line-height so the QR image and the
  surrounding text line up the same on every browser.

### Added

- **`[iroh]` credentials can come from a file or the environment.** Two
  keys point at a separate file holding the value instead of spelling it
  inline: `secret_key_file` for the endpoint identity and
  `relay_auth_token_file` for the relay bearer token; relative paths are
  read against the config file's directory. Two environment variables carry
  the value directly: `NEXAPIPE_IROH_SECRET_KEY` and
  `NEXAPIPE_RELAY_AUTH_TOKEN`. Sources rank environment, then file, then
  the inline literal, and naming more than one source for one credential
  is refused at load rather than silently picked — a config that disagrees
  with itself is a deployment mistake. The sidecar files are still enforced
  `0600` on Unix and refuse the load otherwise, now that the config file's
  own mode is no longer checked (see `### Changed`).

- **The endpoint identity can come out of the config directory entirely.**
  `NEXAPIPE_IROH_SECRET_KEY_FILE` names, by *path*, the file holding the
  `[iroh]` secret key — the file-pointing sibling of
  `NEXAPIPE_IROH_SECRET_KEY`, which carries the key value itself. A missing
  env-named file is generated into on first start (`0600` on Unix), and the
  key is never written back into `config.toml`, so the config holds no
  credential and does not have to be private. The environment credentials
  apply even when the config has no `[iroh]` table at all — the generated
  first-run template has none, which is exactly the docker first-run path:
  an empty table is materialised in memory for the load, the file on disk is
  not touched. The env path is deployment wiring: it is taken literally
  rather than read against the config's directory (that reading stays with
  the existing `secret_key_file` key).
  Naming the key by more than one source — value and path, env and config,
  either and `secret_key` — refuses the start, the same one-credential,
  one-source rule every other pair follows. The docker compose setup wires
  the variable at `/app/secrets/iroh.key` over a new `./secrets` mount, so
  the identity lives next to the config instead of inside it; back the
  directory up with `config/`.

- **A first start with no `config.toml` writes one for you.** Server mode
  only, and only when the file is missing — an existing file is never
  regenerated, and one that exists but does not parse still fails the
  start rather than being replaced. The generated file has
  `[auth] enabled = true`, no `[server] listen_addr` (the plaintext
  listener stays closed), and no `[[routes]]` entry, so every host is
  answered 404 and nothing can connect until a client is enrolled. The
  outcome is announced through the log channel — server-mode startup
  routes advisories through `tracing::info!`, reserving raw stdout for
  output that carries data the operator needs to act on (Node ID,
  ticket, invite, QR code). Read-only commands (`status`,
  `--generate-2fa`, `client list|add|revoke`) do not create the file,
  and `--local-proxy` skips the step too — the template describes a
  server, not a client.

### Fixed

- **Android: the `tun-proxy` feature's stop path is gated on Android.**
  `nativeStopTunProxy` imported `ndk_context` unconditionally and called an
  Android-only NDK function, so a host build with `--features tun-proxy`
  failed to link. Both are now behind `#[cfg(target_os = "android")]`,
  matching the rest of the JNI surface — the TUN proxy is an Android-only
  feature, and the host build was never meant to exercise it.

## [0.6.0] — 2026-10-11

A readable version of this release, with downloads, is published at
<https://open-nexa.github.io/nexapipe/v0.6.0.html>. The page itself
lives in `docs/releases/`, and only that directory reaches the site.

Two configuration keys are added and none is removed or renamed, so a
`config.toml` that works on 0.5.0 loads unchanged on 0.6.0, and a client written
before devices existed answers exactly as it did. Four things behave
differently without being configured to: `/metrics` no longer carries the
request-duration counter it used to, a device struck out loses the connections
it is already holding, a revoked peer is closed with a new code — `6` — and an
enrollment that would replace a device already in the table is refused.

### Added

- **One credential per device, rather than one shared by every device that
  names a client.** `[auth.clients.<id>]` gains a `devices` table: each entry
  carries a secret of its own, issued at enrollment and revocable on its own, so
  striking one out no longer rotates the rest. The credential is still a TOTP
  secret and the handshake still HMAC-SHA256 over `nonce ‖ timestamp`; what
  changed is which secret is looked up. A client entry carrying only `secret`
  keeps working exactly as it did.

- **A client names the device it is speaking as.** Each install answers as one
  named device of itself: the desktop after its hostname, Android after the
  device model, eight random characters behind either so two machines sharing a
  name do not collide. The name is claimed at enrollment and nowhere else — the
  server refuses a device it has no secret filed for — so existing credentials
  carry on answering as they do today and nothing re-enrolls on its own.

- **An access line says whose request it was.** Every access line ends with
  `client=… device=…`, and `/v1/connections` answers who is connected rather
  than only how many. A request that never authenticated gets neither field.

- **`nexapipe client list|add|revoke`**, each with `--device`, writing
  `config.toml` through the same lock the server reads it with, so a running
  instance picks the change up on its next reload. `/v1/*` stays read-only on
  purpose: its token is one opaque value, with no scope and no rotation.

- **`[auth.clients.<id>].unnamed_device_allowed`** (default `true`): set to
  `false`, a peer that names no device is refused rather than answered under the
  client's shared secret — the one path a device cannot be taken off by being
  revoked, since nothing in the table belongs to it alone.

- **A systemd unit for the server** in both READMEs, beside the Docker section.
  It keeps a named account and one writable directory, because this server
  writes back into its own config — the 2FA counters, an enrolled device — and
  writes its admin token beside it. The relay has had a unit in
  `docs/self-hosted-relay.md` since earlier in this release.

- Desktop: session totals, and a page that lists the connections a running proxy
  is holding (#90).
- Desktop: a running proxy says what quitting should do (#88).
- CI: the root workspace is *tested* on Windows, not only compiled (#97).
- Docs: a systemd unit for the relay (#95); what v0.6.0 shipped, in the roadmap
  sections that describe it (#123); which secret an enrollment rotates (#124);
  a size and performance roadmap (#136).
- CI: dependabot's per-dependency version pull requests are replaced by one
  weekly dependency issue (#127).

### Changed

- **`/metrics` reports request latency as a histogram.**
  `nexapipe_request_duration_ms_bucket{le="…"}` beside `_sum` and `_count`
  replaces `nexapipe_request_duration_ms_total`, which carried the same sum under
  a name a histogram cannot have: a p99 no longer takes arithmetic. The
  boundaries are fixed at 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000 and
  10000 milliseconds, plus `+Inf`. A scrape looking for the old counter will not
  find it.
- **The workspace declares the Rust version it needs: 1.89.** The build has
  depended on it since the config write started taking a file lock — `File::lock`
  is stable from there — and a build on an older toolchain used to fail with a
  missing method somewhere in a crate rather than with the toolchain it was
  missing it from.
- **The desktop TUN shares DNS and address space with other TUN apps**, rather
  than taking both over (#87).
- Dependencies: one batched upgrade across the workspace (#85).

### Fixed

- **A device struck out kept the connections it already held.** Revocation
  rewrote `config.toml` and stopped there: the device could not connect again,
  but it went on serving on everything it had open until it hung up — which is
  the one thing revocation is for. The reload that notices what left `[auth]`
  closes them now, at both levels: a client that left takes every device under
  it, a device that left takes only its own. They go with a new close code,
  `REVOKED = 6`, which both clients turn into an error saying the credential is
  gone and that trying again is not going to help.
- A name outside the hijack is answered through the host's own resolver, instead
  of the TUN swallowing it (#105).
- Desktop: an empty window is no longer shown while the app starts (#91); the
  TUN resolver is the exclusive DNS route on Linux (#92); a service an upgrade
  left behind is put back (#93); a stopped macOS service stays stopped (#86);
  the connecting indicator breathes with Reduce Motion on (#89); the webview is
  granted the permission it needs to read the service version (#100); the window
  is shown before the first frame is waited for (#106).
- Desktop: a launch that produced no frame sent no start-up timings at all. The
  wait after `show()` had no end, so a window the compositor never drew never
  reached the `finally` that sends them either. It is bounded at two seconds now
  and reports whether a frame came.
- Desktop (macOS): the bundle carries the content security policy the other two
  platforms use. Platform configs merge as JSON Merge Patch, in which `null`
  means *remove the key* — so `app.security.csp = null` deleted the policy
  rather than relaxing it, and the macOS app ran with none.
- `[peers]` refuses a key it does not recognise (#130). `allow` is the section's
  only key and an absent one means unrestricted, so `allowd = [...]` was dropped
  by serde and left a server that looked restricted and was not.
- Android: `nativeStopTunProxy` was the one JNI entry point with no barrier
  against unwinding (#129), and it ran on the main thread while the VPN was
  being switched off (#135). A device id that could not be stored was reported
  as stored (#147).
- Android: a credential is no longer stored unencrypted without being asked
  (#139). A device with no keystore can still connect; only storing without
  asking is gone.
- TUN: each flow has a budget (#134). A UDP frame could promise 65 535 bytes and
  arrive a byte at a time, and TCP flows had no ceiling at all — 256 now, the
  same ceiling the local HTTP proxy uses.
- Desktop: the desktop build gets the vendored `smoltcp` patch (#133).
  `ui-desktop/src-tauri` is its own workspace, so the root `[patch.crates-io]`
  never reached it and the desktop TUN ran the upstream code.
- A backend that answers slowly is no longer reported unreachable (#137): the
  preconnect budget covered the connect alone and not the wait for a 2FA
  refusal, which ran for up to six seconds more.
- Server: an enrollment could take over a device that was already there (#140);
  a name the table holds is refused now, and `--force` replaces one on purpose.
  A connection stamped the client rather than the device that made it, so every
  device under a client shared one `last_used` (#141). A peer could be connected
  before it was revocable — registration happens under the auth lock now (#144).
- Server: a write to `config.toml` was readable by everyone for as long as it
  took and followed a symlink to reach the file (#146); `--qr-out` had both
  problems and overwrote whatever was at the path (#131); `client add` reported
  a secret it had not written (#143).
- Client: a TOTP period that does not fit a `u32` is refused at enrollment
  (#148) rather than narrowed with `as u32`, which made every code afterwards
  wrong for a step the two ends disagreed about.
- A peer listing takes one reading of the clock for the whole list rather than
  one per entry (#138).
- Desktop: a tunnel whose DNS was never hijacked ran as though it had been, and
  a restore that wrote to no network service was reported as a success (#142).

## [0.5.0] — 2026-10-07

A readable version of this release, with downloads, is published at
<https://open-nexa.github.io/nexapipe/v0.5.0.html>. The page itself
lives in `docs/releases/`, and only that directory reaches the site.

No configuration key changed and no default moved: a `config.toml` that works on
0.4.0 loads unchanged on 0.5.0. One thing behaves differently without being
configured to — a `passthrough` or `tcp` backend that refuses TCP connections is
reported unhealthy now, and skipped in a route with more than one backend, where
it previously looked healthy and failed on the request.

### Added

- **Health decides which node the next request goes to.** 0.4.0 started probing
  the nodes and writing down what came back, and nothing read those records: the
  balancer still picked by index into a list nothing could change, so a node that
  had been dead for an hour went on receiving its share of the traffic.
  Selection takes one flag per candidate and answers `Option<usize>`, so "none of
  them" is an answer it can give — index 0 was always a valid reply to "which
  node", which is why the old code could never say no. A request that fails to
  dial marks the node down where the failure was noticed, rather than waiting up
  to thirty seconds for the probe to find out. A single node that is down is
  still dialled: refusing to dial the only node turns "down" into "no service at
  all" for a deployment with nothing to fail over to.

- **A `passthrough` or `tcp` backend is asked whether it answers.** Only `http`
  routes were probed, so a TLS listener behind a passthrough route had no health
  at all and surfaced as a connect error on whichever flow tried it first. Both
  are probed by connecting now — a TLS backend by completing its handshake —
  which is deliberately the smaller claim: something is listening, not that it
  works. A `udp`-only route is still not probed, and now for a stated reason:
  every probe available is one every backend would fail, and a pool emptied by a
  check that could never have succeeded is worse than an unchecked one.

- **The server counts the bytes it carries.**
  `nexapipe_traffic_bytes_total{direction="sent"|"received"}` on `/metrics`, and
  the same two numbers in `/v1/status`. They are counted on the client leg and
  nowhere else — the one place where one number means one thing across paths
  this different — and an HTTP response takes its count from what the access log
  already printed, so the log line and the Prometheus number cannot disagree.
  What is counted is tunnel payload: no protocol headers, nothing discarded,
  nothing counted twice.

- **Both clients report what each node carried, and whether it answered.** The
  desktop lists a node's health beside its traffic — whether it answered the last
  probe, how long it has been unreachable, how much it has carried — and the
  Android notification shows live up and down rates.

- **A container image is published with the release.**
  `ghcr.io/open-nexa/nexapipe`, one multi-arch manifest for `linux/amd64` and
  `linux/arm64`, under the same tag that already drives the archives, the desktop
  bundles and the APK. `docker-compose.yaml` names it, so `docker compose up`
  pulls rather than builds; `--build` still builds locally under the same name.

- **`docs/self-hosted-relay.md`: how to run your own relay**, and how to point
  NexaPipe at it. It does not remove the third-party dependency — only changes
  whom you depend on.

### Changed

- **The desktop credential door now stands in front of the whole Config page.**
  Confirming who is at the keyboard — Touch ID or the account password on macOS,
  Windows Hello or the account password on Windows, PAM on Linux — is what opens
  the page, rather than something each reveal button asks for on its own. A shut
  page renders none of it: no nodes, no connection strings, no two-factor
  secrets, no relay, so there is nothing on the screen and nothing in the
  document to read out of it. The window is still two minutes and still shuts
  itself; the button at the top of the page opens it again, and shuts it early.

- **The relay settings moved from Settings to Config.** Which relay this machine
  dials is part of how it connects, not a preference about how the app looks, and
  a custom relay's bearer token is a credential — so it now sits with the rest of
  the connection configuration, behind the same door.

- **macOS stopped using the keychain.** Reading a keychain entry is an access
  macOS asks about with a sheet of its own — at startup, again whenever the app's
  signature changes, and once more for every prompt — which is how one unlock
  turned into two sheets, and how a locked page once came up with no way out.
  The master key now lives in the same `0600` file the other platforms fall back
  to, and is moved out of the keychain on the first launch rather than replaced,
  so nothing already stored becomes unreadable. The door asks Authorization
  Services instead — the framework a System Settings pane uses to put a lock on a
  page, which brings its own sheet and asks nothing of the keychain. The right
  it asks for is `system.privilege.admin`, because the policy database defines
  it `shared = false`: a shared right (`system.preferences` is the trap) keeps
  its credential in the session for its timeout, and any authentication that
  landed there — an unlock of System Settings counts — would let the page open
  with no sheet at all.

### Fixed

- **Service shutdown is graceful on every platform rather than one.** The Unix
  service process had no signal handling at all, so `launchctl unload`,
  `systemctl stop` and the shutdown broadcast each simply killed it: UNIX signals
  are handled now, and DNS restore, self-heal and exit hooks exist on all three
  platforms rather than on Windows alone. macOS gets an explicit `ExitTimeOut`,
  and Windows a service entry point matching what the `nexa-service` binary
  already did.

- **CI compiles the root workspace on Windows**, which it never did — only the
  desktop crate had a Windows job. Check only, no tests: the integration tests
  spawn the binary and reach for `cfg(unix)` fixtures.

### Fixed

- **The machine's DNS no longer outlives the tunnel.** Three separate gaps each
  leaked on their own: a run that died before its teardown left the system DNS
  pointed at the TUN with nothing to undo it at the next start, and on macOS and
  Linux there was no self-heal at all; quitting skipped the restore entirely,
  because nothing handled the exit events, so Cmd+Q left the machine pointed at a
  tunnel that no longer existed. Only the `…254` host address of a candidate
  block counts as ours now, never the `/24` around it — `10.0.0.0/24` is both a
  candidate block and the subnet a great many home LANs use.

- **A password the operating system did not accept said nothing.** Asking and
  being refused came back as "the door is shut", which the UI read as its own
  instruction to stay quiet: a wrong password, a dismissed prompt or a failed
  fingerprint left the page exactly as it had been, and the button that was
  pressed answered for nothing. A press that does nothing now says why — the
  locked page reports whether the password was not accepted or the device did
  not confirm, and the password field carries that line when it opens again.

- **On Linux a password that was not accepted left the page looking unanswered
  for as long as PAM took to refuse it.** The dialog closed the moment the
  password was typed, which made it look as though the answer had already come
  back, and the refusal then turned up seconds later on the page behind. The
  password is now checked while the dialog is still open: the wait is said out
  loud on the button, and the answer lands in the field it was typed in. PAM
  still takes its time over a password it refuses — that delay is deliberate —
  but nothing looks broken while it does.

- **Copying a value the door had just opened came back as "could not copy".**
  Those copies wrote straight to the asynchronous clipboard API, which WebKit
  refuses once the document is not focused — and confirming who is at the
  keyboard takes long enough to lose it. Every copy in the app now goes through
  the same writer, which writes natively through the operating system's own
  clipboard — no focus, scheme or gesture required — and falls back to the
  asynchronous API and then a selection with the legacy command. A value that
  never arrived also stopped being reported as a clipboard failure, which sent
  the user looking at the wrong thing.

- **The loading spinner never turned on a Mac with Reduce Motion on.** The
  accessibility rule that stills every animation flattened it along with
  everything ornamental, and a spinner that does not turn is a button that
  looks dead. A spinner is the state rather than decoration — there is no other
  way to say "working" — so it is exempt from the stop now. The pulse next to
  the proxy's status is not: the status text already says "Starting", so that
  one is decoration and still respects the setting.

- **macOS ran the window with a title bar of its own on top of the app's.** The
  macOS build asked for native decorations without the title bar style that makes
  them transparent, so the system's bar sat above the one the app draws — two
  title bars, and two sets of close and minimize buttons, one at each end of the
  window. The window now asks for the overlay style: the traffic lights stay
  where macOS puts them, over the left of the app's own bar, and the app stops
  drawing a second set.

- **Server: an invalid health-check path panicked instead of failing the
  probe.**

## [0.4.0] — 2026-09-30

A readable version of this release, with downloads, is published at
<https://open-nexa.github.io/nexapipe/v0.4.0.html>. The page itself
lives in `docs/releases/`, and only that directory reaches the site.

### Added

- **A door in front of the credentials the desktop app holds.** Showing a TOTP
  secret, a node's connection string or this endpoint's Node ID now asks the
  operating system to confirm the user first — Touch ID or the account
  password on macOS, Windows Hello or the account password on Windows, PAM on
  Linux — and stays open for two minutes afterwards. Sealing the store at rest
  and masking what crosses into the UI were answers to "is this value on the
  screen"; this is the other half, and the one neither of them could answer:
  *who* is asking. There is deliberately no app password, because a credential
  of its own would be one more thing to forget, reset and attack — what gates
  the surfaces is what gates the machine. A machine with nothing to confirm
  anybody with refuses rather than handing the value over, which is the one
  outcome this exists to prevent. The proxy is unaffected: it still starts and
  reopens its endpoints after a reboot with nobody at the keyboard, because
  the window is two minutes of memory that never leaves this process and is
  never handed to the service. This is the desktop half of the Android app's
  credential lock, which shipped in 0.3.0; both ask the operating system and
  both stay open for two minutes, but not in front of the same surfaces — here
  it is this endpoint's Node ID and a node's connection string, there the TOTP
  secret, its `otpauth` export and the relay configuration.
- `least_conn` as a third load-balancing strategy, alongside `round_robin` and
  `random`: pick the healthy backend with the fewest requests outstanding to it,
  under a lease released when the flow finishes. Ties rotate rather than taking
  the first index, because a tie almost always means nothing is running — and
  taking the first index would then send everything to one backend, which is the
  load this strategy exists to spread. It counts requests, not sockets, because
  how many connections the pooled HTTP client is holding open is not something
  this process can see.
- **IPv6 inside the tunnel.** A proxied domain answered an AAAA query with
  nothing, which made every resolver that prefers IPv6 fall back to A to get
  anywhere. Both families are now answered, each from a pool of its own: `A`
  from `10.0.1.16+` as before, `AAAA` from `fd00:10:0:1::16+`, a ULA block the
  VPN routes into the TUN for itself (Android; the desktop uses
  `fd00:198:18::/64`), and the packet path looks a destination up in whichever
  family it arrived on. A ULA rather than a global address so that an address
  which escapes the tunnel is a dead end, and only that one /64 is claimed —
  the device's own IPv6 traffic still goes to the physical network. On the
  desktop the address is configured per platform and may be refused (a service
  account, an image with IPv6 off); when it is, AAAA is answered with the empty
  reply that sends the resolver back to A rather than with an address nothing
  routes, and the log says which happened.
- `[iroh] bind_ipv6`: bind `[::]` on the configured `bind_port` as well as
  `0.0.0.0`. It adds a socket rather than replacing one, so no client loses the
  route it has, and the IPv6 bind is not required — a host with no IPv6 starts
  and logs it instead of refusing to. Ignored without `bind_port`, which is
  also logged rather than left looking as though it worked.
- **The backends are asked whether they still answer.** Every 30 seconds, with
  up to 5 seconds of jitter, each backend is probed in parallel and the result
  recorded — `EndpointGroup::health_snapshot()` is what a UI polls. Until now
  a group dialled once, at startup, and never again, so a backend that stopped
  answering was discovered by the request that needed it, which on a phone is
  an app that has already timed out. The probe is also the reconnect: the pool
  drops a connection idle for a minute, so a round keeps one warm to a backend
  nobody has talked to. A failure is logged when it starts and then every
  tenth probe, because a backend down for an hour has failed a hundred of
  them. **A dead backend is still handed out**, which is the other half of this
  and is not done: the balancer picks by index into a list it cannot change, so
  removing one needs the group to become mutable — a change to every holder of
  it, and the item this release leaves for the next one.
- **A second Android ABI.** The APK was `arm64-v8a` only, which left an
  emulator — the x86_64 images that run acceptably on a development machine —
  with nothing to install. There are now two APKs, one per ABI, rather than one
  carrying both: a fat APK would make every phone download the x86_64 library
  to get the arm64 one. Each carries its own version code (the base with the
  ABI as its low digit), because two artifacts of one version cannot both claim
  the same one. `run_android.ps1 -Abi x86_64` builds and installs that one;
  without it the local loop would face two APKs and no way to choose.
- `[timeouts]`: `connect_secs` (default `10`) and `response_secs` (default `30`),
  each covering one step of talking to a backend and neither bounding the whole
  request — once a response head arrives, streaming its body can run as long as
  it needs. `connect_secs` is the one deadline behind every dial in the server,
  which used to be four copies of ten seconds. Read once at startup; `0` and
  anything past `3600` are refused at load.

### Changed

- **A route whose backends are all unhealthy now depends on how many there are.**
  One backend is still handed out, because with nothing to choose between the
  health information buys nothing and refusing would answer for every request to
  that route. Several, all down, refuse without dialling: the answer is already
  known, so a connect timeout was only ever spent delivering this refusal late.
- A refused HTTP request distinguishes why. No route serves the host: `404`, as
  before. The route exists and nothing behind it is healthy: `503` — the route is
  configured correctly and something downstream is down, which is a different
  thing to open. An L4 flow says the same on the wire with `Status::BackendFailed`
  rather than `NoRoute`, which would have told the client its request was
  misconfigured at the moment it was correct.

### Fixed

- The DNS cache in the TUN proxy (`crates/nexapipe-client/src/tun_proxy.rs`)
  answered more than it knew: entries were keyed without QCLASS, so one class was
  served from another's answer; they were not keyed on the resolvers that
  produced them; a hit rewrote only the transaction ID, so a long-lived answer
  went back out with its full TTL again; and a zero TTL got a one-second floor
  instead of not being cached. Those tests are now executed in CI, which had only
  been compiling them.
- The desktop app's claim that the OS keychain holds the credential store's
  master key was not true on Linux: `keyring` had no Linux backend, so the key
  was a `0600` file beside the encrypted credentials. Linux now uses the Secret
  Service, and an install that already had a file key keeps it — the same key
  moves into the keychain, because a fresh one would leave every credential in
  the store undecryptable.
- The desktop app's `localStorage` payload no longer holds a node's connection
  string. A ticket is a credential — it names an endpoint *and* carries how to
  reach it — and it was written in the clear beside the rest of the config,
  while the TOTP secret, the enrollment token and the relay bearer had already
  moved into the encrypted store. Both spellings now live there too, a payload
  left over from an older build is migrated into it on the way in, and a node
  whose connection string is in neither is dropped — after the store has been
  asked, which is the only moment that question has an answer. An older build
  reading the new payload finds no connection string and drops the node, so
  downgrading means re-importing the invite.
- The desktop app masked its credentials in the wrong place. The renderer
  already held the value it was shortening, so a mask computed there was a mask
  over a string sitting in that process's own memory — and an invite was worse:
  its TOTP secret and its enrollment token were handed to the frontend in full,
  so the page could work out which node the invite belonged to. Masks are now
  computed in Rust (`credentials::mask`) and what crosses into the renderer is
  the projection; an invite is accepted by `accept_invite`, which puts the
  credentials in the store itself and answers with a receipt carrying none of
  them. The Node ID is masked the same way, and `reveal_credential` and
  `reveal_node_id` are now the only two commands that answer with a whole value
  — which is what makes them the two the OS lock has to sit in front of.
- **Android: Nexa no longer disconnects another app's VPN without asking.**
  Android allows one `VpnService` TUN per user, and `establish()` revokes
  whoever holds the slot without asking anybody. Nexa only checked whether a VPN
  was the *default* network, so a per-app or split-tunnel VPN was invisible to
  the guard and was dropped silently — and even when one was seen the only
  outcome was a refusal, so running Nexa beside another VPN meant stopping that
  app by hand. Every VPN Android reports is now detected (`allNetworks` with
  `TRANSPORT_VPN`), and the first `establish()` asks: take over, or cancel, with
  an optional "remember my choice" that the settings can take back. An
  always-on VPN is refused outright and says why, because Android restores it
  immediately and it may be a work-profile VPN the user is not allowed to break.
  Taking the slot is never automatic: a rebuild after a network switch does not
  take it back.

## [0.3.0] — 2026-09-29

A readable version of this release, with downloads, is published at
<https://open-nexa.github.io/nexapipe/v0.3.0.html>. The page itself
lives in `docs/releases/`, and only that directory reaches the site.

### Added

- An auxiliary listener, bound only when `[admin] listen_addr` is set and only
  ever on loopback: `GET /healthz` for liveness and, while `[metrics] enabled`
  is true, `GET /metrics` in Prometheus text format. A non-loopback bind
  is refused at startup rather than warned about, and unlike `[server] expose`
  there is no escape hatch: what it answers names your routes, clients and
  backends.
- Instance metrics on it: connections (total, active, and by whether the path is
  direct or relayed — read from iroh rather than guessed at a socket address,
  so "nothing to rent" is a number rather than a claim), requests by status
  class and the milliseconds they took, L4 flows by protocol and status,
  backends in and out of rotation, work still in flight, and uptime. The
  exposition is written by hand, so no `prometheus` crate was added and
  `Cargo.lock` is untouched. `/metrics` with metrics off is `404` rather than an
  empty body, so a scraper can tell "disabled" from "no traffic yet".
- A read-only management surface behind a generated token: `GET /v1/status`,
  `/v1/routes`, `/v1/clients`, `/v1/connections` and `/v1/health`, as JSON.
  The token is written to `<config>.admin-token` on first start; there is
  deliberately no key for it in the config, because a credential in the file an
  operator edits, copies and commits is what this design avoids. No token means
  `503`, not an open door.
- `nexapipe status` — asks a running instance those five endpoints and prints
  them grouped, or as one document with `--json`. It is a client of the same
  endpoints rather than a second reader of the config, so the running instance
  stays the one thing that decides what its state is.
- A door in front of the credentials the Android app holds: the TOTP secret of
  an endpoint, its `otpauth` export, and any change to the relay configuration
  now ask Android to confirm the user first — a biometric where there is one,
  the screen-lock credential otherwise — and stay shut for two minutes after
  one confirmation. `SecretStore` already sealed them at rest; what was missing
  was anything asking before handing them back. A device enrolled with neither
  a biometric nor a screen lock is refused rather than downgraded, and the way
  out is one tap away. Proxy start and stop are deliberately not gated: the VPN
  has to come back after a reboot with nobody present.
- A request ID: 32 hex digits per request, one per entry point rather than one
  per connection, appended to that request's access line and carried by a
  `request` tracing span that also holds its method, URI and status. The access
  log has always answered "what happened"; until now it could not say which of
  its lines belonged to the response somebody is looking at.
- `docs/iroh-boundaries.md` — what still depends on third-party infrastructure
  whatever `relay_mode` says. Two README sections oversold what a mode buys:
  `custom` constrains this endpoint only, and Endpoint ID discovery still
  queries `dns.iroh.link` in every mode. Both READMEs now point here instead of
  repeating the caveat.
- This CHANGELOG. 0.2.0 shipped without one, so its entry below is
  retrospective; 0.3.0 is the first release recorded in it as it happened.

### Changed

- Hot-reload rules, previously scattered across the configuration sections, are
  one table in both READMEs: what a reload applies, and what needs a restart.
- The access log line ends with `id=<hex>`. Appended rather than inserted, so
  every field before it keeps the column it had and a script that splits on
  spaces still finds the host, the status and the duration where it did.
- HTTP responses carry `x-request-id`, the same id the access line records. A
  backend that sends its own is dropped rather than duplicated, so there is one
  id to quote and it is ours. An L4 flow and a TLS passthrough are tunnels
  rather than requests: they get an id on the access line and the span, and
  have no HTTP response to put a header on.

### Fixed

- Both READMEs quoted the iroh version wrongly in two ways at once: as pinned at
  1.0.1, when it is declared `^1.0.1` and `Cargo.lock` resolves 1.2.0. The line
  now defers to `docs/iroh-boundaries.md`, which states it correctly.

## [0.2.0] — 2026-09-28

A hardening release: a full review of the tree — server, client library, Android
and desktop — produced a batch of security and correctness fixes, alongside
configurable health checks, a draining shutdown, and access logs on the iroh
tunnel path. It carries **breaking changes**: `default_backend` is removed, and
the server now refuses some configs it used to "fix" silently.

This entry is retrospective: 0.2.0 shipped before this file existed.

### Added

- Health checks are configurable. `[health_check] enabled = false` turns probing
  off, so a backend with no health endpoint is a supported deployment instead of
  a source of log noise (#47).
- CodeQL scanning, with a config in `.github/codeql/codeql-config.yml` (#47).
- `docs/ROADMAP.md` — where the project stands, what is missing, and in what
  order it is meant to be fixed (#47).
- `third_party/smoltcp/PATCHES.md`, documenting the vendored smoltcp patch that
  `third_party/` exists to carry (#48).
- Android: a lint baseline with `warningsAsErrors`, so a *new* lint warning
  fails CI while a recorded one stays quiet (#48).

### Changed

- Shutdown drains instead of sleeping. It counts the connections both accept
  loops spawned and waits for them, with a bound so a stuck peer cannot hold the
  process open (#47).
- The iroh path is logged at startup, including the relay that actually took
  effect (#47).
- Release artifact names are unified across the server archives, the desktop
  bundles and the APK, under one rule (`<product>-<version>-<platform>.<ext>`)
  (#47).
- Hardening across the server and the client: stricter config validation,
  request handling and connection-lifecycle handling; secret scanning through
  `.gitleaks.toml`; hardened Dockerfiles and per-platform build scripts (#50).

### Fixed

- A single failed health probe emptied a backend pool. `failure_threshold` was
  stored and logged but never consulted; it is now the count that takes a
  backend out of rotation (#47).
- Android: the credential key is no longer regenerated when the keystore reports
  an error. On API 26 generating a key under an existing alias deletes that
  entry first, so one transient failure used to make every stored credential
  unreadable (#51).

### Removed

- The top-level `default_backend`. A config that still names it is refused at
  startup rather than silently ignored, so an existing config cannot quietly
  start answering 404 where it used to forward. "Send everything here" is now
  spelled as a catch-all route, `host_pattern = "*"` (#48).

## [0.1.1] — 2026-09-27

### Added

- `[peers]` Node ID allow-list. A malformed entry is fatal rather than dropped:
  a list whose whole purpose is to refuse strangers must not silently come out
  shorter than it was written (#44).
- 2FA can be enabled on a running server. `[auth] enabled` moves on a config
  reload, taking effect for connections opened after it (#44).

### Changed

- The Rust tree is formatted with rustfmt, and the CI format check is now
  blocking (#46).

### Fixed

- Line endings pinned with `.gitattributes`, so a checkout on another platform
  stops producing diffs that are only line endings (#45).
- The Chinese README re-synced with the English one (#45).

## [0.1.0] — 2026-09-26

The first tagged release, and the release that turned NexaPipe into a monorepo.

### Added

- The server, the client library and the L4 wire format (#1, `6d97ad0`).
- 2FA (TOTP) authentication with diagnostics, unified relay configuration, and
  per-platform packaging (#1).
- One-time enrollment invites, so a leaked invite URL stops being a credential
  forever: the first device to scan one trades it for a freshly generated secret
  (#31).
- Per-client host authorization (#15).
- The Android and desktop apps, imported with their full git history from their
  former standalone repos, with unified CI and release pipelines (#15).

### Fixed

- Release pipeline unblocked; comments and docs are English only (#33).
