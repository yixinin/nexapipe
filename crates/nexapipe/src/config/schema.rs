//! The shapes of the configuration file.
//!
//! Every section here refuses the keys it does not know: a key that is not read
//! is a key the operator believes is read, and a setting that silently does not
//! apply looks exactly like a setting that is off.

use crate::conn::limits::LimitsConfig;

use nexapipe_proto::secret::SecretString;

use serde::Deserialize;

use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address of the plaintext listener. **Absent means "do not bind it at
    /// all"**, and that is the default: every client that authenticates comes
    /// in over iroh, and nothing on this listener can be gated — the 2FA
    /// handshake lives in the iroh accept loop (`crate::conn`), so a request
    /// that arrives here reaches a route without ever answering for itself.
    /// Configure it for a client on the same host (a sidecar, another
    /// container sharing the network namespace), not for the network.
    pub listen_addr: Option<String>,
    /// Allow [`Self::listen_addr`] to name something other than loopback.
    ///
    /// Opt-in because binding a non-loopback address publishes every `http`
    /// route and every `passthrough` backend to whoever can reach the port,
    /// with no authentication step in between. Set it only when something
    /// downstream does the gating (a reverse proxy, a firewall, a private
    /// network you control).
    pub expose: Option<bool>,

    // ---- Removed keys, still accepted so an existing config.toml keeps parsing ----
    //
    // This process no longer terminates TLS: the backend does (Caddy &co). The
    // fields below are kept only so `ProxyConfig::from_file` does not fail on a
    // config written for the old layout; `warn_removed_tls_keys` logs them at
    // startup and they can be deleted from the file.
    pub tls_enabled: Option<bool>,
    pub tls_listen_addr: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

/// The `[admin]` section: the auxiliary listener for liveness and metrics.
///
/// Separate from `[server]` on purpose. `[server] listen_addr` serves routes,
/// so a request arriving there is matched against the routing table before
/// anything else can look at it; this listener answers questions about the
/// proxy itself, and has to keep answering them when routing is the thing that
/// is broken.
///
/// **Loopback only, with no `expose`.** Nothing here should be reachable from
/// the network: it names the routes, the clients and the backends, and the
/// unauthenticated paths carry no credential check.
///
/// **There is deliberately no `token` key.** The token that guards `/v1/*` is
/// generated on first start into a file next to this one; a key here would put
/// a credential into the file operators copy around and commit, and writing it
/// back would trip the watcher that reloads on the config's mtime. See
/// [`crate::admin::token`].
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Address of the auxiliary listener. **Absent means "do not bind it"**,
    /// and that is the default: an instance that is not being scraped or
    /// supervised should not hold a port open for it.
    pub listen_addr: Option<String>,
}

/// The `[metrics]` section: whether `/metrics` is served at all.
///
/// A config gate rather than a cargo feature because it is a runtime choice:
/// the same binary is deployed with and without a scraper, and a feature would
/// mean a second build-and-test combination in CI and in every release for a
/// decision a deployment makes per host.
#[derive(Debug, Deserialize, Clone, Copy, Default)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Serve `/metrics` on the `[admin]` listener. Default: `false`.
    ///
    /// Off by default because the listener it hangs off is unauthenticated:
    /// nothing is exposed until someone asks for it *and* binds the address.
    pub enabled: bool,
}

/// `Default` because the startup path builds one from scratch when a config
/// has no `[iroh]` section at all but still needs somewhere to put the secret
/// key it just generated. Every field is optional, so "all of them absent" is
/// exactly what an empty `[iroh]` means.
#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct IrohConfig {
    pub relay_url: Option<String>,
    pub relay_mode: Option<String>,
    /// Bearer token sent to the relay. Only meaningful with `relay_mode = "custom"`;
    /// a relay that requires one has to be configured on both sides, because the
    /// client's relay map is the only place its token is read from.
    ///
    /// A [`SecretString`], for the same reason the key above is one.
    pub relay_auth_token: Option<SecretString>,
    /// Whether this endpoint may use n0's address lookup — the DNS and pkarr
    /// queries that turn a Node ID into "where do I send QUIC packets".
    ///
    /// `"n0"` (the default) keeps it: the endpoint publishes its own address
    /// there and resolves other endpoints' addresses through it. `"none"`
    /// switches it off, and nothing this endpoint sends reaches n0's lookup
    /// service — at the price of a Node ID no longer being enough to reach
    /// this endpoint: a peer has to bring an address of its own (a ticket).
    ///
    /// A value that is present but unknown refuses the start, the same rule
    /// the relay modes follow.
    pub discovery: Option<String>,
    pub bind_port: Option<u16>,
    /// Also bind the IPv6 wildcard (`[::]`) on the same port.
    ///
    /// Off unless asked for, so a config written before this existed keeps
    /// binding exactly what it binds today.
    ///
    /// It is "also", not "instead": the IPv4 socket stays. An endpoint that
    /// could only be reached over IPv6 would be a regression for every client
    /// that has no IPv6 route, and the two sockets are independent here, so
    /// there is nothing to trade off — turning this on adds a socket, it does
    /// not move one.
    ///
    /// Only meaningful together with `bind_port`: without a fixed port there is
    /// nothing to keep the two families on the same one.
    pub bind_ipv6: Option<bool>,
    /// Secret key for stable endpoint identity.
    ///
    /// Optional in the config because the server generates one on first start
    /// when this is absent, and writes it here — so a config that never
    /// mentions it still ends up with a Node ID that survives a restart. Set it
    /// by hand only to move an identity between hosts, or to keep one when the
    /// file is not writable (see `NEXAPIPE_NO_PERSIST_IDENTITY`).
    ///
    /// A value that is present but does not parse refuses the start.
    ///
    /// A [`SecretString`]: this is the endpoint's private key — the thing that
    /// makes the Node ID yours — and it is wiped when the config is dropped.
    pub secret_key: Option<SecretString>,
    /// Path to a file holding `secret_key`, for a config that must not carry
    /// the key itself.
    ///
    /// The point is the permission gate: a config whose only credential is a
    /// pointer holds nothing worth reading, so it can stay `0644` — a Docker
    /// bind mount, a file an operator edits — while the key file it names is
    /// held to the `0600` rule in its place. See [`CredentialSource`].
    pub secret_key_file: Option<String>,
    /// Path to a file holding `relay_auth_token`, same idea as
    /// [`Self::secret_key_file`] for the relay bearer token.
    pub relay_auth_token_file: Option<String>,
    /// Where `secret_key` was resolved from. Filled by
    /// `ProxyConfig::resolve_external_credentials` during the load; not
    /// spelled in the file, so `serde` skips it.
    #[serde(skip)]
    pub secret_key_source: CredentialSource,
    /// Where `relay_auth_token` was resolved from. See
    /// [`Self::secret_key_source`].
    #[serde(skip)]
    pub relay_auth_token_source: CredentialSource,
}

/// Where a `[iroh]` credential was resolved from.
///
/// [`ProxyConfig::holds_credentials`] asks this: the permission gate is about
/// what an account that reads *the config file* would obtain, and a credential
/// that came from the environment or from a pointed-to file is not in the
/// config for anyone to read. Only the inline literal makes the file itself a
/// credential holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialSource {
    /// The literal value written in config.toml.
    #[default]
    Inline,
    /// `NEXAPIPE_IROH_SECRET_KEY` / `NEXAPIPE_RELAY_AUTH_TOKEN`.
    Env,
    /// The file `secret_key_file` / `relay_auth_token_file` names.
    File,
}

/// `Some(_)` becomes `Some("<redacted>")` for a `Debug` view.
///
/// Keeping the `Option` shape is the point: whether a credential is configured
/// at all is something an operator needs to see in a log, and it is not the
/// credential.
pub(crate) fn redacted(value: &Option<SecretString>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
}

/// Handwritten so the endpoint's credentials never reach a log line.
///
/// `ProxyConfig` is logged at debug level whenever it is parsed — including on
/// every hot reload, where the logger is already installed — and a derived
/// `Debug` would put the ed25519 private key and the relay bearer token on that
/// line. Reading the log would then be enough to own this endpoint's identity
/// permanently, which is worse than losing one client's TOTP seed.
impl std::fmt::Debug for IrohConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohConfig")
            .field("relay_url", &self.relay_url)
            .field("relay_mode", &self.relay_mode)
            .field("relay_auth_token", &redacted(&self.relay_auth_token))
            .field("discovery", &self.discovery)
            .field("bind_port", &self.bind_port)
            .field("bind_ipv6", &self.bind_ipv6)
            .field("secret_key", &redacted(&self.secret_key))
            .field("secret_key_file", &self.secret_key_file)
            .field("secret_key_source", &self.secret_key_source)
            .field("relay_auth_token_file", &self.relay_auth_token_file)
            .field("relay_auth_token_source", &self.relay_auth_token_source)
            .finish()
    }
}

/// How a route talks to its backends.
///
/// * `Http` (default) — the proxy parses the request, applies the path rules
///   below and re-issues it with the shared HTTP client. Plaintext `http://`
///   backends only; TLS is not spoken to backends.
/// * `Passthrough` — the proxy copies raw bytes. Used for TLS, which is
///   terminated by the backend (Caddy &co): the route is selected by SNI and
///   `path_pattern` / `path_rewrite` do not apply.
/// * `Tcp` / `Udp` — the L4 tunnel (`crate::l4`). One inner connection is one
///   QUIC bi-stream carrying a preface that names the route and the port; the
///   backend address comes from this route's `backends`. Nothing here parses
///   HTTP, and `path_pattern` / `path_rewrite` do not apply.
///
/// The four modes never see each other's traffic: which one applies is decided
/// before any matching happens, by the first byte of the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteMode {
    #[default]
    Http,
    Passthrough,
    Tcp,
    Udp,
}

impl RouteMode {
    /// The spelling used in the config file and in `GET /v1/routes`.
    ///
    /// Deliberately not `Display` for now: the only two callers want a
    /// `&'static str` — one to write JSON, one to log — and a `Display` impl
    /// would invite formatting a mode into prose before anyone has decided how
    /// it should read there.
    pub fn name(self) -> &'static str {
        match self {
            RouteMode::Http => "http",
            RouteMode::Passthrough => "passthrough",
            RouteMode::Tcp => "tcp",
            RouteMode::Udp => "udp",
        }
    }

    /// True for the two modes the L4 tunnel serves.
    pub fn is_l4(self) -> bool {
        matches!(self, RouteMode::Tcp | RouteMode::Udp)
    }

    /// Which mode carries a given L4 preface protocol.
    pub fn from_l4_proto(proto: nexapipe_proto::L4Proto) -> Self {
        match proto {
            nexapipe_proto::L4Proto::Tcp => RouteMode::Tcp,
            nexapipe_proto::L4Proto::Udp => RouteMode::Udp,
        }
    }
}

/// The wire protocol a route speaks to its backends.
///
/// A separate thing from [`RouteMode`], which is about the *client*: how the
/// proxy serves the request that arrives. This is about what the proxy says
/// to the backend once the request has been rewritten.
///
/// * [`Self::Http1`] (default) — HTTP/1.1. An `https://` backend is spoken to
///   over TLS, where the handshake negotiates HTTP/2 with any backend that
///   offers it, and a cleartext one is spoken to over HTTP/1.1.
/// * [`Self::H2c`] — HTTP/2 in the clear, with prior knowledge. There is
///   nothing on a cleartext connection to negotiate, so the client has to know
///   that the backend speaks h2 and start speaking it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendProtocol {
    #[default]
    Http1,
    H2c,
}

impl BackendProtocol {
    /// The spelling used in the config file.
    pub fn name(self) -> &'static str {
        match self {
            BackendProtocol::Http1 => "http1",
            BackendProtocol::H2c => "h2c",
        }
    }
}

/// Reads the `backend_protocol` key.
///
/// Refused rather than guessed: a backend that only speaks h2 and a client
/// that speaks h1 do not talk to each other, and the operator should read
/// about that here rather than in the log of every request that failed.
pub fn get_backend_protocol(value: &Option<String>) -> anyhow::Result<BackendProtocol> {
    match value.as_deref().map(str::trim) {
        None | Some("") | Some("http1") => Ok(BackendProtocol::Http1),
        Some("h2c") => Ok(BackendProtocol::H2c),
        Some(other) => anyhow::bail!(
            "{other:?} is not a backend protocol; expected \"http1\" (the default) or \"h2c\""
        ),
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
    pub host_pattern: String,
    /// Defaults to `/`. Ignored when `mode = "passthrough"`.
    #[serde(default = "default_path_pattern")]
    pub path_pattern: String,
    pub path_is_prefix: Option<bool>,
    pub strategy: Option<String>,
    pub backends: Vec<String>,
    /// `"http1"` (default) or `"h2c"`. See [`BackendProtocol`].
    ///
    /// Only about the hop to the backend. An `https://` backend speaks HTTP/2
    /// whenever the handshake agrees on it, whatever this says; `"h2c"` is for
    /// the backend that speaks HTTP/2 in the clear, where there is no handshake
    /// to agree on anything.
    pub backend_protocol: Option<String>,
    /// `"http"` (default), `"passthrough"`, `"tcp"` or `"udp"`. See [`RouteMode`].
    pub mode: Option<String>,
    /// Several modes at once, sharing this route's `backends` — the ordinary way
    /// to write a host that answers both a request and a tunnel.
    ///
    /// `mode` and `modes` may be combined; the union is what the route serves.
    /// Two entries instead of one is still the way to give the modes different
    /// `backends`, since a route has exactly one pool.
    pub modes: Option<Vec<String>>,
    pub path_rewrite: Option<String>,
    /// `tcp` / `udp` routes: the client ports this route accepts.
    ///
    /// Only a selector — it decides whether the route matches, never where the
    /// connection goes. Leaving it out accepts every port, which is what you want
    /// when the backend port is the same one the client asked for.
    pub client_ports: Option<Vec<u16>>,
    /// `udp` routes: seconds of silence before a flow is closed. The server
    /// default (`[timeouts] l4_idle_secs`, itself 60) applies when this is
    /// absent.
    pub idle_timeout_secs: Option<u64>,
    /// `tcp` / `udp` routes: seconds one flow may run before it is closed. The
    /// server default (`deadline::DEFAULT_L4_FLOW_SECS`) applies when absent.
    ///
    /// Distinct from `idle_timeout_secs` on purpose: that one bounds the gap
    /// between packets and re-arms on each, while this bounds the flow. Raise it
    /// for a long-lived session — an interactive SSH connection or a database
    /// session over the tunnel is meant to outlive any default.
    pub flow_timeout_secs: Option<u64>,

    // ---- Removed keys, see `ServerConfig` ----
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub redirect_to_https: Option<bool>,
}

pub(crate) fn default_path_pattern() -> String {
    "/".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LocalProxyNode {
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
    pub domains: Vec<String>,
}

/// Client-side 2FA credentials used by local-proxy mode.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LocalProxyTwoFactorConfig {
    pub enabled: Option<bool>,
    pub client_id: String,
    pub secret: String,
    pub algorithm: Option<String>,
}

/// Handwritten for the same reason as [`IrohConfig`]'s: this is the client side
/// of a TOTP secret, and the whole config is logged when it is parsed.
impl std::fmt::Debug for LocalProxyTwoFactorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalProxyTwoFactorConfig")
            .field("enabled", &self.enabled)
            .field("client_id", &self.client_id)
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LocalProxyConfig {
    pub enabled: bool,
    pub listen_addr: String,
    /// Whether the local proxy may bind an address that is reachable from the
    /// network.
    ///
    /// Off by default, and the same shape as `[server] expose`: the local proxy
    /// hands out the tunnel of a connection that has already authenticated, so
    /// anything that reaches the port gets the tunnel without a credential.
    /// Turning this on says that something else gates the port.
    pub expose: Option<bool>,
    pub proxy_domains: Vec<String>,
    pub nodes: Option<Vec<LocalProxyNode>>,
    pub strategy: Option<String>,
    /// Full server ticket (contains Node ID + addresses)
    /// Ticket changes when addresses change, but connection info is complete
    /// Deprecated: use `nodes` for multi-endpoint support
    pub server_ticket: Option<String>,
    /// Server Node ID only (stable across restarts when using secret_key)
    /// When set, uses discovery service to find server addresses
    /// Preferred for long-term configurations
    /// Deprecated: use `nodes` for multi-endpoint support
    pub server_node_id: Option<String>,
    /// 2FA credentials used to authenticate with the server.
    /// Example:
    ///   [local_proxy.two_factor]
    ///   enabled = true
    ///   client_id = "client-001"
    ///   secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    ///   algorithm = "sha1"
    pub two_factor: Option<LocalProxyTwoFactorConfig>,
}

/// Logging configuration (`[log]` section).
///
/// Every field is optional; the defaults (see `log::init`) keep the previous
/// behaviour of logging to stdout and add rotating files under `./logs`.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Write the log to files. Default: `true`.
    pub file: Option<bool>,
    /// Directory holding the log files. Default: `./logs`.
    /// Can be overridden with the `NEXAPIPE_LOG_DIR` environment variable.
    pub dir: Option<String>,
    /// Name of the active log file. Default: `nexapipe.log`.
    /// Rotated copies are written next to it as `nexapipe.<timestamp>.log`.
    pub file_name: Option<String>,
    /// Emit one line per proxied request. Default: `true`.
    pub access_log: Option<bool>,
    /// Name of the access log file. Default: `access.log`.
    pub access_log_file_name: Option<String>,
    /// Rotation interval: `daily` (default), `hourly` or `never`.
    pub rotation: Option<String>,
    /// Also rotate once the active file is bigger than this (MiB, 0 = off). Default: 0.
    pub max_size_mb: Option<u64>,
    /// Rotated files to keep per log file (0 = keep all). Default: 14.
    pub max_files: Option<usize>,
    /// Keep logging to stdout as well. Default: `true`.
    pub console: Option<bool>,
    /// Replace query parameter values with `<redacted>` in the access log.
    /// Default: `true`.
    ///
    /// Parameter names are kept, because they are what makes an access log
    /// useful when you read it back; values are not, because that is where
    /// tokens and signatures travel. Set it to `false` to log request URIs
    /// verbatim — only do that on a log file nobody else can read.
    pub redact_query: Option<bool>,
}

/// The `[timeouts]` section: how long one round trip to a backend may take,
/// and how long each phase of a proxied exchange may hold its slot.
///
/// Two families of wait live here, and keeping them in one section is the point:
/// they are all "a bound that expires as a diagnostic, not a quota", and a
/// deployment that needs one of them raised usually needs to reason about the
/// others beside it.
///
/// The first family covers one step of talking to a backend — dialing it, or
/// waiting for its answer — and deliberately not the request as a whole: once
/// a response head arrives, streaming its body may run for as long as it needs
/// to, on purpose, because "slow backend" is not the same failure as "silent
/// backend".
///
/// The second family bounds the phases of the exchange itself: how long a
/// client may take to send its head and body, how long a streamed response may
/// stay silent between chunks, how long an L4 flow may run and how idle a UDP
/// flow may go, how long a TLS hello may take. See
/// [`crate::deadline`] for which of these are phase deadlines — taken once and
/// never renewed, which is what stops a one-byte trickle from holding a slot
/// forever — and which are idle timeouts, correct only where the phase is
/// meant to stay open.
///
/// Every key is optional, and every default is the constant the server used
/// before this section existed, so writing `[timeouts]` and nothing under it
/// changes nothing.
///
/// Read once at startup, not live: these are handed to the HTTP client builder
/// and to the stream handlers when they start, so an edit takes a restart.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct TimeoutsConfig {
    /// Seconds allowed for dialing a backend. Default: 10.
    ///
    /// One value because it is one thing: the HTTP path (including WebSocket
    /// upgrades), TLS passthrough and the L4 tunnel all dial exactly one TCP
    /// connection toward exactly one backend, and before this existed they each
    /// carried their own copy of ten seconds.
    ///
    /// Dialing ends when the connection is up, so this has to cover the network
    /// and nothing the backend says afterwards — raise it for a backend across
    /// a slow or lossy link, where a too-short one turns every request into a
    /// failure that looks like the backend being down.
    pub connect_secs: Option<u64>,
    /// Seconds a backend may take to answer with a status line. Default: 30.
    ///
    /// This is the wait for the response head, not for the response: the moment
    /// the head arrives the deadline is over, and a one-hour stream can follow
    /// it. It is the number to raise for an API that computes before it
    /// answers, and what stops a backend that accepts the connection and then
    /// says nothing from holding the request slot until the client gives up.
    pub response_secs: Option<u64>,
    /// Seconds a client may take to send its request head. Default: 30.
    ///
    /// A **phase deadline**, taken once when the head starts arriving: a client
    /// that trickles one byte of `Host:` every few seconds holds a slot, a task
    /// and a connection slot, and a per-read timeout is exactly what it wants.
    /// This is the number that closes that. See [`crate::deadline`].
    ///
    /// It bounds the head, not the stream: the first byte says which protocol
    /// the stream carries, and until it arrives the protocol is unknown, so the
    /// wait for it is the longer of this and [`Self::tls_hello_secs`]. A short
    /// `header_secs` therefore never cuts off a TLS session or an L4 tunnel —
    /// neither of them sends a request head at all.
    pub header_secs: Option<u64>,
    /// Seconds a client may take to send a request body once the head is in.
    /// Default: 300.
    ///
    /// A **phase deadline**, separate from the head because a large upload
    /// legitimately takes longer than a header does; one budget for both would
    /// be too short for uploads or too loose against a stalled one.
    pub body_secs: Option<u64>,
    /// Seconds a backend response body may stay silent before it is treated as
    /// dead. Default: 120.
    ///
    /// **Idle, not a phase deadline**, and deliberately so: a streamed response
    /// or a server-sent-events stream is supposed to be open for as long as the
    /// two ends want. What must not be possible is a backend that sent the head
    /// and then said nothing at all, so the bound is on the gap between chunks
    /// and re-arms on every chunk by design.
    ///
    /// It applies to every path that proxies a response, the plaintext
    /// listener included: there the body is handed to the client as it arrives,
    /// and a backend that stalls mid-body fails the response rather than
    /// truncating it quietly.
    pub response_idle_secs: Option<u64>,
    /// Seconds an L4 tunnel may run before it is closed. Default: 3600.
    ///
    /// A **phase deadline**, because an L4 flow has no protocol-level end: a
    /// backend connection that never closes and never sends is indistinguishable
    /// from one being used, and bounding the whole flow is what stops a peer
    /// from renewing it indefinitely. Raise it for long-lived SSH or a database
    /// session over the tunnel; a per-route [`crate::routes`] `flow_timeout_secs`
    /// overrides it for one route alone.
    pub l4_flow_secs: Option<u64>,
    /// Seconds between two UDP datagrams in either direction before an L4 flow
    /// is considered idle. Default: 60.
    ///
    /// **Idle**, because a UDP flow has no "complete" to wait for; this bounds
    /// the gap, not the flow, and re-arming on every datagram is the correct
    /// shape here.
    pub l4_idle_secs: Option<u64>,
    /// Seconds a TLS ClientHello may take to arrive. Default: 10.
    ///
    /// A **phase deadline**. The client sends the record header and then the
    /// body of it; a peer that sends the five header bytes and nothing else
    /// would otherwise hold the connection open indefinitely with no read
    /// deadline at all.
    ///
    /// It also covers the wait for the session's first byte, on both
    /// listeners: that byte is what says a TLS session is starting, so it
    /// belongs to the hello rather than to the head.
    pub tls_hello_secs: Option<u64>,
}

/// The `[timeouts]` section with every default filled in.
///
/// The file answers "was this key written?"; this answers "how long do I wait?",
/// which is the question the rest of the server actually asks. Reading either
/// field of the config directly would put `.unwrap_or(TEN_SECONDS)` in every
/// call site — three of them today — and one of them would eventually disagree
/// with the others.
///
/// `deadlines` carries the per-phase budgets ([`crate::deadline::Deadlines`])
/// resolved from the same section, so a handler that needs "how long may the
/// client take to send its head" reads it off the `Timeouts` it was already
/// handed rather than reaching the config itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub connect: std::time::Duration,
    pub response: std::time::Duration,
    pub deadlines: crate::deadline::Deadlines,
}

impl Timeouts {
    /// The deadlines a server without a `[timeouts]` section runs with, i.e. the
    /// constants this section replaced.
    const DEFAULT_CONNECT: std::time::Duration = std::time::Duration::from_secs(10);
    const DEFAULT_RESPONSE: std::time::Duration = std::time::Duration::from_secs(30);

    /// The longest wait either dial key accepts: an hour spent dialing, or
    /// waiting for a status line, is not a slow backend but one that will never
    /// answer.
    pub(crate) const MAX_SECS: u64 = 3600;

    pub fn resolve(config: TimeoutsConfig) -> Self {
        let deadlines = crate::deadline::Deadlines::resolve(&crate::deadline::Overrides {
            header_secs: config.header_secs,
            body_secs: config.body_secs,
            response_idle_secs: config.response_idle_secs,
            l4_flow_secs: config.l4_flow_secs,
            l4_idle_secs: config.l4_idle_secs,
            tls_hello_secs: config.tls_hello_secs,
        });
        Timeouts {
            connect: config
                .connect_secs
                .map_or(Self::DEFAULT_CONNECT, std::time::Duration::from_secs),
            response: config
                .response_secs
                .map_or(Self::DEFAULT_RESPONSE, std::time::Duration::from_secs),
            deadlines,
        }
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self::resolve(TimeoutsConfig::default())
    }
}

/// The `[health_check]` section: periodic `GET {path}` probing of `http` route
/// backends.
///
/// A switch rather than a behaviour everyone gets, because a probe is only
/// meaningful if the backend answers it. Plenty of backends — a device's web UI
/// that answers 5xx on an unknown path, or one that does not speak HTTP and so
/// times out — cannot answer a probe at all, and before this section existed a
/// single failed probe was enough to take such a backend out of rotation for
/// good. Set `enabled = false` for those: every backend stays in the pool and
/// traffic is simply forwarded, which is what the proxy did before health checks
/// existed. A backend that 404s, or answers any 2xx, is already counted healthy,
/// so having no dedicated health endpoint is not on its own a reason to opt out.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// `false` disables probing entirely. Default: `true`.
    pub enabled: bool,
    /// Seconds between two rounds of checks. Default: 10.
    pub interval: u64,
    /// Seconds before a single check is abandoned. Default: 5.
    pub timeout: u64,
    /// Consecutive failed checks before a backend leaves the pool. One failure
    /// is never enough: a probe lost to a restart or a GC pause must not empty
    /// the pool. Default: 3.
    pub threshold: usize,
    /// Path appended to the backend URL. Default: `/health`.
    pub path: String,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        HealthCheckConfig {
            enabled: true,
            interval: 10,
            timeout: 5,
            threshold: 3,
            path: "/health".to_string(),
        }
    }
}

/// The whole configuration file.
///
/// **An unknown key is an error.** Every section refuses the keys it does not
/// know, and so does the top level: a key that is not read is a key the
/// operator believes is read, and a setting that silently does not apply
/// looks exactly like a setting that is off. `exposee = true` under
/// `[server]` used to be dropped without a word.
///
/// The two keys that exist only to be refused — `default_backend` and
/// `[acme]` — are still parsed, so a config carrying one is told what to do
/// with it instead of being accepted and ignored.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// **Removed.** Kept in the struct for exactly one reason: serde drops keys
    /// it does not know, so deleting this field would let a config that still
    /// names a `default_backend` keep running — and quietly start answering 404
    /// for hosts it used to forward somewhere. Parsed as an opaque value so its
    /// presence is detected, and refused by [`Self::build_routes`].
    ///
    /// What it did is spelled as a route now: `host_pattern = "*"`.
    #[serde(default)]
    pub default_backend: Option<toml::Value>,
    pub debug: Option<bool>,
    pub routes: Option<Vec<RouteSpec>>,
    pub server: Option<ServerConfig>,
    pub iroh: Option<IrohConfig>,
    pub local_proxy: Option<LocalProxyConfig>,
    /// Which client Node IDs may hold a connection at all. Optional, and
    /// different in kind from `[auth]`: this is not a second factor, so it is
    /// what a server without 2FA uses to stop being reachable by anyone who
    /// learns the Node ID. See [`crate::conn::allow_list`].
    pub peers: Option<PeersConfig>,
    /// Removed: certificates are managed by the backend now. Parsed as an opaque
    /// value so `[acme]` is detected and reported, not silently swallowed.
    pub acme: Option<toml::Value>,
    pub log: Option<LogConfig>,
    /// Probing of `http` backends. Absent means the defaults, i.e. enabled.
    #[serde(default)]
    pub health_check: HealthCheckConfig,
    /// The ceilings the whole process runs under: connections per peer and in
    /// total, streams in flight, and bytes held in request bodies. Absent means
    /// the defaults, i.e. the constants this section replaced, unchanged.
    ///
    /// **Read once at startup**, not live: a budget that changed under an
    /// in-flight upload would release bytes against a ceiling it was never
    /// counted against. See [`crate::conn::limits`].
    #[serde(default)]
    pub limits: LimitsConfig,
    /// How long to wait on a backend, and how long each phase of a proxied
    /// exchange may hold its slot. Absent means the deadlines this section
    /// replaced, unchanged.
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    /// The auxiliary listener for `/healthz` and `/metrics`. Absent means it is
    /// not bound at all.
    pub admin: Option<AdminConfig>,
    /// Whether `/metrics` is served. Absent means it is not.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// How the proxy reaches the backends. Absent means the defaults, i.e. the
    /// machine's own trust store and nothing else.
    #[serde(default)]
    pub backends: BackendsConfig,
    /// How often a failed request is tried again. Absent means it is not.
    #[serde(default)]
    pub retry: RetryConfig,
    /// When a backend that keeps failing stops being picked. Absent means it
    /// is, with the defaults.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// The `[auth]` section, as far as the port rule is concerned.
    ///
    /// The 2FA half of the file is parsed by [`Self::load_with_auth`], which
    /// owns the seeds and the rules around them — this section is where they
    /// are validated, where the enrollment tokens live and where the counters
    /// are read. The top level refuses the keys it does not know, and `[auth]`
    /// is not one of them.
    ///
    /// Only the two keys that say which of the two port rules a client is held
    /// against are read here, and no credential is among them: the seeds stay
    /// with the loader that owns them, and a copy of them inside this struct
    /// would be a second copy of every secret in the file, held for as long as
    /// the configuration lives.
    ///
    /// Read at all so the operator can be told which rule is in force. A port
    /// list held against the port a client names is a weaker restriction than
    /// it looks — a request that names no port is not checked at all — and the
    /// flag that says so is not in the name of the setting.
    #[serde(default, deserialize_with = "deserialize_auth_port_rules")]
    pub(crate) auth: Option<AuthPortRules>,
}

/// The `[auth]` section, as far as the port rule is concerned.
///
/// The credentials in that section belong to the auth loader, and this struct
/// keeps none of them: it reads the two keys that say which of the two port
/// rules a client is held against, and ignores everything else in the section.
/// An ignored value is never copied, so the seeds in the file stay in the one
/// place that owns them.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct AuthPortRules {
    /// The clients, by id.
    #[serde(default)]
    pub clients: HashMap<String, ClientPortRule>,
}

/// One client's port rule: the list of ports, and the port it is held against.
///
/// The two keys are the whole of it. `allow_ports` is the list, and
/// `allow_ports_strict` says whether that list is checked against the port the
/// request is *served from* (the stronger rule) or the one the client *names*
/// (the historical one).
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct ClientPortRule {
    /// The ports this client may reach.
    #[serde(default)]
    pub allow_ports: Option<Vec<u16>>,
    /// Whether the list is checked against the port the request is served from.
    #[serde(default)]
    pub allow_ports_strict: Option<bool>,
}

impl AuthPortRules {
    /// The clients whose port list is held against the port the client names.
    ///
    /// A client with no port list is not limited by ports at all, and a client
    /// with `allow_ports_strict` on is held against the port the request is
    /// served from — the stronger rule. What is left is the historical one,
    /// and it is the one an operator has to be told about.
    pub fn clients_with_the_named_port_rule(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self
            .clients
            .iter()
            .filter(|(_, client)| {
                client.allow_ports.is_some() && !client.allow_ports_strict.unwrap_or(false)
            })
            .map(|(id, _)| id.as_str())
            .collect();
        ids.sort_unstable();
        ids
    }
}

/// Reads the `[auth]` section far enough to know which port rule is in force,
/// and says so when it is the weaker one.
///
/// Said here, at the parse, because this is the one point every reader of the
/// file passes through — the startup path included — and a second read of the
/// same section would be a second pass over the credentials in it.
fn deserialize_auth_port_rules<'de, D>(deserializer: D) -> Result<Option<AuthPortRules>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let rules = Option::<AuthPortRules>::deserialize(deserializer)?;
    if let Some(rules) = &rules {
        for client in rules.clients_with_the_named_port_rule() {
            tracing::warn!(
                "[auth.clients.{client}] has an allow_ports list but allow_ports_strict is off: \
                 the list is checked against the port the client names, and a request that \
                 names no port is not checked at all. Set allow_ports_strict = true to check \
                 the port the request is served from"
            );
        }
    }
    Ok(rules)
}

/// The `[backends]` section: how the proxy reaches the backends themselves.
///
/// One key today, and it is about trust rather than about transport: the
/// certificates an `https://` backend is checked against. The transport is
/// decided per route — an `http://` backend is fetched in the clear, an
/// `https://` one over a TLS session this process originates.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct BackendsConfig {
    /// A PEM file of extra CA certificates to trust when verifying an
    /// `https://` backend, for a backend whose certificate is signed by an
    /// internal authority the machine does not know.
    ///
    /// The machine's own roots are trusted as well; this *adds* to them, it
    /// does not replace them. There is deliberately no way to trust a
    /// certificate without checking it: a proxy that connects to a backend
    /// without knowing who it is talking to can be redirected by whoever
    /// answers the name.
    pub ca_file: Option<String>,
}

/// The `[retry]` section: how often a request that failed is tried again.
///
/// Off by default, because a retry is a second attempt at something the
/// backend may already have done: a request that failed on the way *to* the
/// backend is safe to try again, and one that failed after the backend had it
/// is not, unless the request was idempotent to begin with. What may be
/// retried, and what may not, is spelled out in `crate::http`.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct RetryConfig {
    /// How many times a request may be tried again after it failed. Default: 0,
    /// which is no retry at all.
    ///
    /// A retry asks the route for a *different* backend where the route has
    /// one, because the backend that just failed is the one most likely to
    /// fail again.
    pub attempts: Option<u64>,
    /// Milliseconds to wait before the next attempt. Default: 100.
    ///
    /// Not zero by default: a backend that refused the connection because it
    /// is restarting refuses the next one too, and asking again immediately
    /// turns one outage into as many attempts as the section allows.
    pub backoff_ms: Option<u64>,
}

/// The `[retry]` section with every default filled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    /// How many *extra* attempts a failed request may have. Zero means one
    /// try and no more.
    pub attempts: u32,
    /// How long to wait between two attempts.
    pub backoff: std::time::Duration,
}

impl Retry {
    const DEFAULT_BACKOFF_MS: u64 = 100;
    /// The most attempts a section may ask for. A hundred is already a
    /// request that has been failing for a minute; more than that is a
    /// request that should have been given up on.
    const MAX_ATTEMPTS: u64 = 16;
    const MAX_BACKOFF_MS: u64 = 60_000;

    pub fn resolve(config: RetryConfig) -> Self {
        Retry {
            attempts: config.attempts.unwrap_or(0).min(Self::MAX_ATTEMPTS) as u32,
            backoff: std::time::Duration::from_millis(
                config
                    .backoff_ms
                    .unwrap_or(Self::DEFAULT_BACKOFF_MS)
                    .min(Self::MAX_BACKOFF_MS),
            ),
        }
    }
}

impl Default for Retry {
    fn default() -> Self {
        Self::resolve(RetryConfig::default())
    }
}

/// The `[circuit_breaker]` section: when a backend that keeps failing stops
/// being picked.
///
/// A health probe says what a backend looked like the last time somebody
/// asked. A circuit breaker says what the traffic itself found: this backend
/// refused the last five connections, so stop sending it any until it has had
/// a chance to come back. The two answer different questions and are meant to
/// be on at the same time.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct CircuitBreakerConfig {
    /// `false` leaves every backend in rotation however it fails. Default:
    /// `true`.
    pub enabled: Option<bool>,
    /// Consecutive failures before a backend stops being picked. Default: 5.
    ///
    /// More than one, because a single refused connection is a blip and a
    /// backend taken out of rotation on one is a backend that stays out.
    pub failure_threshold: Option<u64>,
    /// Seconds before an open circuit lets a request through to try the
    /// backend again. Default: 30.
    ///
    /// The request that gets through is a trial: it decides whether the
    /// circuit closes again, and the backend is out of rotation until it
    /// answers.
    pub reset_secs: Option<u64>,
}

/// The `[circuit_breaker]` section with every default filled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreaker {
    pub enabled: bool,
    pub failure_threshold: usize,
    pub reset: std::time::Duration,
}

impl CircuitBreaker {
    const DEFAULT_FAILURE_THRESHOLD: u64 = 5;
    const DEFAULT_RESET_SECS: u64 = 30;
    const MAX_FAILURE_THRESHOLD: u64 = 1000;
    const MAX_RESET_SECS: u64 = 3600;

    pub fn resolve(config: CircuitBreakerConfig) -> Self {
        CircuitBreaker {
            enabled: config.enabled.unwrap_or(true),
            failure_threshold: config
                .failure_threshold
                .unwrap_or(Self::DEFAULT_FAILURE_THRESHOLD)
                .clamp(1, Self::MAX_FAILURE_THRESHOLD) as usize,
            reset: std::time::Duration::from_secs(
                config
                    .reset_secs
                    .unwrap_or(Self::DEFAULT_RESET_SECS)
                    .min(Self::MAX_RESET_SECS),
            ),
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::resolve(CircuitBreakerConfig::default())
    }
}

/// The `[peers]` section: a server-side allow-list of client public keys.
///
/// Deliberately not a key under `[auth]`. It is the knob for exactly the server
/// the "no allow-list" gap describes — one running with 2FA off — so tying it to
/// a section that server may not even have would bury it, and its semantics do
/// not depend on `[auth] enabled` either way. `[peers]` is checked on every
/// inbound connection, before the accept loop sees it.
///
/// Unknown keys are refused here, for the reason they are refused under
/// `[auth]`: the only key this section has is `allow`, and `allow` absent means
/// unrestricted, so `allowed = [...]` instead of `allow = [...]` would leave a
/// server that looks restricted and is not, with nothing in the log to say so.
/// A typo here is a security change rather than a lost setting.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PeersConfig {
    /// Node IDs allowed to connect. `None` (the section present but the key
    /// absent) means unrestricted, like every build before this existed.
    ///
    /// A present-but-*empty* list is refused at load time rather than read as
    /// "refuse everybody": "restrict to nobody" is a plausible typo, and the
    /// cost of guessing wrong is an operator locked out of their own server. An
    /// empty list is spelled by naming one Node ID that is not yours.
    pub allow: Option<Vec<String>>,
}

impl PeersConfig {
    /// Parses the configured Node IDs into the set the hook checks against.
    ///
    /// Fails on anything that is not a valid Node ID rather than skipping it: a
    /// typo in one entry of a list whose whole job is to refuse strangers would
    /// otherwise silently narrow the allow-list, and a silent narrowing here is
    /// worse than a refusal to start.
    pub fn parse_allow_list(
        &self,
    ) -> anyhow::Result<Option<std::collections::HashSet<iroh::EndpointId>>> {
        let Some(entries) = &self.allow else {
            return Ok(None);
        };

        if entries.is_empty() {
            anyhow::bail!(
                "[peers] allow = [] refuses every peer, including the operator's own clients. \
                 Remove the key to leave the listener unrestricted, or list the Node IDs that \
                 may connect"
            );
        }

        let mut allowed = std::collections::HashSet::with_capacity(entries.len());
        for entry in entries {
            let id: iroh::EndpointId = entry
                .parse()
                .map_err(|e| anyhow::anyhow!("[peers] allow: {entry:?} is not a Node ID ({e})"))?;
            allowed.insert(id);
        }
        Ok(Some(allowed))
    }
}
