use crate::proxy::dns::DnsServerConfig;
use crate::proxy::dns_config::DnsStrategy;
use crate::proxy::local_proxy::LocalProxyWrapper;
use crate::proxy::tun_proxy::{tun_ip, TunProxy, TunProxyConfig};
use anyhow::Result;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use nexapipe_client::auth::{
    DeviceKey, Enrollment, IssuedCredential, TotpAlgorithm, TwoFactorAuth,
};
use nexapipe_client::connection_pool::parse_endpoint_addr;
use nexapipe_client::discovery::DiscoveryMode;
use nexapipe_client::endpoint_group::{EndpointGroup, NodeConfig, NodeHealth};
use nexapipe_client::lb::LoadBalancingStrategy;
use nexapipe_client::relay::RelayModeSpec;
use nexapipe_client::transport::TransportTuning;
use nexapipe_client::LinkStatus;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::status::{
    ActiveFlow, ActiveFlowPage, EndpointLink, NodeHealthStatus, NodeTrafficStatus,
};

/// Why a start attempt failed.
///
/// `start()` is awaited from a background task in both the app and the service, so its caller
/// never matches on the error type: it only records an [`crate::error::AppError`]. Keeping "no
/// configured backend could be reached" as its own variant is what lets that case keep a code of
/// its own instead of being flattened into `proxy.start_failed`.
#[derive(Debug)]
pub enum StartError {
    /// Nothing would have been forwarded: either no node carries a domain, or every probed
    /// backend failed to connect.
    NoReachableBackend {
        /// How many distinct backends were probed. Zero means the routing table was empty.
        total: usize,
        /// The backends that failed, comma-separated. Empty when `total` is zero.
        unreachable_ids: String,
    },
    /// Everything else: binding the iroh endpoint, the TUN device, the listen socket, ...
    Other(anyhow::Error),
    /// A backend was reached and then closed the connection because this client has no 2FA
    /// credentials while the server requires them. Unreachable in the sense that nothing will be
    /// proxied, but the cause is a missing setting here, not a server that is down.
    TwoFactorRequired {
        /// The backends that demanded credentials, comma-separated.
        unreachable_ids: String,
    },
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::NoReachableBackend { total: 0, .. } => f.write_str(
                "no backend is configured: the configured nodes carry no domains, so there is \
                 nothing to forward",
            ),
            StartError::NoReachableBackend {
                total,
                unreachable_ids,
            } => write!(
                f,
                "no backend is reachable: all {} configured node(s) failed to connect ({})",
                total, unreachable_ids
            ),
            StartError::TwoFactorRequired { unreachable_ids } => write!(
                f,
                "the server requires 2FA but this client has no credentials: {} accepted the \
                 connection and then refused it",
                unreachable_ids
            ),
            StartError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartError::NoReachableBackend { .. } | StartError::TwoFactorRequired { .. } => None,
            StartError::Other(e) => e.source(),
        }
    }
}

/// Every `?` and `anyhow` error inside `start()` lands in the catch-all variant.
impl From<anyhow::Error> for StartError {
    fn from(e: anyhow::Error) -> Self {
        StartError::Other(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyMode {
    Tun,
    LocalProxy,
}

#[derive(Debug, Clone)]
pub enum ConnectionConfig {
    Ticket(String),
    EndpointId(String),
}

#[derive(Debug, Clone)]
pub struct ProxyNodeConfig {
    pub connection: ConnectionConfig,
    pub domains: Vec<String>,
    /// 2FA credentials for *this* endpoint, not for every endpoint: each server keeps its own
    /// `[auth].clients` entry, so a single shared pair is what forced a second server to be
    /// given the first one's secret. `None` performs no handshake at all, which is also what
    /// lets one client mix servers that require 2FA with ones that do not.
    pub two_factor: Option<NodeTwoFactor>,
    /// A one-time enrollment token this node was invited with, instead of a secret.
    ///
    /// It is spent on the first connection, which answers with the real credential and
    /// rotates the server-side secret; see [`NodeEnrollment`]. Only nodes carrying a token
    /// enroll — a node that already has a secret authenticates with it and never enrolls,
    /// so re-importing the same invite after the credential landed is a no-op.
    #[allow(dead_code)]
    pub enrollment: Option<NodeEnrollment>,
    /// This machine's own Ed25519 key for this endpoint, as 64 hex characters.
    ///
    /// A property of the *device* rather than of the credential: the same key is offered by
    /// the enrollment that spends the token and signs every handshake after it, so it exists
    /// before there is a credential to sign with. A node whose credential is a secret simply
    /// has one it never used — the server ignored the offer.
    pub device_key: Option<String>,
}

/// The 2FA credentials one node is configured with.
#[derive(Debug, Clone)]
pub struct NodeTwoFactor {
    pub client_id: String,
    pub secret: String,
    /// Lowercase algorithm name, as `TotpAlgorithm::try_from_name` expects it.
    pub algorithm: String,
    /// Which device of this client this secret belongs to.
    ///
    /// `None` is the device that was never given a name, which answers with the
    /// client's own secret — the only kind that existed before a client could
    /// have several, and still what a server that predates devices issues.
    /// `Some` is a name the server filed this secret under, so sending it is
    /// what makes the handshake check the right one: the same secret under two
    /// names is two credentials, and revoking one leaves the other alone.
    pub device: Option<String>,
}

/// A one-time enrollment token, which is what a `--registration` invite carries.
///
/// A token is a credential in transit but not one at rest: the server replaces the
/// client's secret when it is spent and forgets the token in the same write, so a link
/// copied on its way to this machine stops being usable the moment it is used. What comes
/// back has to be persisted by whoever holds the configuration — see
/// [`ProxyManager::take_issued_credential`] — because a token cannot be spent twice and an
/// app that restarts holding only the invite has nothing left to authenticate with.
#[derive(Debug, Clone)]
pub struct NodeEnrollment {
    pub client_id: String,
    pub token: String,
    /// The name to be enrolled under, rather than taking the client's own
    /// secret: it is what turns this into a credential the server can revoke on
    /// its own. Absent enrolls as the unnamed device, which is the behaviour a
    /// server that predates per-device credentials still has.
    pub device: Option<String>,
}

/// The address a configured node resolves to.
///
/// `None` when the string is neither a valid Node ID nor a valid ticket: such a node never got a
/// pool in the group, so there is nothing to configure or report for it.
fn backend_addr(connection: &ConnectionConfig) -> Option<EndpointAddr> {
    match connection {
        ConnectionConfig::Ticket(ticket) => parse_endpoint_addr(None, Some(ticket)).ok(),
        ConnectionConfig::EndpointId(id) => parse_endpoint_addr(Some(id), None).ok(),
    }
}

/// The device key a node carries, read from the spelling it is stored in.
///
/// `None` when it has none, and also when the stored value is not a key: a
/// credential nobody can read is no credential, and a node that answered with
/// a key the server does not hold would be refused for a reason that says
/// nothing about this side.
fn key_for(node: &ProxyNodeConfig) -> Option<iroh::SecretKey> {
    let spelled = node.device_key.as_deref()?;
    let key = DeviceKey::from_hex(spelled).ok()?;
    Some(key.secret_key().clone())
}

#[derive(Debug, Clone)]
pub struct ProxyManagerConfig {
    pub nodes: Vec<ProxyNodeConfig>,
    pub local_proxy_addr: String,
    pub dns_listen_addr: String,
    pub upstream_dns: String,
    /// What the machine's DNS is asked to do. The user's decision, carried
    /// through untouched: a machine that cannot honour it says so rather than
    /// having its whole DNS replaced.
    pub dns_strategy: DnsStrategy,
    pub load_balancing: LoadBalancingStrategy,
    pub tun_name: String,
    /// Forwarding mode, chosen by the user, not probed: `true` requests TUN (and fails if the
    /// process cannot create it), `false` runs the local proxy. There is no automatic mode
    /// selection any more — an implicit probe made the mode depend on how the app happened to be
    /// launched, so the same configuration could forward traffic two different ways.
    pub use_tun: bool,
    pub relay_mode: String,
    pub relay_url: String,
    /// Bearer token for a `custom` relay that requires one. Only ever read together with
    /// `relay_url`, and never logged.
    pub relay_auth_token: String,
    /// Whether this endpoint may use n0's address lookup — the DNS and pkarr
    /// queries that turn a Node ID into an address. `"n0"` (the default) keeps
    /// it; `"none"` switches it off, and a peer then has to bring an address
    /// of its own (a ticket) to be reachable.
    pub discovery_mode: String,
}

struct ProxyInstance {
    tun_proxy: Option<Arc<TunProxy>>,
    local_proxy: Option<Arc<LocalProxyWrapper>>,
    endpoint_group: Option<Arc<EndpointGroup>>,
    /// Our own iroh endpoint id: what the UI shows as "this machine", and what a server-side
    /// auth entry has to name when it keys 2FA by client id.
    local_node_id: String,
}

impl ProxyInstance {
    async fn stop(self) {
        tracing::info!("Stopping proxy instance");

        // The local DNS server and the system-DNS restore are owned by tun_proxy::run, and
        // they only happen when that task winds down — so wait for the teardown instead of
        // just flagging it. A service stop drops the whole tokio runtime right after this
        // returns; without the wait the restore never runs and the machine keeps a static
        // DNS pointing at a TUN address that no longer exists.
        if let Some(tun_proxy) = self.tun_proxy {
            tun_proxy.stop_and_wait().await;
        }

        if let Some(local_proxy) = self.local_proxy {
            local_proxy.stop().await;
        }

        if let Some(endpoint_group) = self.endpoint_group {
            endpoint_group.close_all().await;
        }
    }
}

pub struct ProxyManager {
    config: ProxyManagerConfig,
    mode: parking_lot::Mutex<Option<ProxyMode>>,
    instance: parking_lot::Mutex<Option<ProxyInstance>>,
}

impl ProxyManager {
    pub fn new(config: ProxyManagerConfig) -> Self {
        Self {
            config,
            mode: parking_lot::Mutex::new(None),
            instance: parking_lot::Mutex::new(None),
        }
    }

    pub fn get_mode(&self) -> Option<ProxyMode> {
        // `ProxyMode` is `Copy`, so this is a dereference, not a clone.
        *self.mode.lock()
    }

    pub async fn stop(&self) {
        tracing::info!("ProxyManager stopping");
        let instance = self.instance.lock().take();
        if let Some(instance) = instance {
            instance.stop().await;
        }
        *self.mode.lock() = None;
    }

    /// Bring the proxy up, in TUN or local-proxy mode.
    ///
    /// Every failure mode is a hard failure: a proxied start that cannot reach a single backend is
    /// reported (see [`StartError::NoReachableBackend`]) rather than announced as running, because
    /// the UI shows a green light for "running" and the user would have no way to tell that their
    /// traffic goes nowhere.
    pub async fn start(&self) -> Result<(), StartError> {
        tracing::info!("Initializing proxy manager...");

        let all_domains: Vec<String> = self
            .config
            .nodes
            .iter()
            .flat_map(|node| node.domains.iter().cloned())
            .collect();

        // What the list is worth saying, once, before anything is started.
        //
        // A pattern that matches nothing is a warning: the domain is not
        // proxied, and the name resolves for real instead — so a spelling the
        // rule refuses has to be said out loud, because the scope the
        // operating system is given still covers it. The client library has
        // the notes; the desktop never asked for them.
        let notes = nexapipe_client::domain_notes(&all_domains);
        for (pattern, why) in &notes.unusable {
            tracing::warn!("The proxy-domain pattern \"{pattern}\" matches nothing: {why}");
        }
        for pattern in &notes.narrowed {
            tracing::info!(
                "The proxy-domain pattern \"{pattern}\" names that host only; \"*.{pattern}\" \
                 covers its subdomains"
            );
        }

        let nodes: Vec<NodeConfig> = self
            .config
            .nodes
            .iter()
            .map(|node| match &node.connection {
                ConnectionConfig::Ticket(t) => NodeConfig {
                    server_node_id: None,
                    server_ticket: Some(t.clone()),
                    domains: node.domains.clone(),
                },
                ConnectionConfig::EndpointId(e) => NodeConfig {
                    server_node_id: Some(e.clone()),
                    server_ticket: None,
                    domains: node.domains.clone(),
                },
            })
            .collect();

        // Build iroh endpoint with relay configuration.
        //
        // The QUIC transport tuning has to be applied here too: this endpoint carries every
        // proxied stream in both modes, and without it each stream falls back to iroh's 1.25 MB
        // default receive window, which caps a single connection at roughly 50 Mbps on a 200 ms
        // path. `TransportTuning::from_env()` keeps the A/B overrides working.
        //
        // The relay mode comes from the shared resolver in nexapipe-client, so the desktop,
        // Android and the server cannot drift apart. A mode that is set but unusable is an
        // error, never a silent substitution — an empty mode (nothing configured) is the only
        // thing that defers, to "pinned".
        let transport_tuning = TransportTuning::from_env();
        tracing::info!("QUIC transport tuning: {}", transport_tuning.describe());
        let relay = RelayModeSpec::parse(
            Some(&self.config.relay_mode),
            Some(&self.config.relay_url),
            Some(&self.config.relay_auth_token),
        )
        .map_err(StartError::Other)?
        .unwrap_or(RelayModeSpec::Pinned);
        if !relay.uses_url() && !self.config.relay_url.is_empty() {
            tracing::warn!(
                "relay_url {:?} is set but relay_mode {:?} does not use one; ignoring it",
                self.config.relay_url,
                self.config.relay_mode
            );
        }
        tracing::info!("Relay: {}", relay.describe());
        // Whether this endpoint may ask n0 where a peer is. It is the one piece
        // of n0's infrastructure a relay setting does not reach, so it gets a
        // setting of its own.
        // An empty value means nothing was configured, which falls back to the
        // default — the same reading the JNI gives it. Only a value that
        // names a mode wrongly is an error.
        let discovery = DiscoveryMode::parse_or_default(&self.config.discovery_mode)
            .map_err(StartError::Other)?;
        tracing::info!("Discovery: {}", discovery.describe());
        // Which relay a *peer* may be dialled through. `custom` says this
        // endpoint uses one relay and no other, and that has to hold for the
        // peer too — iroh's `relay_mode` only bounds the relay this endpoint
        // registers with, so a peer naming somebody else's relay would
        // otherwise be dialled through it. A peer named only by a Node ID is
        // dialled while the lookup above is on, and refused once it is off.
        let restriction = relay.dial_restriction(discovery);
        if let Some(restriction) = &restriction {
            tracing::info!("Peers are dialled through {}", restriction.describe());
        }
        // Bind IPv4 only. On hosts where IPv6 exists but cannot carry full-size QUIC
        // datagrams (PPPoE: v6 MTU 1480, ICMPv6 "packet too big" filtered), iroh's net
        // report calls v6 usable, relay dials and path migration move traffic onto v6 —
        // where every datagram above the real MTU fails (sendmsg 10040), which reads as a
        // connection that dies a few seconds in. With no v6 socket the net report stays
        // v4-only and relay dials stop preferring v6. The TUN is IPv4-only anyway.
        let mut ep_builder = Endpoint::builder(presets::N0)
            .clear_ip_transports()
            .bind_addr("0.0.0.0:0")
            .map_err(|e| anyhow::anyhow!("Failed to configure the IPv4-only socket: {}", e))?
            .transport_config(transport_tuning.transport_config())
            .relay_mode(relay.relay_mode());
        ep_builder = discovery.apply(ep_builder);
        if let Some(restriction) = restriction {
            ep_builder = ep_builder.hooks(restriction);
        }

        let iroh_endpoint = ep_builder
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind iroh endpoint: {}", e))?;
        tracing::info!("Iroh endpoint bound, node_id={}", iroh_endpoint.id());
        // Taken before the endpoint is handed to the group, which owns it from here on.
        let local_node_id = iroh_endpoint.id().to_string();

        let endpoint_group = EndpointGroup::new_with_nodes_and_endpoint(
            nodes.clone(),
            None,
            self.config.load_balancing,
            iroh_endpoint,
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

        // 2FA is per endpoint, applied after the group exists because that is when each node has
        // been resolved to the backend ID its pool is keyed by. A node with no credentials keeps
        // none, so it opens no auth stream.
        for node in &self.config.nodes {
            // A credential is a secret or a key, and which one it is comes from
            // the record rather than from a flag: a key node stores no seed at
            // all, so a secret that is empty is not a credential that is
            // missing.
            let two_factor = node.two_factor.as_ref();
            let has_secret = two_factor.is_some_and(|tf| !tf.secret.trim().is_empty());
            // A key is a credential only once it names the device it was
            // issued to: the name comes back from the enrollment, and until
            // then the key is an offer rather than something to answer with.
            let has_key = two_factor.is_some_and(|tf| {
                !has_secret
                    && node.device_key.is_some()
                    && tf.device.as_deref().is_some_and(|d| !d.trim().is_empty())
            });
            let has_credential = has_secret || has_key;
            if !has_credential && node.enrollment.is_none() {
                continue;
            }

            let addr = match backend_addr(&node.connection) {
                Some(addr) => addr,
                None => {
                    tracing::warn!(
                        "2FA configured for a node that is neither a Node ID nor a ticket, ignoring it"
                    );
                    continue;
                }
            };

            // A node holding a credential authenticates with it and never
            // enrolls: enrolling rotates the server-side secret, so doing it on
            // every start would invalidate every other device that already
            // scanned the same invite.
            if let Some(enrollment) = node.enrollment.as_ref().filter(|_| !has_credential) {
                // The server looks an enrollment up by client_id too, so a token with no
                // id can never match any pending entry there.
                if enrollment.client_id.trim().is_empty() {
                    tracing::warn!(
                        "Enrollment for {} has a token but an empty client_id — the server will refuse it",
                        addr.id
                    );
                }
                // No algorithm to agree on: the server sends the parameters it generated
                // the secret with in ENROLL_ISSUE, and the exchange builds its TOTP from
                // those rather than from anything configured here.
                // Taken before the name below shadows it: an empty device is not
                // the unnamed device, it is a field left blank, and enrolling
                // as "" would be refused by the server with a message about
                // printable ASCII that says nothing about this side.
                let device = enrollment
                    .device
                    .as_deref()
                    .map(str::trim)
                    .filter(|name| !name.is_empty());
                let enrollment = Enrollment::new(&enrollment.client_id, &enrollment.token);
                let enrollment = match device {
                    Some(device) => enrollment.with_device(device),
                    None => enrollment,
                };
                // A device key is offered here rather than asked for: the
                // server records the public half under the device's name and
                // issues no secret at all, so the private half never has to be
                // anywhere but this machine. A server that predates keys
                // ignores the offer and issues a secret as it always has.
                //
                // Only with a name, because the server refuses a key that
                // names no device — and a refusal that reads as a bad token
                // would be a lie: the token was fine and the device had no
                // name.
                let enrollment = match (device, key_for(node)) {
                    (Some(_), Some(key)) => enrollment.with_key(key),
                    _ => enrollment,
                };
                endpoint_group
                    .set_enrollment_for(&addr.id.to_string(), Some(enrollment))
                    .await;
                tracing::info!(
                    "Enrolling {} with a one-time token as client '{}'",
                    addr.id,
                    node.enrollment.as_ref().unwrap().client_id
                );
                continue;
            }

            let two_factor = match &node.two_factor {
                Some(two_factor) => two_factor,
                None => continue,
            };

            // The server looks a handshake up by client_id (`clients.get(client_id)`),
            // so a secret with no id can never match any entry there: it authenticates
            // as client '' and is refused. That is a configuration mistake worth
            // saying out loud, because the client only ever sees the refusal.
            if two_factor.client_id.trim().is_empty() {
                tracing::warn!(
                    "2FA for {} has a secret but an empty client_id — this node will be rejected by any server keyed by client id",
                    addr.id
                );
            }

            // A key is the credential where there is one: the node stores no
            // secret at all, so the TOTP path would find nothing to build from
            // and the node would answer with nothing. A node that does hold a
            // secret uses it — the server may have ignored the key and issued
            // one instead, and then the secret is what it holds.
            let device = two_factor.device.as_deref().map(str::trim);
            let auth = match (has_secret, key_for(node), device) {
                (false, Some(key), Some(device)) if !device.is_empty() => {
                    TwoFactorAuth::with_key(&two_factor.client_id, key, device)
                }
                _ => {
                    // A name nobody supports is refused rather than downgraded:
                    // the node would compute codes the server does not accept.
                    let algorithm =
                        TotpAlgorithm::try_from_name(&two_factor.algorithm).map_err(|e| {
                            anyhow::anyhow!("Invalid 2FA config for {}: {}", addr.id, e)
                        })?;
                    TwoFactorAuth::new(&two_factor.client_id, &two_factor.secret, algorithm)
                        .map_err(|e| anyhow::anyhow!("Invalid 2FA config for {}: {}", addr.id, e))?
                }
            };
            // Named only when the node carries a name: an empty one is not the
            // unnamed device, it is a field somebody left blank, and enrolling
            // or answering as "" would be refused by the server with a message
            // about printable ASCII that says nothing about this side.
            let auth = match device {
                Some(device) if !device.is_empty() => auth.with_device(device),
                _ => auth,
            };
            endpoint_group
                .set_two_factor_for(&addr.id.to_string(), Some(auth))
                .await;
            tracing::info!(
                "2FA enabled for {}, client_id: {}",
                addr.id,
                two_factor.client_id
            );
        }

        let endpoint_group = Arc::new(endpoint_group);
        // From here on the backends are asked whether they still answer, on a
        // timer, instead of only when something tries to use them. Before this
        // call the group is only dialled once (the gate below) and never again,
        // so a backend that died after startup was discovered by the request
        // that needed it.
        endpoint_group.start_health_probe();

        tracing::info!("EndpointGroup initialized with {} nodes", nodes.len());

        // Reachability gate. Nothing so far has dialed anything: building the group only binds a
        // local endpoint, so a well-formed node ID that does not exist gets this far looking
        // valid. Probing now means a start that would forward to nothing fails here, before a TUN
        // device or a listen socket exists to tear down.
        let report = endpoint_group.preconnect_report().await;
        // A backend that answered and then refused the connection for missing 2FA is counted as
        // unreachable, which on its own reads like "the server is down". Report the real cause
        // instead: the credentials belong on this side.
        if report.any_auth_required() && !report.any_reachable() {
            tracing::error!(
                "Backend(s) require 2FA, but no credentials are configured: {}",
                report.unreachable_ids()
            );
            return Err(StartError::TwoFactorRequired {
                unreachable_ids: report.unreachable_ids(),
            });
        }
        if !report.any_reachable() {
            tracing::error!(
                "No reachable backend out of {} probed node(s)",
                report.total()
            );
            return Err(StartError::NoReachableBackend {
                total: report.total(),
                unreachable_ids: report.unreachable_ids(),
            });
        }
        if report.unreachable.is_empty() {
            tracing::info!("All {} backend(s) reachable", report.total());
        } else {
            // Load balancing tolerates a partial outage, so a partial failure is only a warning.
            tracing::warn!(
                "{} of {} backend(s) unreachable, the remaining {} still serve traffic: {}",
                report.unreachable.len(),
                report.total(),
                report.reachable.len(),
                report.unreachable_ids()
            );
        }

        if self.config.use_tun {
            // No `TunProxy::is_available()` pre-flight any more. That probe is a bare `is_admin()`
            // (`net session` on Windows), and it is the wrong question: what matters is whether
            // the device can be created, which is what `run()` tries next and reports verbatim.
            // The service runs as LocalSystem, where the probe answers false even though the
            // tunnel can be created — so this check alone refused every service-mode TUN start a
            // couple of seconds in, once the endpoint bind and the reachability probe had
            // finished. Callers that want to refuse before touching anything (the desktop process,
            // which is never elevated) still do their own check.
            tracing::info!("TUN mode requested, starting TUN + DNS hijack mode");

            // Starting the local DNS server and switching system DNS is handled inside
            // tun_proxy::run (DNS is started after the interface is configured to avoid
            // WSAEADDRNOTAVAIL); here we only build the configuration.
            // The interface address is only decided when the TUN comes up (the block may have
            // moved), so the fallback is the *currently configured* one; `tun_proxy::retarget`
            // moves whatever lands here into the block actually in use.
            let fallback_ip = tun_ip();
            let dns_ip = self
                .config
                .dns_listen_addr
                .split(':')
                .next()
                .unwrap_or(&fallback_ip)
                .to_string();
            let tun_config = TunProxyConfig {
                tunnel_name: self.config.tun_name.clone(),
                dns_ip,
                dns: DnsServerConfig {
                    listen_addr: self.config.dns_listen_addr.clone(),
                    upstream_dns: self.config.upstream_dns.clone(),
                    proxy_domains: all_domains.clone(),
                },
                dns_strategy: self.config.dns_strategy,
            };
            let tun_proxy = Arc::new(TunProxy::new(tun_config, endpoint_group.clone()));

            *self.instance.lock() = Some(ProxyInstance {
                tun_proxy: Some(tun_proxy.clone()),
                local_proxy: None,
                endpoint_group: Some(endpoint_group.clone()),
                local_node_id: local_node_id.clone(),
            });
            *self.mode.lock() = Some(ProxyMode::Tun);

            // run() creates the device and configures interface/routes/DNS, restoring
            // everything on exit
            match tun_proxy.run().await {
                Ok(()) => {
                    tracing::info!("TUN proxy stopped successfully");
                    // Properly close endpoints before clearing instance
                    let instance = self.instance.lock().take();
                    if let Some(instance) = instance {
                        instance.stop().await;
                    }
                    *self.mode.lock() = None;
                    return Ok(());
                }
                Err(e) => {
                    // TUN was requested explicitly, so a runtime failure is reported rather than
                    // answered with a local proxy: the caller surfaces it as a startup failure
                    // (`proxy.start_failed` with this detail) and the mode goes back to stopped.
                    tracing::error!("TUN proxy failed: {}", e);
                    let instance = self.instance.lock().take();
                    if let Some(instance) = instance {
                        instance.stop().await;
                    }
                    *self.mode.lock() = None;
                    return Err(StartError::Other(anyhow::anyhow!(
                        "TUN proxy failed: {}",
                        e
                    )));
                }
            }
        }

        *self.mode.lock() = Some(ProxyMode::LocalProxy);
        tracing::info!("Starting local proxy...");

        // The proxy runs on the group built above, not on a fresh one: it is what carries the relay
        // mode, the transport tuning and the 2FA credentials, and it is what the reachability probe
        // just validated. Building a second group here used to silently drop all three.
        let local_proxy = Arc::new(
            LocalProxyWrapper::new(
                &self.config.local_proxy_addr,
                all_domains,
                endpoint_group.clone(),
            )
            .await?,
        );

        *self.instance.lock() = Some(ProxyInstance {
            tun_proxy: None,
            local_proxy: Some(local_proxy.clone()),
            endpoint_group: Some(endpoint_group.clone()),
            local_node_id: local_node_id.clone(),
        });

        // Spawn the local proxy run loop as a separate task. This keeps the
        // large async state machine (handle_local_connection, handle_tls_tunnel,
        // etc.) off the current task's stack, preventing stack overflow on
        // tokio worker threads (default 2 MB stack).
        let run_local_proxy = local_proxy.clone();
        tokio::spawn(async move {
            if let Err(e) = run_local_proxy.run().await {
                tracing::error!("Local proxy error: {}", e);
            }
        });

        // The local proxy is now running in a background task, so start() returns immediately;
        // shutdown is handled by ProxyManager::stop(). Do not tear down the instance here.
        Ok(())
    }

    /// The credential the server issued for an enrollment token, if one was spent since
    /// the proxy was started.
    ///
    /// Read once, right after a start: the token cannot be spent twice, so this is the only
    /// chance to persist what it bought. `None` means nothing enrolled — either no node
    /// carried a token, or the credential has already been taken.
    pub async fn take_issued_credential(&self) -> Option<IssuedCredential> {
        let group = self
            .instance
            .lock()
            .as_ref()
            .and_then(|instance| instance.endpoint_group.clone())?;
        group.take_issued_credential().await
    }

    /// Our own endpoint id, or `None` when nothing is running.
    ///
    /// It used to be a stub that always answered `None`, which made every poll log
    /// `proxy.node_id_unavailable` — noise that looked exactly like a proxy that had died.
    pub async fn get_node_id(&self) -> Option<String> {
        // Cloned out of the lock before anything else: a parking_lot guard must not be held
        // across a suspension point.
        self.instance
            .lock()
            .as_ref()
            .map(|i| i.local_node_id.clone())
    }

    /// How each configured node currently reaches its backend: direct, or through a relay.
    ///
    /// One entry per configured node, in configuration order, so the UI can pair a link with
    /// the node it belongs to. Empty when nothing is running: there is no path to report, and a
    /// stale icon for a link that no longer exists is worse than none.
    ///
    /// The answer comes from the paths iroh actually selected, never from the configured relay
    /// mode — a node permitted to use a relay may well have punched through to a direct path.
    pub async fn endpoint_links(&self) -> Vec<EndpointLink> {
        // Cloned out of the lock and dropped before the first await: a parking_lot guard must
        // not be held across a suspension point.
        let group = self
            .instance
            .lock()
            .as_ref()
            .and_then(|instance| instance.endpoint_group.clone());

        let Some(group) = group else {
            return Vec::new();
        };

        let statuses: HashMap<EndpointId, LinkStatus> =
            group.link_statuses().await.into_iter().collect();

        self.config
            .nodes
            .iter()
            .filter_map(|node| {
                let connection = match &node.connection {
                    ConnectionConfig::Ticket(ticket) => ticket.clone(),
                    ConnectionConfig::EndpointId(id) => id.clone(),
                };
                // A node the group could not parse never got a pool, so there is nothing to
                // report for it; dropping it keeps the list aligned with what actually dialed.
                let addr = backend_addr(&node.connection)?;
                let status = statuses.get(&addr.id).copied().unwrap_or_default();
                Some(EndpointLink {
                    connection,
                    endpoint_id: addr.id.to_string(),
                    link: status.kind,
                    rtt_ms: status.rtt.map(|rtt| rtt.as_millis() as u64),
                })
            })
            .collect()
    }

    /// Whether each configured node answered its last probe, and for how long it has been
    /// missing.
    ///
    /// One entry per configured node, in configuration order and keyed by the same `connection`
    /// string as [`Self::endpoint_links`], so the UI can pair the two readings for one node.
    /// Empty when nothing is running, exactly as the links are: there is nothing probing.
    ///
    /// A node the probe has not reached yet reads as unreachable with no `down_for_secs` — it has
    /// not answered, and it has also never answered, so there is no "down since" to report.
    pub async fn node_health(&self) -> Vec<NodeHealthStatus> {
        // Cloned out of the lock and dropped before the first await: a parking_lot guard must
        // not be held across a suspension point.
        let group = self
            .instance
            .lock()
            .as_ref()
            .and_then(|instance| instance.endpoint_group.clone());

        let Some(group) = group else {
            return Vec::new();
        };

        let health: HashMap<EndpointId, NodeHealth> = group
            .health_snapshot()
            .nodes
            .into_iter()
            .map(|node| (node.node, node))
            .collect();

        self.config
            .nodes
            .iter()
            .filter_map(|node| {
                let connection = match &node.connection {
                    ConnectionConfig::Ticket(ticket) => ticket.clone(),
                    ConnectionConfig::EndpointId(id) => id.clone(),
                };
                // Same filter as the links: a node the group could not parse has no pool, so
                // nothing probes it and there is no health to report.
                let addr = backend_addr(&node.connection)?;
                // `None` until the first probe has run, which is up to the probe interval plus
                // its jitter after a start.
                let probed = health.get(&addr.id);
                Some(NodeHealthStatus {
                    connection,
                    reachable: probed.is_some_and(|node| node.reachable),
                    consecutive_failures: probed
                        .map(|node| node.consecutive_failures)
                        .unwrap_or_default(),
                    // Asked only for a node that is actually down: while it answers there is no
                    // outage to time, and `Some(0)` would read as "down for no time at all".
                    down_for_secs: probed
                        .filter(|node| !node.reachable)
                        .and_then(|node| node.down_for())
                        .map(|down| down.as_secs()),
                    since_last_probe_secs: probed
                        .and_then(|node| node.last_probe)
                        .map(|last| last.elapsed().as_secs()),
                })
            })
            .collect()
    }

    /// What each node has carried since these counters started, and how many flows are open to
    /// it.
    ///
    /// Keyed by the same `connection` string as [`Self::endpoint_links`] and
    /// [`Self::node_health`], so the UI lines a volume up next to the link kind and the health of
    /// one node. Empty when nothing is running, as both of those are: nothing is being forwarded,
    /// so there is nothing to count.
    ///
    /// Unlike those two this may carry **no entry for a configured node**: the counters only hold
    /// nodes this group has actually handed a connection out to, and inventing a row of zeros
    /// here would turn "nothing has gone through it yet" into "nothing went through it", which is
    /// not the same claim. Whoever shows the figure is the one that can say which it is looking
    /// at — see [`NodeTrafficStatus`].
    ///
    /// Cumulative, and deliberately not a rate: a rate is two readings and a division, and the
    /// one caller already polls on its own interval.
    pub async fn node_traffic(&self) -> Vec<NodeTrafficStatus> {
        // Cloned out of the lock and dropped before the first await: a parking_lot guard must
        // not be held across a suspension point.
        let group = self
            .instance
            .lock()
            .as_ref()
            .and_then(|instance| instance.endpoint_group.clone());

        let Some(group) = group else {
            return Vec::new();
        };

        let volumes = group.traffic_snapshot();

        self.config
            .nodes
            .iter()
            .filter_map(|node| {
                let connection = match &node.connection {
                    ConnectionConfig::Ticket(ticket) => ticket.clone(),
                    ConnectionConfig::EndpointId(id) => id.clone(),
                };
                // Same filter as the links and the health: a node the group could not parse has
                // no pool, so nothing carries traffic for it.
                let addr = backend_addr(&node.connection)?;
                let volume = volumes.get(&addr.id)?;
                Some(NodeTrafficStatus {
                    connection,
                    sent: volume.sent,
                    received: volume.received,
                    active: volume.active,
                })
            })
            .collect()
    }

    /// The connections this proxy has open right now, one row each.
    ///
    /// The other half of [`Self::node_traffic`], which hands the same bytes back added up per
    /// node: this names each connection, which door it came in by, where it says it is going,
    /// and how long it has been open. A node carrying 40 MiB across 12 flows says nothing about
    /// whether one of those has been stuck for an hour, and "how much" cannot become "stop that
    /// one" without this.
    ///
    /// Empty when nothing is running, like every other reading here: no tunnel, no flows.
    pub async fn active_flows(&self, limit: usize) -> ActiveFlowPage {
        // Cloned out of the lock and dropped before the first await: a parking_lot guard must
        // not be held across a suspension point.
        let group = self
            .instance
            .lock()
            .as_ref()
            .and_then(|instance| instance.endpoint_group.clone());

        let Some(group) = group else {
            return ActiveFlowPage::empty();
        };

        let (total, views) = group.flow_snapshot(limit);

        // Backend -> the connection string the UI configures it by, which is the same key a
        // link, a health reading and a volume carry. Built once for the whole page rather than
        // looked up per flow, and omitted when a flow reaches a backend this configuration does
        // not name.
        let connections: HashMap<EndpointId, String> = self
            .config
            .nodes
            .iter()
            .filter_map(|node| {
                let connection = match &node.connection {
                    ConnectionConfig::Ticket(ticket) => ticket.clone(),
                    ConnectionConfig::EndpointId(id) => id.clone(),
                };
                let addr = backend_addr(&node.connection)?;
                Some((addr.id, connection))
            })
            .collect();

        let flows = views
            .into_iter()
            .map(|view| ActiveFlow {
                id: view.id,
                connection: connections.get(&view.node).cloned(),
                endpoint_id: view.node.to_string(),
                kind: view.kind.as_str().to_string(),
                target: view.target,
                source: view.source,
                open_for_secs: view.open_for_secs,
                sent: view.sent,
                received: view.received,
            })
            .collect();

        ActiveFlowPage {
            flows,
            total,
            limit,
        }
    }

    /// Asks one open flow to end.
    ///
    /// `false` when there is no flow open with that id, which covers both "there never was one"
    /// and "it ended between the list being drawn and the click landing" — a UI polling every
    /// few seconds will sometimes be clicked on a row that has already gone, and the honest
    /// answer is that nothing was asked rather than an error.
    ///
    /// Nothing is *removed* here: the flow wakes the copy loop holding its sockets, and that
    /// loop is what lets go of them and deregisters. A list read immediately afterwards may
    /// therefore still show the flow for a moment, and that is the truth rather than a delay.
    pub fn close_flow(&self, id: u64) -> bool {
        let group = self
            .instance
            .lock()
            .as_ref()
            .and_then(|instance| instance.endpoint_group.clone());

        match group {
            Some(group) => group.close_flow(id),
            None => false,
        }
    }

    /// Asks every flow reaching one configured node to end, and drops the connections the pool
    /// was keeping for it.
    ///
    /// The flows *and* the idle connections, because they are not the same thing: a pool holds
    /// connections no flow is using, and ending the flows while leaving those behind is how a
    /// backend that has gone bad keeps being handed out.
    ///
    /// Returns how many flows were asked, which is what a UI can show. `None` when `connection`
    /// names a node this configuration cannot resolve to, because that is a different answer
    /// from "resolved, and had nothing open" — one is a bad request, the other is an idle
    /// backend.
    pub async fn close_node_flows(&self, connection: &str) -> Option<usize> {
        // Cloned out of the lock and dropped before the first await: a parking_lot guard must
        // not be held across a suspension point.
        let group = self
            .instance
            .lock()
            .as_ref()
            .and_then(|instance| instance.endpoint_group.clone());

        // No manager: nothing is running, so there is no flow to ask about and no node to
        // resolve — which is the same `None` an unresolvable connection gets, because from the
        // caller's side both mean "nothing was closed and here is why not".
        let group = group?;

        let node = self
            .config
            .nodes
            .iter()
            .find(|node| match &node.connection {
                ConnectionConfig::Ticket(ticket) => ticket == connection,
                ConnectionConfig::EndpointId(id) => id == connection,
            })
            .and_then(|node| backend_addr(&node.connection))?;

        Some(group.close_node_flows(&node.id).await)
    }
}
