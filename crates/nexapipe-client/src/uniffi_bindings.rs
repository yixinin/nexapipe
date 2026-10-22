//! The UniFFI surface: the client, for an app that is not written in Rust.
//!
//! What an app needs from this library is a client it can configure, point at
//! one or more servers, watch, and shut down. That is what this surface is:
//! it configures the servers and their credentials, reports what the tunnel
//! is doing, and closes it again.
//!
//! # What is not here, and why
//!
//! The TUN is not here. A TUN needs a packet source and a packet sink — a file
//! descriptor on Android, a `NEPacketTunnelFlow` on iOS — and neither crosses a
//! UniFFI boundary: UniFFI moves values, and a live packet stream is not a
//! value. An app that wants the tunnel itself has to reach for the C ABI, which
//! this crate builds as well (`cdylib`). The local proxy is here instead,
//! because it is the half that does cross: a socket, a port and a domain list.
//!
//! # Threads
//!
//! Every call blocks until its answer is there, and the work runs on a runtime
//! this module owns rather than on the caller's thread. That is deliberate:
//! iroh drives an endpoint from tasks spawned on the ambient runtime, so a
//! runtime that is created and dropped inside one call takes those tasks with
//! it on return — the endpoint handed out by an earlier call stops making
//! progress, and the next call blocks on a connection that is already dead
//! instead of failing. `jni.rs` keeps its runtime for the same reason.
//!
//! An app should still call these from a worker thread rather than from its
//! main one: a call that waits for a server to answer waits for as long as the
//! server takes.

use crate::auth::{Enrollment, TotpAlgorithm, TwoFactorAuth};
use crate::endpoint_group::{EndpointGroup, NodeConfig};
use crate::error::ClientError;
use crate::lb::LoadBalancingStrategy;
use crate::relay::RelayModeSpec;
use crate::transport::TransportTuning;
use crate::{HttpRequest, HttpResponse};
use iroh::Endpoint;
use iroh::endpoint::presets;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::runtime::Runtime;
use uniffi::export;

/// One runtime for the whole process.
///
/// See the module docs for why it is not created per call.
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

fn runtime() -> Result<&'static Runtime, ClientError> {
    RUNTIME
        .get_or_try_init(Runtime::new)
        .map_err(|e| ClientError::IoError(Arc::new(e)))
}

/// The 2FA credentials of one server.
///
/// The secret is the base32 string the server's `[auth.clients]` entry holds.
#[derive(uniffi::Record)]
pub struct TwoFactorCredentials {
    /// Which `[auth.clients]` entry the secret belongs to.
    pub client_id: String,
    /// The shared secret, base32.
    pub secret: String,
    /// The TOTP algorithm. The server's default when absent.
    pub algorithm: Option<String>,
    /// Which device of this client the secret belongs to.
    ///
    /// Absent is the device that was never named, which answers with the
    /// client's own secret.
    pub device: Option<String>,
}

/// A one-time enrollment token.
///
/// It is spent on the first connection, which answers with the real credential
/// and rotates the server-side secret. A node that already holds a secret
/// authenticates with it and never enrolls.
#[derive(uniffi::Record)]
pub struct EnrollmentToken {
    /// Which `[auth.clients]` entry the token is pending for.
    pub client_id: String,
    /// The token itself.
    pub token: String,
    /// The name to enroll under. Absent is the unnamed device.
    pub device: Option<String>,
}

/// One server this client talks to.
#[derive(uniffi::Record)]
pub struct ServerConfig {
    /// The server's Node ID. Absent when a ticket carries one.
    pub server_node_id: Option<String>,
    /// A ticket that carries the server's address.
    pub server_ticket: Option<String>,
    /// The domains this server serves.
    pub domains: Vec<String>,
    /// The credentials for this server.
    ///
    /// Per server, not shared: each server keeps its own `[auth.clients]`
    /// entry, so one client can talk to a server that wants 2FA and one that
    /// does not.
    pub two_factor: Option<TwoFactorCredentials>,
    /// A one-time enrollment token for this server.
    pub enrollment: Option<EnrollmentToken>,
}

/// Which credential one server is configured with.
enum Credential<'a> {
    /// A one-time token, spent on the first connection.
    Enrollment(&'a EnrollmentToken),
    /// A shared secret, answered on every connection.
    TwoFactor(&'a TwoFactorCredentials),
}

/// What one server authenticates with.
///
/// A server that holds a secret authenticates with it and **never** enrolls:
/// enrolling rotates the server-side secret, so an app that kept the invite it
/// scanned next to the credential it got would invalidate every other device
/// on that client id on every start. The token is for a server that has no
/// secret yet.
///
/// `None` for a server with neither: it opens no auth stream at all.
fn credential_for(server: &ServerConfig) -> Option<Credential<'_>> {
    // A secret that is blank is a field nobody filled in, not a secret.
    let has_secret = server
        .two_factor
        .as_ref()
        .is_some_and(|two_factor| !two_factor.secret.trim().is_empty());
    if has_secret {
        return server.two_factor.as_ref().map(Credential::TwoFactor);
    }
    server.enrollment.as_ref().map(Credential::Enrollment)
}

/// How the client is set up.
#[derive(uniffi::Record)]
pub struct ClientConfig {
    /// The servers, and the domains each of them serves.
    pub servers: Vec<ServerConfig>,
    /// How a domain with several servers is picked: `round_robin` or
    /// `random`. Round robin when absent.
    pub load_balancing: Option<String>,
    /// How the tunnel reaches the servers: `disabled`, `default`, `pinned` or
    /// `custom`. Pinned when absent.
    pub relay_mode: Option<String>,
    /// The relay to use, for the `custom` mode.
    pub relay_url: Option<String>,
    /// The token the relay asks for, if it asks for one.
    pub relay_auth_token: Option<String>,
}

/// How one server is reached right now.
#[derive(uniffi::Record)]
pub struct LinkStatus {
    /// The server's Node ID.
    pub node_id: String,
    /// `direct`, `relay` or `unknown`.
    pub kind: String,
    /// The round-trip time of the path carrying the traffic, in milliseconds.
    ///
    /// Absent is "not measured": a path that has just opened has no sample
    /// yet, and a relay that does not report has none at all. It is not a
    /// zero, and a UI must not draw it as one.
    pub rtt_ms: Option<u64>,
}

/// What one server has carried.
#[derive(uniffi::Record)]
pub struct ServerTraffic {
    /// The server's Node ID.
    pub node_id: String,
    /// Bytes sent towards it.
    pub sent: u64,
    /// Bytes received from it.
    pub received: u64,
    /// Flows open right now.
    pub active: u64,
}

/// The flows that are open right now.
#[derive(uniffi::Record)]
pub struct FlowReport {
    /// How many flows are open in total.
    pub total: u64,
    /// The ones listed, capped by what the caller asked for.
    pub flows: Vec<FlowInfo>,
}

/// One open flow.
#[derive(uniffi::Record)]
pub struct FlowInfo {
    /// The flow's id, for closing it.
    pub id: u64,
    /// The server it reaches.
    pub node_id: String,
    /// Which door the bytes came in by: `http`, `connect`, `websocket`,
    /// `tls`, `tun_tcp` or `tun_udp`.
    pub kind: String,
    /// Where the bytes are going, as the client named it.
    pub target: Option<String>,
    /// Where they came from.
    pub source: Option<String>,
    /// Whole seconds since the flow opened.
    pub open_for_secs: u64,
    /// Bytes sent through it.
    pub sent: u64,
    /// Bytes received through it.
    pub received: u64,
}

/// What a probe of the configured servers found.
#[derive(uniffi::Record)]
pub struct ReachabilityReport {
    /// How many servers were probed.
    pub total: u64,
    /// How many answered.
    pub reachable: u64,
    /// The ones that did not, comma separated.
    pub unreachable_ids: String,
    /// Whether any of them refused for missing credentials.
    ///
    /// A server that answered and then refused is counted as unreachable, which
    /// on its own reads like "the server is down". This says the real cause:
    /// the credentials belong on this side.
    pub any_auth_required: bool,
}

/// The client: one tunnel, to one or more servers.
#[derive(uniffi::Object)]
pub struct ProxyClient {
    group: Arc<EndpointGroup>,
    /// The local endpoint's Node ID, taken before the group takes the endpoint.
    node_id: String,
}

#[export]
impl ProxyClient {
    /// Builds a client and binds the endpoint it will tunnel through.
    ///
    /// Nothing is dialled here: the endpoint is bound and the servers are
    /// resolved, so a start that would forward to nothing fails at the first
    /// request rather than here. Call [`ProxyClient::preconnect`] to find out
    /// what is reachable before that.
    #[uniffi::constructor]
    pub fn new(config: ClientConfig) -> Result<Arc<Self>, ClientError> {
        let rt = runtime()?;
        let client = rt.block_on(async move { Self::create(config).await })?;
        Ok(Arc::new(client))
    }

    /// The Node ID this client is reachable as.
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// The servers this client was configured with.
    pub fn server_ids(&self) -> Vec<String> {
        self.group
            .node_ids()
            .into_iter()
            .map(|id| id.to_string())
            .collect()
    }

    /// Asks the servers whether they still answer.
    pub fn preconnect(&self) -> Result<ReachabilityReport, ClientError> {
        let rt = runtime()?;
        rt.block_on(async move {
            let report = self.group.preconnect_report().await;
            Ok(ReachabilityReport {
                total: report.total() as u64,
                reachable: report.reachable.len() as u64,
                unreachable_ids: report.unreachable_ids(),
                any_auth_required: report.any_auth_required(),
            })
        })
    }

    /// How each server is reached right now, and how far away it is.
    pub fn link_statuses(&self) -> Result<Vec<LinkStatus>, ClientError> {
        let rt = runtime()?;
        rt.block_on(async move {
            Ok(self
                .group
                .link_statuses()
                .await
                .into_iter()
                .map(|(node_id, status)| LinkStatus {
                    node_id: node_id.to_string(),
                    kind: status.kind.as_str().to_string(),
                    rtt_ms: status.rtt.map(|rtt| rtt.as_millis() as u64),
                })
                .collect())
        })
    }

    /// What each server has carried.
    pub fn traffic(&self) -> Vec<ServerTraffic> {
        self.group
            .traffic_snapshot()
            .into_iter()
            .map(|(node_id, volume)| ServerTraffic {
                node_id: node_id.to_string(),
                sent: volume.sent,
                received: volume.received,
                active: volume.active,
            })
            .collect()
    }

    /// The flows that are open right now, and how many there are in total.
    ///
    /// The list is capped: a busy client has more flows than a screen can
    /// show, and the count beside it is the answer to "how many are there".
    pub fn flows(&self, limit: u32) -> FlowReport {
        let (total, views) = self.group.flow_snapshot(limit as usize);
        let flows = views
            .into_iter()
            .map(|view| FlowInfo {
                id: view.id,
                node_id: view.node.to_string(),
                kind: view.kind.as_str().to_string(),
                target: view.target,
                source: view.source,
                open_for_secs: view.open_for_secs,
                sent: view.sent,
                received: view.received,
            })
            .collect();
        FlowReport {
            total: total as u64,
            flows,
        }
    }

    /// Closes one flow. `false` when it was already gone.
    pub fn close_flow(&self, id: u64) -> bool {
        self.group.close_flow(id)
    }

    /// Closes every cached connection, keeping the endpoint.
    ///
    /// For the device that changed networks: the tunnel is still up, but the
    /// connections inside it were opened on the old network and are dead while
    /// still looking open.
    pub fn drop_connections(&self) -> Result<(), ClientError> {
        let rt = runtime()?;
        rt.block_on(async move { self.group.drop_connections().await });
        Ok(())
    }

    /// Sends one request through the tunnel.
    ///
    /// The host in the request picks the server: the same domain mapping the
    /// proxy uses, so a request for a domain this client does not serve is
    /// refused rather than sent somewhere else.
    pub fn send_request(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        let rt = runtime()?;
        rt.block_on(async move { self.send_request_inner(request).await })
    }

    /// Sends raw bytes through the tunnel, and returns what comes back.
    ///
    /// `host` picks the server, by the same domain mapping `send_request`
    /// uses: a name this client does not serve is refused rather than sent
    /// somewhere else.
    pub fn send_raw(&self, host: String, data: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        let rt = runtime()?;
        rt.block_on(async move { self.send_raw_inner(host, data).await })
    }

    /// Closes the client: the connections, and the endpoint with them.
    pub fn close(&self) {
        if let Ok(rt) = runtime() {
            rt.block_on(async move { self.group.drop_connections().await });
        }
    }
}

/// The local proxy: a socket an app can point its own proxy settings at.
///
/// It is the half of the tunnel that crosses a language boundary, because it
/// is a socket, a port and a domain list. What goes through it is the same
/// traffic the tunnel would have carried, and it is stopped by dropping it or
/// by calling [`LocalProxy::stop`].
#[derive(uniffi::Object)]
pub struct LocalProxy {
    proxy: Arc<crate::local_proxy::LocalProxy>,
    /// The task the accept loop runs in, so stopping the proxy ends it rather
    /// than leaving it polling a socket nobody answers on.
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[export]
impl LocalProxy {
    /// Starts the proxy on `listen_addr`, forwarding the named domains.
    ///
    /// The domains are the ones the proxy answers for; a request for anything
    /// else is refused rather than forwarded somewhere else.
    #[uniffi::constructor]
    pub fn new(
        client: Arc<ProxyClient>,
        listen_addr: String,
        domains: Vec<String>,
    ) -> Result<Arc<Self>, ClientError> {
        let rt = runtime()?;
        let proxy = rt.block_on(async move {
            crate::local_proxy::LocalProxy::new(&listen_addr, domains, client.group.clone()).await
        })?;
        let proxy = Arc::new(proxy);
        let task = rt.spawn({
            let proxy = Arc::clone(&proxy);
            async move {
                let _ = proxy.run().await;
            }
        });

        Ok(Arc::new(LocalProxy {
            proxy,
            task: std::sync::Mutex::new(Some(task)),
        }))
    }

    /// Stops the proxy: the socket closes and the connections end.
    pub fn stop(&self) {
        self.proxy.stop();
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

impl ProxyClient {
    /// The work behind the constructor.
    async fn create(config: ClientConfig) -> Result<Self, ClientError> {
        let strategy = match config.load_balancing.as_deref().map(str::trim) {
            None | Some("") | Some("round_robin") => LoadBalancingStrategy::RoundRobin,
            Some("random") => LoadBalancingStrategy::Random,
            Some(other) => {
                return Err(ClientError::InvalidConfig(format!(
                    "Unknown load balancing strategy: {other}"
                )));
            }
        };

        // The relay mode comes from the shared resolver in this crate, so the
        // desktop, Android and this surface cannot drift apart. A mode that is
        // set but unusable is an error, never a silent substitution — an empty
        // mode (nothing configured) is the only thing that defers to "pinned".
        let relay = RelayModeSpec::parse(
            config.relay_mode.as_deref(),
            config.relay_url.as_deref(),
            config.relay_auth_token.as_deref(),
        )?
        .unwrap_or(RelayModeSpec::Pinned);

        // The QUIC transport tuning has to be applied here: this endpoint
        // carries every proxied stream, and without it each stream falls back
        // to iroh's 1.25 MB default receive window, which caps a single
        // connection at roughly 50 Mbps on a 200 ms path.
        let tuning = TransportTuning::from_env();
        let endpoint = Endpoint::builder(presets::N0)
            .transport_config(tuning.transport_config())
            .relay_mode(relay.relay_mode())
            .bind()
            .await
            .map_err(|e| ClientError::Other(format!("cannot bind the iroh endpoint: {e}")))?;
        // Taken before the endpoint is handed to the group, which owns it from
        // here on.
        let node_id = endpoint.id().to_string();

        let mut nodes = Vec::with_capacity(config.servers.len());
        for server in &config.servers {
            nodes.push(NodeConfig {
                server_node_id: server.server_node_id.clone(),
                server_ticket: server.server_ticket.clone(),
                domains: server.domains.clone(),
            });
        }

        let group =
            EndpointGroup::new_with_nodes_and_endpoint(nodes, None, strategy, endpoint).await?;
        let group = Arc::new(group);

        // 2FA is per endpoint, applied after the group exists because that is
        // when each node has been resolved to the backend id its pool is keyed
        // by. A node with no credentials keeps none, so it opens no auth
        // stream.
        for server in &config.servers {
            let Some(addr) = crate::connection_pool::parse_endpoint_addr(
                server.server_node_id.as_deref(),
                server.server_ticket.as_deref(),
            )
            .ok() else {
                continue;
            };
            let backend_id = addr.id.to_string();

            // A node holding a secret authenticates with it and never
            // enrolls: enrolling rotates the server-side secret, so doing it on
            // every start would invalidate every other device that already
            // scanned the same invite.
            match credential_for(server) {
                Some(Credential::Enrollment(enrollment)) => {
                    let token = Enrollment::new(&enrollment.client_id, &enrollment.token);
                    let token = match enrollment.device.as_deref().map(str::trim) {
                        Some(device) if !device.is_empty() => token.with_device(device),
                        _ => token,
                    };
                    group.set_enrollment_for(&backend_id, Some(token)).await;
                }
                Some(Credential::TwoFactor(two_factor)) => {
                    let algorithm = TotpAlgorithm::try_from_name(
                        two_factor.algorithm.as_deref().unwrap_or("sha1"),
                    )?;
                    let auth =
                        TwoFactorAuth::new(&two_factor.client_id, &two_factor.secret, algorithm)?;
                    let auth = match two_factor.device.as_deref().map(str::trim) {
                        Some(device) if !device.is_empty() => auth.with_device(device),
                        _ => auth,
                    };
                    group.set_two_factor_for(&backend_id, Some(auth)).await;
                }
                // A server with neither opens no auth stream.
                None => {}
            }
        }

        // From here on the backends are asked whether they still answer, on a
        // timer, instead of only when something tries to use them.
        group.start_health_probe();

        Ok(ProxyClient { group, node_id })
    }

    /// One request, over a connection the domain mapping picked.
    async fn send_request_inner(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        let host = request.host().to_string();
        let pooled = self.group.get_connection(&host).await?;
        let result = crate::client::exchange_over(pooled.conn(), &request.to_bytes()).await;
        HttpResponse::parse(&result?)
    }

    /// Raw bytes, over the connection the domain mapping picked.
    async fn send_raw_inner(&self, host: String, data: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        let pooled = self.group.get_connection(&host).await?;
        let result = crate::client::exchange_over(pooled.conn(), &data).await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Node ID that is syntactically valid and that nothing is behind.
    fn unused_backend_id() -> String {
        iroh::SecretKey::generate()
            .public()
            .to_string()
            .parse::<iroh::EndpointId>()
            .expect("a generated public key is a valid node ID")
            .to_string()
    }

    fn server(node_id: String, domains: Vec<String>) -> ServerConfig {
        ServerConfig {
            server_node_id: Some(node_id),
            server_ticket: None,
            domains,
            two_factor: None,
            enrollment: None,
        }
    }

    fn config_with(servers: Vec<ServerConfig>) -> ClientConfig {
        ClientConfig {
            servers,
            load_balancing: None,
            relay_mode: None,
            relay_url: None,
            relay_auth_token: None,
        }
    }

    /// The surface answers for a client whose server answers nothing: it is
    /// configured, it knows its own node id, and it reports nothing.
    ///
    /// Nothing is dialled here, so this runs without a server and without a
    /// network — which is the point: building a client must not depend on a
    /// server being up.
    #[test]
    fn a_client_answers_for_itself() {
        let client = ProxyClient::new(config_with(vec![server(
            unused_backend_id(),
            vec!["example.test".to_string()],
        )]))
        .expect("a client with one configured server");

        assert!(!client.node_id().is_empty(), "the client has no node id");
        assert_eq!(client.server_ids().len(), 1);
        assert!(client.traffic().is_empty());
        let flows = client.flows(10);
        assert_eq!(flows.total, 0);
        assert!(flows.flows.is_empty());
    }

    /// A load balancing strategy nobody knows is refused at the start, rather
    /// than quietly meaning round robin.
    #[test]
    fn an_unknown_load_balancing_strategy_is_refused() {
        let mut config = config_with(vec![server(unused_backend_id(), vec![])]);
        config.load_balancing = Some("fastest".to_string());

        match ProxyClient::new(config) {
            Err(ClientError::InvalidConfig(_)) => {}
            Err(other) => panic!("the wrong error: {other}"),
            Ok(_) => panic!("an unknown strategy is not a strategy"),
        }
    }

    /// A relay mode nobody knows is refused too: a mode that is set but
    /// unusable is an error, never a silent substitution.
    #[test]
    fn an_unknown_relay_mode_is_refused() {
        let mut config = config_with(vec![server(unused_backend_id(), vec![])]);
        config.relay_mode = Some("through-the-moon".to_string());

        match ProxyClient::new(config) {
            Err(_) => {}
            Ok(_) => panic!("an unknown relay mode is not a mode"),
        }
    }

    /// A server named by neither a node id nor a ticket is a configuration
    /// mistake, and it is refused where it is written rather than at the first
    /// request.
    #[test]
    fn a_server_with_no_address_is_refused() {
        let config = config_with(vec![ServerConfig {
            server_node_id: None,
            server_ticket: None,
            domains: vec!["example.test".to_string()],
            two_factor: None,
            enrollment: None,
        }]);

        match ProxyClient::new(config) {
            Err(_) => {}
            Ok(_) => panic!("a server with no address is not a server"),
        }
    }

    /// The 2FA credentials of one server.
    fn two_factor(secret: &str) -> TwoFactorCredentials {
        TwoFactorCredentials {
            client_id: "client-001".to_string(),
            secret: secret.to_string(),
            algorithm: None,
            device: None,
        }
    }

    /// The one-time enrollment token of one server.
    fn enrollment() -> EnrollmentToken {
        EnrollmentToken {
            client_id: "client-001".to_string(),
            token: "an-enrollment-token".to_string(),
            device: None,
        }
    }

    /// A server that holds a secret authenticates with it and never enrolls.
    ///
    /// Enrolling rotates the server-side secret, so an app that kept the
    /// invite it scanned next to the credential it got would invalidate every
    /// other device on that client id on every start — and its own stored
    /// secret with it.
    #[test]
    fn a_server_with_a_secret_never_enrolls() {
        let mut server = server(unused_backend_id(), vec!["example.test".to_string()]);
        server.two_factor = Some(two_factor("JBSWY3DPEHPK3PXP"));
        server.enrollment = Some(enrollment());

        assert!(
            matches!(credential_for(&server), Some(Credential::TwoFactor(_))),
            "a server with a secret answers with the secret"
        );
    }

    /// A server with no secret spends the token instead.
    #[test]
    fn a_server_with_only_a_token_enrolls() {
        let mut server = server(unused_backend_id(), vec!["example.test".to_string()]);
        server.enrollment = Some(enrollment());

        assert!(
            matches!(credential_for(&server), Some(Credential::Enrollment(_))),
            "a server with no secret spends the token"
        );
    }

    /// A blank secret is a field nobody filled in, not a secret: the token is
    /// still what there is to spend.
    #[test]
    fn a_server_with_a_blank_secret_enrolls() {
        let mut server = server(unused_backend_id(), vec!["example.test".to_string()]);
        server.two_factor = Some(two_factor("   "));
        server.enrollment = Some(enrollment());

        assert!(
            matches!(credential_for(&server), Some(Credential::Enrollment(_))),
            "a blank secret is not a secret"
        );
    }

    /// A server with neither opens no auth stream at all.
    #[test]
    fn a_server_with_no_credential_has_none() {
        let server = server(unused_backend_id(), vec!["example.test".to_string()]);

        assert!(
            credential_for(&server).is_none(),
            "a server with no credential answers with nothing"
        );
    }
}
