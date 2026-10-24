//! The auxiliary listener, over a real socket.
//!
//! The point of these is the *shape* of the answer, which is what a scraper, a
//! supervisor and `nexapipe status` depend on and what no unit test of the
//! counters can pin down: `/healthz` answers without a credential, `/metrics`
//! is **absent** while `[metrics] enabled` is false rather than present and
//! empty, and `/v1/*` answers 503 when there is no token and 401 when the token
//! is wrong — never the resource.
//!
//! The listener is driven in-process rather than through the binary: it is the
//! same `serve_admin` the startup path spawns, and this way a test does not
//! have to bind an iroh endpoint, wait for it, or guess a port that another
//! test may be between uses of.
use nexapipe::admin;
use nexapipe::config::{ProxyConfig, RouteMode};
use nexapipe::conn::peers::PeerRegistry;
use nexapipe::lb::LoadBalancingStrategy;
use nexapipe::routes::{Route, RoutingTable};
use nexapipe::shutdown::{InFlight, ShutdownSignal};
use nexapipe_proto::secret::SecretString;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One answer, split the way an HTTP/1.1 response is laid out.
struct Reply {
    status: u16,
    head: String,
    body: String,
}

/// A listener serving `routes`, on a loopback port nothing else was using.
struct Admin {
    addr: SocketAddr,
    shutdown: Arc<ShutdownSignal>,
}

async fn spawn_admin(routes: Vec<Route>, metrics_enabled: bool, token: Option<&str>) -> Admin {
    spawn_admin_with_clients(routes, metrics_enabled, token, None).await
}

async fn spawn_admin_with_clients(
    routes: Vec<Route>,
    metrics_enabled: bool,
    token: Option<&str>,
    auth: Option<nexapipe::conn::AuthState>,
) -> Admin {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("listener address");
    let shutdown = Arc::new(ShutdownSignal::new());

    let config = Arc::new(RoutingTable::new(routes));
    let in_flight = Arc::new(InFlight::new());
    let peers = Arc::new(PeerRegistry::new());
    let state = Arc::new(admin::AdminState::new(
        config,
        in_flight,
        peers,
        auth,
        metrics_enabled,
        token.map(|token| SecretString::new(token.to_string())),
    ));
    let signal = shutdown.clone();

    tokio::spawn(async move {
        let _ = admin::serve_admin(listener, state, signal).await;
    });

    Admin { addr, shutdown }
}

impl Admin {
    async fn get(&self, path: &str) -> Reply {
        self.get_with(path, None).await
    }

    async fn get_with(&self, path: &str, token: Option<&str>) -> Reply {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .expect("connect to the admin listener");
        let auth = match token {
            Some(token) => format!("Authorization: Bearer {token}\r\n"),
            None => String::new(),
        };
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");

        let mut raw = String::new();
        stream
            .read_to_string(&mut raw)
            .await
            .expect("read response");

        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status line in:\n{raw}"));

        Reply {
            status,
            head: head.to_string(),
            body: body.to_string(),
        }
    }

    fn stop(&self) {
        self.shutdown.request_shutdown();
    }
}

fn http_route(host: &str, backends: Vec<String>) -> Route {
    Route::new(
        host,
        "/",
        true,
        backends,
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    )
}

/// An `[auth]` section with one enrolled client, loaded the way the server
/// loads it, so `/v1/clients` is tested against the real shape.
fn auth_with_secret(secret: &str) -> nexapipe::conn::AuthState {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            "[auth]\nenabled = true\n\n[auth.clients.alice]\nsecret = \"{secret}\"\n\
             created_at = \"2026-09-29T00:00:00Z\"\n"
        ),
    )
    .expect("write the config");
    let path = path.to_string_lossy().into_owned();
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config parses");
    let auth = auth.expect("[auth] is present");
    nexapipe::conn::AuthState::new(auth, path)
}

/// Liveness has to work without a credential — a supervisor should not need one
/// — and it has to be the only thing that does while metrics are off.
#[tokio::test]
async fn healthz_is_live_and_the_rest_is_absent_while_metrics_are_off() {
    let admin = spawn_admin(
        vec![http_route("app.test", vec!["http://127.0.0.1:1".into()])],
        false,
        None,
    )
    .await;

    let health = admin.get("/healthz").await;
    assert_eq!(health.status, 200, "{}", health.head);
    assert_eq!(health.body, "ok");

    // Absent, not empty: a scraper pointed at a deployment that never enabled
    // metrics has to be able to tell that from "no traffic yet".
    let metrics = admin.get("/metrics").await;
    assert_eq!(metrics.status, 404, "{}", metrics.head);

    admin.stop();
}

/// Once it is switched on, `/metrics` is the Prometheus text format and not
/// something a scraper has to be taught about: the content type is the one the
/// format specifies, and every metric declares its type before it is used.
#[tokio::test]
async fn metrics_are_served_in_the_exposition_format_when_enabled() {
    let admin = spawn_admin(
        vec![http_route("app.test", vec!["http://127.0.0.1:1".into()])],
        true,
        None,
    )
    .await;

    let metrics = admin.get("/metrics").await;
    assert_eq!(metrics.status, 200, "{}", metrics.head);
    assert!(
        metrics.head.contains("version=0.0.4"),
        "the exposition content type is missing from:\n{}",
        metrics.head
    );
    assert!(
        metrics
            .body
            .contains("# TYPE nexapipe_requests_total counter"),
        "{}",
        metrics.body
    );
    assert!(
        metrics
            .body
            .contains("nexapipe_connections_by_path{kind=\"direct\"} 0"),
        "{}",
        metrics.body
    );

    admin.stop();
}

/// Backend health is read from the pools at exposition time rather than counted
/// by the probes, so what the pools say now is what the page says — including
/// for a backend that was taken out of rotation since the last reload.
#[tokio::test]
async fn backends_are_counted_from_the_live_pools() {
    let up = "http://127.0.0.1:8080".to_string();
    let down = "http://127.0.0.1:9090".to_string();
    let route = http_route("app.test", vec![up.clone(), down.clone()]);
    route.backend_pool().set_backend_health(&down, false).await;

    let admin = spawn_admin(vec![route], true, None).await;
    let metrics = admin.get("/metrics").await;

    assert!(
        metrics.body.contains("nexapipe_backends_up 1"),
        "{}",
        metrics.body
    );
    assert!(
        metrics.body.contains("nexapipe_backends_down 1"),
        "{}",
        metrics.body
    );

    admin.stop();
}

/// A route that is never probed is never counted: a passthrough backend is a
/// TLS listener, so nothing would ever mark it down and counting it would
/// report backends as up that nobody has checked.
#[tokio::test]
async fn a_route_that_is_never_probed_is_not_counted_as_up() {
    let route = Route::new(
        "app.test",
        "/",
        true,
        vec!["10.0.0.5:443".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Passthrough,
        None,
    );

    let admin = spawn_admin(vec![route], true, None).await;
    let metrics = admin.get("/metrics").await;

    assert!(
        metrics.body.contains("nexapipe_backends_up 0"),
        "{}",
        metrics.body
    );
    assert!(
        metrics.body.contains("nexapipe_backends_down 0"),
        "{}",
        metrics.body
    );

    admin.stop();
}

/// The whole management surface is behind one token, and the token is checked
/// before anything else: a caller without it learns nothing about which paths
/// exist, because every one of them is answered the same way.
#[tokio::test]
async fn every_v1_path_answers_401_without_the_token() {
    let admin = spawn_admin(
        vec![http_route("app.test", vec!["http://127.0.0.1:1".into()])],
        true,
        Some("s3cr3t"),
    )
    .await;

    for path in [
        "/v1/status",
        "/v1/routes",
        "/v1/clients",
        "/v1/connections",
        "/v1/health",
        "/v1/anything",
    ] {
        let reply = admin.get(path).await;
        assert_eq!(
            reply.status, 401,
            "{path} answered {}: {}",
            reply.status, reply.head
        );
        assert!(
            reply
                .head
                .to_lowercase()
                .contains("www-authenticate: bearer"),
            "{path} did not send a challenge:\n{}",
            reply.head
        );
    }

    admin.stop();
}

/// A wrong token is answered exactly like no token: "unauthorized" is the whole
/// answer, and it must not carry which part of the token was right.
#[tokio::test]
async fn a_wrong_token_is_answered_like_no_token() {
    let admin = spawn_admin(Vec::new(), false, Some("s3cr3t")).await;

    let wrong = admin.get_with("/v1/status", Some("s3cr3")).await;
    assert_eq!(wrong.status, 401, "{}", wrong.head);
    assert_eq!(wrong.body, "unauthorized");

    let empty = admin.get_with("/v1/status", Some("")).await;
    assert_eq!(empty.status, 401, "{}", empty.head);

    admin.stop();
}

/// No token at all is 503, not 401: there is nothing the client could present,
/// so a challenge would be a lie — and it is not 404 either, because the
/// listener is up and the path does exist.
#[tokio::test]
async fn with_no_token_the_management_surface_is_unavailable() {
    let admin = spawn_admin(Vec::new(), false, None).await;

    let status = admin.get("/v1/status").await;
    assert_eq!(status.status, 503, "{}", status.head);
    assert!(status.body.contains("no admin token"), "{}", status.body);

    // The unauthenticated half is untouched: liveness is liveness.
    assert_eq!(admin.get("/healthz").await.status, 200);

    admin.stop();
}

/// `/v1/status` is the one an operator reaches for first, so it has to say
/// something about the instance rather than being an empty document: version,
/// uptime and the counters are the least it can answer with.
#[tokio::test]
async fn status_reports_the_instance() {
    let admin = spawn_admin(
        vec![http_route("app.test", vec!["http://127.0.0.1:1".into()])],
        true,
        Some("s3cr3t"),
    )
    .await;

    let status = admin.get_with("/v1/status", Some("s3cr3t")).await;
    assert_eq!(status.status, 200, "{}", status.head);

    let body: serde_json::Value = serde_json::from_str(&status.body).expect("valid JSON");
    assert!(body["version"].is_string(), "{}", body);
    assert!(body["uptime_seconds"].is_number(), "{}", body);
    assert_eq!(body["connections"]["active"], 0);
    assert_eq!(body["routes"], 1);
    assert_eq!(body["peers"], 0);
    assert!(body["backends"]["up"].is_number(), "{}", body);

    admin.stop();
}

/// `/v1/routes` is the live table: what the reload put in it, with the modes a
/// route serves spelled the way the config spells them.
#[tokio::test]
async fn routes_are_listed_with_their_modes_and_backends() {
    let admin = spawn_admin(
        vec![http_route("app.test", vec!["http://127.0.0.1:1".into()])],
        false,
        Some("s3cr3t"),
    )
    .await;

    let reply = admin.get_with("/v1/routes", Some("s3cr3t")).await;
    assert_eq!(reply.status, 200, "{}", reply.head);

    let body: serde_json::Value = serde_json::from_str(&reply.body).expect("valid JSON");
    let routes = body["routes"].as_array().expect("a routes array");
    assert_eq!(routes.len(), 1, "{body}");
    assert_eq!(routes[0]["host_pattern"], "app.test");
    assert_eq!(routes[0]["modes"][0], "http");
    assert_eq!(routes[0]["health_checked"], true);
    assert_eq!(routes[0]["backends"][0]["url"], "http://127.0.0.1:1");

    admin.stop();
}

/// The one thing `/v1/clients` must never do: it names the clients without
/// handing out the secret that is half of their second factor. A management
/// surface that leaks those turns a read-only endpoint into a credential store.
#[tokio::test]
async fn clients_are_listed_without_their_secrets() {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let admin = spawn_admin_with_clients(
        Vec::new(),
        false,
        Some("s3cr3t"),
        Some(auth_with_secret(secret)),
    )
    .await;

    let reply = admin.get_with("/v1/clients", Some("s3cr3t")).await;
    assert_eq!(reply.status, 200, "{}", reply.head);

    let body: serde_json::Value = serde_json::from_str(&reply.body).expect("valid JSON");
    assert_eq!(body["enabled"], true);
    let clients = body["clients"].as_array().expect("a clients array");
    assert_eq!(clients.len(), 1, "{body}");
    assert_eq!(clients[0]["id"], "alice");
    assert_eq!(clients[0]["has_secret"], true);

    // The test that matters: the secret is nowhere in the answer, not masked,
    // not truncated, not under another name.
    assert!(
        !reply.body.contains(secret),
        "the client secret leaked into /v1/clients:\n{}",
        reply.body
    );
    assert!(
        clients[0]["secret"].is_null(),
        "a secret field exists:\n{}",
        clients[0]
    );

    admin.stop();
}

/// The port ACL is listed with the clients: the management surface is where an
/// operator looks to find out what a client may reach.
///
/// The **rule** is listed with it, because the list alone does not say what it
/// means: `allow_ports_strict` off means the list is checked against the port
/// the client named — and a request that named none is not checked at all —
/// while on means it is checked against the port the request is actually
/// served from. A list without the rule is a list an operator has to guess
/// the meaning of.
#[tokio::test]
async fn the_port_acl_is_listed_with_the_clients() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\nenabled = true\n\n[auth.clients.alice]\nsecret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
         created_at = \"2026-09-29T00:00:00Z\"\nallow_ports = [443, 8443]\n\
         allow_ports_strict = true\n",
    )
    .expect("write the config");
    let path = path.to_string_lossy().into_owned();
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config parses");
    let auth = auth.expect("[auth] is present");

    let admin = spawn_admin_with_clients(
        Vec::new(),
        false,
        Some("s3cr3t"),
        Some(nexapipe::conn::AuthState::new(auth, path)),
    )
    .await;

    let reply = admin.get_with("/v1/clients", Some("s3cr3t")).await;
    assert_eq!(reply.status, 200, "{}", reply.head);
    let body: serde_json::Value = serde_json::from_str(&reply.body).expect("valid JSON");
    let clients = body["clients"].as_array().expect("a clients array");
    assert_eq!(
        clients[0]["allow_ports"],
        serde_json::json!([443, 8443]),
        "{body}"
    );
    assert_eq!(
        clients[0]["allow_ports_strict"],
        serde_json::json!(true),
        "the rule the list is read under is listed with it: {body}"
    );

    admin.stop();
}

/// `/v1/health` is about the pools, not the routes: it counts what is in
/// rotation and what is not, read now rather than remembered.
#[tokio::test]
async fn health_reports_backend_pools() {
    let up = "http://127.0.0.1:8080".to_string();
    let down = "http://127.0.0.1:9090".to_string();
    let route = http_route("app.test", vec![up, down.clone()]);
    route.backend_pool().set_backend_health(&down, false).await;

    let admin = spawn_admin(vec![route], false, Some("s3cr3t")).await;
    let reply = admin.get_with("/v1/health", Some("s3cr3t")).await;
    assert_eq!(reply.status, 200, "{}", reply.head);

    let body: serde_json::Value = serde_json::from_str(&reply.body).expect("valid JSON");
    assert_eq!(body["backends_up"], 1, "{body}");
    assert_eq!(body["backends_down"], 1, "{body}");

    admin.stop();
}

/// Nobody is connected in a process that has not accepted anything, and the
/// answer is an empty list rather than a missing key: `nexapipe status` prints
/// it without a special case.
#[tokio::test]
async fn connections_are_empty_when_nobody_is_connected() {
    let admin = spawn_admin(Vec::new(), false, Some("s3cr3t")).await;

    let reply = admin.get_with("/v1/connections", Some("s3cr3t")).await;
    assert_eq!(reply.status, 200, "{}", reply.head);

    let body: serde_json::Value = serde_json::from_str(&reply.body).expect("valid JSON");
    assert_eq!(body["peers"].as_array().expect("a peers array").len(), 0);

    admin.stop();
}

/// Only GET, and only on the paths that exist: the surface is read-only, so a
/// POST is rejected outright rather than answered with something unchanged.
#[tokio::test]
async fn the_management_surface_rejects_anything_but_get() {
    let admin = spawn_admin(Vec::new(), false, Some("s3cr3t")).await;

    let mut stream = TcpStream::connect(admin.addr).await.expect("connect");
    let request = "POST /v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer s3cr3t\r\n\
                   Connection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.expect("read");

    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("a status line");
    assert_eq!(status, "405", "{raw}");

    admin.stop();
}

/// The two sections the listener hangs off, read back through the config file:
/// absent means the listener is not bound, and metrics stay off until someone
/// asks for both.
#[test]
fn the_admin_and_metrics_sections_round_trip_through_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    std::fs::write(
        &path,
        "[admin]\nlisten_addr = \"127.0.0.1:9090\"\n\n[metrics]\nenabled = true\n",
    )
    .unwrap();
    let config = ProxyConfig::from_file(path.to_str().unwrap()).expect("the config parses");
    let admin = config.admin.as_ref().expect("[admin] is present");
    assert_eq!(admin.listen_addr.as_deref(), Some("127.0.0.1:9090"));
    assert!(config.metrics.enabled, "[metrics] enabled = true");

    let empty = dir.path().join("empty.toml");
    std::fs::write(&empty, "[server]\n").unwrap();
    let config = ProxyConfig::from_file(empty.to_str().unwrap()).expect("the config parses");
    assert!(
        config.admin.is_none(),
        "no [admin] section means no listener"
    );
    assert!(
        !config.metrics.enabled,
        "metrics are off until they are asked for"
    );
}

/// A token in the config is refused, not ignored.
///
/// The `[admin]` section has no `token` key: the token is generated into
/// `<config>.admin-token`, and that file is the only source of it. A config
/// that names a token is a config whose operator believes they set one, so it
/// is refused at load rather than parsed and dropped — the difference between
/// "the token you set is not the one in use" and "the config does not start".
#[test]
fn a_token_in_the_config_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[admin]\nlisten_addr = \"127.0.0.1:9090\"\ntoken = \"from-the-config\"\n",
    )
    .unwrap();

    let error = ProxyConfig::from_file(path.to_str().unwrap())
        .expect_err("a config that names a token does not parse");
    assert!(
        error.to_string().contains("token"),
        "the error names the key: {error:#}"
    );

    // The generated file is still the only source of the token: a config that
    // names one never reaches the code that would have read it.
    let token = admin::token::load_or_create(path.to_str().unwrap()).expect("a token is generated");
    assert_ne!(token.expose_secret(), "from-the-config");
    assert_eq!(
        token.expose_secret().len(),
        64,
        "32 random bytes, hex encoded"
    );
}

/// The one address rule that has no escape hatch: unlike the plaintext
/// listener, this one cannot be asked to bind off loopback.
#[test]
fn a_non_loopback_address_is_refused() {
    let addr: SocketAddr = "192.168.1.10:9090".parse().unwrap();
    assert!(!admin::may_bind_admin(addr));

    let refusal = admin::non_loopback_refusal(addr);
    assert!(refusal.contains("192.168.1.10:9090"), "{refusal}");
}

/// The status command does not send the admin token to an address the
/// server itself would refuse to bind.
///
/// `nexapipe status` asks a running instance what it is doing, and it does
/// so with the admin token in the `Authorization` header of every request.
/// The server refuses to bind this listener off loopback, so a config naming
/// a remote address describes an instance that could never have started — and
/// a status run that reached it anyway would hand that address the routes,
/// the client list, the peer identities and the backend inventory.
///
/// The refusal has to come *before* the token is read and before a socket is
/// opened, so the test watches the socket: a stand-in for the instance is
/// bound on the wildcard address, and the address under test is that
/// stand-in's own, so a request that *was* made would arrive here and be
/// seen — with the token in it.
#[tokio::test]
async fn the_status_command_refuses_a_non_loopback_address_without_calling_it() {
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .expect("bind a stand-in on the wildcard address");
    let addr = listener.local_addr().expect("the stand-in address");

    // The stand-in answers what it is asked and counts what arrived, so a
    // status run that reached it finishes instead of waiting for a response
    // that never comes.
    let (arrived, mut arrivals) = tokio::sync::mpsc::unbounded_channel();
    let stand_in = tokio::spawn(async move {
        loop {
            // A deadline rather than a bare accept: the stand-in has to end
            // even when nothing ever asks it anything.
            let accepted =
                tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await;
            let Ok(Ok((mut stream, _))) = accepted else {
                break;
            };
            let _ = arrived.send(());
            let mut request = vec![0u8; 4096];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                )
                .await;
            let _ = stream.flush().await;
        }
    });

    let dir = tempfile::tempdir().expect("a scratch directory");
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, format!("[admin]\nlisten_addr = \"{addr}\"\n"))
        .expect("write the config");

    // The token has to be there, and readable only by this account: the
    // refusal has to be about the address, not about a missing credential.
    let config_str = config_path.to_str().expect("a path");
    let token_path = admin::token::token_file_path(config_str);
    std::fs::write(&token_path, "a token nobody has to see\n").expect("write the token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
            .expect("make the token private");
    }

    let refusal = match nexapipe::status::status(config_str, false).await {
        Ok(()) => panic!(
            "the status command answered a non-loopback address instead of refusing it, so the \
             admin token was sent to {addr}"
        ),
        Err(reason) => reason.to_string(),
    };
    assert!(
        refusal.contains(&addr.to_string()),
        "the refusal names the address: {refusal}"
    );
    assert!(
        refusal.contains("loopback"),
        "the refusal says what to do instead: {refusal}"
    );

    // And nothing was sent: the address was refused before a socket was
    // opened, so the token never left the machine.
    stand_in.await.expect("the stand-in finished");
    assert!(
        arrivals.try_recv().is_err(),
        "the status command opened a connection to {addr} and sent the token there"
    );
}
