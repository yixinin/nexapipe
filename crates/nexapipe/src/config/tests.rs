//! The tests of the configuration file.

//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it
//! is testing.

use nexapipe_proto::secret::SecretString;
use std::collections::HashMap;
use std::fs;

/// Every field of the spec reaches the route.
///
/// The conversion takes the spec apart with a pattern that names every
/// field, so a field the schema grows and the conversion does not know
/// about is a **compile error**. This test is the other half of that: it
/// says that a field the conversion *does* know about is not quietly
/// dropped on the way to the route.
///
/// Every field is set to something distinctive, so a field that stopped
/// being read would show up as a default rather than as a coincidence.
#[test]
fn every_field_of_the_spec_reaches_the_route() {
    let spec = RouteSpec {
        host_pattern: "*.example.com".to_string(),
        path_pattern: "/api".to_string(),
        path_is_prefix: Some(false),
        strategy: Some("least_conn".to_string()),
        backends: vec!["127.0.0.1:9000".to_string(), "127.0.0.1:9001".to_string()],
        backend_protocol: Some("h2c".to_string()),
        mode: Some("tcp".to_string()),
        modes: Some(vec!["udp".to_string()]),
        path_rewrite: Some("/rewritten".to_string()),
        client_ports: Some(vec![8443]),
        idle_timeout_secs: Some(11),
        flow_timeout_secs: Some(22),
        cert_path: None,
        key_path: None,
        redirect_to_https: None,
    };

    let route = crate::routes::Route::try_from(spec).expect("the route is built");

    assert_eq!(route.host_pattern(), "*.example.com");
    assert_eq!(route.path_pattern(), "/api");
    assert!(!route.path_is_prefix(), "path_is_prefix was set to false");
    assert_eq!(
        route.backend_pool().len(),
        2,
        "both backends are on the route"
    );
    assert!(
        matches!(
            route.backend_pool().strategy(),
            crate::lb::LoadBalancingStrategy::LeastConn
        ),
        "the strategy was carried over"
    );
    assert_eq!(
        route.backend_protocol(),
        BackendProtocol::H2c,
        "the backend protocol was carried over"
    );
    assert_eq!(
        route.path_rewrite().as_deref(),
        Some("/rewritten"),
        "the path rewrite was carried over"
    );
    assert_eq!(
        route.idle_timeout(),
        Some(std::time::Duration::from_secs(11))
    );
    assert_eq!(
        route.flow_timeout(),
        Some(std::time::Duration::from_secs(22))
    );
    assert!(
        route.modes().contains(&RouteMode::Tcp),
        "the mode was carried over: {:?}",
        route.modes()
    );
    assert!(
        route.modes().contains(&RouteMode::Udp),
        "the modes list was carried over: {:?}",
        route.modes()
    );
    assert!(
        route.matches_l4("a.example.com", 8443),
        "the client port was carried over"
    );
    assert!(
        !route.matches_l4("a.example.com", 9999),
        "a port the spec did not name does not match"
    );
}
use super::*;
use crate::auth::DeviceMaterial;

/// A credential in a file others can read is worth a warning; one in a
/// file only its owner can read is not.
///
/// The permission gate itself was removed on purpose (ROADMAP §3.5) — a
/// `0644` bind mount has to start — so this line is the only thing that
/// says a 2FA seed is sitting in a file the whole machine can read.
///
/// Unix only: the permission bits are a Unix idea.
#[cfg(unix)]
#[test]
fn a_credential_in_a_readable_file_is_warned_about() {
    use std::os::unix::fs::PermissionsExt;

    let with_a_seed = toml::from_str::<crate::auth::AuthConfig>(
        r#"
enabled = true

[clients.client-001]
secret = "JBSWY3DPEHPK3PXP"
"#,
    )
    .expect("the auth config parses");
    let without_a_seed = crate::auth::AuthConfig::default();
    let proxy = parse("");

    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "").expect("the file is written");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("the mode is set");
    assert!(
        !should_warn_about_permissions(&path, &proxy, Some(&with_a_seed)),
        "a file only its owner can read is not worth a warning"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("the mode is set");
    assert!(
        should_warn_about_permissions(&path, &proxy, Some(&with_a_seed)),
        "a seed in a file others can read is worth a warning"
    );
    assert!(
        !should_warn_about_permissions(&path, &proxy, Some(&without_a_seed)),
        "a file with no credential in it is not worth a warning"
    );
}

/// A file with no `[auth]` section is not a file with no credential.
///
/// An inline `[iroh]` key is a credential on its own, and the files this
/// server actually ships — `config.toml.example`, the generated first-run
/// template — carry one. A warning that only ran when an `AuthConfig`
/// existed was silent for exactly those.
#[cfg(unix)]
#[test]
fn an_inline_key_without_an_auth_section_is_warned_about() {
    use std::os::unix::fs::PermissionsExt;

    let with_a_key = parse("[iroh]\nsecret_key = \"00\"\n");
    assert!(with_a_key.holds_credentials());

    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "").expect("the file is written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("the mode is set");

    assert!(
        should_warn_about_permissions(&path, &with_a_key, None),
        "an inline key in a readable file is worth a warning, [auth] or not"
    );
    assert!(
        !should_warn_about_permissions(&path, &parse(""), None),
        "a file with neither half holding a credential is not"
    );
}

/// Group-readable is enough. A file the owner's group can read is a file
/// somebody else on the machine can read.
#[cfg(unix)]
#[test]
fn a_group_readable_file_is_warned_about() {
    use std::os::unix::fs::PermissionsExt;

    let with_a_seed = toml::from_str::<crate::auth::AuthConfig>(
        r#"
enabled = true

[clients.client-001]
secret = "JBSWY3DPEHPK3PXP"
"#,
    )
    .expect("the auth config parses");
    let proxy = parse("");

    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "").expect("the file is written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
        .expect("the mode is set");

    assert!(
        should_warn_about_permissions(&path, &proxy, Some(&with_a_seed)),
        "a group-readable file is readable by others"
    );
}

/// A device that proves itself with a signature holds no seed, so it is
/// not one of these.
#[test]
fn a_key_based_device_holds_no_seed() {
    let auth = toml::from_str::<crate::auth::AuthConfig>(
        r#"
enabled = true

[clients.client-001]
secret = ""

[clients.client-001.devices.laptop]
public_key = "0011"
"#,
    )
    .expect("the auth config parses");

    assert!(
        !auth.holds_inline_secrets(),
        "a key-based device has nothing to steal"
    );
}

/// A device that was issued a seed is one of these, even when its client
/// has none.
#[test]
fn a_device_with_a_seed_holds_one() {
    let auth = toml::from_str::<crate::auth::AuthConfig>(
        r#"
enabled = true

[clients.client-001]
secret = ""

[clients.client-001.devices.laptop]
secret = "JBSWY3DPEHPK3PXP"
"#,
    )
    .expect("the auth config parses");

    assert!(auth.holds_inline_secrets(), "a device's seed is a seed");
}

/// The port rule is read at the top level as well, so the server can say which
/// of the two rules a client is held against.
///
/// A client with a port list and the strict flag off is the one an operator
/// has to be told about: the list is checked against the port the client
/// *names*, and a request that names no port is not checked at all. A client
/// with no port list is not limited by ports at all, and a client with the
/// strict flag on is held against the port the request is *served from* — the
/// stronger rule, and the one that needs no warning.
#[test]
fn the_port_rule_is_read_at_the_top_level() {
    let config = parse(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.named]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         allow_ports = [443]\n\
         \n\
         [auth.clients.strict]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         allow_ports = [443]\n\
         allow_ports_strict = true\n\
         \n\
         [auth.clients.unlimited]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    );

    let rules = config.auth.expect("the [auth] section was read");
    assert_eq!(
        rules.clients_with_the_named_port_rule(),
        vec!["named"],
        "only the client with a port list and the strict flag off is reported"
    );
}

/// The summary holds no credential.
///
/// The section it is read from holds the seeds, and a copy of them inside the
/// configuration would be a second copy of every secret in the file, held for
/// as long as the configuration lives. The two keys it keeps are not secrets,
/// and nothing else is kept at all.
#[test]
fn the_port_rule_summary_holds_no_credential() {
    let config = parse(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         allow_ports = [443]\n",
    );

    let rules = config.auth.expect("the [auth] section was read");
    let debug = format!("{rules:?}");
    assert!(
        !debug.contains("JBSWY3DPEHPK3PXP"),
        "the seed was copied into the configuration: {debug}"
    );
}

fn parse(source: &str) -> ProxyConfig {
    toml::from_str(source).expect("config should parse")
}

/// Writes `source` to a throwaway file and loads it the way a start does.
///
/// `load_with_auth` takes a path rather than a string — it is also what
/// checks the file's permissions — so parsing a snippet needs a real file.
fn load_from(source: &str) -> anyhow::Result<(ProxyConfig, Option<crate::auth::AuthConfig>)> {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, source).expect("write the config");
    ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
}

/// `build_routes` is what both a cold start and a config reload use, so a
/// route that would work after a restart must also work without one — and a
/// broken one must be *reported*, not silently dropped.
#[test]
fn build_routes_is_what_a_restart_would_have_built() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "fn.iakl.top"
mode = "passthrough"
backends = ["host.docker.internal:8443"]

[[routes]]
host_pattern = "fn.iakl.top"
mode = "tcp"
backends = ["host.docker.internal:8443"]
client_ports = [443]

[[routes]]
host_pattern = "mt.iroh.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );

    let routes = config.build_routes().expect("the config is valid");
    assert_eq!(routes.len(), 3);

    // The two entries for one host do not collapse into each other: same
    // host, different mode, and the L4 one kept its port selector.
    assert_eq!(routes[0].modes(), &[RouteMode::Passthrough][..]);
    assert_eq!(routes[1].modes(), &[RouteMode::Tcp][..]);
    assert!(routes[1].matches_l4("fn.iakl.top", 443));
    assert!(!routes[1].matches_l4("fn.iakl.top", 8443));
    assert_eq!(routes[2].modes(), &[RouteMode::Http][..]);

    // No `default_backend` at all: the key is gone, and building routes
    // must not require one.
    assert!(config.default_backend.is_none());
}

/// A config that still names `default_backend` is refused, not ignored.
///
/// The key is still parsed, because serde drops what the struct does not
/// name: without this the config would keep starting and every host the
/// fallback used to serve would quietly become a 404.
#[test]
fn build_routes_refuses_the_removed_default_backend() {
    let config = parse(
        r#"
default_backend = "http://10.0.0.5:8080"

[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
"#,
    );

    let error = config.build_routes().unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("default_backend has been removed"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("host_pattern = \"*\""),
        "the error must say what to write instead: {message}"
    );
}

/// The `[circuit_breaker]` section, and what it does when it is not
/// there.
#[test]
fn the_circuit_breaker_section_is_read_and_bounded() {
    let breaker = CircuitBreaker::resolve(CircuitBreakerConfig::default());
    assert!(breaker.enabled, "the circuit is on unless it is turned off");
    assert_eq!(breaker.failure_threshold, 5);
    assert_eq!(breaker.reset, std::time::Duration::from_secs(30));

    let config = parse(
        r#"
[circuit_breaker]
enabled = false
failure_threshold = 2
reset_secs = 10
"#,
    );
    let breaker = config.circuit_breaker();
    assert!(!breaker.enabled);
    assert_eq!(breaker.failure_threshold, 2);
    assert_eq!(breaker.reset, std::time::Duration::from_secs(10));

    // A threshold of zero would take every backend out on its first
    // failure, which is not what anybody means by zero.
    let config = parse(
        r#"
[circuit_breaker]
failure_threshold = 0
"#,
    );
    assert_eq!(config.circuit_breaker().failure_threshold, 1);
}

/// The `[retry]` section, and what it does when it is not there.
#[test]
fn the_retry_section_is_read_and_bounded() {
    // Absent means no retry at all: a second attempt at something the
    // backend may already have done is not a decision to make by default.
    assert_eq!(Retry::resolve(RetryConfig::default()).attempts, 0);

    let config = parse(
        r#"
[retry]
attempts = 3
backoff_ms = 250
"#,
    );
    let retry = config.retry();
    assert_eq!(retry.attempts, 3);
    assert_eq!(retry.backoff, std::time::Duration::from_millis(250));

    // A section that asks for a hundred attempts gets a number that is
    // still a number of attempts and not a denial of service.
    let config = parse(
        r#"
[retry]
attempts = 1000
"#,
    );
    assert_eq!(config.retry().attempts, 16);
}

/// The protocol a route speaks to its backends, and what happens when the
/// key says something nobody speaks.
#[test]
fn the_backend_protocol_is_read_and_refused_when_it_is_nonsense() {
    assert_eq!(
        get_backend_protocol(&None).expect("the default"),
        BackendProtocol::Http1
    );
    assert_eq!(
        get_backend_protocol(&Some("http1".to_string())).expect("http1"),
        BackendProtocol::Http1
    );
    assert_eq!(
        get_backend_protocol(&Some("h2c".to_string())).expect("h2c"),
        BackendProtocol::H2c
    );

    let error = get_backend_protocol(&Some("h3".to_string()))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("h2c"),
        "the message has to say what is accepted: {error}"
    );
}

/// `h2c` is HTTP/2 in the clear; an `https://` backend speaks it through
/// the TLS handshake instead, and the two cannot be combined.
#[test]
fn an_h2c_route_refuses_an_https_backend() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["https://caddy:443"]
backend_protocol = "h2c"
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("h2c"),
        "the message has to name the key that caused it: {error}"
    );
}

/// A cleartext backend with `h2c` is what the key is for, and it is
/// accepted.
#[test]
fn an_h2c_route_accepts_a_cleartext_backend() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
backend_protocol = "h2c"
"#,
    );

    let routes = config.build_routes().expect("the route is valid");
    assert_eq!(routes[0].backend_protocol(), BackendProtocol::H2c);
}

/// A backend whose scheme is neither `http` nor `https` cannot be fetched
/// at all, and the message has to name the backend that carries it.
#[test]
fn build_routes_rejects_a_backend_that_cannot_work() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["ftp://caddy:443"]
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("ftp://"),
        "the message has to name the offending backend, got: {error}"
    );
}

/// `0` was clamped with `max(1)` on the way in, which is how a typo turned
/// into a probe storm, or into every backend being taken out of rotation.
#[test]
fn build_routes_refuses_a_zero_health_check_number() {
    for (key, why) in [
        ("interval", "interval is 0"),
        ("timeout", "timeout is 0"),
        ("threshold", "threshold is 0"),
    ] {
        let config = parse(&format!(
            r#"
[health_check]
{key} = 0

[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
"#
        ));

        let error = config.build_routes().unwrap_err().to_string();
        assert!(error.contains(why), "{key}: unexpected error: {error}");
    }
}

#[test]
fn build_routes_accepts_the_health_check_defaults() {
    // Nothing in the file: the defaults have to pass the same check.
    let config = parse(
        r#"
[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
"#,
    );
    assert!(config.build_routes().is_ok());
}

/// Port 0 is not a port a flow arrives from, so a route naming it is dead
/// the moment it loads — and nothing would ever say so.
#[test]
fn build_routes_refuses_a_client_port_no_flow_can_arrive_on() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "db.iakl.top"
mode = "tcp"
backends = ["10.0.0.5:5432"]
client_ports = [0]
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(error.contains("port 0"), "unexpected error: {error}");
}

#[test]
fn build_routes_refuses_an_empty_client_ports_list() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "db.iakl.top"
mode = "tcp"
backends = ["10.0.0.5:5432"]
client_ports = []
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("client_ports is empty"),
        "unexpected error: {error}"
    );
}

/// A zero idle timeout closes a UDP flow as soon as it is opened.
#[test]
fn build_routes_refuses_a_zero_idle_timeout() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "turn.iakl.top"
mode = "udp"
backends = ["10.0.0.5:3478"]
idle_timeout_secs = 0
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("idle_timeout_secs"),
        "unexpected error: {error}"
    );
}

/// A zero flow timeout closes a flow as soon as it is opened, which is what
/// a zero here would actually do — so it is refused rather than accepted.
#[test]
fn build_routes_refuses_a_zero_flow_timeout() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "db.nekblab.top"
mode = "tcp"
backends = ["10.0.0.5:5432"]
flow_timeout_secs = 0
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("flow_timeout_secs"),
        "unexpected error: {error}"
    );
}

/// The two bounds are independent: naming one does not disturb the other,
/// and leaving both out is what a config written before either existed does.
#[test]
fn the_flow_and_idle_timeouts_are_carried_separately() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "db.nekblab.top"
mode = "udp"
backends = ["10.0.0.5:3478"]
idle_timeout_secs = 120
flow_timeout_secs = 7200
"#,
    );
    let routes = config.build_routes().unwrap();
    assert_eq!(
        routes[0].idle_timeout(),
        Some(std::time::Duration::from_secs(120))
    );
    assert_eq!(
        routes[0].flow_timeout(),
        Some(std::time::Duration::from_secs(7200))
    );

    let bare = parse(
        r#"
[[routes]]
host_pattern = "db.nekblab.top"
mode = "udp"
backends = ["10.0.0.5:3478"]
"#,
    );
    let routes = bare.build_routes().unwrap();
    assert!(routes[0].idle_timeout().is_none());
    assert!(
        routes[0].flow_timeout().is_none(),
        "an absent key means the server default, not zero"
    );
}

#[test]
fn build_routes_rejects_a_passthrough_backend_with_no_address() {
    // Passthrough copies bytes, so its backend was never checked at all:
    // this one dials nothing and only failed once a connection arrived.
    let config = parse(
        r#"
[[routes]]
host_pattern = "app.iakl.top"
mode = "passthrough"
backends = [""]
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("passthrough"),
        "the message has to say which route cannot dial it, got: {error}"
    );
}

#[test]
fn build_routes_accepts_an_ipv6_passthrough_backend() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "app.iakl.top"
mode = "passthrough"
backends = ["[::1]:443"]
"#,
    );

    config
        .build_routes()
        .expect("an IPv6 literal is an address a passthrough route can dial");
}

#[test]
fn build_routes_rejects_a_route_with_no_backends() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "app.iakl.top"
mode = "http"
backends = []
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("no backends"),
        "the message has to say what is missing, got: {error}"
    );
}

/// The point of the whole section: writing nothing under it has to mean "the
/// deadlines this server already had", not "wait forever" and not any other
/// number.
#[test]
fn no_timeouts_section_keeps_the_deadlines_it_replaced() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );

    let timeouts = config.timeouts();
    assert_eq!(timeouts.connect, std::time::Duration::from_secs(10));
    assert_eq!(timeouts.response, std::time::Duration::from_secs(30));
}

#[test]
fn a_partial_timeouts_section_leaves_the_rest_alone() {
    let config = parse(
        r#"
[timeouts]
response_secs = 120

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );

    config
        .build_routes()
        .expect("configuring one deadline is not an error");
    let timeouts = config.timeouts();
    assert_eq!(
        timeouts.response,
        std::time::Duration::from_secs(120),
        "the one that was written"
    );
    assert_eq!(
        timeouts.connect,
        std::time::Duration::from_secs(10),
        "the one that was not"
    );
}

/// A zero timeout is not a stricter timeout: it is one no backend can meet,
/// so every request fails — and it fails looking like every backend is down.
#[test]
fn build_routes_rejects_a_zero_timeout() {
    let config = parse(
        r#"
[timeouts]
connect_secs = 0

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("connect_secs is 0"),
        "the message has to name the key nobody can meet, got: {error}"
    );
}

/// Past the ceiling a timeout stops describing a slow backend and starts
/// describing a request that never finishes, which is what it exists to
/// prevent.
#[test]
fn build_routes_rejects_a_timeout_that_never_expires() {
    let config = parse(
        r#"
[timeouts]
response_secs = 86400

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("86400s"),
        "the message has to quote the number it refused, got: {error}"
    );
}

/// The per-phase budgets resolve into `Timeouts::deadlines` beside the dial
/// deadlines, each key answering for its own phase and the rest staying at
/// their defaults.
#[test]
fn a_phase_deadline_override_reaches_the_deadlines() {
    let config = parse(
        r#"
[timeouts]
body_secs = 60
l4_flow_secs = 7200

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );

    config
        .build_routes()
        .expect("raising a phase deadline is not an error");
    let deadlines = config.timeouts().deadlines;
    assert_eq!(
        deadlines.body,
        std::time::Duration::from_secs(60),
        "the one that was written"
    );
    assert_eq!(
        deadlines.l4_flow,
        std::time::Duration::from_secs(7200),
        "raising an L4 flow past its one-hour default is the documented reason the key exists"
    );
    assert_eq!(
        deadlines.header,
        std::time::Duration::from_secs(crate::deadline::DEFAULT_HEADER_SECS),
        "the one that was not written"
    );
    assert_eq!(
        deadlines.response_idle,
        std::time::Duration::from_secs(crate::deadline::DEFAULT_RESPONSE_IDLE_SECS)
    );
}

/// Zero is refused on the phase budgets for the reason it is refused on the
/// dial ones, with a different reading: here it does not fail every request,
/// it closes every flow the instant it opens.
#[test]
fn build_routes_rejects_a_zero_phase_deadline() {
    let config = parse(
        r#"
[timeouts]
header_secs = 0

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );

    let error = config.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("header_secs is 0"),
        "the message has to name the key nobody can meet, got: {error}"
    );
}

/// The phase budgets take their ceiling from `crate::deadline` (a day), not
/// from the dial keys (an hour): a long-lived tunnel is exactly the case
/// `l4_flow_secs` exists to be raised for, so a day must be accepted here
/// where `response_secs = 86400` is refused.
#[test]
fn a_phase_deadline_may_reach_a_day_but_no_further() {
    let ok = parse(
        r#"
[timeouts]
l4_flow_secs = 86400

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );
    ok.build_routes()
        .expect("a day is the ceiling the deadline module itself enforces");

    let over = parse(
        r#"
[timeouts]
l4_flow_secs = 86401

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
    );
    let error = over.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("86401s"),
        "the message has to quote the number it refused, got: {error}"
    );
}

#[test]
fn least_conn_is_a_strategy_a_config_can_ask_for() {
    assert!(matches!(
        get_strategy(&Some("least_conn".to_string())).expect("least_conn"),
        crate::lb::LoadBalancingStrategy::LeastConn
    ));
    assert!(matches!(
        get_strategy(&Some("LeastConn".to_string())).expect("LeastConn"),
        crate::lb::LoadBalancingStrategy::LeastConn
    ));
    assert!(matches!(
        get_strategy(&Some("round_robin".to_string())).expect("round_robin"),
        crate::lb::LoadBalancingStrategy::RoundRobin
    ));
    assert!(matches!(
        get_strategy(&Some("Random".to_string())).expect("Random"),
        crate::lb::LoadBalancingStrategy::Random
    ));
    // A typo is not one of them, and it is refused rather than becoming a
    // strategy that ignores load without saying so.
    let error =
        get_strategy(&Some("least_conns".to_string())).expect_err("a typo is not a strategy");
    let message = error.to_string();
    assert!(message.contains("strategy"), "{message}");
    assert!(message.contains("least_conns"), "{message}");
    assert!(message.contains("round_robin"), "{message}");
}

#[test]
fn route_mode_defaults_to_http() {
    assert_eq!(get_route_mode(&None).expect("the default"), RouteMode::Http);
    assert_eq!(
        get_route_mode(&Some("http".to_string())).expect("http"),
        RouteMode::Http
    );
    assert_eq!(
        get_route_mode(&Some("passthrough".to_string())).expect("passthrough"),
        RouteMode::Passthrough
    );
    // A typo is refused: a route that serves something other than what the
    // file says is a routing surprise nobody is told about.
    let error =
        get_route_mode(&Some("pass-through".to_string())).expect_err("a typo is not a mode");
    let message = error.to_string();
    assert!(message.contains("mode"), "{message}");
    assert!(message.contains("pass-through"), "{message}");
    assert!(message.contains("passthrough"), "{message}");
}

/// An algorithm the server cannot read is refused.
///
/// Both ends of the handshake read the same config, so a name nobody
/// supports does not fail on one side and the other: the deployment just
/// runs weaker than the operator wrote, and nothing says so.
#[test]
fn an_algorithm_the_server_cannot_read_is_refused() {
    let error = load_with_algorithm("sha-512").expect_err("nobody supports it");
    let message = error.to_string();
    assert!(message.contains("algorithm"), "{message}");
    assert!(message.contains("sha-512"), "{message}");
    assert!(message.contains("sha256"), "{message}");
}

/// The algorithm names that have always worked still work.
#[test]
fn the_algorithm_names_that_worked_still_work() {
    for (name, expected) in [
        ("sha1", crate::auth::TotpAlgorithm::SHA1),
        ("SHA1", crate::auth::TotpAlgorithm::SHA1),
        ("sha256", crate::auth::TotpAlgorithm::SHA256),
        ("SHA256", crate::auth::TotpAlgorithm::SHA256),
        ("sha512", crate::auth::TotpAlgorithm::SHA512),
        ("SHA512", crate::auth::TotpAlgorithm::SHA512),
    ] {
        let config = load_with_algorithm(name).expect("the algorithm is read");
        assert_eq!(config.algorithm, expected, "{name} is read as it was");
    }
}

/// A config with an algorithm the server cannot read does not load.
fn load_with_algorithm(algorithm: &str) -> anyhow::Result<crate::auth::AuthConfig> {
    let source = format!(
        "[auth]\nenabled = true\nalgorithm = \"{algorithm}\"\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXP\"\n"
    );
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, source).expect("the config is written");
    let (_, auth) = ProxyConfig::load_with_auth(path.to_str().expect("a path"))?;
    auth.ok_or_else(|| anyhow::anyhow!("the config has no [auth] section"))
}

#[test]
fn l4_route_modes_are_recognised() {
    assert_eq!(
        get_route_mode(&Some("tcp".to_string())).expect("tcp"),
        RouteMode::Tcp
    );
    assert_eq!(
        get_route_mode(&Some("UDP".to_string())).expect("UDP"),
        RouteMode::Udp
    );
    assert!(RouteMode::Tcp.is_l4());
    assert!(RouteMode::Udp.is_l4());
    assert!(!RouteMode::Http.is_l4());
    assert!(!RouteMode::Passthrough.is_l4());

    // The preface protocol is the only thing that picks between the two.
    assert_eq!(
        RouteMode::from_l4_proto(nexapipe_proto::L4Proto::Tcp),
        RouteMode::Tcp
    );
    assert_eq!(
        RouteMode::from_l4_proto(nexapipe_proto::L4Proto::Udp),
        RouteMode::Udp
    );
}

/// One route, several modes: the whole reason `modes` exists is that a host
/// which answers a request and a tunnel with the same backend used to need
/// two entries, and forgetting the second one failed at runtime instead of
/// at startup.
#[test]
fn one_route_may_serve_several_modes() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal:15666"]
"#,
    );

    let routes = config.build_routes().expect("the config is valid");
    assert_eq!(routes.len(), 1);
    assert_eq!(
        routes[0].modes(),
        &[RouteMode::Http, RouteMode::Tcp][..],
        "one entry, both modes, in the order they were written"
    );
    // `client_ports` and `path_pattern` are mode-specific knobs living on the
    // same entry; only the L4 lookups read the former.
    assert!(routes[0].matches_l4("fn.iroh.iakl.top", 80));
    assert!(routes[0].matches("fn.iroh.iakl.top", "/anything"));
}

/// `mode` and `modes` together are the union, and duplicates collapse.
#[test]
fn mode_and_modes_are_merged_and_deduplicated() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
mode = "http"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal:15666"]
"#,
    );

    let routes = config.build_routes().expect("the config is valid");
    assert_eq!(routes[0].modes(), &[RouteMode::Http, RouteMode::Tcp][..]);

    // An empty list means "no extra modes", not "no modes at all".
    let config = parse(
        r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = []
backends = ["http://host.docker.internal:15666"]
"#,
    );
    let routes = config.build_routes().expect("the config is valid");
    assert_eq!(routes[0].modes(), &[RouteMode::Http][..]);
}

/// The price of sharing one `backends` list: an address has to satisfy every
/// mode, and the L4 rules are the stricter ones.
#[test]
fn a_route_serving_tcp_needs_a_port_on_its_backend() {
    // `http://host` is a perfectly good HTTP backend — 80 is implied — but an
    // L4 route dials an address and has no port to fall back on.
    let valid = parse(
        r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
mode = "http"
backends = ["http://host.docker.internal"]
"#,
    );
    assert!(valid.build_routes().is_ok(), "http alone may omit the port");

    let merged = parse(
        r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal"]
"#,
    );
    let error = merged.build_routes().unwrap_err().to_string();
    assert!(
        error.contains("does not name a port"),
        "adding tcp has to be rejected at startup, got: {error}"
    );
}

#[test]
fn parses_a_tcp_route_with_its_l4_keys() {
    let config = parse(
        r#"

[[routes]]
host_pattern = "db.iroh.iakl.top"
mode = "tcp"
backends = ["10.0.0.50:5432"]
client_ports = [5432, 6432]
idle_timeout_secs = 120
"#,
    );

    let routes = config.routes.as_ref().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(
        get_route_mode(&routes[0].mode).expect("the mode"),
        RouteMode::Tcp
    );
    assert_eq!(routes[0].path_pattern, "/");
    assert_eq!(
        routes[0].client_ports.as_deref(),
        Some(&[5432u16, 6432][..])
    );
    assert_eq!(routes[0].idle_timeout_secs, Some(120));

    // A udp route without the optional keys still parses, with the defaults.
    let config = parse(
        r#"

[[routes]]
host_pattern = "turn.iroh.iakl.top"
mode = "udp"
backends = ["udp://10.0.0.60:3478"]
"#,
    );
    let routes = config.routes.as_ref().unwrap();
    assert_eq!(
        get_route_mode(&routes[0].mode).expect("the mode"),
        RouteMode::Udp
    );
    assert!(routes[0].client_ports.is_none());
    assert!(routes[0].idle_timeout_secs.is_none());
    assert!(validate_backend("route turn", RouteMode::Udp, &routes[0].backends[0]).is_ok());
}

#[test]
fn l4_backends_must_name_exactly_one_address() {
    // Both spellings are fine: the scheme is ignored, because an L4 route dials an
    // address rather than fetching a URL.
    for backend in [
        "10.0.0.50:5432",
        "tcp://10.0.0.50:5432",
        "udp://turn.internal:3478",
        "[::1]:5432",
    ] {
        assert!(
            validate_backend("route l4", RouteMode::Tcp, backend).is_ok(),
            "{backend} should be accepted"
        );
    }

    // No port: there is no correct default to fall back on.
    for backend in [
        "10.0.0.50",
        "db.internal",
        "http://10.0.0.50",
        "tcp://10.0.0.50",
        ":5432",
        "10.0.0.50:0",
        "10.0.0.50:notaport",
        "",
    ] {
        assert!(
            validate_backend("route l4", RouteMode::Tcp, backend).is_err(),
            "{backend} should be refused"
        );
    }

    // A path is meaningless: L4 copies bytes, it does not fetch anything.
    assert!(validate_backend("route l4", RouteMode::Tcp, "http://10.0.0.50:5432/x").is_err());
}

#[test]
fn parses_a_passthrough_route_without_a_path() {
    let config = parse(
        r#"

[[routes]]
host_pattern = "fn.iroh.iakl.top"
mode = "passthrough"
backends = ["caddy:443"]
"#,
    );

    let routes = config.routes.as_ref().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(
        get_route_mode(&routes[0].mode).expect("the mode"),
        RouteMode::Passthrough
    );
    // `path_pattern` is required by the struct but meaningless here, so it
    // defaults rather than having to be written out.
    assert_eq!(routes[0].path_pattern, "/");
    assert_eq!(routes[0].backends, vec!["caddy:443".to_string()]);
}

#[test]
fn accepts_a_config_written_for_the_old_tls_layout() {
    // These keys were removed when TLS moved to the backend. An existing
    // config.toml must still load — `warn_removed_tls_keys` is what tells
    // the operator — rather than failing to start.
    let config = parse(
        r#"

[server]
listen_addr = "0.0.0.0:8080"
tls_enabled = true
cert_path = "/certs/a.crt"
key_path = "/certs/a.key"

[[routes]]
host_pattern = "fn.iroh.iakl.top"
path_pattern = "/"
backends = ["https://backend.example.com"]
cert_path = "/certs/a.crt"
redirect_to_https = true

[acme]
enabled = true
domains = ["fn.iroh.iakl.top"]
"#,
    );

    assert!(config.acme.is_some());
    assert!(config.server.as_ref().unwrap().tls_enabled.unwrap_or(false));
    let route = &config.routes.as_ref().unwrap()[0];
    assert!(route.redirect_to_https.unwrap_or(false));
    assert!(route.cert_path.is_some());
    // Parsing it is not the same as honouring it: the backend is fetched
    // over a TLS session this process originates, and the certificate it
    // presents is checked against the machine's trust store.
    assert!(validate_backend("route fn", RouteMode::Http, &route.backends[0]).is_ok());
}

#[test]
fn http_backends_must_name_a_scheme_that_can_be_fetched() {
    assert!(validate_backend("route a", RouteMode::Http, "http://10.0.0.5:8080").is_ok());
    // An `https://` backend is fetched over a TLS session this process
    // originates: it verifies the certificate, it does not hold one.
    assert!(validate_backend("route a", RouteMode::Http, "https://example.com").is_ok());
    assert!(validate_backend("route a", RouteMode::Http, "10.0.0.5:8080").is_err());
    assert!(validate_backend("route a", RouteMode::Http, "ftp://example.com").is_err());

    // Passthrough never interprets the bytes, so the scheme is not its
    // business — a TLS target is conventionally written either way.
    assert!(validate_backend("route b", RouteMode::Passthrough, "caddy:443").is_ok());
    assert!(validate_backend("route b", RouteMode::Passthrough, "https://caddy:443").is_ok());
}

/// A config file in a scratch directory, for the functions that write.
fn scratch_config(source: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("scratch dir");
    let path = dir.path().join("config.toml");
    fs::write(&path, source).expect("write scratch config");
    (dir, path.to_string_lossy().into_owned())
}

/// A client with a secret of its own and a token outstanding, which is the
/// state an enrollment invitation leaves behind.
fn scratch_client_with_token() -> (tempfile::TempDir, String) {
    scratch_config(
        r#"
[auth]
enabled = true

[auth.clients.alice]
secret = "CLIENTSECRET"
pending_enrollment = "TOKEN"
"#,
    )
}

/// Enrolling a device writes that device's own entry and leaves the
/// client's `secret` alone: the two are different credentials, and
/// rotating the shared one is what re-enrolls every device at once.
///
/// Read back through the loader rather than by looking at the text, because
/// what matters is not where the entry lands in the file but that a restart
/// sees the device and verifies it against its own secret.
#[test]
fn enrolling_a_device_writes_its_entry_and_leaves_the_clients_secret() {
    let (_dir, path) = scratch_client_with_token();

    ProxyConfig::complete_device_enrollment(
        &path,
        "alice",
        "laptop",
        DeviceMaterial::Secret("LAPTOPSECRET"),
    )
    .expect("the device enrollment is saved");

    let on_disk = fs::read_to_string(&path).expect("read the config back");
    assert!(
        !on_disk.contains("pending_enrollment"),
        "the token was left spendable: {on_disk}"
    );

    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config still loads");
    let auth = auth.expect("auth is enabled");
    let alice = &auth.clients["alice"];
    assert_eq!(
        alice.secret.as_str(),
        "CLIENTSECRET",
        "the shared secret rotated"
    );
    assert_eq!(alice.devices["laptop"].secret.as_str(), "LAPTOPSECRET");
    assert!(
        !alice.devices["laptop"].created_at.is_empty(),
        "a device with no issued-at looks never issued"
    );
}

/// Revoking a device strikes one entry out of `devices` and leaves the
/// client's own `secret` standing, so while that secret is still a
/// credential, a peer that simply omits the device name goes on
/// authenticating with it. `unnamed_device_allowed = false` is what takes
/// it away, and it has to survive the loader — a flag the file carries but
/// the server ignores would be worse than none at all.
#[test]
fn a_client_can_stop_answering_devices_that_name_themselves_not_at_all() {
    let source = |flag: Option<&str>| {
        format!(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.alice]\n\
             secret = \"CLIENTSECRET\"\n\
             {}\
             \n\
             [auth.clients.alice.devices.laptop]\n\
             secret = \"LAPTOPSECRET\"\n",
            flag.unwrap_or_default()
        )
    };

    let (_dir, path) = scratch_config(&source(None));
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config parses");
    assert!(
        auth.expect("auth is enabled").clients["alice"].unnamed_device_allowed,
        "the default has to stay permissive: every client issued before 0.6.0 has no \
         device table, and the shared secret is its only credential"
    );

    let (_dir, path) = scratch_config(&source(Some("unnamed_device_allowed = false\n")));
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config parses");
    assert!(
        !auth.expect("auth is enabled").clients["alice"].unnamed_device_allowed,
        "a flag the operator set must reach the running server"
    );
}

/// A second device enrolling alongside the first leaves the first one's
/// credential where it is — which is the whole of what the table is for.
#[test]
fn a_second_device_enrolling_leaves_the_first_one_alone() {
    let (_dir, path) = scratch_client_with_token();

    ProxyConfig::complete_device_enrollment(
        &path,
        "alice",
        "laptop",
        DeviceMaterial::Secret("LAPTOPSECRET"),
    )
    .expect("the first device enrolls");
    ProxyConfig::complete_device_enrollment(
        &path,
        "alice",
        "phone",
        DeviceMaterial::Secret("PHONESECRET"),
    )
    .expect("the second device enrolls");

    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config still loads");
    let auth = auth.expect("auth is enabled");
    let devices = &auth.clients["alice"].devices;
    // The count, not the map: the map carries each device's secret, and a
    // failing assertion would render it into the CI log.
    assert_eq!(devices.len(), 2, "both devices are enrolled");
    assert_eq!(devices["laptop"].secret.as_str(), "LAPTOPSECRET");
    assert_eq!(devices["phone"].secret.as_str(), "PHONESECRET");
}

/// Neither writer may hand a device an empty secret.
///
/// The loader refuses one, so writing it is not "a device that cannot
/// authenticate" but "a config that no longer loads at all" — and both
/// writers would have reported success while doing it. Neither may touch
/// the file first: the token has to stay spendable for a real enrollment.
#[test]
fn an_empty_device_secret_is_refused_by_both_writers() {
    let (_dir, path) = scratch_client_with_token();
    let before = fs::read_to_string(&path).expect("read the config first");

    let enrollment = ProxyConfig::complete_device_enrollment(
        &path,
        "alice",
        "laptop",
        DeviceMaterial::Secret(""),
    )
    .expect_err("an empty secret is not a credential, it is a config that cannot be read again");
    assert!(enrollment.to_string().contains("empty"), "{enrollment:#}");

    let operator = ProxyConfig::write_device_credential(
        &path,
        "alice",
        "laptop",
        DeviceMaterial::Secret(""),
        true,
    )
    .expect_err("the same for the operator CLI");
    assert!(operator.to_string().contains("empty"), "{operator:#}");

    assert_eq!(
        fs::read_to_string(&path).expect("read the config back"),
        before,
        "a refused write still changed the file"
    );
    assert!(
        ProxyConfig::load_with_auth(&path).is_ok(),
        "the config was left in a state that cannot be loaded"
    );
}

/// Two writers that both read before either writes lose one of the two
/// edits: the second one's document is built from contents the first one has
/// already replaced. The lock is what sequences them — and it has to be a
/// lock *on the file*, because a process-wide mutex would serialize these
/// two threads while doing nothing for the CLI and the server, which are
/// different processes.
#[test]
fn a_second_writer_sees_the_first_one_s_edit() {
    let (_dir, path) = scratch_config("counter = 0\n");

    let first = {
        let path = path.clone();
        std::thread::spawn(move || {
            with_config_lock(&path, || {
                // Reads, then sits on the lock long enough that an unlocked
                // second writer would have read the old value too.
                let content = fs::read_to_string(&path)?;
                assert_eq!(content.trim(), "counter = 0");
                std::thread::sleep(std::time::Duration::from_millis(150));
                write_config_file(&path, "counter = 1\n")
            })
            .expect("the first writer succeeds")
        })
    };

    // Let the first one take the lock before the second asks for it.
    std::thread::sleep(std::time::Duration::from_millis(25));

    let seen = with_config_lock(&path, || {
        let content = fs::read_to_string(&path)?;
        write_config_file(&path, "counter = 2\n")?;
        Ok(content)
    })
    .expect("the second writer succeeds");

    first.join().expect("the first writer ends");

    assert!(
        seen.contains("counter = 1"),
        "the second writer must read the first one's edit, got {seen:?}"
    );
    assert_eq!(
        fs::read_to_string(&path)
            .expect("the config is still there")
            .trim(),
        "counter = 2"
    );
}

/// A config of TOTP secrets must not be readable by another account, and
/// not only once the write has finished: `write_config_file` used to create
/// the replacement under the umask and chmod it to 0600 *after* flushing the
/// secrets to disk, so a local user reading it in that window got every
/// TOTP seed in the file. The mode now goes into the call that creates it.
#[cfg(unix)]
#[test]
fn a_written_config_is_private_to_its_owner() {
    let (_dir, path) = scratch_config("counter = 0\n");
    write_config_file(&path, "counter = 1\n").expect("the write succeeds");

    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&path)
        .expect("the config is there")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "a config holding TOTP secrets must be private, got {mode:o}"
    );
}

/// A config reached through a symlink is a normal way to keep one file in
/// version control or out of a container image. Renaming a temp file over
/// the link replaces the link with a regular file: the indirection is gone
/// and the file it pointed at keeps the old contents, while every command
/// involved still reports success.
#[cfg(unix)]
#[test]
fn a_config_reached_through_a_symlink_is_the_one_that_changes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let real = dir.path().join("real.toml");
    let link = dir.path().join("config.toml");
    fs::write(&real, "counter = 0\n").expect("write the real file");
    std::os::unix::fs::symlink(&real, &link).expect("create the link");

    let path = link.to_str().expect("utf-8 path").to_string();
    write_config_file(&path, "counter = 1\n").expect("the write succeeds");

    assert!(
        fs::symlink_metadata(&link)
            .expect("the path is still there")
            .file_type()
            .is_symlink(),
        "the link must survive the write"
    );
    assert_eq!(
        fs::read_to_string(&real)
            .expect("read the real file")
            .trim(),
        "counter = 1",
        "the edit has to land in the file the link points at"
    );
}

/// The client the server would see after a write, read back through the
/// very loader `--generate-2fa` and the server share.
fn secret_of(path: &str, client_id: &str) -> Option<String> {
    let (_, auth) = ProxyConfig::load_with_auth(path).expect("config still parses");
    auth.and_then(|auth| {
        auth.clients
            .get(client_id)
            .map(|c| c.secret.expose_secret().to_string())
    })
}

#[test]
fn client_secret_is_appended_without_rewriting_the_file() {
    // `--generate-2fa` edits a file a human wrote, so the comment, the key
    // order and the layout of everything outside `[auth]` have to survive.
    let (_dir, path) = scratch_config(
        "# my proxy\n\
         default_backend = \"http://127.0.0.1:15666\"\n\
         \n\
         [[routes]]\n\
         host_pattern = \"a.example\"\n\
         backends = [\"http://127.0.0.1:8080\"]\n",
    );

    let outcome = ProxyConfig::write_client_secret(&path, "client-001", "JBSWY3DPEHPK3PXP", false)
        .expect("secret should be written");
    assert_eq!(outcome, ClientSecretWrite::Added);

    let written = fs::read_to_string(&path).expect("read back");
    assert!(written.starts_with("# my proxy\n"));
    assert!(written.contains("default_backend = \"http://127.0.0.1:15666\""));
    assert!(written.contains("[[routes]]"));
    assert!(written.contains("[auth.clients.client-001]"));
    assert_eq!(
        secret_of(&path, "client-001").as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
}

#[test]
fn client_secret_joins_an_existing_auth_section() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.other]\n\
         secret = \"AAAAAAAAAAAAAAAA\"\n",
    );

    let outcome = ProxyConfig::write_client_secret(&path, "client-002", "JBSWY3DPEHPK3PXP", false)
        .expect("secret should be written");
    assert_eq!(outcome, ClientSecretWrite::Added);

    let written = fs::read_to_string(&path).expect("read back");
    assert!(written.contains("[auth.clients.other]"));
    assert_eq!(
        secret_of(&path, "other").as_deref(),
        Some("AAAAAAAAAAAAAAAA"),
        "the neighbouring client must not be touched"
    );
    assert_eq!(
        secret_of(&path, "client-002").as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
    // 2FA was already on and stays on; enabling it is the operator's call.
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config parses");
    assert!(auth.expect("[auth] exists").enabled);
}

#[test]
fn client_secret_needs_force_to_replace_one() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"OLDOLDOLDOLDOLD\"\n",
    );

    let err = ProxyConfig::write_client_secret(&path, "client-001", "JBSWY3DPEHPK3PXP", false)
        .expect_err("an enrolled client must not lose its secret by accident");
    assert!(err.to_string().contains("already has a secret"));
    assert_eq!(
        secret_of(&path, "client-001").as_deref(),
        Some("OLDOLDOLDOLDOLD")
    );

    let outcome = ProxyConfig::write_client_secret(&path, "client-001", "JBSWY3DPEHPK3PXP", true)
        .expect("force replaces it");
    assert_eq!(outcome, ClientSecretWrite::Replaced);
    assert_eq!(
        secret_of(&path, "client-001").as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
}

#[test]
fn client_ids_that_are_not_bare_keys_are_quoted() {
    // `[auth.clients.client.001]` would nest three tables; the id has to be
    // quoted so it stays one key.
    let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");

    ProxyConfig::write_client_secret(&path, "client.001", "JBSWY3DPEHPK3PXP", false)
        .expect("secret should be written");

    let written = fs::read_to_string(&path).expect("read back");
    assert!(
        written.contains("[auth.clients.\"client.001\"]"),
        "{written}"
    );
    assert_eq!(
        secret_of(&path, "client.001").as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
}

/// The endpoint key and the relay token are credentials whether or not
/// `[auth]` is on; this is what marks an inline value as a credential that
/// belongs in a sidecar file or the environment rather than the config.
#[test]
fn a_key_or_a_relay_token_makes_the_config_hold_credentials() {
    assert!(parse("[iroh]\nsecret_key = \"00\"\n").holds_credentials());
    assert!(parse("[iroh]\nrelay_auth_token = \"t\"\n").holds_credentials());
    assert!(!parse("").holds_credentials());
}

/// Restricts a credential file the test creates to the owner, the way a
/// real deployment has to for the load to succeed — a `fs::write` file is
/// 0644 under the default umask, and `read_credential_file` rightly refuses
/// that on Unix. Outside Unix there are no modes to set.
#[cfg(unix)]
fn chmod_owner_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 600");
}

#[cfg(not(unix))]
fn chmod_owner_only(_path: &std::path::Path) {}

/// A key in a pointed-to file reaches the config resolved, and — the point
/// of the pointer — does not make the config a credential holder.
#[test]
fn a_key_file_resolves_and_leaves_the_config_credential_free() {
    let dir = tempfile::tempdir().expect("temp dir");
    let key = generate_secret_key_hex();
    let key_path = dir.path().join("iroh.key");
    fs::write(&key_path, &key).expect("write the key file");
    chmod_owner_only(&key_path);
    let path = dir.path().join("config.toml");
    fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n").expect("write the config");

    let (config, _) = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect("a config whose key lives in a file loads");

    let iroh = config.iroh.as_ref().expect("the [iroh] section parsed");
    assert_eq!(
        iroh.secret_key
            .as_ref()
            .map(|key| key.expose_secret().as_str()),
        Some(key.as_str()),
        "the key from the file is what the config runs on"
    );
    assert_eq!(iroh.secret_key_source, CredentialSource::File);
    assert!(
        !config.holds_credentials(),
        "the config holds a pointer, not a key, so the permission gate keeps warning \
         instead of refusing"
    );
}

/// A config naming the key twice refuses to load rather than ranking the
/// candidates: which source wins must not turn on precedence rules the
/// operator has to look up.
#[test]
fn naming_the_key_twice_refuses_to_load() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("iroh.key"), generate_secret_key_hex()).expect("write the key file");
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        format!(
            "[iroh]\nsecret_key = \"{}\"\nsecret_key_file = \"iroh.key\"\n",
            generate_secret_key_hex()
        ),
    )
    .expect("write the config");

    let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect_err("two answers to one question are refused");
    assert!(err.to_string().contains("named by"), "{err}");
    assert!(err.to_string().contains("secret_key_file"), "{err}");
}

/// The environment outranks nothing when the config also names the key:
/// refused, not silently adjudicated.
///
/// Driven through `resolve_secret_key_source`'s parameter rather than the
/// process environment — `set_var` is `unsafe` in Rust 2024, and the
/// end-to-end env coverage lives in `tests/first_run_identity.rs`, where a
/// child process takes the variable.
#[test]
fn an_env_key_alongside_an_inline_one_is_refused() {
    // IrohConfig *is* the [iroh] table, so its TOML carries the fields
    // without the header — a header here would be an unknown field the
    // parser silently drops.
    let iroh: IrohConfig = toml::from_str("secret_key = \"00\"\n").expect("parse");

    let err = resolve_secret_key_source(None, Some("env-key".to_string()), None, &iroh)
        .expect_err("a credential named twice is refused");
    assert!(
        err.to_string().contains(IROH_SECRET_KEY_ENV),
        "the refusal names both sources: {err}"
    );
}

/// An environment credential resolves with the env source, and the value
/// is trimmed: a trailing newline from `printf` must not become key bytes.
#[test]
fn an_env_key_resolves_as_env() {
    let iroh: IrohConfig = toml::from_str("").expect("parse");

    let (key, source) = resolve_secret_key_source(None, Some("  abc  ".to_string()), None, &iroh)
        .expect("one source resolves")
        .expect("the environment names a key");
    assert_eq!(key.expose_secret(), "abc");
    assert_eq!(source, CredentialSource::Env);
}

/// An empty environment variable is "not named", not an empty key — the
/// same reading `NEXAPIPE_NO_PERSIST_IDENTITY` gets — so the literal the
/// config carries stays the one answer.
#[test]
fn an_empty_env_value_names_nothing() {
    let iroh: IrohConfig = toml::from_str("secret_key = \"00\"\n").expect("parse");

    let (key, source) = resolve_secret_key_source(None, Some("   ".to_string()), None, &iroh)
        .expect("a blank env value is not a source")
        .expect("the inline literal is the only source left");
    assert_eq!(key.expose_secret(), "00");
    assert_eq!(source, CredentialSource::Inline);
}

/// An environment-named file path is a file source, taken literally even
/// when it is not next to the config.
#[test]
fn an_env_named_key_file_resolves_as_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let key_path = dir.path().join("elsewhere").join("iroh.key");
    fs::create_dir_all(key_path.parent().expect("parent")).expect("mkdir");
    let key = generate_secret_key_hex();
    fs::write(&key_path, &key).expect("write the key file");
    chmod_owner_only(&key_path);
    let iroh: IrohConfig = toml::from_str("").expect("parse");

    let (resolved, source) =
        resolve_secret_key_source(Some(dir.path()), None, Some(&key_path), &iroh)
            .expect("the env-named file resolves")
            .expect("it names a key");
    assert_eq!(resolved.expose_secret(), key.as_str());
    assert_eq!(source, CredentialSource::File);
}

/// The two environment variables naming the same key two ways are refused,
/// not ranked.
#[test]
fn an_env_value_and_an_env_file_refuse() {
    let dir = tempfile::tempdir().expect("temp dir");
    let key_path = dir.path().join("iroh.key");
    fs::write(&key_path, generate_secret_key_hex()).expect("write the key file");
    chmod_owner_only(&key_path);
    let iroh: IrohConfig = toml::from_str("").expect("parse");

    let err = resolve_secret_key_source(None, Some("env-key".to_string()), Some(&key_path), &iroh)
        .expect_err("two environment answers are refused");
    let text = err.to_string();
    assert!(text.contains(IROH_SECRET_KEY_ENV), "{text}");
    assert!(text.contains(IROH_SECRET_KEY_FILE_ENV), "{text}");
}

/// The environment file outranks nothing when the config also points at a
/// file: refused, same one-source rule.
#[test]
fn an_env_file_and_a_config_pointer_refuse() {
    let dir = tempfile::tempdir().expect("temp dir");
    let env_path = dir.path().join("env.key");
    fs::write(&env_path, generate_secret_key_hex()).expect("write env key");
    chmod_owner_only(&env_path);
    let cfg_path = dir.path().join("cfg.key");
    fs::write(&cfg_path, generate_secret_key_hex()).expect("write config key");
    chmod_owner_only(&cfg_path);
    let iroh: IrohConfig = toml::from_str("secret_key_file = \"cfg.key\"\n").expect("parse");

    let err = resolve_secret_key_source(Some(dir.path()), None, Some(&env_path), &iroh)
        .expect_err("a pointer in the env and one in the config are refused");
    assert!(err.to_string().contains("secret_key_file"), "{err}");
}

/// An environment-named file that does not exist yet defers to first-start
/// generation rather than failing — the caller folds the path onto the
/// pointer field so the key is generated where the env says.
#[test]
fn a_missing_env_named_file_defers_to_generation() {
    let dir = tempfile::tempdir().expect("temp dir");
    let key_path = dir.path().join("secrets").join("iroh.key");
    let iroh: IrohConfig = toml::from_str("").expect("parse");

    let resolved = resolve_secret_key_source(None, None, Some(&key_path), &iroh)
        .expect("a missing pointed-to file is not an error");
    assert!(resolved.is_none(), "nothing is resolved until generation");
}

/// A relay token file resolves like a key file, trimmed.
#[test]
fn a_relay_token_file_resolves() {
    let dir = tempfile::tempdir().expect("temp dir");
    let token_path = dir.path().join("relay.token");
    fs::write(&token_path, "  bearer-token  \n").expect("write the token file");
    chmod_owner_only(&token_path);
    let path = dir.path().join("config.toml");
    fs::write(&path, "[iroh]\nrelay_auth_token_file = \"relay.token\"\n")
        .expect("write the config");

    let (config, _) = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect("a config whose token lives in a file loads");

    let iroh = config.iroh.as_ref().expect("the [iroh] section parsed");
    assert_eq!(
        iroh.relay_auth_token
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("bearer-token")
    );
    assert_eq!(iroh.relay_auth_token_source, CredentialSource::File);
    assert!(!config.holds_credentials());
}

/// A token file that does not exist is refused rather than deferred: the
/// server cannot invent a relay token, and a missing one must not surface
/// later as a vaguer relay-configuration error.
#[test]
fn a_missing_relay_token_file_refuses_to_load() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    fs::write(&path, "[iroh]\nrelay_auth_token_file = \"relay.token\"\n")
        .expect("write the config");

    let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect_err("a token cannot be generated into a missing file");
    assert!(err.to_string().contains("does not exist"), "{err}");
}

/// A key file that holds nothing is a typo to see, not a mode: the pointer
/// was spelled, so a blank file refuses the load.
#[test]
fn an_empty_key_file_refuses_to_load() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("iroh.key"), "  \n").expect("write a blank key file");
    let path = dir.path().join("config.toml");
    fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n").expect("write the config");

    let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect_err("a blank credential file is refused");
    assert!(err.to_string().contains("holds nothing"), "{err}");
}

/// A first start with a `secret_key_file` writes the key into that file —
/// never back into the config — and a reload resolves from the file
/// without turning the config into a credential holder.
#[test]
fn a_missing_key_file_is_generated_into() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n").expect("write the config");

    let config =
        ProxyConfig::from_file(path.to_str().expect("utf-8 path")).expect("the config loads");
    let identity = ProxyConfig::ensure_iroh_secret_key(path.to_str().expect("utf-8 path"), &config)
        .expect("the identity resolves");
    // Compare instead of formatting: the identity is the endpoint's private
    // key, and it does not belong in a message that CI keeps — even though
    // `EndpointIdentity`'s `Debug` redacts it.
    assert!(
        matches!(identity, EndpointIdentity::Generated(_)),
        "a first start generates into the pointed-to file"
    );

    // Compare and measure without formatting the key: a failing
    // assert_eq! would render both values, putting the private key in the
    // CI log the same way EndpointIdentity's Debug refuses to.
    let file_key =
        fs::read_to_string(dir.path().join("iroh.key")).expect("the key file was written");
    let file_key = file_key.trim();
    assert_eq!(
        file_key.len(),
        64,
        "the file holds a full ed25519 key (64 hex chars)"
    );
    assert!(
        identity.key() == file_key,
        "the running identity is the key in the file"
    );

    let content = fs::read_to_string(&path).expect("read the config back");
    assert!(
        !content.contains("secret_key ="),
        "the key must not be written back into the config: that would undo the whole \
         point of the pointer"
    );

    let (reloaded, _) = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect("the config reloads from the key file");
    assert_eq!(
        reloaded.iroh.as_ref().expect("[iroh]").secret_key_source,
        CredentialSource::File,
        "the reload resolves from the file the first start wrote"
    );
    assert!(!reloaded.holds_credentials());
}

/// A key file another account can read is the credential in the open: the
/// same refusal the config gets for holding one inline.
#[cfg(unix)]
#[test]
fn a_world_readable_key_file_refuses_to_load() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let key_path = dir.path().join("iroh.key");
    fs::write(&key_path, generate_secret_key_hex()).expect("write the key file");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("chmod 644");
    let path = dir.path().join("config.toml");
    fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n").expect("write the config");

    let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect_err("a world-readable credential file is refused");
    assert!(err.to_string().contains("chmod 600"), "{err}");
}

/// A key file that appears between the load and the generation — the lost
/// race `write_key_file` reads back — is held to the same 0600 rule as a
/// file a normal load points at: a nonempty 0644 winner is refused rather
/// than adopted.
#[cfg(unix)]
#[test]
fn a_world_readable_race_winner_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let key_path = dir.path().join("iroh.key");
    fs::write(&key_path, generate_secret_key_hex())
        .expect("a sibling process drops a nonempty 0644 key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let err = write_key_file(&key_path)
        .expect_err("the lost-race read-back applies the same permission refusal");
    assert!(err.to_string().contains("chmod 600"), "{err}");
}

/// A credential sidecar file is private or refused; there is no
/// "credentials not live yet" half-way case for these.
#[cfg(unix)]
#[test]
fn a_credential_file_is_private_or_refused() {
    use std::os::unix::fs::PermissionsExt;
    let set_mode = |path: &str, mode: u32| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    };

    let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");

    set_mode(&path, 0o600);
    check_credential_file_permissions(&path).expect("0600 is accepted");

    set_mode(&path, 0o644);
    let err =
        check_credential_file_permissions(&path).expect_err("0644 is fatal for a credential file");
    assert!(err.to_string().contains("chmod 600"), "{err}");
}

/// A file the caller could not even stat has already failed to be read; the
/// permission check is not the place to report that.
#[cfg(unix)]
#[test]
fn credential_file_check_passes_a_file_it_cannot_stat() {
    check_credential_file_permissions("/nonexistent/iroh.key")
        .expect("a missing file is reported by the loader, not here");
}

/// An enrollment is two writes to the same file: a token that an invitation
/// carries, and the secret that replaces it when the token is spent. Both
/// have to survive a reload, because the server that writes the token is
/// usually a different process from the one that spends it.
#[test]
fn an_enrollment_token_is_recorded_then_spent() {
    let (_dir, path) = scratch_config(
        "# my proxy\n\
         default_backend = \"http://127.0.0.1:15666\"\n\
         \n\
         [auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    );

    ProxyConfig::write_pending_enrollment(&path, "client-001", "deadbeef")
        .expect("token should be written");
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config still parses");
    let auth = auth.expect("auth section");
    assert_eq!(
        auth.clients["client-001"]
            .pending_enrollment
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("deadbeef")
    );
    assert_eq!(
        auth.clients["client-001"].secret.as_str(),
        "JBSWY3DPEHPK3PXP"
    );

    // Issuing a second token replaces the first: that is how a link that
    // never arrived gets revoked.
    ProxyConfig::write_pending_enrollment(&path, "client-001", "cafebabe")
        .expect("token should be replaced");
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config still parses");
    assert_eq!(
        auth.unwrap().clients["client-001"]
            .pending_enrollment
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("cafebabe")
    );

    ProxyConfig::complete_enrollment(&path, "client-001", "NEWSECRETVALUE")
        .expect("enrollment should be saved");
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config still parses");
    let client = &auth.unwrap().clients["client-001"];
    assert_eq!(client.secret.as_str(), "NEWSECRETVALUE");
    // The token has to go with it, or the same link enrolls a second device.
    assert_eq!(client.pending_enrollment, None);
}

/// A blank enrollment token is refused instead of read as "no enrollment
/// outstanding".
///
/// `constant_time_eq` calls two empty slices equal, so a config carrying
/// `pending_enrollment = ""` would accept any stranger's empty ENROLL_START
/// and hand them a freshly generated secret, locking out every device that
/// was using the client id. Blanking the key is the natural way to "clear"
/// it, so it has to fail loudly rather than quietly mean "closed".
#[test]
fn a_blank_enrollment_token_is_refused() {
    let (_dir, path) = scratch_config(
        "default_backend = \"http://127.0.0.1:15666\"\n\
         \n\
         [auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         pending_enrollment = \"\"\n",
    );

    let err = ProxyConfig::load_with_auth(&path).expect_err("a blank token must not load");
    assert!(err.to_string().contains("pending_enrollment"), "{err}");
}

/// The endpoint credentials have to stay out of `Debug`, because the whole
/// config is logged at debug level whenever it is parsed — including on
/// every hot reload, where the logger is already installed.
#[test]
fn a_parsed_iroh_config_prints_no_credentials() {
    let iroh = IrohConfig {
        relay_url: Some("https://relay.example".to_string()),
        relay_mode: Some("custom".to_string()),
        relay_auth_token: Some(SecretString::new("bearer-secret".to_string())),
        discovery: Some("none".to_string()),
        bind_port: Some(1234),
        bind_ipv6: Some(true),
        secret_key: Some(SecretString::new("ed25519-private-key".to_string())),
        secret_key_file: Some("iroh.key".to_string()),
        secret_key_source: CredentialSource::Inline,
        relay_auth_token_file: Some("relay.token".to_string()),
        relay_auth_token_source: CredentialSource::Inline,
    };

    let rendered = format!("{iroh:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains("bearer-secret"), "{rendered}");
    assert!(!rendered.contains("ed25519-private-key"), "{rendered}");
    // Whether a key is configured is still worth knowing.
    assert!(rendered.contains("relay_mode"), "{rendered}");
}

/// A token for a client that does not exist would leave a section with no
/// secret behind, which stops the config loading at all.
#[test]
fn an_enrollment_token_needs_a_client() {
    let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");
    let err = ProxyConfig::write_pending_enrollment(&path, "ghost", "deadbeef")
        .expect_err("a missing client must not be silently created");
    assert!(err.to_string().contains("ghost"), "{err}");
}

/// The devices of a client, as the server would read them back.
fn devices_of(path: &str, client_id: &str) -> HashMap<String, crate::auth::DeviceAuth> {
    let (_, auth) = ProxyConfig::load_with_auth(path).expect("config still parses");
    auth.and_then(|auth| auth.clients.get(client_id).map(|c| c.devices.clone()))
        .unwrap_or_default()
}

/// A device credential goes under the client's own `devices` table, and the
/// client's `secret` — the credential of the device that names none — stays
/// exactly as it was.
#[test]
fn a_device_secret_lands_under_the_clients_devices_table() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.acme]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    );

    let outcome = ProxyConfig::write_device_credential(
        &path,
        "acme",
        "laptop",
        DeviceMaterial::Secret("MFRGGZDFMZTWQ2LK"),
        false,
    )
    .expect("the device secret should be written");
    assert_eq!(outcome, ClientSecretWrite::Added);

    let written = fs::read_to_string(&path).expect("read back");
    assert!(
        written.contains("[auth.clients.acme.devices]"),
        "the devices table has to say what it holds: {written}"
    );
    assert_eq!(
        secret_of(&path, "acme").as_deref(),
        Some("JBSWY3DPEHPK3PXP"),
        "the unnamed device keeps the credential it had"
    );
    let devices = devices_of(&path, "acme");
    assert_eq!(
        devices.get("laptop").map(|d| d.secret.as_str()),
        Some("MFRGGZDFMZTWQ2LK")
    );
}

/// Issuing a device a second secret would lock the one already using it out,
/// so it takes `--force` — the same refusal replacing a client's secret does.
#[test]
fn a_device_secret_needs_force_to_replace_one() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.acme]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         \n\
         [auth.clients.acme.devices.laptop]\n\
         secret = \"OLDOLDOLDOLDOLD\"\n",
    );

    let err = ProxyConfig::write_device_credential(
        &path,
        "acme",
        "laptop",
        DeviceMaterial::Secret("NEWNEWNEWNEWNEW"),
        false,
    )
    .expect_err("a device must not lose its credential by accident");
    assert!(
        err.to_string().contains("already has a credential"),
        "{err}"
    );
    assert_eq!(
        devices_of(&path, "acme")
            .get("laptop")
            .map(|d| d.secret.as_str()),
        Some("OLDOLDOLDOLDOLD")
    );

    let outcome = ProxyConfig::write_device_credential(
        &path,
        "acme",
        "laptop",
        DeviceMaterial::Secret("NEWNEWNEWNEWNEW"),
        true,
    )
    .expect("with force the secret is replaced");
    assert_eq!(outcome, ClientSecretWrite::Replaced);
    assert_eq!(
        devices_of(&path, "acme")
            .get("laptop")
            .map(|d| d.secret.as_str()),
        Some("NEWNEWNEWNEWNEW")
    );
}

/// A device under a client with no secret of its own is a config that cannot
/// be loaded, so the write is refused rather than creating one.
#[test]
fn a_device_secret_needs_a_client_with_a_secret() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.other]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    );

    let err = ProxyConfig::write_device_credential(
        &path,
        "ghost",
        "laptop",
        DeviceMaterial::Secret("MFRGGZDFMZTWQ2LK"),
        false,
    )
    .expect_err("a device of a client that is not there must not be created");
    assert!(err.to_string().contains("ghost"), "{err}");
    assert!(
        devices_of(&path, "ghost").is_empty(),
        "nothing was written for it"
    );
}

/// The name becomes a key here and the subject of every log line about the
/// device, so one that is not printable ASCII is refused rather than read as
/// "no name".
#[test]
fn an_unprintable_device_name_is_refused() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.acme]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    );

    for name in ["", "lap top", "laptop\nsecret = \"x\""] {
        let err = ProxyConfig::write_device_credential(
            &path,
            "acme",
            name,
            DeviceMaterial::Secret("MFRGGZDFMZTWQ2LK"),
            false,
        )
        .expect_err("an unusable device name must not be written");
        assert!(err.to_string().contains("printable ASCII"), "{err}");
    }
    assert!(devices_of(&path, "acme").is_empty());
}

/// The other half of the writer: a key an operator registers lands under
/// the same table as a secret, spelled canonically — lowercase hex, so the
/// file says one thing however the key was pasted — and reads back as a
/// key device.
#[test]
fn a_device_key_lands_under_the_clients_devices_table() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.acme]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    );
    let key = crate::auth::public_key_hex(&iroh::SecretKey::generate().public());

    let outcome = ProxyConfig::write_device_credential(
        &path,
        "acme",
        "server",
        DeviceMaterial::PublicKey(&key.to_uppercase()),
        false,
    )
    .expect("the device key should be written");
    assert_eq!(outcome, ClientSecretWrite::Added);

    let written = fs::read_to_string(&path).expect("read back");
    assert!(
        written.contains(&format!("public_key = \"{key}\"")),
        "the key is spelled canonically whatever case it arrived in: {written}"
    );
    let devices = devices_of(&path, "acme");
    let server = &devices["server"];
    assert_eq!(server.public_key.as_deref(), Some(key.as_str()));
    assert!(server.secret.expose_secret().is_empty(), "{server:?}");
    assert_eq!(
        secret_of(&path, "acme").as_deref(),
        Some("JBSWY3DPEHPK3PXP"),
        "the unnamed device keeps the credential it had"
    );
}

/// A key that is not a key is refused before the file is touched, the same
/// way an empty secret is: what the writer must never do is report success
/// while leaving a config the loader will refuse on the next start.
#[test]
fn a_public_key_that_is_not_a_key_is_refused_by_the_writer() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.acme]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    );
    let before = fs::read_to_string(&path).expect("read the config first");

    let err = ProxyConfig::write_device_credential(
        &path,
        "acme",
        "server",
        DeviceMaterial::PublicKey("not a key"),
        false,
    )
    .expect_err("a value that is not a key must not be written");
    assert!(err.to_string().contains("not hex"), "{err}");

    assert_eq!(
        fs::read_to_string(&path).expect("read the config back"),
        before,
        "a refused write still changed the file"
    );
    assert!(
        ProxyConfig::load_with_auth(&path).is_ok(),
        "the config was left in a state that cannot be loaded"
    );
}

/// Switching a device from one credential to the other is a replace like
/// any other: it takes `--force`, because a device answering with a code
/// stops the moment its entry says key. The secret is gone rather than
/// kept beside the key — one credential, which is the shape the loader
/// insists on.
#[test]
fn a_key_replaces_a_secret_only_with_force() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.acme]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         \n\
         [auth.clients.acme.devices.server]\n\
         secret = \"OLDOLDOLDOLDOLD\"\n",
    );
    let key = crate::auth::public_key_hex(&iroh::SecretKey::generate().public());

    let err = ProxyConfig::write_device_credential(
        &path,
        "acme",
        "server",
        DeviceMaterial::PublicKey(&key),
        false,
    )
    .expect_err("a device must not lose its credential by accident");
    assert!(
        err.to_string().contains("already has a credential"),
        "{err}"
    );

    let outcome = ProxyConfig::write_device_credential(
        &path,
        "acme",
        "server",
        DeviceMaterial::PublicKey(&key),
        true,
    )
    .expect("with force the key is written");
    assert_eq!(outcome, ClientSecretWrite::Replaced);

    let devices = devices_of(&path, "acme");
    let server = &devices["server"];
    assert_eq!(server.public_key.as_deref(), Some(key.as_str()));
    assert!(
        server.secret.expose_secret().is_empty(),
        "the old secret is gone, not kept beside the key: {server:?}"
    );
}

/// Revoking one device leaves the client and every other device alone —
/// which is the whole point of the table.
#[test]
fn revoking_a_device_leaves_the_others_alone() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.acme]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         \n\
         [auth.clients.acme.devices.laptop]\n\
         secret = \"AAAAAAAAAAAAAAAA\"\n\
         \n\
         [auth.clients.acme.devices.phone]\n\
         secret = \"BBBBBBBBBBBBBBBB\"\n",
    );

    ProxyConfig::remove_device(&path, "acme", "laptop").expect("the device should be revoked");

    let devices = devices_of(&path, "acme");
    assert_eq!(devices.len(), 1, "one device went, {devices:?}");
    assert_eq!(
        devices.get("phone").map(|d| d.secret.as_str()),
        Some("BBBBBBBBBBBBBBBB")
    );
    assert_eq!(
        secret_of(&path, "acme").as_deref(),
        Some("JBSWY3DPEHPK3PXP"),
        "the client's own credential is not a device's to revoke"
    );
    let written = fs::read_to_string(&path).expect("read back");
    assert!(!written.contains("AAAAAAAAAAAAAAAA"), "{written}");
}

/// Naming a device that is not there says which ones are, so a typo does not
/// look like a successful revocation.
#[test]
fn revoking_a_device_that_is_not_there_says_which_ones_are() {
    let (_dir, path) = scratch_config(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.acme]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         \n\
         [auth.clients.acme.devices.laptop]\n\
         secret = \"AAAAAAAAAAAAAAAA\"\n",
    );

    let err = ProxyConfig::remove_device(&path, "acme", "tablet")
        .expect_err("a missing device must not be reported as revoked");
    assert!(err.to_string().contains("tablet"), "{err}");
    assert!(err.to_string().contains("laptop"), "{err}");
    assert_eq!(devices_of(&path, "acme").len(), 1);
}

/// Revoking a client drops its devices with it: a device credential left
/// behind under a client that is gone is a credential nobody can revoke,
/// because `client list` no longer has a client to list it under.
#[test]
fn revoking_a_client_takes_its_devices_with_it() {
    let source = "[auth]\n\
                  enabled = true\n\
                  \n\
                  [auth.clients.acme]\n\
                  secret = \"JBSWY3DPEHPK3PXP\"\n\
                  \n\
                  [auth.clients.acme.devices.laptop]\n\
                  secret = \"AAAAAAAAAAAAAAAA\"\n\
                  \n\
                  [auth.clients.other]\n\
                  secret = \"CCCCCCCCCCCCCCCC\"\n";
    let (_dir, path) = scratch_config(source);

    ProxyConfig::remove_client(&path, "acme").expect("the client should be revoked");

    let written = fs::read_to_string(&path).expect("read back");
    assert!(!written.contains("acme"), "{written}");
    assert!(!written.contains("AAAAAAAAAAAAAAAA"), "{written}");
    assert_eq!(
        secret_of(&path, "other").as_deref(),
        Some("CCCCCCCCCCCCCCCC"),
        "the neighbouring client is untouched"
    );
    let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config still parses");
    assert_eq!(auth.expect("[auth] exists").clients.len(), 1);
}

/// A revoke that names something absent changes nothing, which is also why
/// it cannot create the section it is about to delete.
#[test]
fn revoking_something_absent_leaves_the_file_alone() {
    let source = "default_backend = \"http://127.0.0.1:15666\"\n\
                  \n\
                  [auth.clients.acme]\n\
                  secret = \"JBSWY3DPEHPK3PXP\"\n";
    let (_dir, path) = scratch_config(source);

    let err = ProxyConfig::remove_client(&path, "ghost")
        .expect_err("a missing client must not be reported as revoked");
    assert!(err.to_string().contains("ghost"), "{err}");
    assert_eq!(
        fs::read_to_string(&path).expect("read back"),
        source,
        "the file is byte for byte what it was"
    );

    // No [auth.clients] at all, and the same answer.
    let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");
    assert!(ProxyConfig::remove_client(&path, "acme").is_err());
    assert!(ProxyConfig::remove_device(&path, "acme", "laptop").is_err());
    assert_eq!(
        fs::read_to_string(&path).expect("read back"),
        "default_backend = \"http://127.0.0.1:15666\"\n"
    );
}

/// A Node ID to write into `[peers] allow`.
fn node_id(seed: u8) -> String {
    iroh::SecretKey::from_bytes(&[seed; 32])
        .public()
        .to_string()
}

/// The default has to stay permissive: every deployment that predates
/// `[peers]` has no section at all, and none of them may start refusing
/// connections after an upgrade.
#[test]
fn no_peers_section_means_no_restriction() {
    assert!(parse("").peers.is_none());

    // The section present but the key absent is the same thing.
    let config = parse("[peers]\n");
    assert!(
        config
            .peers
            .as_ref()
            .unwrap()
            .parse_allow_list()
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_peers_allow_list_parses_into_node_ids() {
    let source = format!("[peers]\nallow = [{:?}, {:?}]\n", node_id(1), node_id(2));
    let config = parse(&source);

    let allowed = config
        .peers
        .as_ref()
        .unwrap()
        .parse_allow_list()
        .unwrap()
        .expect("the list is configured");

    assert_eq!(allowed.len(), 2);
    assert!(allowed.contains(&node_id(1).parse::<iroh::EndpointId>().unwrap()));
    assert!(allowed.contains(&node_id(2).parse::<iroh::EndpointId>().unwrap()));
}

/// A typo in one entry would otherwise silently narrow a list whose whole
/// job is to refuse strangers — so it is fatal, not skipped.
#[test]
fn a_malformed_node_id_is_refused_not_dropped() {
    let source = format!("[peers]\nallow = [{:?}, \"not-a-node-id\"]\n", node_id(1));
    let err = parse(&source)
        .peers
        .as_ref()
        .unwrap()
        .parse_allow_list()
        .expect_err("a malformed entry must be reported");

    assert!(err.to_string().contains("not-a-node-id"), "{err}");
}

/// `allow = []` is refused rather than read as "refuse everybody": it is a
/// plausible typo, and guessing wrong locks the operator out of their own
/// server.
#[test]
fn an_empty_allow_list_is_refused() {
    let config = parse("[peers]\nallow = []\n");
    let err = config
        .peers
        .as_ref()
        .unwrap()
        .parse_allow_list()
        .expect_err("an empty list must not be read as either case");

    assert!(err.to_string().contains("[peers] allow = []"), "{err}");
}

/// A wildcard with no dot after it is a bare `ends_with`, so it covers any
/// host ending in the same letters — `eviliakl.top` for `*iakl.top`. The
/// only useful thing to do with one is refuse to start.
#[test]
fn a_route_wildcard_without_a_label_boundary_is_refused() {
    let config = parse(
        r#"
[[routes]]
host_pattern = "*iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
"#,
    );
    let err = config
        .build_routes()
        .expect_err("the pattern has to be refused");
    assert!(err.to_string().contains("label boundary"), "{err}");
}

/// The same rule for an `allow_hosts` entry, which is a host pattern and
/// would otherwise authorize more hosts than it names.
#[test]
fn an_allow_hosts_wildcard_without_a_label_boundary_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    // No `enabled = true`: with 2FA on, a 0644 file is refused for its
    // permissions before the pattern is ever looked at, and the file mode
    // is not something this test should depend on.
    std::fs::write(
        &path,
        r#"
[auth]

[auth.clients.device]
secret = "JBSWY3DPEHPK3PXP"
allow_hosts = ["*iakl.top"]
"#,
    )
    .expect("write the config");

    let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect_err("the pattern has to be refused");
    assert!(err.to_string().contains("label boundary"), "{err}");
}

/// A pattern that folds into the catch-all is not the catch-all: `*..`
/// and `[*]` both do. A client that may reach every host — or a route that
/// serves every host — because of a spelling nobody meant is the one thing
/// the shared rule must not do.
#[test]
fn a_pattern_that_folds_into_the_catch_all_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
[auth]

[auth.clients.device]
secret = "JBSWY3DPEHPK3PXP"
allow_hosts = ["*.."]
"#,
    )
    .expect("write the config");

    let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect_err("the pattern has to be refused");
    assert!(err.to_string().contains("catch-all"), "{err}");
}

/// `window` is handed to the TOTP library as a `u8`, so 300 was truncated
/// to 44 by the cast: a code valid for ±22 minutes instead of ±30 seconds.
#[test]
fn a_window_that_does_not_fit_is_refused() {
    let err = load_from("[auth]\nwindow = 300\n").expect_err("300 does not fit a u8");
    assert!(err.to_string().contains("window is 300"), "{err}");

    // And a sane window still loads.
    let (_, auth) = load_from("[auth]\nwindow = 1\n").expect("a normal window loads");
    assert_eq!(auth.expect("auth section present").window, 1);
}

#[test]
fn a_digit_count_no_code_has_is_refused() {
    let err = load_from("[auth]\ndigits = 4\n").expect_err("a code is not 4 digits");
    assert!(err.to_string().contains("digits is 4"), "{err}");
}

#[test]
fn a_time_step_of_zero_is_refused() {
    let err = load_from("[auth]\ntime_step = 0\n").expect_err("0 covers no time at all");
    assert!(err.to_string().contains("time_step"), "{err}");
}

/// Why `[auth]` is the one section that refuses keys it does not know:
/// `enable = true` for `enabled` used to leave 2FA off, and the log said
/// nothing, because serde drops what it does not recognise and the default
/// for `enabled` is false.
#[test]
fn an_unknown_auth_key_is_refused_rather_than_ignored() {
    let err = load_from("[auth]\nenable = true\n").expect_err("a typo must not disable 2FA");
    assert!(err.to_string().contains("enable"), "{err}");
}

/// The table an operator writes under a client, read back the way the
/// server reads it — and the client's own `secret` is still there beside
/// it, because that is the credential of the device with no name.
#[test]
fn a_device_table_loads_without_disturbing_the_client() {
    let (_, auth) = load_from(
        r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"

[auth.clients.client-001.devices.laptop]
secret = "LAPTOPSECRET"

[auth.clients.client-001.devices.phone]
secret = "PHONESECRET"
created_at = "1700000000"
"#,
    )
    .expect("a device table loads");

    let client = &auth.expect("auth section present").clients["client-001"];
    assert_eq!(client.secret.as_str(), "CLIENTSECRET");
    assert_eq!(client.devices.len(), 2);
    assert_eq!(client.devices["laptop"].secret.as_str(), "LAPTOPSECRET");
    assert_eq!(client.devices["phone"].created_at, "1700000000");
    assert!(
        !client.devices["laptop"].created_at.is_empty(),
        "an undated device is dated the moment it is issued"
    );
}

/// A device secret keys that device's HMAC, so an empty one is a signature
/// anybody can forge — refused at load rather than read as "a device that
/// authenticates nobody". An empty spelling is no secret at all, so this is
/// also the entry with no credential of any kind.
#[test]
fn an_empty_device_secret_is_refused() {
    let err = load_from(
        r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"

[auth.clients.client-001.devices.laptop]
secret = ""
"#,
    )
    .expect_err("an empty secret must not load");

    assert!(err.to_string().contains("devices.laptop"), "{err}");
    assert!(err.to_string().contains("empty secret"), "{err}");
}

/// A device answers with exactly one credential, and the loader is where
/// that is enforced. Neither field is a config that does not say how the
/// device proves itself; both is two answers to disagree about. Refused
/// here, where the operator can see which entry it is about, rather than at
/// a handshake whose only reportable outcome is "refused".
#[test]
fn a_device_entry_needs_exactly_one_credential() {
    let client = r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"
"#;

    let neither = load_from(&format!(
        "{client}\n[auth.clients.client-001.devices.laptop]\ncreated_at = \"1700000000\"\n"
    ))
    .expect_err("a device with no credential must not load");
    assert!(neither.to_string().contains("devices.laptop"), "{neither}");
    assert!(neither.to_string().contains("no `secret`"), "{neither}");
    assert!(neither.to_string().contains("no `public_key`"), "{neither}");

    let key = crate::auth::public_key_hex(&iroh::SecretKey::generate().public());
    let both = load_from(&format!(
        "{client}\n[auth.clients.client-001.devices.laptop]\nsecret = \"LAPTOPSECRET\"\n\
         public_key = \"{key}\"\n"
    ))
    .expect_err("two credentials must not load");
    assert!(both.to_string().contains("devices.laptop"), "{both}");
    assert!(both.to_string().contains("both"), "{both}");
}

/// A device that proves itself with a key: `public_key` is read where a
/// `secret` would be, and the rest of the entry is what it always was.
#[test]
fn a_public_key_device_loads_where_a_secret_one_does() {
    let key = crate::auth::public_key_hex(&iroh::SecretKey::generate().public());

    let (_, auth) = load_from(&format!(
        "[auth.clients.client-001]\nsecret = \"CLIENTSECRET\"\n\n\
         [auth.clients.client-001.devices.server]\npublic_key = \"{key}\"\n"
    ))
    .expect("a key device loads");

    let device = &auth.expect("auth section present").clients["client-001"].devices["server"];
    assert_eq!(device.public_key.as_deref(), Some(key.as_str()));
    // Not `{device:?}`: `DeviceAuth`'s `Debug` prints `secret: "<redacted>"`,
    // so it says nothing here and reads to the scanner as logging a secret.
    assert!(
        device.secret.expose_secret().is_empty(),
        "a device registered with a key holds no seed"
    );
    assert!(
        !device.created_at.is_empty(),
        "an undated device is dated the moment it is issued"
    );
}

/// A key that is not a key is refused where it is written into the file.
/// The handshake could only refuse the device that holds it — a bad key and
/// a wrong one read the same from there — so the load is the last place
/// this can be caught with something to say about why.
#[test]
fn a_public_key_that_is_not_a_key_is_refused_at_load() {
    let err = load_from(
        r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"

[auth.clients.client-001.devices.server]
public_key = "not a key"
"#,
    )
    .expect_err("a public_key that is not a key must not load");

    assert!(err.to_string().contains("devices.server"), "{err}");
    assert!(err.to_string().contains("not hex"), "{err}");
}

/// Why a device entry refuses keys it does not know, which is the reason
/// every `[auth]` table does: `secrets` for `secret` would leave the device
/// with no credential at all, and nothing would say so.
#[test]
fn an_unknown_device_key_is_refused_rather_than_ignored() {
    let err = load_from(
        r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"

[auth.clients.client-001.devices.laptop]
secrets = "LAPTOPSECRET"
"#,
    )
    .expect_err("a typo must not leave a device without a credential");

    assert!(err.to_string().contains("secrets"), "{err}");
}

/// A device name is written into the log line for everything that happens
/// to it, and it is what an operator names when revoking one — so it is
/// held to what a client id is before it is ever accepted.
#[test]
fn a_device_name_is_refused_before_it_reaches_a_log_line() {
    let client = r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"
"#;

    let err = load_from(&format!(
        "{client}\n[auth.clients.client-001.devices.\"\"]\nsecret = \"LAPTOPSECRET\"\n"
    ))
    .expect_err("an unnamed device is not a device");
    assert!(err.to_string().contains("needs a name"), "{err}");

    let err = load_from(&format!(
        "{client}\n[auth.clients.client-001.devices.\"laptop\\r\\nINFO: connected\"]\n\
         secret = \"LAPTOPSECRET\"\n"
    ))
    .expect_err("a name that ends its own log line must not load");
    assert!(err.to_string().contains("printable ASCII"), "{err}");
}

// -----------------------------------------------------------------------
// The endpoint identity
//
// The property being pinned throughout: a config that never mentions
// `[iroh] secret_key` comes out of the first start with a Node ID that is
// still the same one after the next. Everything else here is about not
// breaking the operator's file on the way there.
// -----------------------------------------------------------------------

/// A config with no `[iroh]` section at all gains one holding the key, and
/// nothing else. This is the three-line config the README's quick start
/// tells people to write, so it is the case that has to work.
#[test]
fn a_config_without_iroh_gains_the_key() {
    let (_dir, path) = scratch_config(
        "[[routes]]\n\
         host_pattern = \"*\"\n\
         backends = [\"http://127.0.0.1:18080\"]\n",
    );

    let identity =
        ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
            .expect("the identity is resolved");

    let EndpointIdentity::Generated(key) = identity else {
        panic!("a missing key has to be generated and written");
    };
    key.expose_secret()
        .parse::<iroh::SecretKey>()
        .expect("the written key parses as an ed25519 secret key");

    let config = parse(&fs::read_to_string(&path).expect("the config is still there"));
    assert_eq!(
        config
            .iroh
            .and_then(|iroh| iroh.secret_key)
            .map(|key| key.expose_secret().to_string()),
        Some(key.expose_secret().to_string()),
        "the key has to be on disk, not only in memory"
    );
    // And the rest of the file is untouched.
    assert!(
        config
            .routes
            .expect("the routes survived")
            .iter()
            .any(|route| route.host_pattern == "*"),
        "the generated key must not cost the operator their routes"
    );
}

/// An `[iroh]` section that exists for other reasons keeps them. Losing
/// `relay_mode = "pinned"` because a key was written would silently change
/// which relays the endpoint uses.
#[test]
fn an_existing_iroh_section_keeps_its_other_keys() {
    let (_dir, path) = scratch_config(
        "[iroh]\n\
         relay_mode = \"pinned\"\n\
         bind_port = 41641\n",
    );

    ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
        .expect("the identity is resolved");

    let written = fs::read_to_string(&path).expect("the config is still there");
    let config = parse(&written);
    let iroh = config.iroh.expect("[iroh] survived");
    assert_eq!(iroh.relay_mode.as_deref(), Some("pinned"));
    assert_eq!(iroh.bind_port, Some(41641));
    assert!(
        iroh.secret_key.is_some(),
        "the key belongs in the section that was already there"
    );
}

/// The comments an operator wrote around the spot are the reason the file is
/// edited as TOML instead of re-serialized. `config.toml.example` is 368
/// lines of prose, and a first start that flattened it to three keys would
/// be a nasty surprise.
#[test]
fn the_comments_around_the_key_survive() {
    let (_dir, path) = scratch_config(
        "# My edge box in the shed.\n\
         [iroh]\n\
         # Turned on after the relay migration.\n\
         relay_mode = \"pinned\"\n",
    );

    ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
        .expect("the identity is resolved");

    let written = fs::read_to_string(&path).expect("the config is still there");
    assert!(
        written.contains("# My edge box in the shed."),
        "the header comment was lost:\n{written}"
    );
    assert!(
        written.contains("# Turned on after the relay migration."),
        "the comment on the key above was lost:\n{written}"
    );
}

/// The read and the write are one pair, and the file that goes through
/// them comes back the way it was.
///
/// Both helpers wipe the copies they make on the way — the text the file
/// was read into, the tree it was parsed into and the text it was rendered
/// into — and the point of that is that none of it touches the file: what
/// the operator wrote is what is still there, down to the comments.
#[test]
fn a_config_that_goes_through_the_helpers_comes_back_unchanged() {
    let source = "# My edge box in the shed.\n\
                  [iroh]\n\
                  # Turned on after the relay migration.\n\
                  relay_mode = \"pinned\"\n";
    let (_dir, path) = scratch_config(source);

    let document = read_config_document(&path, "nothing written").expect("the config parses");
    write_config_document(&path, document).expect("the config is written");

    let written = fs::read_to_string(&path).expect("the config is still there");
    assert_eq!(written, source, "the file did not come back unchanged");
}

/// A key that is already configured is used as it stands. Writing a fresh
/// one here would rotate the endpoint's identity on every restart, which is
/// the exact failure this whole mechanism exists to remove.
///
/// The key is generated rather than written out as a literal. A hardcoded
/// hex string sitting under a `secret_key` key is what a credential scanner
/// is built to catch, and it is right to: once such a line is in the history
/// nobody reviewing a diff can tell a fixture from a real key any more.
#[test]
fn a_configured_key_is_left_alone() {
    let key = generate_secret_key_hex();
    let (_dir, path) = scratch_config(&format!("[iroh]\nsecret_key = \"{key}\"\n"));

    let identity =
        ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
            .expect("the identity is resolved");

    assert_eq!(
        identity,
        EndpointIdentity::Configured(SecretString::new(key.clone()))
    );
    assert_eq!(
        fs::read_to_string(&path).expect("the config is still there"),
        format!("[iroh]\nsecret_key = \"{key}\"\n"),
        "a configured key must not be rewritten"
    );
}

/// A key that does not parse refuses the start. It used to be a warning and
/// a random key, which left the endpoint on a different Node ID after every
/// restart — every stored Node ID stale, and the log saying it had been
/// handled.
#[test]
fn an_unparseable_key_refuses_rather_than_rotating() {
    let broken = "[iroh]\nsecret_key = \"not-a-key\"\n";
    let (_dir, path) = scratch_config(broken);

    let err = ProxyConfig::ensure_iroh_secret_key(&path, &parse(broken))
        .expect_err("a key that does not parse must not be papered over");

    let message = err.to_string();
    assert!(
        message.contains("not a valid key"),
        "the refusal names the problem: {message}"
    );
    assert!(
        message.contains("every restart"),
        "the refusal says what it would have cost: {message}"
    );
    assert_eq!(
        fs::read_to_string(&path).expect("the config is still there"),
        broken,
        "the operator's typo has to survive so they can see it"
    );
}

/// Two starts in a row have to land on the same Node ID. Without this the
/// mechanism could write a key on the first run and still let a later one
/// replace it, which is the bug in a slower form.
/// Two starts in a row land on the same key.
///
/// The variants differ between the two calls — the first start generates, the
/// second finds what the first wrote — so this compares the keys themselves.
/// Asserting the variants would pin the wrong thing: what has to be stable is
/// the identity, not which branch produced it.
#[test]
fn the_node_id_survives_a_restart() {
    let (_dir, path) = scratch_config("debug = true\n");

    let first =
        ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
            .expect("the first start resolves an identity");
    let second =
        ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
            .expect("the second start resolves an identity");

    assert_eq!(
        first.key(),
        second.key(),
        "the second start has to find the key the first one wrote"
    );
    assert_eq!(
        public_key(first.key()),
        public_key(second.key()),
        "and therefore the same Node ID"
    );
}

/// The public key of a hex secret key.
fn public_key(hex_key: &str) -> String {
    iroh::SecretKey::from_bytes(
        &hex::decode(hex_key)
            .expect("the key is hex")
            .try_into()
            .expect("32 bytes"),
    )
    .public()
    .to_string()
}

/// The env var that turns persistence off is read as an operator would expect.
///
/// A compose file that lists a variable with no value (`- NEXAPIPE_NO_PERSIST_IDENTITY`)
/// is asking for the default, not for the behaviour — so empty means "no", like
/// unset. The end-to-end half of this (the server really does leave the file
/// alone) is in `tests/first_run_identity.rs`, which can set the variable on a
/// child process without `unsafe`.
#[test]
fn the_no_persist_flag_reads_the_way_it_looks() {
    for off in [
        None,
        Some(""),
        Some("  "),
        Some("0"),
        Some("false"),
        Some("FALSE"),
    ] {
        assert!(
            !persistence_disabled(off),
            "{off:?} has to mean persistence stays on"
        );
    }
    for on in [Some("1"), Some("true"), Some("yes"), Some("anything else")] {
        assert!(
            persistence_disabled(on),
            "{on:?} has to turn persistence off"
        );
    }
}

/// An unwritable config is an ordinary deployment (a read-only bind mount, a
/// A config that reads fine but cannot be written is an ordinary deployment (a
/// read-only bind mount, a file owned by another user), and it has to keep
/// working. The old code path here was "no key configured, random identity,
/// carry on"; refusing to start would make this change a regression for exactly
/// that case.
///
/// Reachable portably by pointing at a file that is not TOML: the caller already
/// parsed a config (that is what `config` is), and the writer re-reads the
/// path, so the two can disagree — an operator saving over the file mid-start is
/// the realistic version of it.
#[test]
fn an_unwritable_config_still_resolves_an_identity() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    fs::write(&path, "this is not TOML at all: \"\n").expect("write a file that is not TOML");
    let path = path.to_string_lossy().into_owned();

    let identity = ProxyConfig::ensure_iroh_secret_key(&path, &parse("debug = true\n"))
        .expect("a file the server cannot write must not stop it: the key is generated either way");

    // Compare instead of formatting: the identity is the endpoint's private
    // key, and it does not belong in a message that CI keeps — even though
    // `EndpointIdentity`'s `Debug` redacts it.
    assert!(
        matches!(identity, EndpointIdentity::Ephemeral(_)),
        "a failed write has to degrade to a throwaway identity"
    );
    // Still a usable key, or the server would be refusing connections for a
    // reason that has nothing to do with why the write failed.
    assert_eq!(
        identity.key().len(),
        64,
        "an ephemeral key is still a full ed25519 key"
    );
    public_key(identity.key());
}

/// `EndpointIdentity` must not print its key.
///
/// Every variant of it *is* the ed25519 private key, and this enum reaches
/// a `{:?}` on the failure path of this very module, where the message goes
/// to CI and stays there. A derived `Debug` — the obvious way to write this
/// type — would put a live key on that line while the suite still reported
/// green.
///
/// Pinned rather than left to review because the mistake is invisible in the
/// diff that adds the enum: nothing about `#[derive(Debug)]` looks wrong
/// until you know what the type holds.
#[test]
fn an_identity_never_prints_its_key() {
    for identity in [
        EndpointIdentity::Configured(SecretString::new(generate_secret_key_hex())),
        EndpointIdentity::Generated(SecretString::new(generate_secret_key_hex())),
        EndpointIdentity::Ephemeral(SecretString::new(generate_secret_key_hex())),
    ] {
        let rendered = format!("{identity:?}");
        assert!(
            !rendered.contains(identity.key()),
            "{rendered} leaked the private key"
        );
        assert!(
            rendered.contains("<redacted>"),
            "{rendered} should say the key was withheld"
        );
    }
}

/// The variant survives redaction: it is the one thing a reader of that log
/// line needs — which of the three paths produced this identity.
#[test]
fn an_identity_still_says_which_path_it_came_from() {
    let rendered = |identity: EndpointIdentity| format!("{identity:?}");
    assert!(rendered(EndpointIdentity::Configured(SecretString::default())).contains("Configured"));
    assert!(rendered(EndpointIdentity::Generated(SecretString::default())).contains("Generated"));
    assert!(rendered(EndpointIdentity::Ephemeral(SecretString::default())).contains("Ephemeral"));
}

/// The generated key is a private key, so the file it lands in must be
/// private. This is the same rule `check_credential_file_permissions`
/// refuses a load over, so the write has to satisfy it rather than leave
/// the next start to find its own output and reject it.
#[cfg(unix)]
#[test]
fn a_generated_key_lands_in_a_private_file() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, path) = scratch_config("debug = true\n");
    ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
        .expect("the identity is resolved");

    let mode = fs::metadata(&path)
        .expect("the config is there")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "a file holding the endpoint's private key must be private, got {mode:o}"
    );
}

/// The per-route flow bound has no ceiling, while the server-wide one has.
#[test]
fn a_route_may_carry_a_flow_bound_of_a_century() {
    let spec = RouteSpec {
        host_pattern: "app.test".to_string(),
        path_pattern: "/".to_string(),
        path_is_prefix: Some(true),
        strategy: None,
        backends: vec!["127.0.0.1:9000".to_string()],
        backend_protocol: None,
        mode: Some("tcp".to_string()),
        modes: None,
        path_rewrite: None,
        client_ports: None,
        idle_timeout_secs: None,
        flow_timeout_secs: Some(315_360_000_000),
        cert_path: None,
        key_path: None,
        redirect_to_https: None,
    };

    let route = crate::routes::Route::try_from(spec).expect("the route is built");
    assert_eq!(
        route.flow_timeout(),
        Some(std::time::Duration::from_secs(315_360_000_000)),
        "a century-long flow bound is accepted"
    );
    assert!(
        315_360_000_000 > crate::deadline::MAX_SECS,
        "the server-wide ceiling for the same bound is one day"
    );
}
