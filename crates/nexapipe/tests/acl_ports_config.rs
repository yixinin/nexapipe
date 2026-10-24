//! The per-client authorization of a config, from the file to the ACL.
//!
//! These tests are about the config *loading* path, which is easy to break in
//! a way the compiler accepts: a key the loader does not know is dropped, and a
//! dropped key is a security setting that reads as "on" in the file and does
//! nothing at runtime. `allow_ports` has to reach the ACL the handshake
//! consults, and a port of zero has to be refused rather than silently kept.

use nexapipe::config::ProxyConfig;

const EXAMPLE_CONFIG: &str = "../../config.toml.2fa.example";

/// Writes a config with the given `[auth.clients]` body and loads it.
fn load_with_client_body(body: &str) -> anyhow::Result<nexapipe::auth::AuthConfig> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, body).unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path.to_str().unwrap())?;
    Ok(auth.expect("the config declares an [auth] section"))
}

/// `allow_ports` reaches the ACL, so a client that names one port really is
/// limited to it.
#[test]
fn an_allow_ports_list_reaches_the_acl() {
    let auth = load_with_client_body(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
         allow_ports = [443, 8443]\n",
    )
    .expect("the config has to load");

    let acl = auth.clients["client-001"].acl();

    assert!(acl.allows_port(443));
    assert!(acl.allows_port(8443));
    assert!(
        !acl.allows_port(22),
        "a port the file did not name is not reachable"
    );
}

/// `allow_ports_strict` reaches the ACL, so the port list is checked against
/// the port a request is served from and not only against the one the client
/// names.
#[test]
fn the_strict_flag_reaches_the_acl() {
    let auth = load_with_client_body(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
         allow_ports = [443]\n\
         allow_ports_strict = true\n",
    )
    .expect("the config has to load");

    let acl = auth.clients["client-001"].acl();

    assert!(
        acl.allows_backend_port(443),
        "a port the client may reach is still reachable"
    );
    assert!(
        !acl.allows_backend_port(18080),
        "a port the request is served from and the client may not reach is refused"
    );
}

/// Without the flag, the port list is not consulted about the port a request
/// is served from: that is the historical behaviour, and the flag is how an
/// operator asks for the check above.
#[test]
fn the_strict_flag_is_off_by_default() {
    let auth = load_with_client_body(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
         allow_ports = [443]\n",
    )
    .expect("the config has to load");

    let acl = auth.clients["client-001"].acl();

    assert!(
        acl.allows_backend_port(18080),
        "the historical reach is kept until the flag says otherwise"
    );
}

/// A client with no `allow_ports` keeps the reach it always had: every port.
#[test]
fn a_client_without_allow_ports_is_not_limited_by_ports() {
    let auth = load_with_client_body(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n",
    )
    .expect("the config has to load");

    let acl = auth.clients["client-001"].acl();

    assert!(acl.allows_port(443));
    assert!(acl.allows_port(22));
}

/// The two halves are independent: a client may be limited to one host and
/// every port, or every host and one port.
#[test]
fn the_host_and_the_port_are_independent_in_a_config() {
    let auth = load_with_client_body(
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
         allow_hosts = [\"api.example.com\"]\n\
         allow_ports = [443]\n",
    )
    .expect("the config has to load");

    let acl = auth.clients["client-001"].acl();

    assert!(acl.allows_target("api.example.com", 443));
    assert!(!acl.allows_target("api.example.com", 8443));
    assert!(!acl.allows_target("admin.example.com", 443));
}

/// A port of zero is refused at startup: no client ever asks for it, so an
/// entry that lists it authorizes nothing and looks like it authorizes
/// something.
#[test]
fn a_port_of_zero_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
         allow_ports = [443, 0]\n",
    )
    .unwrap();

    let error = ProxyConfig::load_with_auth(path.to_str().unwrap())
        .expect_err("a port of zero has to be refused");
    let message = error.to_string();
    assert!(
        message.contains("allow_ports") && message.contains("port 0"),
        "the refusal has to name the entry: {message}"
    );
}

/// The shipped example config parses: the new key is commented out there, and a
/// config that does not mention it must mean what it meant before it existed.
#[test]
fn the_example_config_still_loads() {
    let (_, auth) = ProxyConfig::load_with_auth(EXAMPLE_CONFIG).expect("the example config parses");

    let auth = auth.expect("the example config declares an [auth] section");
    let acl = auth.clients["client-001"].acl();
    assert!(
        !acl.limits_ports(),
        "a config that does not mention ports is not limited by them"
    );
}
