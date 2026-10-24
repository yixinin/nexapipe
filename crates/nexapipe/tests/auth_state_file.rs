//! The configuration and the runtime state are two files, end to end.
//!
//! The configuration is the operator's: they wrote it, they read it, they
//! keep it in version control. The counters a running server keeps — how many
//! times a client mistyped a code, until when it is locked out, when it was
//! last seen — are the server's, and they live in a file of their own beside
//! the configuration.
//!
//! These tests cover the three things that has to get right: the counters
//! reach the state file and stay out of the configuration, a lockout still
//! survives a restart, and a deployment that was counting in the configuration
//! file before the state file existed keeps its lockouts.

use nexapipe::config::ProxyConfig;
use nexapipe::config_watcher::save_auth_state;
use std::path::Path;

/// A configuration with one client that has a secret and nothing else.
fn config_with_client() -> &'static str {
    "[auth]\n\
     enabled = true\n\
     max_attempts = 3\n\
     lockout_duration = 300\n\
     [auth.clients.client-001]\n\
     secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
     created_at = \"1723756800\"\n\
     [auth.clients.client-001.devices.laptop]\n\
     secret = \"KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP\"\n\
     created_at = \"1723756801\"\n"
}

/// The configuration file and the state file beside it.
fn fixture(dir: &Path) -> (String, String) {
    let config = dir.join("config.toml");
    std::fs::write(&config, config_with_client()).expect("write the configuration");
    (
        config.to_string_lossy().into_owned(),
        dir.join("state.toml").to_string_lossy().into_owned(),
    )
}

/// A counted failure lands in the state file, and the configuration file is
/// byte for byte what the operator wrote.
///
/// The configuration is not the server's file to rewrite. It is not only a
/// question of tidiness: the server watches the configuration's modification
/// time, so a server that wrote its counters into the configuration turned
/// every mistyped code into a configuration reload — the routes rebuilt and
/// the health checks restarted, because a stranger typed a code wrong.
#[test]
fn a_counted_failure_lands_in_the_state_file_and_not_in_the_configuration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (config_path, state_path) = fixture(dir.path());

    let (_, auth) = ProxyConfig::load_with_auth(&config_path).expect("the configuration loads");
    let mut auth = auth.expect("the configuration declares [auth]");

    auth.clients
        .get_mut("client-001")
        .expect("the fixture carries one client")
        .record_failure(3, 300);

    save_auth_state(&state_path, &auth).expect("the counters are written");

    let state_on_disk = std::fs::read_to_string(&state_path).expect("read the state back");
    assert!(
        state_on_disk.contains("failed_attempts = 1"),
        "the counter is in the state file: {state_on_disk}"
    );
    assert!(
        !state_on_disk.contains("locked_until"),
        "one mistake is not a lockout yet: {state_on_disk}"
    );
    assert!(
        !state_on_disk.contains("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
        "a credential has no business in the state file: {state_on_disk}"
    );

    let config_on_disk =
        std::fs::read_to_string(&config_path).expect("read the configuration back");
    assert_eq!(
        config_on_disk,
        config_with_client(),
        "the configuration is the operator's file and is not the server's to rewrite"
    );
}

/// A lockout survives a restart: the counters are in the state file, and the
/// next load reads them from there.
#[test]
fn a_lockout_survives_a_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (config_path, state_path) = fixture(dir.path());

    let (_, auth) = ProxyConfig::load_with_auth(&config_path).expect("the configuration loads");
    let mut auth = auth.expect("the configuration declares [auth]");

    let client = auth.clients.get_mut("client-001").expect("one client");
    client.record_failure(3, 300);
    client.record_failure(3, 300);
    client.record_failure(3, 300);
    assert!(client.is_locked_out(), "three mistakes lock the client out");

    save_auth_state(&state_path, &auth).expect("the counters are written");

    // The next start: a fresh load of the configuration, with the state file
    // beside it, and the client is still locked out.
    let (_, reloaded) = ProxyConfig::load_with_auth(&config_path).expect("the configuration loads");
    let reloaded = reloaded.expect("the configuration declares [auth]");
    let client = &reloaded.clients["client-001"];
    assert_eq!(client.failed_attempts, 3);
    assert!(
        client.is_locked_out(),
        "a lockout that does not survive a restart is not a lockout"
    );
}

/// A deployment that was counting in the configuration file before the state
/// file existed keeps its lockouts.
///
/// The state file wins where it has an entry, and the configuration keeps the
/// answer where it does not — so the upgrade does not hand every client a
/// fresh start.
#[test]
fn a_configuration_that_carries_counters_still_locks_out() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        "[auth]\n\
         enabled = true\n\
         max_attempts = 3\n\
         lockout_duration = 300\n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
         created_at = \"1723756800\"\n\
         failed_attempts = 3\n\
         locked_until = 4102444800\n",
    )
    .expect("write the configuration");
    let config_path = config_path.to_string_lossy().into_owned();

    // No state file: the counters in the configuration are the answer.
    let (_, auth) = ProxyConfig::load_with_auth(&config_path).expect("the configuration loads");
    let auth = auth.expect("the configuration declares [auth]");
    let client = &auth.clients["client-001"];
    assert_eq!(client.failed_attempts, 3);
    assert!(client.is_locked_out(), "the old counters still lock out");

    // And once the state file has an entry for the client, it is the answer.
    let state_path = dir.path().join("state.toml");
    let state_path = state_path.to_string_lossy().into_owned();
    std::fs::write(
        &state_path,
        "[auth.clients.client-001]\nfailed_attempts = 0\nlast_used = 1700000000\n",
    )
    .expect("write the state file");

    let (_, reloaded) = ProxyConfig::load_with_auth(&config_path).expect("the configuration loads");
    let reloaded = reloaded.expect("the configuration declares [auth]");
    let client = &reloaded.clients["client-001"];
    assert_eq!(
        client.failed_attempts, 0,
        "the state file is the answer where it has an entry"
    );
    assert!(!client.is_locked_out());
}

/// The state file is private to the account that runs the server.
#[test]
fn the_state_file_is_private() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (config_path, state_path) = fixture(dir.path());

    let (_, auth) = ProxyConfig::load_with_auth(&config_path).expect("the configuration loads");
    let mut auth = auth.expect("the configuration declares [auth]");
    auth.clients
        .get_mut("client-001")
        .expect("one client")
        .record_failure(3, 300);

    save_auth_state(&state_path, &auth).expect("the counters are written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state_path)
            .expect("the state file is there")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the state file is private: {mode:o}");
    }
}

/// A state file that cannot be read stops the server from starting.
///
/// The lockouts it holds are unknown, and a server that started anyway would
/// have just reset every one of them — which is what somebody who can damage
/// one file wants.
#[test]
fn a_broken_state_file_refuses_the_start() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (config_path, state_path) = fixture(dir.path());

    std::fs::write(&state_path, "this is not TOML at all: \"\n")
        .expect("write a broken state file");

    let error = ProxyConfig::load_with_auth(&config_path)
        .expect_err("a state file that cannot be read stops the start");
    let message = error.to_string();
    assert!(
        message.contains("state.toml"),
        "the message names the file: {message}"
    );
}

/// The state file says which clients are locked out, and it says it in the
/// same shape the configuration uses, so the two read alike.
#[test]
fn the_state_file_reads_like_the_configuration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (config_path, state_path) = fixture(dir.path());

    let (_, auth) = ProxyConfig::load_with_auth(&config_path).expect("the configuration loads");
    let mut auth = auth.expect("the configuration declares [auth]");
    let client = auth.clients.get_mut("client-001").expect("one client");
    client.record_failure(3, 300);
    client.record_device_success("laptop");

    save_auth_state(&state_path, &auth).expect("the counters are written");

    let on_disk = std::fs::read_to_string(&state_path).expect("read the state back");
    assert!(
        on_disk.contains("[auth.clients.client-001]"),
        "the same section the configuration uses: {on_disk}"
    );
    assert!(
        on_disk.contains("[auth.clients.client-001.devices.laptop]"),
        "and the same for a device: {on_disk}"
    );
}

/// A client the server has never counted is not in the state file at all.
///
/// The snapshot carries every client the configuration knows about, and a
/// state file full of empty tables for clients that never mistyped a code
/// says less than one that says nothing.
#[test]
fn a_client_that_was_never_counted_is_not_written() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (config_path, state_path) = fixture(dir.path());

    let (_, auth) = ProxyConfig::load_with_auth(&config_path).expect("the configuration loads");
    let auth = auth.expect("the configuration declares [auth]");

    save_auth_state(&state_path, &auth).expect("the counters are written");

    let on_disk = std::fs::read_to_string(&state_path).expect("read the state back");
    assert!(
        !on_disk.contains("client-001"),
        "a client with nothing counted is not written: {on_disk}"
    );
}
