//! The 2FA settings of the shipped example config, end to end.
//!
//! These tests are about the config *loading* path, which is easy to break in a
//! way the compiler accepts: when the `[auth]` table cannot be read, the server
//! used to get `None` and quietly run with 2FA disabled, which is the worst
//! possible outcome for a security feature. It refuses to start now, and the
//! last test here pins that.

use nexapipe::auth::OtpAuthUri;
use nexapipe::config::ProxyConfig;
use std::time::{Duration, Instant};

const EXAMPLE_CONFIG: &str = "../../config.toml.2fa.example";

/// How long the server gets to refuse to start in
/// [`a_broken_auth_section_refuses_to_start`].
const STARTUP_DEADLINE: Duration = Duration::from_secs(10);

/// `[auth]` reaches [`nexapipe::auth::AuthConfig`] with all of its clients.
///
/// Regression: the table used to be read with `str::parse::<toml::Value>()`,
/// which parses a single TOML value rather than a document and therefore always
/// failed, leaving the server without any 2FA configuration.
#[test]
fn loads_the_auth_section_of_the_example_config() {
    let (_, auth) =
        ProxyConfig::load_with_auth(EXAMPLE_CONFIG).expect("the example config has to parse");

    let auth = auth.expect("the example config declares an [auth] section");
    assert!(auth.enabled, "the example config enables 2FA");
    assert_eq!(auth.issuer, "NexaPipe");
    assert_eq!(auth.time_step, 30);
    assert_eq!(auth.digits, 6);

    let client = auth
        .clients
        .get("client-001")
        .expect("client-001 is configured");
    assert_eq!(client.secret.as_str(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    assert_eq!(
        auth.clients.get("client-002").map(|c| c.secret.as_str()),
        Some("KBSWY3DPEHPK3PXQKBSWY3DPEHPK3PXQ")
    );
}

/// The general example ships with 2FA on, like the first-run template.
///
/// A fresh install that starts with nothing but the Node ID as its credential
/// is a fresh install whose Node ID is a publicly resolvable credential for
/// every route — and that Node ID is in every invite link, in the client's own
/// configuration and in screenshots. The example is the first file an
/// operator copies, so it is the one that has to start secure.
#[test]
fn the_general_example_ships_with_two_factor_on() {
    let (_, auth) = ProxyConfig::load_with_auth("../../config.toml.example")
        .expect("the general example parses");

    let auth = auth.expect("the general example declares an [auth] section");
    assert!(auth.enabled, "the general example starts with 2FA on");
}

/// A config without any `[auth]` table loads as "no 2FA", not as an error.
#[test]
fn accepts_a_config_without_auth() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "").unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path.to_str().unwrap()).unwrap();
    assert!(auth.is_none());
}

/// An `[auth]` table with a broken field is reported instead of being dropped,
/// so a typo cannot silently disable 2FA.
#[test]
fn reports_a_broken_auth_section() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\n\
         enabled = \"not a boolean\"\n",
    )
    .unwrap();

    let error = ProxyConfig::load_with_auth(path.to_str().unwrap()).unwrap_err();
    assert!(
        error.to_string().contains("auth config"),
        "unexpected error: {error:#}"
    );
}

/// The same broken table stops the server instead of turning 2FA off.
///
/// Regression: the startup path logged the error and carried on with no 2FA at
/// all, so `enable = true` and a broken section were the same deployment — one
/// silently unauthenticated, the other only one line of log louder.
#[test]
fn a_broken_auth_section_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[[routes]]\n\
         host_pattern = \"*\"\n\
         mode = \"http\"\n\
         backends = [\"http://127.0.0.1:18080\"]\n\
         \n\
         [auth]\n\
         enabled = \"not a boolean\"\n",
    )
    .unwrap();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args(["--config", path.to_str().unwrap()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn nexapipe");

    // The process is supposed to refuse to start, and the assertion below is
    // about how it exits. Waiting without a deadline would turn a regression —
    // one that lets a broken `[auth]` section through — into a hung suite
    // rather than a failure, so the wait is bounded and a child that outlives
    // it is killed and reported.
    let deadline = Instant::now() + STARTUP_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("check on nexapipe") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "nexapipe did not exit within {}s: a broken [auth] section has to refuse to start",
                STARTUP_DEADLINE.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let output = child.wait_with_output().expect("read nexapipe output");

    // Both streams: the CLI prints through tracing, which decides on its own
    // which one a refusal lands on.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !status.success(),
        "a server with a broken [auth] must not start:\n{text}"
    );
    assert!(
        text.contains("auth config"),
        "the refusal names the section that broke:\n{text}"
    );
}

/// The clients of the example config enroll through the canonical URI.
#[test]
fn builds_the_enrollment_uri_from_the_loaded_settings() {
    let (_, auth) = ProxyConfig::load_with_auth(EXAMPLE_CONFIG).unwrap();
    let auth = auth.unwrap();
    let client = auth.clients.get("client-001").unwrap();

    let uri = OtpAuthUri::from_auth_config(
        &auth.issuer,
        "client-001",
        client.secret.expose_secret(),
        &auth,
    )
    .expect("the example credentials are valid");

    assert_eq!(
        uri.to_uri(),
        "otpauth://totp/NexaPipe:client-001\
         ?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=NexaPipe&algorithm=SHA1&digits=6&period=30"
    );
    assert!(uri.client_warnings().is_empty());
}

/// A seed that is too short to be a secret is refused when the config is
/// read.
///
/// The decode is lazy: a seed is read when a connection proves itself, and
/// the TOTP library refuses one under 128 bits when it builds the validator.
/// So without this check a seed that can never work is found at the
/// operator's first login — long after it was accepted, handed out in an
/// enrollment URI and written down — and it is found as a *failed
/// authentication* rather than as the configuration error it is.
///
/// The refusal names the client, so an operator with a hundred clients in
/// the file knows which one to look at.
#[test]
fn a_seed_too_short_to_be_a_secret_refuses_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[[routes]]\n\
         host_pattern = \"*\"\n\
         mode = \"http\"\n\
         backends = [\"http://127.0.0.1:18080\"]\n\
         \n\
         [auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"AE\"\n",
    )
    .unwrap();

    let refusal = ProxyConfig::load_with_auth(path.to_str().unwrap())
        .expect_err("a seed of one byte is not a secret");
    let refusal = refusal.to_string();
    assert!(
        refusal.contains("client-001"),
        "the refusal names the client whose seed is too short: {refusal}"
    );
    assert!(
        refusal.contains("at least"),
        "the refusal says what the floor is: {refusal}"
    );
}

/// A device's own seed is checked the same way.
///
/// The device table is a second place a seed is written, and it is the one
/// an enrollment puts there: a device that cannot verify is a device that
/// enrolls and then cannot connect, which is worse than a refusal.
#[test]
fn a_devices_seed_too_short_to_be_a_secret_refuses_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[[routes]]\n\
         host_pattern = \"*\"\n\
         mode = \"http\"\n\
         backends = [\"http://127.0.0.1:18080\"]\n\
         \n\
         [auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
         \n\
         [auth.clients.client-001.devices.laptop]\n\
         secret = \"AE\"\n",
    )
    .unwrap();

    let refusal = ProxyConfig::load_with_auth(path.to_str().unwrap())
        .expect_err("a device seed of one byte is not a secret");
    let refusal = refusal.to_string();
    assert!(
        refusal.contains("laptop"),
        "the refusal names the device whose seed is too short: {refusal}"
    );
}
