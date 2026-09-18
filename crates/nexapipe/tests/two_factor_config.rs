//! The 2FA settings of the shipped example config, end to end.
//!
//! These tests are about the config *loading* path, which is easy to break in a
//! way the compiler accepts: when the `[auth]` table cannot be read, the server
//! gets `None` and quietly runs with 2FA disabled, which is the worst possible
//! outcome for a security feature.

use nexapipe::auth::OtpAuthUri;
use nexapipe::config::ProxyConfig;

const EXAMPLE_CONFIG: &str = "../../config.toml.2fa.example";

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
    assert_eq!(client.secret, "JBSWY3DPEHPK3PXP");
    assert_eq!(
        auth.clients.get("client-002").map(|c| c.secret.as_str()),
        Some("KBSWY3DPEHPK3PXQ")
    );
}

/// A config without any `[auth]` table loads as "no 2FA", not as an error.
#[test]
fn accepts_a_config_without_auth() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "default_backend = \"http://localhost:3000\"\n").unwrap();

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
        "default_backend = \"http://localhost:3000\"\n\
         [auth]\n\
         enabled = \"not a boolean\"\n",
    )
    .unwrap();

    let error = ProxyConfig::load_with_auth(path.to_str().unwrap()).unwrap_err();
    assert!(
        error.to_string().contains("auth config"),
        "unexpected error: {error:#}"
    );
}

/// The clients of the example config enroll through the canonical URI.
#[test]
fn builds_the_enrollment_uri_from_the_loaded_settings() {
    let (_, auth) = ProxyConfig::load_with_auth(EXAMPLE_CONFIG).unwrap();
    let auth = auth.unwrap();
    let client = auth.clients.get("client-001").unwrap();

    let uri = OtpAuthUri::from_auth_config(&auth.issuer, "client-001", &client.secret, &auth)
        .expect("the example credentials are valid");

    assert_eq!(
        uri.to_uri(),
        "otpauth://totp/NexaPipe:client-001\
         ?secret=JBSWY3DPEHPK3PXP&issuer=NexaPipe&algorithm=SHA1&digits=6&period=30"
    );
    assert!(uri.client_warnings().is_empty());
}
