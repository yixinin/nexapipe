//! The 2FA lockout and challenge-binding behaviour, end to end.
//!
//! `perform_authentication` needs a live QUIC connection, so these tests drive
//! the two halves it is made of — the client's `TwoFactorAuth` (signing and
//! code generation) and the server's `TotpValidator` (verification) — against
//! each other, plus the `save_auth_state` round trip that makes a lockout
//! survive a restart.

use nexapipe::auth::{AuthConfig, AuthError, ClientAuth, TotpValidator};
use nexapipe::config::ProxyConfig;
use nexapipe::config_watcher::save_auth_state;
use nexapipe_client::auth::{TotpAlgorithm, TwoFactorAuth};
use std::time::{SystemTime, UNIX_EPOCH};

/// A 160-bit Base32 secret, the length `--generate-2fa` hands out. The
/// example configs carry an 80-bit one for brevity, but `totp-rs` refuses to
/// build a validator from anything shorter than 128 bits.
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn auth_config_with_client(max_attempts: u32, lockout_duration: u64) -> AuthConfig {
    let mut config = AuthConfig {
        enabled: true,
        max_attempts,
        lockout_duration,
        ..AuthConfig::default()
    };
    config.clients.insert(
        "client-001".to_string(),
        ClientAuth {
            secret: SECRET.to_string(),
            created_at: "0".to_string(),
            last_used: None,
            failed_attempts: 0,
            locked_until: None,
        },
    );
    config
}

/// A response the client signed over the nonce the server issued verifies.
///
/// This is the cross-crate contract of the signed AUTH_RESPONSE: both halves
/// have to agree on HMAC-SHA256(secret, nonce || timestamp_le) without sharing
/// code, so the signature is computed by the client crate and checked by the
/// server crate.
#[test]
fn accepts_a_signed_current_response() {
    let config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = b"server-challenge-nonce";
    let timestamp = now();
    let signature = client.sign_challenge(nonce, timestamp);
    let code = client.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Ok(true)),
        "a correctly signed current response must verify, got {:?}",
        outcome
    );
}

/// A response signed over a different nonce is refused — this is what stops a
/// captured AUTH_RESPONSE being replayed at another connection, which gets a
/// fresh nonce every time.
#[test]
fn rejects_a_response_signed_over_a_different_nonce() {
    let config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let timestamp = now();
    let signature = client.sign_challenge(b"another-connections-nonce", timestamp);
    let code = client.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        b"server-challenge-nonce",
        timestamp,
        &signature,
        &code,
    );
    assert!(matches!(outcome, Err(AuthError::ChallengeMismatch)));
}

/// A timestamp outside the ±30s window is refused even when correctly signed,
/// so a signed response cannot be replayed next week.
#[test]
fn rejects_a_stale_timestamp() {
    let config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let stale = now() - 120;
    let signature = client.sign_challenge(b"server-challenge-nonce", stale);
    let code = client.generate_code().unwrap();

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        b"server-challenge-nonce",
        stale,
        &signature,
        &code,
    );
    assert!(matches!(outcome, Err(AuthError::StaleTimestamp)));
}

/// A correctly signed response with a wrong code is `Ok(false)`, not an `Err`:
/// it is the only outcome the connection layer counts toward the lockout,
/// while refusals (bad signature, stale timestamp, …) never do.
#[test]
fn reports_a_wrong_code_as_a_counted_failure() {
    let config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = b"server-challenge-nonce";
    let timestamp = now();
    let signature = client.sign_challenge(nonce, timestamp);

    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        nonce,
        timestamp,
        &signature,
        "000000",
    );
    assert!(matches!(outcome, Ok(false)));
}

/// The lockout itself: `max_attempts` counted failures lock the client, and a
/// locked client is refused — even with a correct signature and code — until
/// `record_success` clears the counters. The failure loop mirrors what
/// `perform_authentication` runs per rejected code.
#[test]
fn locks_out_after_max_attempts() {
    let mut config = auth_config_with_client(3, 60);
    let client = TwoFactorAuth::new("client-001", SECRET, TotpAlgorithm::SHA1).unwrap();

    let nonce = b"server-challenge-nonce";
    let timestamp = now();
    let signature = client.sign_challenge(nonce, timestamp);
    let code = client.generate_code().unwrap();

    for _ in 0..3 {
        let outcome = TotpValidator::new(&config).verify_response(
            "client-001",
            nonce,
            timestamp,
            &signature,
            "000000",
        );
        assert!(matches!(outcome, Ok(false)));
        config
            .clients
            .get_mut("client-001")
            .unwrap()
            .record_failure(config.max_attempts, config.lockout_duration);
    }

    assert!(
        config.clients.get("client-001").unwrap().is_locked_out(),
        "three counted failures must lock the client"
    );

    let locked = TotpValidator::new(&config).verify_response(
        "client-001",
        nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(locked, Err(AuthError::LockedOut)),
        "a locked client is refused even with a perfect response"
    );

    config
        .clients
        .get_mut("client-001")
        .unwrap()
        .record_success();
    let outcome = TotpValidator::new(&config).verify_response(
        "client-001",
        nonce,
        timestamp,
        &signature,
        &code,
    );
    assert!(
        matches!(outcome, Ok(true)),
        "record_success must clear the lockout"
    );
}

/// Counters persist through `save_auth_state` and come back on the next load,
/// without touching anything a human wrote into the file.
#[test]
fn persists_lockout_counters_across_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap();
    std::fs::write(
        &path,
        "# operator comment that must survive\n\
         default_backend = \"http://localhost:3000\"\n\
         [auth]\n\
         enabled = true\n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n\
         created_at = \"1723756800\"\n\
         [auth.clients.client-002]\n\
         secret = \"KBSWY3DPEHPK3PXQ\"\n\
         created_at = \"1723756800\"\n",
    )
    .unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path_str).unwrap();
    let mut auth = auth.expect("the config declares [auth]");

    let entry = auth.clients.get_mut("client-001").unwrap();
    entry.record_failure(3, 60);
    entry.record_failure(3, 60);
    entry.last_used = Some(1700000000);
    save_auth_state(path_str, &auth).unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("# operator comment that must survive"),
        "comments are not the server's to rewrite"
    );
    assert!(on_disk.contains("failed_attempts = 2"));
    assert!(on_disk.contains("last_used = 1700000000"));
    assert!(
        on_disk.contains("KBSWY3DPEHPK3PXQ"),
        "the untouched client stays as written"
    );

    let (_, reloaded) = ProxyConfig::load_with_auth(path_str).unwrap();
    let reloaded = reloaded.unwrap();
    let entry = reloaded.clients.get("client-001").unwrap();
    assert_eq!(entry.failed_attempts, 2);
    assert_eq!(entry.last_used, Some(1700000000));

    // A success zeroes the counters, and zeroed counters leave no keys behind.
    let mut auth = reloaded;
    auth.clients
        .get_mut("client-001")
        .unwrap()
        .record_success();
    save_auth_state(path_str, &auth).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(!on_disk.contains("failed_attempts"));
    assert!(!on_disk.contains("locked_until"));

    let (_, reloaded) = ProxyConfig::load_with_auth(path_str).unwrap();
    let reloaded = reloaded.unwrap();
    let entry = reloaded.clients.get("client-001").unwrap();
    assert_eq!(entry.failed_attempts, 0);
    assert!(entry.locked_until.is_none());
}

/// A client that exists only in memory is not written to disk: the operator
/// may have removed it from the file while the server was running, and a
/// section without its secret would break the next load.
#[test]
fn does_not_resurrect_a_client_removed_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap();
    std::fs::write(
        &path,
        "default_backend = \"http://localhost:3000\"\n\
         [auth]\n\
         enabled = true\n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    )
    .unwrap();

    let (_, auth) = ProxyConfig::load_with_auth(path_str).unwrap();
    let mut auth = auth.unwrap();
    auth.clients.insert(
        "client-002".to_string(),
        ClientAuth {
            secret: "KBSWY3DPEHPK3PXQ".to_string(),
            created_at: "0".to_string(),
            last_used: Some(1),
            failed_attempts: 1,
            locked_until: None,
        },
    );

    save_auth_state(path_str, &auth).unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        !on_disk.contains("client-002"),
        "a client removed from the file must not come back"
    );
}
