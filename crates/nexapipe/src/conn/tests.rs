//! The tests of the connection half of the server.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.

use super::auth::constant_time_eq;
use super::auth::enrollment::{
    EnrollmentSlot, EnrollmentVerdict, IssuedCredential, device_taken_hint, enrollment_verdict,
    issue_enrolled_secret, undo_enrolled_secret,
};
use super::auth::state::{blocking_config_write, persist_auth_state};
use super::stream::{StreamBudgets, StreamKind, classify, read_first_bytes};
use super::{AuthState, count_enrollment_failure, find_headers_end};
use crate::auth::{AuthConfig, ClientAuth, DeviceAuth};
use nexapipe_proto::protocol::Protocol;
use nexapipe_proto::secret::SecretString;
use std::collections::HashMap;

/// The state file carries the counters as of the write, not as of an
/// earlier moment.
///
/// The write happens with the auth lock released — a lock held across a
/// disk write stalls every connection that is authenticating, not only the
/// one whose counters are being written — so the counters are read at
/// write time. A failure counted between the record and the write is
/// counted too, which is what "as of the write" means.
#[tokio::test]
async fn the_state_file_carries_the_counters_as_of_the_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\nenabled = true\n\
         [auth.clients.client-001]\n\
         secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n",
    )
    .unwrap();

    let (_, config) = crate::config::ProxyConfig::load_with_auth(path.to_str().unwrap())
        .expect("the config loads");
    let auth = AuthState::new(
        config.expect("the config declares an [auth] section"),
        path.to_str().unwrap(),
    );

    // Two failures, recorded in two separate critical sections — the
    // second one after the first has already been counted.
    for _ in 0..2 {
        let mut cfg = auth.config().write().await;
        cfg.clients
            .get_mut("client-001")
            .expect("the client is there")
            .record_failure(3, 60);
    }

    persist_auth_state(&auth)
        .await
        .expect("the state is written");

    let state = std::fs::read_to_string(dir.path().join("config.state.toml")).unwrap();
    assert!(
        state.contains("failed_attempts = 2"),
        "the file carries the count as of the write, not as of an earlier moment: {state}"
    );
}

/// The budgets a head is read under, loose enough that no test runs into
/// them by accident.
fn generous_budgets() -> StreamBudgets {
    let deadlines = crate::deadline::Deadlines {
        header: std::time::Duration::from_secs(30),
        tls_hello: std::time::Duration::from_secs(30),
        ..crate::deadline::Deadlines::default()
    };
    StreamBudgets::new(&deadlines, tokio::time::Instant::now())
}

/// The first bytes are handed on as they came.
///
/// They are not consumed: a request's first byte is part of the request,
/// and the codec that reads the head has to see it. The reader hands them
/// back, and the request path puts them in front of the rest of the
/// stream, so the head is read from the beginning.
#[tokio::test]
async fn the_first_bytes_are_handed_on_as_they_came() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _ = client
            .write_all(b"GET /x HTTP/1.1\r\nHost: a.example\r\n\r\nBODY")
            .await;
    });

    let bytes = read_first_bytes(&mut server, &generous_budgets())
        .await
        .expect("the bytes")
        .expect("the peer said something");

    assert_eq!(
        bytes,
        b"GET /x HTTP/1.1\r\nHost: a.example\r\n\r\nBODY".to_vec(),
        "the bytes were changed"
    );
}

/// A peer that says nothing at all is gone.
///
/// There is nobody to answer, and what arrived is not a request: it used
/// to be parsed as one, so half a request line became a header.
#[tokio::test]
async fn a_peer_that_says_nothing_is_gone() {
    let (client, mut server) = tokio::io::duplex(4096);
    drop(client);

    let bytes = read_first_bytes(&mut server, &generous_budgets())
        .await
        .expect("the bytes");

    assert!(bytes.is_none(), "expected no bytes at all, got {bytes:?}");
}

/// The first byte says which protocol a stream carries, and it says it
/// before any head is looked for. An L4 tunnel never sends a request head,
/// so waiting for one would hang it.
#[tokio::test]
async fn an_l4_preface_is_handed_on_without_waiting_for_a_head() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _ = client.write_all(&[0x05, 0x01, 0x01, 0x00]).await;
    });

    let bytes = read_first_bytes(&mut server, &generous_budgets())
        .await
        .expect("the bytes")
        .expect("the peer said something");

    assert_eq!(
        bytes,
        vec![0x05, 0x01, 0x01, 0x00],
        "the bytes were changed"
    );
}

/// **The protocol the connection named decides what the stream is.**
///
/// The same bytes — an L4 preface — are a tunnel on a connection that
/// named the L4 protocol, and a request that is not one on a connection
/// that named the HTTP one. A connection that named nothing is served the
/// way it always was: the first byte decides, and this first byte says
/// L4.
///
/// This is the whole point of choosing the protocol at the handshake: the
/// server does not have to guess, and a stream that is not what the
/// connection said it is does not get served as if it were.
#[test]
fn the_named_protocol_decides_what_the_stream_is() {
    let preface = b"\x05\x01\x01\x00";

    // A connection that named L4 is a tunnel.
    assert_eq!(classify(Protocol::L4, preface), StreamKind::L4);

    // A connection that named TLS is a TLS session.
    assert_eq!(classify(Protocol::Tls, preface), StreamKind::Tls);

    // A connection that named HTTP is a request — even when the bytes say
    // otherwise, because that connection is not going to be sent a tunnel.
    assert_eq!(classify(Protocol::Http, preface), StreamKind::Request);

    // A connection that named nothing is served the way it always was:
    // the first byte decides, and this first byte says L4.
    assert_eq!(classify(Protocol::Legacy, preface), StreamKind::L4);

    // A ClientHello is a TLS session.
    assert_eq!(
        classify(Protocol::Legacy, &[0x16, 0x03, 0x01]),
        StreamKind::Tls
    );

    // And a request line is a request.
    assert_eq!(
        classify(Protocol::Legacy, b"GET / HTTP/1.1\r\n"),
        StreamKind::Request
    );
}

#[test]
fn a_short_head_budget_does_not_cut_off_a_tls_or_l4_client() {
    // The observation this test exists for: the first byte says which
    // protocol a stream carries, and the wait for it must not be the HTTP
    // head's budget. A short `header_secs` used to close a TLS or an L4
    // stream before it could be classified, which took the tunnel down
    // with it — and neither protocol ever sends a request head, so the
    // head's budget was never the right one for them.
    let deadlines = crate::deadline::Deadlines {
        header: std::time::Duration::from_secs(1),
        tls_hello: std::time::Duration::from_secs(10),
        ..crate::deadline::Deadlines::default()
    };
    let open = tokio::time::Instant::now();
    let budgets = StreamBudgets::new(&deadlines, open);

    assert_eq!(
        budgets.identify_budget(),
        std::time::Duration::from_secs(10),
        "the first byte is bounded by the hello budget, not the head's"
    );
    assert_eq!(
        budgets.head - open,
        std::time::Duration::from_secs(1),
        "the head itself is still bounded by header_secs"
    );
}

#[test]
fn the_default_budgets_leave_an_http_client_the_room_it_had() {
    // The other half: with the defaults the first byte waits exactly as
    // long as it did before, so nothing about an ordinary HTTP client
    // changes.
    let deadlines = crate::deadline::Deadlines::default();
    let open = tokio::time::Instant::now();
    let budgets = StreamBudgets::new(&deadlines, open);

    assert_eq!(budgets.identify_budget(), deadlines.header);
    assert_eq!(budgets.head - open, deadlines.header);
}

/// The shape an enrollment takes when the client named a device and offered
/// no key: a secret of that device's own.
fn device_secret(name: &str, secret: &str) -> IssuedCredential {
    IssuedCredential::DeviceSecret {
        name: name.to_string(),
        secret: SecretString::new(secret.to_string()),
    }
}

/// A write whose caller gave up still happens, and happens *first*.
///
/// The abandoned write is slow on purpose, so the only way the second one
/// can end up last in the file is for it to have waited: without the gate
/// the two overlap and whichever reaches the disk last wins, which is a
/// lockout counter or an issued secret quietly disappearing.
#[tokio::test]
async fn an_abandoned_write_still_lands_before_the_next_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "start\n").expect("seed the file");
    let slow_path = path.to_string_lossy().into_owned();
    let fast_path = slow_path.clone();

    let abandoned = tokio::spawn(async move {
        let _ = blocking_config_write(slow_path, |path| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            std::fs::write(path, "slow\n").map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await;
    });

    // Give it a start, then walk away the way a cancelled handshake does.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    abandoned.abort();

    blocking_config_write(fast_path, |path| {
        std::fs::write(path, "fast\n").map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await
    .expect("the second write runs");

    let on_disk = std::fs::read_to_string(&path).expect("read the file");
    assert_eq!(on_disk, "fast\n", "the slow write was ordered before it");
}

/// The marker only ever appears once a read has brought in its last byte,
/// and the scan starts where the previous read left off — three bytes back,
/// because a marker split across two reads has to still be found.
#[test]
fn a_header_marker_split_across_reads_is_still_found() {
    let head = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";

    // Everything up to the last three bytes has been scanned already.
    let mut buf = Vec::new();
    let mut searched = 0;
    let mut found = None;
    for chunk in head.chunks(7) {
        buf.extend_from_slice(chunk);
        if let Some(pos) = find_headers_end(&buf, searched) {
            found = Some(pos);
            break;
        }
        searched = buf.len().saturating_sub(3);
    }

    assert_eq!(
        found.map(|pos| pos + 4),
        Some(head.len()),
        "the marker was missed when it arrived in pieces"
    );
}

#[test]
fn a_buffer_without_the_marker_is_not_a_head() {
    assert_eq!(
        find_headers_end(b"GET / HTTP/1.1\r\nHost: a.test\r\n", 0),
        None
    );
    // Nothing to scan: a read that brought no bytes cannot have completed
    // the marker either.
    assert_eq!(find_headers_end(b"", 0), None);
    assert_eq!(find_headers_end(b"\r\n", 40), None);
}

/// A config holding one client, with `token` left outstanding for it.
fn auth_with_pending(token: Option<&str>) -> AuthConfig {
    let mut cfg = AuthConfig::default();
    cfg.clients.insert(
        "alice".to_string(),
        ClientAuth {
            secret: SecretString::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
            created_at: "0".to_string(),
            allow_hosts: None,
            allow_ports: None,
            allow_ports_strict: false,
            pending_enrollment: token.map(|t| SecretString::new(t.to_string())),
            devices: HashMap::new(),
            unnamed_device_allowed: true,
            last_used: None,
            last_used_step: None,
            failed_attempts: 0,
            locked_until: None,
            enrollment_failed_attempts: 0,
            enrollment_locked_until: None,
        },
    );
    cfg
}

/// The comparison is what stands between a token and whoever copied the
/// link, so it has to be right at the boundaries: equal, wrong at the first
/// byte, wrong at the last, and the wrong length.
#[test]
fn token_comparison_only_accepts_an_exact_match() {
    let token = "0123456789abcdef";
    assert!(constant_time_eq(token.as_bytes(), token.as_bytes()));
    assert!(!constant_time_eq(
        token.as_bytes(),
        "1123456789abcdef".as_bytes()
    ));
    assert!(!constant_time_eq(
        token.as_bytes(),
        "0123456789abcdeF".as_bytes()
    ));
    assert!(!constant_time_eq(
        token.as_bytes(),
        "0123456789abcdef0".as_bytes()
    ));
    assert!(!constant_time_eq(token.as_bytes(), b""));
    // Two empty tokens compare equal, which is why a client with no token
    // outstanding must not be enrolled at all rather than compared here.
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn an_outstanding_token_is_accepted() {
    let cfg = auth_with_pending(Some("0123456789abcdef"));
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcdef", None, None),
        EnrollmentVerdict::Accept
    );
}

/// An enrollment that names a device writes that device's own entry and
/// leaves the client's `secret` alone: the two are different credentials,
/// and rotating the shared one is what re-enrolls every device at once.
#[test]
fn an_enrollment_that_names_a_device_writes_only_its_own_entry() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));
    let shared = cfg.clients["alice"].secret.clone();

    let slot = issue_enrolled_secret(
        &mut cfg,
        "alice",
        &device_secret("laptop", "LAPTOPSECRETLAPTOPSECRETLAPTOPSE"),
    );

    let alice = &cfg.clients["alice"];
    assert_eq!(
        alice.secret.expose_secret(),
        shared.expose_secret(),
        "the shared secret was rotated too"
    );
    assert_eq!(
        alice.devices["laptop"].secret.as_str(),
        "LAPTOPSECRETLAPTOPSECRETLAPTOPSE"
    );
    assert!(
        alice.pending_enrollment.is_none(),
        "the token was left spendable"
    );
    assert!(matches!(slot, EnrollmentSlot::Device { .. }));
}

/// A key enrollment records the key and nothing else: the empty secret is
/// what keeps the handshake from ever asking this device for a code, so an
/// entry carrying both would be the one thing the loader refuses to read
/// back.
#[test]
fn a_key_enrollment_records_the_key_and_no_secret() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));
    let key = iroh::SecretKey::generate();
    let spelled = crate::auth::public_key_hex(&key.public());

    let slot = issue_enrolled_secret(
        &mut cfg,
        "alice",
        &IssuedCredential::DeviceKey {
            name: "phone".to_string(),
            key: spelled.clone(),
        },
    );

    let device = &cfg.clients["alice"].devices["phone"];
    assert_eq!(device.public_key.as_deref(), Some(spelled.as_str()));
    assert!(
        device.secret.expose_secret().is_empty(),
        "a key device has no TOTP seed"
    );
    assert!(matches!(slot, EnrollmentSlot::Device { .. }));
}

/// The path that existed before there was a table: no name is the device
/// that has none, and it answers with the client's own `secret`.
#[test]
fn an_enrollment_that_names_no_device_rotates_the_clients_secret() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));

    let slot = issue_enrolled_secret(
        &mut cfg,
        "alice",
        &IssuedCredential::SharedSecret(SecretString::new(
            "NEWSECRETNEWSECRETNEWSECRETNEWSE".to_string(),
        )),
    );

    assert_eq!(
        cfg.clients["alice"].secret.as_str(),
        "NEWSECRETNEWSECRETNEWSECRETNEWSE"
    );
    assert!(cfg.clients["alice"].devices.is_empty());
    assert!(matches!(slot, EnrollmentSlot::Shared { .. }));
}

/// What the rollback is for: a device that was enrolled before keeps the
/// credential it had, because the write that was to replace it failed and
/// the new secret exists nowhere but in this process's memory.
#[test]
fn a_failed_write_puts_the_device_it_replaced_back() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));
    cfg.clients.get_mut("alice").unwrap().devices.insert(
        "laptop".to_string(),
        DeviceAuth {
            secret: SecretString::new("OLDSECRETOLDSECRETOLDSECRETOLDSE".to_string()),
            public_key: None,
            created_at: "0".to_string(),
            last_used: None,
            last_used_step: None,
        },
    );

    let slot = issue_enrolled_secret(
        &mut cfg,
        "alice",
        &device_secret("laptop", "NEWSECRETNEWSECRETNEWSECRETNEWSE"),
    );
    assert_eq!(
        cfg.clients["alice"].devices["laptop"].secret.as_str(),
        "NEWSECRETNEWSECRETNEWSECRETNEWSE"
    );

    undo_enrolled_secret(&mut cfg, "alice", slot, "0123456789abcdef");

    let alice = &cfg.clients["alice"];
    assert_eq!(
        alice.devices["laptop"].secret.as_str(),
        "OLDSECRETOLDSECRETOLDSECRETOLDSE"
    );
    assert_eq!(
        alice
            .pending_enrollment
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("0123456789abcdef"),
        "the token is still the client's only way to enroll"
    );
}

/// The same, for a device that had no entry: taking back the credential
/// means removing it, not leaving a device behind that no config on disk
/// carries.
#[test]
fn a_failed_write_takes_back_a_device_that_had_no_entry() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));

    let slot = issue_enrolled_secret(
        &mut cfg,
        "alice",
        &device_secret("phone", "NEWSECRETNEWSECRETNEWSECRETNEWSE"),
    );
    undo_enrolled_secret(&mut cfg, "alice", slot, "0123456789abcdef");

    let alice = &cfg.clients["alice"];
    assert!(alice.devices.is_empty(), "{:?}", alice.devices.keys());
}

/// The unnamed path rolls back to the secret it rotated away, or this
/// process would keep accepting a credential that is on no disk.
#[test]
fn a_failed_write_puts_the_clients_secret_back() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));
    let shared = cfg.clients["alice"].secret.clone();

    let slot = issue_enrolled_secret(
        &mut cfg,
        "alice",
        &IssuedCredential::SharedSecret(SecretString::new(
            "NEWSECRETNEWSECRETNEWSECRETNEWSE".to_string(),
        )),
    );
    undo_enrolled_secret(&mut cfg, "alice", slot, "0123456789abcdef");

    assert_eq!(cfg.clients["alice"].secret, shared);
}

/// The token is a credential like any other: guessing at it has to cost
/// the same as guessing a TOTP code, or the link is a slower credential
/// with no ceiling on how many times it can be tried.
#[test]
fn a_wrong_token_is_refused_and_counted() {
    let cfg = auth_with_pending(Some("0123456789abcdef"));
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcde0", None, None),
        EnrollmentVerdict::Refuse { counted: true }
    );
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "", None, None),
        EnrollmentVerdict::Refuse { counted: true }
    );
}

/// **What the counting costs is the enrollment's own counter.**
///
/// A client id is not a secret: it is in the invite link, in `nexapipe
/// client list` and in whatever the operator pasted into a ticket. So
/// anybody who knows one can send enrollment attempts at a client that is
/// waiting to enroll — and while those attempts were counted against the
/// client's authentication counter, the devices that had already enrolled
/// were locked out over a credential they were never sent.
#[test]
fn a_wrong_token_is_counted_against_the_enrollment_and_not_the_client() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));

    count_enrollment_failure(&mut cfg, "alice", 5, 300);

    let alice = &cfg.clients["alice"];
    assert_eq!(
        alice.enrollment_failed_attempts, 1,
        "the token's own counter moved"
    );
    assert_eq!(
        alice.failed_attempts, 0,
        "the client's authentication counter did not: a client id is not a secret, and \
         somebody who knows one must not be able to lock the client's own devices out"
    );
    assert_eq!(alice.locked_until, None, "the client is not locked out");
    assert!(!alice.is_locked_out());
}

/// The token keeps a ceiling: `max_attempts` wrong guesses close the
/// enrollment slot for the window, and the right token is refused with it.
///
/// The ceiling is what makes the link unguessable rather than merely
/// unshared — and it is the enrollment's ceiling, not the client's.
#[test]
fn the_token_has_a_ceiling_of_its_own() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));

    for _ in 0..3 {
        count_enrollment_failure(&mut cfg, "alice", 3, 300);
    }

    let alice = &cfg.clients["alice"];
    assert!(alice.is_enrollment_locked_out(), "the slot is closed");
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcdef", None, None),
        EnrollmentVerdict::Refuse { counted: false },
        "even the right token is refused while the slot is closed"
    );
    assert!(
        !alice.is_locked_out(),
        "the client itself is not locked out: the devices that already enrolled go on \
         authenticating"
    );
    assert_eq!(alice.failed_attempts, 0);
}

/// A lockout whose time has run out is cleared, so the first mistake after
/// it does not close the slot again immediately.
#[test]
fn an_expired_enrollment_lockout_is_cleared() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));

    let alice = cfg.clients.get_mut("alice").unwrap();
    alice.enrollment_failed_attempts = 3;
    alice.enrollment_locked_until = Some(1);
    assert!(!alice.is_enrollment_locked_out(), "the window has run out");

    alice.refresh_enrollment_lockout();
    assert_eq!(alice.enrollment_failed_attempts, 0);
    assert_eq!(alice.enrollment_locked_until, None);
}

/// A client with no token outstanding is refused without being counted:
/// counting it would let anyone who knows a client id lock that client out
/// of its own authentication by sending it enrollment requests.
#[test]
fn a_client_with_nothing_pending_is_refused_without_being_counted() {
    let cfg = auth_with_pending(None);
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcdef", None, None),
        EnrollmentVerdict::Refuse { counted: false }
    );
}

#[test]
fn an_unknown_client_is_refused_without_being_counted() {
    let cfg = auth_with_pending(Some("0123456789abcdef"));
    assert_eq!(
        enrollment_verdict(&cfg, "bob", "0123456789abcdef", None, None),
        EnrollmentVerdict::Refuse { counted: false }
    );
}

/// A locked-out client is refused before the token is looked at, so a
/// lockout cannot be walked around by enrolling — and retrying does not
/// push the lockout further out.
#[test]
fn a_locked_out_client_is_refused_even_with_the_right_token() {
    let mut cfg = auth_with_pending(Some("0123456789abcdef"));
    cfg.clients.get_mut("alice").unwrap().locked_until = Some(u64::MAX);
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcdef", None, None),
        EnrollmentVerdict::Refuse { counted: false }
    );
}

/// The runtime half of the empty-token rule: `constant_time_eq` answers
/// true for two empty slices, so a blank token on both sides has to be
/// refused on the way in rather than compared.
#[test]
fn a_blank_pending_token_is_never_accepted() {
    let cfg = auth_with_pending(Some(""));
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "", None, None),
        EnrollmentVerdict::Refuse { counted: false }
    );
}

/// A device that is already in the table keeps its credential.
///
/// The token proves the invite reached someone, not which device it
/// reached — the name is supplied by the client at enrollment time — so
/// overwriting the entry handed a device that is already enrolled to
/// whoever copied the link: the real device is locked out, while the access
/// log and the peer list go on attributing the connection to it.
#[test]
fn an_enrollment_may_not_take_over_a_device_that_is_already_there() {
    let cfg = auth_with_device("laptop", Some("0123456789abcdef"));
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcdef", Some("laptop"), None),
        EnrollmentVerdict::Refuse { counted: false }
    );
}

/// The same table, a name that is not in it: an enrollment is how a device
/// that is not there yet gets one, and refusing those would make the table
/// impossible to grow past the first device.
#[test]
fn an_enrollment_may_still_add_a_device_that_is_not_there() {
    let cfg = auth_with_device("laptop", Some("0123456789abcdef"));
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcdef", Some("phone"), None),
        EnrollmentVerdict::Accept
    );
    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcdef", None, None),
        EnrollmentVerdict::Accept
    );
}

/// Refused for the right reason: it is not a guess at the token, so it must
/// not move the lockout counter. Counting it would let whoever is holding a
/// copied link lock the client out with retries.
#[test]
fn taking_over_a_device_is_not_counted_as_a_wrong_token() {
    let cfg = auth_with_device("laptop", Some("0123456789abcdef"));
    assert!(!enrollment_verdict(&cfg, "alice", "0123456789abcdef", Some("laptop"), None).counted());
}

/// The hint the operator gets names the command that unblocks the enrollment.
///
/// The refusal is about the name being taken, so a command that only replaces
/// the credential filed under that name leaves the next enrollment refused
/// exactly the same way — and the hint used to name exactly that command.
#[test]
fn the_refusal_hint_names_the_command_that_unblocks_the_enrollment() {
    let hint = device_taken_hint("xm17", "phone");
    assert!(
        hint.contains("nexapipe client revoke xm17 --device phone"),
        "{hint}"
    );
}

/// A device that still holds the key the table records may enroll again.
///
/// This is the device coming back for a credential it lost — the answer it was
/// given was never written down, so it asked again with the same key. The
/// enrollment records that same key under the same name, which leaves the
/// device holding the private half working and gives the one that does not
/// nothing.
#[test]
fn a_device_that_holds_the_key_on_file_may_enroll_again() {
    let key = iroh::SecretKey::generate();
    let hex = crate::auth::public_key_hex(&key.public());
    let cfg = auth_with_device_key("phone", &hex, Some("0123456789abcdef"));

    assert_eq!(
        enrollment_verdict(&cfg, "alice", "0123456789abcdef", Some("phone"), Some(&hex)),
        EnrollmentVerdict::Accept
    );
}

/// A different key is somebody else: the name belongs to the device that holds
/// the key on file, and a copied link must not be able to take it over.
#[test]
fn a_device_that_offers_a_different_key_is_still_refused() {
    let stored = iroh::SecretKey::generate();
    let offered = iroh::SecretKey::generate();
    let cfg = auth_with_device_key(
        "phone",
        &crate::auth::public_key_hex(&stored.public()),
        Some("0123456789abcdef"),
    );

    assert_eq!(
        enrollment_verdict(
            &cfg,
            "alice",
            "0123456789abcdef",
            Some("phone"),
            Some(&crate::auth::public_key_hex(&offered.public()))
        ),
        EnrollmentVerdict::Refuse { counted: false }
    );
}

/// A row that holds a secret is a device that proves itself with a code: it is
/// not the device that offered a key, so the name stays where it is.
#[test]
fn a_device_that_holds_a_secret_may_not_enroll_again_with_a_key() {
    let offered = iroh::SecretKey::generate();
    let cfg = auth_with_device("laptop", Some("0123456789abcdef"));

    assert_eq!(
        enrollment_verdict(
            &cfg,
            "alice",
            "0123456789abcdef",
            Some("laptop"),
            Some(&crate::auth::public_key_hex(&offered.public()))
        ),
        EnrollmentVerdict::Refuse { counted: false }
    );
}

/// The key is compared in the spelling the table stores, so a key that arrives
/// in another one is the same key and not a different one.
#[test]
fn the_same_key_in_another_spelling_is_the_same_key() {
    let key = iroh::SecretKey::generate();
    let hex = crate::auth::public_key_hex(&key.public());
    let cfg = auth_with_device_key("phone", &hex, Some("0123456789abcdef"));

    assert_eq!(
        enrollment_verdict(
            &cfg,
            "alice",
            "0123456789abcdef",
            Some("phone"),
            Some(&hex.to_uppercase())
        ),
        EnrollmentVerdict::Accept
    );
}

/// A config holding one client, with `token` left outstanding for it and
/// `device` already enrolled under it.
fn auth_with_device(device: &str, token: Option<&str>) -> AuthConfig {
    let mut cfg = auth_with_pending(token);
    cfg.clients.get_mut("alice").unwrap().devices.insert(
        device.to_string(),
        DeviceAuth {
            secret: SecretString::new("DEVICESECRETDEVICESECRETDEVICESE".to_string()),
            public_key: None,
            created_at: "0".to_string(),
            last_used: None,
            last_used_step: None,
        },
    );
    cfg
}

/// The same, for a device that proves itself with a key rather than a code.
fn auth_with_device_key(device: &str, public_key: &str, token: Option<&str>) -> AuthConfig {
    let mut cfg = auth_with_pending(token);
    cfg.clients.get_mut("alice").unwrap().devices.insert(
        device.to_string(),
        DeviceAuth {
            secret: SecretString::default(),
            public_key: Some(public_key.to_string()),
            created_at: "0".to_string(),
            last_used: None,
            last_used_step: None,
        },
    );
    cfg
}
