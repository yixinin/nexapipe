//! The tests of the configuration watcher.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.
use super::*;
/// A file written twice inside one second has the same time and a
/// different length — and it is a different file.
#[test]
fn a_file_written_twice_inside_one_second_is_a_change() {
    let time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let state = WatchState::new(
        FileStamp {
            modified: time,
            len: 10,
        },
        Instant::now(),
    );
    let now = Instant::now();

    assert!(
        !state.should_load(
            FileStamp {
                modified: time,
                len: 10
            },
            now
        ),
        "the same file is not a change"
    );
    assert!(
        state.should_load(
            FileStamp {
                modified: time,
                len: 11
            },
            now
        ),
        "a different length is a change, time or not"
    );
}

/// A file that replaced another one — restored from a backup, checked out
/// by `git` — can be *older* than the one it replaces.
#[test]
fn an_older_file_is_still_a_change() {
    let older = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(50);
    let newer = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let state = WatchState::new(
        FileStamp {
            modified: newer,
            len: 10,
        },
        Instant::now(),
    );

    assert!(
        state.should_load(
            FileStamp {
                modified: older,
                len: 10
            },
            Instant::now()
        ),
        "an older file is a different file"
    );
}

/// A file that failed to load is tried again.
///
/// The old behaviour advanced the stamp before the reload ran, so a file
/// that was read too early — half-written — was never tried again, and the
/// server kept the routes it had for ever.
#[test]
fn a_failed_load_is_tried_again() {
    let time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let mut state = WatchState::new(
        FileStamp {
            modified: time,
            len: 10,
        },
        Instant::now(),
    );
    let now = Instant::now();
    let half_written = FileStamp {
        modified: time,
        len: 11,
    };

    assert!(
        state.should_load(half_written, now),
        "the change is noticed"
    );
    state.failed(now);

    assert!(
        !state.should_load(half_written, now),
        "not straight away: the backoff"
    );
    assert!(
        state.should_load(half_written, now + POLL_INTERVAL),
        "and again once the backoff is over"
    );
}

/// The wait grows after every failure, and it stops growing.
///
/// A file that is wrong stays wrong, and a log line every five seconds for
/// ever is not a thing anyone wants to read.
#[test]
fn the_retry_backoff_grows_and_is_capped() {
    let time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let mut state = WatchState::new(
        FileStamp {
            modified: time,
            len: 10,
        },
        Instant::now(),
    );
    let now = Instant::now();

    state.failed(now);
    assert_eq!(
        state.retry_delay, POLL_INTERVAL,
        "the first wait is one tick"
    );

    state.failed(now + POLL_INTERVAL);
    assert_eq!(
        state.retry_delay,
        POLL_INTERVAL * 2,
        "the second wait is twice as long"
    );

    for _ in 0..20 {
        state.failed(now);
    }
    assert_eq!(
        state.retry_delay, MAX_RETRY_DELAY,
        "the wait stops growing at the cap"
    );
}

/// A load that worked is remembered, so the same file is not loaded again.
#[test]
fn a_loaded_file_is_not_loaded_again() {
    let time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let stamp = FileStamp {
        modified: time,
        len: 10,
    };
    let mut state = WatchState::new(FileStamp::UNKNOWN, Instant::now());
    let now = Instant::now();

    assert!(
        state.should_load(stamp, now),
        "a file that was never loaded is loaded"
    );
    state.loaded(stamp, now);

    assert!(
        !state.should_load(stamp, now),
        "and not again until it changes"
    );
}

use crate::auth::{ClientAuth, DeviceAuth};
use crate::conn::peers::PeerIdentity;
use nexapipe_proto::secret::SecretString;

fn client(secret: &str) -> ClientAuth {
    ClientAuth {
        secret: SecretString::new(secret.to_string()),
        created_at: "0".to_string(),
        allow_hosts: None,
        allow_ports: None,
        allow_ports_strict: false,
        pending_enrollment: None,
        devices: HashMap::new(),
        unnamed_device_allowed: true,
        last_used: None,
        last_used_step: None,
        failed_attempts: 0,
        locked_until: None,
        enrollment_failed_attempts: 0,
        enrollment_locked_until: None,
    }
}

fn device(secret: &str) -> DeviceAuth {
    DeviceAuth {
        secret: SecretString::new(secret.to_string()),
        public_key: None,
        created_at: "0".to_string(),
        last_used: None,
        last_used_step: None,
    }
}

/// A reload does not take the step memory away.
///
/// The step memory is what refuses the second use of a code, so a reload
/// that put an older value back would hand the replay protection away
/// without saying so. The live value is moved forward by every
/// acceptance, and the file is written after the lock is released — so a
/// reload that lands in that window reads a file that is one step behind
/// memory, and the merge has to keep the newer of the two.
#[test]
fn a_reload_keeps_the_step_memory() {
    let mut live = config_with(&[("phone", client("s"))]);
    let incoming = config_with(&[("phone", client("s"))]);

    // The live server has accepted a code at step 100 and written it
    // down; the file it is reading still says nothing, because the write
    // has not happened yet.
    live.clients.get_mut("phone").unwrap().last_used_step = Some(100);

    merge_auth_clients(&mut live, &incoming);

    assert_eq!(
        live.clients.get("phone").unwrap().last_used_step,
        Some(100),
        "the step memory survives a reload that read a file without it"
    );
}

/// A device's own step memory survives a reload too.
///
/// A device's credential is its own, and a device that authenticated with
/// a code must not lose that by a reload any more than the client it
/// belongs to does.
#[test]
fn a_reload_keeps_a_device_s_step_memory() {
    let mut live_client = client("s");
    let mut live_device = device("d");
    live_device.last_used_step = Some(100);
    live_client
        .devices
        .insert("laptop".to_string(), live_device);

    let mut incoming_client = client("s");
    let incoming_device = device("d");
    incoming_client
        .devices
        .insert("laptop".to_string(), incoming_device);

    let mut live = config_with(&[("phone", live_client)]);
    let incoming = config_with(&[("phone", incoming_client)]);

    merge_auth_clients(&mut live, &incoming);

    assert_eq!(
        live.clients
            .get("phone")
            .and_then(|c| c.devices.get("laptop"))
            .and_then(|d| d.last_used_step),
        Some(100),
        "the device's step memory survives a reload that read a file without it"
    );
}

/// `removed_devices` is the detection half of revocation: a device struck
/// out of the file while its client survives is the only case the
/// client-level pass cannot see, so what it reports is what a reload then
/// closes. Every case below is one an operator reaches by hand-editing —
/// `nexapipe client revoke --device` writes exactly this diff.
fn removed_devices_of(
    before: &[(&str, &[&str])],
    after: &[(&str, &[(&str, &str)])],
) -> Vec<(String, String)> {
    let before: HashMap<String, Vec<String>> = before
        .iter()
        .map(|(id, devices)| {
            (
                id.to_string(),
                devices.iter().map(|name| name.to_string()).collect(),
            )
        })
        .collect();
    let after: HashMap<String, ClientAuth> = after
        .iter()
        .map(|(id, devices)| {
            let mut client = client("SECRETSECRETSECRSECRETSECRETSECR");
            client.devices = devices
                .iter()
                .map(|(name, secret)| (name.to_string(), device(secret)))
                .collect();
            (id.to_string(), client)
        })
        .collect();
    let mut removed = ConfigWatcher::removed_devices(&before, &after);
    removed.sort();
    removed
}

#[test]
fn a_device_struck_out_of_a_surviving_client_is_reported() {
    assert_eq!(
        removed_devices_of(
            &[("alice", &["laptop", "phone"])],
            &[("alice", &[("phone", "P")])]
        ),
        vec![("alice".to_string(), "laptop".to_string())]
    );
}

#[test]
fn a_device_that_moved_to_another_client_is_reported_where_it_was() {
    assert_eq!(
        removed_devices_of(
            &[("alice", &["laptop"]), ("bob", &[])],
            &[("alice", &[]), ("bob", &[("laptop", "L")])]
        ),
        vec![("alice".to_string(), "laptop".to_string())]
    );
}

#[test]
fn a_renamed_device_reports_the_old_name_only() {
    assert_eq!(
        removed_devices_of(
            &[("alice", &["laptop"])],
            &[("alice", &[("laptop-2", "L")])]
        ),
        vec![("alice".to_string(), "laptop".to_string())]
    );
}

/// A client that is gone takes every device under it with it, and those
/// connections are already closed by the client-level pass. Counting them
/// here too would close the same connection twice.
#[test]
fn a_client_that_disappeared_reports_no_devices() {
    assert!(
        removed_devices_of(
            &[("alice", &["laptop", "phone"])],
            &[("bob", &[("laptop", "L")])]
        )
        .is_empty()
    );
}

#[test]
fn an_unchanged_table_reports_nothing() {
    assert!(
        removed_devices_of(
            &[("alice", &["laptop", "phone"])],
            &[("alice", &[("laptop", "L"), ("phone", "P")])]
        )
        .is_empty()
    );
}

/// The empty case: no devices anywhere is the pre-0.6.0 shape, and a
/// reload of it must not invent a revocation.
#[test]
fn a_table_with_no_devices_reports_nothing() {
    assert!(removed_devices_of(&[("alice", &[])], &[("alice", &[])]).is_empty());
}

fn config_with(clients: &[(&str, ClientAuth)]) -> AuthConfig {
    let mut config = AuthConfig::default();
    for (id, client) in clients {
        config.clients.insert(id.to_string(), client.clone());
    }
    config
}

/// A watcher over a config file, with the 2FA state it guards.
fn watcher_for(state: AuthState, path: &str) -> ConfigWatcher {
    watcher_with_peers(state, path, Arc::new(PeerRegistry::new()))
}

/// A watcher over a config file, with the 2FA state it guards and the peer
/// registry its revocations reach.
///
/// The registry is handed in rather than made here, because what most of the
/// tests below are about is which connections a reload reaches — and that is
/// only visible from the registry the reload closes through.
fn watcher_with_peers(state: AuthState, path: &str, peers: Arc<PeerRegistry>) -> ConfigWatcher {
    ConfigWatcher::new(
        path.to_string(),
        Arc::new(RoutingTable::new(Vec::new())),
        Arc::new(
            crate::http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                .expect("the default trust store is always usable"),
        ),
        Arc::new(Mutex::new(HealthProbes::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        Some(state),
        peers,
    )
}

/// A connection in the registry, the way the handshake registers one, and the
/// channel that says it was told to stop.
///
/// The identity is what tells the connections apart: one that authenticated
/// carries the client id it authenticated as, and one that never did carries
/// none.
fn connected(
    peers: &PeerRegistry,
    seed: u8,
    identity: PeerIdentity,
) -> (
    tokio::sync::watch::Receiver<bool>,
    crate::conn::peers::PeerGuard,
) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let guard = peers.insert(
        iroh::SecretKey::from_bytes(&[seed; 32]).public(),
        crate::metrics::PathKind::Direct,
        identity,
        tx,
    );
    (rx, guard)
}

/// A snapshot the caller read is merged as it is, and the file is not read
/// again.
///
/// The read is outside the lock now — that is the point of the change — and
/// the file is not read under it at all, so the lock is not held across a
/// disk read while every handshake and every lockout write waits for it.
///
/// The file names one client and the snapshot names another, so a read
/// would show: the file's client would end up live instead of the
/// snapshot's.
#[tokio::test]
async fn a_snapshot_is_merged_without_reading_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILEFROMTHEFILEFROMTHEFIL\"\n",
    )
    .unwrap();
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = watcher_for(state.clone(), &path);

    watcher
        .reload_auth(
            Some(config_with(&[(
                "from-the-snapshot",
                client("FROMTHESNAPSHOTFROMTHESNAPSHOTFR"),
            )])),
            state.enroll_epoch(),
        )
        .await;

    let live = state.config().read().await;
    assert!(
        live.clients.contains_key("from-the-snapshot"),
        "the snapshot was merged"
    );
    assert!(
        !live.clients.contains_key("from-the-file"),
        "the file was read, and its client is live instead of the snapshot's"
    );
}

/// A snapshot that an enrollment made stale is not merged.
///
/// The enrollment spends a token by changing the live state and only then
/// writing the change back, so a snapshot taken a moment earlier still
/// carries the spent token and the pre-enrollment secret. Merging it would
/// hand out a token that was already used and undo the secret the
/// enrollment just issued.
///
/// So the epoch is sampled before the read and compared under the lock, and
/// a snapshot that has been overtaken is read again.
#[tokio::test]
async fn a_snapshot_an_enrollment_made_stale_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    // The file names one client and the snapshot names another.
    std::fs::write(
        &path,
        "[auth]\nenabled = true\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILEFROMTHEFILEFROMTHEFIL\"\n",
    )
    .unwrap();
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = watcher_for(state.clone(), &path);

    // An enrollment lands after the snapshot was taken: the epoch moves.
    state.bump_enroll_epoch();

    assert!(
        watcher
            .reload_auth(
                Some(config_with(&[(
                    "from-the-snapshot",
                    client("FROMTHESNAPSHOTFROMTHESNAPSHOTFR"),
                )])),
                // The epoch as it was when the snapshot was taken.
                state.enroll_epoch() - 1,
            )
            .await,
        "the snapshot the second read produced was merged"
    );

    let live = state.config().read().await;
    assert!(
        !live.clients.contains_key("from-the-snapshot"),
        "the stale snapshot was merged over the top of the enrollment"
    );
    assert!(
        live.clients.contains_key("from-the-file"),
        "the file was read again, and the client it names is live"
    );
}

/// A re-read that fails is reported as not applied.
///
/// The first read already happened when the overtake is noticed, and the
/// file can be gone or half-written by the time the second one runs. An
/// auth half that was never merged must not be recorded as loaded, or the
/// edit waits until somebody touches the file again.
#[tokio::test]
async fn a_reload_whose_second_read_fails_is_tried_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILEFROMTHEFILEFROMTHEFIL\"\n",
    )
    .unwrap();
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = watcher_for(state.clone(), &path);

    // The snapshot is stale, so the reload reads again — and there is
    // nothing left to read.
    state.bump_enroll_epoch();
    std::fs::remove_file(&path).unwrap();

    assert!(
        !watcher
            .reload_auth(
                Some(config_with(&[(
                    "from-the-snapshot",
                    client("FROMTHESNAPSHOTFROMTHESNAPSHOTFR"),
                )])),
                state.enroll_epoch() - 1,
            )
            .await,
        "an auth half that was not merged is not reported as applied"
    );
}

/// The two halves of the file come from one read.
///
/// Two reads could hand the routes one revision of the file and the 2FA
/// clients another, and a change made between them would be half-applied.
#[tokio::test]
async fn a_reload_applies_both_halves_of_one_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[[routes]]\nhost_pattern = \"app.test\"\nbackends = [\"http://127.0.0.1:1\"]\n\n\
         [auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n",
    )
    .unwrap();
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = watcher_for(state.clone(), &path);

    watcher.reload_config().await;

    let live = state.config().read().await;
    assert!(
        live.clients.contains_key("client-001"),
        "the auth half of the file was applied"
    );
    assert!(
        watcher
            .route_config
            .routes()
            .await
            .iter()
            .any(|r| r.host_pattern() == "app.test"),
        "the routes half of the same read was applied"
    );
}

/// The whole point of the merge: an invite written by `--generate-invite`
/// in another process becomes spendable on the running server without a
/// restart, and a client deleted from the file stops authenticating.
#[test]
fn a_reload_picks_up_an_invited_client_and_drops_a_removed_one() {
    let mut live = config_with(&[("old", client("OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL"))]);
    let incoming = config_with(&[
        ("old", client("OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOL")),
        ("new", client("NEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNE")),
    ]);

    let (added, removed, _rotated) = merge_auth_clients(&mut live, &incoming);

    assert_eq!(added, vec!["new".to_string()]);
    assert!(removed.is_empty());
    assert_eq!(live.clients.len(), 2);
    assert_eq!(
        live.clients["new"].secret.as_str(),
        "NEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNE"
    );

    let (added, removed, _rotated) = merge_auth_clients(&mut live, &config_with(&[]));

    assert!(added.is_empty());
    // HashMap order is per-process, so compare the removed set, not a sequence.
    let mut removed = removed;
    removed.sort();
    assert_eq!(removed, vec!["new".to_string(), "old".to_string()]);
    assert!(live.clients.is_empty());
}

/// A rotated secret (`--generate-2fa --force`, or a spent enrollment) takes
/// over, but the lockout counters the server has been maintaining in
/// memory are not reset by the reload — the file's copy may be stale.
#[test]
fn a_surviving_client_keeps_its_counters_and_takes_the_files_secret() {
    let mut live = config_with(&[("client-001", client("OLDSECRETVALUEOLDSECRETVALUEOLDS"))]);
    let existing = live.clients.get_mut("client-001").unwrap();
    existing.failed_attempts = 2;
    existing.locked_until = Some(12345);
    existing.pending_enrollment = Some(SecretString::new("token".to_string()));
    existing.enrollment_failed_attempts = 2;
    existing.enrollment_locked_until = Some(54321);

    let mut incoming_client = client("NEWSECRETVALUENEWSECRETVALUENEWS");
    incoming_client.pending_enrollment = Some(SecretString::new("token".to_string()));
    let incoming = config_with(&[("client-001", incoming_client)]);

    let (added, removed, _rotated) = merge_auth_clients(&mut live, &incoming);

    assert!(added.is_empty() && removed.is_empty());
    let client = &live.clients["client-001"];
    assert_eq!(client.secret.as_str(), "NEWSECRETVALUENEWSECRETVALUENEWS");
    assert_eq!(
        client
            .pending_enrollment
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("token")
    );
    assert_eq!(client.failed_attempts, 2, "the file's stale counter loses");
    assert_eq!(client.locked_until, Some(12345));
    assert_eq!(
        client.enrollment_failed_attempts, 2,
        "the enrollment's counter is live state too"
    );
    assert_eq!(client.enrollment_locked_until, Some(54321));
}

/// A token the file replaces in memory is a new invite: the guesses at the
/// old token are not guesses at this one, so the new one starts with its
/// own budget rather than one lockout away from closed.
#[test]
fn a_new_invite_starts_with_its_own_budget() {
    let mut live = config_with(&[("client-001", client("SECRETVALUESECRETVALUESECRETVALU"))]);
    let existing = live.clients.get_mut("client-001").unwrap();
    existing.pending_enrollment = Some(SecretString::new("old-token".to_string()));
    existing.enrollment_failed_attempts = 2;
    existing.enrollment_locked_until = Some(54321);

    let mut incoming_client = client("SECRETVALUESECRETVALUESECRETVALU");
    incoming_client.pending_enrollment = Some(SecretString::new("new-token".to_string()));
    let incoming = config_with(&[("client-001", incoming_client)]);

    let (added, removed, _rotated) = merge_auth_clients(&mut live, &incoming);

    assert!(added.is_empty() && removed.is_empty());
    let client = &live.clients["client-001"];
    assert_eq!(
        client
            .pending_enrollment
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("new-token")
    );
    assert_eq!(
        client.enrollment_failed_attempts, 0,
        "the guesses went with the token they were made at"
    );
    assert_eq!(client.enrollment_locked_until, None);
}

/// The configuration file an invite is written into: one client, one pending
/// enrollment token.
fn config_with_pending_token(path: &std::path::Path, token: &str) {
    std::fs::write(
        path,
        format!(
            "[auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
             pending_enrollment = \"{token}\"\n"
        ),
    )
    .expect("the config is written");
}

/// The state file beside the configuration, carrying what the guesses at a
/// token cost.
///
/// Written through the server's own writer, so the file is the one a running
/// server would have left behind: the count of the guesses, the lockout
/// window they earned, and the fingerprint of the token they were paid for.
/// It is put where the server looks for it — the path the state itself
/// names — rather than at a name spelled out here.
fn state_file_with_enrollment_counters(
    config_path: &str,
    token: &str,
    attempts: u32,
    locked_until: u64,
) {
    let mut config = crate::auth::AuthConfig::default();
    let mut client = client("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    client.pending_enrollment = Some(SecretString::new(token.to_string()));
    client.enrollment_failed_attempts = attempts;
    client.enrollment_locked_until = Some(locked_until);
    config.clients.insert("client-001".to_string(), client);

    let path = crate::auth::state::path_for(config_path);
    crate::config_watcher::save_auth_state(&path.to_string_lossy(), &config)
        .expect("the state file is written");
}

/// A lockout window that has not run out yet.
fn a_live_lockout_window() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
        + 3600
}

/// A rotated invite starts with its own budget.
///
/// The counters are the guesses at a **token**, and a token that is replaced
/// is a different credential. The merge used to keep the file's copy of them,
/// and the file's copy is the state file's — so an invite that was rotated
/// while the old token had guesses against it inherited them, and the lockout
/// the old token had earned closed the new invite's slot.
///
/// The file is read the way the watcher reads it: through the loader that
/// applies the state file beside it, so the snapshot the merge sees is the one
/// a running server would see.
#[tokio::test]
async fn a_rotated_invite_starts_with_its_own_budget() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap().to_string();

    config_with_pending_token(&path, "old-token");
    state_file_with_enrollment_counters(&path_str, "old-token", 3, a_live_lockout_window());

    // The live state the server started with: the old token, and the counters
    // the state file carries for it.
    let (_, auth) =
        crate::config::ProxyConfig::load_with_auth(path_str.as_str()).expect("the config loads");
    let state = AuthState::new(
        auth.expect("the config declares an [auth] section"),
        &path_str,
    );
    let watcher = watcher_for(state.clone(), &path_str);

    // The operator rotates the invite: the file carries a new token.
    config_with_pending_token(&path, "new-token");

    watcher.reload_config().await;

    let live = state.config().read().await;
    let client = &live.clients["client-001"];
    assert_eq!(
        client
            .pending_enrollment
            .as_ref()
            .map(|token| token.expose_secret().as_str()),
        Some("new-token"),
        "the new invite is the live one"
    );
    assert_eq!(
        client.enrollment_failed_attempts, 0,
        "the guesses were paid for by the token that is gone"
    );
    assert_eq!(
        client.enrollment_locked_until, None,
        "and so was the lockout that token earned"
    );
}

/// The reset reaches the file the next start reads.
///
/// The merge zeroes the counters in memory, but the file beside the
/// configuration is what a restart reads — and it still held what the guesses
/// at the **old** token cost. The count came back with the next start, handed
/// to the invite that had replaced the one it was paid for.
///
/// So the reload writes the file, and the startup path — the loader that
/// applies the state file onto the configuration — finds nothing to hand
/// back.
#[tokio::test]
async fn a_rotated_invite_leaves_nothing_for_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap().to_string();

    config_with_pending_token(&path, "old-token");
    state_file_with_enrollment_counters(&path_str, "old-token", 3, a_live_lockout_window());

    let (_, auth) =
        crate::config::ProxyConfig::load_with_auth(path_str.as_str()).expect("the config loads");
    let state = AuthState::new(
        auth.expect("the config declares an [auth] section"),
        &path_str,
    );
    let watcher = watcher_for(state.clone(), &path_str);

    // The operator rotates the invite: the file carries a new token.
    config_with_pending_token(&path, "new-token");

    watcher.reload_config().await;

    // The file the next start reads.
    let on_disk = crate::auth::state::load(&crate::auth::state::path_for(&path_str))
        .expect("the state file reads back");
    let carried = on_disk.clients.get("client-001");
    assert!(
        carried.is_none_or(|client| client.enrollment_failed_attempts == 0),
        "the file does not carry the old token's count: {carried:?}"
    );

    // And the startup path itself: the loader that applies the file onto the
    // configuration.
    let (_, auth) =
        crate::config::ProxyConfig::load_with_auth(path_str.as_str()).expect("the config loads");
    let client = &auth.expect("the config declares an [auth] section").clients["client-001"];
    assert_eq!(
        client.enrollment_failed_attempts, 0,
        "the count did not come back with the next start"
    );
    assert_eq!(
        client.enrollment_locked_until, None,
        "and neither did the lockout the old token earned"
    );
}

/// An unchanged token keeps the counters that are live.
///
/// The live counter is the newer one — a failure counted since the last flush
/// to the state file — so the merge keeps it, the way it keeps the client's
/// own lockout.
#[tokio::test]
async fn an_unchanged_token_keeps_its_live_counters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap().to_string();

    config_with_pending_token(&path, "token");
    let window = a_live_lockout_window();
    state_file_with_enrollment_counters(&path_str, "token", 3, window);

    let (_, auth) =
        crate::config::ProxyConfig::load_with_auth(path_str.as_str()).expect("the config loads");
    let state = AuthState::new(
        auth.expect("the config declares an [auth] section"),
        &path_str,
    );
    let watcher = watcher_for(state.clone(), &path_str);

    // A guess counted in memory since the last flush: the file is behind.
    {
        let mut live = state.config().write().await;
        let client = live
            .clients
            .get_mut("client-001")
            .expect("the client is there");
        client.enrollment_failed_attempts = 5;
    }

    watcher.reload_config().await;

    let live = state.config().read().await;
    let client = &live.clients["client-001"];
    assert_eq!(
        client.enrollment_failed_attempts, 5,
        "the live counter is newer than the file's"
    );
    assert_eq!(client.enrollment_locked_until, Some(window));
}

/// The state file's counters are still honoured for a token that did not
/// change.
///
/// The rule is about the token being replaced, not about the counters: a
/// client whose invite is the same one keeps what the state file carries for
/// it, and a reload that leaves the token alone keeps them too.
#[tokio::test]
async fn the_state_file_counters_are_honoured_for_an_unchanged_token() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().unwrap().to_string();

    config_with_pending_token(&path, "token");
    let window = a_live_lockout_window();
    state_file_with_enrollment_counters(&path_str, "token", 3, window);

    let (_, auth) =
        crate::config::ProxyConfig::load_with_auth(path_str.as_str()).expect("the config loads");
    let auth = auth.expect("the config declares an [auth] section");
    let client = &auth.clients["client-001"];
    assert_eq!(
        client.enrollment_failed_attempts, 3,
        "the state file's counter is honoured on the way in"
    );
    assert_eq!(client.enrollment_locked_until, Some(window));

    let state = AuthState::new(auth, &path_str);
    let watcher = watcher_for(state.clone(), &path_str);
    watcher.reload_config().await;

    let live = state.config().read().await;
    let client = &live.clients["client-001"];
    assert_eq!(
        client.enrollment_failed_attempts, 3,
        "a reload that leaves the token alone keeps the counter"
    );
    assert_eq!(client.enrollment_locked_until, Some(window));
}

/// A server started with no `[auth]` section at all can still switch 2FA on
/// while it runs.
///
/// Regression: the state used to be built only when the file already had an
/// `[auth]` table, and `reload_auth` returns early on a missing state, so
/// the one deployment that most needs a live switch — an operator adding
/// the section to a running server for the first time — could only get it
/// by restarting. `run_proxy` builds the state from the default config now,
/// which is `enabled = false` with no clients, and this is what that buys.
#[tokio::test]
async fn a_state_built_without_a_section_still_reloads_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n",
    )
    .unwrap();
    // Private, because enabling 2FA is refused against a file anyone else
    // can read — the secrets in it become live credentials.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let path = path.to_str().unwrap().to_string();

    let state = AuthState::new(AuthConfig::default(), &path);
    let watcher = ConfigWatcher::new(
        path,
        Arc::new(RoutingTable::new(Vec::new())),
        Arc::new(
            crate::http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                .expect("the default trust store is always usable"),
        ),
        Arc::new(Mutex::new(HealthProbes::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        Some(state.clone()),
        Arc::new(PeerRegistry::new()),
    );

    assert!(!state.config().read().await.enabled);

    watcher.reload_config().await;

    let live = state.config().read().await;
    assert!(
        live.enabled,
        "2FA has to come on for a server that started without it"
    );
    assert!(
        live.clients.contains_key("client-001"),
        "and the client the section brought with it has to be live too"
    );
}

/// The TOTP parameters are startup-only: the merge touches the clients
/// table and nothing else, so a mid-run edit cannot strand clients enrolled
/// under the old algorithm, step or digit count.
#[test]
fn the_merge_leaves_the_totp_parameters_alone() {
    let mut live = config_with(&[("a", client("A"))]);
    live.issuer = "Startup Issuer".to_string();
    live.max_attempts = 9;

    let mut incoming = config_with(&[("a", client("A2"))]);
    incoming.issuer = "File Issuer".to_string();
    incoming.max_attempts = 3;

    merge_auth_clients(&mut live, &incoming);

    assert_eq!(live.issuer, "Startup Issuer");
    assert_eq!(live.max_attempts, 9);
    assert_eq!(live.clients["a"].secret.as_str(), "A2");
}

/// Turning 2FA on mid-run is the half of the old startup-only rule that had
/// to go: without it, an operator who writes `enabled = true` gets a log
/// line saying the config reloaded and a listener that is still ungated.
#[test]
fn a_reload_turns_2fa_on() {
    let mut live = config_with(&[("a", client("A"))]);
    live.enabled = false;

    let mut incoming = config_with(&[("a", client("A"))]);
    incoming.enabled = true;

    assert_eq!(apply_auth_enabled(&mut live, &incoming), Some(true));
    assert!(
        live.enabled,
        "the file's `true` is what the listener now uses"
    );
}

/// The transition is reported only when it happens, so the reload path can
/// log it without re-reading the state — and so a route-only edit while 2FA
/// is on stays quiet.
#[test]
fn an_unchanged_enabled_reports_no_transition() {
    let mut live = config_with(&[("a", client("A"))]);
    live.enabled = true;

    let mut incoming = config_with(&[("a", client("A"))]);
    incoming.enabled = true;

    assert_eq!(apply_auth_enabled(&mut live, &incoming), None);
    assert!(live.enabled);
}

/// The direction that has to be refused: `enabled = false` on a server that
/// is gating would remove the listener's only gate, and an operator who
/// wants that restarts.
#[test]
fn a_reload_may_not_turn_2fa_off() {
    let mut live = config_with(&[("a", client("A"))]);
    live.enabled = true;

    let mut incoming = config_with(&[("a", client("A"))]);
    incoming.enabled = false;

    let refusal = ConfigWatcher::auth_enabled_refusal(&live, &incoming, None)
        .expect("turning 2FA off must be refused");

    assert!(
        refusal.contains("[auth] enabled = false is ignored"),
        "{refusal}"
    );
    // The refusal is only a message; the caller applies nothing, so the live
    // state still gates.
    assert!(live.enabled);
}

/// Once 2FA is on, the file repeating `true` is not a transition, so none of
/// the three enabling checks can block an unrelated edit — a route change
/// during a `chmod 644` moment still reloads.
#[test]
fn an_already_enabled_config_is_never_refused() {
    let mut live = config_with(&[]);
    live.enabled = true;

    let mut incoming = config_with(&[]);
    incoming.enabled = true;

    assert_eq!(
        ConfigWatcher::auth_enabled_refusal(&live, &incoming, None),
        None
    );
}

/// 2FA does not run on the plaintext listener, so enabling it while that
/// listener is reachable from the network would produce exactly the state
/// `run_proxy` refuses to start in. A reload must not be the way around a
/// check the startup path enforces.
#[test]
fn a_reload_may_not_enable_2fa_while_plaintext_is_exposed() {
    let live = config_with(&[]);
    let mut incoming = config_with(&[]);
    incoming.enabled = true;

    let exposed = Some(PlaintextListener {
        addr: "0.0.0.0:8080".parse().unwrap(),
        exposed: true,
    });
    let refusal = ConfigWatcher::auth_enabled_refusal(&live, &incoming, exposed)
        .expect("an exposed plaintext listener must block the flip");
    assert!(refusal.contains("plaintext listener"), "{refusal}");

    // A loopback listener is the case the startup path allows, so it is not
    // refused here either.
    let loopback = Some(PlaintextListener {
        addr: "127.0.0.1:8080".parse().unwrap(),
        exposed: false,
    });
    assert_eq!(
        ConfigWatcher::auth_enabled_refusal(&live, &incoming, loopback),
        None
    );

    // And no plaintext listener at all is always fine.
    assert_eq!(
        ConfigWatcher::auth_enabled_refusal(&live, &incoming, None),
        None
    );
}

/// Whether a device is still in use is answered from the stamp the server
/// writes back. A device whose `last_used` never reaches the file reports
/// "never used" forever, and "which of these can I revoke without
/// disconnecting someone" has nothing to go on — which is the whole of what
/// a per-device credential is for.
///
/// The stamp goes to the **state file**, and the configuration file is left
/// exactly as it was: the counters are the server's, the configuration is
/// the operator's, and a server that wrote its own counters into the
/// operator's file moved its modification time every time somebody
/// mistyped a code — which the watcher watches.
#[test]
fn a_device_stamp_is_written_back_without_touching_its_secret() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let state_path = dir.path().join("state.toml");
    let state_path_str = state_path.to_str().expect("utf-8 path").to_string();
    std::fs::write(
        &path,
        "[auth]\n\
         [auth.clients.alice]\n\
         secret = \"ALICEALICEALICEAALICEALICEALICEA\"\n\
         \n\
         [auth.clients.alice.devices.laptop]\n\
         secret = \"LAPTOPLAPTOPLAPTLAPTOPLAPTOPLAPT\"\n",
    )
    .expect("write the config");

    let mut alice = client("ALICEALICEALICEAALICEALICEALICEA");
    alice.devices = [(
        "laptop".to_string(),
        DeviceAuth {
            secret: SecretString::new("LAPTOPLAPTOPLAPTLAPTOPLAPTOPLAPT".to_string()),
            public_key: None,
            created_at: "0".to_string(),
            last_used: Some(1700000000),
            last_used_step: None,
        },
    )]
    .into_iter()
    .collect();
    let config = config_with(&[("alice", alice)]);

    // Written the way the connection layer writes it: from a snapshot, which
    // is a copy that carries no credential.
    save_auth_state(&state_path_str, &config.counter_snapshot()).expect("the writeback succeeds");

    let on_disk = std::fs::read_to_string(&state_path).expect("read the state back");
    assert!(
        on_disk.contains("last_used = 1700000000"),
        "the device stamp did not reach the file: {on_disk}"
    );
    assert!(
        !on_disk.contains("LAPTOPLAPTOPLAPTLAPTOPLAPTOPLAPT"),
        "the snapshot's blanked secret must not be written: {on_disk}"
    );

    let config_on_disk = std::fs::read_to_string(&path).expect("read the config back");
    assert_eq!(
        config_on_disk,
        "[auth]\n\
         [auth.clients.alice]\n\
         secret = \"ALICEALICEALICEAALICEALICEALICEA\"\n\
         \n\
         [auth.clients.alice.devices.laptop]\n\
         secret = \"LAPTOPLAPTOPLAPTLAPTOPLAPTOPLAPT\"\n",
        "the configuration is the operator's file and is not the server's to rewrite"
    );
}

/// A minimal config file carrying one `[auth.clients]` entry.
fn file_with(client_id: &str, secret: &str) -> String {
    format!(
        "[auth]\n\
         [auth.clients.{client_id}]\n\
         secret = \"{secret}\"\n\
         created_at = \"1723756800\"\n"
    )
}

/// A reload that finds an enrollment has overtaken its snapshot reads the
/// file again.
///
/// An enrollment spends a token by changing the live state and then writing
/// the change out, so a snapshot taken before the enrollment — and applied
/// afterwards — would put the spent token back and roll the client's secret
/// back to what it was before the enrollment.
///
/// The read is outside the lock now, so the lock alone cannot order the
/// two. The epoch does: it is sampled before the read and compared under
/// the lock the enrollment itself holds.
///
/// The enrollment is reproduced by holding the lock the way it does,
/// rewriting the file and moving the epoch while it is held: the reload
/// then has to wait for the lock, notice that its snapshot was overtaken,
/// and come away with what the file says *now*.
#[tokio::test]
async fn a_reload_that_finds_an_enrollment_has_overtaken_it_reads_again() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    std::fs::write(&path, file_with("old", "OLDOLDOLDOLDOLDOOLDOLDOLDOLDOLDO"))
        .expect("write the first file");
    let state = AuthState::new(
        config_with(&[("old", client("OLDOLDOLDOLDOLDOOLDOLDOLDOLDOLDO"))]),
        path_str.clone(),
    );

    let watcher = ConfigWatcher::new(
        path_str,
        Arc::new(RoutingTable::new(Vec::new())),
        Arc::new(
            crate::http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                .expect("the default trust store is always usable"),
        ),
        Arc::new(Mutex::new(HealthProbes::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        Some(state.clone()),
        Arc::new(PeerRegistry::new()),
    );

    let enrolled = state.clone();
    let path_for_task = path.clone();
    // The epoch as it was before the enrollment: the snapshot the reload
    // is about to take belongs to the revision before it.
    let epoch_before = state.enroll_epoch();

    let holder = tokio::spawn(async move {
        let _guard = enrolled.config().write().await;
        // The order `enroll_client` uses: the file is written first, and
        // the epoch moves after it, under the same lock. A bump before the
        // write would let the reload sample the new epoch and still read
        // the old file.
        std::fs::write(
            &path_for_task,
            file_with("new", "NEWNEWNEWNEWNEWNNEWNEWNEWNEWNEWN"),
        )
        .expect("write the second file");
        enrolled.bump_enroll_epoch();
        tokio::time::sleep(Duration::from_millis(150)).await;
    });

    // Long enough for the task above to have taken the lock and rewritten
    // the file, which is the only thing that makes this a race.
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The snapshot the reload starts with says "old" — the file as it was
    // before the enrollment.
    watcher
        .reload_auth(
            Some(config_with(&[(
                "old",
                client("OLDOLDOLDOLDOLDOOLDOLDOLDOLDOLDO"),
            )])),
            epoch_before,
        )
        .await;
    holder.await.expect("the holder task ends");

    let live = state.config().read().await;
    assert!(
        live.clients.contains_key("new"),
        "the reload must merge the file as it reads once it holds the lock"
    );
    assert!(
        !live.clients.contains_key("old"),
        "a client the file no longer lists must not survive the reload"
    );
}

/// A device struck out of the file while its client survives has to reach
/// the connection already serving as it, not only the next dial.
///
/// This is the far end of the path `removed_devices` feeds: an operator
/// runs `nexapipe client revoke alice --device laptop`, the reload diffs
/// the device table, and the connection that authenticated as that device
/// is told to stop through the channel it was registered with. The sibling
/// device is the control — a revocation that took every device of the
/// client with it would be a different bug, and a quieter one.
#[tokio::test]
async fn a_reload_closes_the_connection_authenticated_as_a_removed_device() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    let file = |devices: &[&str]| {
        let mut out = String::from(
            "[auth]\n\
             [auth.clients.alice]\n\
             secret = \"ALICEALICEALICEAALICEALICEALICEA\"\n\
             created_at = \"1723756800\"\n",
        );
        for name in devices {
            out.push_str(&format!(
                "\n[auth.clients.alice.devices.{name}]\n\
                 secret = \"DEVICEDEVICEDEVICDEVICEDEVICEDEV\"\n\
                 created_at = \"1723756800\"\n"
            ));
        }
        out
    };

    std::fs::write(&path, file(&["laptop", "phone"])).expect("write the config");

    let mut alice = client("ALICEALICEALICEAALICEALICEALICEA");
    alice.devices = ["laptop", "phone"]
        .into_iter()
        .map(|name| (name.to_string(), device("DEVICEDEVICEDEVICDEVICEDEVICEDEV")))
        .collect();
    let state = AuthState::new(config_with(&[("alice", alice)]), path_str.clone());

    let peers = Arc::new(PeerRegistry::new());
    let watcher = ConfigWatcher::new(
        path_str,
        Arc::new(RoutingTable::new(Vec::new())),
        Arc::new(
            crate::http::BackendClients::new(crate::config::Timeouts::default().connect, None)
                .expect("the default trust store is always usable"),
        ),
        Arc::new(Mutex::new(HealthProbes::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
        Some(state.clone()),
        peers.clone(),
    );

    // Registered the way the handshake registers a connection: identity,
    // channel and guard in one step.
    let registered = |seed: u8, device: &str| {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let guard = peers.insert(
            iroh::SecretKey::from_bytes(&[seed; 32]).public(),
            crate::metrics::PathKind::Direct,
            PeerIdentity {
                client_id: Some("alice".to_string()),
                device: Some(device.to_string()),
            },
            tx,
        );
        (rx, guard)
    };
    let (mut laptop_rx, _laptop) = registered(1, "laptop");
    let (mut phone_rx, _phone) = registered(2, "phone");

    std::fs::write(&path, file(&["phone"])).expect("rewrite without the laptop");
    watcher.reload_config().await;

    assert!(
        *laptop_rx.borrow_and_update(),
        "a connection serving as a device the file no longer lists must be told to stop"
    );
    assert!(
        !*phone_rx.borrow_and_update(),
        "a device that is still in the file must not be closed along with it"
    );
}

/// A config file carrying one client and the hosts it may reach.
fn file_for(client_id: &str, secret: &str, hosts: &[&str]) -> String {
    let hosts = hosts
        .iter()
        .map(|host| format!("\"{host}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[auth]\n\
         [auth.clients.{client_id}]\n\
         secret = \"{secret}\"\n\
         allow_hosts = [{hosts}]\n"
    )
}

/// The authorization a list of hosts and a list of ports grants.
fn authorization(hosts: Option<&[&str]>, ports: Option<&[u16]>) -> ClientAuthorization {
    ClientAuthorization {
        hosts: hosts.map(|hosts| hosts.iter().map(|host| host.to_string()).collect()),
        ports: ports.map(|ports| ports.to_vec()),
        strict_ports: false,
    }
}

/// A host list that lost one of its entries is a tightening.
#[test]
fn a_narrowed_host_list_is_a_tightening() {
    let live = authorization(Some(&["a.test", "b.test"]), None);
    let incoming = authorization(Some(&["a.test"]), None);
    assert!(live.tightened_by(&incoming));
}

/// A host list that gained an entry is a widening, and a widening closes
/// nothing: the connections that are open carry an authorization that is
/// still valid.
#[test]
fn a_widened_host_list_is_not_a_tightening() {
    let live = authorization(Some(&["a.test"]), None);
    let incoming = authorization(Some(&["a.test", "b.test"]), None);
    assert!(!live.tightened_by(&incoming));
}

/// The same list twice is not a tightening either, so a reload that changes
/// nothing does not drop a connection.
#[test]
fn an_unchanged_host_list_is_not_a_tightening() {
    let live = authorization(Some(&["a.test", "b.test"]), None);
    let incoming = authorization(Some(&["a.test", "b.test"]), None);
    assert!(!live.tightened_by(&incoming));
}

/// A list that lost one host and gained another is a tightening: the host it
/// lost is one the client may no longer reach.
#[test]
fn a_host_list_that_swapped_a_host_is_a_tightening() {
    let live = authorization(Some(&["a.test", "b.test"]), None);
    let incoming = authorization(Some(&["a.test", "c.test"]), None);
    assert!(live.tightened_by(&incoming));
}

/// A client that was allowed every host and is given a list has had hosts
/// taken away: the list is not every host.
#[test]
fn an_unrestricted_client_is_tightened_by_a_host_list() {
    let live = authorization(None, None);
    let incoming = authorization(Some(&["a.test"]), None);
    assert!(live.tightened_by(&incoming));
}

/// The other way round is a widening: a list that is replaced by "every host"
/// takes nothing away.
#[test]
fn a_host_list_is_not_tightened_by_every_host() {
    let live = authorization(Some(&["a.test"]), None);
    let incoming = authorization(None, None);
    assert!(!live.tightened_by(&incoming));
}

/// A wildcard covers the names under it, so replacing it with one of them
/// takes the rest away.
#[test]
fn a_wildcard_replaced_by_one_of_its_names_is_a_tightening() {
    let live = authorization(Some(&["*.example.com"]), None);
    let incoming = authorization(Some(&["app.example.com"]), None);
    assert!(live.tightened_by(&incoming));
}

/// The other way round is not: a name under a wildcard keeps everything the
/// wildcard allowed.
#[test]
fn a_name_under_a_wildcard_is_not_taken_away_by_it() {
    let live = authorization(Some(&["app.example.com"]), None);
    let incoming = authorization(Some(&["*.example.com"]), None);
    assert!(!live.tightened_by(&incoming));
}

/// A port that was allowed and is no longer listed is a tightening.
#[test]
fn a_narrowed_port_list_is_a_tightening() {
    let live = authorization(None, Some(&[80, 443]));
    let incoming = authorization(None, Some(&[443]));
    assert!(live.tightened_by(&incoming));
}

/// A port list that gained a port is a widening.
#[test]
fn a_widened_port_list_is_not_a_tightening() {
    let live = authorization(None, Some(&[443]));
    let incoming = authorization(None, Some(&[443, 80]));
    assert!(!live.tightened_by(&incoming));
}

/// A reload that turns 2FA on closes the connections that never
/// authenticated.
///
/// A connection that was opened while 2FA was off never did a handshake, so it
/// carries no credential at all: the registry lists it with no client id.
/// Turning the gate on did not reach it — the reload used to say nothing
/// about those connections at all — and a WebSocket session or an L4 tunnel
/// opened before the change went on serving with nothing behind it for as
/// long as it lived.
#[tokio::test]
async fn a_reload_that_turns_2fa_on_closes_the_connections_that_never_authenticated() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    // 2FA is off, so the connection below is served without a handshake.
    std::fs::write(&path, "[auth]\nenabled = false\n").expect("write the config");
    let state = AuthState::new(AuthConfig::default(), path_str.clone());
    let peers = Arc::new(PeerRegistry::new());
    let watcher = watcher_with_peers(state.clone(), &path_str, peers.clone());

    let (mut anonymous, _guard) = connected(&peers, 1, PeerIdentity::default());

    // The operator turns 2FA on.
    std::fs::write(&path, "[auth]\nenabled = true\n").expect("rewrite the config");
    watcher.reload_config().await;

    assert!(
        *anonymous.borrow_and_update(),
        "a connection that never authenticated must be closed when the gate comes on"
    );
}

/// The connections that did authenticate are left alone by the same reload.
///
/// They carry the authorization they were given when they connected, and that
/// authorization is still valid — the gate is on for the connections opened
/// from here on, and the ones that are open keep working.
#[tokio::test]
async fn a_reload_that_turns_2fa_on_leaves_the_authenticated_connections_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    std::fs::write(&path, "[auth]\nenabled = false\n").expect("write the config");
    let state = AuthState::new(AuthConfig::default(), path_str.clone());
    let peers = Arc::new(PeerRegistry::new());
    let watcher = watcher_with_peers(state.clone(), &path_str, peers.clone());

    let (mut alice, _guard) = connected(
        &peers,
        2,
        PeerIdentity {
            client_id: Some("alice".to_string()),
            device: None,
        },
    );

    std::fs::write(&path, "[auth]\nenabled = true\n").expect("rewrite the config");
    watcher.reload_config().await;

    assert!(
        !*alice.borrow_and_update(),
        "a connection that authenticated must not be closed by the reload that turned 2FA on"
    );
}

/// A reload that tightens a client's authorization closes its connections.
///
/// The ACL is snapshotted at the handshake and never read again, so a client
/// whose host list was narrowed would go on reaching the host that was taken
/// away — on every connection it already had, for as long as they live.
#[tokio::test]
async fn a_reload_that_tightens_a_client_closes_its_connections() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    std::fs::write(
        &path,
        file_for("alice", "ALICEALICEALICEAALICEALICEALICEA", &["a.test"]),
    )
    .expect("write the config");

    // The live client may reach both hosts.
    let mut alice = client("ALICEALICEALICEAALICEALICEALICEA");
    alice.allow_hosts = Some(vec!["a.test".to_string(), "b.test".to_string()]);
    let state = AuthState::new(config_with(&[("alice", alice)]), path_str.clone());
    let peers = Arc::new(PeerRegistry::new());
    let watcher = watcher_with_peers(state.clone(), &path_str, peers.clone());

    let (mut connection, _guard) = connected(
        &peers,
        3,
        PeerIdentity {
            client_id: Some("alice".to_string()),
            device: None,
        },
    );

    watcher.reload_config().await;

    assert!(
        *connection.borrow_and_update(),
        "a client that was given a tighter authorization must not keep the connections it had"
    );
}

/// A reload that widens the list closes nothing.
///
/// The connections that are open carry an authorization that is still valid —
/// the new list allows everything the old one did — so dropping them would
/// take a working session down over an edit that loosened the rules.
#[tokio::test]
async fn a_reload_that_widens_a_client_leaves_its_connections_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    std::fs::write(
        &path,
        file_for(
            "alice",
            "ALICEALICEALICEAALICEALICEALICEA",
            &["a.test", "b.test"],
        ),
    )
    .expect("write the config");

    // The live client may reach one host only.
    let mut alice = client("ALICEALICEALICEAALICEALICEALICEA");
    alice.allow_hosts = Some(vec!["a.test".to_string()]);
    let state = AuthState::new(config_with(&[("alice", alice)]), path_str.clone());
    let peers = Arc::new(PeerRegistry::new());
    let watcher = watcher_with_peers(state.clone(), &path_str, peers.clone());

    let (mut connection, _guard) = connected(
        &peers,
        4,
        PeerIdentity {
            client_id: Some("alice".to_string()),
            device: None,
        },
    );

    watcher.reload_config().await;

    assert!(
        !*connection.borrow_and_update(),
        "a client that was given a wider authorization must keep the connections it had"
    );
}

/// A client that is gone from the file still has its connections closed.
///
/// This is the case the removal path has always covered, and the tightening
/// pass must not take it over: a removed client is not in the file at all, so
/// there is nothing to compare it against.
#[tokio::test]
async fn a_reload_that_removes_a_client_closes_its_connections() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let path_str = path.to_str().expect("utf-8 path").to_string();

    // The file has no clients at all.
    std::fs::write(&path, "[auth]\n").expect("write the config");

    let state = AuthState::new(
        config_with(&[("alice", client("ALICEALICEALICEAALICEALICEALICEA"))]),
        path_str.clone(),
    );
    let peers = Arc::new(PeerRegistry::new());
    let watcher = watcher_with_peers(state.clone(), &path_str, peers.clone());

    let (mut connection, _guard) = connected(
        &peers,
        5,
        PeerIdentity {
            client_id: Some("alice".to_string()),
            device: None,
        },
    );

    watcher.reload_config().await;

    assert!(
        *connection.borrow_and_update(),
        "a client that is no longer in [auth] must not keep the connections it had"
    );
}
