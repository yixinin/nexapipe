use super::step::accept_step;

use super::*;

fn client() -> ClientAuth {
    ClientAuth {
        secret: SecretString::default(),
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

/// Whether a device is still in use is the question the device table exists
/// to answer, and the client-level `record_success` never answered it for a
/// device — so `client list` reported "never used" for every named device,
/// forever.
#[test]
fn authenticating_as_a_device_stamps_that_device() {
    let mut client = client();
    client.devices.insert(
        "laptop".to_string(),
        device("LAPTOPSECRETLAPTOPSECRETLAPTOPSE"),
    );
    client.devices.insert(
        "phone".to_string(),
        device("PHONESECRETPHONESECRETPHONESECRE"),
    );

    assert!(
        client.record_device_success_at("laptop", 1_000),
        "the first stamp is a change"
    );
    let stamped = client.devices["laptop"].last_used;
    assert_eq!(stamped, Some(1_000), "the device was stamped");
    assert_eq!(
        client.devices["phone"].last_used, None,
        "a sibling device must not be stamped with it"
    );

    // Whole seconds, so the same second is not a change — which is what
    // keeps a reconnecting device from costing a write every time.
    assert!(
        !client.record_device_success_at("laptop", 1_000),
        "the same second must not count as a new stamp"
    );
    assert_eq!(client.devices["laptop"].last_used, stamped);

    // And the next second is a change, so the stamp does move.
    assert!(
        client.record_device_success_at("laptop", 1_001),
        "the next second is a new stamp"
    );
    assert_eq!(client.devices["laptop"].last_used, Some(1_001));
}

/// A name that is not in the table is not a stamp, and not an error either:
/// the handshake has already refused it before this can run.
#[test]
fn stamping_a_device_that_is_not_there_does_nothing() {
    let mut client = client();
    assert!(!client.record_device_success("laptop"));
    assert!(client.devices.is_empty());
}

#[test]
fn a_secret_decodes_the_way_an_invite_writes_it() {
    // An invite hands the secret through `normalize_secret`, which drops
    // the padding and folds the case. A config written either of those ways
    // has to decode too, or the client is stuck at "Invalid Base32 secret"
    // with nothing pointing at the spelling.
    let mut lower = client();
    lower.secret = SecretString::new("jbswy3dpehpk3pxpjbswy3dpehpk3pxp".to_string());
    let mut padded = client();
    padded.secret = SecretString::new("JBSWY3DPEHPK3PXPGEZDGNBVGY3TQ===".to_string());
    let mut plain = client();
    plain.secret = SecretString::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string());

    assert_eq!(
        lower.decode_secret().unwrap(),
        plain.decode_secret().unwrap()
    );
    assert_eq!(
        padded.decode_secret().unwrap().as_slice(),
        b"Hello!\xde\xad\xbe\xef12345678"
    );
}

/// `Debug` is what a log line uses, and the whole config — this struct
/// included — is logged whenever it is parsed. Both redacted fields are
/// live credentials: the seed is half of a second factor, and the token is
/// the whole of one until somebody spends it.
#[test]
fn a_client_prints_no_credentials() {
    let mut c = client();
    c.secret = SecretString::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string());
    c.pending_enrollment = Some(SecretString::new("deadbeef".to_string()));

    let rendered = format!("{c:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(
        !rendered.contains("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
        "{rendered}"
    );
    assert!(!rendered.contains("deadbeef"), "{rendered}");
}

#[test]
fn a_lockout_that_ran_out_leaves_nothing_behind() {
    let mut c = client();
    c.failed_attempts = 3;
    c.locked_until = Some(unix_now() - 1);

    c.refresh_lockout();

    assert!(!c.is_locked_out());
    assert_eq!(c.locked_until, None);
    // The counter has to go with it, or the next single failure — one
    // attempt instead of `max_attempts` — locks the client out again.
    assert_eq!(c.failed_attempts, 0);
}

#[test]
fn a_lockout_still_running_is_left_alone() {
    let mut c = client();
    c.failed_attempts = 3;
    c.locked_until = Some(unix_now() + 60);

    c.refresh_lockout();

    assert!(c.is_locked_out());
    assert_eq!(c.failed_attempts, 3);
}

#[test]
fn refreshing_a_client_that_was_never_locked_out_changes_nothing() {
    let mut c = client();
    c.failed_attempts = 2;

    c.refresh_lockout();

    assert_eq!(c.failed_attempts, 2, "a partial counter is not a lockout");
    assert!(!c.is_locked_out());
}

/// A client with no `allow_hosts` keeps the historical reach: every host.
#[test]
fn an_absent_allow_hosts_leaves_a_client_unrestricted() {
    let acl = ClientAcl::from_hosts(None);
    assert_eq!(acl, ClientAcl::unrestricted());
    assert!(acl.allows("anything.test"));
    assert_eq!(client().acl(), ClientAcl::unrestricted());
}

/// The patterns mean what a route's `host_pattern` means: exact or
/// `*.suffix`, case-insensitively, ignoring a fully-qualified trailing dot.
#[test]
fn restricted_patterns_match_the_way_routes_do() {
    let acl = ClientAcl::from_hosts(Some(&[
        "api.example.com".to_string(),
        "*.db.example.com".to_string(),
    ]));

    assert!(acl.allows("api.example.com"));
    assert!(acl.allows("API.Example.Com"), "hosts fold like route hosts");
    assert!(
        acl.allows("api.example.com."),
        "a trailing FQDN dot is not a different host"
    );
    assert!(acl.allows("pg.db.example.com"));
    assert!(
        !acl.allows("db.example.com"),
        "the wildcard needs the *. prefix, like a route"
    );
    assert!(!acl.allows("db.example.com.evil.test"));
    assert!(!acl.allows("admin.example.com"));
}

/// `allow_hosts = []` is "may connect, may touch nothing", not "no
/// restriction" — otherwise a typo in the list would silently publish a
/// client's reach to every backend.
#[test]
fn an_empty_allow_hosts_denies_every_host() {
    let acl = ClientAcl::from_hosts(Some(&[]));
    assert!(!acl.allows("api.example.com"));
    assert!(!acl.allows("anything.test"));
}

/// An entry that is the catch-all in another spelling is not the
/// catch-all: `*.`, `*..` and `[*]` all fold into `*`, and an allow-list
/// written as one of them would otherwise authorize every host.
///
/// The safe direction is the one that denies: an entry nobody meant as
/// "every host" must not be read as "every host".
#[test]
fn an_allow_list_entry_that_folds_into_the_catch_all_authorizes_nothing() {
    for spelling in ["*.", "*..", "[*]"] {
        let acl = ClientAcl::from_hosts_and_ports(Some(&[spelling.to_string()]), None);

        assert!(
            !acl.allows("api.example.com"),
            "{spelling} must not authorize a host"
        );
        assert!(
            !acl.allows("anything.test"),
            "{spelling} must not authorize a host"
        );
    }
}

/// The catch-all is the catch-all, and it is spelled one way.
#[test]
fn the_catch_all_still_authorizes_every_host() {
    let acl = ClientAcl::from_hosts_and_ports(Some(&["*".to_string()]), None);

    assert!(acl.allows("api.example.com"));
    assert!(acl.allows("anything.test"));
}

/// A client with no `allow_ports` keeps the historical reach: every port.
/// The port list is new, and a config that does not mention it must mean
/// what it meant before it existed.
#[test]
fn an_absent_allow_ports_leaves_a_client_unrestricted() {
    let acl = ClientAcl::from_hosts_and_ports(None, None);
    assert!(acl.allows_port(443));
    assert!(acl.allows_port(1));
    assert!(
        !acl.limits_ports(),
        "a client with no port list is not limited by one"
    );
}

/// The port list is a list, and a port that is not on it is refused.
#[test]
fn an_allow_ports_list_limits_the_ports_a_client_may_reach() {
    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443, 8443]));

    assert!(acl.allows_port(443));
    assert!(acl.allows_port(8443));
    assert!(
        !acl.allows_port(22),
        "a port the list does not name is not reachable"
    );
    assert!(acl.limits_ports());
}

/// `allow_ports = []` is "may connect, may reach nothing", not "no
/// restriction" — the same reading `allow_hosts = []` has.
#[test]
fn an_empty_allow_ports_denies_every_port() {
    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[]));
    assert!(!acl.allows_port(443));
    assert!(!acl.allows_port(80));
}

/// The two halves answer different questions and neither replaces the
/// other: a client may have the host and not the port, or the port and not
/// the host.
#[test]
fn the_host_and_the_port_are_independent() {
    let acl = ClientAcl::from_hosts_and_ports(Some(&["api.example.com".to_string()]), Some(&[443]));

    assert!(
        acl.allows_target("api.example.com", 443),
        "the host and the port are both named"
    );
    assert!(
        !acl.allows_target("api.example.com", 8443),
        "the host is named but the port is not"
    );
    assert!(
        !acl.allows_target("admin.example.com", 443),
        "the port is named but the host is not"
    );
}

/// A client that names no port has no port to hold against it: the proxy
/// routes by host and ignores the port otherwise, so there is nothing to
/// refuse.
#[test]
fn a_port_the_client_did_not_name_is_not_checked() {
    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));

    assert!(acl.allows("anything.test"));
    assert!(
        !acl.allows_port(80),
        "the list still refuses a port that is named"
    );
}

/// The patterns themselves are folded, so a config written with uppercase
/// letters answers the lowercase request.
#[test]
fn patterns_are_folded_when_the_acl_is_built() {
    let acl = ClientAcl::from_hosts(Some(&["API.Example.Com.".to_string()]));
    assert!(acl.allows("api.example.com"));
}

/// A device secret is issued and spelled the way a client's is, so it has
/// to decode under the same rule — a device stuck at "Invalid Base32
/// secret" is stuck regardless of which table its secret came from.
/// A step that is **behind** the last accepted one is refused: it is the
/// code of an earlier step, and that code is still inside the acceptance
/// window.
#[test]
fn a_step_behind_the_last_is_refused() {
    let mut last = None;

    assert_eq!(
        accept_step(&mut last, 100),
        StepVerdict::Accepted { moved: true },
        "the first step is accepted, and the memory moves"
    );
    assert_eq!(
        accept_step(&mut last, 99),
        StepVerdict::Refused,
        "an older step is refused: its code is still inside the window"
    );
    assert_eq!(
        accept_step(&mut last, 101),
        StepVerdict::Accepted { moved: true },
        "the next step is accepted"
    );
}

/// **The same step again is allowed**, and it has to be: a client that
/// opens several connections in the same step sends the same code for each
/// of them, and refusing the second would leave the client with
/// connections it cannot open.
#[test]
fn the_same_step_again_is_allowed() {
    let mut last = None;

    assert_eq!(
        accept_step(&mut last, 100),
        StepVerdict::Accepted { moved: true }
    );
    assert_eq!(
        accept_step(&mut last, 100),
        StepVerdict::Accepted { moved: false },
        "the same step again is the same code, and the memory does not move"
    );
}

/// The memory only moves when the step is a new one, so a client that
/// authenticates twice inside one step does not turn every connection
/// into a write.
#[test]
fn a_step_that_did_not_move_is_not_worth_a_write() {
    let mut last = Some(100);

    assert_eq!(
        accept_step(&mut last, 101),
        StepVerdict::Accepted { moved: true },
        "a new step moves the memory"
    );
    assert_eq!(last, Some(101));
}

/// Two credentials, two memories: a step accepted for one says nothing
/// about the other.
#[test]
fn the_memory_is_the_credential_s_own() {
    let mut config = AuthConfig::default();
    config.clients.insert(
        "alice".to_string(),
        ClientAuth {
            secret: nexapipe_proto::secret::SecretString::new(
                "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
            ),
            created_at: "0".to_string(),
            allow_hosts: None,
            allow_ports: None,
            allow_ports_strict: false,
            pending_enrollment: None,
            devices: HashMap::from([(
                "laptop".to_string(),
                DeviceAuth {
                    secret: nexapipe_proto::secret::SecretString::new(
                        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
                    ),
                    public_key: None,
                    created_at: "0".to_string(),
                    last_used: None,
                    last_used_step: None,
                },
            )]),
            unnamed_device_allowed: true,
            last_used: None,
            last_used_step: None,
            failed_attempts: 0,
            locked_until: None,
            enrollment_failed_attempts: 0,
            enrollment_locked_until: None,
        },
    );

    // The client's own secret, the unnamed device: it authenticated on
    // step 100.
    assert_eq!(
        config.accept_step("alice", None, 100),
        StepVerdict::Accepted { moved: true }
    );
    // The named device authenticated earlier, on step 50.
    assert_eq!(
        config.accept_step("alice", Some("laptop"), 50),
        StepVerdict::Accepted { moved: true }
    );

    // The same step, two credentials, two answers: step 99 is behind the
    // client's own memory and ahead of the device's, because the two
    // memories are their own.
    assert_eq!(
        config.accept_step("alice", None, 99),
        StepVerdict::Refused,
        "behind the client's own memory"
    );
    assert_eq!(
        config.accept_step("alice", Some("laptop"), 99),
        StepVerdict::Accepted { moved: true },
        "a named device's memory is its own"
    );
}

#[test]
fn a_device_secret_decodes_the_way_a_clients_does() {
    assert_eq!(
        device("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
            .decode_secret()
            .unwrap()
            .as_slice(),
        b"Hello!\xde\xad\xbe\xefHello!\xde\xad\xbe\xef"
    );
    assert_eq!(
        device(&"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_lowercase())
            .decode_secret()
            .unwrap(),
        device("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
            .decode_secret()
            .unwrap(),
        "the case an invite writes is the case this has to read"
    );
    assert!(
        device("JBSWY3DPEHPK3PX1").decode_secret().is_err(),
        "a character outside the alphabet is not a near miss"
    );
}

/// The fallback path, and the only one that existed before: a client with
/// no device table keeps authenticating against its own `secret`, because
/// an unnamed device has nowhere else to look.
#[test]
fn a_client_without_a_device_table_has_none() {
    let parsed: ClientAuth = toml::from_str(r#"secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP""#)
        .expect("a plain client still parses");

    assert!(parsed.devices.is_empty(), "{parsed:?}");
    assert_eq!(parsed.secret.as_str(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
}

/// The table is spelled the way a `[auth.clients.<id>]` entry nests it, so
/// what this test parses is what an operator writes.
#[test]
fn a_device_table_parses_into_named_devices() {
    let parsed: ClientAuth = toml::from_str(
        r#"
        secret = "CLIENTSECRETCLIENTSECRETCLIENTSE"

        [devices.laptop]
        secret = "LAPTOPSECRETLAPTOPSECRETLAPTOPSE"

        [devices.phone]
        secret = "PHONESECRETPHONESECRETPHONESECRE"
        created_at = "1700000000"
        "#,
    )
    .expect("a device table parses");

    assert_eq!(parsed.devices.len(), 2);
    assert_eq!(
        parsed.devices["laptop"].secret.as_str(),
        "LAPTOPSECRETLAPTOPSECRETLAPTOPSE"
    );
    assert_eq!(parsed.devices["phone"].created_at, "1700000000");
    // Issued-at is filled in when the config does not say, the way a
    // client's is: a device with an empty one looks never-issued.
    assert!(
        !parsed.devices["laptop"].created_at.is_empty(),
        "{parsed:?}"
    );
}

/// The file the server writes is the file the operator wrote.
///
/// The seeds are `Secret`s now, and a `Secret` that serialized differently
/// would rewrite every `[auth]` section in every config on the next write —
/// the seed is the credential, and its spelling in the file is what an
/// operator's tooling reads. The wrapper changes where the bytes live in
/// memory, not what the file says.
#[test]
fn a_client_survives_a_toml_round_trip_unchanged() {
    let written = r#"
        secret = "CLIENTSECRETCLIENTSECRETCLIENTSE"
        created_at = "1700000000"
        pending_enrollment = "deadbeef"

        [devices.laptop]
        secret = "LAPTOPSECRETLAPTOPSECRETLAPTOPSE"
        created_at = "1700000000"
        "#;

    let parsed: ClientAuth = toml::from_str(written).expect("a client parses");
    let written_back = toml::to_string(&parsed).expect("a client serializes");

    assert!(
        written_back.contains(r#"secret = "CLIENTSECRETCLIENTSECRETCLIENTSE""#),
        "{written_back}"
    );
    assert!(
        written_back.contains(r#"pending_enrollment = "deadbeef""#),
        "{written_back}"
    );
    assert!(
        written_back.contains(r#"secret = "LAPTOPSECRETLAPTOPSECRETLAPTOPSE""#),
        "{written_back}"
    );
    // And it reads back as the same thing, which is the part that matters
    // for a file the server rewrites on every counter change.
    let reparsed: ClientAuth = toml::from_str(&written_back).expect("it parses back");
    assert_eq!(reparsed.secret.as_str(), "CLIENTSECRETCLIENTSECRETCLIENTSE");
    assert_eq!(
        reparsed.devices["laptop"].secret.as_str(),
        "LAPTOPSECRETLAPTOPSECRETLAPTOPSE"
    );
}

/// `Debug` is what a log line uses, and the whole config is logged when it
/// is parsed. A device secret is as live a credential as a client's — it
/// authenticates on its own — so it is redacted for the same reason.
#[test]
fn a_device_secret_is_no_more_printable_than_a_clients() {
    let mut c = client();
    c.secret = SecretString::new("CLIENTSECRETCLIENTSECRETCLIENTSE".to_string());
    c.devices.insert(
        "laptop".to_string(),
        device("LAPTOPSECRETLAPTOPSECRETLAPTOPSE"),
    );

    let rendered = format!("{c:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(
        !rendered.contains("CLIENTSECRETCLIENTSECRETCLIENTSE"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("LAPTOPSECRETLAPTOPSECRETLAPTOPSE"),
        "{rendered}"
    );
}

/// `counter_snapshot` exists so that counting a wrong code does not copy a
/// credential, and the table is the place a new field gets forgotten: it
/// is one level further from the field the comment was written about. The
/// device's stamp travels — it is what the writeback persists — but the
/// secret it sits next to must not.
#[test]
fn a_counter_snapshot_carries_no_device_secret() {
    let mut c = client();
    c.devices.insert(
        "laptop".to_string(),
        device("LAPTOPSECRETLAPTOPSECRETLAPTOPSE"),
    );
    let config = AuthConfig {
        enabled: true,
        clients: HashMap::from([("alice".to_string(), c)]),
        ..AuthConfig::default()
    };

    let snapshot = config.counter_snapshot();
    let snapshot = &snapshot.clients["alice"];

    assert!(snapshot.secret.expose_secret().is_empty());
    let laptop = &snapshot.devices["laptop"];
    assert!(laptop.secret.expose_secret().is_empty(), "{snapshot:?}");
    assert!(laptop.public_key.is_none(), "{snapshot:?}");
    assert!(laptop.created_at.is_empty(), "{snapshot:?}");
}
