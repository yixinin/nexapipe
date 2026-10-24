//! A key the config file names and the server does not know is an error.
//!
//! A key that is silently dropped is a setting the operator believes is in
//! force. `exposee = true` under `[server]` used to be dropped without a word,
//! and the server it produced looked exactly like a server that never had the
//! key — for a key that gates reachability, a typo and "off" were the same
//! deployment.
//!
//! These tests pin the refusal from the outside: one case per section, the
//! error naming the key, and the shipped examples still loading — a config
//! that has been wrong for years is still a config that has to work.

use nexapipe::config::ProxyConfig;

/// One section, and a key in it that does not exist.
struct Case {
    /// Where the key sits, for the failure message.
    section: &'static str,
    /// The file, with the key in it.
    file: &'static str,
    /// The key that does not exist.
    key: &'static str,
}

/// Every section of the config file, each with the smallest file that carries
/// a key it does not have.
///
/// The last three were already strict before this change — `[limits]`,
/// `[peers]` and `[auth]` refused unknown keys from the start — and they are
/// here because the rule is worth having in one place: a section that is
/// strict next to a section that is not is a section nobody can reason about.
const CASES: &[Case] = &[
    Case {
        section: "the top level",
        file: "debugg = false\n",
        key: "debugg",
    },
    Case {
        section: "[server]",
        file: "[server]\nexposee = true\n",
        key: "exposee",
    },
    Case {
        section: "[[routes]]",
        file: "[[routes]]\nhost_pattern = \"*\"\nbackends = [\"http://127.0.0.1:1\"]\nmodde = \"http\"\n",
        key: "modde",
    },
    Case {
        section: "[iroh]",
        file: "[iroh]\nrelay_modee = \"default\"\n",
        key: "relay_modee",
    },
    Case {
        section: "[log]",
        file: "[log]\nfilee = true\n",
        key: "filee",
    },
    Case {
        section: "[timeouts]",
        file: "[timeouts]\nconnect_secs = 5\nconnect_secss = 5\n",
        key: "connect_secss",
    },
    Case {
        section: "[backends]",
        file: "[backends]\nca_filee = \"/etc/ssl/ca.pem\"\n",
        key: "ca_filee",
    },
    Case {
        section: "[admin]",
        file: "[admin]\nlisten_addr = \"127.0.0.1:9090\"\ntoken = \"from-the-config\"\n",
        key: "token",
    },
    Case {
        section: "[metrics]",
        file: "[metrics]\nenabledd = true\n",
        key: "enabledd",
    },
    Case {
        section: "[health_check]",
        file: "[health_check]\nintervall = 10\n",
        key: "intervall",
    },
    Case {
        section: "[local_proxy]",
        file: "[local_proxy]\nenabled = false\nlisten_addr = \"127.0.0.1:8081\"\nproxy_domains = []\nstrategie = \"round_robin\"\n",
        key: "strategie",
    },
    Case {
        section: "[[local_proxy.nodes]]",
        file: "[local_proxy]\nenabled = false\nlisten_addr = \"127.0.0.1:8081\"\nproxy_domains = []\n\n[[local_proxy.nodes]]\nserver_node_id = \"0123456789abcdef\"\ndomainz = []\n",
        key: "domainz",
    },
    Case {
        section: "[local_proxy.two_factor]",
        file: "[local_proxy]\nenabled = false\nlisten_addr = \"127.0.0.1:8081\"\nproxy_domains = []\n\n[local_proxy.two_factor]\nenabled = true\nclient_id = \"client-001\"\nsecret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\nalgorithmme = \"sha1\"\n",
        key: "algorithmme",
    },
    Case {
        section: "[retry]",
        file: "[retry]\nattemptss = 2\n",
        key: "attemptss",
    },
    Case {
        section: "[circuit_breaker]",
        file: "[circuit_breaker]\nfailure_thresholdh = 5\n",
        key: "failure_thresholdh",
    },
    Case {
        section: "[limits]",
        file: "[limits]\nmax_connections_per_peerr = 64\n",
        key: "max_connections_per_peerr",
    },
    Case {
        section: "[peers]",
        file: "[peers]\nalloww = []\n",
        key: "alloww",
    },
];

/// Writes a config file and loads it the way a start does.
fn load(file: &str) -> anyhow::Result<ProxyConfig> {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, file).expect("write the config");
    ProxyConfig::from_file(path.to_str().expect("utf-8 path"))
}

/// Every section refuses a key it does not know, and the error names it.
///
/// The name is the whole point: an error that says "unknown field" without
/// saying which field leaves the operator to diff the file against a
/// documentation page, and the one they need is the one the file says.
#[test]
fn an_unknown_key_is_refused_in_every_section() {
    for case in CASES {
        let error = load(case.file).expect_err(&format!(
            "{}: a key this build does not know is refused",
            case.section
        ));
        let message = error.to_string();
        assert!(
            message.contains(case.key),
            "{}: the error names the key: {message}",
            case.section
        );
    }
}

/// The same refusal, from the loader the server itself uses.
///
/// `from_file` and `load_with_auth` parse the file separately, and a key
/// that one of them refuses the other has to refuse as well — a config that
/// starts on one path and is refused on the other is a config that behaves
/// differently depending on which code is looking at it.
#[test]
fn the_loader_the_server_uses_refuses_an_unknown_key_too() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[server]\nexposee = true\n").expect("write the config");

    let error = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect_err("a key this build does not know is refused");
    assert!(
        error.to_string().contains("exposee"),
        "the error names the key: {error:#}"
    );
}

/// The error says what to do about it.
///
/// The key's name is in the error already; what is not is the one thing the
/// operator can do about it, and it is the same either way: the key is a
/// typo, or it belongs to a version of the file this build does not read.
#[test]
fn the_error_says_what_to_do_with_an_unknown_key() {
    let error = load("[server]\nexposee = true\n").expect_err("the key is refused");
    let message = error.to_string();
    assert!(
        message.contains("spelling"),
        "the error says how to fix it: {message}"
    );
}

/// The shipped examples still load.
///
/// A config that has been wrong for years is still a config that has to work:
/// the refusal is for keys nobody meant to write, not for the ones every
/// deployment has been carrying.
#[test]
fn the_shipped_examples_still_load() {
    let examples: &[(&str, &str)] = &[
        (
            "config.toml.example",
            include_str!("../../../config.toml.example"),
        ),
        (
            "config.toml.2fa.example",
            include_str!("../../../config.toml.2fa.example"),
        ),
        (
            "first-run-config.toml",
            include_str!("../templates/first-run-config.toml"),
        ),
    ];

    for (name, file) in examples {
        load(file).unwrap_or_else(|e| panic!("{name} still loads: {e:#}"));
    }
}

/// The 2FA example still loads *and* still carries its 2FA.
///
/// The `[auth]` section is parsed by the loader that owns it, not by the
/// top-level parse, and the top-level parse has to leave it alone: the seeds
/// in it are credentials, and a copy of them inside the configuration would be
/// a second copy of every secret in the file.
#[test]
fn the_auth_section_is_still_read() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[auth]\nenabled = true\nissuer = \"NexaPipe\"\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n",
    )
    .expect("write the config");

    let (config, auth) =
        ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path")).expect("the config parses");
    let auth = auth.expect("[auth] was read");
    assert!(auth.enabled, "2FA is on");
    assert_eq!(auth.issuer, "NexaPipe");
    assert!(
        config.admin.is_none(),
        "the rest of the file was read too: nothing else is in it"
    );
}

/// A config without an `[auth]` section is still a config without 2FA.
#[test]
fn a_config_without_an_auth_section_loads() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "debug = false\n").expect("write the config");

    let (_, auth) =
        ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path")).expect("the config parses");
    assert!(auth.is_none(), "no [auth] section means no 2FA");
}
