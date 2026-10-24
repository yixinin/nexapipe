//! A pattern that is the catch-all in another spelling is refused.
//!
//! The fold a host pattern goes through takes the trailing dots and the
//! brackets off, so `*.`, `*..` and `[*]` all become `*` — the catch-all.
//! A config that meant one host, or one suffix, would then serve every host,
//! and the failure mode is silent: the pattern is folded before it is ever
//! matched, so nothing says the route covers more than it says.
//!
//! These tests pin where the refusal happens: where the pattern is
//! configured, which is the only place an operator can see it. The catch-all
//! itself is spelled `*` and is not refused — a config that says every host
//! means every host.

use nexapipe::config::ProxyConfig;

/// Writes a config with the given body and loads it.
fn load(body: &str) -> anyhow::Result<(ProxyConfig, Option<nexapipe::auth::AuthConfig>)> {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, body).expect("write the config");
    ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
}

/// The spellings that fold into the catch-all.
const CATCH_ALL_SPELLINGS: [&str; 5] = ["*.", "*..", "[*]", "[*].", "*[]"];

/// A route whose `host_pattern` folds into the catch-all is refused: the
/// route would serve every host instead of the one it names.
#[test]
fn a_route_that_folds_into_the_catch_all_is_refused() {
    for spelling in CATCH_ALL_SPELLINGS {
        let (config, _) = load(&format!(
            "[[routes]]\nhost_pattern = \"{spelling}\"\nbackends = [\"http://127.0.0.1:18080\"]\n"
        ))
        .expect("the config itself parses");

        let error = config
            .build_routes()
            .expect_err("the pattern has to be refused");

        let message = error.to_string();
        assert!(
            message.contains("catch-all"),
            "{spelling} must be refused as the catch-all: {message}"
        );
    }
}

/// An `allow_hosts` entry that folds into the catch-all is refused for the
/// same reason: a client whose allow-list reads as one host would be
/// authorized for every one of them.
#[test]
fn an_allow_hosts_entry_that_folds_into_the_catch_all_is_refused() {
    for spelling in CATCH_ALL_SPELLINGS {
        let error = load(&format!(
            "[auth]\n\
             \n\
             [auth.clients.client-001]\n\
             secret = \"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\"\n\
             allow_hosts = [\"{spelling}\"]\n"
        ))
        .expect_err("the pattern has to be refused");

        let message = error.to_string();
        assert!(
            message.contains("catch-all"),
            "{spelling} must be refused as the catch-all: {message}"
        );
    }
}

/// The catch-all is spelled one way, and a config that says it means it.
#[test]
fn the_catch_all_is_accepted() {
    let (config, _) =
        load("[[routes]]\nhost_pattern = \"*\"\nbackends = [\"http://127.0.0.1:18080\"]\n")
            .expect("the catch-all has to load");

    let routes = config.build_routes().expect("the route is there");
    assert_eq!(routes.len(), 1, "the route is there");
}
