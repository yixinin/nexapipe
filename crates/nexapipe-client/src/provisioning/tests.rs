//! The tests of the provisioning module.
//!
//! They are in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.

use super::invite::is_usable_relay_hint;
use super::totp::parse_algorithm;
use super::uri::percent_encode;
use super::*;
use crate::auth::TotpAlgorithm;
use iroh::EndpointId;
use iroh_tickets::endpoint::EndpointTicket;

/// A relay hint that names no relay this client can reach is refused.
///
/// The URL parser accepting it is not the question: the hint is applied
/// later, as a relay URL, and a hint that names nothing usable is not a
/// hint.
#[test]
fn a_relay_hint_that_names_no_relay_is_refused() {
    for hint in [
        "ftp://relay.example.com",
        "file:///etc/passwd",
        "foo://relay.example.com",
        "https://",
        "https://aps1-1.relay.n0.iroh.link",
    ] {
        assert!(
            !is_usable_relay_hint(hint),
            "{hint:?} is not a relay this client can reach"
        );

        let uri = format!(
            "nexapipe://endpoint/{}?v=1&relay={}",
            node_id(),
            percent_encode(hint)
        );
        assert!(
            EndpointInvite::from_uri(&uri).is_err(),
            "a code carrying {hint:?} is refused"
        );
    }
}

/// A hint that names a relay this client can reach is kept.
///
/// A self-hosted relay over plain HTTP is a supported deployment, so
/// `http://` is as good as `https://` here.
#[test]
fn a_relay_hint_that_names_a_relay_is_kept() {
    for hint in [
        "https://relay.example.com",
        "http://relay.example.com",
        "wss://relay.example.com",
    ] {
        assert!(is_usable_relay_hint(hint), "{hint:?} is usable");
    }

    let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
        .unwrap()
        .with_relay(Some("https://relay.example.com"));
    assert_eq!(invite.relay.as_deref(), Some("https://relay.example.com"));
}

/// A hint that names no relay is dropped rather than obeyed.
#[test]
fn a_hint_that_names_no_relay_is_dropped_rather_than_obeyed() {
    let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
        .unwrap()
        .with_relay(Some("ftp://relay.example.com"));
    assert!(
        invite.relay.is_none(),
        "a hint that names no relay is not kept"
    );
}

/// A code past the hard limit is refused rather than parsed.
#[test]
fn a_code_past_the_hard_limit_is_refused() {
    let long = "x".repeat(MAX_URI_LEN + 1);
    let uri = format!("nexapipe://endpoint/{long}");
    let error = EndpointInvite::from_uri(&uri).expect_err("the code is past the limit");
    assert!(error.to_string().contains("past the"), "{error}");
}

/// The invite path and the configuration path read a name the same way.
///
/// They used to be two parsers: the invite one was strict and the
/// configuration one fell back to SHA1. A name the invite path refused and
/// the configuration path accepted was a name the two halves of the client
/// did not agree about.
#[test]
fn the_invite_and_the_configuration_read_a_name_the_same_way() {
    for name in ["sha1", "sha256", "sha512", "SHA1", "SHA256", "SHA512"] {
        let invite = parse_algorithm(Some(name)).expect("the invite path accepts it");
        let config = TotpAlgorithm::try_from_name(name).expect("the config path accepts it");
        assert_eq!(invite, config, "{name:?} is read the same way by both");
    }

    for name in ["sha-256", "SHA3-256", "sha", "sha 256", "sha1x"] {
        assert!(
            parse_algorithm(Some(name)).is_err(),
            "the invite path refuses {name:?}"
        );
        assert!(
            TotpAlgorithm::try_from_name(name).is_err(),
            "the configuration path refuses {name:?}"
        );
    }
}

/// An invite that names no algorithm gets the default.
#[test]
fn an_invite_that_names_no_algorithm_gets_the_default() {
    assert_eq!(
        parse_algorithm(None).expect("the default"),
        TotpAlgorithm::SHA1
    );
    assert_eq!(
        parse_algorithm(Some("")).expect("the default"),
        TotpAlgorithm::SHA1
    );
}

/// A Node ID nobody is listening on.
///
/// Derived from a fixed seed instead of being random: every test compares a
/// parsed invite against the one it was built from, which only works when
/// the identity is stable. It has to be a real public key, because parsing
/// a Node ID checks that the point is valid, not just that it is 64 hex
/// characters.
fn node_id() -> String {
    iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string()
}

/// A real ticket, produced by the same encoder the app reads back, so the
/// round trip exercises the format rather than a made-up sample.
fn ticket() -> String {
    let id: EndpointId = node_id().parse().expect("the test node ID is well formed");
    EndpointTicket::new(id.into()).to_string()
}

fn invite() -> EndpointInvite {
    EndpointInvite::new(
        EndpointTarget::NodeId(node_id().to_string()),
        &["a.example".to_string(), "b.example".to_string()],
    )
    .unwrap()
    .with_name("Home")
    .with_totp(Some(
        InviteTotp::new("client-001", "jbswy3dpehpk3pxp").unwrap(),
    ))
}

#[test]
fn round_trips_every_field() {
    let parsed = EndpointInvite::from_uri(&invite().to_uri()).unwrap();
    assert_eq!(parsed, invite());
}

#[test]
fn round_trips_a_bare_endpoint() {
    let invite = EndpointInvite::new(
        EndpointTarget::NodeId(node_id().to_string()),
        &["a.example".to_string()],
    )
    .unwrap();
    let uri = invite.to_uri();
    assert_eq!(
        uri,
        format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}?v=1&domains=a.example",
            invite.target
        )
    );
    assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite);
}

#[test]
fn round_trips_a_ticket_target() {
    let target = EndpointTarget::Ticket(ticket());
    let invite = EndpointInvite::new(target.clone(), &["a.example".to_string()]).unwrap();
    let uri = invite.to_uri();
    assert!(
        uri.starts_with(&format!("{INVITE_SCHEME}://{TICKET_HOST}/")),
        "{uri}"
    );
    assert_eq!(EndpointInvite::from_uri(&uri).unwrap().target, target);
}

#[test]
fn leaves_optional_fields_out_of_the_uri() {
    let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[]).unwrap();
    let uri = invite.to_uri();
    assert!(!uri.contains("name="), "{uri}");
    assert!(!uri.contains("domains="), "{uri}");
    assert!(!uri.contains("relay="), "{uri}");
    assert!(!uri.contains("secret="), "{uri}");
}

#[test]
fn accepts_any_case_of_the_scheme() {
    let uri = invite().to_uri().replace("nexapipe://", "NEXAPIPE://");
    assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite());
}

#[test]
fn percent_decodes_values() {
    let invite = invite()
        .with_name("My VPN @ home")
        .with_relay(Some("https://relay.example"));
    let uri = invite.to_uri();
    assert!(uri.contains("My%20VPN%20%40%20home"), "{uri}");
    assert!(uri.contains("https%3A%2F%2Frelay.example"), "{uri}");
    assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite);
}

#[test]
fn keeps_the_comma_separator_readable() {
    let uri = invite().to_uri();
    assert!(uri.contains("domains=a.example,b.example"), "{uri}");
}

#[test]
fn tolerates_percent_encoded_commas() {
    let uri = invite().to_uri().replace(
        "domains=a.example,b.example",
        "domains=a.example%2Cb.example",
    );
    assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite());
}

#[test]
fn ignores_unknown_parameters_for_forward_compatibility() {
    let uri = format!(
        "{}&strike=magnet&relay=https%3A%2F%2Frelay.example",
        invite().to_uri()
    );
    let parsed = EndpointInvite::from_uri(&uri).unwrap();
    assert_eq!(parsed.relay.as_deref(), Some("https://relay.example"));
    assert_eq!(parsed.domains, invite().domains);
}

#[test]
fn keeps_the_first_occurrence_of_a_repeated_parameter() {
    let base = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[]).unwrap();
    let uri = format!("{}&domains=a.example&domains=b.example", base.to_uri());
    assert_eq!(
        EndpointInvite::from_uri(&uri).unwrap().domains,
        vec!["a.example".to_string()]
    );
}

#[test]
fn drops_a_trailing_fragment() {
    let uri = format!("{}#/from-a-browser", invite().to_uri());
    assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite());
}

#[test]
fn rejects_another_scheme() {
    let error = EndpointInvite::from_uri("https://example.com/?v=1").unwrap_err();
    assert!(
        error.to_string().contains("not a nexapipe:// invite code"),
        "{error}"
    );
}

#[test]
fn rejects_an_unknown_host() {
    let error = EndpointInvite::from_uri(&format!("{INVITE_SCHEME}://server/abc?v=1")).unwrap_err();
    assert!(error.to_string().contains("unknown invite kind"), "{error}");
}

#[test]
fn rejects_a_future_version() {
    // v=2 became real — enrollment — so the version nobody can read is the
    // next one along.
    let error = EndpointInvite::from_uri(&format!(
        "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?v=3",
        node_id()
    ))
    .unwrap_err();
    assert!(
        error.to_string().contains("unsupported invite version 3"),
        "{error}"
    );
}

#[test]
fn rejects_a_node_id_that_is_not_hex() {
    let error = EndpointInvite::from_uri(&format!("{INVITE_SCHEME}://{NODE_ID_HOST}/nope?v=1"))
        .unwrap_err();
    assert!(error.to_string().contains("is not a Node ID"), "{error}");
}

#[test]
fn node_id_lookups_work_on_built_targets() {
    let id = node_id();
    let target = EndpointTarget::node_id_target(&id).unwrap();
    assert_eq!(target.node_id().unwrap().to_string(), id);
}

#[test]
fn normalizes_domains() {
    let invite = EndpointInvite::new(
        EndpointTarget::NodeId(node_id().to_string()),
        &[
            " A.example. ".to_string(),
            "a.example".to_string(),
            "B.EXAMPLE".to_string(),
        ],
    )
    .unwrap();
    assert_eq!(
        invite.domains,
        vec!["a.example".to_string(), "b.example".to_string()]
    );
}

/// The domain list is a list of patterns, and the server's route patterns
/// are what ends up in an invite.
///
/// `*.` is the catch-all in another spelling: folded into `*`, it would
/// hand the client the catch-all — every host — for a spelling that asked
/// for something narrower. It keeps its own shape instead, and a pattern
/// in that shape matches nothing.
#[test]
fn a_pattern_that_folds_into_the_catch_all_keeps_its_shape() {
    let invite = EndpointInvite::new(
        EndpointTarget::NodeId(node_id().to_string()),
        &["*.example.com".to_string(), "*.".to_string()],
    )
    .unwrap();
    assert_eq!(
        invite.domains,
        vec!["*.example.com".to_string(), "*.".to_string()]
    );
    // And so the client does not proxy every host on the strength of a
    // spelling that never asked for it.
    let proxied = crate::domains::should_proxy_domain("example.com", &invite.domains);
    assert!(!proxied);
}

#[test]
fn rejects_broken_domain_lists() {
    fn error_for(list: &str) -> String {
        let uri = format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?domains={list}",
            node_id()
        );
        EndpointInvite::from_uri(&uri).unwrap_err().to_string()
    }
    assert!(
        error_for("a,,b").contains("empty entry"),
        "{}",
        error_for("a,,b")
    );
    assert!(
        error_for("a%2Fb").contains("is not a valid domain"),
        "{}",
        error_for("a%2Fb")
    );
}

#[test]
fn rejects_a_relay_that_is_not_a_url() {
    let uri = format!(
        "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?relay=not-a-url",
        node_id()
    );
    let error = EndpointInvite::from_uri(&uri).unwrap_err();
    assert!(error.to_string().contains("is invalid"), "{error}");
}

#[test]
fn normalizes_the_secret() {
    let totp = InviteTotp::new("client-001", " jbswy3dpehpk3pxp== ").unwrap();
    assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
    assert_eq!(totp.issuer, DEFAULT_ISSUER);
}

#[test]
fn rejects_a_secret_that_is_not_base32() {
    let error = InviteTotp::new("client-001", "hello-there").unwrap_err();
    assert!(error.to_string().contains("is not Base32"), "{error}");

    let error = InviteTotp::new("client-001", "ab").unwrap_err();
    assert!(error.to_string().contains("too short"), "{error}");
}

#[test]
fn a_rejected_secret_is_not_quoted_back() {
    // These errors are shown to a user and end up in logs, so the secret
    // has to stay out of them whatever the reason it was refused.
    for bad in ["hello-there", "ab", "JBSWY3DPEHPK3PX!"] {
        let error = InviteTotp::new("client-001", bad).unwrap_err();
        assert!(!error.to_string().contains(bad), "{error}");
    }
}

#[test]
fn needs_a_client_id_next_to_the_secret() {
    let uri = format!(
        "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?secret=JBSWY3DPEHPK3PXP",
        node_id()
    );
    let error = EndpointInvite::from_uri(&uri).unwrap_err();
    assert!(error.to_string().contains("no client id"), "{error}");
}

#[test]
fn needs_a_secret_next_to_the_other_two_factor_parameters() {
    let uri = format!(
        "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?client=client-001",
        node_id()
    );
    let error = EndpointInvite::from_uri(&uri).unwrap_err();
    assert!(error.to_string().contains("no secret"), "{error}");
}

#[test]
fn reads_a_nested_otpauth_uri() {
    let embedded = "otpauth%3A%2F%2Ftotp%2FNexaPipe%3Aclient-001%3Fsecret%3DJBSWY3DPEHPK3PXP\
                    %26issuer%3DNexaPipe%26algorithm%3DSHA256";
    let uri = format!(
        "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?otpauth={embedded}",
        node_id()
    );
    let parsed = EndpointInvite::from_uri(&uri).unwrap();
    let totp = parsed.totp.unwrap();
    assert_eq!(totp.client_id, "client-001");
    assert_eq!(totp.issuer, "NexaPipe");
    assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
    assert_eq!(totp.algorithm, TotpAlgorithm::SHA256);
}

#[test]
fn rejects_an_algorithm_the_client_cannot_generate() {
    let uri = format!(
        "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?client=client-001\
         &secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        node_id()
    );
    let error = EndpointInvite::from_uri(&uri).unwrap_err();
    assert!(
        error.to_string().contains("unsupported algorithm"),
        "{error}"
    );

    // The default is SHA1, and the name is case insensitive.
    let uri = format!(
        "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?client=client-001\
         &secret=JBSWY3DPEHPK3PXP&algorithm=sha256",
        node_id()
    );
    let parsed = EndpointInvite::from_uri(&uri).unwrap();
    assert_eq!(
        parsed.totp.unwrap().algorithm,
        TotpAlgorithm::SHA256,
        "unknown algorithms would silently become weaker codes"
    );
}

/// A code printed by `nexapipe --generate-invite`, byte for byte.
///
/// The Android client reimplements this module in Kotlin and reads exactly
/// these bytes, so the same fixture anchors both test suites: change the
/// grammar on either side and one of them fails.
#[test]
fn reads_a_code_printed_by_the_server() {
    let uri = "nexapipe://endpoint/a612286b30098f67db06783c45004e43cf182e06806540e7e6260a0f009a7063\
               ?v=1&name=Home&domains=example.com,api.example.com\
               &relay=https%3A%2F%2Frelay.example.com\
               &client=client-001&issuer=NexaPipe&secret=JBSWY3DPEHPK3PXP\
               &algorithm=SHA256&digits=6&period=30";
    let invite = EndpointInvite::from_uri(uri).unwrap();

    assert_eq!(
        invite.target,
        EndpointTarget::NodeId(
            "a612286b30098f67db06783c45004e43cf182e06806540e7e6260a0f009a7063".to_string()
        )
    );
    assert_eq!(invite.name.as_deref(), Some("Home"));
    assert_eq!(invite.domains, ["example.com", "api.example.com"]);
    assert_eq!(invite.relay.as_deref(), Some("https://relay.example.com"));

    let totp = invite.totp.as_ref().unwrap();
    assert_eq!(totp.client_id, "client-001");
    assert_eq!(totp.issuer, "NexaPipe");
    assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
    assert_eq!(totp.algorithm, TotpAlgorithm::SHA256);
    assert_eq!((totp.digits, totp.period), (6, 30));

    // The same code comes back out of `to_uri`, so a client can re-share
    // what it scanned.
    assert_eq!(EndpointInvite::from_uri(&invite.to_uri()).unwrap(), invite);
}

#[test]
fn warns_about_two_factor_parameters_the_client_drops() {
    let totp = InviteTotp::with_params(
        DEFAULT_ISSUER,
        "client-001",
        "JBSWY3DPEHPK3PXP",
        TotpAlgorithm::SHA512,
        8,
        60,
    )
    .unwrap();
    let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
        .unwrap()
        .with_totp(Some(totp.clone()));

    let warnings = invite.client_warnings();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("ignored"), "{warnings:?}");

    assert!(
        InviteTotp::new("client-001", "JBSWY3DPEHPK3PXP")
            .unwrap()
            .client_warnings()
            .is_empty()
    );
}

#[test]
fn an_enrollment_invite_round_trips_as_v2() {
    let enrollment = InviteEnrollment::new("client-001", "token-abc").unwrap();
    let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
        .unwrap()
        .with_name("Home")
        .with_enrollment(Some(enrollment.clone()));

    let uri = invite.to_uri();
    assert!(uri.contains("v=2"), "{uri}");
    assert!(uri.contains("enroll=token-abc"), "{uri}");
    assert!(!uri.contains("secret="), "{uri}");
    assert!(invite.is_enrollment());

    let parsed = EndpointInvite::from_uri(&uri).unwrap();
    assert_eq!(parsed, invite);
    assert_eq!(parsed.enrollment.as_ref().unwrap(), &enrollment);
    assert!(parsed.totp.is_none());
}

/// v=1 apps ignore parameters they do not know, so a token in a v=1 code
/// would be dropped and the scan would import a credential-less endpoint
/// that looks like it worked.
#[test]
fn a_v1_code_may_not_carry_an_enrollment_token() {
    let uri = format!(
        "nexapipe://endpoint/{}?v=1&client=client-001&enroll=token-abc",
        node_id()
    );
    let err = EndpointInvite::from_uri(&uri).unwrap_err().to_string();
    assert!(err.contains("enrollment"), "{err}");
}

/// A code that hands out both is a code that cannot say which one wins.
#[test]
fn a_token_and_a_secret_cannot_share_a_code() {
    let uri = format!(
        "nexapipe://endpoint/{}?v=2&client=client-001&enroll=token-abc&secret=JBSWY3DPEHPK3PXP",
        node_id()
    );
    let err = EndpointInvite::from_uri(&uri).unwrap_err().to_string();
    assert!(err.contains("both"), "{err}");

    // Same thing on the way out: whichever was attached last wins.
    let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
        .unwrap()
        .with_totp(Some(
            InviteTotp::new("client-001", "JBSWY3DPEHPK3PXP").unwrap(),
        ))
        .with_enrollment(Some(InviteEnrollment::new("client-001", "tok").unwrap()));
    assert!(invite.totp.is_none());
    assert!(invite.is_enrollment());
}

#[test]
fn an_empty_enrollment_token_is_refused() {
    assert!(InviteEnrollment::new("client-001", "  ").is_err());
    assert!(InviteEnrollment::new("", "tok").is_err());
}

/// A secret is a credential, so nothing that formats an invite — a parse
/// error, a UI binding, a log line — may carry one.
#[test]
fn debug_never_prints_the_secret() {
    let totp = InviteTotp::new("client-001", "jbswy3dpehpk3pxp").unwrap();
    let printed = format!("{totp:?}");
    // Static messages, not `{printed}`: an assertion message is a log sink
    // to a scanner, and one that prints the Debug output taints the secret
    // straight into it — even though what it would print is already
    // redacted, which taint tracking cannot see.
    assert!(
        !printed.contains("JBSWY3DPEHPK3PXP"),
        "the secret must not appear in Debug output"
    );
    assert!(
        printed.contains("***"),
        "the redaction marker must appear in Debug output"
    );
}

#[test]
fn debug_never_prints_the_enrollment_token() {
    let enrollment = InviteEnrollment::new("client-001", "tok-abc").unwrap();
    let printed = format!("{enrollment:?}");
    assert!(
        !printed.contains("tok-abc"),
        "the token must not appear in Debug output"
    );
    assert!(
        printed.contains("***"),
        "the redaction marker must appear in Debug output"
    );
}

/// The whole invite carries whichever of the two it was given, so its own
/// `Debug` has to be redacted as well — and the URI must *not* be, because
/// a redacted invite scans to nothing.
#[test]
fn debug_of_a_whole_invite_redacts_the_credential_it_carries() {
    let printed = format!("{:?}", invite());
    assert!(!printed.contains("JBSWY3DPEHPK3PXP"), "{printed}");
    assert!(invite().to_uri().contains("secret=JBSWY3DPEHPK3PXP"));

    let with_token = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
        .unwrap()
        .with_enrollment(Some(
            InviteEnrollment::new("client-001", "tok-abc").unwrap(),
        ));
    assert!(!format!("{with_token:?}").contains("tok-abc"));
    assert!(with_token.to_uri().contains("enroll=tok-abc"));
}

/// A parameter's *name* is matched without its case.
///
/// The name is what decides whether a parameter is read at all, and a
/// parameter that is not read is an unknown one — and unknown parameters are
/// dropped. So `Secret=…` used to be dropped whole: the code imported as an
/// endpoint with no second factor at all, while the app that reads the same
/// code kept the credential and authenticated with it. The Android codec
/// folds the name too, and the two have to agree about which codes are codes.
#[test]
fn a_parameter_name_is_matched_without_its_case() {
    let bare = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[]).unwrap();
    let uri = format!(
        "{}&Secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&client=client-001",
        bare.to_uri()
    );
    let parsed = EndpointInvite::from_uri(&uri).expect("the code carries a credential");
    let totp = parsed.totp.expect("the credential is not dropped");
    assert_eq!(totp.client_id, "client-001");
    assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
}

/// A malformed escape sequence is refused rather than kept as a literal `%`.
///
/// The Android codec used to keep it, so a code the desktop app refused
/// imported there as an endpoint with a name of `%ZZ` in it.
#[test]
fn a_malformed_escape_sequence_is_refused() {
    let uri = format!("{}&name=%ZZ", invite().to_uri());
    let error = EndpointInvite::from_uri(&uri).expect_err("the escape is malformed");
    assert!(error.to_string().contains("escape sequence"), "{error}");
}

/// Bytes that are not UTF-8 are refused rather than turned into replacement
/// characters.
///
/// The Android codec used to substitute them, so the same code named an
/// endpoint here and named something else there.
#[test]
fn a_code_that_is_not_utf8_is_refused() {
    let uri = format!("{}&name=%C3%28", invite().to_uri());
    let error = EndpointInvite::from_uri(&uri).expect_err("the bytes are not UTF-8");
    assert!(error.to_string().contains("UTF-8"), "{error}");
}

/// A parameter with no name is a malformed one, and the code is refused.
///
/// The Android codec used to drop it and read the rest, so the two halves
/// disagreed about which codes are codes.
#[test]
fn a_parameter_with_no_name_is_refused() {
    let uri = format!("{}&=x", invite().to_uri());
    let error = EndpointInvite::from_uri(&uri).expect_err("the parameter has no name");
    assert!(error.to_string().contains("malformed parameter"), "{error}");
}
