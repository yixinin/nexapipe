//! The tests of the endpoint group.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.
use super::*;
use crate::auth::TotpAlgorithm;
use iroh::endpoint::presets;

/// A syntactically valid backend node ID that no endpoint is bound to.
fn unused_backend_id() -> EndpointId {
    iroh::SecretKey::generate()
        .public()
        .to_string()
        .parse()
        .expect("a generated public key is a valid node ID")
}

fn node(backend: EndpointId, domain: &str) -> NodeConfig {
    NodeConfig {
        server_node_id: Some(backend.to_string()),
        server_ticket: None,
        domains: vec![domain.to_string()],
    }
}

/// A set of pools with no backend in it, for a test that only asks what
/// the index does with a pattern.
fn empty_domain_pools() -> Arc<DomainPools> {
    Arc::new(DomainPools::new(
        Vec::new(),
        LoadBalancingStrategy::RoundRobin,
        Arc::new(Mutex::new(HashMap::new())),
        traffic::table(),
        traffic::flow_registry(),
    ))
}

/// Regression guard: the group must report the *configured* backend IDs.
///
/// When every pool shares one caller-owned endpoint (the Android JNI shape),
/// `IrohConnectionPool::node_id()` answers with the same local endpoint ID
/// for all of them. Reporting that made `preconnect_all` dedupe every
/// backend into a single probe, so only one of N nodes was ever checked and
/// N-1 unreachable nodes went unnoticed.
#[tokio::test]
async fn node_ids_are_the_configured_backends_not_the_local_endpoint() {
    let ep = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("binding a local endpoint needs no network");

    let backend_a = unused_backend_id();
    let backend_b = unused_backend_id();
    assert_ne!(backend_a, backend_b);

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![
            node(backend_a, "a.example.com"),
            node(backend_b, "b.example.com"),
        ],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep.clone(),
    )
    .await
    .expect("a bogus but well-formed node ID must still build a group");

    let ids = group.node_ids();
    assert_eq!(ids.len(), 2, "both backends must be listed: {ids:?}");
    assert!(ids.contains(&backend_a), "{ids:?} is missing {backend_a}");
    assert!(ids.contains(&backend_b), "{ids:?} is missing {backend_b}");
    assert!(
        !ids.contains(&ep.id()),
        "the group reported its local endpoint ID {ids:?} instead of the backends"
    );
}

/// Two distinct backends behind two domains must stay two pools, so the
/// dedup in `preconnect_all` probes each of them.
#[tokio::test]
async fn distinct_backends_stay_distinct_pools() {
    let ep = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("binding a local endpoint needs no network");

    let backend_a = unused_backend_id();
    let backend_b = unused_backend_id();

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![
            node(backend_a, "a.example.com"),
            node(backend_b, "b.example.com"),
        ],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    // One pool per backend, and each domain load-balances over its own pool.
    for (domain, expected) in [("a.example.com", backend_a), ("b.example.com", backend_b)] {
        let pools = group
            .domains
            .get(domain)
            .expect("the domain must have a pool");
        assert_eq!(pools.pools.len(), 1, "{domain} should map to one pool");
        assert_eq!(pools.pools[0].backend_id(), expected);
    }
}

/// The backend a host is sent to, or `None` when the group has none for it.
fn served_by(group: &EndpointGroup, host: &str) -> Option<EndpointId> {
    group
        .pools_for(host)
        .map(|pools| pools.pools[0].backend_id())
}

/// A wildcard mapping has to serve the names it covers.
///
/// The client decides `www.example.com` belongs in the tunnel because
/// `*.example.com` covers it, and the backend it is sent to is named by
/// that same list. A lookup that knew only exact names would not find the
/// wildcard mapping, and the request would go to the default backend or
/// to none.
#[tokio::test]
async fn a_wildcard_mapping_serves_the_names_it_covers() {
    let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
    let backend = unused_backend_id();

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![node(backend, "*.example.com")],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    assert_eq!(served_by(&group, "www.example.com"), Some(backend));
    assert_eq!(served_by(&group, "a.b.example.com"), Some(backend));
    // The apex is not under its own wildcard, the way DNS reads it.
    assert_eq!(served_by(&group, "example.com"), None);
}

/// A bare mapping is that name and nothing else.
///
/// The lookup used to walk up the labels, so `example.com` answered for
/// `www.example.com` as well. That is the rule the client used before the
/// patterns were unified, and it is the rule the server never had.
#[tokio::test]
async fn a_bare_mapping_does_not_serve_a_subdomain() {
    let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
    let backend = unused_backend_id();

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![node(backend, "example.com")],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    assert_eq!(served_by(&group, "example.com"), Some(backend));
    assert_eq!(served_by(&group, "www.example.com"), None);
}

/// A wildcard and the apex it sits next to are two mappings, and the
/// wildcard is the one that serves the subdomain.
///
/// The old lookup answered with the apex, because it walked up the labels
/// — the request went to a backend that was not the one the pattern named.
#[tokio::test]
async fn a_wildcard_serves_the_subdomain_rather_than_the_apex() {
    let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
    let apex_backend = unused_backend_id();
    let wildcard_backend = unused_backend_id();

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![
            node(apex_backend, "example.com"),
            node(wildcard_backend, "*.example.com"),
        ],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    assert_eq!(served_by(&group, "example.com"), Some(apex_backend));
    assert_eq!(served_by(&group, "www.example.com"), Some(wildcard_backend));
}

/// Where two wildcards cover the same name, the more specific one answers.
#[tokio::test]
async fn the_most_specific_wildcard_serves_the_name() {
    let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
    let broad_backend = unused_backend_id();
    let narrow_backend = unused_backend_id();

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![
            node(broad_backend, "*.example.com"),
            node(narrow_backend, "*.www.example.com"),
        ],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    assert_eq!(served_by(&group, "a.example.com"), Some(broad_backend));
    assert_eq!(served_by(&group, "a.www.example.com"), Some(narrow_backend));
}

/// A pattern that matches nothing serves nothing.
///
/// `*.` is the catch-all in another spelling, and the rule in
/// `nexapipe-proto` refuses it and matches it with nothing: a
/// configuration that was never meant to be loaded cannot widen what a
/// client proxies. The client warns about the spelling rather than
/// refusing the configuration, so the pattern does reach the lookup — and
/// a lookup that keyed a pattern by the name it covers gave `*.` the
/// catch-all's own key, because the name `*.` covers is the empty one.
/// A client configured with `*.` alone would have served **every** host.
#[tokio::test]
async fn a_pattern_that_matches_nothing_serves_nothing() {
    let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
    let backend = unused_backend_id();

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![node(backend, "*.")],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    assert_eq!(served_by(&group, "example.com"), None);
    assert_eq!(served_by(&group, "www.example.com"), None);
    assert_eq!(served_by(&group, "anything.test"), None);
}

/// The catch-all is the catch-all, whatever else is configured.
///
/// The catch-all is filed under the empty name, and `*.` — a pattern that
/// matches nothing — would have claimed that same key. Which of the two
/// answered a name then depended on the order the map happened to be
/// walked in, so the same configuration served different hosts from one
/// run to the next.
///
/// Each map below is built afresh, and each is walked in its own order,
/// so the old answer shows itself in at least one of them.
#[test]
fn the_catch_alls_key_belongs_to_the_catch_all() {
    let catch_all = empty_domain_pools();
    let unusable = empty_domain_pools();

    for _ in 0..32 {
        let mut domains = HashMap::new();
        domains.insert("*".to_string(), catch_all.clone());
        domains.insert("*.".to_string(), unusable.clone());

        let wildcards = wildcards_of(&domains);
        let filed = wildcards
            .get("")
            .expect("the catch-all is filed under the empty name");
        assert!(
            Arc::ptr_eq(filed, &catch_all),
            "the catch-all's own key was given to a pattern that matches nothing"
        );
    }
}

/// The empty name is the catch-all's key, and the catch-all's alone.
///
/// A pattern that matches nothing covers no name at all, so it is filed
/// under no key — it is not the catch-all, whatever its spelling.
#[test]
fn a_pattern_that_matches_nothing_is_filed_under_no_key_at_all() {
    let unusable = empty_domain_pools();

    let mut domains = HashMap::new();
    domains.insert("*.".to_string(), unusable.clone());

    assert!(
        wildcards_of(&domains).is_empty(),
        "a pattern that matches nothing must not be indexed"
    );

    // And the catch-all itself is filed under the empty name.
    let mut domains = HashMap::new();
    domains.insert("*".to_string(), unusable.clone());
    assert!(
        wildcards_of(&domains).contains_key(""),
        "the catch-all is filed under the empty name"
    );
}

/// A name written the way DNS writes it — with the trailing dot — is the
/// same name, and finds the same backend.
#[tokio::test]
async fn a_name_with_a_trailing_dot_finds_its_mapping() {
    let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
    let backend = unused_backend_id();

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![node(backend, "example.com")],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    assert_eq!(served_by(&group, "example.com."), Some(backend));
    assert_eq!(served_by(&group, "EXAMPLE.com"), Some(backend));
}

/// The two answers have to be the same answer.
///
/// Whether a name belongs in the tunnel and which backend serves it are
/// two halves of one question, and the configuration spells the pattern
/// once. A name the rule covers but the lookup cannot find is a name the
/// client carries and the server has no route for — the failure this
/// whole change is about.
#[tokio::test]
async fn the_backend_lookup_agrees_with_the_membership_rule() {
    let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
    let backend = unused_backend_id();
    let patterns = ["example.com", "*.wild.test"];

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        patterns
            .iter()
            .map(|pattern| node(backend, pattern))
            .collect(),
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    let patterns: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
    for host in [
        "example.com",
        "www.example.com",
        "a.wild.test",
        "wild.test",
        "notexample.com",
    ] {
        let proxied = crate::domains::should_proxy_domain(host, &patterns);
        let served = group.pools_for(host).is_some();
        assert_eq!(
            proxied, served,
            "{host}: the membership rule and the backend lookup disagree"
        );
    }
}

/// Credentials given for one backend must not reach any other.
///
/// `set_two_factor` writes to every pool, so the only way a client can hold
/// a different key per server is `set_two_factor_for`. If it ever leaks, a
/// server that has no 2FA at all gets an auth stream it never asked for.
#[tokio::test]
async fn per_backend_two_factor_does_not_spill_to_other_backends() {
    let ep = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("binding a local endpoint needs no network");

    let backend_a = unused_backend_id();
    let backend_b = unused_backend_id();

    let group = EndpointGroup::new_with_nodes_and_endpoint(
        vec![
            node(backend_a, "a.example.com"),
            node(backend_b, "b.example.com"),
        ],
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    let auth = TwoFactorAuth::new(
        "client-a",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        TotpAlgorithm::SHA1,
    )
    .expect("a Base32 secret must decode");
    group
        .set_two_factor_for(&backend_a.to_string(), Some(auth))
        .await;

    for (domain, expected) in [("a.example.com", true), ("b.example.com", false)] {
        let pools = group
            .domains
            .get(domain)
            .expect("the domain must have a pool");
        for pool in &pools.pools {
            assert_eq!(
                pool.has_two_factor().await,
                expected,
                "{domain} (backend {}) should{} have credentials",
                pool.backend_id(),
                if expected { "" } else { " not" }
            );
        }
    }
}

/// A group with no backend must not look like a reachable one: the callers
/// treat an empty report as a failed start, so `total()` has to be 0 rather
/// than "all of nothing answered".
#[tokio::test]
async fn group_without_backends_reports_nothing_probed() {
    let ep = Endpoint::builder(presets::N0).bind().await.unwrap();
    let group = EndpointGroup::new_with_nodes_and_endpoint(
        Vec::new(),
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .unwrap();

    let report = group.preconnect_report().await;
    assert_eq!(report.total(), 0);
    assert!(!report.any_reachable());
    assert_eq!(report.unreachable_ids(), "");
}

/// The report is what callers put in their error messages, so the summary
/// must name exactly the backends that failed and nothing else.
#[test]
fn report_names_only_the_unreachable_backends() {
    let reached = unused_backend_id();
    let failed = unused_backend_id();

    let report = PreconnectReport {
        reachable: vec![reached],
        unreachable: vec![failed],
        auth_required: Vec::new(),
    };

    assert_eq!(report.total(), 2);
    assert!(report.any_reachable());
    assert!(!report.any_auth_required());
    assert_eq!(report.unreachable_ids(), failed.to_string());
    assert!(!report.unreachable_ids().contains(&reached.to_string()));

    let all_failed = PreconnectReport {
        reachable: Vec::new(),
        unreachable: vec![reached, failed],
        auth_required: Vec::new(),
    };
    assert!(!all_failed.any_reachable());
    assert_eq!(
        all_failed.unreachable_ids(),
        format!("{}, {}", reached, failed)
    );

    // A backend that answers the handshake and then refuses it for missing
    // 2FA is unreachable *and* named as such: the caller's error message
    // has to be able to say why.
    let needs_2fa = PreconnectReport {
        reachable: Vec::new(),
        unreachable: vec![failed],
        auth_required: vec![failed],
    };
    assert!(!needs_2fa.any_reachable());
    assert!(needs_2fa.any_auth_required());
}

/// A group with two backends, bound to a local endpoint. Nothing is dialled
/// by building it, so the tests below decide what each "probe" found.
async fn group_with(backends: &[EndpointId]) -> EndpointGroup {
    let ep = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("binding a local endpoint needs no network");
    EndpointGroup::new_with_nodes_and_endpoint(
        backends
            .iter()
            .enumerate()
            .map(|(i, id)| node(*id, &format!("backend{i}.example.com")))
            .collect(),
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .expect("a bogus but well-formed node ID must still build a group")
}

/// The snapshot is empty — not "everything is up" — before the first probe:
/// a caller reading it must not conclude the tunnel is healthy because
/// nothing has been asked yet.
#[tokio::test]
async fn nothing_has_been_probed_yet_is_not_the_same_as_healthy() {
    let backend = unused_backend_id();
    let group = group_with(&[backend]).await;

    let snapshot = group.health_snapshot();
    assert!(snapshot.nodes.is_empty(), "{snapshot:?}");
    assert!(!snapshot.any_reachable(), "{snapshot:?}");
}

#[tokio::test]
async fn one_down_backend_does_not_hide_the_one_that_answers() {
    let up = unused_backend_id();
    let down = unused_backend_id();
    let group = group_with(&[up, down]).await;

    group.record_probe(up, true);
    group.record_probe(down, false);

    let snapshot = group.health_snapshot();
    assert_eq!(snapshot.nodes.len(), 2, "{snapshot:?}");
    assert_eq!(snapshot.reachable(), 1, "{snapshot:?}");
    assert!(snapshot.any_reachable(), "{snapshot:?}");
    assert_eq!(snapshot.unreachable_ids(), down.to_string());

    let up = snapshot
        .nodes
        .iter()
        .find(|n| n.reachable)
        .expect("the answering backend");
    assert_eq!(up.consecutive_failures, 0);
    assert!(up.last_ok.is_some(), "it answered");
    assert!(up.down_for().is_some());

    let down = snapshot
        .nodes
        .iter()
        .find(|n| !n.reachable)
        .expect("the silent backend");
    assert_eq!(down.consecutive_failures, 1);
    assert!(down.last_ok.is_none(), "it never answered");
    assert!(down.down_for().is_none());
}

/// What an operator is told: "down for twenty minutes", not "down".
#[tokio::test]
async fn a_backend_that_comes_back_resets_its_failure_count() {
    let backend = unused_backend_id();
    let group = group_with(&[backend]).await;

    for _ in 0..3 {
        group.record_probe(backend, false);
    }
    let snapshot = group.health_snapshot();
    assert_eq!(snapshot.nodes[0].consecutive_failures, 3, "{snapshot:?}");
    assert!(!snapshot.any_reachable());

    group.record_probe(backend, true);

    let snapshot = group.health_snapshot();
    assert_eq!(snapshot.nodes[0].consecutive_failures, 0, "{snapshot:?}");
    assert!(snapshot.nodes[0].reachable);
    assert!(snapshot.nodes[0].down_for().is_some());
    assert!(snapshot.any_reachable());
}

/// The snapshot is what a UI polls, and entries that change places between
/// two polls read as backends flapping.
#[tokio::test]
async fn the_snapshot_stays_in_one_order() {
    let first = unused_backend_id();
    let second = unused_backend_id();
    let group = group_with(&[second, first]).await;
    group.record_probe(first, true);
    group.record_probe(second, false);

    let ids: Vec<String> = group
        .health_snapshot()
        .nodes
        .iter()
        .map(|n| n.node.to_string())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "the entries are not in a stable order");
    assert_eq!(
        ids,
        group
            .health_snapshot()
            .nodes
            .iter()
            .map(|n| n.node.to_string())
            .collect::<Vec<_>>()
    );
}

/// Two backends behind one domain, which is the only shape in which there
/// is anything to choose between.
async fn shared_domain_group(backends: &[EndpointId]) -> EndpointGroup {
    let ep = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("binding a local endpoint needs no network");
    EndpointGroup::new_with_nodes_and_endpoint(
        backends
            .iter()
            .map(|backend| node(*backend, "shared.example.com"))
            .collect(),
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .expect("a bogus but well-formed node ID must still build a group")
}

/// The point of probing: a backend that stopped answering stops being
/// handed out, instead of being found dead by the request that needed it.
#[tokio::test]
async fn a_backend_the_probe_found_dead_stops_being_handed_out() {
    let up = unused_backend_id();
    let down = unused_backend_id();
    let group = shared_domain_group(&[up, down]).await;
    group.record_probe(up, true);
    group.record_probe(down, false);

    let pools = group
        .domains
        .get("shared.example.com")
        .expect("both backends serve it");
    assert_eq!(pools.pools.len(), 2, "the domain must see both backends");

    for _ in 0..4 {
        let index = pools.choose().expect("one backend answers");
        assert_eq!(
            pools.pools[index].backend_id(),
            up,
            "the backend that is down was handed out"
        );
    }
}

/// "Not asked" is not "not answering": a group that has not probed yet has
/// to keep serving, or the tunnel would be dead for its first interval.
#[tokio::test]
async fn a_backend_that_has_never_been_probed_is_still_handed_out() {
    let group = shared_domain_group(&[unused_backend_id(), unused_backend_id()]).await;

    let pools = group
        .domains
        .get("shared.example.com")
        .expect("the domain must have pools");
    assert!(pools.choose().is_ok(), "nothing has said it is down yet");
}

/// The rule the server already follows: with several backends and none of
/// them answering, refuse at once instead of spending a connect timeout on
/// delivering the refusal late.
#[tokio::test]
async fn a_domain_with_nothing_answering_refuses_before_dialling() {
    let first = unused_backend_id();
    let second = unused_backend_id();
    let group = shared_domain_group(&[first, second]).await;
    group.record_probe(first, false);
    group.record_probe(second, false);

    let pools = group
        .domains
        .get("shared.example.com")
        .expect("the domain must have pools");
    let err = pools.choose().expect_err("nothing answers");
    assert!(err.to_string().contains("no backend is answering"), "{err}");
}

/// ...and the exception to it. With one backend there is nothing to choose
/// between, so refusing would turn every request into a failure and buy
/// nothing: hand it out and let the request fail loudly.
#[tokio::test]
async fn the_only_backend_is_handed_out_even_when_it_is_down() {
    let only = unused_backend_id();
    let group = shared_domain_group(&[only]).await;
    group.record_probe(only, false);

    let pools = group
        .domains
        .get("shared.example.com")
        .expect("the domain must have pools");
    assert_eq!(
        pools.choose().expect("there is nothing to choose between"),
        0
    );
}

/// The other half of the same change: a backend a request could not be
/// served by — after every attempt was spent, not on the first connection
/// that turned out stale — stops being handed out, while the one nothing
/// happened to keeps answering.
#[tokio::test]
async fn a_request_that_spent_every_attempt_marks_its_backend_down() {
    let up = unused_backend_id();
    let down = unused_backend_id();
    let group = group_with(&[up, down]).await;
    group.record_probe(up, true);
    group.record_probe(down, true);

    group.record_request_failures(&[down]);

    let snapshot = group.health_snapshot();
    let down = snapshot
        .nodes
        .iter()
        .find(|node| node.node == down)
        .expect("it was probed");
    assert!(
        !down.reachable,
        "a request that failed is a backend that is down"
    );
    assert_eq!(down.consecutive_failures, 1);
    assert!(
        snapshot.any_reachable(),
        "the backend that was left alone still answers"
    );
}

/// The corollary, and the reason the recording moved out of
/// [`PooledConnection::discard`]: nothing else got named, so nothing else
/// changed. A group whose other backend was left alone keeps serving.
#[tokio::test]
async fn a_request_failure_leaves_the_other_backend_alone() {
    let up = unused_backend_id();
    let down = unused_backend_id();
    let group = group_with(&[up, down]).await;
    group.record_probe(up, true);
    group.record_probe(down, true);

    group.record_request_failures(&[down]);

    let snapshot = group.health_snapshot();
    let up = snapshot
        .nodes
        .iter()
        .find(|node| node.node == up)
        .expect("it was probed");
    assert!(up.reachable, "only the backend that failed is recorded");
    assert_eq!(up.consecutive_failures, 0);
}

/// The one failure `get_connection` can report that is not the backend's.
///
/// Every other failure here means a backend was asked and did not answer,
/// and so belongs in the health table. This one means there was nothing to
/// ask with: our own endpoint is gone, which is what shutting a tunnel down
/// does, and every pool says it at the same moment. Reading it as "the
/// backend is down" would turn stopping a proxy into a node list where
/// nothing answers — and restarting would inherit that list.
#[tokio::test]
async fn letting_go_of_our_own_endpoint_is_news_about_us() {
    let backend = unused_backend_id();
    // A pool that owns its endpoint, unlike every pool `group_with` builds:
    // ownership is what decides whether `close_all` takes it away. Nothing
    // is ever dialled — the endpoint is gone before anything could try.
    let pool = crate::connection_pool::IrohConnectionPool::new(iroh::EndpointAddr::new(backend))
        .await
        .expect("binding a local endpoint needs no network");
    let group = EndpointGroup::new_with_single_pool(pool).await;
    group.record_probe(backend, true);

    group.close_all().await;
    let outcome = group
        .get_connection("whatever.example", Protocol::Http)
        .await;

    assert!(
        outcome.is_err(),
        "there is no endpoint left to dial out from"
    );
    let snapshot = group.health_snapshot();
    let backend = snapshot.nodes.first().expect("it was probed");
    assert!(
        backend.reachable,
        "nothing said the backend stopped answering"
    );
    assert_eq!(backend.consecutive_failures, 0);
}

/// One request is one failure. An attempt that landed on the same backend
/// three times must not grow a counter someone reads as "three things went
/// wrong", or a number that looked stable would start moving with how the
/// balancer happened to rotate.
#[tokio::test]
async fn repeating_a_backend_in_the_list_counts_it_once() {
    let only = unused_backend_id();
    let group = group_with(&[only]).await;
    group.record_probe(only, true);

    group.record_request_failures(&[only, only, only]);

    let snapshot = group.health_snapshot();
    let only = snapshot
        .nodes
        .iter()
        .find(|node| node.node == only)
        .expect("it was probed");
    assert_eq!(only.consecutive_failures, 1);
}
