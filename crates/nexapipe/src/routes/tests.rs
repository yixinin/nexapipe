//! The tests of the routing table.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.
use super::*;

/// A strict client is limited by the port the request is **served from**.
///
/// The port the client named is a virtual one: it asked for
/// `https://api.example.com` and the proxy serves it from
/// `http://10.0.0.5:18080`. The port that decides what a client can
/// touch is the backend's, and this is the check that uses it.
#[tokio::test]
async fn a_strict_client_is_limited_by_the_backends_port() {
    use crate::auth::ClientAcl;

    let route = http_route("api.iakl.top", &["http://10.0.0.5:18080"]);
    let config = RoutingTable::new(vec![route]);

    // The client may reach 443, and the route's backend is on 18080.
    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443])).with_strict_ports(true);

    assert!(
        matches!(
            config
                .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
                .await,
            BackendLookup::NoRoute
        ),
        "the request is served from a port the client may not reach"
    );
}

/// The same client, the same route, and a backend on a port it may reach.
#[tokio::test]
async fn a_strict_client_reaches_a_backend_on_a_port_it_may_reach() {
    use crate::auth::ClientAcl;

    let route = http_route("api.iakl.top", &["http://10.0.0.5:443"]);
    let config = RoutingTable::new(vec![route]);

    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443])).with_strict_ports(true);

    assert!(
        config
            .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
            .await
            .is_found(),
        "the backend is on a port the client may reach"
    );
}

/// Without the strict flag, the historical reach is what happens: the port
/// list is checked against the port the client *named*, and a request that
/// named none is not checked at all.
///
/// This is the behaviour a deployed configuration was written against, so
/// it is the default; `allow_ports_strict` is how an operator asks for the
/// check above.
#[tokio::test]
async fn a_client_that_is_not_strict_keeps_its_historical_reach() {
    use crate::auth::ClientAcl;

    let route = http_route("api.iakl.top", &["http://10.0.0.5:18080"]);
    let config = RoutingTable::new(vec![route]);

    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));

    assert!(
        config
            .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
            .await
            .is_found(),
        "the port list is not checked against the backend's port"
    );
}

/// Health says which of several backends to send to, so a pool that has only
/// one has nothing to decide — and refusing is not "safer" there, it is answering
/// for every request to a route in order to report that nothing is up. See
/// [`crate::lb::BackendPool::select_backend`].
#[tokio::test]
async fn one_unhealthy_backend_is_still_the_answer() {
    let route = http_route("api.iakl.top", &["http://10.0.0.5:8080"]);
    route
        .backend_pool()
        .set_backend_health("http://10.0.0.5:8080", false)
        .await;
    let config = RoutingTable::new(vec![route]);

    assert!(
        config.get_backend("api.iakl.top", "/").await.is_found(),
        "the one backend behind this route is the only path it has"
    );
}

/// The same pool state, one more backend: now the health information means
/// something, and the lookup has to say "unavailable" rather than hand out a
/// backend it knows is down. 503 and 404 differ in which file the operator
/// opens.
#[tokio::test]
async fn unhealthy_backends_are_not_confused_with_a_missing_route() {
    let route = http_route(
        "api.iakl.top",
        &["http://10.0.0.5:8080", "http://10.0.0.6:8080"],
    );
    let pool = route.backend_pool().clone();
    pool.set_backend_health("http://10.0.0.5:8080", false).await;
    pool.set_backend_health("http://10.0.0.6:8080", false).await;
    let config = RoutingTable::new(vec![route]);

    assert!(
        matches!(
            config.get_backend("api.iakl.top", "/").await,
            BackendLookup::Unavailable
        ),
        "every backend is down, and the route that matched still exists"
    );
    assert!(
        matches!(
            config.get_backend("nope.iakl.top", "/").await,
            BackendLookup::NoRoute
        ),
        "no route serves this host at all, which is a different answer"
    );
}

/// A pool shared by `http` and another mode carries one health state, so the
/// tunnel and the TLS passthrough see the same refusal as a request does —
/// which is why all three lookups speak in [`BackendLookup`] rather than
/// `Option`.
#[tokio::test]
async fn the_same_refusal_reaches_the_tunnel_and_the_passthrough() {
    // One route, three modes, one pool — exactly the shape a health probe
    // marks through `http` and the other two dial into.
    let route = http_route("fn.iroh.iakl.top", &["caddy:443", "caddy2:443"]).with_modes(vec![
        RouteMode::Http,
        RouteMode::Passthrough,
        RouteMode::Tcp,
    ]);
    let pool = route.backend_pool().clone();
    let config = RoutingTable::new(vec![route]);
    pool.set_backend_health("caddy:443", false).await;
    pool.set_backend_health("caddy2:443", false).await;

    assert!(matches!(
        config.get_passthrough_backend("fn.iroh.iakl.top").await,
        BackendLookup::Unavailable
    ));
    assert!(matches!(
        config
            .get_l4_backend("fn.iroh.iakl.top", 443, RouteMode::Tcp)
            .await,
        BackendLookup::Unavailable
    ));
}

fn http_route(host: &str, backends: &[&str]) -> Route {
    Route::new(
        host,
        "/",
        true,
        backends.iter().map(|b| b.to_string()).collect(),
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    )
}

fn passthrough_route(host: &str, backends: &[&str]) -> Route {
    Route::new(
        host,
        "/",
        true,
        backends.iter().map(|b| b.to_string()).collect(),
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Passthrough,
        None,
    )
}

/// The two modes are separate tables: a TLS session is served by the
/// passthrough route and a plain request by the http one, even when they
/// share a host name.
#[tokio::test]
async fn each_mode_only_sees_its_own_routes() {
    let config = RoutingTable::new(vec![
        passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
        http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]),
        http_route("mt.iroh.iakl.top", &["http://10.0.0.6:9000"]),
    ]);

    assert_eq!(
        config
            .get_passthrough_backend("fn.iroh.iakl.top")
            .await
            .found()
            .map(|lease| lease.url().to_string()),
        Some("caddy:443".to_string())
    );
    assert_eq!(
        config
            .get_backend("fn.iroh.iakl.top", "/")
            .await
            .backend()
            .expect("the http route serves this host")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
    // A host that is only served over plain HTTP has no TLS backend, and
    // the default backend is not a passthrough fallback.
    assert_eq!(
        config
            .get_passthrough_backend("mt.iroh.iakl.top")
            .await
            .found()
            .map(|lease| lease.url().to_string()),
        None
    );
    assert!(
        config
            .get_passthrough_backend("unknown.test")
            .await
            .is_no_route()
    );
}

/// `modes = ["http", "tcp"]` in the form of a lookup: one route, two tables,
/// one shared pool.
///
/// This is the configuration a TUN client needs — every one of its flows
/// arrives as an L4 preface, even on port 80 — and it used to take two
/// entries, where forgetting the second one cost a runtime `NoRoute`.
#[tokio::test]
async fn one_route_may_serve_both_a_request_and_a_tunnel() {
    let config = RoutingTable::new(vec![
        http_route("fn.iroh.iakl.top", &["http://host.docker.internal:15666"])
            .with_modes(vec![RouteMode::Http, RouteMode::Tcp]),
    ]);

    assert_eq!(
        config
            .get_backend("fn.iroh.iakl.top", "/")
            .await
            .backend()
            .expect("the route serves this host as a request")
            .url
            .as_ref(),
        "http://host.docker.internal:15666"
    );
    assert_eq!(
        config
            .get_l4_backend("fn.iroh.iakl.top", 80, RouteMode::Tcp)
            .await
            .backend()
            .expect("the same route serves this host as a tunnel")
            .backend,
        "http://host.docker.internal:15666"
    );
    // Declaring two modes did not turn the route into a catch-all: udp was
    // never one of them, and there is no default backend to fall back on.
    assert!(
        config
            .get_l4_backend("fn.iroh.iakl.top", 80, RouteMode::Udp)
            .await
            .is_no_route()
    );
}

/// One server, four kinds of traffic — the question "can http, https, tcp and udp
/// run at the same time" in the form of a test.
///
/// They can, because a route belongs to exactly one mode and each lookup only ever
/// searches its own mode: the same host name may appear four times without the
/// entries shadowing each other. What decides which one a *connection* gets is the
/// first byte it arrives with, so a single connection still only ever takes one path
/// — a TLS `ClientHello` cannot reach the `tcp` route, and an L4 preface cannot reach
/// `passthrough`, even though both point at the same backend here.
#[tokio::test]
async fn one_config_serves_http_https_tcp_and_udp_at_once() {
    let config = RoutingTable::new(vec![
        // https:// reaching the server as raw TLS, routed by SNI.
        passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
        // http:// reaching it as a request, routed by Host.
        http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]),
        // The same https:// service seen through a TUN or a CONNECT tunnel,
        // where the client announces host and port instead of sending TLS.
        l4_route("fn.iroh.iakl.top", RouteMode::Tcp, "caddy:443", None),
        // A UDP service on the same name.
        l4_route("fn.iroh.iakl.top", RouteMode::Udp, "10.0.0.60:3478", None),
    ]);

    // Plain HTTP request.
    assert_eq!(
        config
            .get_backend("fn.iroh.iakl.top", "/")
            .await
            .backend()
            .expect("the http route serves this host")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
    // TLS session, routed by SNI.
    assert_eq!(
        config
            .get_passthrough_backend("fn.iroh.iakl.top")
            .await
            .found()
            .map(|lease| lease.url().to_string()),
        Some("caddy:443".to_string())
    );
    // TCP tunnel, and UDP tunnel.
    assert_eq!(
        config
            .get_l4_backend("fn.iroh.iakl.top", 443, RouteMode::Tcp)
            .await
            .backend()
            .unwrap()
            .backend,
        "caddy:443"
    );
    assert_eq!(
        config
            .get_l4_backend("fn.iroh.iakl.top", 3478, RouteMode::Udp)
            .await
            .backend()
            .unwrap()
            .backend,
        "10.0.0.60:3478"
    );

    // The two directions of the same claim: the tunnels refuse what they do not
    // serve, while HTTP still has somewhere to go.
    assert!(
        config
            .get_l4_backend("fn.iroh.iakl.top", 3478, RouteMode::Tcp)
            .await
            .is_found(),
        "a tcp route with no client_ports serves every port"
    );
    assert!(
        config
            .get_l4_backend("nothing.iroh.iakl.top", 443, RouteMode::Tcp)
            .await
            .is_no_route()
    );
    // The one thing HTTP does not share with the tunnels: it is the only
    // lookup with no route for this host either, so it says 404.
    assert!(
        config
            .get_backend("nothing.iroh.iakl.top", "/")
            .await
            .is_no_route()
    );
}

#[tokio::test]
async fn passthrough_catch_all_and_exact_host_priority() {
    let config = RoutingTable::new(vec![
        passthrough_route("*", &["caddy:443"]),
        passthrough_route("other.iakl.top", &["caddy-alt:443"]),
    ]);

    assert_eq!(
        config
            .get_passthrough_backend("anything.test")
            .await
            .found()
            .map(|lease| lease.url().to_string()),
        Some("caddy:443".to_string())
    );
    // An exact host outranks the wildcard regardless of declaration order.
    assert_eq!(
        config
            .get_passthrough_backend("other.iakl.top")
            .await
            .found()
            .map(|lease| lease.url().to_string()),
        Some("caddy-alt:443".to_string())
    );
}

fn l4_route(host: &str, mode: RouteMode, backend: &str, ports: Option<&[u16]>) -> Route {
    Route::new(
        host,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        mode,
        None,
    )
    .with_l4_options(L4Options {
        client_ports: ports.map(|p| p.to_vec()),
        idle_timeout: None,
        flow_timeout: None,
    })
}

#[tokio::test]
async fn l4_lookups_only_see_their_own_mode() {
    let config = RoutingTable::new(vec![
        l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None),
        http_route("web.iroh.iakl.top", &["http://10.0.0.5:8080"]),
    ]);

    let tcp = config
        .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Tcp)
        .await
        .backend()
        .expect("the tcp route should answer");
    assert_eq!(tcp.backend, "10.0.0.50:5432");

    // The tcp route is not reachable as UDP...
    assert!(
        config
            .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Udp)
            .await
            .is_no_route()
    );
    // ...and an HTTP route is not an L4 target in either mode, while the HTTP path
    // still serves it.
    assert!(
        config
            .get_l4_backend("web.iroh.iakl.top", 80, RouteMode::Tcp)
            .await
            .is_no_route()
    );
    assert!(
        config
            .get_l4_backend("web.iroh.iakl.top", 80, RouteMode::Udp)
            .await
            .is_no_route()
    );
    assert_eq!(
        config
            .get_backend("web.iroh.iakl.top", "/")
            .await
            .backend()
            .expect("the http route serves this host")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
}

#[tokio::test]
async fn an_unrouted_host_is_refused() {
    // The other route's backend is a real, working address here. If the
    // lookup served a host it has no route for, a mistyped domain would
    // quietly reach it instead of being refused.
    let config = RoutingTable::new(vec![l4_route(
        "db.iroh.iakl.top",
        RouteMode::Tcp,
        "10.0.0.50:5432",
        None,
    )]);

    assert!(
        config
            .get_l4_backend("typo.iroh.iakl.top", 5432, RouteMode::Tcp)
            .await
            .is_no_route()
    );
    assert!(
        config
            .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Udp)
            .await
            .is_no_route()
    );
}

#[tokio::test]
async fn client_ports_pick_a_route_without_changing_its_target() {
    let config = RoutingTable::new(vec![
        l4_route(
            "db.iroh.iakl.top",
            RouteMode::Tcp,
            "10.0.0.50:5432",
            Some(&[5432]),
        ),
        l4_route(
            "db.iroh.iakl.top",
            RouteMode::Tcp,
            "10.0.0.51:6432",
            Some(&[6432]),
        ),
    ]);

    // Each port selects its own route, and each route dials its own backend: the
    // client's port is a selector, never the address that is dialled.
    assert_eq!(
        config
            .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Tcp)
            .await
            .backend()
            .unwrap()
            .backend,
        "10.0.0.50:5432"
    );
    assert_eq!(
        config
            .get_l4_backend("db.iroh.iakl.top", 6432, RouteMode::Tcp)
            .await
            .backend()
            .unwrap()
            .backend,
        "10.0.0.51:6432"
    );
    // A port no route lists is refused rather than served by the nearest match.
    assert!(
        config
            .get_l4_backend("db.iroh.iakl.top", 9999, RouteMode::Tcp)
            .await
            .is_no_route()
    );
}

#[tokio::test]
async fn without_client_ports_every_port_matches() {
    let config = RoutingTable::new(vec![l4_route(
        "db.iroh.iakl.top",
        RouteMode::Tcp,
        "10.0.0.50:5432",
        None,
    )]);

    for port in [1u16, 443, 5432, 65535] {
        assert_eq!(
            config
                .get_l4_backend("db.iroh.iakl.top", port, RouteMode::Tcp)
                .await
                .backend()
                .map(|r| r.backend),
            Some("10.0.0.50:5432".to_string()),
            "port {port}"
        );
    }
}

#[test]
fn l4_matching_is_host_then_ports() {
    let exact = l4_route(
        "db.iroh.iakl.top",
        RouteMode::Tcp,
        "10.0.0.50:5432",
        Some(&[5432]),
    );
    assert!(exact.matches_l4("db.iroh.iakl.top", 5432));
    assert!(!exact.matches_l4("db.iroh.iakl.top", 5433));
    assert!(!exact.matches_l4("other.iakl.top", 5432));

    let wildcard = l4_route("*.iroh.iakl.top", RouteMode::Udp, "10.0.0.60:3478", None);
    assert!(wildcard.matches_l4("turn.iroh.iakl.top", 1));
    assert!(!wildcard.matches_l4("iroh.iakl.top.bad.test", 1));
}

#[test]
fn idle_timeouts_travel_with_the_route() {
    let route = Route::new(
        "turn.iroh.iakl.top",
        "/",
        true,
        vec!["10.0.0.60:3478".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Udp,
        None,
    )
    .with_l4_options(L4Options {
        client_ports: None,
        idle_timeout: Some(std::time::Duration::from_secs(120)),
        flow_timeout: None,
    });
    assert_eq!(
        route.idle_timeout(),
        Some(std::time::Duration::from_secs(120))
    );

    // An HTTP route has no L4 knobs, and asking for them must not invent one.
    assert_eq!(http_route("a.test", &["http://b:80"]).idle_timeout(), None);
}

/// A path prefix ends at a segment boundary.
///
/// `/api` covers `/api` and `/api/x`. It does not cover `/apifoo`: that
/// is a different path that happens to start with the same letters, and a
/// route that serves it is a route that serves more than it says.
#[test]
fn a_path_prefix_ends_at_a_segment_boundary() {
    let route = Route::new(
        "app.test",
        "/api",
        true,
        vec!["http://backend:80".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    );

    assert!(route.matches("app.test", "/api"), "the pattern itself");
    assert!(route.matches("app.test", "/api/x"), "under the pattern");
    assert!(route.matches("app.test", "/api/x/y"), "under the pattern");
    assert!(!route.matches("app.test", "/apifoo"), "mid-segment");
    assert!(!route.matches("app.test", "/apifoo/x"), "mid-segment");
    assert!(!route.matches("app.test", "/other"), "another path");
}

/// A trailing slash on the pattern is the same pattern.
///
/// `/api/` and `/api` name the same place, and the path does not need a
/// second slash in it to match either.
#[test]
fn a_trailing_slash_on_the_pattern_is_the_same_pattern() {
    let route = Route::new(
        "app.test",
        "/api/",
        true,
        vec!["http://backend:80".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    );

    assert!(route.matches("app.test", "/api"), "the pattern itself");
    assert!(route.matches("app.test", "/api/"), "with the slash");
    assert!(route.matches("app.test", "/api/x"), "under the pattern");
    assert!(
        route.matches("app.test", "/api//x"),
        "no second slash needed"
    );
    assert!(!route.matches("app.test", "/apifoo"), "mid-segment");
}

/// The rewrite computes the suffix that matched.
///
/// The same predicate the match uses, so the two cannot disagree: a path
/// the route does not serve is not rewritten either.
#[tokio::test]
async fn the_rewrite_computes_the_suffix_that_matched() {
    let config = RoutingTable::new(vec![Route::new(
        "app.test",
        "/api",
        true,
        vec!["http://backend:80".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        Some("/v2{}".to_string()),
    )]);

    let backend = config.get_backend("app.test", "/api/x").await;
    let info = backend.found().expect("the route serves /api/x");

    assert_eq!(
        info.rewritten_path("/api/x"),
        "/v2/x",
        "the suffix is what the pattern did not cover"
    );
    assert_eq!(info.rewritten_path("/api"), "/v2", "the pattern itself");
    assert_eq!(
        info.rewritten_path("/apifoo"),
        "/apifoo",
        "a path this route does not serve is not rewritten"
    );
}

/// An exact route is unchanged: it matches one path and rewrites it.
#[tokio::test]
async fn an_exact_route_is_unchanged() {
    let config = RoutingTable::new(vec![Route::new(
        "app.test",
        "/api",
        false,
        vec!["http://backend:80".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        Some("/v2".to_string()),
    )]);

    let backend = config.get_backend("app.test", "/api").await;
    let info = backend.found().expect("the route serves /api");

    assert!(info.rewritten_path("/api") == "/v2", "the exact path");
    assert_eq!(
        info.rewritten_path("/api/x"),
        "/api/x",
        "an exact route rewrites nothing else"
    );
}

/// An unrouted host has nowhere to go, and says so.
///
/// There is no fallback a config can name any more: a route is the only way
/// to serve a host, so a mistyped or unknown `Host` is a 404 instead of
/// quietly reaching whatever service happened to be listed.
#[tokio::test]
async fn an_unrouted_host_is_answered_404() {
    let config = RoutingTable::new(vec![http_route(
        "fn.iroh.iakl.top",
        &["http://10.0.0.5:8080"],
    )]);

    assert!(
        config
            .get_backend("typo.iroh.iakl.top", "/")
            .await
            .is_no_route()
    );
    // The routed host is unaffected.
    assert_eq!(
        config
            .get_backend("fn.iroh.iakl.top", "/")
            .await
            .backend()
            .expect("the http route serves this host")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
}

/// `host_pattern = "*"` is how "send everything here" is spelled now.
///
/// It is an ordinary `http` route — same pool, same priority rules, same
/// lookup — so an exact host still outranks it, and it is not a fallback for
/// anything else: an SNI or L4 lookup cannot reach it.
#[tokio::test]
async fn a_catch_all_route_serves_every_unrouted_host() {
    let config = RoutingTable::new(vec![
        http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
        http_route("*", &["http://10.0.0.9:9000"]),
    ]);

    assert_eq!(
        config
            .get_backend("anything.test", "/")
            .await
            .backend()
            .expect("the catch-all serves what no other route names")
            .url
            .as_ref(),
        "http://10.0.0.9:9000"
    );
    // An exact host still outranks the catch-all.
    assert_eq!(
        config
            .get_backend("api.iakl.top", "/")
            .await
            .backend()
            .expect("the exact route serves this host")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
    // It is an `http` route, not a fallback for the other modes.
    assert!(
        config
            .get_passthrough_backend("anything.test")
            .await
            .is_no_route()
    );
    assert!(
        config
            .get_l4_backend("anything.test", 443, RouteMode::Tcp)
            .await
            .is_no_route()
    );
}

/// A restricted client reaches the hosts its allowlist names, and nothing
/// else — the refusal for a host not on the list is the same 404 an
/// unrouted host gets, so the difference cannot be used as a probe.
#[tokio::test]
async fn a_restricted_client_reaches_only_its_allowed_hosts() {
    use crate::auth::ClientAcl;

    let config = RoutingTable::new(vec![
        http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
        http_route("admin.iakl.top", &["http://10.0.0.9:9090"]),
    ]);
    let acl = ClientAcl::from_hosts(Some(&["api.iakl.top".to_string()]));

    // The allowed host reaches its own route.
    assert_eq!(
        config
            .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
            .await
            .backend()
            .expect("an allowed host reaches its route")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
    // A routed host the allowlist never named is refused, not served.
    assert!(
        config
            .get_backend_with_acl("admin.iakl.top", "/", None, Some(&acl))
            .await
            .is_no_route()
    );
    // So is an unrouted one: being on the allowlist does not conjure a
    // route for a host the server does not serve.
    assert!(
        config
            .get_backend_with_acl("typo.iakl.top", "/", None, Some(&acl))
            .await
            .is_no_route()
    );
}

/// A restricted client is served by routes, not by anything unnamed: a host
/// on the allowlist with no route of its own is a 404, the same one an
/// unrouted host gets, so the difference cannot be used as a probe.
#[tokio::test]
async fn a_restricted_client_needs_a_route_and_not_just_a_host() {
    use crate::auth::ClientAcl;

    let config = RoutingTable::new(vec![
        http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
        http_route("*", &["http://10.0.0.9:9000"]),
    ]);

    // `other.iakl.top` is on the allowlist and has no route of its own; the
    // catch-all matches it, and that is a route like any other, so the
    // allowlist is what decides.
    let acl = ClientAcl::from_hosts(Some(&[
        "api.iakl.top".to_string(),
        "other.iakl.top".to_string(),
    ]));
    assert_eq!(
        config
            .get_backend_with_acl("other.iakl.top", "/", None, Some(&acl))
            .await
            .backend()
            .expect("the allowlist names this host")
            .url
            .as_ref(),
        "http://10.0.0.9:9000"
    );

    // A host the allowlist never named is refused even though the catch-all
    // would serve it for anyone else.
    let narrow = ClientAcl::from_hosts(Some(&["api.iakl.top".to_string()]));
    assert!(
        config
            .get_backend_with_acl("other.iakl.top", "/", None, Some(&narrow))
            .await
            .is_no_route()
    );
    assert!(config.get_backend("other.iakl.top", "/").await.is_found());
}

#[test]
fn host_matching_handles_wildcards() {
    let route = passthrough_route("*.iroh.iakl.top", &["caddy:443"]);
    assert!(route.matches_host("fn.iroh.iakl.top"));
    assert!(route.matches_host(".iroh.iakl.top"));
    assert!(!route.matches_host("iroh.iakl.top.bad.test"));

    let exact = passthrough_route("fn.iroh.iakl.top", &["caddy:443"]);
    assert!(exact.matches_host("fn.iroh.iakl.top"));
    assert!(!exact.matches_host("comfyui.iroh.iakl.top"));
}

/// A `Host` header is case-insensitive and may carry a fully-qualified
/// trailing dot. Both spellings name the host the route was written for, so
/// neither may slip past it and reach a different service entirely.
#[tokio::test]
async fn a_differently_spelled_host_still_reaches_its_route() {
    let config = RoutingTable::new(vec![http_route("api.iakl.top", &["http://10.0.0.5:8080"])]);

    for host in ["API.IAKL.TOP", "Api.Iakl.Top", "api.iakl.top."] {
        assert_eq!(
            config
                .get_backend(host, "/")
                .await
                .backend()
                .unwrap_or_else(|| panic!("host {host} must reach its route"))
                .url
                .as_ref(),
            "http://10.0.0.5:8080",
            "host {host} fell through to the default backend"
        );
    }

    // The pattern side is folded the same way, so a config written with
    // uppercase letters answers the lowercase request.
    let uppercase = RoutingTable::new(vec![http_route("API.Iakl.Top", &["http://10.0.0.7:8080"])]);
    assert_eq!(
        uppercase
            .get_backend("api.iakl.top", "/")
            .await
            .backend()
            .expect("the folded pattern matches the lowercase host")
            .url
            .as_ref(),
        "http://10.0.0.7:8080"
    );
}

/// The walk folds the host once, before it starts, and the route's own
/// methods take the host that is already folded.
///
/// A caller that hands one of them an unfolded name gets a quiet `false`
/// rather than an error, so the precondition is pinned here: it is a fact
/// about the API and not a comment.
#[tokio::test]
async fn the_route_is_asked_about_a_host_that_is_already_folded() {
    let route = http_route("api.iakl.top", &["http://10.0.0.5:8080"]);

    assert!(
        route.serves_host(&normalize_host("API.Iakl.Top.")),
        "the folded name reaches the route"
    );
    assert!(
        !route.serves_host("API.Iakl.Top."),
        "an unfolded name does not match, and says so by not matching"
    );

    assert!(
        route.serves_request(&normalize_host("API.Iakl.Top."), "/"),
        "the request is matched against the folded host too"
    );
    assert!(
        !route.serves_request("API.Iakl.Top.", "/"),
        "an unfolded name does not match the request either"
    );
}

/// The lookup-level view of the same rule for SNI and L4 hosts: both feed
/// `matches_host`, so both are folded.
#[tokio::test]
async fn sni_and_l4_hosts_are_folded_the_same_way() {
    let config = RoutingTable::new(vec![
        passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
        l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None),
    ]);

    assert_eq!(
        config
            .get_passthrough_backend("FN.IROH.IAKL.TOP.")
            .await
            .found()
            .map(|lease| lease.url().to_string()),
        Some("caddy:443".to_string())
    );
    assert_eq!(
        config
            .get_l4_backend("DB.Iroh.Iakl.Top.", 5432, RouteMode::Tcp)
            .await
            .backend()
            .expect("the folded host reaches the L4 route")
            .backend,
        "10.0.0.50:5432"
    );
}

/// A reload keeps the pool of a route that did not change, which is what
/// lets the health probe already running keep watching the pool traffic
/// actually goes through.
#[tokio::test]
async fn a_reload_keeps_the_pool_of_a_route_that_did_not_change() {
    let config = RoutingTable::new(vec![http_route(
        "fn.iroh.iakl.top",
        &["http://10.0.0.5:8080"],
    )]);
    let before = config
        .routes()
        .await
        .first()
        .expect("one route")
        .backend_pool()
        .clone();

    // A reload of the very same table, which is what an edit to a second
    // route — or to any other section — looks like from here.
    config
        .update_routes(vec![http_route(
            "fn.iroh.iakl.top",
            &["http://10.0.0.5:8080"],
        )])
        .await;

    let after = config
        .routes()
        .await
        .first()
        .expect("one route")
        .backend_pool()
        .clone();

    assert!(
        Arc::ptr_eq(&before, &after),
        "an unchanged route must keep the pool it had, so its health probe stays attached"
    );
}

/// The counterpart: a route that now points elsewhere is a different pool,
/// because a pool *is* the backends it dials.
#[tokio::test]
async fn a_route_that_changed_backends_gets_a_new_pool() {
    let config = RoutingTable::new(vec![http_route(
        "fn.iroh.iakl.top",
        &["http://10.0.0.5:8080"],
    )]);
    let before = config
        .routes()
        .await
        .first()
        .expect("one route")
        .backend_pool()
        .clone();

    config
        .update_routes(vec![http_route(
            "fn.iroh.iakl.top",
            &["http://10.0.0.9:8080"],
        )])
        .await;

    let after = config
        .routes()
        .await
        .first()
        .expect("one route")
        .backend_pool()
        .clone();

    assert!(
        !Arc::ptr_eq(&before, &after),
        "new backends mean a new pool, and the old probe has to be stopped"
    );
}

/// Two routes on one host, differing only in path, are not the same route
/// and must not be treated as one — sharing a key would leave one of them
/// without a health probe.
#[tokio::test]
async fn routes_sharing_a_host_are_still_different_routes() {
    let mut route = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
    let same_host_other_path = {
        let mut other = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
        other.path_pattern = "/api".to_string();
        other
    };

    assert_ne!(
        route.pool_key().await,
        same_host_other_path.pool_key().await
    );

    route.path_pattern = "/api".to_string();
    assert_eq!(
        route.pool_key().await,
        same_host_other_path.pool_key().await
    );
}

/// A pool is its backends *and* the way it picks between them, so a reload
/// that changes only the strategy has to be a new pool. Keyed without it,
/// the old pool was reused and the edit did nothing, with no log line to
/// say why the traffic still went out the same way.
#[tokio::test]
async fn changing_only_the_strategy_is_a_different_pool() {
    let round_robin = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
    let random = Route::new(
        "fn.iroh.iakl.top",
        "/",
        true,
        vec!["http://10.0.0.5:8080".to_string()],
        LoadBalancingStrategy::Random,
        RouteMode::Http,
        None,
    );

    assert_ne!(round_robin.pool_key().await, random.pool_key().await);
}

/// The dot is what makes a wildcard a wildcard over *labels*. Without it
/// the match is a bare `ends_with`, and a host that merely ends in the same
/// letters — belonging to somebody else — is in.
#[test]
fn a_wildcard_stops_at_the_label_boundary() {
    assert!(host_matches("*.example.com", "api.example.com"));
    assert!(host_matches("*.example.com", "a.b.example.com"));

    assert!(
        !host_matches("*.example.com", "notexample.com"),
        "a host that merely ends in the same letters is not under the wildcard"
    );
    assert!(
        !host_matches("*.example.com", "example.com"),
        "the apex is not under its own wildcard, the way DNS reads it"
    );
    assert!(host_matches("*", "anything.at.all"), "`*` is the catch-all");
}

/// A `*` with anything but a dot after it matches nothing: it is refused
/// when the config loads, and whatever slipped past the check must not
/// quietly match more than it says.
#[test]
fn a_wildcard_without_its_dot_matches_nothing() {
    assert!(!host_matches("*iakl.top", "eviliakl.top"));
    assert!(!host_matches("*iakl.top", "iakl.top"));
}

#[test]
fn a_loose_wildcard_is_refused_when_the_config_loads() {
    assert!(pattern_error("*").is_none());
    assert!(pattern_error("*.example.com").is_none());
    assert!(pattern_error("example.com").is_none());

    let why = pattern_error("*iakl.top").expect("*iakl.top must be refused");
    assert!(why.contains("label boundary"), "{why}");
    assert!(
        pattern_error("").is_some(),
        "an empty pattern names nothing"
    );
}

/// An IPv6 literal carries colons of its own, so splitting on the first one
/// does not leave a host behind — it leaves `[`, and every request to that
/// host 404s.
#[test]
fn a_host_header_keeps_an_ipv6_literal_whole() {
    assert_eq!(host_without_port("[::1]:8080"), "[::1]");
    assert_eq!(host_without_port("[2001:db8::1]"), "[2001:db8::1]");
    assert_eq!(host_without_port("api.example.com:8080"), "api.example.com");
    assert_eq!(host_without_port("api.example.com"), "api.example.com");

    // What the routing table is asked about, brackets dropped.
    assert_eq!(normalize_host(host_without_port("[::1]:8080")), "::1");
    assert_eq!(normalize_host("[::1]"), "::1");
}

/// A name may carry more than one trailing dot. Stripping a single one left
/// `a.example.com..` as `a.example.com.`, which is a different string than
/// the route it names.
#[test]
fn every_trailing_dot_is_dropped() {
    assert_eq!(normalize_host("a.example.com"), "a.example.com");
    assert_eq!(normalize_host("a.example.com."), "a.example.com");
    assert_eq!(normalize_host("a.example.com.."), "a.example.com");
    assert_eq!(normalize_host("A.Example.COM.."), "a.example.com");
}

/// The tiers: an exact host outranks a wildcard no matter how long the
/// wildcard's path is. They used to be one sum, so a path of 102 characters
/// outweighed the host.
#[test]
fn an_exact_host_beats_any_path_length() {
    let long_path = "/".to_string() + &"x".repeat(200);
    let exact = Route::new(
        "api.example.com",
        "/",
        true,
        vec!["a".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    );
    let wildcard_with_a_long_path = Route::new(
        "*.example.com",
        &long_path,
        true,
        vec!["b".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    );

    assert!(exact.priority() > wildcard_with_a_long_path.priority());
}

/// Two tcp routes for one host: the one that names its ports wins for those
/// ports, and the other one stays reachable for everything else. With no
/// tie-break the first declared won for good and the second never matched.
#[tokio::test]
async fn a_route_that_names_its_ports_wins_over_one_that_takes_them_all() {
    let every_port = Route::new(
        "ssh.example.com",
        "/",
        true,
        vec!["fallback:22".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Tcp,
        None,
    );
    // Declared second on purpose: declaration order must not decide it.
    let only_443 = Route::new(
        "ssh.example.com",
        "/",
        true,
        vec!["tls-backend:443".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Tcp,
        None,
    )
    .with_l4_options(L4Options {
        client_ports: Some(vec![443]),
        idle_timeout: None,
        flow_timeout: None,
    });

    let config = RoutingTable::new(vec![every_port, only_443]);

    assert_eq!(
        config
            .get_l4_backend("ssh.example.com", 443, RouteMode::Tcp)
            .await
            .backend()
            .expect("port 443 has a route")
            .backend,
        "tls-backend:443"
    );
    // The catch-all is not shadowed: a port it was the only answer for
    // still reaches it.
    assert_eq!(
        config
            .get_l4_backend("ssh.example.com", 22, RouteMode::Tcp)
            .await
            .backend()
            .expect("port 22 falls to the catch-all")
            .backend,
        "fallback:22"
    );
}

/// A `*.suffix` wildcard is more specific than the bare `*`, so it wins in
/// either declaration order. Two tiers put them level and the winner was
/// whichever came first in the file — the thing tiers are for.
#[tokio::test]
async fn a_wildcard_host_beats_the_catch_all_in_either_order() {
    let catch_all = http_route("*", &["http://10.0.0.1:8080"]);
    let wildcard = http_route("*.example.com", &["http://10.0.0.2:8080"]);

    let catch_all_first = RoutingTable::new(vec![catch_all.clone(), wildcard.clone()]);
    assert_eq!(
        catch_all_first
            .get_backend("api.example.com", "/")
            .await
            .backend()
            .expect("the wildcard has a route")
            .url
            .as_ref(),
        "http://10.0.0.2:8080"
    );

    let wildcard_first = RoutingTable::new(vec![wildcard, catch_all]);
    assert_eq!(
        wildcard_first
            .get_backend("api.example.com", "/")
            .await
            .backend()
            .expect("the wildcard has a route")
            .url
            .as_ref(),
        "http://10.0.0.2:8080"
    );

    // The catch-all is not shadowed: it still answers everything else.
    assert_eq!(
        wildcard_first
            .get_backend("elsewhere.test", "/")
            .await
            .backend()
            .expect("the catch-all has a route")
            .url
            .as_ref(),
        "http://10.0.0.1:8080"
    );
}

/// The end-to-end shape of the same thing: a request for an IPv6 literal
/// reaches the route written for that address.
#[tokio::test]
async fn a_request_for_an_ipv6_literal_reaches_its_route() {
    let config = RoutingTable::new(vec![http_route("::1", &["http://10.0.0.5:8080"])]);

    assert_eq!(
        config
            .get_backend(host_without_port("[::1]:8080"), "/")
            .await
            .backend()
            .expect("the literal host reaches the route")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
}
/// The port a `Host` header names, and the host it names beside it.
///
/// The two are split the same way for every shape: an IPv6 literal keeps
/// its brackets, and a header that names no port says so rather than
/// guessing one.
#[test]
fn a_host_header_is_split_into_its_host_and_its_port() {
    assert_eq!(host_and_port("api.example.com"), ("api.example.com", None));
    assert_eq!(
        host_and_port("api.example.com:8443"),
        ("api.example.com", Some(8443))
    );
    assert_eq!(
        host_and_port("[::1]:8080"),
        ("[::1]", Some(8080)),
        "the brackets belong to the address and the port follows them"
    );
    assert_eq!(
        host_and_port("[::1]"),
        ("[::1]", None),
        "a literal with no port names no port"
    );
    assert_eq!(
        host_and_port("api.example.com:not-a-port"),
        ("api.example.com", None),
        "a port that does not parse is not a port"
    );
}

/// The host and the port are taken apart by one rule, so the two cannot
/// disagree about where the host ends.
#[test]
fn the_host_is_the_same_whether_or_not_the_port_is_read() {
    for header in [
        "api.example.com",
        "api.example.com:8443",
        "[::1]",
        "[::1]:8080",
    ] {
        assert_eq!(
            host_without_port(header),
            host_and_port(header).0,
            "{header} splits one way"
        );
    }
}

/// A client that may reach a host on one port only is refused the other,
/// and the refusal is the same 404 a host it may not reach gets — so the
/// difference cannot be used to probe what exists.
#[tokio::test]
async fn a_port_the_acl_does_not_list_is_refused_the_way_a_host_is() {
    use crate::auth::ClientAcl;

    let config = RoutingTable::new(vec![http_route("api.iakl.top", &["http://10.0.0.5:8080"])]);
    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));

    assert_eq!(
        config
            .get_backend_with_acl("api.iakl.top", "/", Some(443), Some(&acl))
            .await
            .backend()
            .expect("the port is on the list")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
    assert!(
        config
            .get_backend_with_acl("api.iakl.top", "/", Some(8443), Some(&acl))
            .await
            .is_no_route(),
        "a port the list does not name is refused"
    );
}

/// A request that names no port has no port to hold against the client:
/// the proxy routes by host and ignores the port otherwise.
#[tokio::test]
async fn a_request_that_names_no_port_is_not_held_against_the_port_list() {
    use crate::auth::ClientAcl;

    let config = RoutingTable::new(vec![http_route("api.iakl.top", &["http://10.0.0.5:8080"])]);
    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));

    assert_eq!(
        config
            .get_backend_with_acl("api.iakl.top", "/", None, Some(&acl))
            .await
            .backend()
            .expect("no port was named, so none is refused")
            .url
            .as_ref(),
        "http://10.0.0.5:8080"
    );
}

/// The port a backend is reached on, in either spelling.
///
///
/// The two spellings are not the same thing to a URL parser: `http://host:8443`
/// is a URL, and `host:8443` is not one at all — `Url::parse` reads it as a
/// scheme and finds no port, and refuses `127.0.0.1:8443` outright. A TLS
/// passthrough backend is written the second way, so a check that only read
/// URLs would never fire on one.
mod backend_port_tests {
    use super::backend_port;

    #[test]
    fn a_url_backend_is_read() {
        assert_eq!(backend_port("http://10.0.0.5:18080"), Some(18080));
        assert_eq!(backend_port("https://example.com"), Some(443));
    }

    #[test]
    fn a_bare_host_and_port_is_read() {
        // The spelling a TLS passthrough backend is written in.
        assert_eq!(backend_port("127.0.0.1:8443"), Some(8443));
        assert_eq!(backend_port("host.docker.internal:8443"), Some(8443));
        assert_eq!(backend_port("[::1]:8443"), Some(8443));
    }
}

/// Two passthrough routes for the same host: the one whose `path_pattern` is
/// longer wins, even though a passthrough route's path is not matched at all.
#[tokio::test]
async fn a_passthrough_route_is_chosen_by_its_path_pattern() {
    let short = Route::new(
        "app.test",
        "/",
        true,
        vec!["short-backend:443".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Passthrough,
        None,
    );
    let long = Route::new(
        "app.test",
        "/a/longer/path",
        true,
        vec!["long-backend:443".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Passthrough,
        None,
    );
    let config = RoutingTable::new(vec![short, long]);

    let lease = config
        .get_passthrough_backend("app.test")
        .await
        .backend()
        .expect("a passthrough route serves the name");
    assert_eq!(
        lease.url(),
        "long-backend:443",
        "the path pattern, which a passthrough route never matches on, picked the backend"
    );
}
