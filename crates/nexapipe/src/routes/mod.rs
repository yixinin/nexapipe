use crate::config::RouteMode;
use crate::lb::{BackendPool, LoadBalancingStrategy};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// The extra knobs only `tcp` / `udp` routes have.
///
/// Kept out of [`Route::new`] so that the many HTTP and passthrough call sites — and
/// their tests — do not have to name two fields they will never use.
#[derive(Debug, Clone, Default)]
pub struct L4Options {
    /// Client ports this route accepts. `None` accepts every port. Only a selector:
    /// it never changes the address that is dialled.
    pub client_ports: Option<Vec<u16>>,
    /// Silence after which a UDP flow is closed. `None` means the server default.
    pub idle_timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct Route {
    host_pattern: String,
    path_pattern: String,
    path_is_prefix: bool,
    /// Every mode this route serves, in declaration order.
    ///
    /// More than one is the ordinary case for a host that has to answer both a
    /// request and a tunnel: the same `backends` serve whichever of these the
    /// connection turned out to be. Which one a *connection* gets is still
    /// decided before matching, by its first byte.
    modes: Vec<RouteMode>,
    backend_pool: Arc<BackendPool>,
    path_rewrite: Option<String>,
    l4: L4Options,
}

impl Route {
    // A plain constructor mirroring the `[proxy.routes]` schema in config.toml.
    // Bundling the fields into a params struct would just move the argument list
    // somewhere else, so the lint is silenced here instead.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host_pattern: &str,
        path_pattern: &str,
        path_is_prefix: bool,
        backends: Vec<String>,
        strategy: LoadBalancingStrategy,
        mode: RouteMode,
        path_rewrite: Option<String>,
    ) -> Self {
        Route {
            host_pattern: host_pattern.to_string(),
            path_pattern: path_pattern.to_string(),
            path_is_prefix,
            modes: vec![mode],
            backend_pool: Arc::new(BackendPool::new(backends, strategy)),
            path_rewrite,
            l4: L4Options::default(),
        }
    }

    /// Serve several modes from one route instead of one.
    ///
    /// Replaces rather than extends, because the caller (the config parser) has
    /// already merged what the file said; duplicates collapse, so `mode = "http"`
    /// together with `modes = ["http", "tcp"]` is not two entries. An empty list
    /// is ignored: a route serving nothing would be a silent hole in the table,
    /// and the constructor has already given it exactly one mode.
    pub fn with_modes(mut self, modes: Vec<RouteMode>) -> Self {
        let mut merged: Vec<RouteMode> = Vec::with_capacity(modes.len());
        for mode in modes {
            if !merged.contains(&mode) {
                merged.push(mode);
            }
        }
        if !merged.is_empty() {
            self.modes = merged;
        }
        self
    }

    /// Attach the `tcp` / `udp` knobs. A no-op for the other modes, which have no
    /// use for them.
    pub fn with_l4_options(mut self, options: L4Options) -> Self {
        self.l4 = options;
        self
    }

    /// Host-only match.
    ///
    /// The TLS passthrough path selects on SNI, i.e. before a request line
    /// exists, so there is no path to match against.
    pub fn matches_host(&self, host: &str) -> bool {
        if let Some(suffix) = self.host_pattern.strip_prefix('*') {
            host.ends_with(suffix)
        } else {
            host == self.host_pattern
        }
    }

    /// Match for an L4 flow: the host, plus the optional client-port allow list.
    ///
    /// `client_ports` only decides whether *this* route answers. Where the connection
    /// is then dialled is entirely the route's `backends`, so a client cannot use the
    /// list to steer the tunnel somewhere else.
    pub fn matches_l4(&self, host: &str, port: u16) -> bool {
        if !self.matches_host(host) {
            return false;
        }
        match &self.l4.client_ports {
            Some(allowed) => allowed.contains(&port),
            None => true,
        }
    }

    /// `udp` routes only: how long a flow may sit idle.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.l4.idle_timeout
    }

    pub fn matches(&self, host: &str, path: &str) -> bool {
        let path_matches = if self.path_is_prefix {
            path.starts_with(&self.path_pattern)
        } else {
            path == self.path_pattern
        };

        self.matches_host(host) && path_matches
    }

    pub fn priority(&self) -> u32 {
        let mut priority = 0;

        if !self.host_pattern.starts_with('*') {
            priority += 100;
        }

        if !self.path_is_prefix {
            priority += 10;
        }

        priority += self.path_pattern.len() as u32;

        priority
    }

    pub fn host_pattern(&self) -> &str {
        &self.host_pattern
    }

    pub fn path_pattern(&self) -> &str {
        &self.path_pattern
    }

    pub fn path_is_prefix(&self) -> bool {
        self.path_is_prefix
    }

    /// Every mode this route serves, in declaration order.
    pub fn modes(&self) -> &[RouteMode] {
        &self.modes
    }

    /// Whether this route takes part in `mode`'s lookup.
    ///
    /// A route may serve several modes, and which one a connection gets is
    /// decided earlier — by its first byte — so this is a membership test, not a
    /// choice between alternatives.
    pub fn serves(&self, mode: RouteMode) -> bool {
        self.modes.contains(&mode)
    }

    pub fn backend_pool(&self) -> &Arc<BackendPool> {
        &self.backend_pool
    }

    pub fn path_rewrite(&self) -> &Option<String> {
        &self.path_rewrite
    }

    pub fn rewrite_path(&self, original_path: &str) -> String {
        if let Some(rewrite_pattern) = &self.path_rewrite {
            if self.path_is_prefix && original_path.starts_with(&self.path_pattern) {
                let suffix = &original_path[self.path_pattern.len()..];
                rewrite_pattern.replace("{}", suffix)
            } else if !self.path_is_prefix && original_path == self.path_pattern {
                rewrite_pattern.replace("{}", "")
            } else {
                original_path.to_string()
            }
        } else {
            original_path.to_string()
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub url: String,
    pub path_rewrite: Option<String>,
    pub path_pattern: String,
    pub path_is_prefix: bool,
}

/// What the L4 tunnel needs in order to serve one flow.
#[derive(Debug, Clone)]
pub struct L4RouteInfo {
    /// The address to dial. Never the default backend — see
    /// [`RouteConfig::get_l4_backend`].
    pub backend: String,
    /// `udp` routes only; `None` means the caller's own default.
    pub idle_timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct RouteConfig {
    routes: Arc<RwLock<Vec<Route>>>,
    default_backend: Arc<RwLock<Option<String>>>,
}

impl RouteConfig {
    pub fn new(routes: Vec<Route>, default_backend: Option<String>) -> Self {
        Self {
            routes: Arc::new(RwLock::new(routes)),
            default_backend: Arc::new(RwLock::new(default_backend)),
        }
    }

    /// Backend for an HTTP request, or `None` when nothing serves it.
    ///
    /// `None` means the caller must answer 404 — not pick some address at
    /// random. The old behaviour of falling back to a required
    /// `default_backend` meant a mistyped host silently reached an unrelated
    /// service; with it optional, the honest answer is "no route".
    pub async fn get_backend(&self, host: &str, path: &str) -> Option<BackendInfo> {
        tracing::debug!("Looking up backend for host={}, path={}", host, path);

        // Only `http` routes take requests. A passthrough route exists so its
        // bytes can be copied to a TLS backend, and that listener is not an
        // HTTP server: letting one match here would send a plain request to a
        // TLS port.
        let matched_route = {
            let routes = self.routes.read().await;
            best_match(&routes, RouteMode::Http, |route| route.matches(host, path))
        };

        if let Some(route) = matched_route {
            let backend_url = route.backend_pool().select_backend().await;
            tracing::debug!(
                "Selected backend: {} for host={}, path={}",
                backend_url,
                host,
                path
            );
            return Some(BackendInfo {
                url: backend_url,
                path_rewrite: route.path_rewrite().clone(),
                path_pattern: route.path_pattern().to_string(),
                path_is_prefix: route.path_is_prefix(),
            });
        }

        let default_backend = self.default_backend.read().await.clone();
        match default_backend {
            Some(default_backend) => {
                tracing::debug!(
                    "No route matched, using default backend: {} for host={}, path={}",
                    default_backend,
                    host,
                    path
                );
                Some(BackendInfo {
                    url: default_backend,
                    path_rewrite: None,
                    path_pattern: "/".to_string(),
                    path_is_prefix: true,
                })
            }
            None => {
                tracing::debug!(
                    "No route matched and no default_backend is configured: \
                     host={host}, path={path} -> 404"
                );
                None
            }
        }
    }

    /// Backend for a raw TLS passthrough connection, selected by SNI.
    ///
    /// Only `mode = "passthrough"` routes take part; the response is `None`
    /// when nothing serves this name, which is the caller's cue to hang up
    /// rather than guess at a backend.
    pub async fn get_passthrough_backend(&self, sni: &str) -> Option<String> {
        let matched_route = {
            let routes = self.routes.read().await;
            best_match(&routes, RouteMode::Passthrough, |route| {
                route.matches_host(sni)
            })
        };

        match matched_route {
            Some(route) => {
                let backend_url = route.backend_pool().select_backend().await;
                tracing::debug!(
                    "Passthrough route matched: sni={}, host={}, backend={}",
                    sni,
                    route.host_pattern(),
                    backend_url
                );
                Some(backend_url)
            }
            None => None,
        }
    }

    /// Backend for one L4 flow, selected by host and port.
    ///
    /// Only `mode`'s own routes take part — a `tcp` lookup never sees a `udp` route and
    /// vice versa — and the response is `None` when nothing serves this host, which is
    /// the caller's cue to answer `NoRoute` rather than guess.
    ///
    /// **There is no fallback to `default_backend`.** That default exists for HTTP
    /// requests whose `Host` header matched nothing; for a tunnel it would mean a
    /// mistyped or unconfigured domain silently reaches an unrelated service, which is
    /// exactly the failure this lookup exists to prevent.
    pub async fn get_l4_backend(&self, host: &str, port: u16, mode: RouteMode) -> Option<L4RouteInfo> {
        debug_assert!(mode.is_l4(), "get_l4_backend called with {mode:?}");

        let matched_route = {
            let routes = self.routes.read().await;
            best_match(&routes, mode, |route| route.matches_l4(host, port))
        };

        let route = matched_route?;
        let backend = route.backend_pool().select_backend().await;
        tracing::debug!(
            "L4 route matched: host={}, port={}, mode={:?}, route={}, backend={}",
            host,
            port,
            mode,
            route.host_pattern(),
            backend
        );
        Some(L4RouteInfo {
            backend,
            idle_timeout: route.idle_timeout(),
        })
    }

    pub async fn routes(&self) -> Vec<Route> {
        self.routes.read().await.clone()
    }

    pub async fn default_backend(&self) -> Option<String> {
        self.default_backend.read().await.clone()
    }

    pub async fn update_routes(&self, new_routes: Vec<Route>) {
        let mut routes = self.routes.write().await;
        *routes = new_routes;
        tracing::info!("Routes updated successfully");
    }

    pub async fn update_default_backend(&self, new_default: Option<String>) {
        let mut default_backend = self.default_backend.write().await;
        // A reload rewrites the whole table, so most of them change nothing:
        // only announce an actual change, or every save of the file would claim
        // to have removed a default that was never there.
        if *default_backend == new_default {
            return;
        }
        match &new_default {
            Some(url) => tracing::info!("Default backend updated to: {}", url),
            None => tracing::info!("Default backend removed: unrouted hosts now get 404"),
        }
        *default_backend = new_default;
    }
}

/// Highest-priority route of `mode` that `matches` accepts.
///
/// Ties keep the first declaration. A route serves only the modes it declares,
/// and which of them a connection uses is decided before matching, by the first
/// byte of the connection — a TLS handshake goes to `Passthrough`, an L4 preface
/// to `Tcp` or `Udp`, anything else to `Http`. One route may declare several
/// modes; a connection still takes exactly one path.
fn best_match(routes: &[Route], mode: RouteMode, matches: impl Fn(&Route) -> bool) -> Option<Route> {
    let mut best: Option<(Route, u32)> = None;

    for route in routes.iter() {
        if !route.serves(mode) || !matches(route) {
            continue;
        }

        let priority = route.priority();
        tracing::debug!(
            "Route matched: host={}, path={}, mode={:?}, priority={}",
            route.host_pattern(),
            route.path_pattern(),
            mode,
            priority
        );

        if best
            .as_ref()
            .is_none_or(|(_, best_priority)| priority > *best_priority)
        {
            best = Some((route.clone(), priority));
        }
    }

    best.map(|(route, _)| route)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let config = RouteConfig::new(
            vec![
                passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
                http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]),
                http_route("mt.iroh.iakl.top", &["http://10.0.0.6:9000"]),
            ],
            Some("http://default:80".to_string()),
        );

        assert_eq!(
            config.get_passthrough_backend("fn.iroh.iakl.top").await,
            Some("caddy:443".to_string())
        );
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .expect("the http route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
        // A host that is only served over plain HTTP has no TLS backend, and
        // the default backend is not a passthrough fallback.
        assert_eq!(config.get_passthrough_backend("mt.iroh.iakl.top").await, None);
        assert_eq!(config.get_passthrough_backend("unknown.test").await, None);
    }

    /// `modes = ["http", "tcp"]` in the form of a lookup: one route, two tables,
    /// one shared pool.
    ///
    /// This is the configuration a TUN client needs — every one of its flows
    /// arrives as an L4 preface, even on port 80 — and it used to take two
    /// entries, where forgetting the second one cost a runtime `NoRoute`.
    #[tokio::test]
    async fn one_route_may_serve_both_a_request_and_a_tunnel() {
        let config = RouteConfig::new(
            vec![
                http_route("fn.iroh.iakl.top", &["http://host.docker.internal:15666"])
                    .with_modes(vec![RouteMode::Http, RouteMode::Tcp]),
            ],
            None,
        );

        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .expect("the route serves this host as a request")
                .url,
            "http://host.docker.internal:15666"
        );
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 80, RouteMode::Tcp)
                .await
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
                .is_none()
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
        let config = RouteConfig::new(
            vec![
                // https:// reaching the server as raw TLS, routed by SNI.
                passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
                // http:// reaching it as a request, routed by Host.
                http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]),
                // The same https:// service seen through a TUN or a CONNECT tunnel,
                // where the client announces host and port instead of sending TLS.
                l4_route("fn.iroh.iakl.top", RouteMode::Tcp, "caddy:443", None),
                // A UDP service on the same name.
                l4_route("fn.iroh.iakl.top", RouteMode::Udp, "10.0.0.60:3478", None),
            ],
            Some("http://default:80".to_string()),
        );

        // Plain HTTP request.
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .expect("the http route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
        // TLS session, routed by SNI.
        assert_eq!(
            config.get_passthrough_backend("fn.iroh.iakl.top").await,
            Some("caddy:443".to_string())
        );
        // TCP tunnel, and UDP tunnel.
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 443, RouteMode::Tcp)
                .await
                .unwrap()
                .backend,
            "caddy:443"
        );
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 3478, RouteMode::Udp)
                .await
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
                .is_some(),
            "a tcp route with no client_ports serves every port"
        );
        assert!(
            config
                .get_l4_backend("nothing.iroh.iakl.top", 443, RouteMode::Tcp)
                .await
                .is_none()
        );
        assert_eq!(
            config
                .get_backend("nothing.iroh.iakl.top", "/")
                .await
                .expect("an unrouted host falls back to the default backend")
                .url,
            "http://default:80"
        );
    }

    #[tokio::test]
    async fn passthrough_catch_all_and_exact_host_priority() {
        let config = RouteConfig::new(
            vec![
                passthrough_route("*", &["caddy:443"]),
                passthrough_route("other.iakl.top", &["caddy-alt:443"]),
            ],
            Some("http://default:80".to_string()),
        );

        assert_eq!(
            config.get_passthrough_backend("anything.test").await,
            Some("caddy:443".to_string())
        );
        // An exact host outranks the wildcard regardless of declaration order.
        assert_eq!(
            config.get_passthrough_backend("other.iakl.top").await,
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
        })
    }

    #[tokio::test]
    async fn l4_lookups_only_see_their_own_mode() {
        let config = RouteConfig::new(
            vec![
                l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None),
                http_route("web.iroh.iakl.top", &["http://10.0.0.5:8080"]),
            ],
            Some("http://default:80".to_string()),
        );

        let tcp = config
            .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Tcp)
            .await
            .expect("the tcp route should answer");
        assert_eq!(tcp.backend, "10.0.0.50:5432");

        // The tcp route is not reachable as UDP...
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Udp)
                .await
                .is_none()
        );
        // ...and an HTTP route is not an L4 target in either mode, while the HTTP path
        // still serves it.
        assert!(
            config
                .get_l4_backend("web.iroh.iakl.top", 80, RouteMode::Tcp)
                .await
                .is_none()
        );
        assert!(
            config
                .get_l4_backend("web.iroh.iakl.top", 80, RouteMode::Udp)
                .await
                .is_none()
        );
        assert_eq!(
            config
                .get_backend("web.iroh.iakl.top", "/")
                .await
                .expect("the http route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
    }

    #[tokio::test]
    async fn an_unrouted_host_never_falls_back_to_the_default_backend() {
        // The default backend is a real, working address here. If the lookup fell back
        // to it, a mistyped domain would quietly reach it instead of being refused.
        let config = RouteConfig::new(
            vec![l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None)],
            Some("http://default:80".to_string()),
        );

        assert!(
            config
                .get_l4_backend("typo.iroh.iakl.top", 5432, RouteMode::Tcp)
                .await
                .is_none()
        );
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Udp)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn client_ports_pick_a_route_without_changing_its_target() {
        let config = RouteConfig::new(
            vec![
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
            ],
            Some("http://default:80".to_string()),
        );

        // Each port selects its own route, and each route dials its own backend: the
        // client's port is a selector, never the address that is dialled.
        assert_eq!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Tcp)
                .await
                .unwrap()
                .backend,
            "10.0.0.50:5432"
        );
        assert_eq!(
            config
                .get_l4_backend("db.iroh.iakl.top", 6432, RouteMode::Tcp)
                .await
                .unwrap()
                .backend,
            "10.0.0.51:6432"
        );
        // A port no route lists is refused rather than served by the nearest match.
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 9999, RouteMode::Tcp)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn without_client_ports_every_port_matches() {
        let config = RouteConfig::new(
            vec![l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None)],
            Some("http://default:80".to_string()),
        );

        for port in [1u16, 443, 5432, 65535] {
            assert_eq!(
                config
                    .get_l4_backend("db.iroh.iakl.top", port, RouteMode::Tcp)
                    .await
                    .map(|r| r.backend),
                Some("10.0.0.50:5432".to_string()),
                "port {port}"
            );
        }
    }

    #[test]
    fn l4_matching_is_host_then_ports() {
        let exact = l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", Some(&[5432]));
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
        });
        assert_eq!(route.idle_timeout(), Some(std::time::Duration::from_secs(120)));

        // An HTTP route has no L4 knobs, and asking for them must not invent one.
        assert_eq!(http_route("a.test", &["http://b:80"]).idle_timeout(), None);
    }

    /// Without a `default_backend`, an unrouted host has nowhere to go and says so.
    ///
    /// This is why the key is optional: a config that routes every domain it
    /// serves used to be forced to name one anyway, and that placeholder then
    /// quietly absorbed every mistyped or unknown `Host`.
    #[tokio::test]
    async fn without_a_default_backend_an_unrouted_host_is_refused() {
        let config = RouteConfig::new(
            vec![http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"])],
            None,
        );

        assert!(config.get_backend("typo.iroh.iakl.top", "/").await.is_none());
        assert_eq!(config.default_backend().await, None);
        // The routed host is unaffected.
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .expect("the http route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
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
}
