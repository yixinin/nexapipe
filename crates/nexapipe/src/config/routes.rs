//! The configuration translated into routes.
//!
//! The schema says what a route is; this says what the one in the file *is*:
//! which backends serve it, in which mode, and what it does with the path.

use crate::routes::{L4Options, Route};

use super::*;

impl ProxyConfig {
    /// Logs configuration that no longer has any effect.
    ///
    /// TLS moved to the backend, so a config.toml written for the old layout
    /// parses but does nothing useful. Reporting it beats a silent failure.
    pub fn warn_removed_tls_keys(&self) {
        const HINT: &str =
            "TLS is terminated by the backend now (see README, `mode = \"passthrough\"`)";

        if self.acme.is_some() {
            tracing::warn!("[acme] is ignored and can be removed from config.toml: {HINT}");
        }

        if let Some(server) = &self.server {
            if server.tls_enabled.unwrap_or(false) {
                tracing::warn!("[server] tls_enabled is ignored and can be removed: {HINT}");
            }
            if server.tls_listen_addr.is_some() {
                tracing::warn!("[server] tls_listen_addr is ignored and can be removed: {HINT}");
            }
            if server.cert_path.is_some() || server.key_path.is_some() {
                tracing::warn!(
                    "[server] cert_path/key_path are ignored and can be removed: {HINT}"
                );
            }
        }

        for route in self.routes.iter().flatten() {
            if route.cert_path.is_some() || route.key_path.is_some() {
                tracing::warn!(
                    "[[routes]] cert_path/key_path for host_pattern={} are ignored and can be removed: {HINT}",
                    route.host_pattern
                );
            }
            if route.redirect_to_https.unwrap_or(false) {
                tracing::warn!(
                    "[[routes]] redirect_to_https for host_pattern={} is ignored: let the backend redirect instead",
                    route.host_pattern
                );
            }
        }
    }
}

impl ProxyConfig {
    /// Whether this config puts a credential in the file it was read from.
    ///
    /// The 2FA seeds are the obvious one and live in `[auth]`, but this file also
    /// carries `[iroh] secret_key` — the endpoint's private key, which is what
    /// makes a Node ID yours — and `relay_auth_token`, a bearer token. Either one
    /// is worth refusing a permissive mode over, on a server with `[auth]` off.
    /// Refuses the `[health_check]` numbers that would otherwise be rewritten
    /// on the way in.
    ///
    /// Each of them was clamped with `max(1)`, which turns a typo into
    /// behaviour nobody asked for: `interval = 0` is one round of probes per
    /// second, per route; `timeout = 0` is a probe that can never succeed, so
    /// every backend is taken out of rotation; and `threshold = 0` means a
    /// single lost probe empties the pool, the opposite of what the knob is
    /// for. All three are seconds nobody would write on purpose.
    fn validate_health_check(&self) -> anyhow::Result<()> {
        let health = &self.health_check;

        if health.interval == 0 {
            anyhow::bail!(
                "[health_check] interval is 0: it is the number of seconds between two \
                 rounds of checks, so it has to be at least 1"
            );
        }
        if health.timeout == 0 {
            anyhow::bail!(
                "[health_check] timeout is 0: no probe could ever finish, so every backend \
                 would be marked unhealthy and taken out of rotation"
            );
        }
        if health.threshold == 0 {
            anyhow::bail!(
                "[health_check] threshold is 0: one failed probe would empty the pool. \
                 It is the number of consecutive failures that takes a backend out, so it \
                 has to be at least 1"
            );
        }

        Ok(())
    }

    /// Two families of wait live in `[timeouts]`: the two backend keys cover
    /// one step of talking to a backend, and the six phase keys bound a phase
    /// of the exchange itself. Neither end of either range is a number anyone
    /// would dial: zero is a deadline that expires before the round trip (or
    /// the phase) it is meant to bound; anything past the ceiling is not a
    /// longer wait but a missing one, and the symptom is a request slot held
    /// until the client gives up. Refused at load, where the operator is
    /// looking, rather than discovered as "all requests fail 502" — or, for an
    /// L4 flow, as a tunnel that closes the instant it opens.
    fn validate_timeouts(&self) -> anyhow::Result<()> {
        for (key, secs) in [
            ("connect_secs", self.timeouts.connect_secs),
            ("response_secs", self.timeouts.response_secs),
        ] {
            let Some(secs) = secs else {
                continue;
            };
            if secs == 0 {
                anyhow::bail!(
                    "[timeouts] {key} is 0: no backend could answer that fast, so every request \
                     would fail. It is a whole number of seconds, and the shortest wait anyone \
                     asks for is 1"
                );
            }
            if secs > Timeouts::MAX_SECS {
                anyhow::bail!(
                    "[timeouts] {key} is {secs}s, past the {max}s ceiling: a wait that long is a \
                     request slot held until the client gives up, which is the failure a timeout \
                     exists to prevent",
                    max = Timeouts::MAX_SECS
                );
            }
        }

        // The per-phase budgets take the ceiling from `crate::deadline`, not
        // `Timeouts::MAX_SECS`: `l4_flow_secs` defaults to an hour and a
        // long-lived tunnel is exactly the case an operator raises it for, so
        // its ceiling is a day, not an hour. Zero is refused for the same reason
        // as above, with a different reading — here zero does not fail every
        // request, it closes every flow the instant it opens, which looks like a
        // working server that transfers nothing.
        for (key, secs) in [
            ("header_secs", self.timeouts.header_secs),
            ("body_secs", self.timeouts.body_secs),
            ("response_idle_secs", self.timeouts.response_idle_secs),
            ("l4_flow_secs", self.timeouts.l4_flow_secs),
            ("l4_idle_secs", self.timeouts.l4_idle_secs),
            ("tls_hello_secs", self.timeouts.tls_hello_secs),
        ] {
            let Some(secs) = secs else {
                continue;
            };
            if secs == 0 {
                anyhow::bail!(
                    "[timeouts] {key} is 0: the phase it bounds would close the moment it \
                     opens, and nothing would ever get through. It is a whole number of \
                     seconds, and the shortest wait anyone asks for is 1"
                );
            }
            if secs > crate::deadline::MAX_SECS {
                anyhow::bail!(
                    "[timeouts] {key} is {secs}s, past the {max}s ceiling: a bound that long \
                     never fires within a process lifetime, which is the failure a timeout \
                     exists to prevent",
                    max = crate::deadline::MAX_SECS
                );
            }
        }

        Ok(())
    }

    /// The `[timeouts]` deadlines this config resolves to.
    pub fn timeouts(&self) -> Timeouts {
        Timeouts::resolve(self.timeouts)
    }

    /// The `[retry]` settings this config resolves to.
    pub fn retry(&self) -> Retry {
        Retry::resolve(self.retry)
    }

    /// The `[circuit_breaker]` settings this config resolves to.
    pub fn circuit_breaker(&self) -> CircuitBreaker {
        CircuitBreaker::resolve(self.circuit_breaker)
    }

    /// Whether the config file this was read from holds a credential.
    ///
    /// Asked about the *file*, not about what the process is running with: what
    /// it feeds is "can another account on this host read the secrets in that
    /// file". So a key generated at startup and never written — because the
    /// config was read-only, or because `NEXAPIPE_NO_PERSIST_IDENTITY` said not
    /// to — must not make this true. Folding an ephemeral identity in here
    /// would warn exactly the deployments that need one about a key that is
    /// not on disk.
    ///
    /// The same logic covers a credential that lives outside the file: a key
    /// resolved from the environment or from a `secret_key_file` pointer is
    /// not in *this* file for anyone to read, so it does not make the config a
    /// credential holder — the pointed-to file is held to the `0600` rule in
    /// the config's place, where it is read (see `read_credential_file`).
    pub fn holds_credentials(&self) -> bool {
        self.iroh.as_ref().is_some_and(|iroh| {
            (iroh.secret_key.is_some() && iroh.secret_key_source == CredentialSource::Inline)
                || (iroh.relay_auth_token.is_some()
                    && iroh.relay_auth_token_source == CredentialSource::Inline)
        })
    }

    /// Turns the `[[routes]]` table into the objects the proxy actually routes
    /// with, rejecting anything that cannot work.
    ///
    /// Shared by the startup path and the config watcher: a reload has to build
    /// routes exactly the way a cold start does, or an edit would behave
    /// differently depending on when it was made. An error here is not fatal for
    /// a reload — the caller keeps the routes it already has.
    pub fn build_routes(&self) -> anyhow::Result<Vec<Route>> {
        // Both a cold start and a reload come through this function, so the
        // health check is validated here rather than only at startup: an edit
        // that sets `interval = 0` is as wrong as one written by hand.
        self.validate_health_check()?;
        self.validate_timeouts()?;

        // Refused rather than ignored: silently dropping the key would turn
        // every host it used to forward into a 404, which is a routing change
        // nobody asked for. A reload keeps the routes it already has, so a
        // config that fails here is the one that was never serving anyway.
        if self.default_backend.is_some() {
            anyhow::bail!(
                "default_backend has been removed: a host with no `http` route is answered 404. \
                 Replace it with the catch-all route it always meant — \
                 [[routes]] host_pattern = \"*\", mode = \"http\", backends = [\"<backend>\"]"
            );
        }

        let mut routes = Vec::new();

        for spec in self.routes.iter().flatten() {
            // The translation from the configuration's spelling of a route to
            // the route the server serves is a `TryFrom`, and it takes the
            // spec apart with a pattern that names every field — see
            // `impl TryFrom<RouteSpec> for Route`.
            //
            // The spec is copied because the configuration is shared and this
            // is a read of it; the copy happens once per route, when the
            // configuration is loaded.
            let route = crate::routes::Route::try_from(spec.clone())?;
            // Copied out for the log line below, so that the route itself can
            // be moved into the table.
            let host_pattern = route.host_pattern().to_string();
            let path_pattern = route.path_pattern().to_string();
            let path_is_prefix = route.path_is_prefix();
            let modes = route.modes().to_vec();
            let strategy = route.backend_pool().strategy();
            let backends_count = route.backend_pool().len();
            routes.push(route.with_circuit_breaker(self.circuit_breaker()));

            tracing::info!(
                "Loaded route: host={}, path={} (prefix={}), modes={:?}, backends={}, strategy={:?}",
                host_pattern,
                path_pattern,
                path_is_prefix,
                modes,
                backends_count,
                strategy
            );

            if modes.iter().any(|mode| mode.is_l4()) {
                // Worth spelling out: `client_ports` changes which flows match, and a
                // reader who assumed "the port is what gets dialled" would be wrong.
                tracing::info!(
                    "  L4 route {}: client_ports={:?} (absent = every port matches; the port never \
                     decides where the connection goes), idle_timeout_secs={:?}",
                    host_pattern,
                    spec.client_ports,
                    spec.idle_timeout_secs
                );
            }
        }

        Ok(routes)
    }
}

impl TryFrom<RouteSpec> for crate::routes::Route {
    type Error = anyhow::Error;

    /// The translation from the configuration's spelling of a route to the
    /// route the server serves.
    ///
    /// **The pattern the spec is taken apart with is the point.** It names
    /// every field, so a field the schema grows and this does not is a
    /// **compile error** — not a field that is quietly dropped.
    ///
    /// Before this, adding an option to `[proxy.routes]` and forgetting to
    /// read it in the translation compiled fine and did nothing at all: the
    /// operator set it, the server ignored it, and nothing said so. The
    /// compiler could not have caught it, because the translation read the
    /// fields it knew about and the field it did not know about was simply
    /// not there.
    fn try_from(spec: RouteSpec) -> Result<Self, Self::Error> {
        let RouteSpec {
            host_pattern,
            path_pattern,
            path_is_prefix,
            strategy,
            backends,
            backend_protocol,
            mode,
            modes,
            path_rewrite,
            client_ports,
            idle_timeout_secs,
            flow_timeout_secs,
            // Keys that are no longer read. They stay in the schema so that a
            // configuration carrying one is told about it rather than having
            // it ignored — see `ServerConfig`.
            cert_path: _,
            key_path: _,
            redirect_to_https: _,
        } = spec;

        let strategy = get_strategy(&strategy)?;
        let modes = get_route_modes(&mode, &modes)?;
        let path_is_prefix = path_is_prefix.unwrap_or(true);
        let label = format!("route {host_pattern}");

        // Refused rather than matched loosely: a wildcard without its dot
        // silently covers hosts that merely end in the same letters, so a
        // config using one is a config that routes more than it says.
        if let Some(why) = crate::routes::pattern_error(&host_pattern) {
            anyhow::bail!("{label}: host_pattern {why}");
        }

        // A route with no backends matches and then has nothing to send
        // the request to: `select_backend` answers with an empty string and
        // the client gets a 502 that looks like a backend being down.
        if backends.is_empty() {
            anyhow::bail!("{label}: has no backends; a route needs at least one to forward to");
        }

        // A port no flow can arrive on, or an empty list that says "every
        // port" by accident: either one is a route that never matches, and
        // the operator has no way to notice — the client just gets refused.
        if let Some(ports) = &client_ports {
            if ports.is_empty() {
                anyhow::bail!("{label}: client_ports is empty; leave it out to match every port");
            }
            if ports.contains(&0) {
                anyhow::bail!(
                    "{label}: client_ports contains port 0; no flow ever arrives from \
                         port 0, so that entry can never match"
                );
            }
        }

        // A UDP flow with a zero idle timeout is closed as soon as it is
        // opened: the tunnel is set up and torn down before the first
        // datagram crosses it. Leave it out for the server default.
        if idle_timeout_secs == Some(0) {
            anyhow::bail!(
                "{label}: idle_timeout_secs is 0, which closes a UDP flow the moment it \
                     is opened; leave it out for the default"
            );
        }

        // Same reasoning for the whole-flow bound: zero would close every flow
        // the instant it opened, which is never what a zero here means.
        if flow_timeout_secs == Some(0) {
            anyhow::bail!(
                "{label}: flow_timeout_secs is 0, which closes a flow the moment it is \
                     opened; leave it out for the default"
            );
        }

        // And a bound that long never fires within a process lifetime, which
        // is the failure a timeout exists to prevent — the same ceiling the
        // server-wide `[timeouts]` bounds are held to, for the same reason.
        //
        // A route's own bound overrides the server-wide one, so without this
        // ceiling a route could carry a century and make the flow
        // effectively unbounded, which is not what a timeout is.
        for (key, secs) in [
            ("idle_timeout_secs", idle_timeout_secs),
            ("flow_timeout_secs", flow_timeout_secs),
        ] {
            let Some(secs) = secs else {
                continue;
            };
            if secs > crate::deadline::MAX_SECS {
                anyhow::bail!(
                    "{label}: {key} is {secs}s, past the {max}s ceiling: a bound that long never \
                     fires within a process lifetime, which is the failure a timeout exists to \
                     prevent",
                    max = crate::deadline::MAX_SECS
                );
            }
        }

        // Every declared mode has to be able to dial these backends, so each
        // one is checked: the `http` rules and the L4 rules disagree (a URL
        // to fetch versus an address to dial, and only the L4 one insists on
        // a port), and a route serving both has to satisfy both.
        for backend in &backends {
            for mode in &modes {
                let label = format!("{label} (mode {mode:?})");
                validate_backend(&label, *mode, backend)?;
            }
        }

        // `h2c` is HTTP/2 in the clear, and an `https://` backend is spoken
        // to over TLS — so the two cannot be combined: the client would
        // start h2 in the clear at a port that expects TLS. Refused here
        // rather than at the first request, because every request to that
        // route would fail the same way.
        let backend_protocol =
            get_backend_protocol(&backend_protocol).map_err(|e| anyhow::anyhow!("{label}: {e}"))?;
        if backend_protocol == BackendProtocol::H2c && modes.contains(&RouteMode::Http) {
            for backend in &backends {
                if url::Url::parse(backend)
                    .map(|url| url.scheme() == "https")
                    .unwrap_or(false)
                {
                    anyhow::bail!(
                        "{label}: backend_protocol = \"h2c\" speaks HTTP/2 in the clear, but \
                             backend \"{backend}\" is https://. An https backend speaks HTTP/2 \
                             through the TLS handshake, which is what backend_protocol = \
                             \"http1\" already does; drop the key."
                    );
                }
            }
        }

        // Only meaningful for `tcp` / `udp`, where they are harmless defaults
        // otherwise; the other modes never read them.
        let l4_options = L4Options {
            client_ports,
            idle_timeout: idle_timeout_secs.map(std::time::Duration::from_secs),
            flow_timeout: flow_timeout_secs.map(std::time::Duration::from_secs),
        };

        Ok(crate::routes::Route::new(
            &host_pattern,
            &path_pattern,
            path_is_prefix,
            backends,
            strategy,
            // The first mode only seeds the constructor; `with_modes` then
            // puts the whole set on the route.
            modes[0],
            path_rewrite,
        )
        .with_l4_options(l4_options)
        .with_modes(modes)
        .with_backend_protocol(backend_protocol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> ProxyConfig {
        toml::from_str(source).expect("the config parses")
    }

    /// A route's own bound is held to the same ceiling as the server-wide one.
    ///
    /// The `[timeouts]` bounds are refused above `crate::deadline::MAX_SECS`
    /// precisely because a bound that long never fires within a process
    /// lifetime. A per-route bound overrides the server-wide one, so without
    /// the same ceiling a route could carry `flow_timeout_secs =
    /// 315_360_000_000` — a century — and silently make the flow unbounded.
    #[test]
    fn a_route_bound_past_the_ceiling_is_refused() {
        for key in ["idle_timeout_secs", "flow_timeout_secs"] {
            let config = parse(&format!(
                r#"
[[routes]]
host_pattern = "db.example.com"
mode = "tcp"
backends = ["10.0.0.5:5432"]
{key} = 315_360_000_000
"#
            ));

            let error = config.build_routes().unwrap_err().to_string();
            assert!(
                error.contains(key),
                "the error does not name {key}: {error}"
            );
            assert!(
                error.contains(&crate::deadline::MAX_SECS.to_string()),
                "the error does not name the ceiling: {error}"
            );
        }
    }

    /// The ceiling itself is allowed: a day is a long flow, and refusing it
    /// would refuse the case the key exists for.
    #[test]
    fn a_route_bound_at_the_ceiling_is_accepted() {
        let config = parse(&format!(
            r#"
[[routes]]
host_pattern = "db.example.com"
mode = "tcp"
backends = ["10.0.0.5:5432"]
idle_timeout_secs = {}
flow_timeout_secs = {}
"#,
            crate::deadline::MAX_SECS,
            crate::deadline::MAX_SECS
        ));

        let routes = config.build_routes().expect("the route is built");
        assert_eq!(routes.len(), 1);
    }
}
