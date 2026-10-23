use crate::auth::{AuthConfig, ClientAuth};
use crate::config::ProxyConfig;
use crate::conn::AuthState;
use crate::conn::peers::PeerRegistry;
use crate::health::HealthProbes;
use crate::proxy::{BackendClients, sync_health_checks};
use crate::routes::RoutingTable;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Watches `config.toml` and applies a change to the live routing table.
///
/// Reloading used to stop at re-parsing the file: the new `ProxyConfig` was
/// stored, the log said "reloaded successfully", and the routes — built once at
/// startup — kept serving the old table. An edit to `[[routes]]` only took
/// effect after a restart, which is exactly how a freshly added route came to
/// look like it had never been added. The watcher
/// now owns what applying one takes: the `RoutingTable` to update and the HTTP
/// client any new health check needs.
///
/// The same edit usually carries an `[auth]` change the running server also
/// needs — a `--generate-invite --registration` run in another process (in
/// Docker, on the host against the mounted file) writes `pending_enrollment`
/// into the file, and without a reload the enrollment link only worked after a
/// restart. When an auth state is present, a reload swaps the clients table in
/// the same pass; see `ConfigWatcher::reload_auth`.
///
/// `enabled` now moves too, in one direction only: a reload may turn 2FA *on*
/// (for connections opened after it), and is refused when it would turn 2FA
/// *off*. See `ConfigWatcher::apply_auth_enabled`.
pub struct ConfigWatcher {
    config_path: String,
    route_config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    /// Health probes already running, and the pool each one is watching, so a
    /// reload can tell a route that was rebuilt from one that is still here.
    health_probes: Arc<Mutex<HealthProbes>>,
    /// Whether probing is on right now. Shared with every `HealthChecker`, which
    /// pauses instead of exiting: a spawned probe has no owner left to cancel it.
    health_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// The live 2FA state, when 2FA is configured. Its `RwLock` is what makes a
    /// client-table reload possible without dropping an existing connection.
    auth: Option<AuthState>,
    /// The connections being served right now, so a reload can tell one about
    /// the credential it authenticated with going away. See
    /// [`PeerRegistry::close_where`]: removing a client — or one device of it —
    /// from `[auth]` has to stop the traffic it is carrying now, not only the
    /// next dial.
    peers: Arc<PeerRegistry>,
    /// Where the plaintext listener ended up, when it is bound at all.
    ///
    /// Carried here for one check: turning 2FA on is only sound if the plaintext
    /// listener is not reachable from the network, which is the conflict
    /// `run_proxy` refuses a *start* over. A reload has to reach the same
    /// verdict, and it cannot see the bound socket from inside this task.
    ///
    /// A `OnceLock` rather than a constructor argument because the socket is
    /// bound minutes of code after the watcher is constructed and spawned; the
    /// reload that needs this value cannot run before the first 5 s poll, so the
    /// two are ordered by construction, not by luck. Empty means "bound a
    /// listener whose address nobody recorded, or none at all", which the
    /// enabling check treats as the permissive case — losing the check is not a
    /// reason to refuse an operator's edit.
    plaintext: std::sync::OnceLock<PlaintextListener>,
}

/// The plaintext listener as the reload path needs to judge it: the address it
/// actually bound and whether the operator opted into exposing it.
///
/// Copied out of `run_proxy` rather than looked up later because the socket's
/// own `local_addr` is the only thing that knows what `0.0.0.0` and a concrete
/// LAN address have in common, and the listener task owns it after startup.
#[derive(Debug, Clone, Copy)]
pub struct PlaintextListener {
    pub addr: std::net::SocketAddr,
    pub exposed: bool,
}

/// How often the watcher looks at the file.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The longest the watcher waits before trying the same file again after a
/// failed load.
///
/// A file that is wrong stays wrong, and a log line every five seconds for
/// ever is not a thing anyone wants to read. The wait starts at the poll
/// interval and doubles, so a file that was half-written is retried soon.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);

/// What the watcher remembers between ticks.
///
/// Two things: the file as it was when it was last loaded **successfully**,
/// and what to do about a load that failed.
#[derive(Debug, Clone, Copy)]
struct WatchState {
    /// The file as it was when it was last loaded.
    loaded: FileStamp,
    /// When a failed load may be tried again.
    retry_at: Instant,
    /// How long the next wait is. Doubles after every failure.
    retry_delay: Duration,
}

impl WatchState {
    fn new(loaded: FileStamp, now: Instant) -> Self {
        Self {
            loaded,
            retry_at: now,
            retry_delay: Duration::ZERO,
        }
    }

    /// Whether the file as it is now should be loaded.
    ///
    /// The stamp is compared as a whole, and **neither half has to be
    /// newer**: the time *or* the length being different is enough. A file
    /// that replaced another one — restored from a backup, checked out by
    /// `git` — can be *older* than the one it replaces, and a file written
    /// twice inside one second has the same time and a different length.
    ///
    /// A file that failed to load is tried again once the backoff says so.
    fn should_load(&self, current: FileStamp, now: Instant) -> bool {
        current != self.loaded && now >= self.retry_at
    }

    /// The file was loaded: this is the one to compare against next time.
    fn loaded(&mut self, current: FileStamp, now: Instant) {
        self.loaded = current;
        self.retry_at = now;
        self.retry_delay = Duration::ZERO;
    }

    /// The load failed: try again after a wait that grows.
    ///
    /// A file that was half-written when it was read is worth retrying soon;
    /// a file that is simply wrong is worth retrying every so often rather
    /// than on every tick, which is a log line every five seconds for ever.
    fn failed(&mut self, now: Instant) {
        self.retry_delay = (self.retry_delay * 2)
            .max(POLL_INTERVAL)
            .min(MAX_RETRY_DELAY);
        self.retry_at = now + self.retry_delay;
    }
}

/// What the file looked like the last time it was read.
///
/// The length is here as well as the time, for the two reasons the state's
/// own comment gives: a file written twice inside one second has the same
/// time and a different length, and a file that replaced another one can be
/// older.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: std::time::SystemTime,
    len: u64,
}

impl FileStamp {
    /// The stamp of a file that has not been loaded yet.
    const UNKNOWN: Self = Self {
        modified: std::time::SystemTime::UNIX_EPOCH,
        len: 0,
    };

    /// The stamp of the file as it is now.
    async fn read(path: &str) -> std::io::Result<Self> {
        let metadata = fs::metadata(path).await?;
        Ok(Self {
            modified: metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            len: metadata.len(),
        })
    }
}

impl ConfigWatcher {
    pub fn new(
        config_path: String,
        route_config: Arc<RoutingTable>,
        clients: Arc<BackendClients>,
        health_probes: Arc<Mutex<HealthProbes>>,
        health_enabled: Arc<std::sync::atomic::AtomicBool>,
        auth: Option<AuthState>,
        peers: Arc<PeerRegistry>,
    ) -> Self {
        ConfigWatcher {
            config_path,
            route_config,
            clients,
            health_probes,
            health_enabled,
            auth,
            peers,
            plaintext: std::sync::OnceLock::new(),
        }
    }

    /// Records where the plaintext listener ended up, once `run_proxy` has bound
    /// it. Ignored on a second call: there is only one listener per process.
    pub fn set_plaintext_listener(&self, listener: PlaintextListener) {
        let _ = self.plaintext.set(listener);
    }

    pub async fn start_watch(&self) {
        // The asynchronous one, like the check below: a synchronous
        // `std::fs::metadata` in an async function blocks the runtime's
        // thread, and the runtime has few of them.
        let mut state = WatchState::new(
            FileStamp::read(&self.config_path)
                .await
                // A file that is not there yet is a file that has not been
                // loaded: the first tick loads it, whatever its time says.
                .unwrap_or(FileStamp::UNKNOWN),
            Instant::now(),
        );

        loop {
            tokio::time::sleep(POLL_INTERVAL).await;

            let current = match FileStamp::read(&self.config_path).await {
                Ok(current) => current,
                Err(e) => {
                    tracing::warn!("Failed to check config file: {}", e);
                    continue;
                }
            };

            let now = Instant::now();
            if !state.should_load(current, now) {
                continue;
            }

            if self.reload_config().await {
                // Only now: a reload that failed keeps the old stamp, so the
                // file is tried again rather than ignored for ever.
                state.loaded(current, now);
            } else {
                state.failed(now);
            }
        }
    }

    /// Re-reads the file and applies what is live in it: the `[auth]` section
    /// and the routing table, each keeping the old value if the new one is
    /// unusable.
    ///
    /// A bad edit must not take the proxy down: the file is saved every time it
    /// is touched, so half-written and downright invalid configs are both normal
    /// here, and keeping the previous routes costs far less than dropping every
    /// connection. Once the file parses, the two halves are applied separately:
    /// a route table that will not build leaves the auth half applied, and an
    /// `[auth] enabled` the server refuses does not stop the clients table from
    /// being merged. A file that does not parse at all is refused whole, as the
    /// startup path refuses it.
    ///
    /// Whether the new config was applied.
    ///
    /// `false` means the file was read and could not be used, and the file is
    /// worth trying again: a half-written file is the common case, and it
    /// becomes a good file a moment later. It is also `false` when the routes
    /// were applied but the auth half was left for the next attempt: the file
    /// stamp is only advanced on `true`, which is what makes that attempt
    /// happen.
    async fn reload_config(&self) -> bool {
        tracing::info!("Detected config change, reloading...");

        // The epoch is sampled **before** the read: an enrollment that lands
        // while the file is being read is what the merge has to notice.
        let epoch = self.auth.as_ref().map(|s| s.enroll_epoch()).unwrap_or(0);

        // **One read for both halves.** The file is read once and parsed once,
        // so the routes and the 2FA clients come from the same revision of it.
        // Two reads could hand the two halves two different revisions, and a
        // change made between them would be half-applied.
        //
        // The read and the parse are synchronous, so they happen on a
        // blocking thread: the worker this runs on is not parked in `read(2)`
        // while every other task queued behind it waits for the disk.
        let config_path = self.config_path.clone();
        let loaded =
            tokio::task::spawn_blocking(move || ProxyConfig::load_with_auth(&config_path)).await;
        let (new_config, new_auth) = match loaded {
            Ok(Ok((config, auth))) => (config, auth),
            Ok(Err(e)) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return false;
            }
            Err(e) => {
                tracing::error!(
                    "Config not reloaded, keeping the current routes: the read did not run: {}",
                    e
                );
                return false;
            }
        };

        // The same warning the startup path gives. It does not need the auth
        // half to exist: a reload can bring in an inline `[iroh]` credential
        // on a file with no `[auth]` section at all, and that is a credential
        // in the open just the same.
        crate::config::warn_about_readable_credentials(
            std::path::Path::new(&self.config_path),
            &new_config,
            new_auth.as_ref(),
        );

        // Ahead of the routes, and on the same footing as them: a new
        // `[auth.clients]` entry is a change an operator makes while the server
        // runs — an invite was just generated, a device is about to connect —
        // so it must not be lost to a route table that does not parse. The two
        // are separate failure domains: either can fail and the other still
        // applies.
        //
        // The one case where the auth half is not applied is a snapshot that an
        // enrollment overtook twice. Reporting that up keeps the file stamp
        // where it was, so the watcher reads the file again instead of
        // forgetting the edit until somebody touches the file.
        let auth_applied = self.reload_auth(new_auth, epoch).await;

        let routes = match new_config.build_routes() {
            Ok(routes) => routes,
            Err(e) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return false;
            }
        };

        self.route_config.update_routes(routes).await;

        // Live, unlike the intervals a running checker was built with: those are
        // baked into spawned tasks, so only the switch travels.
        self.health_enabled.store(
            new_config.health_check.enabled,
            std::sync::atomic::Ordering::Relaxed,
        );
        sync_health_checks(
            &self.route_config,
            &self.clients,
            &self.health_probes,
            &new_config.health_check,
            &self.health_enabled,
        )
        .await;

        let routes_live = self.route_config.routes().await.len();
        if auth_applied {
            tracing::info!("Config reloaded: {routes_live} routes now live");
        } else {
            tracing::warn!(
                "Config reloaded: {routes_live} routes now live, but the 2FA half was not; the \
                 file is tried again"
            );
        }
        auth_applied
    }
    /// Applies the `[auth]` section of a freshly read config to the live 2FA
    /// state.
    ///
    /// `snapshot` is the auth half of the file as it was when the caller read
    /// it, and `epoch` the number of enrollments applied to the live config at
    /// that moment. The two go together: an enrollment that lands between the
    /// read and the lock would be undone by the merge, and the epoch is what
    /// says whether one did.
    ///
    /// Returns `false` when the snapshot was overtaken twice, or when the
    /// re-read that follows an overtake failed: either way the auth half has
    /// not been applied, and the caller has to keep the file on the retry list.
    ///
    /// The clients table is swapped unconditionally; `enabled` is applied by
    /// [`ConfigWatcher::apply_auth_enabled`], which may refuse it. The TOTP
    /// parameters stay as they were at startup: flipping the algorithm the
    /// issued secrets are keyed with — or the step and digit count their codes
    /// are computed under — mid-run would silently strand every client enrolled
    /// under the old ones, and unlike `enabled` there is no direction of that
    /// change which is ever safe. Those still need a restart; a client list edit
    /// does not.
    ///
    /// Counters live in memory and are only periodically flushed to disk by
    /// [`save_auth_state`], so for a client that survives the reload the
    /// in-memory lockout state wins over whatever the file says. Everything
    /// else — a new client from an invite, a rotated secret, a removed
    /// client — comes from the file.
    async fn reload_auth(&self, mut snapshot: Option<AuthConfig>, mut epoch: u64) -> bool {
        let Some(state) = &self.auth else {
            return true;
        };

        // Two attempts: the snapshot the caller read, and — if an enrollment
        // landed while it was being read — one more read.
        //
        // The read is **outside** the lock, which is the point of the whole
        // change: the lock is what every handshake and every lockout write
        // waits for, and holding it across a disk read makes the disk the
        // bottleneck for all of them.
        for attempt in 0..2 {
            let mut live = state.config().write().await;

            // An enrollment that landed between the read and this lock would
            // be undone by the merge, so the epoch is compared here — under
            // the lock the enrollment itself holds, so the two cannot
            // disagree about what happened.
            if state.enroll_epoch() != epoch {
                drop(live);

                if attempt == 1 {
                    tracing::warn!(
                        "2FA clients not reloaded: an enrollment landed while the config was \
                         being read, twice; the file is kept for the next attempt"
                    );
                    return false;
                }

                // Read the file again — outside the lock — and sample the
                // epoch again before it, so the same check covers this read.
                epoch = state.enroll_epoch();
                let config_path = self.config_path.clone();
                let loaded =
                    tokio::task::spawn_blocking(move || ProxyConfig::load_with_auth(&config_path))
                        .await;
                match loaded {
                    Ok(Ok((_proxy, auth))) => snapshot = auth,
                    Ok(Err(e)) => {
                        tracing::error!(
                            "2FA clients not reloaded, keeping the current ones: {}",
                            e
                        );
                        return false;
                    }
                    Err(e) => {
                        tracing::error!(
                            "2FA clients not reloaded, keeping the current ones: the read did not \
                             run: {}",
                            e
                        );
                        return false;
                    }
                }
                continue;
            }

            // The merge, under the lock, from a snapshot that is known to be
            // current.

            // What was here before the merge replaces it. Taken now rather than
            // derived afterwards because the merge overwrites each client whole:
            // a client survives losing a device, so after it there is nothing to
            // compare against and no way to notice the device is gone.
            let before: HashMap<String, Vec<String>> = live
                .clients
                .iter()
                .map(|(id, client)| (id.clone(), client.devices.keys().cloned().collect()))
                .collect();

            let Some(new_auth) = snapshot else {
                // The section is gone while 2FA is live: treat that as a bad edit,
                // not as "disable everything", the same way an unparsable route
                // table keeps the old routes. Worth saying out loud, but only when
                // something is actually being kept — a server that runs with no
                // `[auth]` at all reaches here on every reload, and a warning each
                // time would be noise about a state nobody asked to leave.
                if live.enabled || !live.clients.is_empty() {
                    tracing::warn!(
                        "Reloaded config has no [auth] section; keeping the current 2FA clients"
                    );
                }
                return true;
            };

            // `enabled` first, because it is the only value here that can refuse
            // itself. A refusal covers that value alone: the clients table below is
            // still merged, so a reload that could not move the gate does not also
            // drop the client the operator just added.
            if let Some(refusal) =
                ConfigWatcher::auth_enabled_refusal(&live, &new_auth, self.plaintext.get().copied())
            {
                tracing::error!("{refusal}");
            } else if apply_auth_enabled(&mut live, &new_auth) == Some(true) {
                tracing::warn!(
                    "[auth] enabled is now true: connections opened from here on must complete \
                 the 2FA handshake. Connections that are already authenticated keep working — \
                 they carry the authorization they were given when they connected"
                );
            }

            let (added, removed) = merge_auth_clients(&mut live, &new_auth);

            for id in &added {
                tracing::info!("2FA client '{id}' added by config reload");
            }
            for id in &removed {
                tracing::info!("2FA client '{id}' removed by config reload");
            }
            if !added.is_empty() || !removed.is_empty() {
                tracing::info!(
                    "2FA clients reloaded: {} now live ({} added, {} removed)",
                    live.clients.len(),
                    added.len(),
                    removed.len()
                );
            }

            // A client that survived losing one of its devices is not in `removed`,
            // so the devices are diffed against the snapshot from before the merge.
            let removed_devices = Self::removed_devices(&before, &live.clients);
            for (client_id, device) in &removed_devices {
                tracing::info!(
                    "2FA device '{device}' of client '{client_id}' removed by config reload"
                );
            }

            if !removed.is_empty() {
                let closed = self.peers.close_where(|identity| {
                    removed
                        .iter()
                        .any(|id| identity.client_id.as_deref() == Some(id))
                });
                if closed > 0 {
                    tracing::info!(
                        "Closed {} connection(s) authenticating as a client that is no longer in [auth]",
                        closed
                    );
                }
            }
            if !removed_devices.is_empty() {
                let closed = self.peers.close_where(|identity| {
                    removed_devices.iter().any(|(client_id, device)| {
                        identity.client_id.as_deref() == Some(client_id)
                            && identity.device.as_deref() == Some(device)
                    })
                });
                if closed > 0 {
                    tracing::info!(
                        "Closed {} connection(s) authenticating as a device that is no longer in [auth]",
                        closed
                    );
                }
            }

            return true;
        }

        // Unreachable: the second attempt either merges the snapshot or
        // returns `false`. Written out rather than `unreachable!()` because a
        // future third attempt that falls through must not claim the auth half
        // was applied.
        false
    }

    /// Which `(client, device)` pairs the merge dropped, for clients that are
    /// still there.
    ///
    /// Only clients on both sides are asked: one that disappeared takes every
    /// device under it with it, and those connections are already closed by
    /// the client-level pass — diffing it here too would count them twice.
    fn removed_devices(
        before: &HashMap<String, Vec<String>>,
        after: &HashMap<String, ClientAuth>,
    ) -> Vec<(String, String)> {
        let mut removed = Vec::new();
        for (client_id, devices) in before {
            let Some(client) = after.get(client_id) else {
                continue;
            };
            for device in devices {
                if !client.devices.contains_key(device) {
                    removed.push((client_id.clone(), device.clone()));
                }
            }
        }
        removed
    }

    /// Why this reload must not move `enabled`, when it must not.
    ///
    /// Returns the message to log and otherwise does nothing; the caller keeps
    /// the live state and applies the rest of the section. Two refusals, both
    /// about the single direction that can go wrong — turning the gate on:
    ///
    /// - **The file wants 2FA off.** Nothing requires this direction, and it
    ///   silently removes the listener's only gate on a running server. An
    ///   operator who wants it off restarts, which is also the only way to be
    ///   sure the change was meant rather than a half-saved edit.
    /// - **The plaintext listener is reachable from the network.** `run_proxy`
    ///   already refuses to *start* in this configuration, and 2FA does not run
    ///   on that listener, so enabling it mid-run would produce exactly the
    ///   state the startup check exists to prevent. A reload must not be the way
    ///   around a check the startup path enforces.
    ///
    /// A permissive mode on `config.toml` itself is no longer a reason to
    /// refuse: the file's permissions are not checked at start or on reload,
    /// and credentials belong in a sidecar file or the environment.
    ///
    /// `live.enabled == true` short-circuits all of it: once 2FA is on, the file
    /// saying `true` again changes nothing, so a reload that only edits routes
    /// cannot be blocked by either.
    fn auth_enabled_refusal(
        live: &AuthConfig,
        incoming: &AuthConfig,
        plaintext: Option<PlaintextListener>,
    ) -> Option<String> {
        if live.enabled == incoming.enabled {
            return None;
        }

        // The file says false while the process is gating: refuse the change.
        if live.enabled {
            return Some(
                "[auth] enabled = false is ignored: 2FA gates this listener and a reload cannot \
                 drop the only gate it has. Restart to disable 2FA."
                    .to_string(),
            );
        }

        // The file says true while the process is not gating: the plaintext
        // listener has to be the local one, and that gets its own message.
        if let Some(plaintext) = plaintext
            && crate::proxy::plaintext_auth_conflict(plaintext.addr, plaintext.exposed, true)
                .is_some()
        {
            return Some(format!(
                "[auth] enabled = true is ignored: the plaintext listener on {} would still reach \
                 every route without credentials, because 2FA only runs on the iroh listener. \
                 Remove [server] listen_addr or set expose = false, then restart.",
                plaintext.addr
            ));
        }

        None
    }
}

/// Moves `enabled` from the file onto the live state, and reports the transition.
///
/// Returns `Some(true)` when 2FA was just switched on, `Some(false)` when it was
/// switched off, and `None` when nothing changed — so the caller can log the one
/// transition worth a word without re-reading the state.
///
/// Deliberately only `enabled`: every other field of `[auth]` is either applied
/// by [`merge_auth_clients`] or startup-only, and the TOTP parameters are the
/// latter for the reason on [`ConfigWatcher::reload_auth`].
fn apply_auth_enabled(live: &mut AuthConfig, incoming: &AuthConfig) -> Option<bool> {
    if live.enabled == incoming.enabled {
        return None;
    }
    live.enabled = incoming.enabled;
    Some(live.enabled)
}

pub type SharedConfigWatcher = Arc<ConfigWatcher>;

/// Persists the runtime 2FA counters of `config` into the state file at `path`.
///
/// A lockout only means anything if it survives a restart, so
/// `failed_attempts`, `locked_until` and `last_used` are written back whenever
/// the connection layer changes them — and `last_used` under
/// `[auth.clients.<id>.devices.<name>]` with them, which is the stamp that says
/// whether a device is still in use.
///
/// The file they go to is the **state file**, not the configuration file, and
/// that is the whole point of this function having moved: the configuration is
/// the operator's, and a server that writes its own counters into it changes
/// a file nobody asked it to touch — and moves its modification time, which
/// the watcher watches, so a stranger mistyping a code was a configuration
/// reload. The state file is the server's, and only the server writes it.
///
/// Only the counters travel. The credentials, the host lists and the
/// enrollment tokens stay where they are, and a client or device that the
/// configuration does not have is not written: the operator may have removed
/// it while the server was running.
pub fn save_auth_state(path: &str, config: &AuthConfig) -> anyhow::Result<()> {
    // The whole read-modify-write runs under the lock, not just the write: two
    // counter writebacks that both read first would each build their document
    // from the file as it was before the other one landed, and one set of
    // counters would be lost.
    crate::config::with_config_lock(path, || {
        crate::auth::state::save(
            std::path::Path::new(path),
            &crate::auth::state::snapshot(config),
        )
    })
}

/// Folds the freshly parsed `[auth.clients]` table into the live one.
///
/// Returns the ids that were added and the ones that were removed, for the
/// reload log. A client present on both sides keeps its in-memory counters —
/// [`save_auth_state`] flushes them to the state file, but a failure recorded
/// between the last flush and this merge is newer than the file — and takes
/// everything else (`secret`, `pending_enrollment`, `allow_hosts`) from the
/// file, which is how an invite written by another process becomes spendable
/// and a rotated secret takes over without a restart. A client the file no
/// longer lists is dropped: the operator removed it, and keeping it alive in
/// memory would let a deleted credential keep authenticating until the next
/// restart.
/// The greater of two step memories, whichever they are.
///
/// The live value is by construction never older than the file's — it is
/// moved forward by every acceptance — so the greater of the two is the live
/// one. Taking the greater rather than the live one outright keeps the rule
/// right if the two ever disagree the other way, and it keeps the two
/// optionals from needing three cases at every call site.
fn newest_step(live: Option<u64>, from_file: Option<u64>) -> Option<u64> {
    match (live, from_file) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

fn merge_auth_clients(live: &mut AuthConfig, incoming: &AuthConfig) -> (Vec<String>, Vec<String>) {
    let mut added = Vec::new();
    let mut removed = Vec::new();

    let mut merged = HashMap::with_capacity(incoming.clients.len());
    for (id, incoming_client) in &incoming.clients {
        let mut client = incoming_client.clone();
        match live.clients.get(id) {
            Some(existing) => {
                // A token the file carries and memory does not — or a
                // different one — is a new invite, not more guesses at the old
                // one: the guesses and the lockout belong to the token they
                // were paid for, and this one starts with its own budget. A
                // reload that leaves the token alone keeps the live counter,
                // which is newer than the file's.
                let replaces_token = client.pending_enrollment != existing.pending_enrollment;
                client.failed_attempts = existing.failed_attempts;
                client.locked_until = existing.locked_until;
                if !replaces_token {
                    client.enrollment_failed_attempts = existing.enrollment_failed_attempts;
                    client.enrollment_locked_until = existing.enrollment_locked_until;
                }
                client.last_used = existing.last_used;
                // The step memory is preserved the same way, and for the same
                // reason: it is what refuses the second use of a code, and a
                // reload that lands between the in-memory record and the
                // state-file write would otherwise put the older value back
                // and hand the replay protection away.
                client.last_used_step = newest_step(existing.last_used_step, client.last_used_step);
                // The devices' own step memory, for the same reason: a
                // device's credential is its own, and a device that
                // authenticated in memory must not lose that by a reload.
                for (name, device) in client.devices.iter_mut() {
                    if let Some(existing_device) = existing.devices.get(name) {
                        device.last_used_step =
                            newest_step(existing_device.last_used_step, device.last_used_step);
                    }
                }
            }
            None => added.push(id.clone()),
        }
        merged.insert(id.clone(), client);
    }

    for id in live.clients.keys() {
        if !incoming.clients.contains_key(id) {
            removed.push(id.clone());
        }
    }

    live.clients = merged;
    (added, removed)
}

#[cfg(test)]
mod tests {
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
                let mut client = client("SECRETSECRETSECR");
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
            Arc::new(PeerRegistry::new()),
        )
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
            "[auth]\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILE\"\n",
        )
        .unwrap();
        let path = path.to_str().unwrap().to_string();

        let state = AuthState::new(AuthConfig::default(), &path);
        let watcher = watcher_for(state.clone(), &path);

        watcher
            .reload_auth(
                Some(config_with(&[(
                    "from-the-snapshot",
                    client("FROMTHESNAPSHOT"),
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
            "[auth]\nenabled = true\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILE\"\n",
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
                        client("FROMTHESNAPSHOT"),
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
            "[auth]\n\n[auth.clients.from-the-file]\nsecret = \"FROMTHEFILE\"\n",
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
                        client("FROMTHESNAPSHOT"),
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
             [auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXP\"\n",
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
        let mut live = config_with(&[("old", client("OLDOLDOLDOLDOLD"))]);
        let incoming = config_with(&[
            ("old", client("OLDOLDOLDOLDOLD")),
            ("new", client("NEWNEWNEWNEWNEW")),
        ]);

        let (added, removed) = merge_auth_clients(&mut live, &incoming);

        assert_eq!(added, vec!["new".to_string()]);
        assert!(removed.is_empty());
        assert_eq!(live.clients.len(), 2);
        assert_eq!(live.clients["new"].secret.as_str(), "NEWNEWNEWNEWNEW");

        let (added, removed) = merge_auth_clients(&mut live, &config_with(&[]));

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
        let mut live = config_with(&[("client-001", client("OLDSECRETVALUE"))]);
        let existing = live.clients.get_mut("client-001").unwrap();
        existing.failed_attempts = 2;
        existing.locked_until = Some(12345);
        existing.pending_enrollment = Some(SecretString::new("token".to_string()));
        existing.enrollment_failed_attempts = 2;
        existing.enrollment_locked_until = Some(54321);

        let mut incoming_client = client("NEWSECRETVALUE");
        incoming_client.pending_enrollment = Some(SecretString::new("token".to_string()));
        let incoming = config_with(&[("client-001", incoming_client)]);

        let (added, removed) = merge_auth_clients(&mut live, &incoming);

        assert!(added.is_empty() && removed.is_empty());
        let client = &live.clients["client-001"];
        assert_eq!(client.secret.as_str(), "NEWSECRETVALUE");
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
        let mut live = config_with(&[("client-001", client("SECRETVALUE"))]);
        let existing = live.clients.get_mut("client-001").unwrap();
        existing.pending_enrollment = Some(SecretString::new("old-token".to_string()));
        existing.enrollment_failed_attempts = 2;
        existing.enrollment_locked_until = Some(54321);

        let mut incoming_client = client("SECRETVALUE");
        incoming_client.pending_enrollment = Some(SecretString::new("new-token".to_string()));
        let incoming = config_with(&[("client-001", incoming_client)]);

        let (added, removed) = merge_auth_clients(&mut live, &incoming);

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
            "[auth]\nenabled = true\n\n[auth.clients.client-001]\nsecret = \"JBSWY3DPEHPK3PXP\"\n",
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
             secret = \"ALICEALICEALICEA\"\n\
             \n\
             [auth.clients.alice.devices.laptop]\n\
             secret = \"LAPTOPLAPTOPLAPT\"\n",
        )
        .expect("write the config");

        let mut alice = client("ALICEALICEALICEA");
        alice.devices = [(
            "laptop".to_string(),
            DeviceAuth {
                secret: SecretString::new("LAPTOPLAPTOPLAPT".to_string()),
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
        save_auth_state(&state_path_str, &config.counter_snapshot())
            .expect("the writeback succeeds");

        let on_disk = std::fs::read_to_string(&state_path).expect("read the state back");
        assert!(
            on_disk.contains("last_used = 1700000000"),
            "the device stamp did not reach the file: {on_disk}"
        );
        assert!(
            !on_disk.contains("LAPTOPLAPTOPLAPT"),
            "the snapshot's blanked secret must not be written: {on_disk}"
        );

        let config_on_disk = std::fs::read_to_string(&path).expect("read the config back");
        assert_eq!(
            config_on_disk,
            "[auth]\n\
             [auth.clients.alice]\n\
             secret = \"ALICEALICEALICEA\"\n\
             \n\
             [auth.clients.alice.devices.laptop]\n\
             secret = \"LAPTOPLAPTOPLAPT\"\n",
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

        std::fs::write(&path, file_with("old", "OLDOLDOLDOLDOLDO")).expect("write the first file");
        let state = AuthState::new(
            config_with(&[("old", client("OLDOLDOLDOLDOLDO"))]),
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
            std::fs::write(&path_for_task, file_with("new", "NEWNEWNEWNEWNEWN"))
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
                Some(config_with(&[("old", client("OLDOLDOLDOLDOLDO"))])),
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
                 secret = \"ALICEALICEALICEA\"\n\
                 created_at = \"1723756800\"\n",
            );
            for name in devices {
                out.push_str(&format!(
                    "\n[auth.clients.alice.devices.{name}]\n\
                     secret = \"DEVICEDEVICEDEVIC\"\n\
                     created_at = \"1723756800\"\n"
                ));
            }
            out
        };

        std::fs::write(&path, file(&["laptop", "phone"])).expect("write the config");

        let mut alice = client("ALICEALICEALICEA");
        alice.devices = ["laptop", "phone"]
            .into_iter()
            .map(|name| (name.to_string(), device("DEVICEDEVICEDEVIC")))
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
}
