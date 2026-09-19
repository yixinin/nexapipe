use crate::auth::AuthConfig;
use crate::config::ProxyConfig;
use crate::proxy::{HttpClient, spawn_health_checks};
use crate::routes::RouteConfig;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;

/// Watches `config.toml` and applies a change to the live routing table.
///
/// Reloading used to stop at re-parsing the file: the new `ProxyConfig` was
/// stored, the log said "reloaded successfully", and the routes — built once at
/// startup — kept serving the old table. An edit to `[[routes]]` or
/// `default_backend` only took effect after a restart, which is exactly how a
/// freshly added route came to look like it had never been added. The watcher
/// now owns what applying one takes: the `RouteConfig` to update and the HTTP
/// client any new health check needs.
pub struct ConfigWatcher {
    config_path: String,
    route_config: Arc<RouteConfig>,
    http_client: Arc<HttpClient>,
    /// Health checks already running, keyed by host + backends. A probe cannot
    /// be stopped, so a reload only starts the ones it has not started yet.
    health_seen: Arc<Mutex<HashSet<String>>>,
}

impl ConfigWatcher {
    pub fn new(
        config_path: String,
        route_config: Arc<RouteConfig>,
        http_client: Arc<HttpClient>,
        health_seen: Arc<Mutex<HashSet<String>>>,
    ) -> Self {
        ConfigWatcher {
            config_path,
            route_config,
            http_client,
            health_seen,
        }
    }

    pub async fn start_watch(&self) {
        let mut last_modified = std::fs::metadata(&self.config_path)
            .map(|m| m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            match fs::metadata(&self.config_path).await {
                Ok(metadata) => {
                    if let Ok(modified) = metadata.modified()
                        && modified > last_modified
                    {
                        last_modified = modified;
                        self.reload_config().await;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to check config file: {}", e);
                }
            }
        }
    }

    /// Re-reads the file and swaps the routing table, keeping the old one if the
    /// new file is unusable.
    ///
    /// A bad edit must not take the proxy down: the file is saved every time it
    /// is touched, so half-written and downright invalid configs are both normal
    /// here, and keeping the previous routes costs far less than dropping every
    /// connection.
    async fn reload_config(&self) {
        tracing::info!("Detected config change, reloading...");

        let new_config = match ProxyConfig::from_file(&self.config_path) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return;
            }
        };

        let routes = match new_config.build_routes() {
            Ok(routes) => routes,
            Err(e) => {
                tracing::error!("Config not reloaded, keeping the current routes: {}", e);
                return;
            }
        };

        self.route_config
            .update_default_backend(new_config.default_backend.clone())
            .await;
        self.route_config.update_routes(routes).await;
        spawn_health_checks(&self.route_config, &self.http_client, &self.health_seen).await;

        tracing::info!(
            "Config reloaded: {} routes now live",
            self.route_config.routes().await.len()
        );
    }
}

pub type SharedConfigWatcher = Arc<ConfigWatcher>;

/// Persists the runtime 2FA counters of `config` into the file at `path`.
///
/// A lockout only means anything if it survives a restart, so
/// `failed_attempts`, `locked_until` and `last_used` are written back whenever
/// the connection layer changes them. Only those three keys of
/// `[auth.clients.<id>]` are touched — and only for clients that already have
/// a section on disk, so a stale in-memory entry cannot resurrect a client
/// the operator removed. Everything else in the file, comments included,
/// survives byte for byte, exactly like [`ProxyConfig::write_client_secret`].
pub fn save_auth_state(path: &str, config: &AuthConfig) -> anyhow::Result<()> {
    let content =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, auth state not written ({e})"))?;

    let clients = doc
        .as_table_mut()
        .get_mut("auth")
        .and_then(|item| item.as_table_like_mut())
        .and_then(|auth| auth.get_mut("clients"))
        .and_then(|item| item.as_table_like_mut())
        .ok_or_else(|| anyhow::anyhow!("{path} has no [auth.clients] table, auth state not written"))?;

    for (id, client) in &config.clients {
        let Some(table) = clients.get_mut(id).and_then(|item| item.as_table_like_mut()) else {
            // Not on disk: the operator edited the file under us; writing a
            // section without a secret would break the next load.
            continue;
        };
        set_counter(table, "failed_attempts", client.failed_attempts as u64);
        set_counter(table, "locked_until", client.locked_until.unwrap_or(0));
        set_counter(table, "last_used", client.last_used.unwrap_or(0));
    }

    std::fs::write(path, doc.to_string())
        .map_err(|e| anyhow::anyhow!("cannot write {path}: {e}"))
}

/// Writes `value` under `key`, or removes the key when the counter is back at
/// zero — a config file should not accumulate `failed_attempts = 0` lines for
/// every client that ever mistyped a code.
fn set_counter(table: &mut dyn toml_edit::TableLike, key: &str, value: u64) {
    if value != 0 {
        table.insert(key, toml_edit::value(value as i64));
    } else {
        table.remove(key);
    }
}
