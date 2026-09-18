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
