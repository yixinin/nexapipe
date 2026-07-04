use crate::config::ProxyConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;

pub struct ConfigWatcher {
    config_path: String,
    current_config: Mutex<ProxyConfig>,
    last_modified: Mutex<std::time::SystemTime>,
}

impl ConfigWatcher {
    pub fn new(config_path: String, initial_config: ProxyConfig) -> Self {
        let last_modified = std::fs::metadata(&config_path)
            .map(|m| m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

        ConfigWatcher {
            config_path,
            current_config: Mutex::new(initial_config),
            last_modified: Mutex::new(last_modified),
        }
    }

    pub async fn get_config(&self) -> ProxyConfig {
        self.current_config.lock().await.clone()
    }

    pub async fn start_watch(&self) -> Result<(), anyhow::Error> {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            match fs::metadata(&self.config_path).await {
                Ok(metadata) => {
                    if let Ok(modified) = metadata.modified() {
                        let mut last_modified = self.last_modified.lock().await;
                        if modified > *last_modified {
                            *last_modified = modified;
                            self.reload_config().await?;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to check config file: {}", e);
                }
            }
        }
    }

    async fn reload_config(&self) -> Result<(), anyhow::Error> {
        tracing::info!("Detected config change, reloading...");

        match ProxyConfig::from_file(&self.config_path) {
            Ok(new_config) => {
                let mut current_config = self.current_config.lock().await;
                *current_config = new_config;
                tracing::info!("Config reloaded successfully");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to reload config: {}", e);
                Err(e)
            }
        }
    }
}

pub type SharedConfigWatcher = Arc<ConfigWatcher>;
