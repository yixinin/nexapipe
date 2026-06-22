use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub tls_enabled: Option<bool>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IrohConfig {
    pub relay_url: Option<String>,
    pub relay_mode: Option<String>,
    pub bind_port: Option<u16>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub host_pattern: String,
    pub path_pattern: String,
    pub path_is_prefix: Option<bool>,
    pub strategy: Option<String>,
    pub backends: Vec<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalProxyConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub proxy_domains: Vec<String>,
    pub server_ticket: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub default_backend: String,
    pub routes: Option<Vec<RouteConfig>>,
    pub server: Option<ServerConfig>,
    pub iroh: Option<IrohConfig>,
    pub local_proxy: Option<LocalProxyConfig>,
}

impl ProxyConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let path = Path::new(path);
        tracing::debug!("Loading config from: {}", path.display());
        
        if !path.exists() {
            return Err(anyhow::anyhow!("Config file not found: {}", path.display()));
        }
        
        tracing::debug!("Config file exists, reading content");
        let content = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;
        
        tracing::debug!("Config content read successfully, parsing TOML");
        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;
        
        tracing::debug!("Config parsed successfully: {:?}", config);
        Ok(config)
    }
}

pub fn get_strategy(strategy: &Option<String>) -> crate::lb::LoadBalancingStrategy {
    match strategy.as_deref() {
        Some("random") | Some("Random") => crate::lb::LoadBalancingStrategy::Random,
        Some("round_robin") | Some("RoundRobin") | Some("roundrobin") => crate::lb::LoadBalancingStrategy::RoundRobin,
        None | Some(_) => crate::lb::LoadBalancingStrategy::RoundRobin,
    }
}
