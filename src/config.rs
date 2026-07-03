use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_addr: Option<String>,
    pub tls_enabled: Option<bool>,
    pub tls_listen_addr: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AcmeConfig {
    pub enabled: Option<bool>,
    pub email: Option<String>,
    pub directory_url: Option<String>,
    pub cloudflare_api_token: Option<String>,
    pub certs_dir: Option<String>,
    pub renew_before_days: Option<u32>,
    pub domains: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IrohConfig {
    pub relay_url: Option<String>,
    pub relay_mode: Option<String>,
    pub bind_port: Option<u16>,
    /// Secret key for stable endpoint identity.
    /// If provided, the endpoint will have the same Node ID across restarts.
    /// Can be generated using `nexapipe --generate-secret` command.
    pub secret_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub host_pattern: String,
    pub path_pattern: String,
    pub path_is_prefix: Option<bool>,
    pub strategy: Option<String>,
    pub backends: Vec<String>,
    pub cert_path: Option<String>,
    pub path_rewrite: Option<String>,
    pub redirect_to_https: Option<bool>,
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
    pub debug: Option<bool>,
    pub routes: Option<Vec<RouteConfig>>,
    pub server: Option<ServerConfig>,
    pub iroh: Option<IrohConfig>,
    pub local_proxy: Option<LocalProxyConfig>,
    pub acme: Option<AcmeConfig>,
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
