use serde::Deserialize;
use std::collections::HashMap;
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
pub struct LocalProxyNode {
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
    pub domains: Vec<String>,
}

/// Client-side 2FA credentials used by local-proxy mode.
#[derive(Debug, Deserialize, Clone)]
pub struct LocalProxyTwoFactorConfig {
    pub enabled: Option<bool>,
    pub client_id: String,
    pub secret: String,
    pub algorithm: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalProxyConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub proxy_domains: Vec<String>,
    pub nodes: Option<Vec<LocalProxyNode>>,
    pub strategy: Option<String>,
    /// Full server ticket (contains Node ID + addresses)
    /// Ticket changes when addresses change, but connection info is complete
    /// Deprecated: use `nodes` for multi-endpoint support
    pub server_ticket: Option<String>,
    /// Server Node ID only (stable across restarts when using secret_key)
    /// When set, uses discovery service to find server addresses
    /// Preferred for long-term configurations
    /// Deprecated: use `nodes` for multi-endpoint support
    pub server_node_id: Option<String>,
    /// 2FA credentials used to authenticate with the server.
    /// Example:
    ///   [local_proxy.two_factor]
    ///   enabled = true
    ///   client_id = "client-001"
    ///   secret = "JBSWY3DPEHPK3PXP"
    ///   algorithm = "sha1"
    pub two_factor: Option<LocalProxyTwoFactorConfig>,
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

// ===== 2FA 认证配置 =====

/// TOML 格式的认证配置
#[derive(Debug, Deserialize, Clone)]
pub struct AuthTomlConfig {
    pub enabled: Option<bool>,
    pub algorithm: Option<String>,
    pub time_step: Option<u32>,
    pub digits: Option<u32>,
    pub window: Option<u32>,
    pub max_attempts: Option<u32>,
    pub lockout_duration: Option<u64>,
    pub clients: Option<HashMap<String, ClientAuthToml>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientAuthToml {
    pub secret: String,
    pub created_at: Option<String>,
}

impl ProxyConfig {
    /// Load config and extract auth settings from TOML
    pub fn load_with_auth(path: &str) -> anyhow::Result<(Self, Option<crate::auth::AuthConfig>)> {
        let content = std::fs::read_to_string(path)?;
        
        // Parse the base config
        let base: Self = toml::from_str(&content)?;
        
        // Try to parse auth section separately
        let auth_config = match content.parse::<toml::Value>() {
            Ok(toml_value) => {
                if let Some(auth_section) = toml_value.get("auth") {
                    let auth_toml: AuthTomlConfig = auth_section.clone().try_into()
                        .map_err(|e| anyhow::anyhow!("Failed to parse auth config: {}", e))?;
                    
                    let mut clients = HashMap::new();
                    if let Some(clients_toml) = auth_toml.clients {
                        for (id, client_toml) in clients_toml {
                            clients.insert(
                                id,
                                crate::auth::ClientAuth {
                                    secret: client_toml.secret,
                                    created_at: client_toml.created_at.unwrap_or_else(|| {
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .map(|d| d.as_secs().to_string())
                                            .unwrap_or_else(|_| "0".to_string())
                                    }),
                                    last_used: None,
                                    failed_attempts: 0,
                                    locked_until: None,
                                },
                            );
                        }
                    }
                    
                    let algorithm = match auth_toml.algorithm.as_deref() {
                        Some("sha256") | Some("SHA256") => crate::auth::TotpAlgorithm::SHA256,
                        Some("sha512") | Some("SHA512") => crate::auth::TotpAlgorithm::SHA512,
                        _ => crate::auth::TotpAlgorithm::SHA1,
                    };
                    
                    Some(crate::auth::AuthConfig {
                        enabled: auth_toml.enabled.unwrap_or(false),
                        algorithm,
                        time_step: auth_toml.time_step.unwrap_or(30),
                        digits: auth_toml.digits.unwrap_or(6),
                        window: auth_toml.window.unwrap_or(1),
                        clients,
                        max_attempts: auth_toml.max_attempts.unwrap_or(5),
                        lockout_duration: auth_toml.lockout_duration.unwrap_or(300),
                    })
                } else {
                    None
                }
            }
            Err(_) => None,
        };
        
        Ok((base, auth_config))
    }
}
