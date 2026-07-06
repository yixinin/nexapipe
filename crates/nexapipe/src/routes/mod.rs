use crate::lb::{BackendPool, LoadBalancingStrategy};
use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Route {
    host_pattern: String,
    path_pattern: String,
    path_is_prefix: bool,
    backend_pool: Arc<BackendPool>,
    certs: Arc<Option<Vec<CertificateDer<'static>>>>,
    key: Arc<Option<PrivateKeyDer<'static>>>,
    path_rewrite: Option<String>,
    redirect_to_https: bool,
}

impl Route {
    pub fn new(
        host_pattern: &str,
        path_pattern: &str,
        path_is_prefix: bool,
        backends: Vec<String>,
        strategy: LoadBalancingStrategy,
        cert_path: Option<String>,
        key_path: Option<String>,
        path_rewrite: Option<String>,
        redirect_to_https: bool,
    ) -> Self {
        let (certs, key) = load_certs_keys(&cert_path, &key_path);
        
        Route {
            host_pattern: host_pattern.to_string(),
            path_pattern: path_pattern.to_string(),
            path_is_prefix,
            backend_pool: Arc::new(BackendPool::new(backends, strategy)),
            certs: Arc::new(certs),
            key: Arc::new(key),
            path_rewrite,
            redirect_to_https,
        }
    }

    pub fn matches(&self, host: &str, path: &str) -> bool {
        let host_matches = if self.host_pattern.starts_with('*') {
            let suffix = &self.host_pattern[1..];
            host.ends_with(suffix)
        } else {
            host == self.host_pattern
        };

        let path_matches = if self.path_is_prefix {
            path.starts_with(&self.path_pattern)
        } else {
            path == self.path_pattern
        };

        host_matches && path_matches
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

    pub fn backend_pool(&self) -> &Arc<BackendPool> {
        &self.backend_pool
    }

    pub fn certs(&self) -> &Option<Vec<CertificateDer<'static>>> {
        &self.certs
    }

    pub fn key(&self) -> &Option<PrivateKeyDer<'static>> {
        &self.key
    }

    pub fn has_cert(&self) -> bool {
        self.certs.is_some() && self.key.is_some()
    }

    pub fn path_rewrite(&self) -> &Option<String> {
        &self.path_rewrite
    }

    pub fn redirect_to_https(&self) -> bool {
        self.redirect_to_https
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

fn load_certs_keys(cert_path: &Option<String>, key_path: &Option<String>) -> (Option<Vec<CertificateDer<'static>>>, Option<PrivateKeyDer<'static>>) {
    if let (Some(cert_p), Some(key_p)) = (cert_path, key_path) {
        match load_certs(cert_p) {
            Ok(certs) => match load_keys(key_p) {
                Ok(mut keys) => {
                    if !keys.is_empty() {
                        return (Some(certs), Some(keys.remove(0)));
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load key file {}: {}", key_p, e);
                }
            },
            Err(e) => {
                tracing::warn!("Failed to load cert file {}: {}", cert_p, e);
            }
        }
    }
    (None, None)
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open cert file: {}", e))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse cert file: {}", e))?;
    Ok(certs)
}

fn load_keys(path: &str) -> anyhow::Result<Vec<PrivateKeyDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open key file: {}", e))?;
    let mut reader = std::io::BufReader::new(file);
    let keys: Vec<PrivatePkcs8KeyDer<'static>> = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse key file: {}", e))?;
    Ok(keys.into_iter().map(|k| PrivateKeyDer::Pkcs8(k)).collect())
}

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub url: String,
    pub verify_cert: bool,
    pub path_rewrite: Option<String>,
    pub redirect_to_https: bool,
    pub path_pattern: String,
    pub path_is_prefix: bool,
}

#[derive(Debug, Clone)]
pub struct RouteConfig {
    routes: Arc<RwLock<Vec<Route>>>,
    default_backend: Arc<RwLock<String>>,
}

impl RouteConfig {
    pub fn new(routes: Vec<Route>, default_backend: String) -> Self {
        Self {
            routes: Arc::new(RwLock::new(routes)),
            default_backend: Arc::new(RwLock::new(default_backend)),
        }
    }

    pub async fn get_backend(&self, host: &str, path: &str) -> BackendInfo {
        tracing::debug!("Looking up backend for host={}, path={}", host, path);
        
        let matched_route_info = {
            let routes = self.routes.read().await;
            let mut matched_route: Option<(Route, u32)> = None;

            for route in routes.iter() {
                if route.matches(host, path) {
                    let priority = route.priority();
                    tracing::debug!(
                        "Route matched: host={}, path={}, priority={}",
                        route.host_pattern(),
                        route.path_pattern(),
                        priority
                    );
                    match matched_route {
                        None => {
                            matched_route = Some((route.clone(), priority));
                        }
                        Some((_, current_priority)) => {
                            if priority > current_priority {
                                tracing::debug!(
                                    "Higher priority route found: {} > {}",
                                    priority,
                                    current_priority
                                );
                                matched_route = Some((route.clone(), priority));
                            }
                        }
                    }
                }
            }
            matched_route
        };

        if let Some((route, _)) = matched_route_info {
            let backend_url = route.backend_pool().select_backend().await;
            tracing::debug!(
                "Selected backend: {} for host={}, path={}",
                backend_url,
                host,
                path
            );
            BackendInfo {
                url: backend_url,
                verify_cert: true,
                path_rewrite: route.path_rewrite().clone(),
                redirect_to_https: route.redirect_to_https(),
                path_pattern: route.path_pattern().to_string(),
                path_is_prefix: route.path_is_prefix(),
            }
        } else {
            let default_backend = self.default_backend.read().await.clone();
            tracing::debug!(
                "No route matched, using default backend: {} for host={}, path={}",
                default_backend,
                host,
                path
            );
            BackendInfo {
                url: default_backend,
                verify_cert: true,
                path_rewrite: None,
                redirect_to_https: false,
                path_pattern: "/".to_string(),
                path_is_prefix: true,
            }
        }
    }

    pub async fn routes(&self) -> Vec<Route> {
        self.routes.read().await.clone()
    }

    pub async fn default_backend(&self) -> String {
        self.default_backend.read().await.clone()
    }

    pub async fn get_route_for_host(&self, host: &str) -> Option<Route> {
        let routes = self.routes.read().await;
        for route in routes.iter() {
            if route.matches(host, "/") {
                return Some(route.clone());
            }
        }
        None
    }

    pub async fn update_routes(&self, new_routes: Vec<Route>) {
        let mut routes = self.routes.write().await;
        *routes = new_routes;
        tracing::info!("Routes updated successfully");
    }

    pub async fn update_default_backend(&self, new_default: String) {
        let mut default_backend = self.default_backend.write().await;
        *default_backend = new_default.clone();
        tracing::info!("Default backend updated to: {}", new_default);
    }
}
