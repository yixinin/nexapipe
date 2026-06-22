use crate::lb::{BackendPool, LoadBalancingStrategy};
use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Route {
    host_pattern: String,
    path_pattern: String,
    path_is_prefix: bool,
    backend_pool: Arc<BackendPool>,
    cert_path: Option<String>,
    key_path: Option<String>,
    certs: Arc<Option<Vec<CertificateDer<'static>>>>,
    key: Arc<Option<PrivateKeyDer<'static>>>,
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
    ) -> Self {
        let (certs, key) = load_certs_keys(&cert_path, &key_path);
        
        Route {
            host_pattern: host_pattern.to_string(),
            path_pattern: path_pattern.to_string(),
            path_is_prefix,
            backend_pool: Arc::new(BackendPool::new(backends, strategy)),
            cert_path,
            key_path,
            certs: Arc::new(certs),
            key: Arc::new(key),
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
}

#[derive(Debug, Clone)]
pub struct RouteConfig {
    routes: Arc<Vec<Route>>,
    default_backend: Arc<String>,
}

impl RouteConfig {
    pub fn new(routes: Vec<Route>, default_backend: String) -> Self {
        Self {
            routes: Arc::new(routes),
            default_backend: Arc::new(default_backend),
        }
    }

    pub async fn get_backend(&self, host: &str, path: &str) -> BackendInfo {
        let mut matched_route: Option<(&Route, u32)> = None;

        for route in self.routes.iter() {
            if route.matches(host, path) {
                let priority = route.priority();
                match matched_route {
                    None => {
                        matched_route = Some((route, priority));
                    }
                    Some((_, current_priority)) => {
                        if priority > current_priority {
                            matched_route = Some((route, priority));
                        }
                    }
                }
            }
        }

        if let Some((route, _)) = matched_route {
            let backend_url = route.backend_pool().select_backend().await;
            BackendInfo {
                url: backend_url.to_string(),
                verify_cert: true,
            }
        } else {
            BackendInfo {
                url: self.default_backend.clone().to_string(),
                verify_cert: true,
            }
        }
    }

    pub fn routes(&self) -> &Vec<Route> {
        &self.routes
    }

    pub fn default_backend(&self) -> &str {
        &self.default_backend
    }

    pub async fn get_route_for_host(&self, host: &str) -> Option<&Route> {
        for route in self.routes.iter() {
            if route.matches(host, "/") {
                return Some(route);
            }
        }
        None
    }
}
