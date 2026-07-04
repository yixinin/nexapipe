use rand;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
}

#[derive(Debug, Clone)]
pub struct BackendStatus {
    url: String,
    healthy: bool,
    last_check: Option<std::time::Instant>,
    consecutive_failures: usize,
}

impl BackendStatus {
    pub fn new(url: String) -> Self {
        BackendStatus {
            url,
            healthy: true,
            last_check: None,
            consecutive_failures: 0,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    pub fn mark_healthy(&mut self) {
        self.healthy = true;
        self.consecutive_failures = 0;
        self.last_check = Some(std::time::Instant::now());
    }

    pub fn mark_unhealthy(&mut self) {
        self.healthy = false;
        self.consecutive_failures += 1;
        self.last_check = Some(std::time::Instant::now());
    }

    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }
}

#[derive(Debug, Clone)]
pub struct BackendPool {
    backends: Vec<Arc<RwLock<BackendStatus>>>,
    strategy: LoadBalancingStrategy,
    round_robin_index: Arc<RwLock<usize>>,
}

impl BackendPool {
    pub fn new(backends: Vec<String>, strategy: LoadBalancingStrategy) -> Self {
        let backend_statuses = backends
            .into_iter()
            .map(|url| Arc::new(RwLock::new(BackendStatus::new(url))))
            .collect();

        BackendPool {
            backends: backend_statuses,
            strategy,
            round_robin_index: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn select_backend(&self) -> String {
        let mut healthy_backends = Vec::new();
        for (i, b) in self.backends.iter().enumerate() {
            if b.read().await.is_healthy() {
                healthy_backends.push(i);
            }
        }

        if healthy_backends.is_empty() {
            tracing::warn!("No healthy backends available, falling back to all backends");
            return if let Some(b) = self.backends.first() {
                b.read().await.url.clone()
            } else {
                String::new()
            };
        }

        let idx = match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let mut index = self.round_robin_index.write().await;
                let idx = healthy_backends[*index % healthy_backends.len()];
                *index = (*index + 1) % healthy_backends.len();
                idx
            }
            LoadBalancingStrategy::Random => {
                let rand_idx = (rand::random::<u64>() % healthy_backends.len() as u64) as usize;
                healthy_backends[rand_idx]
            }
        };

        let selected = &self.backends[idx];
        let url = selected.read().await.url.clone();
        tracing::debug!(
            "Selected backend: {} (strategy={:?})",
            url,
            self.strategy
        );
        url
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn strategy(&self) -> LoadBalancingStrategy {
        self.strategy
    }

    pub async fn backends(&self) -> Vec<String> {
        let mut result = Vec::new();
        for b in &self.backends {
            result.push(b.read().await.url.clone());
        }
        result
    }

    pub async fn set_backend_health(&self, url: &str, healthy: bool) {
        for backend in &self.backends {
            let mut status = backend.write().await;
            if status.url == url {
                if healthy {
                    status.mark_healthy();
                } else {
                    status.mark_unhealthy();
                }
                tracing::debug!(
                    "Backend {} health status: {} (failures: {})",
                    url,
                    healthy,
                    status.consecutive_failures()
                );
                return;
            }
        }
    }

    pub async fn get_backend_statuses(&self) -> Vec<(String, bool)> {
        let mut result = Vec::new();
        for b in &self.backends {
            let status = b.read().await;
            result.push((status.url.clone(), status.healthy));
        }
        result
    }
}
