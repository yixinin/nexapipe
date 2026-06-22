use rand;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
}

#[derive(Debug, Clone)]
pub struct BackendPool {
    backends: Vec<String>,
    strategy: LoadBalancingStrategy,
    round_robin_index: Arc<RwLock<usize>>,
}

impl BackendPool {
    pub fn new(backends: Vec<String>, strategy: LoadBalancingStrategy) -> Self {
        BackendPool {
            backends,
            strategy,
            round_robin_index: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn select_backend(&self) -> &str {
        if self.backends.is_empty() {
            return "";
        }

        match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let mut index = self.round_robin_index.write().await;
                let selected = &self.backends[*index];
                *index = (*index + 1) % self.backends.len();
                selected
            }
            LoadBalancingStrategy::Random => {
                let idx = (rand::random::<u64>() % self.backends.len() as u64) as usize;
                &self.backends[idx]
            }
        }
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn strategy(&self) -> LoadBalancingStrategy {
        self.strategy
    }

    pub fn backends(&self) -> &[String] {
        &self.backends
    }
}
