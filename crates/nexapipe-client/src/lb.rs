use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
}

pub struct RoundRobinBalancer {
    index: AtomicUsize,
}

impl RoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            index: AtomicUsize::new(0),
        }
    }

    pub fn select(&self, count: usize) -> usize {
        if count == 0 {
            return 0;
        }
        let current = self.index.fetch_add(1, Ordering::Relaxed);
        current % count
    }
}

pub struct RandomBalancer;

impl RandomBalancer {
    pub fn new() -> Self {
        Self
    }

    pub fn select(&self, count: usize) -> usize {
        if count == 0 {
            return 0;
        }
        fastrand::usize(0..count)
    }
}

pub trait LoadBalancer {
    fn select(&self, count: usize) -> usize;
}

impl LoadBalancer for RoundRobinBalancer {
    fn select(&self, count: usize) -> usize {
        self.select(count)
    }
}

impl LoadBalancer for RandomBalancer {
    fn select(&self, count: usize) -> usize {
        self.select(count)
    }
}