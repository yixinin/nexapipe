use crate::lb::BackendPool;
use hyper_util::client::legacy;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

type HttpClient = legacy::Client<
    hyper_rustls::HttpsConnector<legacy::connect::HttpConnector>,
    http_body_util::Full<bytes::Bytes>,
>;

pub struct HealthChecker {
    backend_pool: Arc<BackendPool>,
    client: Arc<HttpClient>,
    interval: Duration,
    timeout: Duration,
    failure_threshold: usize,
    health_path: String,
}

impl HealthChecker {
    pub fn new(
        backend_pool: Arc<BackendPool>,
        client: Arc<HttpClient>,
        interval: Duration,
        timeout: Duration,
        failure_threshold: usize,
        health_path: &str,
    ) -> Self {
        HealthChecker {
            backend_pool,
            client,
            interval,
            timeout,
            failure_threshold,
            health_path: health_path.to_string(),
        }
    }

    pub async fn run(self) {
        tracing::info!(
            "Health checker started with interval={:?}, timeout={:?}, threshold={}",
            self.interval,
            self.timeout,
            self.failure_threshold
        );

        loop {
            self.check_all_backends().await;
            sleep(self.interval).await;
        }
    }

    async fn check_all_backends(&self) {
        let backends = self.backend_pool.backends().await;
        for url in backends {
            let is_healthy = self.check_backend(&url).await;
            let statuses = self.backend_pool.get_backend_statuses().await;
            let current_healthy = statuses
                .into_iter()
                .find(|(u, _)| u == &url)
                .map(|(_, h)| h);

            if let Some(current) = current_healthy {
                if !is_healthy && current {
                    tracing::warn!("Backend {} health check failed", url);
                    self.backend_pool.set_backend_health(&url, false).await;
                } else if is_healthy && !current {
                    tracing::info!("Backend {} recovered, marking healthy", url);
                    self.backend_pool.set_backend_health(&url, true).await;
                }
            } else if !is_healthy {
                self.backend_pool.set_backend_health(&url, false).await;
            }
        }
    }

    async fn check_backend(&self, url: &str) -> bool {
        let health_url = format!("{}{}", url, self.health_path);

        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(&health_url)
            .header("host", "health-check")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();

        match tokio::time::timeout(self.timeout, self.client.request(request)).await {
            Ok(Ok(response)) => {
                let status = response.status();
                let healthy = status.is_success();
                if healthy {
                    tracing::debug!("Backend {} health check passed: {}", url, status);
                } else {
                    tracing::warn!("Backend {} health check failed: {}", url, status);
                }
                healthy
            }
            Ok(Err(e)) => {
                tracing::warn!("Backend {} health check error: {}", url, e);
                false
            }
            Err(_) => {
                tracing::warn!("Backend {} health check timed out", url);
                false
            }
        }
    }
}