use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::signal;

pub struct ShutdownSignal {
    shutdown_requested: AtomicBool,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        ShutdownSignal {
            shutdown_requested: AtomicBool::new(false),
        }
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, std::sync::atomic::Ordering::Relaxed);
        tracing::info!("Shutdown requested");
    }
}

pub async fn wait_for_shutdown_signal(shutdown_signal: Arc<ShutdownSignal>) {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM signal");
            shutdown_signal.request_shutdown();
        }
        _ = sigint.recv() => {
            tracing::info!("Received SIGINT signal");
            shutdown_signal.request_shutdown();
        }
    }
}

pub type SharedShutdownSignal = Arc<ShutdownSignal>;
