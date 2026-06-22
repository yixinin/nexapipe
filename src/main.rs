use clap::Parser;
use nexapipe::config::{self, IrohConfig, LocalProxyConfig, ProxyConfig, ServerConfig};
use nexapipe::proxy::{run_local_proxy, run_proxy};
use nexapipe::routes::Route;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[arg(long, help = "Run in client local proxy mode")]
    local_proxy: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let proxy_config = match ProxyConfig::from_file(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    if cli.local_proxy {
        run_local_proxy_mode(&proxy_config).await;
    } else {
        run_server_mode(&proxy_config).await;
    }
}

async fn run_server_mode(proxy_config: &ProxyConfig) {
    let server_config: Option<ServerConfig> = proxy_config.server.clone();
    let iroh_config: Option<IrohConfig> = proxy_config.iroh.clone();

    let mut routes = Vec::new();

    if let Some(route_configs) = proxy_config.routes.clone() {
        for route_config in route_configs {
            let strategy = config::get_strategy(&route_config.strategy);
            let path_is_prefix = route_config.path_is_prefix.unwrap_or(true);
            let backends_count = route_config.backends.len();
            let host_pattern = route_config.host_pattern.clone();
            let path_pattern = route_config.path_pattern.clone();

            routes.push(Route::new(
                &host_pattern,
                &path_pattern,
                path_is_prefix,
                route_config.backends,
                strategy,
                route_config.cert_path,
                route_config.key_path,
            ));

            tracing::info!(
                "Loaded route: host={}, path={} (prefix={}), backends={}, strategy={:?}",
                host_pattern,
                path_pattern,
                path_is_prefix,
                backends_count,
                strategy
            );
        }
    }

    tracing::info!("Starting proxy with domain-based and path-based routing");
    tracing::info!("Default backend: {}", proxy_config.default_backend);

    if let Err(e) = run_proxy(routes, proxy_config.default_backend.clone(), server_config, iroh_config).await {
        tracing::error!("Proxy failed: {}", e);
        std::process::exit(1);
    }
}

async fn run_local_proxy_mode(proxy_config: &ProxyConfig) {
    let local_proxy_config: Option<LocalProxyConfig> = proxy_config.local_proxy.clone();

    let config = match local_proxy_config {
        Some(cfg) => cfg,
        None => {
            tracing::error!("Local proxy config not found");
            std::process::exit(1);
        }
    };

    if !config.enabled {
        tracing::error!("Local proxy is not enabled in config");
        std::process::exit(1);
    }

    tracing::info!("Starting local proxy mode");

    if let Err(e) = run_local_proxy(config).await {
        tracing::error!("Local proxy failed: {}", e);
        std::process::exit(1);
    }
}
