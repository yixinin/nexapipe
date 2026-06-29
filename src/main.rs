use clap::Parser;
use nexapipe::acme::{AcmeConfig, AcmeManager};
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

    #[arg(long, help = "Obtain certificates without starting proxy")]
    obtain_certs: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let proxy_config = match ProxyConfig::from_file(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    let debug_enabled = proxy_config.debug.unwrap_or(false);
    let log_filter = if debug_enabled {
        "nexapipe=debug"
    } else {
        "nexapipe=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_filter))
        .with_target(false)
        .with_level(true)
        .init();

    if debug_enabled {
        tracing::info!("Debug mode enabled");
    }

    if let Some(acme_config) = &proxy_config.acme {
        if let Ok(acme_manager) = setup_acme(acme_config).await {
            if cli.obtain_certs {
                obtain_certs_once(&acme_manager, acme_config).await;
                return;
            }

            tokio::spawn(async move {
                if let Err(e) = acme_manager.start_renewal_loop().await {
                    tracing::error!("ACME renewal loop failed: {}", e);
                }
            });
        }
    }

    if cli.local_proxy {
        run_local_proxy_mode(&proxy_config).await;
    } else {
        run_server_mode(&proxy_config).await;
    }
}

async fn setup_acme(config: &config::AcmeConfig) -> Result<AcmeManager, anyhow::Error> {
    if !config.enabled.unwrap_or(false) {
        return Err(anyhow::anyhow!("ACME is not enabled"));
    }

    let email = config
        .email
        .clone()
        .ok_or_else(|| anyhow::anyhow!("ACME email is required"))?;
    let directory_url = config
        .directory_url
        .clone()
        .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".to_string());
    let cloudflare_api_token = config
        .cloudflare_api_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Cloudflare API token is required"))?;
    let certs_dir = config
        .certs_dir
        .clone()
        .unwrap_or_else(|| "./certs".to_string());
    let renew_before_days = config.renew_before_days.unwrap_or(30);
    let domains = config.domains.clone().unwrap_or_default();

    if domains.is_empty() {
        return Err(anyhow::anyhow!("ACME domains list is empty"));
    }

    std::fs::create_dir_all(&certs_dir)?;

    let acme_config = AcmeConfig {
        enabled: true,
        email,
        directory_url,
        cloudflare_api_token,
        certs_dir,
        renew_before_days,
        domains,
    };

    let manager = AcmeManager::new(acme_config).await?;
    tracing::info!("ACME manager initialized");

    Ok(manager)
}

async fn obtain_certs_once(manager: &AcmeManager, config: &config::AcmeConfig) {
    let domains = config.domains.clone().unwrap_or_default();

    for domain in domains {
        match manager.obtain_or_renew_certificate(&domain).await {
            Ok(info) => {
                tracing::info!(
                    "Successfully obtained certificate for {} (expires in {} days)",
                    domain,
                    info.days_remaining
                );
            }
            Err(e) => {
                tracing::error!("Failed to obtain certificate for {}: {}", domain, e);
            }
        }
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

    if let Err(e) = run_proxy(
        routes,
        proxy_config.default_backend.clone(),
        server_config,
        iroh_config,
    )
    .await
    {
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
