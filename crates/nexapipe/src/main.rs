use clap::{Parser, ValueEnum};
use iroh::SecretKey;
use nexapipe::auth::AuthConfig;
use nexapipe::config::{self, IrohConfig, LocalProxyConfig, ProxyConfig, RouteMode, ServerConfig};
use nexapipe::config_watcher::ConfigWatcher;
use nexapipe::proxy::{run_local_proxy, run_proxy};
use nexapipe::routes::{L4Options, Route};
use nexapipe::shutdown::{ShutdownSignal, wait_for_shutdown_signal};
use std::sync::Arc;

/// How the 2FA enrollment QR code is drawn.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum QrFormat {
    /// Half blocks with explicit colors, readable on any terminal theme
    Unicode,
    /// Half blocks without escape sequences, for terminals without colors
    Plain,
    /// Plain ASCII, for logs and text files
    Ascii,
    /// SVG markup, for files and browsers
    Svg,
    /// No QR code, print the otpauth:// URI only
    None,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[arg(long, help = "Run in client local proxy mode")]
    local_proxy: bool,

    #[arg(long, help = "Generate a new secret key for stable endpoint identity")]
    generate_secret: bool,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        help = "Generate a new 2FA secret for a client and print a scannable QR code"
    )]
    generate_2fa: Option<String>,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        help = "Print the QR code of a client already configured in [auth.clients]"
    )]
    show_2fa: Option<String>,

    #[arg(
        long,
        value_name = "NAME",
        help = "Issuer label shown by the authenticator app (default: [auth] issuer)"
    )]
    issuer: Option<String>,

    #[arg(
        long,
        value_enum,
        default_value_t = QrFormat::Unicode,
        help = "How to draw the QR code"
    )]
    qr_format: QrFormat,

    #[arg(long, help = "Draw the QR code light on dark")]
    qr_invert: bool,

    #[arg(
        long,
        value_name = "PATH",
        help = "Also write the QR code to a file (.svg, anything else is ASCII)"
    )]
    qr_out: Option<String>,

    #[arg(
        long,
        value_name = "CLIENT_ID",
        num_args = 0..=1,
        default_missing_value = "",
        help = "Print a scannable nexapipe:// invite for this endpoint; \
                with a CLIENT_ID the matching [auth.clients] 2FA secret goes in too, \
                without one the invite only carries the endpoint and its domains"
    )]
    generate_invite: Option<String>,

    #[arg(
        long = "invite-domains",
        value_delimiter = ',',
        value_name = "DOMAINS",
        help = "Domains to put in the invite (default: [local_proxy] proxy_domains, else the route hosts)"
    )]
    invite_domains: Vec<String>,

    #[arg(
        long = "invite-name",
        value_name = "NAME",
        help = "Human readable label stored alongside the endpoint in the invite"
    )]
    invite_name: Option<String>,

    #[arg(
        long = "invite-relay",
        value_name = "URL",
        help = "Relay URL to put in the invite (default: [iroh] relay_url)"
    )]
    invite_relay: Option<String>,

    #[arg(
        long = "endpoint-id",
        value_name = "NODE_ID",
        help = "Endpoint ID to advertise (default: derived from [iroh] secret_key)"
    )]
    endpoint_id: Option<String>,
}

#[tokio::main]
async fn main() {
    // Install ring as the default CryptoProvider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring as default CryptoProvider");

    let cli = Cli::parse();

    // Handle --generate-secret flag
    if cli.generate_secret {
        let secret_key = SecretKey::generate();
        // Convert to hex string for storage
        let secret_key_hex = hex::encode(secret_key.to_bytes());
        println!("Generated secret key for stable endpoint identity:");
        println!("{}", secret_key_hex);
        println!();
        println!("Add this to your config.toml under [iroh] section:");
        println!("secret_key = \"{}\"", secret_key_hex);
        return;
    }

    // Handle --generate-2fa / --show-2fa
    if cli.generate_2fa.is_some() || cli.show_2fa.is_some() {
        if let Err(e) = print_2fa_enrollment(&cli) {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // Handle --generate-invite
    if cli.generate_invite.is_some() {
        if let Err(e) = print_endpoint_invite(&cli) {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    let proxy_config = match ProxyConfig::from_file(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    let debug_enabled = proxy_config.debug.unwrap_or(false);

    // Console output plus the rotating log files configured in `[log]`.
    nexapipe::log::init(proxy_config.log.as_ref(), debug_enabled);

    // Last chance to notice configuration that TLS termination left behind.
    proxy_config.warn_removed_tls_keys();

    if debug_enabled {
        tracing::info!("Debug mode enabled");
    }

    let shutdown_signal = Arc::new(ShutdownSignal::new());
    let shutdown_signal_clone = shutdown_signal.clone();

    tokio::spawn(async move {
        wait_for_shutdown_signal(shutdown_signal_clone).await;
    });
    tracing::info!("Shutdown signal handler registered");

    if cli.local_proxy {
        run_local_proxy_mode(&proxy_config, &shutdown_signal).await;
    } else {
        run_server_mode(&proxy_config, &cli.config, &shutdown_signal).await;
    }

    tracing::info!("Waiting for graceful shutdown...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    tracing::info!("Proxy shutdown complete");
}

async fn run_server_mode(
    proxy_config: &ProxyConfig,
    config_path: &str,
    shutdown_signal: &Arc<ShutdownSignal>,
) {
    let config_watcher = Arc::new(ConfigWatcher::new(
        config_path.to_string(),
        proxy_config.clone(),
    ));

    tokio::spawn({
        let config_watcher_clone = config_watcher.clone();
        async move {
            if let Err(e) = config_watcher_clone.start_watch().await {
                tracing::error!("Config watcher failed: {}", e);
            }
        }
    });
    tracing::info!("Config watcher started, monitoring: {}", config_path);

    let server_config: Option<ServerConfig> = proxy_config.server.clone();
    let iroh_config: Option<IrohConfig> = proxy_config.iroh.clone();

    let mut routes = Vec::new();

    if let Err(e) = config::validate_backend(
        "default_backend",
        RouteMode::Http,
        &proxy_config.default_backend,
    ) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }

    if let Some(route_configs) = proxy_config.routes.clone() {
        for route_config in route_configs {
            let strategy = config::get_strategy(&route_config.strategy);
            let mode = config::get_route_mode(&route_config.mode);
            let path_is_prefix = route_config.path_is_prefix.unwrap_or(true);
            let backends_count = route_config.backends.len();
            let host_pattern = route_config.host_pattern.clone();
            let path_pattern = route_config.path_pattern.clone();
            let label = format!("route {host_pattern}");

            for backend in &route_config.backends {
                if let Err(e) = config::validate_backend(&label, mode, backend) {
                    tracing::error!("{}", e);
                    std::process::exit(1);
                }
            }

            // Only meaningful for `tcp` / `udp`, where they are harmless defaults
            // otherwise; the other modes never read them.
            let l4_options = L4Options {
                client_ports: route_config.client_ports.clone(),
                idle_timeout: route_config
                    .idle_timeout_secs
                    .map(std::time::Duration::from_secs),
            };
            let client_ports = route_config.client_ports.clone();
            let idle_timeout_secs = route_config.idle_timeout_secs;

            routes.push(
                Route::new(
                    &host_pattern,
                    &path_pattern,
                    path_is_prefix,
                    route_config.backends,
                    strategy,
                    mode,
                    route_config.path_rewrite,
                )
                .with_l4_options(l4_options),
            );

            tracing::info!(
                "Loaded route: host={}, path={} (prefix={}), mode={:?}, backends={}, strategy={:?}",
                host_pattern,
                path_pattern,
                path_is_prefix,
                mode,
                backends_count,
                strategy
            );

            if mode.is_l4() {
                // Worth spelling out: `client_ports` changes which flows match, and a
                // reader who assumed "the port is what gets dialled" would be wrong.
                tracing::info!(
                    "  L4 route {}: client_ports={:?} (absent = every port matches; the port never \
                     decides where the connection goes), idle_timeout_secs={:?}",
                    host_pattern,
                    client_ports,
                    idle_timeout_secs
                );
            }
        }
    }

    tracing::info!("Starting proxy with domain-based and path-based routing");
    tracing::info!("Default backend: {}", proxy_config.default_backend);

    // Load 2FA auth config
    let auth_config = match ProxyConfig::load_with_auth(config_path) {
        Ok((_, auth_cfg)) => {
            if let Some(ref cfg) = auth_cfg {
                tracing::info!(
                    "2FA authentication enabled with {} clients",
                    cfg.clients.len()
                );
            }
            auth_cfg
        }
        Err(e) => {
            tracing::warn!("Failed to load auth config: {}", e);
            None
        }
    };
    if let Err(e) = run_proxy(
        routes,
        proxy_config.default_backend.clone(),
        server_config,
        iroh_config,
        shutdown_signal.clone(),
        auth_config,
    )
    .await
    {
        tracing::error!("Proxy failed: {}", e);
        std::process::exit(1);
    }
}

async fn run_local_proxy_mode(proxy_config: &ProxyConfig, shutdown_signal: &Arc<ShutdownSignal>) {
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

    if let Err(e) = run_local_proxy(config, shutdown_signal.clone()).await {
        tracing::error!("Local proxy failed: {}", e);
        std::process::exit(1);
    }
}

/// Prints everything needed to enroll a client in 2FA: the credentials, the
/// standard `otpauth://` URI and a QR code carrying that URI, which the NexaPipe
/// app and any third party authenticator app can import.
fn print_2fa_enrollment(cli: &Cli) -> anyhow::Result<()> {
    use nexapipe::auth::OtpAuthUri;
    use nexapipe::auth::otpauth::DEFAULT_ISSUER;

    let (auth_config, config_loaded) = load_auth_config(&cli.config);

    let (client_id, secret, generated) = if let Some(client_id) = &cli.generate_2fa {
        (
            client_id.trim().to_string(),
            nexapipe::auth::TotpValidator::generate_secret(),
            true,
        )
    } else if let Some(client_id) = &cli.show_2fa {
        let client_id = client_id.trim().to_string();
        let client = auth_config.clients.get(&client_id).ok_or_else(|| {
            anyhow::anyhow!(
                "client \"{}\" has no [auth.clients.{}] section in {}",
                client_id,
                toml_key(&client_id),
                cli.config
            )
        })?;
        (client_id, client.secret.clone(), false)
    } else {
        anyhow::bail!("no client given");
    };

    // `--issuer` wins, then the configured one, then the built-in default.
    let issuer = match &cli.issuer {
        Some(issuer) => issuer.trim().to_string(),
        None => auth_config.issuer.clone(),
    };
    let issuer = if issuer.is_empty() {
        DEFAULT_ISSUER.to_string()
    } else {
        issuer
    };

    let uri = OtpAuthUri::from_auth_config(&issuer, &client_id, &secret, &auth_config)?;
    let link = uri.to_uri();

    println!();
    println!("2FA enrollment for client \"{}\"", uri.client_id);
    println!(
        "  Secret     {}{}",
        uri.secret,
        if generated {
            "   (newly generated)"
        } else {
            ""
        }
    );
    println!("  Algorithm  {}", uri.algorithm);
    println!(
        "  Code       {} digits, {} second step",
        uri.digits, uri.period
    );
    println!("  Issuer     {}", uri.issuer);
    if !config_loaded {
        println!("             (built-in 2FA defaults)");
    }
    println!();

    // These are settings the app cannot honor, so they are worth shouting about.
    for warning in uri.client_warnings() {
        eprintln!("warning: {warning}");
    }

    println!("otpauth:// URI, for manual entry:");
    println!("  {link}");
    println!();

    render_qr(
        &link,
        cli,
        "Scan this with the NexaPipe app (2FA settings -> scan QR code):",
    )?;

    if generated {
        println!("Add the secret to {} on the server:", cli.config);
        println!("[auth.clients.{}]", toml_key(&uri.client_id));
        println!("secret = \"{}\"", uri.secret);
        println!();
        println!("The 2FA settings are read once at startup, so restart the server to pick");
        println!("up the new client. Scanning the code above only imports the credentials");
        println!("into the app; it does not change anything on the server.");
    } else {
        println!(
            "This secret already comes from {}, so the server needs no change.",
            cli.config
        );
        println!("Scanning the code above imports it into another app or device.");
    }

    Ok(())
}

/// Prints (and, with `--qr-out`, writes) a QR code of `link` in whatever format
/// was asked for.
fn render_qr(link: &str, cli: &Cli, header: &str) -> anyhow::Result<()> {
    if cli.qr_format != QrFormat::None {
        println!("{header}");
        let qr = match cli.qr_format {
            QrFormat::Unicode => nexapipe::qr::render_unicode(link, cli.qr_invert)?,
            QrFormat::Plain => nexapipe::qr::render_plain(link, cli.qr_invert)?,
            QrFormat::Ascii => nexapipe::qr::render_ascii(link, cli.qr_invert)?,
            QrFormat::Svg => nexapipe::qr::render_svg(link, cli.qr_invert)?,
            QrFormat::None => unreachable!("filtered above"),
        };
        print!("{qr}");
        println!();
    }

    if let Some(path) = &cli.qr_out {
        write_qr_file(path, link, cli.qr_invert)?;
    }
    Ok(())
}

/// Prints everything a client needs to reach this endpoint in one scannable
/// `nexapipe://` invite: the endpoint identity, the domains it serves and, when
/// `--client` names one, the 2FA credentials to authenticate with.
///
/// The identity comes from `[iroh] secret_key` when it is set, which is the same
/// key the server starts with, so the printed code stays valid across restarts;
/// without it the endpoint ID would change on every start and the code would be
/// worthless, so the flag is required instead of silently printing a throwaway.
fn print_endpoint_invite(cli: &Cli) -> anyhow::Result<()> {
    use nexapipe_client::auth::TotpAlgorithm;
    use nexapipe_client::provisioning::{
        EndpointInvite, EndpointTarget, InviteTotp, RECOMMENDED_URI_LIMIT,
    };

    let (proxy_config, auth_config, config_loaded) = load_config_pair(&cli.config);

    let target = match &cli.endpoint_id {
        Some(id) => EndpointTarget::node_id_target(id)?,
        None => {
            let secret_key = proxy_config
                .as_ref()
                .and_then(|config| config.iroh.as_ref())
                .and_then(|iroh| iroh.secret_key.as_deref())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no endpoint identity in {}: set [iroh] secret_key \
                         (see `nexapipe --generate-secret`) or pass --endpoint-id",
                        cli.config
                    )
                })?;
            let public: iroh::PublicKey = secret_key
                .parse::<SecretKey>()
                .map_err(|e| {
                    anyhow::anyhow!("[iroh] secret_key in {} is invalid ({e})", cli.config)
                })?
                .public();
            EndpointTarget::node_id_target(&public.to_string())?
        }
    };

    let (domains, domains_source) = invite_domains(&cli.invite_domains, proxy_config.as_ref());
    let relay = cli.invite_relay.clone().or_else(|| {
        proxy_config
            .as_ref()
            .and_then(|config| config.iroh.as_ref())
            .filter(|iroh| !matches!(iroh.relay_mode.as_deref(), Some("disabled")))
            .and_then(|iroh| iroh.relay_url.clone())
    });

    let mut invite = EndpointInvite::new(target, &domains)?
        .with_relay(relay.as_deref())
        .with_name(cli.invite_name.as_deref().unwrap_or_default());

    let mut two_factor_enabled = false;
    // `--generate-invite` without a value is a valid request for an endpoint
    // share with no 2FA in it, so an empty client id skips the lookup instead
    // of looking up a client literally named "".
    if let Some(client_id) = cli
        .generate_invite
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        let client = auth_config.clients.get(client_id).ok_or_else(|| {
            let known = if auth_config.clients.is_empty() {
                " (no client is configured yet)".to_string()
            } else {
                let mut names: Vec<&str> = auth_config.clients.keys().map(String::as_str).collect();
                names.sort_unstable();
                format!(" (configured: {})", names.join(", "))
            };
            anyhow::anyhow!(
                "client \"{}\" has no [auth.clients.{}] section in {}{}",
                client_id,
                toml_key(client_id),
                cli.config,
                known
            )
        })?;

        let issuer = if auth_config.issuer.is_empty() {
            nexapipe::auth::DEFAULT_ISSUER
        } else {
            auth_config.issuer.as_str()
        };
        let totp = InviteTotp::with_params(
            issuer,
            client_id,
            &client.secret,
            TotpAlgorithm::from_name(auth_config.algorithm.name()),
            auth_config.digits,
            auth_config.time_step,
        )?;
        two_factor_enabled = true;
        invite = invite.with_totp(Some(totp));
    }

    let link = invite.to_uri();

    println!();
    println!("Endpoint invitation");
    println!("  Endpoint    {}", invite.target);
    println!(
        "              {}",
        match invite.target {
            EndpointTarget::NodeId(_) => "Node ID, the app resolves the addresses itself",
            EndpointTarget::Ticket(_) => "ticket, the addresses travel with the code",
        }
    );
    if !invite.domains.is_empty() {
        println!("  Domains     {}", invite.domains.join(", "));
        println!("              ({domains_source})");
    }
    if let Some(relay) = &invite.relay {
        println!("  Relay       {relay}");
    }
    if let Some(name) = &invite.name {
        println!("  Label       {name}");
    }
    if let Some(totp) = &invite.totp {
        println!(
            "  2FA         client \"{}\", {}, {} digits, {} second step",
            totp.client_id,
            totp.algorithm.name().to_ascii_uppercase(),
            totp.digits,
            totp.period
        );
    }
    if !config_loaded {
        println!(
            "              ({} was not read, built-in defaults used)",
            cli.config
        );
    }
    println!();

    for warning in invite.client_warnings() {
        eprintln!("warning: {warning}");
    }
    if two_factor_enabled && !auth_config.enabled {
        eprintln!(
            "warning: [auth] enabled is false in {}, so the server will not ask for \
             these credentials even though the invite configures the app to send them",
            cli.config
        );
    }
    if invite.domains.is_empty() {
        eprintln!("warning: the invite carries no domains, pass --invite-domains to route traffic");
    }
    if link.len() > RECOMMENDED_URI_LIMIT {
        eprintln!(
            "warning: the invite is {} characters long; that needs a dense QR code, \
             keep the domain list short",
            link.len()
        );
    }

    println!("Invite URI, to paste into the app:");
    println!("  {link}");
    println!();

    render_qr(
        &link,
        cli,
        "Scan this with the NexaPipe app (add endpoint -> scan):",
    )?;

    if two_factor_enabled {
        println!("Scanning imports the endpoint, the domains and the 2FA credentials in one");
        println!("step. The code carries the TOTP secret in the clear: treat it like a password.");
    } else {
        println!("Scanning imports the endpoint and its domains. Pass a client id to");
        println!("--generate-invite to put that client's 2FA credentials in the code too.");
    }

    Ok(())
}

/// Loads the proxy config and `[auth]` together.
///
/// A config that cannot be read is not fatal: with `--endpoint-id` and
/// `--invite-domains` given on the command line everything the invite needs is
/// already known, so the missing file only costs the 2FA lookup.
fn load_config_pair(path: &str) -> (Option<ProxyConfig>, AuthConfig, bool) {
    match ProxyConfig::load_with_auth(path) {
        Ok((proxy, Some(auth))) => (Some(proxy), auth, true),
        Ok((proxy, None)) => {
            eprintln!("warning: {path} has no [auth] section, the invite carries no 2FA");
            (Some(proxy), AuthConfig::default(), false)
        }
        Err(e) => {
            eprintln!("warning: {path} could not be read ({e}), using built-in 2FA defaults");
            (None, AuthConfig::default(), false)
        }
    }
}

/// Where the domain list comes from, so the printed invite says so.
fn invite_domains(explicit: &[String], config: Option<&ProxyConfig>) -> (Vec<String>, String) {
    if !explicit.is_empty() {
        return (explicit.to_vec(), "from --invite-domains".to_string());
    }

    if let Some(local_proxy) = config.and_then(|config| config.local_proxy.as_ref())
        && !local_proxy.proxy_domains.is_empty()
    {
        return (
            local_proxy.proxy_domains.clone(),
            "from [local_proxy] proxy_domains".to_string(),
        );
    }

    let routed: Vec<String> = config
        .and_then(|config| config.routes.as_ref())
        .map(|routes| {
            routes
                .iter()
                .map(|route| route.host_pattern.trim().to_string())
                .filter(|host| !host.is_empty() && host != "*")
                .collect()
        })
        .unwrap_or_default();

    if !routed.is_empty() {
        (routed, "from the [[routes]] host patterns".to_string())
    } else {
        (Vec::new(), "none configured".to_string())
    }
}

/// Loads `[auth]` for the enrollment output.
///
/// Returns the settings together with whether they came from the file. A missing
/// or unreadable config is not fatal here: `--generate-2fa` has to work before a
/// config file exists, and it only needs the TOTP parameters, not the routes.
fn load_auth_config(path: &str) -> (AuthConfig, bool) {
    match ProxyConfig::load_with_auth(path) {
        Ok((_, Some(auth))) => (auth, true),
        Ok((_, None)) => {
            eprintln!("warning: {path} has no [auth] section, using built-in 2FA defaults");
            (AuthConfig::default(), false)
        }
        Err(e) => {
            eprintln!("warning: {path} could not be read ({e}), using built-in 2FA defaults");
            (AuthConfig::default(), false)
        }
    }
}

/// Writes the QR code to `path`. The extension picks the format: `.svg` is a
/// standalone document, anything else is ASCII text with the URI on top.
fn write_qr_file(path: &str, link: &str, invert: bool) -> anyhow::Result<()> {
    let is_svg = path.to_ascii_lowercase().ends_with(".svg");
    let content = if is_svg {
        nexapipe::qr::render_svg(link, invert)?
    } else {
        format!(
            "# NexaPipe 2FA enrollment\n# {link}\n{}",
            nexapipe::qr::render_ascii(link, invert)?
        )
    };

    std::fs::write(path, content)
        .map_err(|e| anyhow::anyhow!("failed to write the QR code to {path}: {e}"))?;
    println!();
    println!(
        "Wrote the QR code to {path} ({})",
        if is_svg { "SVG" } else { "ASCII" }
    );
    Ok(())
}

/// Quotes a TOML key, as `[auth.clients."client-001"]` requires.
fn toml_key(key: &str) -> String {
    format!("\"{}\"", key.replace('\\', "\\\\").replace('"', "\\\""))
}
