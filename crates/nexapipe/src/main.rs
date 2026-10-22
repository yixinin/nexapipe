use clap::{Parser, Subcommand, ValueEnum};
use iroh::SecretKey;
use nexapipe::auth::AuthConfig;
use nexapipe::config::{
    AdminConfig, ClientSecretWrite, EndpointIdentity, IrohConfig, LocalProxyConfig, ProxyConfig,
    ServerConfig,
};
use nexapipe::proxy::{ProxyOptions, run_local_proxy, run_proxy};
use nexapipe::routes::RoutingTable;
use nexapipe::shutdown::{ShutdownSignal, wait_for_shutdown_signal};
use nexapipe_client::relay::RelayModeSpec;
use nexapipe_proto::secret::SecretString;
use std::sync::Arc;

/// The default config path the binary uses when `--config` is not given.
///
/// Two paths land at the same file: `./config.toml` is what local dev has
/// always used, `./config/config.toml` is what `docker-compose.yaml`'s
/// bind-mount target resolves to inside the container. Rather than pick
/// one and break the other, this function lets the environment decide —
/// the docker-compose sets `NEXAPIPE_CONFIG_DIR=/app/config`, and the
/// binary prepends that to `config.toml`. Local dev that does not set the
/// variable gets the original behaviour.
fn compute_default_config() -> String {
    match std::env::var("NEXAPIPE_CONFIG_DIR") {
        Ok(dir) if !dir.trim().is_empty() => {
            // Trim a trailing slash so the join reads as `<dir>/config.toml`,
            // not `<dir>//config.toml`. A trailing slash is the most common
            // case (compose file style: `- /app/config/`) but other shapes
            // (`- /app/config`, `- /app/config///`) should all land at the
            // same path.
            let trimmed = dir.trim().trim_end_matches('/');
            format!("{trimmed}/config.toml")
        }
        _ => "config.toml".to_string(),
    }
}

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
    // `global` so it can be written before or after a subcommand: `status`
    // needs the config for the listener address, and `nexapipe --config X
    // status` is the spelling an operator who already uses the flag will try
    // first.
    //
    // The default is computed: `NEXAPIPE_CONFIG_DIR` shifts it to that
    // directory's `config.toml` when set, otherwise it stays at `./config.toml`.
    // The docker setup sets `NEXAPIPE_CONFIG_DIR=/app/config` (matching the
    // bind-mount target), so the container picks up `/app/config/config.toml`
    // by default and a local dev that omits `--config` keeps the old behaviour.
    // `--config` always wins, so an operator can still point the binary at any
    // path they like.
    #[arg(short, long, default_value_t = compute_default_config(), global = true)]
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
        help = "With --generate-2fa: issue a new secret even when the client already has \
                one in [auth.clients], and replace it in the config"
    )]
    force: bool,

    #[arg(
        long,
        value_name = "NAME",
        global = true,
        help = "Issuer label shown by the authenticator app (default: [auth] issuer)"
    )]
    issuer: Option<String>,

    #[arg(
        long,
        value_enum,
        default_value_t = QrFormat::Unicode,
        global = true,
        help = "How to draw the QR code"
    )]
    qr_format: QrFormat,

    #[arg(long, global = true, help = "Draw the QR code light on dark")]
    qr_invert: bool,

    #[arg(
        long,
        value_name = "PATH",
        global = true,
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
        long,
        requires = "generate_invite",
        help = "With --generate-invite CLIENT_ID: put a one-time enrollment token in the \
                invite instead of the client's TOTP secret. The first device to scan it \
                trades the token for a freshly generated secret, and the link stops being \
                a credential — the secret in it is never one"
    )]
    registration: bool,

    #[arg(
        long,
        requires = "generate_invite",
        help = "With --generate-invite CLIENT_ID: create the client when it does not exist \
                yet, generating and writing its TOTP secret in the same run. Only a client \
                that is missing entirely is created; an existing one is used as it is"
    )]
    create_client: bool,

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

    #[command(subcommand)]
    command: Option<Commands>,
}

/// The two things this binary does besides run: ask a running instance how it
/// is, and — with the flags above — write credentials into a config.
///
/// A subcommand rather than another flag because it is a different kind of
/// thing: the flags are all "do this to the config and exit", while `status`
/// talks to a process that is already running.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Ask the instance at [admin] listen_addr what it is doing
    Status {
        /// Print the whole answer as one JSON document instead of the grouped
        /// reading, for anything that has to parse it
        #[arg(long)]
        json: bool,
    },

    /// List, add and revoke the 2FA clients in [auth.clients]
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },
}

/// The write half of the management surface.
///
/// Subcommands rather than `POST /v1/clients`: the admin token is one opaque
/// value with no scope and no rotation, and giving it something to change is
/// how a read-only surface becomes the way into the credential store. A
/// subcommand writes the same file the server watches instead, and needs no
/// token — but it does need to be able to write that file, which is the access
/// an operator adding a client already has.
#[derive(Subcommand, Debug)]
enum ClientAction {
    /// List the clients in [auth.clients], and the devices of each
    List {
        /// Print one JSON document instead of the reading below, for anything
        /// that has to parse it
        #[arg(long)]
        json: bool,
    },

    /// Issue a credential to a client, or to one device of it
    Add {
        /// The client id: the key under [auth.clients]
        #[arg(value_name = "CLIENT_ID")]
        client_id: String,

        /// Give this device a secret of its own, leaving the client's alone
        #[arg(long, value_name = "NAME")]
        device: Option<String>,

        /// Issue this device a key instead of a secret: the public half of an
        /// Ed25519 key pair, 64 hex characters. The device proves itself by
        /// signing each challenge — no code for anyone to read — which is what
        /// a device that runs unattended needs; the private half never leaves
        /// the device.
        #[arg(long, value_name = "HEX", requires = "device")]
        public_key: Option<String>,

        /// Replace the credential that is already there, enrolling out whatever
        /// is using it now
        #[arg(long)]
        force: bool,
    },

    /// Drop a client's credentials, or one device's
    Revoke {
        /// The client id: the key under [auth.clients]
        #[arg(value_name = "CLIENT_ID")]
        client_id: String,

        /// Drop only this device's credential, keeping the client and every
        /// other device of it
        #[arg(long, value_name = "NAME")]
        device: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    // Install ring as the default CryptoProvider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring as default CryptoProvider");

    let cli = Cli::parse();

    // `status` is handled before anything that loads the config for a *start*:
    // it is the only command that runs against another process, and it has to
    // work while that process holds the config. It reads the same file, read
    // only, for the address and the token.
    if let Some(Commands::Status { json }) = &cli.command {
        if let Err(e) = nexapipe::status::status(&cli.config, *json).await {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // Handle --generate-secret flag
    if cli.generate_secret {
        // Printing a key is not the same thing as giving the endpoint one: this
        // writes nothing, and a copy-paste is still the operator's job. The
        // startup path generates and persists a key on its own
        // (`ProxyConfig::ensure_iroh_secret_key`); this stays for generating one
        // to move between hosts, or to seed a config before its first run.
        let secret_key_hex = nexapipe::config::generate_secret_key_hex();
        println!("Generated secret key for stable endpoint identity:");
        println!("{}", secret_key_hex);
        println!();
        println!("Add this to your config.toml under [iroh] section:");
        println!("secret_key = \"{}\"", secret_key_hex);
        println!();
        println!("To keep the key out of config.toml instead (so the file holds no");
        println!("credential and can stay world-readable), point [iroh] secret_key_file");
        println!("at a file holding just the key, or set NEXAPIPE_IROH_SECRET_KEY.");
        println!();
        println!("Or skip this entirely: nexapipe writes [iroh] secret_key on first start");
        println!("when the key is missing.");
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

    // `client` reads and writes the config file, which is the other half of the
    // management surface. It is handled here rather than after the config load
    // below because it does not start a proxy: a `revoke` has to work while one
    // is running, and it takes the same lock the server does.
    if let Some(Commands::Client { action }) = &cli.command {
        let outcome = match action {
            ClientAction::List { json } => list_clients(&cli, *json),
            ClientAction::Add {
                client_id,
                device,
                public_key,
                force,
            } => add_client(
                &cli,
                client_id,
                device.as_deref(),
                public_key.as_deref(),
                *force,
            ),
            ClientAction::Revoke { client_id, device } => {
                revoke_client(&cli, client_id, device.as_deref())
            }
        };
        if let Err(e) = outcome {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // A first start with no config file gets a minimal one written for it,
    // rather than a refusal to start with nothing to act on. Server mode only:
    // `--local-proxy` reads the same path as a *client* config, and the file
    // written here describes a server, so handing it to the client half would
    // be worse than the error it replaces.
    //
    // The "did we just write it?" flag is captured here and the advisory is
    // emitted after `log::init` below — server-mode startup routes advisory
    // output through the log channel rather than raw stdout, and the tracing
    // subscriber is not installed yet at this point.
    let config_just_generated = if !cli.local_proxy {
        match nexapipe::config::ensure_config_file(&cli.config) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                eprintln!("Failed to create {}: {:#}", cli.config, e);
                std::process::exit(1);
            }
        }
    } else {
        false
    };

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

    // The endpoint's identity, generated and written back to `config.toml` if it
    // has none. Before `log::init` would mean a warning nobody sees; after the
    // credential warning would mean writing a credential into a file that
    // warning is about to name. Here it sits in both gaps' place: logged, and
    // before anything reads the file's mode.
    //
    // Local-proxy mode is skipped: it is the client half, and the endpoint it
    // dials is somebody else's identity.
    let identity = if cli.local_proxy {
        None
    } else {
        match ProxyConfig::ensure_iroh_secret_key(&cli.config, &proxy_config) {
            Ok(identity) => Some(identity),
            Err(e) => {
                tracing::error!("{}", e);
                std::process::exit(1);
            }
        }
    };

    if debug_enabled {
        tracing::info!("Debug mode enabled");
    }

    if config_just_generated {
        // Server-mode advisories go through the log channel, not raw stdout:
        // a banner is reserved for output that carries data the operator needs
        // to act on (Node ID / ticket / invite / QR). This is just "what I
        // did and what you should do next", which is what the log is for.
        tracing::info!(
            "No config at {} — wrote a minimal one: [auth] enabled = true with 0 \
             clients enrolled (nothing can connect), no [[routes]] entry (every \
             host is answered 404). Enroll the first client with: \
             nexapipe --generate-invite client-001 --create-client --config {}",
            cli.config,
            cli.config,
        );
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
        run_server_mode(
            &proxy_config,
            &cli.config,
            identity.as_ref(),
            &shutdown_signal,
        )
        .await;
    }

    // The server mode has already drained its connections by the time it
    // returns, so there is nothing left to wait for here.
    tracing::info!("Proxy shutdown complete");
}

async fn run_server_mode(
    proxy_config: &ProxyConfig,
    config_path: &str,
    identity: Option<&EndpointIdentity>,
    shutdown_signal: &Arc<ShutdownSignal>,
) {
    let server_config: Option<ServerConfig> = proxy_config.server.clone();
    let mut iroh_config: Option<IrohConfig> = proxy_config.iroh.clone();
    let admin_config: Option<AdminConfig> = proxy_config.admin.clone();
    let metrics_config = proxy_config.metrics;

    // The resolved identity overrides whatever `[iroh] secret_key` the config
    // holds, because it is that key or the one written in its place.
    //
    // On the *endpoint's* copy only. `proxy_config` stays as it was loaded,
    // because `holds_credentials()` is asked about the file on disk further
    // down and an ephemeral identity was never written there — folding it in
    // would warn about a key that is not in the file, which is the one case an
    // ephemeral identity exists for.
    if let Some(identity) = identity {
        iroh_config.get_or_insert_with(Default::default).secret_key =
            Some(SecretString::new(identity.key().to_string()));
    }

    // Same builder the config watcher calls on a reload: a route that works
    // after a restart must work without one too. A bad config is fatal here,
    // where nothing is serving yet — on a reload it only keeps the old routes.
    let routes = match proxy_config.build_routes() {
        Ok(routes) => routes,
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };

    // The `[timeouts]` values ride along here rather than being read where they
    // are used: they were validated above, and being handed to the table is what
    // keeps every handler agreeing on one value for "too long to wait".
    let route_config = Arc::new(RoutingTable::with_settings(
        routes,
        proxy_config.timeouts(),
        proxy_config.retry(),
    ));

    tracing::info!("Starting proxy with domain-based and path-based routing");

    // Load 2FA auth config
    let auth_config = match ProxyConfig::load_with_auth(config_path) {
        Ok((_, auth_cfg)) => {
            if let Some(ref cfg) = auth_cfg {
                if cfg.enabled {
                    tracing::info!(
                        "2FA authentication enabled with {} clients",
                        cfg.clients.len()
                    );
                } else {
                    tracing::warn!("[auth] is configured but disabled, connections are not gated");
                }
            }
            auth_cfg
        }
        // Fatal, unlike the same error on a reload: by now the file has been
        // read and the routes have been built, so the only thing left that can
        // fail is `[auth]` itself — a misspelled key, an unknown one, an empty
        // enrollment token. Degrading to "no 2FA" was the bug this whole
        // section exists to close: `enable = true` used to be exactly as
        // silent as a typo, and the only difference was one line of log.
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };

    // The config file's own permission is not a gate (ROADMAP §3.5), but a
    // credential in a file anybody can read is worth saying out loud once.
    //
    // Called whether or not the file has an `[auth]` section: the `[iroh]`
    // half is a credential on its own, and `config.toml.example` — like the
    // generated first-run template — has no `[auth]` at all.
    nexapipe::config::warn_about_readable_credentials(
        std::path::Path::new(config_path),
        proxy_config,
        auth_config.as_ref(),
    );

    // The `[peers]` allow-list. A malformed entry is fatal rather than dropped:
    // a list whose whole purpose is to refuse strangers must not silently come
    // out shorter than it was written.
    let peer_allow_list = match proxy_config
        .peers
        .as_ref()
        .map(nexapipe::config::PeersConfig::parse_allow_list)
        .transpose()
    {
        Ok(list) => list
            .flatten()
            .map(|allowed| nexapipe::conn::allow_list::PeerAllowList::new(Some(allowed))),
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = run_proxy(
        route_config,
        config_path,
        shutdown_signal.clone(),
        ProxyOptions {
            server: server_config,
            iroh: iroh_config,
            auth: auth_config,
            peers: peer_allow_list,
            health_check: proxy_config.health_check.clone(),
            admin: admin_config,
            metrics: metrics_config,
            backends: proxy_config.backends.clone(),
            limits: proxy_config.limits,
        },
    )
    .await
    {
        // The alternate form prints the whole chain, so the cause reaches the
        // log and not only the outermost context — an operator who wrote
        // `discovery = "off"` has to see which value was wrong, not just that
        // something about the iroh configuration was.
        tracing::error!("Proxy failed: {e:#}");
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

    // The QR code has to carry the secret the server will accept, so a client
    // that is already configured keeps the one it has: running --generate-2fa
    // twice must not hand out a second secret and silently lock the app out.
    let (client_id, secret, generated) = if let Some(client_id) = &cli.generate_2fa {
        let client_id = client_id.trim().to_string();
        match auth_config.clients.get(&client_id) {
            Some(client) if !cli.force => (client_id, client.secret.clone(), false),
            _ => (
                client_id,
                SecretString::new(nexapipe::auth::TotpValidator::generate_secret()),
                true,
            ),
        }
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

    let uri =
        OtpAuthUri::from_auth_config(&issuer, &client_id, secret.expose_secret(), &auth_config)?;
    let link = uri.to_uri();

    println!();
    println!("2FA enrollment for client \"{}\"", uri.client_id);
    // The secret belongs on this terminal: the command exists to hand the
    // operator a credential, and the two lines after it are the `otpauth://`
    // URI and the QR code, which carry the same secret by design. Nothing else
    // prints it, and this is the one place it is meant to be seen.
    // codeql[rust/cleartext-logging]
    // CodeQL does not honour inline suppressions in Rust yet (github/codeql#21637),
    // so this marker records the intent and starts suppressing on its own once
    // that support lands. Until then the alert is dismissed by hand.
    println!(
        "  Secret     {}{}",
        uri.secret.expose_secret(),
        if generated {
            "   (newly generated)"
        } else if cli.generate_2fa.is_some() {
            // Kept from the config: see the branch above.
            "   (already in the config)"
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
        save_generated_secret(
            cli,
            &client_id,
            uri.secret.expose_secret(),
            auth_config.enabled,
        );
    } else if cli.generate_2fa.is_some() {
        println!(
            "Client \"{}\" already has a secret in {}, so that is the one above:",
            uri.client_id, cli.config
        );
        println!("issuing a new one would enroll the app with credentials the server");
        println!("rejects. Pass --force to rotate it instead — the secret in the config");
        println!("is then replaced, and every device enrolled with the old one has to");
        println!("scan again.");
    } else {
        println!(
            "This secret already comes from {}, so the server needs no change.",
            cli.config
        );
        println!("Scanning the code above imports it into another app or device.");
    }

    Ok(())
}

/// Puts a freshly generated secret into the config file, so the server ends up
/// holding the same credentials the QR code carries and nothing has to be copied
/// by hand.
///
/// Failing is not fatal: the secret is on screen either way, the file may not
/// exist yet or may not be writable, and the snippet can still be typed in.
fn save_generated_secret(cli: &Cli, client_id: &str, secret: &str, auth_enabled: bool) {
    let outcome = ProxyConfig::write_client_secret(&cli.config, client_id, secret, cli.force);
    let written = match outcome {
        Ok(ClientSecretWrite::Added) => {
            println!(
                "Wrote the secret to {} as [auth.clients.{}].",
                cli.config,
                toml_key(client_id)
            );
            true
        }
        Ok(ClientSecretWrite::Replaced) => {
            println!(
                "Replaced the secret of [auth.clients.{}] in {}: every device enrolled",
                toml_key(client_id),
                cli.config
            );
            println!("with the old one has to scan again.");
            true
        }
        Err(e) => {
            // Not fatal, but loud: without the file the server never sees it.
            eprintln!("warning: {e:#}, so add it by hand:");
            println!("[auth.clients.{}]", toml_key(client_id));
            println!("secret = \"{}\"", secret);
            false
        }
    };
    println!();

    // Only worth saying when there is a file to edit: a config that could not be
    // written has no `[auth]` to enable either.
    if written && !auth_enabled {
        eprintln!(
            "warning: [auth] enabled is not true in {}, so the server will not ask for this \
             secret; add enabled = true under [auth]",
            cli.config
        );
    }
    println!("The 2FA settings are read once at startup, so restart the server to pick");
    println!("up the new client. Scanning the code above only imports the credentials");
    println!("into the app; it does not change anything on the server.");
}

/// `[auth]` as the server reads it, or `None` when the file has no `[auth]`
/// section.
///
/// Not `load_auth_config`, which falls back to built-in defaults and prints a
/// warning: that is right for enrollment, which has to work before a config file
/// exists, and wrong here. `list` and `revoke` are about the file as it stands,
/// and reporting defaults for a file that could not be read would describe a
/// client table that may not be the one on disk.
fn load_auth_or_none(path: &str) -> anyhow::Result<Option<AuthConfig>> {
    let (_, auth) =
        ProxyConfig::load_with_auth(path).map_err(|e| anyhow::anyhow!("{path}: {e:#}"))?;
    Ok(auth)
}

/// A unix timestamp as it reads where the operator is, or `-`.
///
/// Zero is not 1970 here: the counter writeback writes `last_used = 0` for a
/// client that has never authenticated, and `0` as `created_at` is the value an
/// entry carries when the file was written by hand. Both mean "never"/"unknown",
/// and a wall of 1970 dates would say the opposite.
///
/// (The state file no longer writes a zero counter at all — it leaves the key
/// out — but a `created_at` of `0` is still what a hand-written entry
/// carries.)
fn stamp(seconds: Option<i64>) -> String {
    let Some(seconds) = seconds.filter(|at| *at > 0) else {
        return "-".to_string();
    };
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|at| {
            at.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "-".to_string())
}

/// `created_at` is carried as a string, and one written by hand may be anything.
fn seconds_of(value: &str) -> Option<i64> {
    value.trim().parse().ok()
}

/// Prints the clients in `[auth.clients]`, and under each the devices that have
/// a credential of their own.
///
/// No secret is printed, in either form. This is the command that gets run to
/// see what is configured, and a terminal's scrollback, a paste into a ticket
/// and a screenshot are all places a secret printed once ends up living;
/// `--show-2fa` draws the code for one client for the one time it is needed.
fn list_clients(cli: &Cli, json: bool) -> anyhow::Result<()> {
    let Some(auth) = load_auth_or_none(&cli.config)? else {
        if json {
            println!("[]");
        } else {
            println!("{} has no [auth] section, so no clients", cli.config);
        }
        return Ok(());
    };

    let mut ids: Vec<&String> = auth.clients.keys().collect();
    ids.sort();

    if json {
        let clients: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| {
                let client = &auth.clients[*id];
                let mut devices: Vec<serde_json::Value> = client
                    .devices
                    .iter()
                    .map(|(name, device)| {
                        serde_json::json!({
                            "name": name,
                            "created_at": seconds_of(&device.created_at),
                            "last_used": device.last_used,
                            "key": device.public_key.is_some(),
                        })
                    })
                    .collect();
                devices.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
                serde_json::json!({
                    "id": id,
                    "has_secret": !client.secret.expose_secret().is_empty(),
                    "created_at": seconds_of(&client.created_at),
                    "last_used": client.last_used,
                    "allow_hosts": client.allow_hosts,
                    "allow_ports": client.allow_ports,
                    "invite_outstanding": client.pending_enrollment.is_some(),
                    "failed_attempts": client.failed_attempts,
                    "locked_out": client.is_locked_out(),
                    "devices": devices,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&clients)?);
        return Ok(());
    }

    println!(
        "{} {} in {} ([auth] enabled = {})",
        ids.len(),
        if ids.len() == 1 { "client" } else { "clients" },
        cli.config,
        auth.enabled
    );
    if ids.is_empty() {
        return Ok(());
    }
    println!();

    for id in &ids {
        let client = &auth.clients[*id];
        println!("  {id}");
        println!(
            "    secret      {}",
            if client.secret.expose_secret().is_empty() {
                "missing"
            } else {
                "set"
            }
        );
        println!("    created     {}", stamp(seconds_of(&client.created_at)));
        println!(
            "    last used   {}",
            stamp(client.last_used.map(|at| at as i64))
        );
        // Printed whenever the key is there, empty list included: an empty
        // list is the strictest setting there is, and a line that only shows
        // up for a non-empty list hides it exactly where it matters.
        if let Some(hosts) = &client.allow_hosts {
            let hosts = if hosts.is_empty() {
                "none, every host is denied".to_string()
            } else {
                hosts.join(", ")
            };
            println!("    allow hosts {hosts}");
        }
        // Printed whenever the key is there, empty list included: an empty
        // list is the strictest setting there is, and a line that only shows
        // up for a non-empty list hides it exactly where it matters.
        if let Some(ports) = &client.allow_ports {
            let ports = if ports.is_empty() {
                "none, every port is denied".to_string()
            } else {
                ports
                    .iter()
                    .map(|port| port.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!("    allow ports {ports}");
        }
        if client.pending_enrollment.is_some() {
            println!("    invite      outstanding");
        }
        if client.failed_attempts > 0 {
            println!(
                "    attempts    {} failed since the last success",
                client.failed_attempts
            );
        }
        if client.is_locked_out() {
            println!(
                "    lockout     until {}",
                stamp(client.locked_until.map(|at| at as i64))
            );
        }

        let mut devices: Vec<_> = client.devices.iter().collect();
        devices.sort_by(|a, b| a.0.cmp(b.0));
        if devices.is_empty() {
            println!("    devices     none");
        } else {
            println!("    devices     {}", devices.len());
            let width = devices
                .iter()
                .map(|(name, _)| name.len())
                .max()
                .unwrap_or(0)
                .max(8);
            for (name, device) in devices {
                let mut line = format!("created {}", stamp(seconds_of(&device.created_at)));
                if let Some(used) = device.last_used {
                    line.push_str(&format!(", last used {}", stamp(Some(used as i64))));
                }
                if device.public_key.is_some() {
                    line.push_str(", key");
                }
                println!("      {name:width$}  {line}");
            }
        }
    }

    println!();
    println!(
        "No secret is printed here: `nexapipe --show-2fa <CLIENT_ID>` draws the code for one."
    );
    Ok(())
}

/// Issues a credential and writes it into the config, for a client or for one
/// device of it.
///
/// The two differ in what they rotate, and that is the whole reason the device
/// table exists: `client add <id>` rewrites the client's own `secret`, which is
/// the credential of the device that names none — every device that enrolled
/// before the table existed — while `client add <id> --device <name>` writes a
/// credential of its own under that device and leaves the client's alone, so the
/// other devices keep working.
///
/// `--device <name> --public-key <hex>` is the third case: the device is issued
/// a key instead of a secret, so the ordinary path — generate a secret, draw it
/// as a QR code — is skipped whole. Nothing is generated, because the private
/// half is already on the device; what is written is the public half the
/// operator pasted.
fn add_client(
    cli: &Cli,
    client_id: &str,
    device: Option<&str>,
    public_key: Option<&str>,
    force: bool,
) -> anyhow::Result<()> {
    use nexapipe::auth::OtpAuthUri;
    use nexapipe::auth::otpauth::DEFAULT_ISSUER;

    let client_id = client_id.trim();
    // Both ids are checked before anything is written, for the reason the
    // handshake checks them: either one becomes a key in this file, is sent by a
    // device, and is the subject of every log line about it. An id the server
    // would refuse on the wire is no use in the config either.
    if !nexapipe::auth::is_presentable_client_id(client_id) {
        anyhow::bail!(
            "client id {client_id:?} is printable ASCII of at most {} characters and not empty — \
             it is the key under [auth.clients], the name a device sends in its handshake, and \
             the subject of every log line about it",
            nexapipe::auth::MAX_CLIENT_ID_LEN
        );
    }
    if let Some(device) = device
        && !nexapipe::auth::is_presentable_device_id(device)
    {
        anyhow::bail!(
            "device name {device:?} is printable ASCII of at most {} characters and not empty — \
             it is a key under [auth.clients.{}.devices] and the subject of every log line about \
             it",
            nexapipe::auth::MAX_DEVICE_ID_LEN,
            toml_key(client_id)
        );
    }

    let (auth_config, config_loaded) = load_auth_config(&cli.config);

    // A device cannot be the first thing a client gets: a device table under a
    // client with no secret of its own is a config that will not load, and
    // saying so here beats writing a file that cannot be read back.
    let client = auth_config.clients.get(client_id);
    if device.is_some() && client.is_none() {
        anyhow::bail!(
            "client \"{client_id}\" has no [auth.clients.{}] secret in {}; add the client first \
             with `nexapipe client add {client_id}`",
            toml_key(client_id),
            cli.config
        );
    }
    let already = match device {
        Some(name) => client.is_some_and(|client| client.devices.contains_key(name)),
        None => client.is_some(),
    };
    if already && !force {
        match device {
            Some(name) => anyhow::bail!(
                "device \"{name}\" of client \"{client_id}\" already has a credential in {}; \
                 pass --force to issue it another one, which enrolls the device using the \
                 current one out",
                cli.config
            ),
            None => anyhow::bail!(
                "client \"{client_id}\" already has a secret in {}; pass --force to rotate it, \
                 which enrolls out every device using it",
                cli.config
            ),
        }
    }

    // The key path ends here: there is no secret to draw and nothing to scan,
    // because the private half is already where it belongs. What the QR code
    // normally does — getting the credential onto the device — has been done
    // by whoever generated the pair; all that is missing is the public half
    // recorded on this side.
    if let Some(offered) = public_key {
        // `requires = "device"` on the flag already refuses this spelling;
        // the check stays because this function is where the invariant lives,
        // and a key belongs to one named device — the unnamed slot is the
        // client's shared secret, which has no key to be half of.
        let Some(name) = device else {
            anyhow::bail!("--public-key needs --device: a key is issued to one named device");
        };
        let key = nexapipe::auth::parse_public_key(offered)
            .map_err(|why| anyhow::anyhow!("--public-key: {why}"))?;
        let key = nexapipe::auth::public_key_hex(&key);

        println!();
        println!("Key for device \"{name}\" of client \"{client_id}\"");
        println!("  Public key {key}");
        println!();
        println!(
            "The device proves itself by signing each challenge with the private half of this \
             key: no code for anyone to read and nothing to scan, which is what lets it run \
             unattended. The private half stays on the device; this command never sees it."
        );
        println!();

        return write_issued_credential(
            cli,
            client_id,
            Some(name),
            nexapipe::auth::DeviceMaterial::PublicKey(&key),
            auth_config.enabled,
            force,
        );
    }

    let issuer = match &cli.issuer {
        Some(issuer) => issuer.trim().to_string(),
        None => auth_config.issuer.clone(),
    };
    let issuer = if issuer.is_empty() {
        DEFAULT_ISSUER.to_string()
    } else {
        issuer
    };

    let secret = nexapipe::auth::TotpValidator::generate_secret();
    // The label is the client id even for a device: that is what the app takes
    // from the URI and sends as the client id, so a label carrying the device
    // name would authenticate as a client nobody configured. The device names
    // itself in the handshake, where the server can tell the two apart.
    let uri = OtpAuthUri::from_auth_config(&issuer, client_id, &secret, &auth_config)?;
    let link = uri.to_uri();

    println!();
    match device {
        Some(name) => println!(
            "Credential for device \"{name}\" of client \"{}\"",
            uri.client_id
        ),
        None => println!("Credential for client \"{}\"", uri.client_id),
    }
    // The secret belongs on this terminal, for the same reason as in the
    // `--generate-2fa` path above: the operator asked for this credential and
    // the next step is typing it into an authenticator app.
    // codeql[rust/cleartext-logging]
    // Rust does not honour inline suppressions yet (github/codeql#21637); see
    // the `--generate-2fa` path above for the full explanation.
    println!("  Secret     {}", uri.secret.expose_secret());
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
    println!();

    write_issued_credential(
        cli,
        client_id,
        device,
        nexapipe::auth::DeviceMaterial::Secret(uri.secret.expose_secret()),
        auth_config.enabled,
        force,
    )
}

/// Puts the credential that was just printed into the config, so the server
/// ends up holding the same thing the device carries: the secret the QR code
/// spelled out, or the public half the operator pasted.
///
/// `force` is passed through rather than assumed: whether the credential is
/// already there is decided under the config lock by the writer, which is the
/// only place that can answer it without racing a second writer.
fn write_issued_credential(
    cli: &Cli,
    client_id: &str,
    device: Option<&str>,
    material: nexapipe::auth::DeviceMaterial<'_>,
    auth_enabled: bool,
    force: bool,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    // Spelled the way the file is written: a device goes under the client's
    // `devices` table as an inline entry rather than as a section of its own,
    // because that table may be one an operator wrote inline.
    let (section, entry, noun, outcome) = match (device, material) {
        (None, nexapipe::auth::DeviceMaterial::Secret(secret)) => {
            let section = format!("[auth.clients.{}]", toml_key(client_id));
            (
                section.clone(),
                format!("secret = \"{secret}\""),
                "secret",
                ProxyConfig::write_client_secret(&cli.config, client_id, secret, force),
            )
        }
        (Some(name), nexapipe::auth::DeviceMaterial::Secret(secret)) => (
            format!("[auth.clients.{}.devices]", toml_key(client_id)),
            format!("{} = {{ secret = \"{secret}\" }}", toml_key(name)),
            "secret",
            ProxyConfig::write_device_credential(&cli.config, client_id, name, material, force),
        ),
        (Some(name), nexapipe::auth::DeviceMaterial::PublicKey(key)) => (
            format!("[auth.clients.{}.devices]", toml_key(client_id)),
            format!("{} = {{ public_key = \"{key}\" }}", toml_key(name)),
            "public key",
            ProxyConfig::write_device_credential(&cli.config, client_id, name, material, force),
        ),
        // A key is one device's, and the unnamed slot — the client's own
        // `secret` — is a string a key cannot live in. The CLI refuses this
        // spelling twice before it gets here; the arm keeps the writer from
        // being the one place that would write such a key nowhere.
        (None, nexapipe::auth::DeviceMaterial::PublicKey(_)) => {
            anyhow::bail!("a public key is issued to a named device; pass --device with it")
        }
    };
    let what = match device {
        None => section.clone(),
        Some(name) => format!("\"{name}\" under {section}"),
    };

    let written = match outcome {
        Ok(ClientSecretWrite::Added) => {
            println!("Wrote the {noun} to {} as {}.", cli.config, what);
            false
        }
        Ok(ClientSecretWrite::Replaced) => {
            println!("Replaced the {noun} of {} in {}.", what, cli.config);
            true
        }
        // Fatal rather than a warning. The credential is on screen either way,
        // so nothing is lost by stopping — but a command that exits 0 after
        // writing nothing lets `client add acme && deploy` go ahead with no
        // credential on disk, and the next thing that fails is a handshake
        // somewhere else, pointing at the client rather than at this write.
        // The snippet goes with the error for the reason it used to be printed
        // on its own: the operator can still put it in the file by hand.
        Err(e) => {
            return Err(e).context(format!(
                "the {noun} was not written to {}; add it by hand:\n\
                 {section}\n\
                 {entry}",
                cli.config
            ));
        }
    };
    println!();

    if !auth_enabled {
        eprintln!(
            "warning: [auth] enabled is not true in {}, so the server will not ask for this \
             credential; add enabled = true under [auth]",
            cli.config
        );
    }
    println!(
        "The config is watched, so a running server picks this up without a restart. \
         What changed is the file, not the server: nothing is revoked by issuing a credential."
    );
    match (device, written) {
        (Some(_), _) => println!(
            "Only this device's credential changed. The client's own secret is untouched, so \
             every other device of it keeps working."
        ),
        (None, true) => println!(
            "The client's own secret is the credential of the device that names none, so every \
             device using it has to scan again."
        ),
        (None, false) => println!(
            "Nothing was using it yet: scan the code above on the device that should carry \
             this client."
        ),
    }
    Ok(())
}

/// Drops a client, or one device of it, from `[auth.clients]`.
///
/// A revoke deletes rather than rewriting, because a missing entry is what the
/// handshake reads as "this device has no credential" — the same answer a device
/// that never enrolled gets, so what happened to it cannot be told from outside.
///
/// The `[auth]` section is read best-effort and only for the counts the message
/// prints: the removal itself edits the TOML directly and needs no typed auth,
/// so a config that no longer parses — an `allow_hosts` that is not a list, say
/// — must still be revocable. Refusing it would leave the one operator remedy
/// for a bad hand edit behind the very edit that broke it.
fn revoke_client(cli: &Cli, client_id: &str, device: Option<&str>) -> anyhow::Result<()> {
    let client_id = client_id.trim();
    // The checks `add` makes, for the same reason it makes them: either id
    // arrives on a command line and becomes a key in this file, and an id
    // carrying a newline or an ANSI escape splits the terminal output it is
    // printed into. A revoke is also the one command here that cannot be
    // undone by running it again, so refusing a mistyped id before anything is
    // read is cheaper than reading it first.
    if !nexapipe::auth::is_presentable_client_id(client_id) {
        anyhow::bail!(
            "client id {client_id:?} is printable ASCII of at most {} characters and not empty — \
             it is the key under [auth.clients], the name a device sends in its handshake, and \
             the subject of every log line about it",
            nexapipe::auth::MAX_CLIENT_ID_LEN
        );
    }
    if let Some(device) = device
        && !nexapipe::auth::is_presentable_device_id(device)
    {
        anyhow::bail!(
            "device name {device:?} is printable ASCII of at most {} characters and not empty — \
             it is a key under [auth.clients.{}.devices] and the subject of every log line about \
             it",
            nexapipe::auth::MAX_DEVICE_ID_LEN,
            toml_key(client_id)
        );
    }
    // Counts are for the message only; a config that fails to load must still be revocable.
    let auth = load_auth_or_none(&cli.config).ok().flatten();
    let client = auth.as_ref().and_then(|auth| auth.clients.get(client_id));

    match device {
        Some(name) => {
            let others = client.map(|client| client.devices.len()).unwrap_or(0);
            ProxyConfig::remove_device(&cli.config, client_id, name)?;
            println!(
                "Removed [auth.clients.{}.devices.{}] from {}.",
                toml_key(client_id),
                toml_key(name),
                cli.config
            );
            match others {
                // The shared secret is the credential of the peer that names no
                // device, so whether it still authenticates anyone is exactly
                // what `unnamed_device_allowed` decides.
                0 | 1 => match client {
                    Some(client) if !client.unnamed_device_allowed => println!(
                        "The client's own secret is untouched, but unnamed_device_allowed = false \
                         refuses a peer that names no device, so that secret authenticates no one."
                    ),
                    // `None` means the config could not be loaded: the counts
                    // above are best-effort in that case, so the advice stays
                    // the conservative one.
                    _ => {
                        println!(
                            "The client's own secret is untouched: that is the credential of the \
                             device that names none, so one can still authenticate as this client."
                        );
                        println!(
                            "Set unnamed_device_allowed = false under [auth.clients.{}] to take \
                             that credential away as well.",
                            toml_key(client_id)
                        );
                    }
                },
                2 => println!("1 other device of it keeps its credential."),
                left => println!("{} other devices of it keep their credentials.", left - 1),
            }
        }
        None => {
            let devices = client.map(|client| client.devices.len()).unwrap_or(0);
            ProxyConfig::remove_client(&cli.config, client_id)?;
            println!(
                "Removed [auth.clients.{}] from {}.",
                toml_key(client_id),
                cli.config
            );
            match devices {
                0 => {}
                1 => println!(
                    "Its 1 device credential went with it — a device entry under a client that \
                     is gone is one nobody can revoke, because there is no client left to list \
                     it under."
                ),
                many => println!(
                    "Its {many} device credentials went with it — a device entry under a client \
                     that is gone is one nobody can revoke, because there is no client left to \
                     list it under."
                ),
            }
        }
    }

    println!();
    println!("The config is watched, so a running server stops accepting it on the next reload —");
    println!("and closes the connections already authenticated as it, rather than leaving them");
    println!("to finish what they were doing.");
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
        EndpointInvite, EndpointTarget, InviteEnrollment, InviteTotp, RECOMMENDED_URI_LIMIT,
    };

    let (proxy_config, auth_config, config_loaded) = load_config_pair(&cli.config);

    let target = match &cli.endpoint_id {
        Some(id) => EndpointTarget::node_id_target(id)?,
        None => {
            let secret_key = proxy_config
                .as_ref()
                .and_then(|config| config.iroh.as_ref())
                .and_then(|iroh| {
                    iroh.secret_key
                        .as_ref()
                        .map(|key| key.expose_secret().as_str())
                })
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
    // Only a relay this endpoint is actually pinned to is worth advertising: with `default`
    // the home relay is chosen at runtime and can move, and with `disabled` there is none.
    // Read off the resolved spec rather than the raw strings, so a `"custom"` that is really
    // unusable (no URL, n0-operated URL) does not end up in the invite.
    let relay = cli.invite_relay.clone().or_else(|| {
        let iroh = proxy_config
            .as_ref()
            .and_then(|config| config.iroh.as_ref())?;
        let spec = RelayModeSpec::parse(
            iroh.relay_mode.as_deref(),
            iroh.relay_url.as_deref(),
            iroh.relay_auth_token
                .as_ref()
                .map(|token| token.expose_secret().as_str()),
        )
        .ok()
        .flatten()?;
        match spec {
            RelayModeSpec::Custom { .. } => iroh.relay_url.clone(),
            _ => None,
        }
    });

    let mut invite = EndpointInvite::new(target, &domains)?
        .with_relay(relay.as_deref())
        .with_name(cli.invite_name.as_deref().unwrap_or_default());

    let mut two_factor_enabled = false;
    // Kept past the block below: the banner has to name the client whose
    // credential it is handing out.
    let mut enrolled_client: Option<String> = None;
    // `--generate-invite` without a value is a valid request for an endpoint
    // share with no 2FA in it, so an empty client id skips the lookup instead
    // of looking up a client literally named "".
    if let Some(client_id) = cli
        .generate_invite
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        // The secret this invite will carry: the one already in the config, or
        // one created on the spot by `--create-client`. Held as a `String`
        // rather than borrowed from `auth_config` because the creation branch
        // below has no client to borrow from yet.
        let secret = match auth_config.clients.get(client_id) {
            Some(client) => client.secret.clone(),
            None if cli.create_client => {
                SecretString::new(create_client_for_invite(cli, client_id, &auth_config)?)
            }
            None => {
                let known = if auth_config.clients.is_empty() {
                    " (no client is configured yet)".to_string()
                } else {
                    let mut names: Vec<&str> =
                        auth_config.clients.keys().map(String::as_str).collect();
                    names.sort_unstable();
                    format!(" (configured: {})", names.join(", "))
                };
                anyhow::bail!(
                    "client \"{}\" has no [auth.clients.{}] section in {}{}; \
                     pass --create-client to make one now, or run --generate-2fa {} first",
                    client_id,
                    toml_key(client_id),
                    cli.config,
                    known,
                    client_id
                )
            }
        };

        if cli.registration {
            // An enrollment invite has to be written down before it is printed:
            // the token is only worth anything if the server knows to accept it,
            // and generating a second one is how a link that went astray is
            // revoked — the old token is replaced, not added to.
            let token = nexapipe::auth::generate_enrollment_token();
            ProxyConfig::write_pending_enrollment(&cli.config, client_id, &token).map_err(|e| {
                anyhow::anyhow!(
                    "could not record the enrollment token in {} ({e}); without it the \
                     invite would be refused on first connect",
                    cli.config
                )
            })?;
            let enrollment = InviteEnrollment::new(client_id, &token)?;
            enrolled_client = Some(client_id.to_string());
            invite = invite.with_enrollment(Some(enrollment));
        } else {
            let issuer = if auth_config.issuer.is_empty() {
                nexapipe::auth::DEFAULT_ISSUER
            } else {
                auth_config.issuer.as_str()
            };
            let totp = InviteTotp::with_params(
                issuer,
                client_id,
                secret.expose_secret(),
                TotpAlgorithm::from_name(auth_config.algorithm.name()),
                auth_config.digits,
                auth_config.time_step,
            )?;
            two_factor_enabled = true;
            enrolled_client = Some(client_id.to_string());
            invite = invite.with_totp(Some(totp));
        }
    } else if cli.registration {
        anyhow::bail!(
            "--registration needs a CLIENT_ID: --generate-invite <CLIENT_ID> --registration"
        );
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
    // Both invite shapes, not just the one carrying a secret: with
    // `enabled = false` the server never runs the handshake, so an enrollment
    // token cannot be exchanged either — and that failure is silent, because
    // nothing ever asks the app for a code.
    if !auth_config.enabled && invite.enrollment.is_some() {
        eprintln!(
            "warning: [auth] enabled is false in {}, so the server never runs the 2FA \
             handshake and the enrollment token in this invite can never be exchanged",
            cli.config
        );
    } else if two_factor_enabled && !auth_config.enabled {
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

    // Printed between the summary and the URI, because the usual fate of a link
    // is a chat window: by the time it is pasted, "this is a password" has to
    // already have been said, and the one-line note at the end of the output is
    // easy to scroll past when all the reader wants is the code.
    if let Some(client) = &enrolled_client
        && two_factor_enabled
    {
        println!("*******************************************************************");
        println!("* THIS LINK IS A CREDENTIAL, NOT JUST AN ADDRESS.");
        println!("*");
        println!("* It carries the TOTP secret in the clear, so anyone who scans or");
        println!("* copies it can authenticate as \"{client}\" until that secret is");
        println!("* rotated. Hand it to one device over one channel, then let it go.");
        println!("*");
        println!("* To revoke it: nexapipe --generate-2fa {client} --force");
        println!("* That rotates the secret, and every device enrolled with the old");
        println!("* one has to scan again — there is no per-device revocation.");
        println!("*******************************************************************");
        println!();
    }
    if let Some(enrollment) = &invite.enrollment {
        println!("-------------------------------------------------------------------");
        println!(" THIS LINK CARRIES AN ENROLLMENT TOKEN, NOT THE SECRET.");
        println!();
        println!(" The first device to scan it trades the token for a freshly");
        println!(
            " generated secret for client \"{}\", and the token is spent: a",
            enrollment.client_id
        );
        println!(" copy of this link stops being a credential the moment it is used.");
        println!(" Enrolling replaces the credential the device that scans it");
        println!(" will use: one that names a device gets a secret of its own,");
        println!(" and one that does not gets this client's shared secret —");
        println!(" which every device already using it has to scan again for.");
        println!();
        println!(" A link you did not deliver is revoked by generating another one");
        println!(" -- this command again -- which replaces the outstanding token.");
        println!("-------------------------------------------------------------------");
        println!();
    }

    println!("Invite URI, to paste into the app:");
    println!("  {link}");
    println!();

    render_qr(
        &link,
        cli,
        "Scan this with the NexaPipe app (add endpoint -> scan):",
    )?;

    if invite.is_enrollment() {
        println!("Scanning imports the endpoint, the domains and a one-time enrollment");
        println!("token; the first connect turns it into the real credential.");
    } else if two_factor_enabled {
        println!("Scanning imports the endpoint, the domains and the 2FA credentials in one");
        println!("step.");
    } else {
        println!("Scanning imports the endpoint and its domains. Pass a client id to");
        println!("--generate-invite to put that client's 2FA credentials in the code too");
        println!("(add --create-client when that client does not exist yet).");
    }

    Ok(())
}

/// Generates a TOTP secret for a client that does not exist yet, writes it into
/// the config, and returns it so the invite being built can carry it.
///
/// This is what `--create-client` does, and it only ever runs for a client that
/// is missing **entirely**: a section that exists but holds no secret is a
/// broken file, not an invitation to fill in the blank, and the caller's lookup
/// handles that case by refusing.
///
/// Unlike [`save_generated_secret`] a failure here is fatal. That one prints a
/// secret the operator can paste by hand because `--generate-2fa` has nothing
/// riding on the file; an invite with `--create-client` is a promise that the
/// server will recognise the client, so a secret that never reached the disk
/// would produce a link that is refused on first connect.
fn create_client_for_invite(
    cli: &Cli,
    client_id: &str,
    auth_config: &AuthConfig,
) -> anyhow::Result<String> {
    let secret = nexapipe::auth::TotpValidator::generate_secret();
    ProxyConfig::write_client_secret(&cli.config, client_id, &secret, false).map_err(|e| {
        anyhow::anyhow!(
            "could not create client \"{client_id}\" in {} ({e}); without the section there \
             is nothing for the invite to authenticate against",
            cli.config
        )
    })?;

    println!(
        "Created [auth.clients.{}] in {} with a newly generated secret.",
        toml_key(client_id),
        cli.config
    );
    // Same warning `--generate-2fa` prints: the secret on disk is worthless
    // until the server is allowed to ask for it.
    if !auth_config.enabled {
        eprintln!(
            "warning: [auth] enabled is not true in {}, so the server will not ask for this \
             secret; add enabled = true under [auth]",
            cli.config
        );
    }
    println!("The 2FA settings are read once at startup, so restart the server before the");
    println!("client above can connect.");
    println!();

    Ok(secret)
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
///
/// The file carries the TOTP secret in the clear, so it is written private: a
/// QR code left at the default mode is a credential anybody with access to the
/// machine can read back.
fn write_qr_file(path: &str, link: &str, invert: bool) -> anyhow::Result<()> {
    use std::io::Write;

    let is_svg = path.to_ascii_lowercase().ends_with(".svg");
    let content = if is_svg {
        nexapipe::qr::render_svg(link, invert)?
    } else {
        format!(
            "# NexaPipe 2FA enrollment\n# {link}\n{}",
            nexapipe::qr::render_ascii(link, invert)?
        )
    };

    // Opened with the mode in the same call that creates it, rather than
    // written and then made private. `fs::write` truncates whatever is already
    // at the path and follows a symlink to reach it, so a `--qr-out` naming a
    // file another account got there first could aim the write at something the
    // operator owns; and between the create and the chmod the file is readable
    // by anyone watching. `create_new` refuses to open a path that already
    // exists, which closes both, and the mode is applied by the same open.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::AlreadyExists {
            " (refusing to overwrite a file that is already there)"
        } else {
            ""
        };
        anyhow::anyhow!("failed to write the QR code to {path}: {e}{hint}")
    })?;
    file.write_all(content.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to write the QR code to {path}: {e}"))?;

    println!();
    println!(
        "Wrote the QR code to {path} ({})",
        if is_svg { "SVG" } else { "ASCII" }
    );
    Ok(())
}

/// Renders a TOML key the way it is written into the config file, as
/// `[auth.clients."client.001"]` requires while `client-001` stays bare. Sharing
/// one renderer with `write_client_secret` keeps the section named in a message
/// identical to the one that ends up in the file.
fn toml_key(key: &str) -> String {
    toml_edit::Key::new(key).to_string()
}

// path-filter verification: a server-only change.
