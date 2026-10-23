pub mod autostart;
pub mod credentials;
pub mod error;
pub mod gate;
mod proxy;
pub mod quit;
pub mod service;
pub mod status;
pub mod tray;
#[cfg(windows)]
mod win;

use error::{codes, AppError};
use nexapipe_client::auth::DeviceKey;
use nexapipe_client::provisioning::{EndpointInvite, EndpointTarget};
use proxy::{
    ConnectionConfig, ProxyManager, ProxyManagerConfig,
    ProxyNodeConfig, StartError,
};
use serde::Serialize;
use service::ipc::{IssuedCredentialPayload, NodeInput, StartProxyRequest};
use service::platform::ServiceState;
use service::IpcClient;
use status::{
    ActiveFlowPage, EndpointLink, NodeHealthStatus, NodeTrafficStatus, ProxyStatus, FLOW_PAGE_LIMIT,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use tauri::{AppHandle, Manager};
use tokio::sync::RwLock;

lazy_static::lazy_static! {
    static ref PROXY_MANAGER: Arc<RwLock<Option<Arc<ProxyManager>>>> = Arc::new(RwLock::new(None));
    static ref STARTUP_ERROR: Arc<RwLock<Option<AppError>>> = Arc::new(RwLock::new(None));
    static ref LOG_CURSOR: Arc<RwLock<Option<LogCursor>>> = Arc::new(RwLock::new(None));
}

/// Whether the tray icon could be created.
///
/// The window's close button can only mean "keep running" if there is a tray to
/// keep running in: without one, the window is the only way back into the app,
/// and hiding it would leave a running app nobody can reach. The renderer asks
/// before it hides anything.
static TRAY_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Whether [`take_runtime_credentials`] has answered already.
///
/// What makes it a start-up read rather than a general one: it is asked by the
/// config store filling itself in before the app mounts, and refuses everything
/// after that. A read that could be repeated at any time would be the ungated
/// one this replaced, whatever it is called.
///
/// Debug builds are the exception, and only because a reload of the webview
/// runs that start-up again without restarting this process. Re-arming it in a
/// shipped build would not be a concession to that: a script in the renderer
/// can reload the page whenever it likes, so anything that re-opens the read on
/// a reload hands the script the answer this command exists to refuse.
static RUNTIME_CREDENTIALS_TAKEN: AtomicBool = AtomicBool::new(false);

/// The nodes [`accept_invite`] filed credentials for in this process.
///
/// What [`take_invited_node_credentials`] answers from. A node is here only
/// because the user just imported an invite for it, and it leaves when those
/// credentials are handed over — so the command cannot be pointed at a node
/// whose credentials the renderer has no business holding.
static INVITED_NODES: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// When this process started: the origin the backend's own start-up timings are measured from.
///
/// The frontend reports a series of its own, measured from the document navigation, and the two
/// have to be read together because neither side can see the other's start. Subtracting the
/// last frontend mark from this instant's elapsed time is the only way to put a number on the
/// stretch neither clock covers — the binary loading, the runtime coming up, the webview being
/// created — which is also the stretch nobody can guess at from the outside.
///
/// A `LazyLock` rather than a plain `Instant`, because `Instant::now()` is not `const`; the
/// first read happens in [`run`], so the gap it misses is the dynamic linker's and not ours.
static APP_START: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

/// How far the log page has read into the newest log file.
///
/// `get_logs` in incremental mode returns only the bytes after this offset, which is what makes
/// "clear" stick: the lines before the offset are never offered to the frontend again, even
/// though the file itself keeps growing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LogCursor {
    path: std::path::PathBuf,
    offset: u64,
}

/// Log directory for the desktop process: `%APPDATA%\nexa\logs` on Windows and the user's
/// XDG state directory on Unix.
///
/// This is deliberately per-user and never shared with [`service_log_dir`]. A root service must
/// not create the directory first and leave the desktop user unable to write its own log there.
pub fn log_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var("APPDATA")
            .map(|d| std::path::Path::new(&d).join("nexa").join("logs"))
            .unwrap_or_else(|_| std::env::temp_dir().join("nexa").join("logs"))
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| std::path::PathBuf::from(home).join(".local").join("state"))
            })
            .unwrap_or_else(std::env::temp_dir);
        base.join("nexa").join("logs")
    }
}

/// Where the *service* writes its log.
///
/// Not [`log_dir()`]: the service runs as LocalSystem on Windows and root on Unix, while the
/// desktop process runs as the logged-in user. Keeping the two apart means a service startup
/// failure can always write its diagnostic without taking ownership of the user's log directory.
pub fn service_log_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var("PROGRAMDATA")
            .map(|d| std::path::Path::new(&d).join("nexa").join("logs"))
            .unwrap_or_else(|_| log_dir())
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/var/log/nexa-service")
    }
}

/// [`init_tracing`] pointed at a directory of the caller's choosing; see [`service_log_dir`].
///
/// Logging is allowed to degrade to stdout when the directory or file cannot be created. A
/// missing log file must never prevent either binary from starting.
pub fn init_tracing_in(
    dir: std::path::PathBuf,
    prefix: &str,
) -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let file_appender = match std::fs::create_dir_all(&dir) {
        Ok(()) => tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(prefix)
            .build(&dir)
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    let (file_writer, guard) = match file_appender {
        Ok(appender) => tracing_appender::non_blocking(appender),
        Err(error) => {
            eprintln!(
                "failed to initialize log file in {}: {}; continuing with stdout logging",
                dir.display(),
                error
            );
            // The stdout layer below remains active, so this writer is only a harmless sink for
            // the file layer and keeps the returned guard type uniform.
            tracing_appender::non_blocking(std::io::sink())
        }
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_writer)
                .with_ansi(false),
        )
        .with(filter)
        .init();
    guard
}

/// Initializes logging: info level by default (override with RUST_LOG), writing both to the
/// console and to a daily rolling file below [`log_dir()`].
/// The returned guard must be kept alive for the log flushing thread to keep running.
pub fn init_tracing(prefix: &str) -> tracing_appender::non_blocking::WorkerGuard {
    init_tracing_in(log_dir(), prefix)
}

/// Starts the proxy, in service mode when asked and in process mode otherwise.
///
/// The forwarding mode is explicit: `use_tun` requests TUN and fails with
/// `proxy.tun_unavailable` when the process cannot create the tunnel, everything else runs the
/// local proxy. Nothing is probed and nothing is downgraded silently — the UI gates TUN on the
/// service being installed, so a request that cannot be honoured must say so.
///
/// Returns nothing on success: the success text this used to return was English prose that the
/// frontend discarded, so the UI now renders its own localized confirmation. Failures come back
/// as an [`AppError`] whose code the frontend translates and whose detail it can log.
/// Ask the service for something, and say whether it answered.
///
/// `Some` is the service's answer. `None` is "it could not answer": the
/// caller then does the same thing in this process, which is what the app has
/// always done — a service that is not installed, not running or not answering
/// leaves the app usable.
///
/// The reason it could not answer is logged here, so that every command that
/// goes through the service says so the same way. The rule was written out
/// once per command, and a change to it — what a fallback means, when it is
/// allowed — was a change in eleven places.
async fn ask_service<T, S>(use_service: bool, what: &str, service: S) -> Option<T>
where
    S: std::future::Future<Output = Result<T, AppError>>,
{
    if !use_service {
        return None;
    }
    match service.await {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::warn!("Failed to {what} via service, falling back to process mode: {e}");
            None
        }
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn start_proxy(
    nodes: Vec<NodeInput>,
    domains: Vec<String>,
    local_addr: Option<String>,
    dns_addr: Option<String>,
    upstream_dns: Option<String>,
    dns_strategy: Option<String>,
    load_balancing: Option<String>,
    tun_name: Option<String>,
    use_service: Option<bool>,
    use_tun: Option<bool>,
    relay_mode: Option<String>,
    relay_url: Option<String>,
    relay_auth_token: Option<String>,
    discovery_mode: Option<String>,
) -> Result<(), AppError> {
    let use_service = use_service.unwrap_or(false);
    let use_tun = use_tun.unwrap_or(false);

    // Before anything is probed or spawned, and only when a tunnel is actually being asked for.
    // The stale-hijack cleanup resets every adapter still pointing at a TUN address, and on
    // Windows there is no "is that tunnel still alive" guard (`address_is_held` is macOS and
    // Linux only) — so a cleanup still running would reset the DNS of the tunnel this start is
    // in the middle of bringing up.
    //
    // Service mode is not exempt. The cleanup this process started is *this* process's, not the
    // service's: the service runs one of its own when it boots (`ServiceRunner::run`), which is
    // no help here, because a long-lived service does not boot again between two starts and has
    // no reason to re-clean before the second one. The tunnel whose DNS is at stake belongs to
    // the service, and this process's cleanup is perfectly capable of resetting it.
    if use_tun {
        stale_hijack_cleanup().await;
    }

    // Checked here, before anything is spawned, so the caller gets the precise code instead of a
    // generic async start failure: a manager that cannot obtain privileges must not be created
    // in TUN mode at all.
    //
    // Service mode is exempt on purpose. The tunnel is created by whoever runs the proxy, and in
    // service mode that is the service process, which is already elevated — while this process is
    // the desktop GUI and never is, so asking `TunProxy::is_available()` here (it is just an
    // `is_admin()` probe) refused a tunnel the service could perfectly well create, and reported
    // `proxy.tun_unavailable` for every TUN start. The service re-checks on its side, where the
    // answer means something.
    if use_tun && !use_service && !proxy::tun_proxy::TunProxy::is_available().await {
        // Named so the log says which of the two processes refused: the same code is raised by
        // the service runner for its own probe, and they were indistinguishable.
        return Err(AppError::with_detail(
            codes::PROXY_TUN_UNAVAILABLE,
            "the desktop process is not elevated, so it cannot create the tunnel itself",
        ));
    }

    // Anything the caller spells out is checked before the request is handed to
    // either runner. Absent means "take the default", and both defaults are
    // loopback / TUN addresses by construction — they are re-checked below in
    // case they ever stop being.
    //
    // What is at stake: `local_addr` fronts a proxy with nothing authenticating
    // in front of it, so binding it anywhere but loopback publishes an open
    // proxy to everyone who can reach the machine. That is the one thing the
    // service side refuses on purpose, and until now only the service side
    // refused it — the in-process path took the address as it came.
    if let Some(addr) = local_addr.as_deref() {
        service::runner::require_loopback(addr, codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK)?;
    }
    if let Some(addr) = dns_addr.as_deref() {
        service::runner::require_tun_subnet(addr)?;
    }

    if use_service {
        match IpcClient::start_proxy(StartProxyRequest {
            nodes: nodes.clone(),
            domains: domains.clone(),
            local_addr: local_addr.clone(),
            dns_addr: dns_addr.clone(),
            upstream_dns: upstream_dns.clone(),
            dns_strategy: dns_strategy.clone(),
            load_balancing: load_balancing.clone(),
            tun_name: tun_name.clone(),
            use_tun: Some(use_tun),
            relay_mode: relay_mode.clone(),
            relay_url: relay_url.clone(),
            relay_auth_token: relay_auth_token.clone(),
            discovery_mode: discovery_mode.clone(),
        })
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                // With TUN requested, a service failure is reported instead of falling back:
                // the fallback would start a local proxy while the user asked for a tunnel.
                //
                // This is the one command that does not go through `ask_service`, because
                // here the fallback is not allowed at all rather than merely unwanted.
                if use_tun {
                    tracing::error!("TUN requested but service start failed: {}", e);
                    return Err(e);
                }
                tracing::warn!(
                    "Failed to start proxy via service, falling back to process mode: {}",
                    e
                );
            }
        }
    }

    // Merge the global domains into every node's domains: the global list holds every domain
    // configured in the UI text area. Migration from older versions writes them into
    // node[0].domains, but domains the user adds later only exist in the global list, so we
    // de-duplicate and append them to each node. This makes sure both DNS hijacking
    // (all_domains collection) and routing (EndpointGroup) pick up newly added domains
    // (e.g. comfyui.iroh.top).
    let global_domains: Vec<String> = domains
        .into_iter()
        .filter(|d| !d.trim().is_empty())
        .collect();

    let parsed_nodes: Vec<ProxyNodeConfig> = nodes
        .into_iter()
        .filter(|n| !n.ticket.is_empty() || !n.endpoint_id.is_empty())
        .map(|n| {
            // Read before the connection string is moved out of `n`.
            let two_factor = n.two_factor();
            let enrollment = n.enrollment();
            let connection = if n.connection_type == "ticket" || !n.ticket.is_empty() {
                ConnectionConfig::Ticket(n.ticket)
            } else {
                ConnectionConfig::EndpointId(n.endpoint_id)
            };
            // Merge: node-local domains + global domains, de-duplicated, order preserved
            let mut merged: Vec<String> = n.domains;
            for g in &global_domains {
                if !merged.iter().any(|d| d == g) {
                    merged.push(g.clone());
                }
            }
            ProxyNodeConfig {
                connection,
                domains: merged,
                two_factor,
                enrollment,
                // The device's own key, which belongs to the device rather
                // than to the credential: the same key is offered by the
                // enrollment and signs every handshake after it.
                device_key: n.device_key.clone(),
            }
        })
        .collect();

    if parsed_nodes.is_empty() {
        return Err(AppError::new(codes::PROXY_NO_NODES));
    }

    let load_balancing = load_balancing.unwrap_or_else(|| "round_robin".to_string());
    let load_balancing = nexapipe_client::lb::LoadBalancingStrategy::from_name(&load_balancing)
        .map_err(|e: String| AppError::cause(codes::PROXY_INVALID_LOAD_BALANCING, e))?;

    let local_addr = local_addr.unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let dns_addr = dns_addr.unwrap_or_else(|| "198.18.0.254:53".to_string());
    let upstream_dns = upstream_dns.unwrap_or_else(|| "8.8.8.8:53".to_string());

    // What the machine's DNS is asked to do. Read here rather than deeper
    // down, so a spelling nobody knows is refused before anything is changed:
    // a strategy that is not known must not be read as "leave the machine's
    // DNS alone" or "replace all of it".
    let dns_strategy = match dns_strategy.as_deref() {
        Some(value) => proxy::dns_config::DnsStrategy::parse(value)
            .map_err(|e| AppError::cause(codes::PROXY_INVALID_DNS_STRATEGY, e.to_string()))?,
        None => proxy::dns_config::DnsStrategy::default(),
    };

    // The in-process path is the one that had no validation at all, so it
    // re-checks after the defaults have been substituted: the caller's values
    // were already refused above, and this catches a default that stops being
    // loopback or leaves the TUN block.
    service::runner::require_loopback(&local_addr, codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK)?;
    service::runner::require_tun_subnet(&dns_addr)?;

    let tun_name = tun_name.unwrap_or_else(|| "nexa-tun".to_string());

    let config = ProxyManagerConfig {
        nodes: parsed_nodes,
        local_proxy_addr: local_addr,
        dns_listen_addr: dns_addr,
        upstream_dns,
        dns_strategy,
        load_balancing,
        tun_name,
        use_tun,
        relay_mode: relay_mode.unwrap_or_else(|| "pinned".to_string()),
        relay_url: relay_url.unwrap_or_default(),
        relay_auth_token: relay_auth_token.unwrap_or_default(),
        discovery_mode: discovery_mode.unwrap_or_else(|| "n0".to_string()),
    };

    let manager = Arc::new(ProxyManager::new(config));

    {
        let mut proxy_manager = PROXY_MANAGER.write().await;
        *proxy_manager = Some(manager.clone());
    }

    let startup_error_clone = STARTUP_ERROR.clone();
    let proxy_manager_clone = PROXY_MANAGER.clone();
    let manager_cleanup = manager.clone();
    tokio::spawn(async move {
        if let Err(e) = manager.start().await {
            tracing::error!("Proxy manager failed: {}", e);
            // "No backend is reachable" is a foreseeable configuration/network problem the user
            // can act on, so it keeps its own code; everything else stays the generic startup
            // failure. Either way the raw reason rides along as `detail`.
            let code = match &e {
                StartError::NoReachableBackend { .. } => codes::PROXY_NO_REACHABLE_BACKEND,
                StartError::TwoFactorRequired { .. } => codes::PROXY_TWO_FACTOR_REQUIRED,
                StartError::Other(_) => codes::PROXY_START_FAILED,
            };
            *startup_error_clone.write().await = Some(AppError::with_detail(code, e.to_string()));

            // A manager that failed to start reports `None` as its mode, which `get_proxy_status`
            // renders as "starting" — but nothing is starting: the tunnel or the listen socket was
            // never brought up, or has just gone away. Leaving it registered made the UI sit on
            // the connecting state forever after a failed start. This mirrors what the service
            // runner already does, and only clears the entry if a newer start has not replaced it.
            let mut registered = proxy_manager_clone.write().await;
            if registered
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &manager_cleanup))
            {
                *registered = None;
            }
        }
    });

    Ok(())
}

#[tauri::command]
async fn stop_proxy(use_service: Option<bool>) -> Result<(), AppError> {
    let use_service = use_service.unwrap_or(false);

    if ask_service(use_service, "stop proxy", IpcClient::stop_proxy())
        .await
        .is_some()
    {
        return Ok(());
    }

    // Clear the registration as well as stopping the instance. A manager that is still registered
    // reports its mode as `None`, which the UI reads as "starting"; after a stop nothing is
    // starting, and `waitForStart` in the frontend relies on that mode to tell a failed start from
    // a slow one.
    let mut proxy_manager = PROXY_MANAGER.write().await;
    if let Some(manager) = proxy_manager.as_ref() {
        manager.stop().await;
    }
    *proxy_manager = None;
    Ok(())
}

#[tauri::command]
async fn get_proxy_status(use_service: Option<bool>) -> Result<ProxyStatus, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(status) = ask_service(use_service, "get status", IpcClient::get_status()).await {
        return Ok(status);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        // A manager with no mode yet is starting up, not running: see `ProxyStatus::starting`.
        Some(manager) => match manager.get_mode() {
            Some(mode) => ProxyStatus::running_with(mode),
            None => ProxyStatus::starting(),
        },
        // No manager here, and the service could not be asked: the tunnel may be the service's,
        // and this process cannot say. "Stopped" would be a guess, and the guess is what starts a
        // second tunnel over a live one — so the state is reported as unknown instead.
        None if use_service => ProxyStatus::unknown(),
        None => ProxyStatus::stopped(),
    })
}

/// This endpoint's Node ID, as [`credentials::mask`] renders it.
///
/// Masked for the same reason a stored credential is: this is the string the UI
/// prints, and it is the name this machine answers to on the network. Nothing in
/// the app needs the whole of it to work — [`reveal_node_id`] is how the user
/// gets one to paste somewhere, which is a deliberate act rather than a glance.
#[tauri::command]
async fn get_node_id_display(use_service: Option<bool>) -> Result<String, AppError> {
    Ok(credentials::mask(&node_id(use_service).await?))
}

/// This endpoint's Node ID in full.
///
/// The one way a surface gets the whole of it, for the user to copy into a
/// server's `[peers] allow` or into a message to whoever runs one — which is
/// why the door stands in front of it.
#[tauri::command]
async fn reveal_node_id(use_service: Option<bool>) -> Result<String, AppError> {
    require_unlocked()?;
    node_id(use_service).await
}

/// This endpoint's Node ID, from whichever process is running the proxy.
async fn node_id(use_service: Option<bool>) -> Result<String, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(id) = ask_service(use_service, "get node ID", IpcClient::get_node_id()).await {
        return Ok(id);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    match proxy_manager.as_ref() {
        Some(manager) => manager
            .get_node_id()
            .await
            .ok_or_else(|| AppError::new(codes::PROXY_NODE_ID_UNAVAILABLE)),
        None => Err(AppError::new(codes::PROXY_NOT_RUNNING)),
    }
}

/// How each configured node currently reaches its backend: direct, or through a relay.
///
/// Empty when the proxy is not running. There is deliberately no error for "not running": the
/// UI polls this while the proxy is up and simply draws no icon when it gets nothing back.
#[tauri::command]
async fn get_endpoint_links(use_service: Option<bool>) -> Result<Vec<EndpointLink>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(links) = ask_service(
        use_service,
        "get endpoint links",
        IpcClient::get_endpoint_links(),
    )
    .await
    {
        return Ok(links);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.endpoint_links().await,
        None => Vec::new(),
    })
}

/// Whether each configured node answered its last probe, and how long it has been down.
///
/// Empty when the proxy is not running — there is nothing probing. Like the links, this is a
/// poll with no error for "not running": the UI draws no badge when it gets nothing back.
#[tauri::command]
async fn get_node_health(use_service: Option<bool>) -> Result<Vec<NodeHealthStatus>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(health) =
        ask_service(use_service, "get node health", IpcClient::get_node_health()).await
    {
        return Ok(health);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.node_health().await,
        None => Vec::new(),
    })
}

/// What each configured node has carried since the counters started, and how many flows are open
/// to it.
///
/// Cumulative bytes, not a rate: a rate is two readings and a division, and the UI already polls
/// this on its own interval. Empty when the proxy is not running, and keyed by `connection` like
/// the links and the health, so the UI can put all three on one row.
#[tauri::command]
async fn get_node_traffic(use_service: Option<bool>) -> Result<Vec<NodeTrafficStatus>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(traffic) = ask_service(
        use_service,
        "get node traffic",
        IpcClient::get_node_traffic(),
    )
    .await
    {
        return Ok(traffic);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.node_traffic().await,
        None => Vec::new(),
    })
}

/// The connections the proxy has open right now, one row each.
///
/// The per-node counters say how much each backend has carried; this says which connections
/// those are, so a reader can see what is actually open and end one of them. Empty when the
/// proxy is not running, like the polls above — no tunnel, no flows.
///
/// Capped at [`FLOW_PAGE_LIMIT`] rows, with `total` reported alongside so a UI can say how busy
/// the tunnel really is without trying to draw thousands of rows.
#[tauri::command]
async fn get_active_flows(use_service: Option<bool>) -> Result<ActiveFlowPage, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(page) = ask_service(
        use_service,
        "list active flows",
        IpcClient::get_active_flows(),
    )
    .await
    {
        return Ok(page);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.active_flows(FLOW_PAGE_LIMIT).await,
        None => ActiveFlowPage::empty(),
    })
}

/// Asks one open flow to end.
///
/// `false` when there is no flow open with that id, which covers both "there never was one" and
/// "it ended while the list was being read" — a page polling every few seconds will sometimes be
/// clicked on a row that has already gone, and that is not an error.
///
/// The flow is not *gone* when this returns: it wakes the copy loop holding its sockets, and
/// that loop is what lets go of them. The next poll is where the UI sees it disappear.
#[tauri::command]
async fn close_flow(id: u64, use_service: Option<bool>) -> Result<bool, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(closed) = ask_service(use_service, "close a flow", IpcClient::close_flow(id)).await
    {
        return Ok(closed);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.close_flow(id),
        None => false,
    })
}

/// Asks every flow reaching one configured node to end.
///
/// `connection` is the ticket or endpoint ID exactly as the node was configured — the same key
/// the links, the health and the traffic are keyed by — and `None` comes back when it names a
/// node this configuration cannot resolve to. That is deliberately not `Some(0)`: one of those
/// is a request about a node that is not configured, the other is a configured node that had
/// nothing open.
#[tauri::command]
async fn close_node_flows(
    connection: String,
    use_service: Option<bool>,
) -> Result<Option<usize>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(closed) = ask_service(
        use_service,
        "close a node's flows",
        IpcClient::close_node_flows(&connection),
    )
    .await
    {
        return Ok(closed);
    }

    let proxy_manager = PROXY_MANAGER.read().await;
    Ok(match proxy_manager.as_ref() {
        Some(manager) => manager.close_node_flows(&connection).await,
        None => None,
    })
}

/// A `nexapipe://` invitation read into the shape the UI needs to *show* before the
/// user commits.
///
/// The grammar lives in `nexapipe-client` (module `provisioning`), the same parser the server that
/// prints the code and the Android client that scans it both read; the desktop asks it instead of
/// growing a third implementation that would drift.
///
/// Nothing here is applied, and — the difference from what this used to return —
/// nothing secret crosses either: the connection string is masked by
/// [`credentials::mask`], and a TOTP secret or enrollment token a code carries is
/// not handed to the renderer at all. Showing an invite needs neither, and
/// `accept_invite` is what files them once the user says yes.
///
/// The fields cross into TypeScript, where `InvitePayload` in `src/types/index.ts` spells them
/// camelCase. Nothing in Tauri rewrites the keys of a command result — every struct has to ask
/// for the conversion itself — so without this rename the frontend reads `undefined` for every
/// multi-word field while the single-word ones arrive intact, which is how a parsed invite lost
/// its client id and kept its secret.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePayload {
    /// `endpoint` for a bare Node ID, `ticket` for an address-bearing ticket.
    pub kind: String,
    /// The Node ID, or the ticket, as [`credentials::mask`] renders it.
    ///
    /// Masked because the preview is a surface: this is the string the dialog
    /// prints, and a ticket is the whole of what someone needs to connect.
    pub target_masked: String,
    /// Cosmetic label from the invite. Nothing routes on it.
    pub name: Option<String>,
    pub domains: Vec<String>,
    pub relay: Option<String>,
    pub totp: Option<InviteTotpPayload>,
    /// A one-time enrollment token, which is what a `v=2` invite carries instead of a
    /// secret. Mutually exclusive with `totp` — the parser refuses a code that carries
    /// both — so the UI can branch on this without deciding a precedence of its own.
    pub enrollment: Option<InviteEnrollmentPayload>,
}

/// The enrollment half of an invite: a token to spend, not a secret to keep.
///
/// What crosses is *that* there is one and who it is for. The token itself is
/// filed by `accept_invite` and never reaches the renderer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteEnrollmentPayload {
    /// Which `[auth.clients]` entry the token is pending for.
    pub client_id: String,
}

/// The 2FA half of an invite, in the form the config store keeps it.
///
/// The secret is not in here: an invite is shown to be recognised, not to be
/// read, and the secret is the one part of a code that is still a credential
/// after the connection it authorises is set up.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteTotpPayload {
    pub client_id: String,
    /// Lowercase algorithm name, which is what `twoFactorAlgorithm` holds.
    pub algorithm: String,
    pub issuer: String,
}

/// What `accept_invite` answers: which node an invite belongs to, and
/// everything about it that is not a credential.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteAccepted {
    /// The node the invite's credentials were filed under. An existing node's id
    /// when one already held this connection string, so importing the same
    /// invite twice tops a node up instead of adding a second one pointing at
    /// the same backend.
    pub node_id: String,
    /// `ticket` or `endpoint_id`, which is what `connectionType` calls them.
    pub connection_type: String,
    /// Whether `node_id` named a node that was already here.
    pub existing: bool,
    /// Cosmetic label from the invite. Nothing routes on it.
    pub name: Option<String>,
    pub domains: Vec<String>,
    pub relay: Option<String>,
    pub totp: Option<InviteTotpPayload>,
    pub enrollment: Option<InviteEnrollmentPayload>,
    /// The public half of the device key this node will enroll with, as 64 hex
    /// characters.
    ///
    /// `None` for an invite that hands out a secret rather than a token, and
    /// for one whose key could not be stored. The private half never crosses
    /// this boundary: it is filed in the store and read from there when a
    /// connection needs it.
    pub public_key: Option<String>,
}

/// Reads a `nexapipe://` invite pasted into the UI.
///
/// Pure parsing: no proxy is touched and no config is written, so the UI can show what a code
/// carries before the user accepts it. A rejected code comes back as `invite.parse_failed` with
/// the parser's reason as `detail` — the reason names the offending part ("unsupported version",
/// "unknown host"), which is worth more than a generic failure but is still an English diagnostic.
///
/// Not `async`: it is a string parse with no I/O, and a synchronous command keeps it off the
/// async runtime entirely.
#[tauri::command]
fn parse_invite(uri: String) -> Result<InvitePayload, AppError> {
    let invite = EndpointInvite::from_uri(&uri)
        .map_err(|e| AppError::cause(codes::INVITE_PARSE_FAILED, e))?;

    let (kind, target) = match &invite.target {
        EndpointTarget::NodeId(id) => ("endpoint".to_string(), id.clone()),
        EndpointTarget::Ticket(ticket) => ("ticket".to_string(), ticket.clone()),
    };

    Ok(InvitePayload {
        kind,
        target_masked: credentials::mask(&target),
        name: invite.name.clone(),
        domains: invite.domains.clone(),
        relay: invite.relay.clone(),
        totp: invite.totp.as_ref().map(|totp| InviteTotpPayload {
            client_id: totp.client_id.clone(),
            algorithm: totp.algorithm.name().to_string(),
            issuer: totp.issuer.clone(),
        }),
        enrollment: invite
            .enrollment
            .as_ref()
            .map(|enrollment| InviteEnrollmentPayload {
                client_id: enrollment.client_id.clone(),
            }),
    })
}

/// Files what an invite carries into the encrypted store and says which node it
/// belongs to.
///
/// This exists because [`parse_invite`] stopped handing secrets to the renderer:
/// something has to put the connection string, the TOTP secret and the enrollment
/// token where they live, and the renderer is the one place they should not pass
/// through on the way. The answer is everything else about the code — no
/// credential in it, so the caller can build the node without ever holding one.
///
/// Which node it is gets decided here, by looking for one that already holds this
/// connection string: the renderer cannot do that comparison any more, because it
/// no longer has the string to compare with. Node ids are the keys the store
/// files credentials under, so "which node" is a question about the store.
#[tauri::command]
fn accept_invite(uri: String) -> Result<InviteAccepted, AppError> {
    let invite = EndpointInvite::from_uri(&uri)
        .map_err(|e| AppError::cause(codes::INVITE_PARSE_FAILED, e))?;

    let (connection_type, target, kind) = match &invite.target {
        EndpointTarget::NodeId(id) => (
            "endpoint_id",
            id.clone(),
            credentials::CredentialKind::EndpointId,
        ),
        EndpointTarget::Ticket(ticket) => (
            "ticket",
            ticket.clone(),
            credentials::CredentialKind::Ticket,
        ),
    };

    let existing = node_holding(kind, &target)?;
    let node_id = existing.clone().unwrap_or_else(new_node_id);

    // The connection string first: everything below is filed under a node that
    // is identified by having it, so a failure here must leave nothing behind.
    credentials::put(&credentials::secret_key(kind, &node_id), &target)?;

    if let Some(totp) = &invite.totp {
        credentials::put(
            &credentials::secret_key(credentials::CredentialKind::TotpSecret, &node_id),
            totp.secret.expose_secret(),
        )?;
    }
    if let Some(enrollment) = &invite.enrollment {
        credentials::put(
            &credentials::secret_key(credentials::CredentialKind::EnrollmentToken, &node_id),
            enrollment.token.expose_secret(),
        )?;
    }

    // A registration invite is the one moment a device key can be offered: the
    // token in it is the human moment, and the key is what this machine proves
    // itself with from then on. Minted here so it is on file before the token
    // is spent — a token cannot be spent twice, and a node whose key was lost
    // afterwards cannot enroll again from the same code.
    //
    // Only for a node that has no key yet: the key belongs to the device, and
    // replacing it here would leave the server holding the old public half
    // while this machine signs with a new one. Re-importing the same invite
    // keeps the key it already has.
    //
    // The private half is filed in the store and never crosses to the
    // renderer; only the public half does, because it is not a secret and it
    // is what names this key to an operator.
    let public_key = match &invite.enrollment {
        Some(_) => {
            let key = match credentials::get(&credentials::secret_key(
                credentials::CredentialKind::DeviceKey,
                &node_id,
            ))? {
                Some(spelled) => DeviceKey::from_hex(&spelled)
                    .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))?,
                None => {
                    let key = DeviceKey::generate();
                    credentials::put(
                        &credentials::secret_key(credentials::CredentialKind::DeviceKey, &node_id),
                        &key.private_hex(),
                    )?;
                    key
                }
            };
            Some(key.public_hex())
        }
        None => None,
    };

    // What `take_invited_node_credentials` answers from: the connection string
    // this node is identified by was filed by an invite the user just imported,
    // so the configuration is allowed to read it back — once.
    INVITED_NODES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(node_id.clone());

    Ok(InviteAccepted {
        node_id,
        connection_type: connection_type.to_string(),
        existing: existing.is_some(),
        name: invite.name.clone(),
        domains: invite.domains.clone(),
        relay: invite.relay.clone(),
        totp: invite.totp.as_ref().map(|totp| InviteTotpPayload {
            client_id: totp.client_id.clone(),
            algorithm: totp.algorithm.name().to_string(),
            issuer: totp.issuer.clone(),
        }),
        enrollment: invite
            .enrollment
            .as_ref()
            .map(|enrollment| InviteEnrollmentPayload {
                client_id: enrollment.client_id.clone(),
            }),
        public_key,
    })
}

/// The node whose stored connection string is `target`, if there is one.
///
/// A scan rather than an index because there is no index to keep: a node is
/// identified by its connection string and there are a handful of them. Every
/// entry is read here, and every read is a decrypt, which is the point — the
/// comparison happens where the values are plaintext anyway.
fn node_holding(
    kind: credentials::CredentialKind,
    target: &str,
) -> Result<Option<String>, AppError> {
    let prefix = format!("{}:", kind.as_str());

    for key in credentials::keys()? {
        if !key.starts_with(&prefix) {
            continue;
        }
        if credentials::get(&key)?.as_deref() == Some(target) {
            return Ok(Some(key[prefix.len()..].to_string()));
        }
    }

    Ok(None)
}

/// An id for a node no stored connection string belongs to yet.
///
/// Only has to be unique among the store's keys, and unguessable is not part of
/// the job: it names a node in a file the user already owns.
fn new_node_id() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Not a credential and not a nonce, so a coarse fallback is fine: the
        // clock plus whatever the address happened to be still distinguishes
        // two nodes created in the same session.
        return format!("node-{:?}", std::time::SystemTime::now());
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("node-{hex}")
}

/// Hands back the credential a server issued for an enrollment token, and clears it.
///
/// `None` when nothing enrolled on this run — no node carried a token, or the credential
/// has already been taken. A token is spent by the first connection that uses it, so the
/// caller gets exactly one chance to read this; the frontend stores it as that node's 2FA
/// credentials, because without it a restart has nothing left to authenticate with.
#[tauri::command]
async fn take_issued_credential(
    use_service: Option<bool>,
) -> Result<Option<IssuedCredentialPayload>, AppError> {
    let use_service = use_service.unwrap_or(false);

    if let Some(credential) = ask_service(
        use_service,
        "read the enrolled credential",
        IpcClient::take_issued_credential(),
    )
    .await
    {
        return Ok(credential);
    }

    // Cloned out of the lock first: the guard must not be held across the await below.
    let manager = PROXY_MANAGER.read().await.as_ref().cloned();
    Ok(match manager {
        Some(manager) => {
            manager
                .take_issued_credential()
                .await
                .map(|credential| IssuedCredentialPayload {
                    client_id: credential.client_id,
                    // The credential is on its way to the keychain, which is
                    // outside this process: the copy handed over is a plain
                    // string, and the one that stays behind is wiped with the
                    // credential.
                    secret: credential.secret.expose_secret().to_string(),
                    algorithm: credential.algorithm,
                    public_key: credential.public_key,
                    device: credential.device,
                })
        }
        None => None,
    })
}

/// Registers the system service, asking for administrator rights.
///
/// Deliberately *not* routed through the IPC channel: the service is by definition not running
/// before it is installed, so an IPC request could only ever fail with `service.unavailable` and
/// the user would never see the UAC / sudo prompt. Running it here lets
/// [`service::platform::install_service`] re-launch this binary elevated when needed.
#[tauri::command]
async fn install_service() -> Result<(), AppError> {
    run_elevated("install", service::platform::install_service).await
}

/// Removes the system service, asking for administrator rights — see [`install_service`] for why
/// this does not go through the IPC channel.
#[tauri::command]
async fn uninstall_service() -> Result<(), AppError> {
    run_elevated("uninstall", service::platform::uninstall_service).await
}

/// Runs a service-management operation that may have to wait for an elevation prompt.
///
/// The wait is not bounded by this process: a sudo password typed in a terminal gets a two-minute
/// budget inside [`service::elevate`], so the work is moved off the async runtime's thread
/// instead of blocking every other command while the user decides.
async fn run_elevated(verb: &str, operation: fn() -> Result<(), AppError>) -> Result<(), AppError> {
    let outcome = tauri::async_runtime::spawn_blocking(operation)
        .await
        .unwrap_or_else(|e| Err(AppError::cause(codes::SERVICE_FAILED, e)));

    if let Err(e) = &outcome {
        tracing::error!("service {} failed: {}", verb, e);
    }

    outcome
}

/// Whether the service is registered, stopped or running — as the service manager sees it.
///
/// Infallible: an unreadable service manager means "we cannot tell", which the UI renders like an
/// uninstalled service rather than failing the whole panel.
#[tauri::command]
async fn get_service_status() -> ServiceState {
    tauri::async_runtime::spawn_blocking(service::platform::service_state)
        .await
        .unwrap_or(ServiceState::NotInstalled)
}

/// The build the installed service reports, when it can say.
///
/// `None` covers "no service is answering" and "the service predates the question", which the
/// caller cannot tell apart: a build that does not know [`IpcMessage::GetVersion`] refuses it
/// and closes the connection. Both mean the same thing to the UI, which compares this against
/// the app's own version and offers to reinstall when they differ — an older service answers
/// the requests it does understand with whatever it has, which is how an upgrade that never
/// happened looked like a page with nothing in it.
#[tauri::command]
async fn get_service_version() -> Option<String> {
    match IpcClient::get_version().await {
        Ok(version) => Some(version),
        Err(e) => {
            tracing::debug!("Could not ask the service which build it is: {e}");
            None
        }
    }
}

/// Starts the service, asking for administrator rights when the unprivileged call is refused.
#[tauri::command]
async fn start_service() -> Result<(), AppError> {
    run_elevated("start", service::platform::start_service).await
}

/// Stops the service, asking for administrator rights when the unprivileged call is refused.
#[tauri::command]
async fn stop_service() -> Result<(), AppError> {
    run_elevated("stop", service::platform::stop_service).await
}

/// Whether a service is answering on the IPC port.
///
/// Infallible on purpose: an unreachable service is reported as "not running", which is what the
/// status indicator needs to know. The reason is logged by the IPC client on the way out.
#[tauri::command]
async fn is_service_running() -> bool {
    IpcClient::is_service_running().await
}

/// The failure `start_proxy` recorded after it had already returned, if any.
///
/// Infallible: "there is no recorded failure" and "the failure could not be read" are the same
/// answer to the caller. That is also why this deliberately does *not* clear the value — the
/// frontend polls it, and clearing it would make the message flash for one poll interval.
#[tauri::command]
async fn get_startup_error() -> Option<AppError> {
    if let Some(error) = STARTUP_ERROR.read().await.clone() {
        return Some(error);
    }

    // A service-mode start fails in the other process, where this one cannot see it — and its
    // log is written under LocalSystem's profile, which nobody can read. So ask: the service
    // records the same failure with the same code, and an unreachable service or an older build
    // that does not know the question is simply "no failure on file".
    match IpcClient::get_startup_error().await {
        Ok(Some(error)) => Some(error),
        Ok(None) | Err(_) => None,
    }
}

/// The result of `get_logs`.
///
/// `fresh` marks a full tail read (the first poll, a day roll-over, or anything else that
/// invalidates the incremental cursor); the frontend must *replace* its view with `lines`.
/// `fresh: false` lines are an append-only continuation of what was delivered before.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogPage {
    lines: Vec<String>,
    fresh: bool,
}

/// Picks the most recently modified `nexa.log` file in `dir` (daily rolling: `nexa.log.YYYY-MM-DD`).
fn newest_log_file(dir: &std::path::Path) -> Result<Option<std::path::PathBuf>, AppError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(AppError::cause(codes::LOGS_DIR_UNREADABLE, error)),
    };

    Ok(entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("nexa.log"))
                    .unwrap_or(false)
        })
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok()))
}

/// Splits `content` into the lines that are guaranteed complete.
///
/// A log file is read while the writer is still appending, so the tail may end mid-line; a
/// fragment without a trailing newline is held back and the returned byte length tells the
/// caller where the complete portion ends, so the next poll re-reads it instead of losing it.
/// Returns `(lines, consumed_bytes)`.
fn complete_lines(content: &str) -> (Vec<&str>, usize) {
    match content.rfind('\n') {
        Some(pos) => (content[..pos].lines().collect(), pos + 1),
        None => (Vec::new(), 0),
    }
}

/// Reads the log file for the frontend log page.
///
/// Pass `append: true` to get only the lines written since the previous call (incremental);
/// the default is a fresh tail read. Incremental reads are what keep the page in sync with a
/// file that outgrew the tail window — a file with more than `limit` lines never changes the
/// *length* of the tail, so counting lines to detect new ones never fires. They are also what
/// makes `clear_logs` stick.
///
/// The lines themselves are raw log output and stay untranslated; only failures to read them are
/// reported as codes.
#[tauri::command]
async fn get_logs(limit: Option<usize>, append: Option<bool>) -> Result<LogPage, AppError> {
    use std::io::{Read, Seek};

    let limit = limit.unwrap_or(200);
    let append = append.unwrap_or(false);
    let dir = log_dir();

    let Some(path) = newest_log_file(&dir)? else {
        *LOG_CURSOR.write().await = None;
        return Ok(LogPage {
            lines: vec![],
            fresh: true,
        });
    };

    let mut file =
        std::fs::File::open(&path).map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut cursor = LOG_CURSOR.write().await;
    let incremental = append
        && cursor
            .as_ref()
            .is_some_and(|c| c.path == path && c.offset <= file_len);

    let (lines, fresh) = if incremental {
        // Continue exactly where the previous read stopped.
        let offset = cursor.as_ref().expect("checked above").offset;
        file.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        // A partially written last line stays in the file for the next poll.
        let (lines, consumed) = complete_lines(&content);
        *cursor = Some(LogCursor {
            path,
            offset: offset + consumed as u64,
        });
        (
            lines.into_iter().map(String::from).collect::<Vec<_>>(),
            false,
        )
    } else {
        // Only read the tail so that large files are not loaded in full. When the window starts
        // mid-line, drop the partial first line instead of showing it as garbled output.
        const MAX_TAIL: u64 = 512 * 1024;
        let tail_offset = file_len.saturating_sub(MAX_TAIL);
        if tail_offset > 0 {
            file.seek(std::io::SeekFrom::Start(tail_offset))
                .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        }
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| AppError::cause(codes::LOGS_READ_FAILED, e))?;
        if tail_offset > 0 {
            if let Some(pos) = content.find('\n') {
                content.drain(..=pos);
            } else {
                content.clear();
            }
        }
        let all: Vec<&str> = content.lines().collect();
        let start = all.len().saturating_sub(limit);
        let lines = all[start..].iter().map(|l| l.to_string()).collect();
        *cursor = Some(LogCursor {
            path,
            offset: file_len,
        });
        (lines, true)
    };

    Ok(LogPage { lines, fresh })
}

/// Marks every line currently in the newest log file as already seen.
///
/// The frontend clears its view and calls this; the next incremental poll returns only lines
/// written *after* the clear, so old entries never reappear. The file itself is deliberately not
/// truncated: the rolling writer in whichever process owns it (often the service) keeps its
/// handle open, and cutting a file out from under an appender corrupts the stream.
#[tauri::command]
async fn clear_logs() -> Result<(), AppError> {
    let newest = newest_log_file(&log_dir())?;
    *LOG_CURSOR.write().await = newest.and_then(|path| {
        std::fs::File::open(&path)
            .ok()
            .and_then(|f| f.metadata().ok())
            .map(|m| LogCursor {
                path,
                offset: m.len(),
            })
    });
    Ok(())
}

/// Turns what the frontend names into one of the keys [`credentials`] knows.
///
/// The frontend sends a kind and, for per-node credentials, a node id: letting it
/// spell the whole key would let it write entries nothing can ever read back, and
/// would make the two sides agree by convention rather than by construction.
fn credential_kind(kind: &str, node_id: Option<String>) -> Result<String, AppError> {
    let kind = match kind {
        "totp" => credentials::CredentialKind::TotpSecret,
        "enrollment" => credentials::CredentialKind::EnrollmentToken,
        "devicekey" => credentials::CredentialKind::DeviceKey,
        "relay" => credentials::CredentialKind::RelayToken,
        "ticket" => credentials::CredentialKind::Ticket,
        "endpoint" => credentials::CredentialKind::EndpointId,
        other => {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("{other:?} is not a credential kind"),
            ))
        }
    };

    // A per-node credential with no node named belongs to no node.
    let node_id = node_id.unwrap_or_default();
    if node_id.trim().is_empty() && !matches!(kind, credentials::CredentialKind::RelayToken) {
        return Err(AppError::with_detail(
            codes::CREDENTIALS_STORE_FAILED,
            format!("a {} credential needs a node id", kind.as_str()),
        ));
    }

    Ok(credentials::secret_key(kind, &node_id))
}

/// One node's credentials, in full.
///
/// Not a display shape: this is what the config store fills itself in with at
/// start-up, because `start_proxy` still takes a connection string and a TOTP
/// secret as arguments. Nothing renders it — a surface asks
/// [`credential_display`], or [`reveal_credential`] once the door is open.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeCredentials {
    totp: Option<String>,
    enrollment: Option<String>,
    /// The private half of this node's device key, when it has one.
    ///
    /// A credential like the secret beside it, and it crosses this boundary for
    /// the same reason: the proxy needs it to sign, and in the service mode the
    /// service is a separate process with no store of its own.
    device_key: Option<String>,
    /// The public half of that key, as 64 hex characters.
    ///
    /// Derived from the private half rather than stored beside it, so the two
    /// can never disagree about which key this is. Not a secret — the server
    /// holds the same one — and it is what the app shows to name the key an
    /// operator has on file.
    #[serde(default)]
    public_key: Option<String>,
    ticket: Option<String>,
    endpoint: Option<String>,
}

/// Everything the app runs on: the relay bearer and one entry per node.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeCredentials {
    relay: Option<String>,
    nodes: HashMap<String, NodeCredentials>,
}

/// Reads one node's credentials out of the store.
fn node_credentials(node_id: &str) -> Result<NodeCredentials, AppError> {
    let device_key = credentials::get(&credentials::secret_key(
        credentials::CredentialKind::DeviceKey,
        node_id,
    ))?;
    // Derived rather than stored: a value that could disagree with the private
    // half beside it would name the wrong key to an operator.
    let public_key = device_key
        .as_deref()
        .and_then(|spelled| DeviceKey::from_hex(spelled).ok())
        .map(|key| key.public_hex());
    Ok(NodeCredentials {
        totp: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::TotpSecret,
            node_id,
        ))?,
        enrollment: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::EnrollmentToken,
            node_id,
        ))?,
        device_key,
        public_key,
        ticket: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::Ticket,
            node_id,
        ))?,
        endpoint: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::EndpointId,
            node_id,
        ))?,
    })
}

/// Every credential the app runs on, read once at start-up.
///
/// The store used to be readable one value at a time, at any time, through
/// `get_credential`. [`reveal_credential`] is gated, but a general read beside
/// it is a gate with an open door next to it: anything that could reach this
/// process could ask for a TOTP secret without the operating system ever being
/// consulted. This is asked once, by the config store filling itself in before
/// the app mounts, and refuses everything after that.
///
/// The node ids are an argument rather than something discovered here, so it
/// answers for the configuration the caller already has and for nothing else.
/// A read that failed is not spent: a store that handed nothing over has given
/// nothing away.
#[tauri::command]
async fn take_runtime_credentials(node_ids: Vec<String>) -> Result<RuntimeCredentials, AppError> {
    // See `RUNTIME_CREDENTIALS_TAKEN`: a debug build answers again, because a
    // reload of the webview is a new renderer in the same process and would
    // otherwise be locked out of the store for the rest of the run.
    if RUNTIME_CREDENTIALS_TAKEN.load(Ordering::SeqCst) && !cfg!(debug_assertions) {
        return Err(AppError::with_detail(
            codes::CREDENTIALS_STORE_FAILED,
            "the credentials were already read at start-up",
        ));
    }

    // Timed because this is the one call the first paint waits on: it is where the master key
    // is loaded — the keychain read, on the one launch that still asks — and where the store
    // file is read and every entry in it decrypted.
    let started = std::time::Instant::now();

    let mut nodes = HashMap::with_capacity(node_ids.len());
    for node_id in &node_ids {
        let node_id = node_id.trim();
        if node_id.is_empty() {
            continue;
        }
        nodes.insert(node_id.to_string(), node_credentials(node_id)?);
    }

    let bundle = RuntimeCredentials {
        relay: credentials::get(&credentials::secret_key(
            credentials::CredentialKind::RelayToken,
            "",
        ))?,
        nodes,
    };

    tracing::info!(
        "[startup] credentials read took {}ms for {} node(s)",
        started.elapsed().as_millis(),
        bundle.nodes.len()
    );

    RUNTIME_CREDENTIALS_TAKEN.store(true, Ordering::SeqCst);
    Ok(bundle)
}

/// One node's credentials, for the node an invite has just filed them under.
///
/// `applyInvite` needs the connection string back after [`accept_invite`]
/// filed it: the node in the configuration has to agree with the store, or the
/// next save reads the empty string as a deletion and drops what was just
/// imported. Narrower than a read by node id — it answers for the nodes this
/// process imported an invite for, once each, and for no others.
#[tauri::command]
async fn take_invited_node_credentials(node_id: String) -> Result<NodeCredentials, AppError> {
    let node_id = node_id.trim();

    let accepted = INVITED_NODES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(node_id);
    if !accepted {
        return Err(AppError::with_detail(
            codes::CREDENTIALS_STORE_FAILED,
            "no invite was accepted for this node",
        ));
    }

    let credentials = node_credentials(node_id)?;

    // Taken off on the way out rather than on the way in: a read that failed
    // has handed nothing over, so the caller may still ask again.
    INVITED_NODES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(node_id);

    Ok(credentials)
}

/// One credential as a surface may show it: [`credentials::mask`] applied where
/// the value is, so the renderer is handed a projection and never the thing.
#[tauri::command]
async fn credential_display(
    kind: String,
    node_id: Option<String>,
) -> Result<Option<String>, AppError> {
    let key = credential_kind(&kind, node_id)?;
    Ok(credentials::get(&key)?.map(|value| credentials::mask(&value)))
}

/// One credential in full, for the user to copy.
///
/// The only path from the store to a surface, and the one the door stands in
/// front of: everything else the UI can ask for is either a mask or a shape.
#[tauri::command]
async fn reveal_credential(
    kind: String,
    node_id: Option<String>,
) -> Result<Option<String>, AppError> {
    require_unlocked()?;
    let key = credential_kind(&kind, node_id)?;
    credentials::get(&key)
}

/// Refuses a reveal while the door is shut.
///
/// The check the rest of `gate` exists to make possible. It reads the window and
/// nothing else: whether the machine can still ask is re-read when the UI asks
/// for the status, which is what it does when the app comes back into view, and
/// a window that is open is at most two minutes old.
fn require_unlocked() -> Result<(), AppError> {
    if gate::is_unlocked() {
        Ok(())
    } else {
        Err(AppError::new(codes::CREDENTIALS_LOCKED))
    }
}

/// The credential door, as a surface sees it: whether it is open, how long it
/// has left, and whether this machine can be asked at all.
#[tauri::command]
async fn gate_status() -> Result<gate::Status, AppError> {
    on_blocking_task(gate::status).await
}

/// Asks the operating system to confirm the user, and opens the door if it does.
///
/// `reason` is what the prompt says it is for, already in the user's language:
/// the caller knows which credential is about to be shown and the door does not.
/// `password` is what [`gate_status`] asked the UI to collect, and is `None` on
/// the platforms that bring their own prompt.
#[tauri::command]
async fn unlock_credentials(
    reason: String,
    password: Option<String>,
) -> Result<gate::Status, AppError> {
    // Zeroed on drop, so the one platform that needs a password does not leave
    // one behind in the heap of a task that has moved on.
    let password = password.map(zeroize::Zeroizing::new);

    let outcome =
        on_blocking_task(move || gate::confirm(&reason, password.as_ref().map(|p| p.as_str())))
            .await?;

    match outcome {
        gate::Outcome::Unlocked => on_blocking_task(gate::status).await,
        // Asked, and the answer was no. Not worth telling the user twice: they
        // just said it.
        gate::Outcome::Refused => Err(AppError::new(codes::CREDENTIALS_LOCKED)),
        gate::Outcome::Unavailable => Err(AppError::new(codes::CREDENTIALS_GATE_UNAVAILABLE)),
        gate::Outcome::Failed(detail) => Err(AppError::with_detail(
            codes::CREDENTIALS_GATE_FAILED,
            detail,
        )),
    }
}

/// Shuts the door again, without waiting for the window to lapse.
#[tauri::command]
async fn lock_credentials() -> Result<gate::Status, AppError> {
    on_blocking_task(|| {
        gate::lock();
        gate::status()
    })
    .await
}

/// Runs one of the door's blocking calls off the async runtime.
///
/// Every platform prompt is a modal that lasts as long as the user takes to
/// answer it, and even `capability` is a syscall or two; neither belongs on a
/// worker that is also answering IPC for the proxy.
async fn on_blocking_task<T>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, AppError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|error| AppError::with_detail(codes::CREDENTIALS_GATE_FAILED, error.to_string()))
}

/// Writes one credential.
#[tauri::command]
async fn put_credential(
    kind: String,
    value: String,
    node_id: Option<String>,
) -> Result<(), AppError> {
    let key = credential_kind(&kind, node_id)?;
    credentials::put(&key, &value)
}

/// Forgets one credential: what "this server has no 2FA" and "the token has been
/// spent" look like on this side.
#[tauri::command]
async fn delete_credential(kind: String, node_id: Option<String>) -> Result<(), AppError> {
    let key = credential_kind(&kind, node_id)?;
    credentials::remove(&key)
}

/// Forgets every credential, for a reset that also forgets the nodes they belong to.
#[tauri::command]
async fn clear_credentials() -> Result<(), AppError> {
    for key in credentials::keys()? {
        credentials::remove(&key)?;
    }
    Ok(())
}

/// Where the master key ended up: `"keychain"`, or `"file"` when no keychain would
/// take it and the weaker fallback is in use. Reported so the UI can say so
/// rather than let the two look alike.
#[tauri::command]
async fn credential_store_status() -> Result<String, AppError> {
    Ok(credentials::status()?.as_str().to_string())
}

/// Writes the renderer's start-up timings to the log.
///
/// The window is created hidden and shown by the frontend, so "the application takes a while
/// to appear" is a question about code this process cannot see. This is what makes it
/// answerable: the renderer's own series, in the same file as the backend's, measured from the
/// document navigation — and, alongside it, how long this process had been running when the
/// report arrived. The difference is the part neither clock covers.
///
/// Bounded on the way in, because a log line is somewhere a caller can write. The caller here
/// is the renderer, which can reach any other command just as easily, so a mark is treated as
/// untrusted text: control characters dropped, label and count capped. Nothing about this can
/// fail a start-up, so it returns nothing.
#[tauri::command]
async fn log_startup_timing(marks: Vec<(String, f64)>) {
    /// Beyond this a label is prose, not a label.
    const MAX_LABEL_CHARS: usize = 64;
    /// Generous for every mark the start-up path records, and small enough that a series is
    /// one line of log rather than a wall of them.
    const MAX_MARKS: usize = 64;

    let rendered: Vec<String> = marks
        .iter()
        .take(MAX_MARKS)
        .map(|(label, ms)| {
            let label: String = label
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_LABEL_CHARS)
                .collect();
            format!("{label}={ms:.0}ms")
        })
        .collect();

    tracing::info!(
        "[startup] frontend, from the document navigation: {}",
        rendered.join(", ")
    );
    tracing::info!(
        "[startup] process start to this report: {}ms",
        APP_START.elapsed().as_millis()
    );
}

/// Whether this app is started when the machine starts.
///
/// See [`autostart`]. A read that fails is a failure rather than "off": a
/// switch that claims to be off while the entry is there is the same silent
/// lie it used to tell.
#[tauri::command]
async fn is_auto_start_enabled() -> Result<bool, AppError> {
    autostart::is_enabled()
}

/// Arranges for this app to start when the machine starts, or not.
///
/// Writes the entry and stops there. The platform's own login mechanism is
/// what starts the app next time, so switching this on does not launch a
/// second copy of the app in the middle of the session.
#[tauri::command]
async fn set_auto_start(enabled: bool) -> Result<(), AppError> {
    autostart::set_enabled(enabled)
}

/// Whether this launch was asked for by the machine rather than by a person.
///
/// True when the start-up entry started the app: the window stays hidden and
/// the app waits in the tray.
#[tauri::command]
async fn is_background_launch() -> bool {
    autostart::is_background_launch()
}

/// Whether the tray icon could be created.
///
/// The renderer needs this before it lets a closed window hide instead of
/// closing: a window that hides with no tray to bring it back is an app that
/// cannot be reached again.
#[tauri::command]
async fn is_tray_available() -> bool {
    TRAY_AVAILABLE.load(Ordering::Relaxed)
}

/// Rewrites the tray menu in the user's language.
///
/// The translations live in the renderer, which is the only side that knows
/// which language is in use, so the words are handed over rather than looked
/// up here.
///
/// Infallible on purpose: the labels are a nicety, and a tray whose menu is in
/// the wrong language is still a working tray. The failure is logged, because
/// it is worth knowing about.
#[tauri::command]
async fn set_tray_labels(app: AppHandle, show_label: String, quit_label: String) {
    if let Err(e) = tray::set_labels(&app, &show_label, &quit_label) {
        tracing::warn!("the tray menu could not be relabelled: {e}");
    }
}

/// Writes the connection state onto the tray icon.
///
/// The words come from the renderer, which is the only side that knows the status
/// and the language it should be said in.
///
/// Refused rather than trimmed when the text is not one short line: the text goes
/// straight to a native tooltip and a native title, and a caller that could put
/// a newline or a control character there would be writing into another
/// process's window.
///
/// Infallible on purpose, like [`set_tray_labels`]: the state on the tray is
/// information, and a tray that cannot be written to is still a working tray.
#[tauri::command]
async fn set_tray_status(app: AppHandle, status: String) {
    if !tray::is_writable_status(&status) {
        tracing::warn!("the tray status was refused: it is not a single short line");
        return;
    }
    if let Err(e) = tray::set_status(&app, &status) {
        tracing::warn!("the tray status could not be written: {e}");
    }
}

/// How long the window stays hidden waiting for the frontend to paint, before it is shown
/// anyway.
///
/// The frontend normally shows the window itself one frame after it mounts, which is the
/// right moment: the first paint is on screen and nothing empty was ever displayed. This is
/// the deadline for the case where that never happens — a bundle that failed to load, a
/// renderer that threw before mount — because a window that never appears is
/// indistinguishable from an application that did not start.
///
/// Generous on purpose. A cold WebView2 on a slow machine, or a first run that also has to
/// unpack and JIT the bundle, can take a while, and showing a window with nothing in it is a
/// lesser failure than never showing one. Nothing waits on this: it runs alongside the
/// frontend's own `show()` and whichever arrives first wins, the second being a no-op.
const FIRST_PAINT_FALLBACK: std::time::Duration = std::time::Duration::from_secs(10);

/// The stale-hijack cleanup, once per process: whoever needs it first runs it, everyone else
/// waits for that run.
///
/// Spawned rather than run inline because on Windows it costs 1.4-1.7 seconds: it shells out
/// to PowerShell, and `Get-NetUDPEndpoint` / `Get-DnsClientServerAddress` each load the
/// `NetTCPIP` module first. Run from `setup()` that is time the window sits there empty — the
/// window is created *before* the setup closure runs, so the user stares at a blank frame for
/// the whole of it.
///
/// Waiting for it in [`start_proxy`] is not optional. The Windows cleanup resets every adapter
/// whose DNS still points at a TUN address, and the guard that spares a live tunnel
/// (`address_is_held`) is only compiled on macOS and Linux — so a cleanup still running when a
/// start begins would reset the DNS of the tunnel that start is bringing up.
///
/// A [`tokio::sync::OnceCell`], not a `OnceLock` plus a second cell standing in for "finished".
/// `OnceLock::get_or_init` is the wrong shape for this: the closure runs in whichever caller
/// finds the cell empty, so a caller arriving while the cleanup is mid-flight would initialise
/// the cell itself and return at once — the wait would be a no-op in exactly the case it
/// exists for. This cell's `get_or_init` instead hands the work to the one caller that wins the
/// permit and parks the others until it is done, and the cleanup goes to a blocking thread
/// because it is 1.4 seconds of synchronous process output that must not sit on a runtime
/// worker.
static STALE_HIJACK_CLEANUP: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// Runs [`cleanup_stale_hijack`] once per process, off the async runtime, and resolves when it
/// has finished.
///
/// Two callers, opposite needs: [`setup`] starts it and walks away so the first paint is not
/// held up, and [`start_proxy`] waits for it so a tunnel cannot come up underneath it. Both
/// reach the same cleanup through [`STALE_HIJACK_CLEANUP`], so whichever gets there first does
/// the work and the other one waits for the result rather than starting a second run.
async fn stale_hijack_cleanup() {
    let _ = STALE_HIJACK_CLEANUP
        .get_or_init(|| async {
            let _ =
                tokio::task::spawn_blocking(crate::proxy::dns_config::cleanup_stale_hijack).await;
        })
        .await;
}

/// Stops a tunnel this process is still running, so that quitting the app hands the
/// machine's DNS back.
///
/// Quitting reaches neither [`stop_proxy`] nor the teardown inside `TunProxy::run`,
/// so a hijack that was up when the window closed stayed up — and stayed pointing
/// the machine at a TUN address that was about to stop existing. Only the in-process
/// tunnel is stopped: one the launchd/systemd service owns belongs to that daemon,
/// which outlives the window on purpose.
async fn stop_tunnel_on_exit() {
    // Taken rather than borrowed, so a second pass — `ExitRequested` is followed by
    // `Exit` — finds nothing and does not run the teardown twice.
    let manager = PROXY_MANAGER.write().await.take();
    let Some(manager) = manager else {
        return;
    };
    tracing::info!("stopping the tunnel on exit so the system DNS is restored");
    manager.stop().await;
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Read before anything else this process does, so the elapsed times below are measured
    // from as close to the real start as a `LazyLock` can get.
    std::sync::LazyLock::force(&APP_START);

    let _guard = init_tracing("nexa.log");
    // Logged after the subscriber exists rather than before it: a line emitted before
    // `init_tracing` has nowhere to go.
    tracing::info!("[startup] process start");

    // Increase tokio worker thread stack size to 4 MB (default 2 MB) to
    // prevent stack overflow from deeply nested async state machines in
    // iroh / proxy code.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(4 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let handle = runtime.handle().clone();
    // Prevent the runtime from being dropped — it must live as long as the
    // process. Tauri holds the Handle and uses it for all async commands.
    std::mem::forget(runtime);
    // Kept: the exit hook below has to run the teardown on this very runtime, and
    // the one Tauri is handed is a clone of it.
    let shutdown = handle.clone();
    tauri::async_runtime::set(handle);

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            // The window exists by the time this runs and is still hidden, so this is the
            // moment the process stops being "starting up" and starts being "loading the
            // frontend": everything after it is the webview's, and everything before it was
            // ours — the binary, the runtime, the window.
            tracing::info!(
                "[startup] setup reached, window created: +{}ms",
                APP_START.elapsed().as_millis()
            );

            // Same reason the service runner does it: a hijack whose process died
            // before its teardown left the machine's DNS pointing at a TUN address
            // that no longer exists, and nothing else will ever undo that. Doing it
            // here as well matters because the tunnel is not always the service's —
            // the desktop can run one itself when it was launched elevated — and a
            // LaunchDaemon is not what that process becomes. Best effort: an
            // unprivileged desktop cannot change system DNS and the service, which
            // runs as root, cleans up on its own start.
            //
            // On a task, because this is not something the first paint should wait
            // for: the window already exists by the time this closure runs, and on
            // Windows the PowerShell it shells out to costs over a second. A start
            // waits for it explicitly — see `stale_hijack_cleanup`.
            tauri::async_runtime::spawn(stale_hijack_cleanup());

            // The tray icon: the app's second home, and the one it starts in
            // when the machine starts it. Built before the window is shown so
            // that a launch with no window still has a way back into the app.
            //
            // Best effort: a desktop with no tray — a bare session, a
            // container — must still be able to run the app, and what is lost
            // there is an icon rather than the application.
            match tray::build(app.handle()) {
                Ok(()) => TRAY_AVAILABLE.store(true, Ordering::Relaxed),
                Err(e) => tracing::warn!("the tray icon could not be created: {e}"),
            }

            // The window is created hidden (`visible: false`) and shown by the frontend
            // once it has something to paint, so a slow start shows no window rather
            // than an empty one. This is the backstop for the case where the frontend
            // never gets there — a bundle that failed to load, a renderer that threw
            // before mount: a window that never appears is indistinguishable from an app
            // that did not start, so it is shown anyway once the wait has clearly run
            // long enough to be a failure rather than a slow machine.
            //
            // Not for a launch the machine asked for: that one comes up in the
            // tray on purpose, and a window appearing over whatever the user
            // was doing at login is exactly what it was meant to avoid.
            //
            // Unless there is no tray to come up in. The tray is built on a
            // best-effort basis and can fail — a bare session, a container, a
            // Linux host without a StatusNotifier — and an app with no window
            // and no tray icon is an app nobody can reach again.
            //
            // Best effort on every platform, and deliberately not fatal: a build with no
            // window to show must still start.
            if !autostart::is_background_launch() || !TRAY_AVAILABLE.load(Ordering::Relaxed) {
                if let Some(window) = app.get_webview_window("main") {
                    let handle = window.clone();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(FIRST_PAINT_FALLBACK).await;
                        if let Err(e) = handle.show() {
                            tracing::warn!("the fallback could not show the window: {e}");
                        }
                    });
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            get_proxy_status,
            get_node_id_display,
            reveal_node_id,
            get_endpoint_links,
            get_node_health,
            get_node_traffic,
            get_active_flows,
            close_flow,
            close_node_flows,
            parse_invite,
            accept_invite,
            take_issued_credential,
            install_service,
            uninstall_service,
            start_service,
            stop_service,
            get_service_status,
            get_service_version,
            is_service_running,
            get_startup_error,
            get_logs,
            clear_logs,
            take_runtime_credentials,
            take_invited_node_credentials,
            credential_display,
            reveal_credential,
            gate_status,
            unlock_credentials,
            lock_credentials,
            put_credential,
            delete_credential,
            clear_credentials,
            credential_store_status,
            log_startup_timing,
            is_auto_start_enabled,
            set_auto_start,
            is_background_launch,
            is_tray_available,
            set_tray_labels,
            set_tray_status,
            quit::finish_quit,
            quit::quit_guard_ready
        ]);

    // macOS only: the predefined Quit item terminates the process before any event carrying a
    // `prevent_exit()` exists, so nothing about it can be intercepted — see the module doc in
    // `quit`. Ours asks instead and leaves the deciding to the renderer, which is the same answer
    // closing the window gets. If asking itself fails the process still has to go, or Cmd+Q would
    // quietly stop working.
    #[cfg(target_os = "macos")]
    let builder = builder.menu(quit::menu_bar).on_menu_event(|app, event| {
        if event.id() != quit::QUIT_ITEM_ID {
            return;
        }
        tracing::info!("Quit chosen from the menu; waiting for the answer");
        quit::ask(app);
    });

    let app = builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    // Closing the window, Cmd+Q, or an `app.exit()` all end the process without
    // going anywhere near the proxy's teardown, which is what put the system DNS
    // back — so the machine kept the address the hijack gave it until the next
    // start cleaned up after it. Both events are handled because which of them a
    // platform emits last is not this code's to choose: one is the last window's
    // destruction, the other the event loop being torn down, and a quit reaches
    // either one or both depending on how it was asked for.
    //
    // Blocking here is what makes it work — the restore runs on the runtime these
    // commands use — and it is bounded: `stop_and_wait` gives the teardown twenty
    // seconds. Stale-hijack cleanup at start-up is still the backstop, because
    // nothing reaches either event when the process is killed or the power goes.
    app.run(move |_app_handle, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            shutdown.block_on(stop_tunnel_on_exit());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexapipe_client::provisioning::{InviteEnrollment, InviteTotp};

    /// A Node ID nobody is listening on, derived from a fixed seed so the expected strings in
    /// these tests stay stable — parsing checks that the point is valid, not just that it is
    /// 64 hex characters.
    fn node_id() -> String {
        iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string()
    }

    fn endpoint_invite() -> EndpointInvite {
        EndpointInvite::new(
            EndpointTarget::NodeId(node_id()),
            &["a.example".to_string(), "b.example".to_string()],
        )
        .expect("the sample invite is well formed")
    }

    #[test]
    fn reads_a_node_id_invite() {
        let payload = parse_invite(endpoint_invite().with_name("Home").to_uri()).unwrap();

        assert_eq!(payload.kind, "endpoint");
        // Recognisable, and not the thing: the preview is a surface.
        assert_eq!(payload.target_masked, credentials::mask(&node_id()));
        assert_ne!(payload.target_masked, node_id());
        assert_eq!(payload.name.as_deref(), Some("Home"));
        assert_eq!(payload.domains, vec!["a.example", "b.example"]);
        assert_eq!(payload.relay, None);
        assert!(payload.totp.is_none());
    }

    #[test]
    fn reads_a_ticket_invite() {
        let target = EndpointTarget::Ticket(
            iroh_tickets::endpoint::EndpointTicket::new(
                node_id()
                    .parse::<iroh::EndpointId>()
                    .expect("the sample node ID is well formed")
                    .into(),
            )
            .to_string(),
        );
        let invite =
            EndpointInvite::new(target.clone(), &[]).expect("the sample invite is well formed");

        let payload = parse_invite(invite.to_uri()).unwrap();
        assert_eq!(payload.kind, "ticket");
        assert_eq!(
            payload.target_masked,
            credentials::mask(&target.to_string())
        );
        assert!(
            !payload
                .target_masked
                .contains(&target.to_string()[8..target.to_string().len() - 8]),
            "the middle of the ticket must not reach the renderer"
        );
        assert!(payload.domains.is_empty());
    }

    #[test]
    fn reads_the_2fa_half() {
        let invite = endpoint_invite().with_totp(Some(
            InviteTotp::new("client-001", "jbswy3dpehpk3pxp").expect("the secret is valid base32"),
        ));

        let payload = parse_invite(invite.to_uri()).unwrap();
        assert!(payload.totp.is_some(), "the invite carries 2FA");

        // What is *not* here is the point: a secret the renderer cannot show is
        // one it cannot leak, and `accept_invite` files it without asking.
        let json: serde_json::Value = serde_json::to_value(&payload).unwrap();
        let totp = json["totp"]
            .as_object()
            .expect("the 2FA block travels whole");
        assert_eq!(totp["clientId"], "client-001");
        assert_eq!(totp["algorithm"], "sha1");
        assert!(
            totp.get("secret").is_none(),
            "a parsed invite must not carry its secret: {totp:?}"
        );
    }

    /// The frontend reads `invite.totp.clientId`, and only the multi-word key was ever at risk:
    /// `secret` and `algorithm` have no casing to disagree about, so a missing rename did not fail
    /// a parse — it produced a node with a secret and no client id, which every server then
    /// refuses. Pin the keys the UI actually sees.
    #[test]
    fn hands_the_2fa_half_to_the_frontend_in_camel_case() {
        let invite = endpoint_invite().with_totp(Some(
            InviteTotp::new("client-001", "jbswy3dpehpk3pxp").expect("the secret is valid base32"),
        ));

        let payload = parse_invite(invite.to_uri()).unwrap();
        let json: serde_json::Value = serde_json::to_value(&payload).unwrap();
        let totp = json["totp"]
            .as_object()
            .expect("the 2FA block travels whole");
        assert_eq!(totp["clientId"], "client-001");
        assert!(
            totp.get("client_id").is_none(),
            "keys must reach the UI as camelCase"
        );
    }

    /// A registration invite carries a token instead of a secret, and the UI has to be able
    /// to tell the two apart without guessing: it enrolls for one and stores credentials for
    /// the other.
    #[test]
    fn hands_a_registration_token_to_the_frontend_instead_of_a_secret() {
        let invite = endpoint_invite()
            .with_enrollment(Some(InviteEnrollment::new("client-001", "tok").unwrap()));

        let payload = parse_invite(invite.to_uri()).unwrap();
        let enrollment = payload
            .enrollment
            .clone()
            .expect("the invite carries a token");
        assert_eq!(enrollment.client_id, "client-001");
        assert!(payload.totp.is_none(), "a code cannot carry both");

        let json: serde_json::Value = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["enrollment"]["clientId"], "client-001");
        assert!(
            json["enrollment"].get("token").is_none(),
            "a parsed invite must not carry the token it is showing a summary of"
        );
    }

    #[test]
    fn reports_a_code_and_a_reason_when_the_link_is_not_an_invite() {
        let error = parse_invite("https://example.com".to_string()).unwrap_err();

        assert_eq!(error.code, codes::INVITE_PARSE_FAILED);
        assert!(
            error.detail.is_some(),
            "the parser's reason travels as detail"
        );
    }

    #[test]
    fn complete_lines_hold_back_a_trailing_fragment() {
        let (lines, consumed) = complete_lines("one\ntwo\nthree");

        assert_eq!(lines, vec!["one", "two"]);
        assert_eq!(
            consumed, 8,
            "only the bytes up to and including the last newline"
        );
    }

    #[test]
    fn complete_lines_accept_a_fully_terminated_buffer() {
        let (lines, consumed) = complete_lines("one\ntwo\n");

        assert_eq!(lines, vec!["one", "two"]);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn complete_lines_return_nothing_without_a_newline() {
        let (lines, consumed) = complete_lines("half a line");

        assert!(lines.is_empty());
        assert_eq!(consumed, 0);
    }
}
