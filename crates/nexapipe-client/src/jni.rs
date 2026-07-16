use crate::{IrohConnectionPool, LocalProxy, EndpointGroup, NodeConfig, DomainMapping, LoadBalancingStrategy};
use iroh::Endpoint;
use iroh::endpoint::presets;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use ndk_context;
use once_cell::sync::OnceCell;
use std::panic;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Runtime, Builder};

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static ENDPOINT: Mutex<Option<Endpoint>> = Mutex::new(None);
static STATE: OnceCell<Arc<Mutex<ProxyState>>> = OnceCell::new();

struct ProxyState {
    conn_pool: Option<IrohConnectionPool>,
    endpoint_group: Option<Arc<EndpointGroup>>,
    local_proxy: Option<LocalProxy>,
    nodes: Vec<NodeConfig>,
    domain_mappings: Vec<DomainMapping>,
    domains: Vec<String>,
}

fn get_runtime() -> Option<&'static Runtime> {
    RUNTIME.get_or_try_init(|| Runtime::new()).ok()
}

fn get_endpoint() -> Option<Endpoint> {
    ENDPOINT.lock().ok()?.clone()
}

fn get_state() -> Option<&'static Arc<Mutex<ProxyState>>> {
    STATE.get()
}

fn init_state() -> &'static Arc<Mutex<ProxyState>> {
    STATE.get_or_init(|| Arc::new(Mutex::new(ProxyState {
        conn_pool: None,
        endpoint_group: None,
        local_proxy: None,
        nodes: Vec::new(),
        domain_mappings: Vec::new(),
        domains: Vec::new(),
    })))
}

#[cfg(feature = "jni")]
#[cfg(target_os = "android")]
pub(crate) fn android_log(level: log::Level, msg: &str) {
    log::log!(level, "{}", msg);
}

#[cfg(feature = "jni")]
#[cfg(not(target_os = "android"))]
pub(crate) fn android_log(_level: log::Level, msg: &str) {
    eprintln!("{}", msg);
}

#[cfg(feature = "jni")]
#[macro_export]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        $crate::jni::android_log(log::Level::Debug, &format!($($arg)*))
    };
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeInit(env: JNIEnv, _class: JClass) -> jint {
    #[cfg(target_os = "android")]
    {
        unsafe {
            let raw_env = env.get_raw();
            let mut raw_vm = std::ptr::null_mut();
            (**raw_env).GetJavaVM.unwrap()(raw_env, &mut raw_vm);
            ndk_context::initialize_android_context(raw_vm as *mut _, std::ptr::null_mut());
        }
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("NexaVpnService"),
        );
    }

    std::panic::set_hook(Box::new(|panic_info| {
        let msg = match panic_info.payload().downcast_ref::<&str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => s.as_str(),
                None => "Unknown panic",
            },
        };
        let location = panic_info.location().map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column())).unwrap_or_default();
        jni_log!("RUST PANIC: {}{}", msg, location);
    }));

    let rt = Builder::new_multi_thread()
        .thread_name("nexapipe-worker")
        .worker_threads(4)
        .enable_all()
        .build();
    
    match rt {
        Ok(rt) => {
            let _ = RUNTIME.set(rt);
        }
        Err(e) => {
            jni_log!("Failed to create tokio runtime: {}", e);
            return -1;
        }
    }
    let _ = init_state();
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartIroh(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartIroh");
        env.exception_clear().unwrap();
        return std::ptr::null_mut();
    }
    
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let result = runtime.block_on(async {
        if let Ok(mut guard) = ENDPOINT.lock() {
            if let Some(ep) = guard.as_ref() {
                return Ok(ep.id().to_string());
            }

            match Endpoint::builder(presets::N0).bind().await {
                Ok(ep) => {
                    let node_id = ep.id().to_string();
                    *guard = Some(ep);
                    Ok(node_id)
                }
                Err(e) => {
                    jni_log!("Failed to start iroh endpoint: {}", e);
                    Err(format!("Failed to start iroh endpoint: {}", e))
                }
            }
        } else {
            Err("Failed to lock endpoint mutex".to_string())
        }
    });

    match result {
        Ok(node_id) => {
            match env.new_string(node_id) {
                Ok(s) => s.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartProxy(
    env: JNIEnv,
    _class: JClass,
    listen_port: jint,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartProxy");
        env.exception_clear().unwrap();
        return -1;
    }
    
    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            return -1;
        }
    };

    let nodes: Vec<NodeConfig>;
    let domain_mappings: Vec<DomainMapping>;
    
    {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state mutex (poisoned)");
                return -1;
            }
        };
        nodes = guard.nodes.clone();
        domain_mappings = guard.domain_mappings.clone();
    }

    let listen_addr = format!("127.0.0.1:{}", listen_port);
    jni_log!("[DEBUG:jni] nativeStartProxy called for port {}", listen_port);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move {
            let endpoint_group: EndpointGroup;
            let proxy_domains: Vec<String>;

            if !domain_mappings.is_empty() {
                jni_log!("[DEBUG:jni] Using domain_mappings ({} entries)", domain_mappings.len());
                proxy_domains = domain_mappings.iter().map(|m| m.domain.clone()).collect();
                
                if let Some(ep) = get_endpoint() {
                    endpoint_group = match EndpointGroup::new_with_domain_mappings_and_endpoint(
                        domain_mappings,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        ep.clone(),
                    ).await {
                        Ok(eg) => eg,
                        Err(e) => {
                            jni_log!("Failed to create endpoint group: {}", e);
                            return Err(format!("Failed to create endpoint group: {}", e));
                        }
                    };
                } else {
                    endpoint_group = match EndpointGroup::new_with_domain_mappings(
                        domain_mappings,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                    ).await {
                        Ok(eg) => eg,
                        Err(e) => {
                            jni_log!("Failed to create endpoint group: {}", e);
                            return Err(format!("Failed to create endpoint group: {}", e));
                        }
                    };
                }
            } else if !nodes.is_empty() {
                jni_log!("[DEBUG:jni] Using nodes ({} entries)", nodes.len());
                proxy_domains = nodes.iter()
                    .flat_map(|node| node.domains.iter().cloned())
                    .collect();

                if proxy_domains.is_empty() {
                    jni_log!("No domains configured for nodes");
                    return Err("No domains configured for nodes".to_string());
                }

                if let Some(ep) = get_endpoint() {
                    endpoint_group = match EndpointGroup::new_with_nodes_and_endpoint(
                        nodes,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        ep.clone(),
                    ).await {
                        Ok(eg) => eg,
                        Err(e) => {
                            jni_log!("Failed to create endpoint group: {}", e);
                            return Err(format!("Failed to create endpoint group: {}", e));
                        }
                    };
                } else {
                    endpoint_group = match EndpointGroup::new_with_nodes(
                        nodes,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                    ).await {
                        Ok(eg) => eg,
                        Err(e) => {
                            jni_log!("Failed to create endpoint group: {}", e);
                            return Err(format!("Failed to create endpoint group: {}", e));
                        }
                    };
                }
            } else {
                jni_log!("No nodes or domain mappings configured");
                return Err("No nodes or domain mappings configured".to_string());
            }

            jni_log!("[DEBUG:jni] Creating LocalProxy on {}", listen_addr);
            let endpoint_group_arc = Arc::new(endpoint_group);
            let proxy = match LocalProxy::new(&listen_addr, proxy_domains, endpoint_group_arc.clone()).await {
                Ok(p) => {
                    jni_log!("[DEBUG:jni] LocalProxy created successfully");
                    p
                }
                Err(e) => {
                    jni_log!("[DEBUG:jni] Failed to create local proxy: {}", e);
                    return Err(format!("Failed to create local proxy: {}", e));
                }
            };

            {
                let mut guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        jni_log!("Failed to lock state mutex (poisoned)");
                        return Err("Failed to update state".to_string());
                    }
                };
                guard.local_proxy = Some(proxy.clone());
                guard.endpoint_group = Some(endpoint_group_arc);
            }

            runtime.spawn(async move {
                let proxy_run = match panic::catch_unwind(panic::AssertUnwindSafe(|| async move {
                    proxy.run().await
                })) {
                    Ok(future) => future,
                    Err(_) => {
                        jni_log!("Proxy run panicked during setup");
                        return;
                    }
                };
                match proxy_run.await {
                    Err(e) => jni_log!("Proxy run failed: {}", e),
                    Ok(_) => jni_log!("Proxy run completed"),
                }
            });

            Ok(())
        })
    }));

    match result {
        Ok(Ok(_)) => {
            jni_log!("[DEBUG:jni] nativeStartProxy returning success");
            0
        }
        Ok(Err(e)) => {
            jni_log!("[DEBUG:jni] Proxy start error: {}", e);
            -1
        }
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during proxy start");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartProxyLegacy(
    mut env: JNIEnv,
    _class: JClass,
    listen_port: jint,
    target_endpoint_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartProxyLegacy");
        env.exception_clear().unwrap();
        return -1;
    }
    
    let target_id = match env.get_string(&target_endpoint_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert target endpoint ID to string");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get target endpoint ID from JNI");
            return -1;
        }
    };

    if target_id.is_empty() {
        jni_log!("Target endpoint ID is empty");
        return -1;
    }

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            return -1;
        }
    };

    let domains: Vec<String> = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state mutex (poisoned)");
                return -1;
            }
        };
        guard.domains.clone()
    };

    let listen_addr = format!("127.0.0.1:{}", listen_port);

    let result = runtime.block_on(async move {
        match crate::connection_pool::parse_endpoint_addr(Some(&target_id), None) {
            Ok(addr) => {
                let pool: IrohConnectionPool;
                if let Some(ep) = get_endpoint() {
                    pool = IrohConnectionPool::new_with_endpoint(ep.clone(), addr);
                } else {
                    match IrohConnectionPool::new(addr).await {
                        Ok(p) => pool = p,
                        Err(e) => {
                            jni_log!("Failed to create connection pool: {}", e);
                            return Err(format!("Failed to create connection pool: {}", e));
                        }
                    }
                }

                match LocalProxy::new_with_single_pool(&listen_addr, domains, pool.clone()).await {
                    Ok(proxy) => {
                        {
                            let mut guard = match state.lock() {
                                Ok(g) => g,
                                Err(_) => {
                                    jni_log!("Failed to lock state mutex (poisoned)");
                                    return Err("Failed to update state".to_string());
                                }
                            };
                            guard.conn_pool = Some(pool);
                        }

                        tokio::spawn(async move {
                            let proxy_run = match panic::catch_unwind(panic::AssertUnwindSafe(|| async move {
                                proxy.run().await
                            })) {
                                Ok(future) => future,
                                Err(_) => {
                                    jni_log!("Proxy run panicked during setup");
                                    return;
                                }
                            };
                            match proxy_run.await {
                                Err(e) => jni_log!("Proxy run failed: {}", e),
                                Ok(_) => jni_log!("Proxy run completed"),
                            }
                        });

                        Ok(())
                    }
                    Err(e) => {
                        jni_log!("Failed to create local proxy: {}", e);
                        Err(format!("Failed to create local proxy: {}", e))
                    }
                }
            }
            Err(e) => {
                jni_log!("Failed to parse endpoint address: {}", e);
                Err(format!("Failed to parse endpoint address: {}", e))
            }
        }
    });

    match result {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopProxy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativeStopProxy called");
    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] State not initialized, nothing to stop");
            return 0;
        }
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => {
            jni_log!("[DEBUG:jni] Failed to lock state, aborting stop");
            return 0;
        }
    };

    jni_log!("[DEBUG:jni] Stop: endpoint_group exists = {}, conn_pool exists = {}, local_proxy exists = {}",
        guard.endpoint_group.is_some(), guard.conn_pool.is_some(), guard.local_proxy.is_some());

    if let Some(proxy) = guard.local_proxy.as_ref() {
        proxy.stop();
        jni_log!("[DEBUG:jni] LocalProxy stopped");
    }

    if let Some(group) = guard.endpoint_group.as_ref() {
        let runtime = get_runtime();
        if let Some(r) = runtime {
            r.block_on(async {
                group.close_all().await;
            });
        }
    }
    
    if let Some(pool) = guard.conn_pool.as_ref() {
        let runtime = get_runtime();
        if let Some(r) = runtime {
            r.block_on(async {
                pool.close_all().await;
            });
        }
    }
    
    guard.conn_pool = None;
    guard.endpoint_group = None;
    guard.local_proxy = None;
    
    if let Ok(mut guard) = ENDPOINT.lock() {
        guard.take();
    }
    jni_log!("[DEBUG:jni] nativeStopProxy returning after cleanup");
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddNode(
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
    domains: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddNode");
        env.exception_clear().unwrap();
        return -1;
    }
    
    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let domains_str = match env.get_string(&domains) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let domains_list: Vec<String> = domains_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

    if domains_list.is_empty() {
        jni_log!("Warning: Domains list is empty for node: {}", node_id_str);
    }

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let node_config = NodeConfig {
        server_node_id: Some(node_id_str),
        server_ticket: None,
        domains: domains_list,
    };

    guard.nodes.push(node_config);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomainMapping(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
    node_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddDomainMapping");
        env.exception_clear().unwrap();
        return -1;
    }
    
    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let domain_mapping = DomainMapping {
        domain: domain_str,
        server_node_id: Some(node_id_str),
        server_ticket: None,
    };

    guard.domain_mappings.push(domain_mapping);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveNode(
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeRemoveNode");
        env.exception_clear().unwrap();
        return -1;
    }
    
    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    guard.nodes.retain(|n| n.server_node_id.as_deref() != Some(&node_id_str));
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeClearNodes(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let state = match get_state() {
        Some(s) => s,
        None => return 0,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    guard.nodes.clear();
    guard.domain_mappings.clear();
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomain(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddDomain");
        env.exception_clear().unwrap();
        return -1;
    }
    
    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    if !guard.domains.contains(&domain_str) {
        guard.domains.push(domain_str);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveDomain(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeRemoveDomain");
        env.exception_clear().unwrap();
        return -1;
    }
    
    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    guard.domains.retain(|d| d != &domain_str);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    Java_com_nexa_pipe_IrohProxy_nativeStopProxy(_env, _class)
}