use crate::{IrohConnectionPool, LocalProxy};
use iroh::Endpoint;
use iroh::endpoint::presets;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static ENDPOINT: OnceCell<Endpoint> = OnceCell::new();
static STATE: OnceCell<Arc<Mutex<ProxyState>>> = OnceCell::new();

struct ProxyState {
    conn_pool: Option<IrohConnectionPool>,
    domains: Vec<String>,
}

fn get_runtime() -> Option<&'static Runtime> {
    RUNTIME.get_or_try_init(|| Runtime::new()).ok()
}

fn get_endpoint() -> Option<&'static Endpoint> {
    ENDPOINT.get()
}

fn get_state() -> Option<&'static Arc<Mutex<ProxyState>>> {
    STATE.get()
}

fn init_state() -> &'static Arc<Mutex<ProxyState>> {
    STATE.get_or_init(|| Arc::new(Mutex::new(ProxyState {
        conn_pool: None,
        domains: Vec::new(),
    })))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeInit(_env: JNIEnv, _class: JClass) -> jint {
    match Runtime::new() {
        Ok(rt) => {
            let _ = RUNTIME.set(rt);
        }
        Err(e) => {
            eprintln!("Failed to create tokio runtime: {}", e);
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
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let result = runtime.block_on(async {
        if let Some(ep) = ENDPOINT.get() {
            return Ok(ep.id().to_string());
        }

        match Endpoint::builder(presets::N0).bind().await {
            Ok(ep) => {
                let node_id = ep.id().to_string();
                match ENDPOINT.set(ep) {
                    Ok(_) => Ok(node_id),
                    Err(e) => {
                        eprintln!("Endpoint already exists: {}", e.id());
                        Ok(e.id().to_string())
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to start iroh endpoint: {}", e);
                Err(format!("Failed to start iroh endpoint: {}", e))
            }
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
    mut env: JNIEnv,
    _class: JClass,
    listen_port: jint,
    target_endpoint_id: JString,
) -> jint {
    let target_id = match env.get_string(&target_endpoint_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                eprintln!("Failed to convert target endpoint ID to string");
                return -1;
            }
        },
        Err(_) => {
            eprintln!("Failed to get target endpoint ID from JNI");
            return -1;
        }
    };

    if target_id.is_empty() {
        eprintln!("Target endpoint ID is empty");
        return -1;
    }

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            eprintln!("Runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            eprintln!("State not initialized");
            return -1;
        }
    };

    let domains: Vec<String> = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                eprintln!("Failed to lock state mutex (poisoned)");
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
                            eprintln!("Failed to create connection pool: {}", e);
                            return Err(format!("Failed to create connection pool: {}", e));
                        }
                    }
                }

                match LocalProxy::new(&listen_addr, domains, pool.clone()).await {
                    Ok(proxy) => {
                        {
                            let mut guard = match state.lock() {
                                Ok(g) => g,
                                Err(_) => {
                                    eprintln!("Failed to lock state mutex (poisoned)");
                                    return Err("Failed to update state".to_string());
                                }
                            };
                            guard.conn_pool = Some(pool);
                        }

                        tokio::spawn(async move {
                            if let Err(e) = proxy.run().await {
                                eprintln!("Proxy run failed: {}", e);
                            }
                        });

                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Failed to create local proxy: {}", e);
                        Err(format!("Failed to create local proxy: {}", e))
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to parse endpoint address: {}", e);
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
    let state = match get_state() {
        Some(s) => s,
        None => return 0,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    if let Some(pool) = guard.conn_pool.as_ref() {
        let runtime = get_runtime();
        if let Some(r) = runtime {
            r.block_on(async {
                pool.close_all().await;
            });
        }
    }
    guard.conn_pool = None;
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomain(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
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
