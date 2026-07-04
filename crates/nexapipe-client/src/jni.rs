use crate::{IrohConnectionPool, LocalProxy};
use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static CONN_POOL: OnceCell<Arc<Mutex<Option<IrohConnectionPool>>>> = OnceCell::new();
static PROXY_DOMAINS: OnceCell<Arc<Mutex<Vec<String>>>> = OnceCell::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().unwrap())
}

fn get_conn_pool_mutex() -> &'static Arc<Mutex<Option<IrohConnectionPool>>> {
    CONN_POOL.get_or_init(|| Arc::new(Mutex::new(None)))
}

fn get_proxy_domains() -> &'static Arc<Mutex<Vec<String>>> {
    PROXY_DOMAINS.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeInit(_env: JNIEnv, _class: JClass) -> jint {
    let _ = get_runtime();
    let _ = get_conn_pool_mutex();
    let _ = get_proxy_domains();
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartIroh(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let runtime = get_runtime();
    let result = runtime.block_on(async {
        let endpoint_addr = crate::connection_pool::parse_endpoint_addr(None, None);
        match endpoint_addr {
            Ok(addr) => {
                let pool = IrohConnectionPool::new(addr).await;
                match pool {
                    Ok(p) => {
                        let node_id = p.node_id().to_string();
                        let pool_mutex = get_conn_pool_mutex();
                        let mut pool_guard = pool_mutex.lock().unwrap();
                        *pool_guard = Some(p);
                        Ok(node_id)
                    }
                    Err(e) => Err(format!("Failed to create connection pool: {}", e)),
                }
            }
            Err(e) => Err(format!("Failed to parse endpoint address: {}", e)),
        }
    });

    match result {
        Ok(node_id) => env.new_string(node_id).unwrap().into_raw(),
        Err(msg) => {
            #[cfg(feature = "tracing")]
            tracing::error!("{}", msg);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartProxy(
    mut env: JNIEnv,
    _class: JClass,
    listen_port: jint,
    target_endpoint_id: JString,
) -> jint {
    let target_id: String = env.get_string(&target_endpoint_id).unwrap().into();
    
    let runtime = get_runtime();
    let domains = get_proxy_domains().lock().unwrap().clone();
    
    let result = runtime.block_on(async {
        let endpoint_addr = crate::connection_pool::parse_endpoint_addr(Some(&target_id), None);
        match endpoint_addr {
            Ok(addr) => {
                let pool = IrohConnectionPool::new(addr).await;
                match pool {
                    Ok(p) => {
                        let pool_clone = p.clone();
                        let pool_mutex = get_conn_pool_mutex();
                        let mut pool_guard = pool_mutex.lock().unwrap();
                        *pool_guard = Some(p);
                        
                        let listen_addr = format!("127.0.0.1:{}", listen_port);
                        let proxy = LocalProxy::new(&listen_addr, domains, pool_clone).await;
                        match proxy {
                            Ok(proxy) => {
                                tokio::spawn(async move {
                                    let _ = proxy.run().await;
                                });
                                Ok(())
                            }
                            Err(e) => Err(format!("Failed to create local proxy: {}", e)),
                        }
                    }
                    Err(e) => Err(format!("Failed to create connection pool: {}", e)),
                }
            }
            Err(e) => Err(format!("Failed to parse endpoint address: {}", e)),
        }
    });

    match result {
        Ok(_) => 0,
        Err(msg) => {
            #[cfg(feature = "tracing")]
            tracing::error!("{}", msg);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopProxy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let pool_mutex = get_conn_pool_mutex();
    let mut pool_guard = pool_mutex.lock().unwrap();
    if let Some(pool) = pool_guard.as_ref() {
        let runtime = get_runtime();
        runtime.block_on(async {
            pool.close_all().await;
        });
    }
    *pool_guard = None;
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomain(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    let domains = get_proxy_domains();
    let mut domains_mut = domains.lock().unwrap();
    if !domains_mut.contains(&domain_str) {
        domains_mut.push(domain_str);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveDomain(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    let domains = get_proxy_domains();
    let mut domains_mut = domains.lock().unwrap();
    domains_mut.retain(|d| d != &domain_str);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    unsafe {
        Java_com_nexa_pipe_IrohProxy_nativeStopProxy(_env, _class)
    }
}
