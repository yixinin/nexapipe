pub mod client;
pub mod connection_pool;
pub mod endpoint_group;
pub mod error;
pub mod http;
pub mod lb;

#[cfg(feature = "local-proxy")]
pub mod local_proxy;

// TUN 代理：用 smoltcp 在 Rust 侧实现用户态 TCP/IP 栈，替代 Kotlin 手写 TCP 栈。
// 仅 Android 使用（依赖 tokio::io::unix::AsyncFd，Unix-only）。
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
pub mod tun_proxy;

#[cfg(feature = "uniffi")]
pub mod uniffi;

#[cfg(feature = "jni")]
pub mod jni;

pub use client::IrohProxyClient;
pub use connection_pool::IrohConnectionPool;
pub use endpoint_group::{EndpointGroup, NodeConfig, DomainMapping, PooledConnection};
pub use error::ClientError;
pub use http::{HttpRequest, HttpResponse};
pub use lb::LoadBalancingStrategy;

#[cfg(feature = "local-proxy")]
pub use local_proxy::LocalProxy;

#[cfg(feature = "uniffi")]
uniffi::include_scaffolding!("nexapipe_client");
