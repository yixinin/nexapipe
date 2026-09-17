pub mod client;
pub mod connection_pool;
pub mod endpoint_group;
pub mod error;
pub mod http;
pub mod lb;
pub mod transport;

#[cfg(feature = "local-proxy")]
pub mod local_proxy;

// TUN proxy: implements a userspace TCP/IP stack in Rust with smoltcp, replacing the
// hand-written Kotlin TCP stack.
// Android only (relies on tokio::io::unix::AsyncFd, which is Unix-only).
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
pub use transport::{TransportTuning, transport_config, transport_config_with_tuning};

#[cfg(feature = "local-proxy")]
pub use local_proxy::LocalProxy;

#[cfg(feature = "uniffi")]
uniffi::include_scaffolding!("nexapipe_client");
pub mod auth;
