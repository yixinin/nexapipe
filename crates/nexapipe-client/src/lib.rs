pub mod client;
pub mod connection_pool;
pub mod endpoint_group;
pub mod error;
pub mod http;
pub mod lb;

#[cfg(feature = "local-proxy")]
pub mod local_proxy;

#[cfg(feature = "uniffi")]
pub mod uniffi;

#[cfg(feature = "jni")]
pub mod jni;

pub use client::IrohProxyClient;
pub use connection_pool::IrohConnectionPool;
pub use endpoint_group::{EndpointGroup, NodeConfig, PooledConnection};
pub use error::ClientError;
pub use http::{HttpRequest, HttpResponse};
pub use lb::LoadBalancingStrategy;

#[cfg(feature = "local-proxy")]
pub use local_proxy::LocalProxy;

#[cfg(feature = "uniffi")]
uniffi::include_scaffolding!("nexapipe_client");
