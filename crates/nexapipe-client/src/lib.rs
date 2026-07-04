pub mod client;
pub mod connection_pool;
pub mod error;
pub mod http;

#[cfg(feature = "local-proxy")]
pub mod local_proxy;

#[cfg(feature = "uniffi")]
pub mod uniffi;

#[cfg(feature = "jni")]
pub mod jni;

pub use client::IrohProxyClient;
pub use connection_pool::IrohConnectionPool;
pub use error::ClientError;
pub use http::{HttpRequest, HttpResponse};

#[cfg(feature = "local-proxy")]
pub use local_proxy::LocalProxy;

#[cfg(feature = "uniffi")]
uniffi::include_scaffolding!("nexapipe_client");
