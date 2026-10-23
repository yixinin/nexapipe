// `setup_scaffolding!` (uniffi 0.25) expands to a comparison of two `extern "C"` fn
// pointers, which rustc warns about and no item-level `allow` can reach.
#![cfg_attr(feature = "uniffi", allow(unpredictable_function_pointer_comparisons))]
pub mod auth;
pub mod client;
pub mod connection_pool;
pub mod deadline;
pub mod discovery;
pub mod domains;
pub mod endpoint_group;
pub mod error;
pub mod flow;
pub mod http;
pub mod lb;
pub mod provisioning;
pub mod relay;
pub mod traffic;
pub mod transport;

// L4 tunnel: TCP and UDP to a server route's backend. Shares the local proxy's
// connection-pool plumbing (`open_stream_with_retry`), hence the same feature gate.
// The upstream DNS resolvers and the sockets they are asked through. The TUN
// hands every name the device looks up to these, and they keep one socket per
// resolver so a query does not cost a new source port every time.
// Not platform-gated so its tests run everywhere, including Windows.
#[cfg(feature = "tun-proxy")]
pub mod dns;

#[cfg(feature = "local-proxy")]
pub mod l4;

#[cfg(feature = "local-proxy")]
pub mod local_proxy;

// Virtual IP ↔ domain mapping: the DNS answers the TUN hands out carry one
// address per domain, and the reverse lookup is what turns a packet's
// destination back into a name (and therefore into a server route).
// Not platform-gated so its tests run everywhere, including Windows.
#[cfg(feature = "tun-proxy")]
pub mod virtual_ip;

// The block of addresses the tunnel claims, and the pools inside it. One
// address space on both clients: the desktop walks a list of candidate blocks
// and keeps the first the host will let it use, and Android takes the same
// list. The two halves have to agree on which block it is — the Kotlin side
// configures the VPN's addresses and routes, the Rust side hands out the
// per-domain addresses inside the same block — so it is one value rather than
// a constant compiled into each side.
#[cfg(feature = "tun-proxy")]
pub mod virtual_block;

// TUN proxy: implements a userspace TCP/IP stack in Rust with smoltcp. Shared by
// the Android client (fd-based entry point) and the desktop app (IP-packet
// reader/writer entry point); the fd plumbing itself is Android-gated inside.
#[cfg(feature = "tun-proxy")]
pub mod tun_proxy;

#[cfg(feature = "uniffi")]
// Named `uniffi_bindings` on purpose: a module called `uniffi` would shadow the external
// crate at the crate root, and `setup_scaffolding!` expands to `uniffi::ffi::...`.
pub mod uniffi_bindings;

#[cfg(feature = "jni")]
pub mod jni;

pub use client::IrohProxyClient;
pub use connection_pool::{IrohConnectionPool, LinkKind, LinkStatus};
pub use discovery::DiscoveryMode;
pub use domains::{DomainNotes, domain_notes, fold_domain, should_proxy_domain};
pub use endpoint_group::{
    DomainMapping, EndpointGroup, NodeConfig, PooledConnection, PreconnectReport,
};
pub use error::ClientError;
pub use flow::{FlowId, FlowKind, FlowRegistry, FlowView};
pub use http::{HttpRequest, HttpResponse};
pub use lb::LoadBalancingStrategy;
pub use nexapipe_proto::secret::{Secret, SecretBytes, SecretString};
pub use provisioning::{EndpointInvite, EndpointTarget, InviteTotp};
pub use relay::{PINNED_RELAY_URL, RelayModeSpec, RelayRestriction};
pub use transport::{Congestion, TransportTuning, transport_config, transport_config_with_tuning};

#[cfg(feature = "local-proxy")]
pub use local_proxy::LocalProxy;

#[cfg(feature = "uniffi")]
::uniffi::setup_scaffolding!();
