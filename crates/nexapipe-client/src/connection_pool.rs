use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;

#[cfg(feature = "tracing")]
use tracing;

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
const MAX_CONNECTIONS: usize = 10;
const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Idle connections older than this are evicted when a new connection is requested.
const CONNECTION_IDLE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);
/// Interval of the background watcher that removes closed/stale connections from the pool.
const CONNECTION_CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);
/// Per-pool timeout for preconnect / warm-up. Much shorter than CONNECTION_TIMEOUT
/// so that a single unreachable node does not hold up the entire preconnect phase.
pub(crate) const PRECONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);

struct PooledConnection {
    conn: Connection,
    created_at: std::time::Instant,
}

impl PooledConnection {
    /// True if the underlying iroh connection is still open (not closed by either side).
    fn is_live(&self) -> bool {
        self.conn.close_reason().is_none()
    }
}

#[derive(Clone)]
pub struct IrohConnectionPool {
    inner: Arc<IrohConnectionPoolInner>,
}

struct IrohConnectionPoolInner {
    connections: Mutex<Vec<PooledConnection>>,
    ep: Arc<Mutex<Option<Endpoint>>>,
    endpoint_addr: EndpointAddr,
    /// Whether this pool created (and therefore owns) its iroh endpoint.
    ///
    /// `new()` binds a dedicated endpoint, so `close_all` must close it.
    /// `new_with_endpoint()` shares a caller-owned endpoint (e.g. the global
    /// ENDPOINT in the Android JNI layer); closing it here would break the
    /// next `nativeStartProxy`/`nativePreconnect` with "Endpoint is closed"
    /// and tear down a running tunnel on proxy restart / reconnect.
    owns_endpoint: bool,
}

impl IrohConnectionPool {
    pub async fn new(endpoint_addr: EndpointAddr) -> Result<Self, crate::error::ClientError> {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            owns_endpoint: true,
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    pub fn new_with_endpoint(ep: Endpoint, endpoint_addr: EndpointAddr) -> Self {
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            owns_endpoint: false,
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Self { inner }
    }

    pub fn node_id(&self) -> EndpointId {
        match self.inner.ep.try_lock() {
            Ok(ep) => {
                if let Some(e) = ep.as_ref() {
                    e.id()
                } else {
                    EndpointId::from_bytes(&[0u8; 32])
                        .expect("Failed to create default endpoint id")
                }
            }
            Err(_) => {
                EndpointId::from_bytes(&[0u8; 32]).expect("Failed to create default endpoint id")
            }
        }
    }

    pub async fn get_connection(&self) -> Result<Connection, crate::error::ClientError> {
        let mut connections = self.inner.connections.lock().await;

        // Drop stale connections before handing one out: anything already closed
        // by the peer, or idle for longer than CONNECTION_IDLE_TIMEOUT.
        connections.retain(|pooled| {
            pooled.created_at.elapsed() < CONNECTION_IDLE_TIMEOUT && pooled.is_live()
        });

        if let Some(pooled) = connections.pop() {
            return Ok(pooled.conn);
        }

        drop(connections);

        let ep = self.inner.ep.lock().await;
        let ep = ep.as_ref().ok_or_else(|| {
            crate::error::ClientError::InvalidConfig("Endpoint has been closed".to_string())
        })?;

        let conn = tokio::time::timeout(
            CONNECTION_TIMEOUT,
            ep.connect(self.inner.endpoint_addr.clone(), ALPN_NEXAPIPE),
        )
        .await
        .map_err(|_| crate::error::ClientError::TimeoutError)?
        .map_err(|e| anyhow::anyhow!(e))?;

        let conn_clone = conn.clone();
        tokio::spawn(async move {
            let mut path_events = conn_clone.path_events();
            while let Some(event) = path_events.next().await {
                match event {
                    iroh::endpoint::PathEvent::Selected { remote_addr, .. } => {
                        if remote_addr.is_ip() {
                            #[cfg(feature = "tracing")]
                            tracing::info!("Connection upgraded: Relay -> Direct");
                        } else if remote_addr.is_relay() {
                            #[cfg(feature = "tracing")]
                            tracing::info!("Connection downgraded: Direct -> Relay");
                        }
                    }
                    iroh::endpoint::PathEvent::Opened { remote_addr, .. } => {
                        if remote_addr.is_ip() {
                            #[cfg(feature = "tracing")]
                            tracing::info!("Direct path opened");
                        } else if remote_addr.is_relay() {
                            #[cfg(feature = "tracing")]
                            tracing::info!("Relay path opened");
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(conn)
    }

    /// Ensure at least one live connection to the backend is cached in the
    /// pool, establishing one if the pool is empty. Used for pre-connect /
    /// warm-up so the first real request does not pay the QUIC/relay handshake
    /// latency. Returns true if a connection is available in the pool
    /// afterwards.
    pub async fn preconnect(&self) -> bool {
        {
            let connections = self.inner.connections.lock().await;
            if let Some(pooled) = connections.last() {
                if pooled.is_live() {
                    return true;
                }
            }
        }

        let conn = {
            let ep = self.inner.ep.lock().await;
            let Some(ep) = ep.as_ref() else {
                return false;
            };
            match tokio::time::timeout(
                CONNECTION_TIMEOUT,
                ep.connect(self.inner.endpoint_addr.clone(), ALPN_NEXAPIPE),
            )
            .await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("preconnect failed: {}", e);
                    return false;
                }
                Err(_) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("preconnect timed out");
                    return false;
                }
            }
        };

        self.return_connection(conn).await;
        true
    }

    pub async fn return_connection(&self, conn: Connection) {
        // Never pool a connection that has already been closed: handing it out
        // again would just fail on the next request. The background watcher also
        // reaps such connections, but checking here avoids re-inserting them.
        if conn.close_reason().is_some() {
            return;
        }

        let mut connections = self.inner.connections.lock().await;
        if connections.len() < MAX_CONNECTIONS {
            connections.push(PooledConnection {
                conn,
                created_at: std::time::Instant::now(),
            });
        }
    }

    pub async fn close_all(&self) {
        let mut connections = self.inner.connections.lock().await;
        connections.clear();

        // Only close the endpoint if this pool owns it (created via `new()`).
        // Pools created via `new_with_endpoint()` share a caller-owned endpoint
        // (e.g. the global ENDPOINT in the Android JNI layer); closing it here
        // would break the next `nativeStartProxy`/`nativePreconnect` with
        // "Endpoint is closed" and tear down a running tunnel on reconnect.
        if !self.inner.owns_endpoint {
            return;
        }

        let mut ep = self.inner.ep.lock().await;
        if let Some(endpoint) = ep.take() {
            #[cfg(feature = "tracing")]
            tracing::info!("Closing iroh endpoint");
            endpoint.close().await;
        }
    }
}

/// Spawn a background task that periodically drops closed connections from the
/// pool. It holds only a [`Weak`] reference so it exits once the pool itself is
/// dropped (e.g. on shutdown), and never keeps the pool alive on its own.
fn spawn_cleanup_task(inner: Weak<IrohConnectionPoolInner>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CONNECTION_CLEANUP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(inner) = inner.upgrade() else {
                // Pool dropped; nothing left to clean.
                break;
            };
            let mut connections = inner.connections.lock().await;
            let before = connections.len();
            connections.retain(|pooled| pooled.is_live());
            let removed = before - connections.len();
            if removed > 0 {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    "Connection pool cleanup: removed {} closed connection(s)",
                    removed
                );
            }
        }
    });
}

pub fn parse_endpoint_addr(
    server_node_id: Option<&str>,
    server_ticket: Option<&str>,
) -> Result<EndpointAddr, crate::error::ClientError> {
    if let Some(node_id_str) = server_node_id {
        let endpoint_id: EndpointId = node_id_str.parse().map_err(|e| {
            crate::error::ClientError::ParseError(format!("Failed to parse server_node_id: {}", e))
        })?;
        Ok(endpoint_id.into())
    } else if let Some(ticket_str) = server_ticket {
        if let Ok(ticket) = ticket_str.parse::<EndpointTicket>() {
            Ok(ticket.into())
        } else {
            let endpoint_id: EndpointId = ticket_str.parse().map_err(|e| {
                crate::error::ClientError::ParseError(format!(
                    "Failed to parse as ticket or node ID: {}",
                    e
                ))
            })?;
            Ok(endpoint_id.into())
        }
    } else {
        Err(crate::error::ClientError::InvalidConfig(
            "Either server_node_id or server_ticket must be provided".to_string(),
        ))
    }
}
