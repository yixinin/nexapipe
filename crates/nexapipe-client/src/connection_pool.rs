use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;

#[cfg(feature = "tracing")]
use tracing;

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
const MAX_CONNECTIONS: usize = 10;
const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);

struct PooledConnection {
    conn: Connection,
    created_at: std::time::Instant,
}

#[derive(Clone)]
pub struct IrohConnectionPool {
    inner: Arc<IrohConnectionPoolInner>,
}

struct IrohConnectionPoolInner {
    connections: Mutex<Vec<PooledConnection>>,
    ep: Arc<Mutex<Option<Endpoint>>>,
    endpoint_addr: EndpointAddr,
}

impl IrohConnectionPool {
    pub async fn new(endpoint_addr: EndpointAddr) -> Result<Self, crate::error::ClientError> {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(Self {
            inner: Arc::new(IrohConnectionPoolInner {
                connections: Mutex::new(Vec::new()),
                ep: Arc::new(Mutex::new(Some(ep))),
                endpoint_addr,
            }),
        })
    }

    pub fn new_with_endpoint(ep: Endpoint, endpoint_addr: EndpointAddr) -> Self {
        Self {
            inner: Arc::new(IrohConnectionPoolInner {
                connections: Mutex::new(Vec::new()),
                ep: Arc::new(Mutex::new(Some(ep))),
                endpoint_addr,
            }),
        }
    }

    pub fn node_id(&self) -> EndpointId {
        match self.inner.ep.try_lock() {
            Ok(ep) => {
                if let Some(e) = ep.as_ref() {
                    e.id()
                } else {
                    EndpointId::from_bytes(&[0u8; 32]).expect("Failed to create default endpoint id")
                }
            }
            Err(_) => EndpointId::from_bytes(&[0u8; 32]).expect("Failed to create default endpoint id"),
        }
    }

    pub async fn get_connection(&self) -> Result<Connection, crate::error::ClientError> {
        let mut connections = self.inner.connections.lock().await;

        connections.retain(|pooled| pooled.created_at.elapsed() < tokio::time::Duration::from_secs(60));

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

    pub async fn return_connection(&self, conn: Connection) {
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

        let mut ep = self.inner.ep.lock().await;
        if let Some(endpoint) = ep.take() {
            #[cfg(feature = "tracing")]
            tracing::info!("Closing iroh endpoint");
            endpoint.close().await;
        }
    }
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
