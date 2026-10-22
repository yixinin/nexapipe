use crate::ClientError;
use crate::connection_pool::IrohConnectionPool;
use crate::http::{HttpRequest, HttpResponse};
use iroh::endpoint::Connection;
use iroh::{EndpointAddr, EndpointId};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const MAX_RESPONSE_SIZE: usize = 1024 * 1024 * 10;

/// Budget for a single request/response exchange, once a connection has been
/// borrowed from the pool.
///
/// Neither `open_bi` nor `read_to_end` carries a deadline of its own, so a peer
/// that accepts the stream but never answers would otherwise hold the caller
/// for as long as the process lives.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct IrohProxyClient {
    conn_pool: Arc<IrohConnectionPool>,
}

impl IrohProxyClient {
    pub async fn new(endpoint_addr: EndpointAddr) -> Result<Self, ClientError> {
        let conn_pool = Arc::new(IrohConnectionPool::new(endpoint_addr).await?);
        Ok(Self { conn_pool })
    }

    pub async fn new_with_pool(conn_pool: IrohConnectionPool) -> Self {
        Self {
            conn_pool: Arc::new(conn_pool),
        }
    }

    pub fn node_id(&self) -> EndpointId {
        self.conn_pool.node_id()
    }

    pub async fn send_request(&self, request: &HttpRequest) -> Result<HttpResponse, ClientError> {
        let conn = self.conn_pool.get_connection().await?;
        let response = exchange_over(&conn.conn, request.to_bytes().as_slice()).await?;
        // The borrow ends when this handle is dropped, which is here: the pool
        // owns the connection and this was only ever a handle to it.

        HttpResponse::parse(&response)
    }

    pub async fn send_raw(&self, data: &[u8]) -> Result<Vec<u8>, ClientError> {
        let conn = self.conn_pool.get_connection().await?;
        let response = exchange_over(&conn.conn, data).await?;
        // The borrow ends here; the pool still owns the connection.

        Ok(response)
    }

    /// Opens a bidirectional stream on a pooled connection and lends it to `f`.
    ///
    /// The borrow ends when `f` is done, whatever `f` does with the stream —
    /// the pool owns the connection and this is a handle to it.
    ///
    /// The streams are borrowed rather than moved, so they cannot leave the
    /// closure: the lease and the streams' lifetime are the same scope. A
    /// stream that outlived the lease would sit on a pooled connection, which
    /// the idle timeout may close underneath it. Use an async closure
    /// (`async |send, recv| ...`); an `async move` block would capture the
    /// borrows in a way the `AsyncFnOnce` bound cannot accept.
    ///
    /// It used to be `open_bi_stream`, which returned the two streams and
    /// dropped the connection: the pool never saw that connection again, so
    /// every call dialled a new one and the pool lost a slot each time. The
    /// streams go **into** the closure rather than out of it, so a connection
    /// cannot escape the pool with its slot already spent.
    pub async fn with_stream<T, F>(&self, f: F) -> Result<T, ClientError>
    where
        F: AsyncFnOnce(
            &mut iroh::endpoint::SendStream,
            &mut iroh::endpoint::RecvStream,
        ) -> Result<T, ClientError>,
    {
        let conn = self.conn_pool.get_connection().await?;
        let (mut send, mut recv) = conn.conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

        let result = f(&mut send, &mut recv).await;
        drop((send, recv));
        // The borrow ends here; the pool still owns the connection.
        result
    }

    pub async fn close(&self) {
        self.conn_pool.close_all().await;
    }
}

/// Writes `payload` on a fresh bidirectional stream and reads the peer's whole
/// reply, under `EXCHANGE_TIMEOUT`.
///
/// Free rather than a method, because the exchange is over a *connection* and
/// not over a pool: the callers that hold one — the single-endpoint client
/// here, the endpoint group behind the UniFFI surface — differ in where the
/// connection came from and not in what is done with it.
pub(crate) async fn exchange_over(
    conn: &Connection,
    payload: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let request = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

        send.write_all(payload).await?;
        send.finish().map_err(|e| anyhow::anyhow!(e))?;

        let response = recv
            .read_to_end(MAX_RESPONSE_SIZE)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok::<_, ClientError>(response)
    };

    timeout(EXCHANGE_TIMEOUT, request)
        .await
        .map_err(|_| ClientError::TimeoutError)?
}

pub async fn create_client(
    server_node_id: Option<&str>,
    server_ticket: Option<&str>,
) -> Result<IrohProxyClient, ClientError> {
    let endpoint_addr = crate::connection_pool::parse_endpoint_addr(server_node_id, server_ticket)?;
    IrohProxyClient::new(endpoint_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::Endpoint;
    use iroh::endpoint::presets;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The ALPN the tunnel speaks. The same bytes the client uses.
    const ALPN: &[u8] = b"\x05nexapipe";

    /// The connection comes back to the pool.
    ///
    /// It used to be dropped: `open_bi_stream` returned the two streams and
    /// let the connection go, so the pool never saw that connection again —
    /// every call dialled a new one, and the pool lost a slot each time.
    ///
    /// The far side's count of accepted connections is the outside view of
    /// that: one connection for three streams, or three.
    #[tokio::test]
    async fn a_stream_leaves_the_connection_in_the_pool() {
        // The far side: an endpoint that accepts and holds its connections.
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the far side binds");
        let server_addr = server.addr();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let Ok(accepting) = incoming.accept() else {
                    continue;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    // Hold the connection open for the rest of the test.
                    let _conn = accepting.await;
                    std::future::pending::<()>().await;
                });
            }
        });

        // This side: an endpoint, a pool over it, and the client.
        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");
        let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
        let client = IrohProxyClient::new_with_pool(pool).await;

        for _ in 0..3 {
            client
                .with_stream(
                    async |send: &mut iroh::endpoint::SendStream,
                           _recv: &mut iroh::endpoint::RecvStream| {
                        let _ = send.finish();
                        Ok::<(), ClientError>(())
                    },
                )
                .await
                .expect("the stream opens");
        }

        // Give the far side a moment to count what it was sent.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the three streams shared one connection"
        );
    }
}
