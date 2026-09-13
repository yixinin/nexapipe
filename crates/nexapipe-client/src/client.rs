use crate::connection_pool::IrohConnectionPool;
use crate::http::{HttpRequest, HttpResponse};
use crate::ClientError;
use iroh::{EndpointAddr, EndpointId};
use std::sync::Arc;

#[cfg(feature = "uniffi")]
use uniffi::export;

const MAX_RESPONSE_SIZE: usize = 1024 * 1024 * 10;

#[derive(Clone)]
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
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

        send.write_all(request.to_bytes().as_slice()).await?;
        send.finish().map_err(|e| anyhow::anyhow!(e))?;

        let response = recv.read_to_end(MAX_RESPONSE_SIZE).await.map_err(|e| anyhow::anyhow!(e))?;
        self.conn_pool.return_connection(conn).await;

        HttpResponse::parse(&response)
    }

    pub async fn send_raw(&self, data: &[u8]) -> Result<Vec<u8>, ClientError> {
        let conn = self.conn_pool.get_connection().await?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

        send.write_all(data).await?;
        send.finish().map_err(|e| anyhow::anyhow!(e))?;

        let response = recv.read_to_end(MAX_RESPONSE_SIZE).await.map_err(|e| anyhow::anyhow!(e))?;
        self.conn_pool.return_connection(conn).await;

        Ok(response)
    }

    pub async fn open_bi_stream(&self) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream), ClientError> {
        let conn = self.conn_pool.get_connection().await?;
        let (send, recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;
        
        Ok((send, recv))
    }

    pub async fn close(&self) {
        self.conn_pool.close_all().await;
    }
}

pub async fn create_client(
    server_node_id: Option<&str>,
    server_ticket: Option<&str>,
) -> Result<IrohProxyClient, ClientError> {
    let endpoint_addr = crate::connection_pool::parse_endpoint_addr(server_node_id, server_ticket)?;
    IrohProxyClient::new(endpoint_addr).await
}
