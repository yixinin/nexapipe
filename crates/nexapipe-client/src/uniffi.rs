use crate::client::IrohProxyClient;
use crate::http::{HttpRequest, HttpResponse};
use crate::ClientError;
use iroh::EndpointId;
use std::str::FromStr;
use uniffi::export;

#[export]
pub fn new_client(server_node_id: Option<String>, server_ticket: Option<String>) -> Result<IrohProxyClient, ClientError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| ClientError::IoError(e))?;
    
    let node_id_str = server_node_id.as_deref();
    let ticket_str = server_ticket.as_deref();
    
    rt.block_on(async move {
        crate::client::create_client(node_id_str, ticket_str).await
    })
}

#[export]
pub fn client_node_id(client: &IrohProxyClient) -> String {
    client.node_id().to_string()
}

#[export]
pub fn client_send_request(client: &IrohProxyClient, request: HttpRequest) -> Result<HttpResponse, ClientError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| ClientError::IoError(e))?;
    
    rt.block_on(async move {
        client.send_request(&request).await
    })
}

#[export]
pub fn client_send_raw(client: &IrohProxyClient, data: Vec<u8>) -> Result<Vec<u8>, ClientError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| ClientError::IoError(e))?;
    
    rt.block_on(async move {
        client.send_raw(&data).await
    })
}

#[export]
pub fn client_close(client: &IrohProxyClient) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    rt.block_on(async move {
        client.close().await;
    });
}
