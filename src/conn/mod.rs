use crate::http;
use crate::routes::{BackendInfo, RouteConfig};
use iroh::endpoint::{Connection, Incoming};
use std::sync::Arc;

pub async fn handle_bidi_stream(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    config: &RouteConfig,
) -> anyhow::Result<()> {
    let buf = recv.read_to_end(http::get_max_request_size()).await?;

    let request = http::parse_http_request(&buf)?;

    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h));

    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path());

    let backend_info: BackendInfo = match host {
        Some(h) => config.get_backend(h, path).await,
        None => BackendInfo {
            url: config.default_backend().to_string(),
            verify_cert: true,
        },
    };

    tracing::debug!(
        "Request: host={:?}, path={} -> backend={}, verify_cert={}",
        host,
        path,
        backend_info.url,
        backend_info.verify_cert
    );
    tracing::debug!("Received request: {} {}", request.method(), request.uri());

    let response = http::proxy_to_backend(&request, &backend_info.url, backend_info.verify_cert).await?;
    tracing::debug!("Proxy response status: {}", response.status());

    http::send_response(send, &response).await?;

    Ok(())
}

pub async fn handle_connection(conn: Connection, config: Arc<RouteConfig>) {
    let peer_id = conn.remote_id();
    tracing::info!("New connection from peer: {}", peer_id);

    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let config_clone = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_bidi_stream(&mut send, &mut recv, &config_clone).await {
                        tracing::error!("Failed to handle stream from {}: {}", peer_id, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Connection {} stream accept error: {}", peer_id, e);
                break;
            }
        }
    }

    tracing::info!("Connection closed for peer: {}", peer_id);
}

pub async fn handle_incoming(incoming: Incoming, config: Arc<RouteConfig>) {
    match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => {
                tokio::spawn(async move {
                    handle_connection(conn, config).await;
                });
            }
            Err(e) => {
                tracing::error!("Failed to complete connection: {}", e);
            }
        },
        Err(e) => {
            tracing::error!("Failed to accept incoming connection: {}", e);
        }
    }
}
