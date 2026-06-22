use crate::config::LocalProxyConfig;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use iroh_tickets::endpoint::EndpointTicket;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const ALPN_HTTP3: &[u8] = b"\x05http/3";
const MAX_RESPONSE_SIZE: usize = 1024 * 1024 * 10; // 10MB

pub async fn run_local_proxy(config: LocalProxyConfig) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr.clone();
    let proxy_domains = Arc::new(config.proxy_domains);
    let server_ticket = config.server_ticket;

    tracing::info!("Starting local proxy on: {}", listen_addr);
    tracing::info!("Proxy domains: {:?}", proxy_domains);

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("Local proxy listener bound successfully");

    let ep = Endpoint::builder(presets::N0).bind().await?;
    let node_id = ep.id();
    tracing::info!("Iroh client endpoint started, node ID: {}", node_id);

    let ticket_str = if let Some(ticket) = server_ticket {
        ticket
    } else {
        println!("Enter server ticket:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let ticket: EndpointTicket = ticket_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse ticket: {}", e))?;
    let endpoint_addr: EndpointAddr = ticket.into();

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::debug!("New connection from: {}", addr);

                let proxy_domains_clone = proxy_domains.clone();
                let ep_clone = ep.clone();
                let endpoint_addr_clone = endpoint_addr.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_local_connection(
                        stream,
                        proxy_domains_clone,
                        ep_clone,
                        endpoint_addr_clone,
                    )
                    .await
                    {
                        tracing::error!("Failed to handle local connection: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_local_connection(
    mut stream: tokio::net::TcpStream,
    proxy_domains: Arc<Vec<String>>,
    ep: Endpoint,
    endpoint_addr: EndpointAddr,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buf[..n]);
    let host = extract_host(&request_str);

    if host.is_none() {
        tracing::warn!("No host header found in request");
        return Ok(());
    }

    let host = host.unwrap();
    let should_proxy = should_proxy_domain(&host, &proxy_domains);

    if !should_proxy {
        tracing::debug!("Host {} not in proxy domains, skipping", host);
        return Ok(());
    }

    tracing::info!("Proxying request for host: {}", host);

    let conn = ep.connect(endpoint_addr, ALPN_HTTP3).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    send.write_all(&buf[..n]).await?;
    send.finish()?;

    let response = recv.read_to_end(MAX_RESPONSE_SIZE).await?;
    stream.write_all(&response).await?;

    Ok(())
}

fn extract_host(request: &str) -> Option<&str> {
    for line in request.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host = line.trim_start_matches("host:").trim();
            return Some(host.split(':').next().unwrap_or(host));
        }
    }
    None
}

fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    for domain in proxy_domains {
        if domain.starts_with('*') {
            let suffix = &domain[1..];
            if host.ends_with(suffix) {
                return true;
            }
        } else if host == domain {
            return true;
        }
    }
    false
}
