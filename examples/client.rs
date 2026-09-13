//! Client example: connect to the iroh proxy
//!
//! Usage:
//! 1. Start the proxy server and get its Ticket
//! 2. Pass that Ticket to this client

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use iroh_tickets::endpoint::EndpointTicket;

const ALPN_HTTP3: &[u8] = b"\x05http/3";
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1 MB

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Get the Ticket from the command-line argument or the environment
    let ticket_str = std::env::args().nth(1).expect("Usage: client <ticket>");

    println!("Connecting to proxy with ticket: {}...", ticket_str);

    // Parse the Ticket
    let ticket: EndpointTicket = ticket_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse ticket: {}", e))?;

    // Get the endpoint address
    let endpoint_addr: EndpointAddr = ticket.into();

    // Create the client Endpoint
    let ep = Endpoint::builder(presets::N0).bind().await?;

    // Connect to the proxy server
    println!("Establishing connection...");
    let conn = ep
        .connect(endpoint_addr, ALPN_HTTP3)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect: {}", e))?;

    println!("Connected successfully!");

    // Open a bidirectional stream
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open bidirectional stream: {}", e))?;

    // Build the HTTP request
    let request = construct_http_request("GET", "/", "example.com");

    println!("Sending request:\n{}", request);

    // Send the request
    send.write_all(request.as_bytes()).await?;
    send.finish()
        .map_err(|e| anyhow::anyhow!("Failed to finish stream: {}", e))?;

    // Receive the response
    let response = recv.read_to_end(MAX_RESPONSE_SIZE).await?;

    println!(
        "\nReceived response:\n{}",
        String::from_utf8_lossy(&response)
    );

    Ok(())
}

fn construct_http_request(method: &str, path: &str, host: &str) -> String {
    format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        method, path, host
    )
}
