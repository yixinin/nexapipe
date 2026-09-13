//! 客户端示例：连接到 iroh 代理
//!
//! 使用方法：
//! 1. 运行代理服务，获取 Ticket
//! 2. 将 Ticket 传递给此客户端

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use iroh_tickets::endpoint::EndpointTicket;

const ALPN_HTTP3: &[u8] = b"\x05http/3";
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 从命令行参数或环境变量获取 Ticket
    let ticket_str = std::env::args().nth(1).expect("Usage: client <ticket>");

    println!("Connecting to proxy with ticket: {}...", ticket_str);

    // 解析 Ticket
    let ticket: EndpointTicket = ticket_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse ticket: {}", e))?;

    // 获取端点地址
    let endpoint_addr: EndpointAddr = ticket.into();

    // 创建客户端 Endpoint
    let ep = Endpoint::builder(presets::N0).bind().await?;

    // 连接到代理服务器
    println!("Establishing connection...");
    let conn = ep
        .connect(endpoint_addr, ALPN_HTTP3)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect: {}", e))?;

    println!("Connected successfully!");

    // 打开双向流
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open bidirectional stream: {}", e))?;

    // 构造 HTTP 请求
    let request = construct_http_request("GET", "/", "example.com");

    println!("Sending request:\n{}", request);

    // 发送请求
    send.write_all(request.as_bytes()).await?;
    send.finish()
        .map_err(|e| anyhow::anyhow!("Failed to finish stream: {}", e))?;

    // 接收响应
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
