//! TUN proxy: a user-space TCP/IP stack implemented in Rust with netstack-smoltcp, replacing the Kotlin hand-written TCP stack.
//!
//! Data flow:
//! ```text
//! APP → TUN fd → Rust(AsyncFd) → Stack(Sink: IP packets in)
//!                                  ↓ smoltcp processing
//!                           ┌──────┴──────┐
//!                      TcpListener    UdpSocket
//!                      (TCP connections) (DNS queries)
//!                           │              │
//!                           ↓              ↓
//!                    10.0.1.3:80,443    resolve domain
//!                    (proxied traffic)      │
//!                           │            ↓
//!               handle_local_     proxy→10.0.1.3
//!               connection       other→forward to real DNS
//!               (→iroh→backend)   (tokio UdpSocket)
//!                           │
//!                Stack(Stream: IP packets out) → AsyncFd → write back to TUN fd
//! ```

use crate::ClientError;
use crate::EndpointGroup;
use crate::local_proxy::{handle_local_connection, should_proxy_domain};

#[cfg(feature = "jni")]
use crate::jni_log;

#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {};
}

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener as SmolTcpListener};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;

// Virtual IP constants — must match the TUN config in the Kotlin-side NexaVpnService.
// 10.0.1.2 = DNS server (smoltcp UdpSocket receives DNS queries)
// 10.0.1.3 = proxy IP (TCP connections go through handle_local_connection → iroh)
/// Virtual DNS server IP — documented only; matches Kotlin-side NexaVpnService.virtualDNSIP.
/// The DNS query's dst_addr is this IP, and it is used as-is as the src_addr in the response.
#[allow(dead_code)]
const VIRTUAL_DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
const VIRTUAL_PROXY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 3);

const TUN_MTU: usize = 1500;
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// TUN proxy: manages the smoltcp stack and all background pump/acceptor tasks.
///
/// Lifecycle: created by `nativeStartTunProxy` and stored in `ProxyState.tun_proxy`.
/// `nativeStopTunProxy` / `nativeDestroy` call `stop()` to terminate all tasks.
/// `Drop` also calls `stop()` as a safety net.
pub struct TunProxy {
    stopped: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

impl TunProxy {
    /// Create and start the TUN proxy.
    ///
    /// - `tun_fd`: the raw fd returned by Kotlin's `ParcelFileDescriptor.detachFd()`.
    ///   This function `dup`s it twice (read/write) and closes the original fd.
    /// - `endpoint_group`: the `Arc<EndpointGroup>` cloned from `ProxyState`, used for iroh connections.
    /// - `proxy_domains`: the list of domains to proxy (already split from comma-separated input).
    /// - `custom_dns_servers`: the system DNS server list (read from `CUSTOM_DNS_SERVERS`).
    ///
    /// All tasks are started via `runtime.spawn()` internally — **no block_on**.
    pub fn new(
        tun_fd: RawFd,
        endpoint_group: Arc<EndpointGroup>,
        proxy_domains: Vec<String>,
        custom_dns_servers: Vec<SocketAddr>,
    ) -> Result<Self, ClientError> {
        // 1. dup the fd twice (read/write) and close the original fd.
        let fd_read = unsafe { libc::dup(tun_fd) };
        if fd_read < 0 {
            let e = std::io::Error::last_os_error();
            jni_log!("[tun-proxy] dup(read) failed: {}", e);
            return Err(e.into());
        }
        let fd_write = unsafe { libc::dup(tun_fd) };
        if fd_write < 0 {
            let e = std::io::Error::last_os_error();
            jni_log!("[tun-proxy] dup(write) failed: {}", e);
            unsafe { libc::close(fd_read) };
            return Err(e.into());
        }
        // Close the original fd — we now hold two dups.
        unsafe { libc::close(tun_fd) };

        set_nonblocking(fd_read)?;
        set_nonblocking(fd_write)?;

        jni_log!(
            "[tun-proxy] fd_read={}, fd_write={} (non-blocking)",
            fd_read,
            fd_write
        );

        // 2. Build the smoltcp stack.
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .mtu(TUN_MTU)
            .build()?;

        let stopped = Arc::new(AtomicBool::new(false));
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        // 3. spawn the Runner (drives smoltcp's internal processing: retransmits, timeouts, etc.).
        if let Some(runner) = runner {
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                match runner.await {
                    Ok(()) => jni_log!("[tun-proxy] smoltcp runner completed"),
                    Err(e) => jni_log!("[tun-proxy] smoltcp runner error: {}", e),
                }
                stopped_clone.store(true, Ordering::Release);
            }));
        }

        // 4. split Stack → (Sink for IP packets in, Stream for IP packets out).
        let (stack_sink, stack_stream) = stack.split();

        // 5. TUN → Stack pump (read fd → Stack Sink).
        {
            let file = unsafe { std::fs::File::from_raw_fd(fd_read) };
            let async_fd = AsyncFd::new(file)?;
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let async_fd = async_fd;
                let mut sink = stack_sink;
                let mut buf = vec![0u8; TUN_MTU];
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    let mut guard = match async_fd.readable().await {
                        Ok(g) => g,
                        Err(e) => {
                            jni_log!("[tun-proxy] readable() error: {}", e);
                            break;
                        }
                    };
                    // Use try_io: &File implements Read, so we can use get_ref() (the immutable guard
                    // only has get_ref()). try_io auto-clears readiness on WouldBlock, no manual clear_ready needed.
                    match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                        Ok(Ok(0)) => {
                            // EOF — the TUN fd was closed.
                            jni_log!("[tun-proxy] TUN read EOF, stopping pump-in");
                            break;
                        }
                        Ok(Ok(n)) => {
                            // n > 0 — read an IP packet; feed it into the smoltcp stack.
                            if let Err(e) = sink.send(buf[..n].to_vec()).await {
                                jni_log!("[tun-proxy] stack send error: {}", e);
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            jni_log!("[tun-proxy] TUN read error: {}", e);
                            break;
                        }
                        Err(_would_block) => {
                            // try_io already cleared readiness; wait again.
                            continue;
                        }
                    }
                }
                jni_log!("[tun-proxy] pump-in task exiting");
            }));
        }

        // 6. Stack → TUN pump (Stack Stream → write fd).
        {
            let file = unsafe { std::fs::File::from_raw_fd(fd_write) };
            let async_fd = AsyncFd::new(file)?;
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let async_fd = async_fd;
                let mut stream = stack_stream;
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match stream.next().await {
                        Some(Ok(pkt)) => {
                            // Write to the TUN fd, retrying on WouldBlock.
                            loop {
                                if stopped_clone.load(Ordering::Acquire) {
                                    break;
                                }
                                let mut guard = match async_fd.writable().await {
                                    Ok(g) => g,
                                    Err(e) => {
                                        jni_log!("[tun-proxy] writable() error: {}", e);
                                        break;
                                    }
                                };
                                // Use try_io: &File implements Write, so we can use get_ref().
                                // try_io auto-clears readiness on WouldBlock.
                                match guard.try_io(|inner| inner.get_ref().write_all(&pkt)) {
                                    Ok(Ok(())) => break, // write succeeded
                                    Ok(Err(e)) => {
                                        jni_log!("[tun-proxy] TUN write error: {}", e);
                                        break;
                                    }
                                    Err(_would_block) => {
                                        // try_io already cleared readiness; retry.
                                        continue;
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            jni_log!("[tun-proxy] stack stream error: {}", e);
                        }
                        None => {
                            jni_log!("[tun-proxy] stack stream ended, stopping pump-out");
                            break;
                        }
                    }
                }
                jni_log!("[tun-proxy] pump-out task exiting");
            }));
        }

        // 7. TCP acceptor — accept the TCP connections produced by smoltcp and route them by destination IP.
        //
        // Beware a netstack-smoltcp naming trap: TcpListener yields (stream, local_addr, remote_addr)
        // where local_addr = stream.local_addr() = src_addr = the packet's source IP = the client address,
        //      remote_addr = stream.remote_addr() = dst_addr = the packet's destination IP = the server address (10.0.1.3).
        // So local/remote semantics are the REVERSE of standard TCP! We use the third element (remote_addr) to decide the destination IP.
        if let Some(tcp_listener) = tcp_listener {
            let eg = endpoint_group.clone();
            let pd = Arc::new(proxy_domains.clone());
            let stopped_clone = stopped.clone();
            tasks.push(tokio::spawn(async move {
                let mut listener: SmolTcpListener = tcp_listener;
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match listener.next().await {
                        Some((stream, client_addr, server_addr)) => {
                            let dest_ip = server_addr.ip();
                            let dest_port = server_addr.port();
                            jni_log!(
                                "[tun-proxy] TCP accept: dest={}:{}, client={}",
                                dest_ip,
                                dest_port,
                                client_addr
                            );
                            if dest_ip == IpAddr::V4(VIRTUAL_PROXY_IP) {
                                // Proxied traffic → handle_local_connection → iroh.
                                let eg = eg.clone();
                                let pd = pd.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_local_connection(stream, pd, eg).await {
                                        jni_log!(
                                            "[tun-proxy] handle_local_connection error: {}",
                                            e
                                        );
                                    }
                                });
                            } else {
                                jni_log!(
                                    "[tun-proxy] TCP accept: unknown dest {}, ignoring",
                                    dest_ip
                                );
                            }
                        }
                        None => {
                            jni_log!("[tun-proxy] TCP listener stream ended");
                            break;
                        }
                    }
                }
                jni_log!("[tun-proxy] TCP acceptor task exiting");
            }));
        }

        // 8. DNS handler (UDP 53) — handle DNS queries, hijacking proxied domains to the virtual IP.
        //
        // Process concurrently: spawn one independent task per DNS query to avoid serial blocking.
        // The original serial implementation blocked all subsequent queries on a DNS forward timeout (~1.6s), causing APP DNS timeouts.
        if let Some(udp_socket) = udp_socket {
            let (udp_rx, udp_tx) = udp_socket.split();
            let proxy_vec = Arc::new(proxy_domains.clone());
            let dns_servers = Arc::new(custom_dns_servers);
            let stopped_clone = stopped.clone();
            // udp_tx needs Arc<Mutex> to be shared across concurrent tasks.
            let tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
            tasks.push(tokio::spawn(async move {
                let mut rx = udp_rx;
                loop {
                    if stopped_clone.load(Ordering::Acquire) {
                        break;
                    }
                    match rx.next().await {
                        Some((data, src_addr, dst_addr)) => {
                            // Process each DNS query concurrently without blocking later queries.
                            let tx = tx.clone();
                            let proxy_vec = proxy_vec.clone();
                            let dns_servers = dns_servers.clone();
                            tokio::spawn(async move {
                                let response =
                                    handle_dns_query(&data, &proxy_vec, &dns_servers).await;
                                if let Some(resp) = response {
                                    // Echo back: src=10.0.1.2:53 (the query's dst), dst=client (the query's src).
                                    let mut tx = tx.lock().await;
                                    let _ = tx.send((resp, dst_addr, src_addr)).await;
                                }
                            });
                        }
                        None => {
                            jni_log!("[tun-proxy] UDP stream ended");
                            break;
                        }
                    }
                }
                jni_log!("[tun-proxy] DNS handler task exiting");
            }));
        }

        jni_log!("[tun-proxy] Started with {} tasks", tasks.len());
        Ok(Self { stopped, tasks })
    }

    /// Stop all background tasks. Non-blocking — abort() marks the tasks for cancellation without waiting.
    /// Used by `Drop` or when we don't need to wait for the fd to close.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        for task in &self.tasks {
            task.abort();
        }
        jni_log!("[tun-proxy] Stopped (aborted {} tasks)", self.tasks.len());
    }

    /// Abort all tasks and wait for them to finish (with a timeout), ensuring the fd is closed before returning.
    /// Consumes self. Used in `nativeStopTunProxy` / `nativeStopProxy` to ensure the TUN proxy's fd
    /// is released before endpoint_group.close_all().
    pub fn shutdown(mut self, runtime: &tokio::runtime::Runtime) {
        self.stopped.store(true, Ordering::Release);
        // Use mem::take to pull tasks out, avoiding E0509 (can't move a field out of a Drop type).
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            task.abort();
            // Wait for the task to end (drop future → drop AsyncFd → close fd).
            let _ = runtime.block_on(async {
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
            });
        }
        jni_log!("[tun-proxy] Shutdown complete (all tasks joined)");
        // self dropped here → Drop::drop calls stop() (idempotent; tasks are already empty).
    }
}

impl Drop for TunProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

// ============================================================
// Helper functions
// ============================================================

/// Put the fd into non-blocking mode.
fn set_nonblocking(fd: RawFd) -> Result<(), ClientError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

// ============================================================
// DNS handling — ported from the Kotlin NexaVpnService.
// ============================================================

/// Handle a DNS query and return the DNS response payload.
///
/// - Proxied domain → return 10.0.1.3 (an A record).
/// - iroh infrastructure domain → forward to the real DNS (not proxied inside the TUN).
/// - Other domain → forward to the real DNS and return the response as-is.
///
/// Note: do NOT hijack the system's captive-portal validation domains (connectivitycheck.gstatic.com,
/// etc.) to a private virtual IP. Android's NetworkMonitor treats "validation domain resolves to a
/// private IP" as "no internet" (DNS returned private IP = no internet), which shows a WiFi
/// exclamation mark in the status bar. Let them use the real DNS and reach the physical network,
/// matching the behavior when the VPN is off.
async fn handle_dns_query(
    query: &[u8],
    proxy_domains: &Arc<Vec<String>>,
    dns_servers: &Arc<Vec<SocketAddr>>,
) -> Option<Vec<u8>> {
    let (domain, qtype) = match parse_dns_query(query) {
        Some(d) => d,
        None => return None,
    };
    if domain.is_empty() {
        return None;
    }

    let domain_lower = domain.to_lowercase();

    // iroh infrastructure domains are not proxied through the TUN — iroh's own traffic goes via addDisallowedApplication.
    let is_iroh = domain_lower.ends_with(".iroh.link") || domain_lower.ends_with(".n0.iroh.link");

    let is_proxy = !is_iroh && should_proxy_domain(&domain, proxy_domains);

    if is_proxy {
        jni_log!(
            "[tun-proxy] DNS: '{}' -> proxy IP {}",
            domain,
            VIRTUAL_PROXY_IP
        );
        Some(build_dns_response(query, VIRTUAL_PROXY_IP, qtype))
    } else {
        // Forward to the real DNS.
        jni_log!(
            "[tun-proxy] DNS: '{}' -> forwarding to real DNS (qtype={})",
            domain,
            qtype
        );
        forward_dns_query(query, dns_servers).await
    }
}

/// Parse a DNS query, returning (domain, QTYPE).
/// QTYPE: 1=A, 28=AAAA. Returns None on parse failure.
fn parse_dns_query(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 12 {
        return None;
    }

    // DNS header: ID(2) + flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse the Question section's domain name (length-prefixed labels).
    let mut pos = 12;
    let mut labels: Vec<&str> = Vec::new();

    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 {
            pos += 1; // Skip the null terminator.
            break;
        }
        // Prevent out-of-bounds access.
        if pos + 1 + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
        labels.push(label);
        pos += 1 + len;
    }

    // pos points right after the null byte. QTYPE is the 2 bytes immediately following it.
    let qtype = if pos + 2 <= payload.len() {
        u16::from_be_bytes([payload[pos], payload[pos + 1]])
    } else {
        0
    };

    Some((labels.join("."), qtype))
}

/// Build a DNS response resolving the domain to the given IPv4 address.
///
/// - qtype=1 (A): return an A record with 4 bytes of RDATA.
/// - qtype=28 (AAAA) or other: return an empty answer (ANCOUNT=0) so the client falls back to an A query.
fn build_dns_response(query: &[u8], ip: Ipv4Addr, qtype: u16) -> Vec<u8> {
    // Non-A query: return an empty answer (the virtual IP is IPv4, so it can't answer AAAA/MX, etc.).
    if qtype != 1 {
        return build_empty_dns_response(query);
    }

    let mut response = Vec::with_capacity(query.len() + 16);
    response.extend_from_slice(query);

    // Set flags: QR=1, Opcode=0, AA=0, TC=0, RD=1(copied), RA=1
    response[2] = 0x81;
    response[3] = 0x80;
    // ANCOUNT = 1
    response[6] = 0x00;
    response[7] = 0x01;

    // Answer section:
    // Name: compression pointer 0xC00C → points to offset 12 (the Question section's domain name)
    response.push(0xC0);
    response.push(0x0C);
    // TYPE: A = 1
    response.push(0x00);
    response.push(0x01);
    // CLASS: IN = 1
    response.push(0x00);
    response.push(0x01);
    // TTL: 60 seconds (0x0000003C)
    response.push(0x00);
    response.push(0x00);
    response.push(0x00);
    response.push(0x3C);
    // RDLENGTH: 4 (IPv4)
    response.push(0x00);
    response.push(0x04);
    // RDATA: the 4 bytes of the IP address.
    response.extend_from_slice(&ip.octets());

    response
}

/// Build an empty DNS answer: QR=1, RA=1, RCODE=0 (NoError), ANCOUNT=0.
/// Used for "query type not supported" or "no address of the matching type".
fn build_empty_dns_response(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    // ANCOUNT = 0
    response[6] = 0x00;
    response[7] = 0x00;
    response
}

/// Forward a DNS query to the real DNS server and return the response as-is.
///
/// Iterates over all configured DNS servers, **preferring IPv4**, binding the socket by address family
/// (IPv4→0.0.0.0:0, IPv6→[::]:0). Each server has its own 800ms timeout, with an overall 3s cap.
///
/// Fix: the system DNS list often starts with IPv6 servers (e.g. 2408:8888::8), which made binding
/// 0.0.0.0:0 then connect() fail, and the old code only tried dns_servers[0] with no fallback.
async fn forward_dns_query(query: &[u8], dns_servers: &Arc<Vec<SocketAddr>>) -> Option<Vec<u8>> {
    if dns_servers.is_empty() {
        jni_log!("[tun-proxy] No DNS servers configured, dropping query");
        return None;
    }

    // Prefer IPv4: try IPv4 DNS first (faster and more reliable), then IPv6.
    let mut ordered: Vec<&SocketAddr> = dns_servers.iter().collect();
    ordered.sort_by_key(|s| !s.is_ipv4() as u8); // false(=IPv4) goes first

    let per_server_timeout = Duration::from_millis(800);

    let result = tokio::time::timeout(DNS_FORWARD_TIMEOUT, async {
        for dns_server in ordered.iter() {
            // Bind by address family: IPv4 DNS → 0.0.0.0:0, IPv6 DNS → [::]:0.
            let bind_addr = if dns_server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };

            // Per-server timeout so we don't get stuck on an unreachable IPv6 DNS server.
            let server_result = tokio::time::timeout(per_server_timeout, async {
                let sock = tokio::net::UdpSocket::bind(bind_addr).await.ok()?;
                sock.connect(**dns_server).await.ok()?;
                sock.send(query).await.ok()?;
                let mut buf = vec![0u8; 4096];
                let n = sock.recv(&mut buf).await.ok()?;
                Some(buf[..n].to_vec())
            })
            .await;

            match server_result {
                Ok(Some(resp)) => return Some(resp),
                _ => continue,
            }
        }
        None
    })
    .await;

    match result {
        Ok(Some(resp)) => Some(resp),
        Ok(None) => {
            jni_log!(
                "[tun-proxy] DNS forward failed (all {} servers failed)",
                dns_servers.len()
            );
            None
        }
        Err(_) => {
            jni_log!(
                "[tun-proxy] DNS forward timed out after {}s",
                DNS_FORWARD_TIMEOUT.as_secs()
            );
            None
        }
    }
}
