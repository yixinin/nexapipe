//! TUN proxy: a user-space TCP/IP stack implemented in Rust with netstack-smoltcp, replacing the Kotlin hand-written TCP stack.
//!
//! Data flow:
//! ```text
//! APP → TUN fd → Rust(AsyncFd) → Stack(Sink: IP packets in)
//!                                  ↓ smoltcp processing
//!                            ┌──────┴────────┐
//!                       TcpListener      UdpSocket
//!                            │              │
//!                            │              ├─ dst 10.0.1.2:53 ─→ DNS hijack,
//!                            │              │                     answers with a
//!                            │              │                     per-domain IP
//!                            │              │
//!                            │              └─ dst 10.0.1.16+ ─→ l4::open_udp(domain, port)
//!                            │                                   (one bi-stream per flow,
//!                            │                                    one datagram per frame)
//!                            ↓
//!                  reverse-lookup the destination address
//!                            │
//!                            ↓
//!                  l4::open_tcp(domain, port)
//!                            │
//!                            ↓
//!                  iroh bi-stream → server route → backend (TCP or UDP)
//!
//! Stack(Stream: IP packets out) → AsyncFd → write back to TUN fd
//! ```
//!
//! # The destination address is the destination
//!
//! `10.0.1.3` used to be the single virtual proxy address: every connection went
//! there and the far side worked out where it was going from the payload — SNI
//! out of a TLS `ClientHello`, `Host` out of an HTTP request — and the port was
//! thrown away, so a flow to `example.com:8080` arrived looking like a flow to
//! 443. UDP cannot work that way at all: a datagram carries no host name.
//!
//! So the DNS answers handed out by this module carry one address per domain
//! (see [`IpMapping`]), and the address *is* the destination:
//!
//! ```text
//! dns.example.com   → 10.0.1.16:53    → l4::open_udp("dns.example.com", 53)
//! db.example.com    → 10.0.1.17:5432  → l4::open_tcp("db.example.com", 5432)
//! ```
//!
//! `10.0.1.3` is still accepted **for TCP only**, so applications that cached
//! the address before this change keep working; it goes down the old
//! payload-sniffing path ([`handle_local_connection`]).

use crate::ClientError;
use crate::EndpointGroup;
use crate::l4;
use crate::local_proxy::{handle_local_connection, should_proxy_domain};
use crate::virtual_ip::IpMapping;

#[cfg(feature = "jni")]
use crate::jni_log;

/// No-op `jni_log!` for builds without the `jni` feature.
///
/// The format arguments are still *evaluated* (borrowed) inside a dead branch,
/// so the optimiser removes the call but `unused_variables` does not fire on
/// variables that only ever appear inside a log statement.
#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if false {
            let _ = ::std::format_args!($($arg)*);
        }
    };
}

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::udp::{ReadHalf as UdpReadHalf, UdpMsg, WriteHalf as UdpWriteHalf};
use netstack_smoltcp::{StackBuilder, TcpListener as SmolTcpListener, TcpStream as SmolTcpStream};
use nexapipe_proto::{
    FRAME_HEADER_LEN, Frame, MAX_UDP_PAYLOAD, decode_frame, encode_frame,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// Virtual IP constants — must match the TUN config in the Kotlin-side NexaVpnService.
// 10.0.1.1 = the TUN interface
// 10.0.1.2 = DNS server (smoltcp UdpSocket receives DNS queries)
// 10.0.1.3 = legacy proxy IP (TCP only; payload sniffing, kept for stale caches)
// 10.0.1.16+ = per-domain addresses handed out by `IpMapping`
/// Virtual DNS server IP — matches Kotlin-side NexaVpnService.virtualDNSIP, which
/// the system resolver is pointed at (`addDnsServer`). The query's dst_addr is this
/// IP, and it is used as-is as the src_addr in the response.
const VIRTUAL_DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
/// The address every proxied domain used to resolve to. See the module docs.
const VIRTUAL_PROXY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 3);
/// The only port the DNS hijack answers on. A datagram to any other port is a flow.
const DNS_PORT: u16 = 53;

/// Inner MTU for both the TUN device (see `Builder.setMtu` in NexaVpnService.kt) and the
/// smoltcp stack. These two must agree.
///
/// Not 1500: an inner IP packet of 1500 bytes does not fit in one QUIC datagram. iroh's MTU
/// discovery tops out around a 1452-byte UDP payload, and the QUIC short header plus the
/// AEAD tag eat ~17 more bytes, leaving ~1435 for stream data. A 1500-byte inner packet
/// therefore had to be fragmented across two datagrams, roughly doubling the datagram count
/// and the number of AEAD operations per megabyte. 1400 leaves ~35 bytes of headroom and
/// keeps one inner segment == one QUIC datagram.
const TUN_MTU: usize = 1400;
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a UDP flow may stay silent before this side closes it.
///
/// Deliberately under the server's own 60 s UDP idle timeout: if the server closes
/// first, we keep writing into a stream that is being reset. The window is the same
/// on both sides — silence in *either* direction — so this side simply gets there
/// first.
const UDP_FLOW_IDLE: Duration = Duration::from_secs(50);

/// Datagrams that may be waiting for one UDP flow's tunnel to accept them.
///
/// A flow is created when its first datagram arrives and the tunnel takes a
/// moment to open (a connection may have to be dialled), so the datagrams that
/// follow in that window queue here. Beyond this depth they are dropped: UDP is
/// allowed to lose datagrams, and buffering without bound would turn a stalled
/// flow into memory growth.
const UDP_FLOW_QUEUE: usize = 256;

/// Datagrams on their way from the proxy to the application (DNS replies and
/// every UDP flow's inbound traffic) queue here for the single TUN writer.
const TUN_WRITE_QUEUE: usize = 1024;

/// Buffer size for the byte-copying TCP paths.
const COPY_BUF_SIZE: usize = 16 * 1024;

/// TUN proxy: manages the smoltcp stack and all background pump/acceptor tasks.
///
/// Lifecycle: created by `nativeStartTunProxy` and stored in `ProxyState.tun_proxy`.
/// `nativeStopTunProxy` / `nativeDestroy` call `stop()` to terminate all tasks.
/// `Drop` also calls `stop()` as a safety net.
pub struct TunProxy {
    stopped: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

/// Everything the acceptors and the flows need, so each spawned task takes one
/// clone instead of five arguments.
#[derive(Clone)]
struct TunContext {
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
    ip_mapping: Arc<IpMapping>,
    /// Every datagram leaving the proxy for the application, from both the DNS
    /// hijack and the L4 UDP flows.
    ///
    /// One queue and one writer task: the smoltcp `WriteHalf` is a `Sink`, not a
    /// shared writer, and a `Mutex` around it (the previous design) made every
    /// concurrent reply wait for the lock, so one slow flow delayed the DNS
    /// answers behind it.
    tun_out: mpsc::Sender<UdpMsg>,
    stopped: Arc<AtomicBool>,
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

        let (tun_out, tun_out_rx) = mpsc::channel::<UdpMsg>(TUN_WRITE_QUEUE);
        let ctx = TunContext {
            endpoint_group,
            proxy_domains: Arc::new(proxy_domains),
            ip_mapping: Arc::new(IpMapping::new()),
            tun_out,
            stopped: stopped.clone(),
        };

        // 7. TCP acceptor — accept the TCP connections produced by smoltcp and route them by destination IP.
        //
        // Beware a netstack-smoltcp naming trap: TcpListener yields (stream, local_addr, remote_addr)
        // where local_addr = stream.local_addr() = src_addr = the packet's source IP = the client address,
        //      remote_addr = stream.remote_addr() = dst_addr = the packet's destination IP = the server address.
        // So local/remote semantics are the REVERSE of standard TCP! We use the third element (remote_addr) to decide the destination IP.
        if let Some(tcp_listener) = tcp_listener {
            let ctx = ctx.clone();
            tasks.push(tokio::spawn(run_tcp_acceptor(tcp_listener, ctx)));
        }

        // 8. UDP: one writer for everything going back to the application, and one
        // demultiplexer splitting the inbound stream into DNS queries and L4 flows.
        if let Some(udp_socket) = udp_socket {
            let (udp_rx, udp_tx) = udp_socket.split();
            tasks.push(tokio::spawn(run_tun_udp_writer(udp_tx, tun_out_rx)));
            tasks.push(tokio::spawn(run_udp_demux(
                udp_rx,
                Arc::new(custom_dns_servers),
                ctx,
            )));
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
            runtime.block_on(async {
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
// TCP
// ============================================================

/// Accept TCP connections from the stack and route each one by destination address.
async fn run_tcp_acceptor(mut listener: SmolTcpListener, ctx: TunContext) {
    while !ctx.stopped.load(Ordering::Acquire) {
        let Some((stream, client_addr, server_addr)) = listener.next().await else {
            jni_log!("[tun-proxy] TCP listener stream ended");
            break;
        };

        let dest_ip = server_addr.ip();
        let dest_port = server_addr.port();
        jni_log!(
            "[tun-proxy] TCP accept: dest={}:{}, client={}",
            dest_ip,
            dest_port,
            client_addr
        );

        let IpAddr::V4(dest_ip) = dest_ip else {
            jni_log!("[tun-proxy] TCP to {dest_ip} has no domain mapping, dropping");
            continue;
        };

        // Legacy address: applications that cached a DNS answer from before the
        // per-domain addresses existed still connect to 10.0.1.3, so those
        // connections keep the payload-sniffing path (SNI / Host header) instead
        // of being dropped. DNS answers only live 60 s, so this is a short tail.
        if dest_ip == VIRTUAL_PROXY_IP {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_local_connection(
                    stream,
                    ctx.proxy_domains.clone(),
                    ctx.endpoint_group.clone(),
                )
                .await
                {
                    jni_log!("[tun-proxy] handle_local_connection error: {}", e);
                }
            });
            continue;
        }

        let Some(domain) = ctx.ip_mapping.lookup_domain(&dest_ip) else {
            jni_log!("[tun-proxy] TCP to {dest_ip}:{dest_port} has no domain mapping, dropping");
            continue;
        };

        let ctx = ctx.clone();
        tokio::spawn(serve_tcp_flow(stream, ctx, domain, dest_port));
    }
    jni_log!("[tun-proxy] TCP acceptor task exiting");
}

/// Carry one TCP flow between the application's smoltcp socket and a server route.
///
/// Nothing is sniffed: the domain came from the destination address, so a raw
/// binary protocol on any port works as well as TLS on 443.
async fn serve_tcp_flow(
    stream: SmolTcpStream,
    ctx: TunContext,
    domain: String,
    port: u16,
) {
    // The tunnel is opened before any payload is read, so the application sees
    // the connection go quiet rather than being told a connection exists that
    // the server has no route for.
    let (pooled, mut tunnel_send, mut tunnel_recv) =
        match l4::open_tcp(&ctx.endpoint_group, &domain, port).await {
            Ok(tunnel) => tunnel,
            Err(e) => {
                jni_log!("[tun-proxy] TCP {}:{} refused: {}", domain, port, e);
                return;
            }
        };

    jni_log!("[tun-proxy] TCP flow {} -> {}:{}", client_addr_hint(&stream), domain, port);

    let (mut app_read, mut app_write) = tokio::io::split(stream);

    let app_to_tunnel = async {
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            match app_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tunnel_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    jni_log!("[tun-proxy] TCP {}:{} app read error: {}", domain, port, e);
                    break;
                }
            }
        }
        // Half-close: the application said it is done sending, and the backend
        // needs to hear that (an HTTP request without a length ends this way).
        let _ = tunnel_send.finish();
    };

    let tunnel_to_app = async {
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            match tunnel_recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if app_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    jni_log!("[tun-proxy] TCP {}:{} tunnel read error: {}", domain, port, e);
                    break;
                }
            }
        }
        // smoltcp's `poll_shutdown` returns `Pending` until the FIN has been
        // acknowledged, so this is bounded: sending the FIN is what matters, and
        // waiting forever for an application that has already gone away is not.
        let _ = tokio::time::timeout(Duration::from_secs(5), app_write.shutdown()).await;
    };

    tokio::select! {
        _ = app_to_tunnel => (),
        _ = tunnel_to_app => (),
    }

    // Dropping both halves closes the smoltcp socket (its `Drop` sends, at most,
    // a FIN; the flow is over either way).
    ctx.endpoint_group.return_connection(&domain, pooled).await;
}

/// The application's address, for the log line. Only valid before `split`.
fn client_addr_hint(stream: &SmolTcpStream) -> String {
    // `local_addr` is the *source* address here; see the naming trap in
    // `run_tcp_acceptor`.
    stream.local_addr().to_string()
}

// ============================================================
// UDP
// ============================================================

/// `(the application's address, the address the application sent to)`.
///
/// The application's address is enough to separate two sockets on the same
/// address — its port distinguishes them — and the destination address
/// identifies the flow, since every domain has its own (see [`IpMapping`]).
type FlowKey = (SocketAddr, SocketAddr);

/// The live UDP flows: their key, and the channel feeding datagrams into them.
type FlowTable = Arc<Mutex<HashMap<FlowKey, mpsc::Sender<Vec<u8>>>>>;

/// Which side of a UDP flow spoke.
enum Activity {
    /// A datagram from the application; `None` means the flow was replaced.
    Application(Option<Vec<u8>>),
    /// Bytes from the tunnel, or why it ended.
    Tunnel(Result<Option<usize>, String>),
}

/// Write every datagram the proxy has for the application back into the stack.
///
/// One task owns the smoltcp `WriteHalf`; everyone else hands datagrams to it
/// through the channel in [`TunContext::tun_out`].
async fn run_tun_udp_writer(mut writer: UdpWriteHalf, mut queue: mpsc::Receiver<UdpMsg>) {
    while let Some(datagram) = queue.recv().await {
        // Note: the stack's sink drops a zero-length payload silently. A
        // zero-length UDP datagram is legal but nothing sends one, so there is
        // nothing to work around here.
        if let Err(e) = writer.send(datagram).await {
            jni_log!("[tun-proxy] TUN UDP write error: {}", e);
            break;
        }
    }
    jni_log!("[tun-proxy] UDP writer task exiting");
}

/// Split the stack's inbound UDP stream into DNS queries and proxied flows.
async fn run_udp_demux(
    mut socket: UdpReadHalf,
    dns_servers: Arc<Vec<SocketAddr>>,
    ctx: TunContext,
) {
    let table: FlowTable = Arc::new(Mutex::new(HashMap::new()));

    while !ctx.stopped.load(Ordering::Acquire) {
        let Some((payload, client_addr, dst_addr)) = socket.next().await else {
            jni_log!("[tun-proxy] UDP stream ended");
            break;
        };

        // The system resolver is pointed at VIRTUAL_DNS_IP (Kotlin: addDnsServer),
        // and 10.0.1.0/24 is the only route into the TUN, so a datagram to port 53
        // there is a DNS query and nothing else.
        if dst_addr.ip() == IpAddr::V4(VIRTUAL_DNS_IP) && dst_addr.port() == DNS_PORT {
            // Answer from the address the query went to: the application's socket
            // may be connected, and a reply from anywhere else is discarded by the
            // kernel before the application ever sees it.
            let ctx = ctx.clone();
            let dns_servers = dns_servers.clone();
            tokio::spawn(async move {
                let Some(response) =
                    handle_dns_query(&payload, &ctx.proxy_domains, &dns_servers, &ctx.ip_mapping)
                        .await
                else {
                    return;
                };
                if ctx
                    .tun_out
                    .send((response, dst_addr, client_addr))
                    .await
                    .is_err()
                {
                    jni_log!("[tun-proxy] TUN writer is gone, dropping the DNS reply");
                }
            });
            continue;
        }

        let IpAddr::V4(dst_ip) = dst_addr.ip() else {
            jni_log!("[tun-proxy] UDP to {} has no domain mapping, dropping", dst_addr);
            continue;
        };
        let Some(domain) = ctx.ip_mapping.lookup_domain(&dst_ip) else {
            jni_log!("[tun-proxy] UDP to {} has no domain mapping, dropping", dst_addr);
            continue;
        };

        let key: FlowKey = (client_addr, dst_addr);
        // A closed channel means the flow ended (idle, refused, or the server
        // closed it) — the next datagram starts a fresh one rather than being
        // written into a dead tunnel.
        let existing = lock_flows(&table)
            .get(&key)
            .filter(|sender| !sender.is_closed())
            .cloned();

        let sender = match existing {
            Some(sender) => sender,
            None => {
                let (sender, receiver) = mpsc::channel::<Vec<u8>>(UDP_FLOW_QUEUE);
                lock_flows(&table).insert(key, sender.clone());
                tokio::spawn(run_udp_flow(
                    ctx.clone(),
                    table.clone(),
                    key,
                    sender.clone(),
                    receiver,
                    domain,
                ));
                sender
            }
        };

        match sender.try_send(payload) {
            Ok(()) => {}
            // Datagrams arriving while the tunnel is still opening are the normal
            // case for the first few, so a full queue is not worth a log line —
            // printing one per dropped datagram would be its own problem under
            // load. Losing them is what UDP promises anyway.
            Err(mpsc::error::TrySendError::Full(_)) => {}
            // The flow ended between the lookup and the send. The next datagram
            // creates a new one.
            Err(mpsc::error::TrySendError::Closed(_)) => {
                jni_log!("[tun-proxy] UDP flow to {} closed", dst_addr);
            }
        }
    }
    jni_log!("[tun-proxy] UDP demux task exiting");
}

/// Carry one UDP flow: datagrams in from the demultiplexer, frames out to the
/// tunnel, and the reverse.
///
/// The flow ends on silence in either direction, when the tunnel closes, or when
/// the server refuses it. A refusal is logged once and the flow is dropped: UDP
/// has nowhere to report an error to, and the application's own retry is what
/// creates the next flow.
async fn run_udp_flow(
    ctx: TunContext,
    table: FlowTable,
    key: FlowKey,
    mine: mpsc::Sender<Vec<u8>>,
    mut datagrams: mpsc::Receiver<Vec<u8>>,
    domain: String,
) {
    let (client_addr, virtual_dst) = key;
    let port = virtual_dst.port();

    let (pooled, mut tunnel_send, mut tunnel_recv) =
        match l4::open_udp(&ctx.endpoint_group, &domain, port).await {
            Ok(tunnel) => tunnel,
            Err(e) => {
                jni_log!("[tun-proxy] UDP {}:{} refused: {}", domain, port, e);
                release_flow(&table, &key, &mine);
                return;
            }
        };

    jni_log!("[tun-proxy] UDP flow {} -> {}:{}", client_addr, domain, port);

    let mut read_buf = vec![0u8; MAX_UDP_PAYLOAD + FRAME_HEADER_LEN];
    // A bi-stream has no message boundaries, so a datagram can start in one read
    // and finish in the next. `partial` holds the bytes of the frames that have
    // not fully arrived.
    let mut partial: Vec<u8> = Vec::new();
    let mut encoded: Vec<u8> = Vec::new();

    loop {
        // Silence in *either* direction is what ends a flow, so the timer wraps
        // the whole step rather than just the tunnel read.
        let activity = match tokio::time::timeout(UDP_FLOW_IDLE, async {
            tokio::select! {
                datagram = datagrams.recv() => Activity::Application(datagram),
                read = tunnel_recv.read(&mut read_buf) => {
                    Activity::Tunnel(read.map_err(|e| e.to_string()))
                }
            }
        })
        .await
        {
            Ok(activity) => activity,
            Err(_) => {
                jni_log!(
                    "[tun-proxy] UDP flow {} -> {}:{} idle for {}s, closing",
                    client_addr,
                    domain,
                    port,
                    UDP_FLOW_IDLE.as_secs()
                );
                break;
            }
        };

        match activity {
            // The demultiplexer dropped our sender: the flow was replaced.
            Activity::Application(None) => break,
            Activity::Application(Some(datagram)) => {
                encoded.clear();
                match encode_frame(&datagram, &mut encoded) {
                    Ok(()) => {
                        if tunnel_send.write_all(&encoded).await.is_err() {
                            jni_log!("[tun-proxy] UDP flow to {}:{} is gone", domain, port);
                            break;
                        }
                    }
                    Err(e) => {
                        jni_log!(
                            "[tun-proxy] dropping a {}-byte datagram to {}:{}: {}",
                            datagram.len(),
                            domain,
                            port,
                            e
                        );
                    }
                }
            }
            // The server closed the flow.
            Activity::Tunnel(Ok(None)) => break,
            // A read that returned no bytes is not an end of stream.
            Activity::Tunnel(Ok(Some(0))) => {}
            Activity::Tunnel(Ok(Some(n))) => {
                partial.extend_from_slice(&read_buf[..n]);

                let mut consumed = 0usize;
                let mut tun_gone = false;
                while let Frame::Ready {
                    payload,
                    consumed: frame_len,
                } = decode_frame(&partial[consumed..])
                {
                    // The reply comes *from* the address the application sent to,
                    // because the application's socket is often connected and a
                    // datagram from any other source is discarded.
                    if ctx
                        .tun_out
                        .send((payload.to_vec(), virtual_dst, client_addr))
                        .await
                        .is_err()
                    {
                        tun_gone = true;
                        break;
                    }
                    consumed += frame_len;
                }
                partial.drain(..consumed);
                if tun_gone {
                    jni_log!("[tun-proxy] TUN writer is gone, ending UDP flow to {}", domain);
                    break;
                }
            }
            Activity::Tunnel(Err(e)) => {
                jni_log!("[tun-proxy] UDP flow to {}:{} ended: {}", domain, port, e);
                break;
            }
        }
    }

    let _ = tunnel_send.finish();
    ctx.endpoint_group.return_connection(&domain, pooled).await;
    release_flow(&table, &key, &mine);
}

/// Drop a finished flow from the table.
///
/// Only removes the entry if it is still *ours*: a flow that ends after the
/// demultiplexer replaced it (which happens when the channel is closed) must not
/// take the live flow's channel down with it.
fn release_flow(table: &FlowTable, key: &FlowKey, mine: &mpsc::Sender<Vec<u8>>) {
    let mut flows = lock_flows(table);
    if flows.get(key).is_some_and(|entry| entry.same_channel(mine)) {
        flows.remove(key);
    }
}

/// A poisoned lock still holds a usable table — every critical section is a
/// handful of `HashMap` calls and nothing that can panic in between — so
/// recovering beats taking the tunnel down.
fn lock_flows(table: &FlowTable) -> MutexGuard<'_, HashMap<FlowKey, mpsc::Sender<Vec<u8>>>> {
    table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
/// - Proxied domain → allocate a virtual address for it and return that as an A record.
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
    ip_mapping: &IpMapping,
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
        // Only an A query gets an address. A rack of virtual IPv4 addresses
        // cannot answer an AAAA query with the truth, so non-A types get an empty
        // NOERROR and the application falls back to A — and, just as important,
        // do not consume an address for a name nothing may ever connect to.
        if qtype != 1 {
            return Some(build_empty_dns_response(query));
        }
        let virtual_ip = ip_mapping.allocate(&domain);
        jni_log!("[tun-proxy] DNS: '{}' -> {}", domain, virtual_ip);
        Some(build_dns_response(query, virtual_ip, qtype))
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
