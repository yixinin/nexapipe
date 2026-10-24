//! The HTTP data plane, driven end to end over a real iroh connection.
//!
//! The unit tests cover the pieces — routing, the legacy parsers, the body
//! limit, `copy_both_ways` — but nothing until now has put a request through
//! `conn::handle_bidi_stream` and read the answer back. That path is where the
//! first byte is dispatched, the head is collected and the body is read, and it
//! is the one every client actually uses.
//!
//! These tests run two endpoints on loopback with the relay disabled, so they
//! need a UDP socket on 127.0.0.1 and nothing else: no relay, no DNS, no
//! network. Each one pairs the proxy with a backend that is a real socket, so a
//! request that is forwarded wrongly — to the wrong backend, or not at all —
//! shows up as a backend that saw nothing.

use iroh::endpoint::{ConnectOptions, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use nexapipe::auth::{AuthConfig, ClientAuth, DeviceAuth};
use nexapipe::config::{Retry, RouteMode, Timeouts};
use nexapipe::conn;
use nexapipe::http;
use nexapipe::l4::FlowLimiter;
use nexapipe::lb::LoadBalancingStrategy;
use nexapipe::routes::{Route, RoutingTable};
use nexapipe_client::auth::{Enrollment, TotpAlgorithm as ClientTotpAlgorithm, TwoFactorAuth};
use nexapipe_proto::auth::{AuthMessage, Format};
use nexapipe_proto::secret::SecretString;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The ALPN the proxy endpoint is built with; iroh refuses a connection whose
/// ALPN does not match, so the test client has to ask for the same one.
///
/// The name lives in the crate the proxy links too: the two ends have to
/// agree on it, and a name written down twice is a name that eventually
/// differs.
const ALPN: &[u8] = nexapipe_proto::ALPN_NEXAPIPE;

/// The ALPN clients built before the prefix byte was dropped use.
const ALPN_LEGACY: &[u8] = nexapipe_proto::ALPN_NEXAPIPE_LEGACY;

/// Ceiling for one reply. Far above anything these backends return, and it
/// stops a test from waiting on a stream that never ends.
const REPLY_LIMIT: usize = 1024 * 1024;

/// `conn::handle_bidi_stream` stops collecting a head at this size.
const HEAD_LIMIT: usize = 64 * 1024;

/// A deadline generous for loopback, and short enough that a hang fails the
/// test instead of the 45-minute CI timeout doing it.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// An endpoint that never leaves the machine: no relay, no discovery, one
/// loopback socket. `presets::Minimal` sets only the crypto provider, which is
/// the one option iroh requires and the rest of the presets come with network
/// services this test must not depend on.
async fn bind() -> Endpoint {
    bind_with_alpns(vec![ALPN.to_vec()]).await
}

/// An endpoint that accepts exactly the ALPNs it is given.
///
/// The list matters: iroh negotiates the first protocol of the peer's offer that
/// it also accepts, and refuses the connection when the two lists do not meet.
async fn bind_with_alpns(alpns: Vec<Vec<u8>>) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(alpns)
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .expect("loopback bind address")
        .bind()
        .await
        .expect("bind endpoint")
}

/// The address to dial: the endpoint's own id, with only its loopback address.
///
/// `addr()` also advertises whatever global addresses the host has, and a
/// client that tries those first spends the whole dial timeout on them.
fn dial_address(ep: &Endpoint) -> EndpointAddr {
    let local = *ep
        .addr()
        .ip_addrs()
        .find(|a| a.ip().is_loopback())
        .expect("an endpoint bound to loopback reports a loopback address");
    EndpointAddr::new(ep.id()).with_ip_addr(local)
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// One request as a backend saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    request_line: String,
    body: Vec<u8>,
}

/// An HTTP/1.1 backend on a loopback port that answers every request with the
/// same body and remembers what it was asked for.
struct Backend {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Backend {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

async fn spawn_backend(reply_body: &'static str) -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let url = format!("http://{}", listener.local_addr().expect("backend address"));

    let sink = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let Some(request) = read_request(&mut sock).await else {
                    return;
                };
                sink.lock().unwrap().push(request);

                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                    reply_body.len(),
                    reply_body
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });

    Backend { url, seen }
}

/// A backend that answers with a reply of its own.
///
/// The proxy's job includes not passing on what belongs to the hop between
/// the backend and it, so a test needs a backend that says the awkward things
/// to see that they do not arrive.
async fn spawn_backend_answering(reply: &'static str) -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let url = format!("http://{}", listener.local_addr().expect("backend address"));

    let sink = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let Some(request) = read_request(&mut sock).await else {
                    return;
                };
                sink.lock().unwrap().push(request);
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });

    Backend { url, seen }
}

/// Reads one HTTP/1.1 request: the head, then a body if `content-length` asks
/// for one. A backend that read only the head would make every test with a body
/// look like a proxy bug.
async fn read_request(sock: &mut TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    let head_end = loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let content_length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    Some(Seen { request_line, body })
}

/// A backend that reads the whole request and then hangs up without
/// answering.
///
/// The request was carried — the backend saw it, body and all — and the
/// answer never came. That is the shape of a failure a retry would answer,
/// and what decides whether it is tried again is the body.
async fn spawn_backend_that_hangs_up() -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let url = format!("http://{}", listener.local_addr().expect("backend address"));

    let sink = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let Some(request) = read_request(&mut sock).await else {
                    return;
                };
                sink.lock().unwrap().push(request);
                // The connection dies with the request read: the backend saw
                // it and says nothing.
                drop(sock);
            });
        }
    });

    Backend { url, seen }
}

/// An address nothing is listening on.
///
/// The port is held by a UDP socket, so a TCP connection to it is refused
/// rather than timing out. The socket is returned so the caller keeps the
/// address dead for as long as the test runs.
async fn dead_backend() -> (String, tokio::net::UdpSocket) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a dead backend");
    let port = socket.local_addr().expect("dead backend address").port();
    (format!("http://127.0.0.1:{port}"), socket)
}

/// A backend that speaks nothing: it keeps the bytes it was sent and answers
/// with one byte. This is what a passthrough route's TLS backend looks like
/// from the proxy's side.
async fn spawn_raw_backend() -> (String, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind raw backend");
    let addr = listener
        .local_addr()
        .expect("raw backend address")
        .to_string();
    let got = Arc::new(Mutex::new(Vec::new()));

    let sink = got.clone();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(n) = sock.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        sink.lock().unwrap().extend_from_slice(&buf);
        let _ = sock.write_all(b"\x16").await;
    });

    (addr, got)
}

/// A WebSocket backend on the loopback address that speaks TLS.
///
/// The certificate is made here rather than kept in the repository, and the CA
/// that signed it is handed to the proxy through `[backends] ca_file`'s
/// equivalent. A backend that accepts the TLS session and answers the upgrade
/// is all this path needs.
struct TlsWebSocketBackend {
    url: String,
    ca_file: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn spawn_tls_websocket_backend() -> TlsWebSocketBackend {
    use rcgen::{CertificateParams, IsCa, KeyPair};

    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("a CA with no names is a CA");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("a key pair");
    let ca_cert = ca_params.self_signed(&ca_key).expect("a self-signed CA");

    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("a certificate for the loopback address");
    server_params.is_ca = IsCa::NoCa;
    let server_key = KeyPair::generate().expect("a key pair");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("a certificate signed by the CA");

    let dir = tempfile::tempdir().expect("a scratch directory");
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&ca_file, ca_cert.pem()).expect("the CA file");

    let certs = vec![rustls::pki_types::CertificateDer::from(
        server_cert.der().to_vec(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::try_from(server_key.serialize_der())
        .expect("a DER private key");
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("a server configuration");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the TLS backend");
    let port = listener.local_addr().expect("backend address").port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                        Err(_) => return,
                    }
                }
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: websocket\r\n\
                          Connection: Upgrade\r\n\r\n",
                    )
                    .await;
                let _ = tls.flush().await;
                // Keep the connection alive while the test reads the upgrade,
                // so the proxy's pipes do not race it into an early close.
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
        }
    });

    TlsWebSocketBackend {
        url: format!("https://127.0.0.1:{port}"),
        ca_file,
        _dir: dir,
    }
}

/// A WebSocket backend that answers the upgrade and then keeps sending a byte
/// every `interval`.
///
/// The proxy's WebSocket tunnel is bounded by how long the session may be
/// quiet, and the shape that matters is the one where only **one** side is
/// quiet: a client that only listens to a feed has nothing to say while the
/// backend keeps pushing.
async fn spawn_websocket_backend(interval: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the WebSocket backend");
    let port = listener.local_addr().expect("backend address").port();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                        Err(_) => return,
                    }
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: websocket\r\n\
                          Connection: Upgrade\r\n\r\n",
                    )
                    .await;
                let _ = sock.flush().await;
                loop {
                    tokio::time::sleep(interval).await;
                    if sock.write_all(b"x").await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    format!("http://127.0.0.1:{port}")
}

/// A WebSocket backend that answers the upgrade and then says nothing at all.
async fn spawn_quiet_websocket_backend() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the quiet WebSocket backend");
    let port = listener.local_addr().expect("backend address").port();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                        Err(_) => return,
                    }
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: websocket\r\n\
                          Connection: Upgrade\r\n\r\n",
                    )
                    .await;
                let _ = sock.flush().await;
                // The session has to end on the proxy's own bound, so the
                // backend holds the connection open without saying anything.
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });

    format!("http://127.0.0.1:{port}")
}

// ---------------------------------------------------------------------------
// The proxy under test
// ---------------------------------------------------------------------------

struct Proxy {
    addr: EndpointAddr,
}

/// Serves `routes` over a loopback endpoint, the way the binary does: accept a
/// connection, then hand every bidirectional stream to
/// `conn::handle_bidi_stream`.
async fn spawn_proxy(routes: Vec<Route>) -> Proxy {
    spawn_proxy_with(routes, Retry::default(), None).await
}

/// The same proxy, with the retry policy the binary would read from
/// `[retry]`.
async fn spawn_proxy_with_settings(routes: Vec<Route>, retry: Retry) -> Proxy {
    spawn_proxy_with(routes, retry, None).await
}

/// The same proxy, trusting the CA in `ca_file` for `https://` backends.
async fn spawn_proxy_with_ca(routes: Vec<Route>, ca_file: &std::path::Path) -> Proxy {
    spawn_proxy_with(routes, Retry::default(), Some(ca_file)).await
}

async fn spawn_proxy_with(
    routes: Vec<Route>,
    retry: Retry,
    ca_file: Option<&std::path::Path>,
) -> Proxy {
    spawn_proxy_with_timeouts(routes, retry, ca_file, Timeouts::default()).await
}

/// The same proxy, with the deadlines the caller asks for.
///
/// The head deadline is 30 s by default, and a test that waits for it is a test
/// that never runs in a normal suite.
async fn spawn_proxy_with_timeouts(
    routes: Vec<Route>,
    retry: Retry,
    ca_file: Option<&std::path::Path>,
    timeouts: Timeouts,
) -> Proxy {
    let ep = bind().await;
    let addr = dial_address(&ep);

    let config = Arc::new(RoutingTable::with_settings(routes, timeouts, retry));
    let clients = Arc::new(
        http::BackendClients::new(Timeouts::default().connect, ca_file)
            .expect("the trust store is always usable"),
    );
    let limiter = Arc::new(FlowLimiter::new(64));

    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Ok(accepting) = incoming.accept() else {
                continue;
            };
            let Ok(conn) = accepting.await else {
                continue;
            };

            let config = config.clone();
            let clients = clients.clone();
            let limiter = limiter.clone();
            tokio::spawn(async move {
                // Keep accepting on this connection: a task that returns after
                // one stream drops the connection with it, and the reply it
                // just wrote goes with it.
                while let Ok((send, recv)) = conn.accept_bi().await {
                    // One id per stream, the way the server does it: what the
                    // reply carries has to be the id of this request, not a
                    // constant, or a test that reads the header proves nothing.
                    let request_id = nexapipe::log::next_request_id();
                    // No handshake in front of this one, so no client or
                    // device for the access log to name.
                    let _ = conn::handle_bidi_stream(
                        send,
                        recv,
                        config.clone(),
                        clients.clone(),
                        &limiter,
                        "data-plane-test",
                        None,
                        &request_id,
                        nexapipe::conn::peers::PeerIdentity::default(),
                        nexapipe_proto::protocol::Protocol::Legacy,
                    )
                    .await;
                }
            });
        }
    });

    Proxy { addr }
}

/// The same proxy, with 2FA in front of it.
///
/// The connection is handed to `handle_connection` rather than to
/// `handle_bidi_stream`, because the handshake lives in the first: the stream
/// that carries AUTH_START is not a request, and a client that does not
/// perform the handshake never gets to the data path at all.
async fn spawn_proxy_with_auth(routes: Vec<Route>, auth: conn::AuthState) -> Proxy {
    let ep = bind().await;
    let addr = dial_address(&ep);

    let config = Arc::new(RoutingTable::with_settings(
        routes,
        Timeouts::default(),
        Retry::default(),
    ));
    let clients = Arc::new(
        http::BackendClients::new(Timeouts::default().connect, None)
            .expect("the trust store is always usable"),
    );
    let peers = Arc::new(conn::peers::PeerRegistry::new());
    let limits = conn::limits::Limits::resolve(
        &conn::limits::LimitsConfig::default(),
        &conn::limits::EnvCaps::from_environment(),
    )
    .expect("the default limits resolve");
    let limiters = conn::limits::Limiters::from_limits(&limits);

    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Ok(accepting) = incoming.accept() else {
                continue;
            };
            let Ok(conn) = accepting.await else {
                continue;
            };

            let config = config.clone();
            let clients = clients.clone();
            let auth = auth.clone();
            let peers = peers.clone();
            let limiters = limiters.clone();

            tokio::spawn(async move {
                conn::handle_connection(conn, config, clients, Some(auth), peers, limiters).await;
            });
        }
    });

    Proxy { addr }
}

/// The ALPNs the server accepts, in the order the binary lists them.
///
/// The list is written down once, in the crate the binary links too: the
/// per-protocol names come first, because QUIC picks the first of the
/// **accept side's** entries that the peer also offers — so the server's
/// order is the preference order, and the client's offer order is not.
fn server_alpns() -> Vec<Vec<u8>> {
    nexapipe_proto::protocol::accepted_alpns()
}

/// The proxy the binary runs: the connection is handed to `handle_connection`,
/// so the protocol is read off the handshake rather than sniffed off the
/// stream.
///
/// The earlier harness here hands the stream to `handle_bidi_stream` with the
/// protocol spelled out, which skips the half that reads it — and that half
/// is the one this is about.
async fn spawn_proxy_that_reads_the_protocol(routes: Vec<Route>) -> Proxy {
    let ep = bind_with_alpns(server_alpns()).await;
    let addr = dial_address(&ep);

    let config = Arc::new(RoutingTable::with_settings(
        routes,
        Timeouts::default(),
        Retry::default(),
    ));
    let clients = Arc::new(
        http::BackendClients::new(Timeouts::default().connect, None)
            .expect("the trust store is always usable"),
    );
    let peers = Arc::new(conn::peers::PeerRegistry::new());
    let limits = conn::limits::Limits::resolve(
        &conn::limits::LimitsConfig::default(),
        &conn::limits::EnvCaps::from_environment(),
    )
    .expect("the default limits resolve");
    let limiters = conn::limits::Limiters::from_limits(&limits);

    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Ok(accepting) = incoming.accept() else {
                continue;
            };
            let Ok(conn) = accepting.await else {
                continue;
            };

            let config = config.clone();
            let clients = clients.clone();
            let peers = peers.clone();
            let limiters = limiters.clone();

            tokio::spawn(async move {
                conn::handle_connection(conn, config, clients, None, peers, limiters).await;
            });
        }
    });

    Proxy { addr }
}

fn http_route(host: &str, backend: &str) -> Route {
    Route::new(
        host,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    )
}

fn passthrough_route(host: &str, backend: &str) -> Route {
    Route::new(
        host,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Passthrough,
        None,
    )
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

struct Tunnel {
    // Outlives the connection: dropping the endpoint closes everything on it.
    _endpoint: Endpoint,
    conn: iroh::endpoint::Connection,
}

impl Tunnel {
    async fn dial(addr: EndpointAddr) -> Self {
        Self::dial_with_alpn(addr, ALPN).await
    }

    /// The same, asking for a named protocol.
    ///
    /// The ALPN is what the negotiation lands on, and the server reads the
    /// protocol off it — so a test that asks for one is a test of the
    /// server's answer to it.
    async fn dial_with_alpn(addr: EndpointAddr, alpn: &[u8]) -> Self {
        let endpoint = bind().await;
        let conn = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, alpn))
            .await
            .expect("dialling the proxy timed out")
            .expect("dial the proxy");
        Tunnel {
            _endpoint: endpoint,
            conn,
        }
    }

    /// Sends `payload` and leaves the stream open, then waits out whatever the
    /// proxy does.
    ///
    /// Finishing the stream is the ordinary way to say "that was the whole
    /// request", and the head loop treats an unfinished stream that has ended
    /// as a short request — so the slowloris shape has to keep talking
    /// without ever hanging up.
    async fn send_and_keep_open(&self, payload: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = self.conn.open_bi().await.expect("open_bi");
        send.write_all(payload).await.expect("write request");

        let reply =
            tokio::time::timeout(Duration::from_secs(45), recv.read_to_end(REPLY_LIMIT)).await;
        drop(send);

        match reply {
            Ok(Ok(reply)) => reply,
            _ => Vec::new(),
        }
    }

    /// Sends `parts` on one stream with a pause between them.
    ///
    /// One `write_all` can arrive in a single read, which is the easy case for
    /// anything that reads a body. A pause forces the reader to hold on to
    /// bytes it cannot use yet and pick them up on the next read, which is
    /// where chunk framing is easy to get wrong.
    async fn exchange_split(&self, parts: &[&[u8]]) -> Vec<u8> {
        self.exchange_parts(parts, Duration::from_millis(50)).await
    }

    /// Sends `parts` on one stream, `gap` apart.
    async fn exchange_parts(&self, parts: &[&[u8]], gap: Duration) -> Vec<u8> {
        let (mut send, mut recv) = self.conn.open_bi().await.expect("open_bi");
        for part in parts {
            send.write_all(part).await.expect("write request");
            tokio::time::sleep(gap).await;
        }
        send.finish().expect("finish request");

        recv.read_to_end(REPLY_LIMIT).await.unwrap_or_default()
    }

    /// Sends `payload` on a fresh stream and reads the reply until the peer
    /// finishes it.
    async fn exchange(&self, payload: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = self.conn.open_bi().await.expect("open_bi");
        send.write_all(payload).await.expect("write request");
        send.finish().expect("finish request");

        // A refused or abandoned stream reads back as an empty reply, which is
        // a legitimate answer for the tests that provoke one.
        recv.read_to_end(REPLY_LIMIT).await.unwrap_or_default()
    }

    /// Sends a WebSocket upgrade and reads only its response head.
    ///
    /// An upgrade is not a request with an end: once the `101` arrives the
    /// stream is a conversation, and waiting for EOF would hang on a backend
    /// that is doing exactly the right thing.
    async fn upgrade(&self, payload: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = self.conn.open_bi().await.expect("open_bi");
        send.write_all(payload).await.expect("write request");
        send.finish().expect("finish request");

        let mut reply = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut chunk)).await;
            let Ok(Ok(Some(n))) = read else {
                break;
            };
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&chunk[..n]);
            if reply.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        reply
    }

    /// Opens a WebSocket upgrade and leaves **both** sides of the stream
    /// open, the way the client does.
    ///
    /// A WebSocket keeps talking after the handshake, so the request cannot
    /// be finished: a finished stream is an end of stream for the server,
    /// and it ends the session with it.
    async fn upgrade_and_keep_open(
        &self,
        payload: &[u8],
    ) -> (iroh::endpoint::SendStream, iroh::endpoint::RecvStream) {
        let (mut send, recv) = self.conn.open_bi().await.expect("open_bi");
        send.write_all(payload).await.expect("write request");
        (send, recv)
    }
}

/// Polls `probe` until it yields, so a test can assert on what another task
/// recorded without sleeping for a fixed time.
///
/// The backends record what they saw as their own task gets to it, which is
/// after the exchange that caused it has already returned.
async fn eventually<T, F>(mut probe: F) -> T
where
    F: FnMut() -> Option<T>,
{
    for _ in 0..100 {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the condition was never met within 5s");
}

fn reply_body(reply: &[u8]) -> String {
    let text = String::from_utf8_lossy(reply).to_string();
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}

fn status_of(reply: &[u8]) -> String {
    String::from_utf8_lossy(reply)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A response does not arrive with the backend's own hop headers.
///
/// `connection: keep-alive` describes the backend's link to the proxy, and
/// forwarding it tells the client to keep *its* link open for a response that
/// arrived over a different one.
///
/// And a 204 has no body, so it is not framed: RFC 9110 §6.1 forbids a
/// `transfer-encoding` on a bodyless status, and a client told "chunked"
/// waits for the terminator of a body that is not there.
#[tokio::test]
async fn a_response_is_not_forwarded_with_the_backends_own_hop_headers() {
    let backend = spawn_backend_answering(
        "HTTP/1.1 204 No Content\r\nconnection: keep-alive\r\nkeep-alive: timeout=5\r\n\r\n",
    )
    .await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;
    let text = String::from_utf8_lossy(&reply).to_lowercase();

    assert!(
        !text.contains("keep-alive"),
        "the hop header arrived: {text}"
    );
    assert!(
        !text.contains("connection"),
        "the hop header arrived: {text}"
    );
    assert!(
        !text.contains("transfer-encoding"),
        "a bodyless response was framed: {text}"
    );
}

/// A response with a body is still framed for the client.
///
/// The hop-by-hop headers are dropped, but the body still needs a length or a
/// framing: the client speaks HTTP/1.1, which has no way to say "the body
/// ends when this stream ends", so a body with no length has to be chunked.
#[tokio::test]
async fn a_response_with_a_body_is_still_framed() {
    let backend = spawn_backend_answering(
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;
    let text = String::from_utf8_lossy(&reply).to_lowercase();

    assert!(
        text.contains("transfer-encoding: chunked"),
        "the body was not framed: {text}"
    );
    assert!(
        reply_body(&reply).contains("hello"),
        "the body did not arrive: {text}"
    );
}

/// A `304` is bodyless as well, and equally unframed.
///
/// Its headers still travel: only the hop-by-hop ones are dropped, and an
/// `etag` is what makes a conditional request worth making.
#[tokio::test]
async fn a_304_is_not_framed() {
    let backend =
        spawn_backend_answering("HTTP/1.1 304 Not Modified\r\netag: \"v1\"\r\n\r\n").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET /x HTTP/1.1\r\nHost: app.test\r\nIf-None-Match: \"v1\"\r\n\r\n")
        .await;
    let text = String::from_utf8_lossy(&reply).to_lowercase();

    assert!(
        !text.contains("transfer-encoding"),
        "a bodyless response was framed: {text}"
    );
    assert!(
        text.contains("etag: \"v1\""),
        "a header was dropped: {text}"
    );
    assert!(
        reply_body(&reply).is_empty(),
        "a 304 carried a body: {text}"
    );
}

/// A `HEAD` response is not framed either: the client asked for the head of a
/// response whose body is not sent, whatever the status says.
#[tokio::test]
async fn a_head_response_is_not_framed() {
    let backend = spawn_backend_answering("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"HEAD /x HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;
    let text = String::from_utf8_lossy(&reply).to_lowercase();

    assert!(
        !text.contains("transfer-encoding"),
        "a HEAD response was framed: {text}"
    );
    assert!(
        text.contains("content-length: 5"),
        "the length of the body that would have been sent was dropped: {text}"
    );
    assert!(
        reply_body(&reply).is_empty(),
        "a HEAD response carried a body: {text}"
    );
}

/// A request for a host no route serves is answered **before** its body is
/// read.
///
/// The body of a request that is going to be refused is work nobody asked
/// for: up to `MAX_REQUEST_BODY` (64 MiB) per stream, held in memory, for a
/// request that has no backend to go to.
///
/// And the client waits for the refusal until the body arrives — so a client
/// that has no body to send waits for the body deadline (60 s) instead of
/// being told there is nowhere to send it.
///
/// The plaintext listener already answers first — the lookup, then the body —
/// so the two paths now agree.
#[tokio::test]
async fn a_refused_request_is_answered_without_its_body() {
    let backend = spawn_backend("hello from the backend").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let (mut send, mut recv) = tunnel.conn.open_bi().await.expect("open_bi");
    // A host no route serves, and a body that never arrives.
    send.write_all(b"GET /x HTTP/1.1\r\nHost: unserved.test\r\ncontent-length: 1048576\r\n\r\n")
        .await
        .expect("write the head");

    // The stream stays open: finishing it would end the body, and the test
    // is about a body that does not arrive.
    let mut reply = Vec::new();
    let mut chunk = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(2), recv.read(&mut chunk)).await;
    if let Ok(Ok(Some(n))) = read {
        reply.extend_from_slice(&chunk[..n]);
    }
    drop(send);

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 404"),
        "the refusal arrives without waiting for the body, got {:?}",
        status_of(&reply)
    );
}

#[tokio::test]
async fn a_get_reaches_the_backend_and_the_reply_comes_back() {
    let backend = spawn_backend("hello from the backend").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET /hello HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "expected a 200, got {:?}",
        status_of(&reply)
    );
    assert_eq!(reply_body(&reply), "hello from the backend");

    let seen = backend.seen();
    assert_eq!(seen.len(), 1, "the backend should have seen one request");
    assert_eq!(seen[0].request_line, "GET /hello HTTP/1.1");
}

/// The same retry rule on the tunnel path: a request that never reached a
/// backend is asked of another one.
#[tokio::test]
async fn a_tunneled_request_that_failed_is_tried_on_another_backend() {
    let (dead, _hold) = dead_backend().await;
    let backend = spawn_backend("second").await;
    let route = Route::new(
        "retry.test",
        "/",
        true,
        vec![dead, backend.url.clone()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    );
    let proxy = spawn_proxy_with_settings(
        vec![route],
        Retry {
            attempts: 1,
            backoff: Duration::ZERO,
        },
    )
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET /retry HTTP/1.1\r\nHost: retry.test\r\n\r\n")
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "expected the second backend's 200, got {:?}",
        status_of(&reply)
    );
    assert_eq!(reply_body(&reply), "second");
    assert_eq!(
        backend.seen().len(),
        1,
        "the surviving backend should have seen the retried request once"
    );
}

/// An upload that takes longer than the response deadline is not cut short.
///
/// The response deadline is the backend's: it says how long the backend may
/// take to answer with a status line. It is not the client's, and a client
/// that is still sending its body is not a backend that is slow to answer —
/// the body has a deadline of its own, and it is the one that bounds the
/// upload.
#[tokio::test]
async fn an_upload_longer_than_the_response_deadline_is_not_cut_short() {
    let backend = spawn_backend("uploaded").await;
    let proxy = spawn_proxy_with_timeouts(
        vec![http_route("upload.test", &backend.url)],
        Retry::default(),
        None,
        Timeouts {
            connect: Duration::from_secs(1),
            response: Duration::from_secs(1),
            deadlines: nexapipe::deadline::Deadlines {
                body: Duration::from_secs(30),
                ..Default::default()
            },
        },
    )
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // The body takes longer to arrive than the backend is given to answer.
    let reply = tunnel
        .exchange_parts(
            &[
                b"POST /upload HTTP/1.1\r\nHost: upload.test\r\ncontent-length: 11\r\n\r\nhello ",
                b"world",
            ],
            Duration::from_secs(2),
        )
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "the upload was cut short by the response deadline: {:?}",
        status_of(&reply)
    );
    let seen = backend.seen();
    assert_eq!(
        seen.len(),
        1,
        "the backend should have seen the request once"
    );
    assert_eq!(
        seen[0].body, b"hello world",
        "the backend saw the whole of the body"
    );
}

/// A request with a body is tried on another backend when the first one
/// refused the connection.
///
/// The body was never touched: the connection was refused before a byte of it
/// was sent, so the bytes are still on the client's stream and the next
/// backend gets the whole of them.
#[tokio::test]
async fn a_tunneled_request_with_a_body_is_tried_on_another_backend() {
    let (dead, _hold) = dead_backend().await;
    let backend = spawn_backend("second").await;
    let route = Route::new(
        "retry.test",
        "/",
        true,
        vec![dead, backend.url.clone()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    );
    let proxy = spawn_proxy_with_settings(
        vec![route],
        Retry {
            attempts: 1,
            backoff: Duration::ZERO,
        },
    )
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(
            b"POST /retry HTTP/1.1\r\nHost: retry.test\r\ncontent-length: 11\r\n\r\nhello world",
        )
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "expected the second backend's 200, got {:?}",
        status_of(&reply)
    );
    assert_eq!(reply_body(&reply), "second");
    let seen = backend.seen();
    assert_eq!(
        seen.len(),
        1,
        "the surviving backend should have seen the retried request once"
    );
    assert_eq!(
        seen[0].body, b"hello world",
        "the retried request carries the body the client sent"
    );
}

/// A request whose body was read is **not** tried on another backend.
///
/// The bytes came off the client's stream and are gone: there is no second
/// copy of them, so a retry would send a body that is short. The request
/// fails instead, and the other backend is not asked at all.
#[tokio::test]
async fn a_tunneled_request_whose_body_was_read_is_not_tried_again() {
    let first = spawn_backend_that_hangs_up().await;
    let second = spawn_backend("second").await;
    let route = Route::new(
        "retry.test",
        "/",
        true,
        vec![first.url.clone(), second.url.clone()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    );
    let proxy = spawn_proxy_with_settings(
        vec![route],
        Retry {
            attempts: 1,
            backoff: Duration::ZERO,
        },
    )
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // The body arrives in two pieces, so part of it is still on the client's
    // stream when the backend is reached: the backend reads it, and what came
    // off the stream is gone.
    let reply = tunnel
        .exchange_split(&[
            b"PUT /retry HTTP/1.1\r\nHost: retry.test\r\ncontent-length: 11\r\n\r\nhello ",
            b"world",
        ])
        .await;

    assert!(
        !status_of(&reply).starts_with("HTTP/1.1 200"),
        "the request cannot be tried again, so there is no answer to give: {:?}",
        status_of(&reply)
    );
    assert_eq!(
        first.seen().len(),
        1,
        "the first backend should have seen the request once"
    );
    assert_eq!(
        second.seen().len(),
        0,
        "the second backend must not be asked: the body cannot be sent again"
    );
}

/// **A WebSocket over the connection that named the HTTP protocol.**
///
/// The same upgrade the legacy path carries, over a connection that said what
/// it carries: hyper's own codec hands the connection over when the `101` is
/// written, and the session that follows is two byte streams moved either way.
#[tokio::test]
async fn a_websocket_over_the_named_http_protocol() {
    use nexapipe_proto::protocol::ALPN_HTTP;

    let backend = spawn_websocket_backend(Duration::from_millis(50)).await;
    let proxy = spawn_proxy_that_reads_the_protocol(vec![http_route("ws.test", &backend)]).await;
    let tunnel = Tunnel::dial_with_alpn(proxy.addr.clone(), ALPN_HTTP).await;

    let (_send, mut recv) = tunnel
        .upgrade_and_keep_open(
            b"GET /ws HTTP/1.1\r\n\
              Host: ws.test\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await;

    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await;
    let Ok(Ok(Some(n))) = read else {
        panic!("the upgrade never came back");
    };
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected the backend's upgrade, got {head:?}"
    );

    // The session is what the upgrade is for: the backend keeps pushing, and
    // the bytes have to reach the client.
    let read = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await;
    let Ok(Ok(Some(n))) = read else {
        panic!("the session carried nothing");
    };
    assert!(n > 0, "the session carried no bytes");
}

/// A WebSocket owns its connection, but an `https://` backend is still reached
/// over a TLS session the proxy originates and verifies.
#[tokio::test]
async fn a_websocket_reaches_an_https_backend_over_tls() {
    let backend = spawn_tls_websocket_backend().await;
    let proxy =
        spawn_proxy_with_ca(vec![http_route("ws.test", &backend.url)], &backend.ca_file).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .upgrade(
            b"GET /ws HTTP/1.1\r\n\
              Host: ws.test\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 101"),
        "expected the backend's upgrade, got {:?}",
        String::from_utf8_lossy(&reply)
    );
}

/// A WebSocket that is quiet on one side only stays open.
///
/// The tunnel is bounded by how long the session may be quiet, but a quiet
/// *direction* is not a quiet session: a client that only listens to a feed
/// the backend keeps pushing has nothing to say, and ending that session
/// would cut exactly the traffic that is still flowing.
#[tokio::test]
async fn a_websocket_whose_client_is_quiet_stays_open() {
    let backend = spawn_websocket_backend(Duration::from_millis(100)).await;
    let timeouts = Timeouts {
        deadlines: nexapipe::deadline::Deadlines {
            response_idle: Duration::from_millis(300),
            ..Default::default()
        },
        ..Timeouts::default()
    };
    let proxy = spawn_proxy_with_timeouts(
        vec![http_route("ws.test", &backend)],
        Retry::default(),
        None,
        timeouts,
    )
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let (_send, mut recv) = tunnel
        .upgrade_and_keep_open(
            b"GET /ws HTTP/1.1\r\n\
              Host: ws.test\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await;

    // The upgrade first.
    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await;
    let Ok(Ok(Some(n))) = read else {
        panic!("the upgrade never came back");
    };
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected the backend's upgrade, got {head:?}"
    );

    // Then the traffic: the backend keeps pushing for longer than the idle
    // window while the client says nothing at all. The session has to
    // survive it — the window bounds a quiet session, not a quiet side.
    let mut payload = 0usize;
    let until = tokio::time::Instant::now() + Duration::from_millis(1200);
    while tokio::time::Instant::now() < until {
        let Ok(Ok(Some(n))) =
            tokio::time::timeout(Duration::from_millis(200), recv.read(&mut buf)).await
        else {
            break;
        };
        payload += n;
    }
    assert!(
        payload >= 5,
        "the session should have carried the backend's traffic past the idle \
         window, got {payload} bytes"
    );
}

/// A WebSocket whose two sides both went quiet ends.
///
/// This is the case the bound exists for: neither side has anything left to
/// say, and without it the session keeps a backend connection, a task and a
/// stream slot for as long as the process lives.
#[tokio::test]
async fn a_websocket_whose_two_sides_went_quiet_ends() {
    let backend = spawn_quiet_websocket_backend().await;
    let timeouts = Timeouts {
        deadlines: nexapipe::deadline::Deadlines {
            response_idle: Duration::from_millis(300),
            ..Default::default()
        },
        ..Timeouts::default()
    };
    let proxy = spawn_proxy_with_timeouts(
        vec![http_route("ws.test", &backend)],
        Retry::default(),
        None,
        timeouts,
    )
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let (_send, mut recv) = tunnel
        .upgrade_and_keep_open(
            b"GET /ws HTTP/1.1\r\n\
              Host: ws.test\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await;

    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(Some(_)))),
        "the upgrade never came back: {read:?}"
    );

    // And then the session ends on its own, without another byte from either
    // side.
    let ended = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024)).await;
    assert!(
        ended.is_ok(),
        "the session should have ended once both sides went quiet"
    );
}

/// The id on the reply is the one the access log records, so a client that
/// reports a bad answer can name the line that goes with it. Two exchanges on
/// one tunnel must not come back with the same id, or the header is a constant
/// that identifies nothing.
#[tokio::test]
async fn the_reply_carries_the_request_id() {
    let backend = spawn_backend("hello from the backend").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let first = tunnel
        .exchange(b"GET /one HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;
    let second = tunnel
        .exchange(b"GET /two HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;

    let id_of = |reply: &[u8]| -> String {
        String::from_utf8_lossy(reply)
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.eq_ignore_ascii_case("x-request-id")).then(|| value.trim().to_string())
            })
            .unwrap_or_default()
    };

    assert!(
        status_of(&first).starts_with("HTTP/1.1 200"),
        "expected a 200, got {:?}",
        status_of(&first)
    );
    assert_eq!(
        id_of(&first).len(),
        32,
        "the reply carried no request id: {:?}",
        String::from_utf8_lossy(&first)
    );
    assert_ne!(
        id_of(&first),
        id_of(&second),
        "both replies carried the same id"
    );
}

#[tokio::test]
async fn the_host_header_selects_which_backend_is_asked() {
    let app = spawn_backend("app").await;
    let api = spawn_backend("api").await;
    let proxy = spawn_proxy(vec![
        http_route("app.test", &app.url),
        http_route("api.test", &api.url),
    ])
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let first = tunnel
        .exchange(b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;
    let second = tunnel
        .exchange(b"GET / HTTP/1.1\r\nHost: api.test\r\n\r\n")
        .await;

    assert_eq!(reply_body(&first), "app");
    assert_eq!(reply_body(&second), "api");

    // Each backend was asked once, and only about its own host: a request that
    // landed on both, or on neither, is a routing bug the status codes alone
    // would not show.
    assert_eq!(app.seen().len(), 1);
    assert_eq!(api.seen().len(), 1);
}

#[tokio::test]
async fn a_request_body_is_forwarded_with_the_request() {
    let backend = spawn_backend("done").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"POST /upload HTTP/1.1\r\nHost: app.test\r\ncontent-length: 5\r\n\r\nworld")
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "expected a 200, got {:?}",
        status_of(&reply)
    );

    let seen = backend.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].request_line, "POST /upload HTTP/1.1");
    assert_eq!(seen[0].body, b"world");
}

#[tokio::test]
async fn a_chunked_request_body_is_forwarded_whole() {
    let backend = spawn_backend("done").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // No `content-length` anywhere: the body is framed, so a proxy that only
    // ever reads a declared length would forward the head and drop the rest.
    let reply = tunnel
        .exchange_split(&[
            b"POST /upload HTTP/1.1\r\nHost: app.test\r\ntransfer-encoding: chunked\r\n\r\n",
            b"5\r\nhello\r\n",
            b"6\r\n world\r\n0\r\n\r\n",
        ])
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "expected a 200, got {:?}",
        status_of(&reply)
    );

    let seen = backend.seen();
    assert_eq!(seen.len(), 1);
    // De-chunked and given a length of its own: a backend that only knows
    // `content-length` sees all of it.
    assert_eq!(seen[0].body, b"hello world");
}

#[tokio::test]
async fn a_client_hello_is_copied_to_the_passthrough_backend() {
    let (backend, got) = spawn_raw_backend().await;
    let proxy = spawn_proxy(vec![passthrough_route("app.test", &backend)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // The first byte is what dispatches: 0x16 is a TLS record, so this never
    // reaches an HTTP route even though the proxy is listening either way.
    let hello = client_hello_with_sni("app.test");
    let _ = tunnel.exchange(&hello).await;

    let seen = eventually(|| {
        let seen = got.lock().unwrap().clone();
        (!seen.is_empty()).then_some(seen)
    })
    .await;
    assert!(
        seen.starts_with(&[0x16]),
        "the backend should have received a TLS record, got {} bytes",
        seen.len()
    );
    assert!(
        seen.windows("app.test".len()).any(|w| w == b"app.test"),
        "the ClientHello should reach the backend with its SNI intact"
    );
}

#[tokio::test]
async fn a_head_past_the_limit_is_answered_without_a_backend() {
    let backend = spawn_backend("never").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // A head that is still going past the limit: no blank line anywhere, and
    // no `Host` before the filler, so the only way this can be answered is by
    // stopping the read.
    let mut head = Vec::new();
    head.extend_from_slice(b"GET / HTTP/1.1\r\n");
    head.extend_from_slice(&vec![b'x'; HEAD_LIMIT * 2]);
    let reply = tunnel.exchange(&head).await;

    // 431, and not the 404 this used to answer. The 404 was an accident: the
    // head this sends has no `Host` in it, so the truncated head that used to
    // be parsed here had no route and fell out as a 404. The status a head
    // that is too large deserves is 431 (RFC 9110 15.5.29), and the test
    // below is the one that shows what the old accident cost.
    assert!(
        status_of(&reply).contains("431"),
        "a head past the limit should be answered with 431, got {:?}",
        status_of(&reply)
    );
    assert!(
        backend.seen().is_empty(),
        "a head that was never completed must not reach a backend"
    );
}

/// A head past the limit that *does* name a host is the case the test above
/// cannot see.
///
/// The head is truncated by the limit, and the truncated head used to be
/// parsed as if it were the whole request. With no `Host` in it that fell out
/// as a 404 and nothing reached a backend, so the test above passed. With a
/// `Host` in it the request was routed, and the backend was asked to serve a
/// head whose last line had been cut in half.
#[tokio::test]
async fn a_head_past_the_limit_with_a_host_never_reaches_a_backend() {
    let backend = spawn_backend("never").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // A `Host` that names a route, and then a head that never ends.
    let mut head = Vec::new();
    head.extend_from_slice(b"GET / HTTP/1.1\r\nHost: app.test\r\n");
    head.extend_from_slice(&vec![b'x'; HEAD_LIMIT * 2]);
    let reply = tunnel.exchange(&head).await;

    assert!(
        status_of(&reply).contains("431"),
        "a head past the limit should be answered with 431, got {:?}",
        status_of(&reply)
    );
    assert!(
        backend.seen().is_empty(),
        "a head that was never completed must not reach a backend, even with a Host in it"
    );
}

/// A request that names more than one host is refused, and reaches no backend.
///
/// The two halves of this proxy used to resolve an ambiguous request
/// differently: the route and the access check read the **first** `Host`
/// header, and the backend was handed **all** of them. A client that was
/// allowed for `app.test` could therefore send that name first and a second
/// one behind it, and a backend that picks the last one would serve the
/// second name's vhost to a request that was authorised for the first.
///
/// The unit tests cover the parser and the header count; this one is the
/// whole path, because the claim is about what reaches a backend.
#[tokio::test]
async fn a_request_with_more_than_one_host_is_refused() {
    let backend = spawn_backend("never").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET / HTTP/1.1\r\nHost: app.test\r\nHost: internal.test\r\n\r\n")
        .await;

    assert!(
        status_of(&reply).contains("400"),
        "a request with two hosts should be answered with 400, got {:?}",
        status_of(&reply)
    );
    assert!(
        backend.seen().is_empty(),
        "a request that names two hosts must not reach a backend: the host that was \
         authorised and the host that would be served are two different hosts"
    );
}

/// **The first byte of a request is part of the request.**
///
/// The old ALPN does not say what a stream carries, so the server reads the
/// first byte to find out. When it turns out to be a request, that byte is
/// part of the request — and the codec reads the head from the beginning, so
/// a head that started one byte later would be a different request.
///
/// The byte is written on its own here, so the read that finds out what the
/// stream carries is a read of one byte and nothing else, and the rest of
/// the head arrives after it.
#[tokio::test]
async fn the_first_byte_of_a_request_is_part_of_the_request() {
    let backend = spawn_backend("done").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange_split(&[b"G", b"ET / HTTP/1.1\r\nHost: app.test\r\n\r\n"])
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "expected a 200, got {:?}",
        status_of(&reply)
    );

    let seen = backend.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].request_line, "GET / HTTP/1.1",
        "the request the backend saw is not the one the client sent"
    );
}

/// A request that names more than one host is refused on the named protocol
/// too.
///
/// The two listeners used to differ here: the plaintext one caught it, and
/// the tunnel one did not — because the tunnel path parsed the head by hand
/// and the parser was the one refusing it. With hyper's codec on both, the
/// check is the proxy's own, and it is made in one place.
#[tokio::test]
async fn a_request_with_more_than_one_host_is_refused_on_the_named_protocol() {
    use nexapipe_proto::protocol::ALPN_HTTP;

    let backend = spawn_backend("never").await;
    let proxy =
        spawn_proxy_that_reads_the_protocol(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial_with_alpn(proxy.addr, ALPN_HTTP).await;

    let reply = tunnel
        .exchange(b"GET / HTTP/1.1\r\nHost: app.test\r\nHost: internal.test\r\n\r\n")
        .await;

    assert!(
        status_of(&reply).contains("400"),
        "a request with two hosts should be answered with 400, got {:?}",
        status_of(&reply)
    );
    assert!(
        backend.seen().is_empty(),
        "a request that names two hosts must not reach a backend: the host that was \
         authorised and the host that would be served are two different hosts"
    );
}

/// A head that never finishes is dropped when its deadline passes.
///
/// The head deadline is 30 s by default, so the proxy is given a short one
/// rather than the test waiting half a minute for it.
#[tokio::test]
async fn a_head_that_never_arrives_is_dropped() {
    let backend = spawn_backend("never").await;
    let timeouts = Timeouts {
        deadlines: nexapipe::deadline::Deadlines {
            header: Duration::from_millis(200),
            ..Default::default()
        },
        ..Timeouts::default()
    };
    let proxy = spawn_proxy_with_timeouts(
        vec![http_route("app.test", &backend.url)],
        Retry::default(),
        None,
        timeouts,
    )
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // A request line and a `Host`, never finished, and the stream is left open
    // so the head loop cannot read an end of stream instead of a head.
    let reply = tunnel
        .send_and_keep_open(b"GET / HTTP/1.1\r\nHost: app.test\r\n")
        .await;

    assert!(
        backend.seen().is_empty(),
        "a head that never finished must not reach a backend"
    );
    assert!(
        !status_of(&reply).starts_with("HTTP/1.1 200"),
        "a request that never completed should not be served"
    );
}

// ---------------------------------------------------------------------------
// A TLS ClientHello
// ---------------------------------------------------------------------------

/// The smallest ClientHello that carries `sni`, built the way
/// `passthrough::extract_sni` reads it: record, handshake, extensions.
fn client_hello_with_sni(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();

    let mut extension = Vec::new();
    extension.extend_from_slice(&0u16.to_be_bytes()); // server_name
    let entry_len = 1 + 2 + sni_bytes.len();
    extension.extend_from_slice(&((2 + entry_len) as u16).to_be_bytes());
    extension.extend_from_slice(&(entry_len as u16).to_be_bytes());
    extension.push(0); // host_name
    extension.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    extension.extend_from_slice(sni_bytes);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id length
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1); // compression methods length
    body.push(0);
    body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    body.extend_from_slice(&extension);

    let mut handshake = vec![0x01]; // client_hello
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

// ---------------------------------------------------------------------------
// The 2FA handshake
// ---------------------------------------------------------------------------

/// The client the handshake authenticates.
const CLIENT_ID: &str = "client-001";

/// The secret it shares with the server.
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// A 2FA configuration with one client and one secret.
fn auth_config() -> AuthConfig {
    let mut config = AuthConfig {
        enabled: true,
        max_attempts: 3,
        lockout_duration: 60,
        ..AuthConfig::default()
    };
    config.clients.insert(
        CLIENT_ID.to_string(),
        ClientAuth {
            secret: SecretString::new(SECRET.to_string()),
            created_at: "0".to_string(),
            allow_hosts: None,
            allow_ports: None,
            allow_ports_strict: false,
            pending_enrollment: None,
            devices: std::collections::HashMap::new(),
            unnamed_device_allowed: true,
            last_used: None,
            last_used_step: None,
            failed_attempts: 0,
            locked_until: None,
            enrollment_failed_attempts: 0,
            enrollment_locked_until: None,
        },
    );
    config
}

/// The same configuration, with a token waiting to be spent.
///
/// A client with nothing pending cannot be enrolled at all, and a guess at it
/// is a guess at nothing — so the enrollment counter only has something to
/// count when the section below carries a token.
fn auth_config_with_pending(token: &str) -> AuthConfig {
    let mut config = auth_config();
    let client = config
        .clients
        .get_mut(CLIENT_ID)
        .expect("the client is there");
    client.pending_enrollment = Some(SecretString::new(token.to_string()));
    config
}

/// 2FA state whose files live in a directory the test owns.
///
/// The counters are written beside the configuration, and a relative path
/// would leave a `state.toml` and its lock file in the crate directory every
/// time the suite runs. The directory is returned so it outlives the proxy.
fn auth_state(config: AuthConfig) -> (conn::AuthState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("config.toml");
    (
        conn::AuthState::new(config, path.to_string_lossy().into_owned()),
        dir,
    )
}

/// Performs the handshake on a fresh stream: AUTH_START, the challenge, and
/// the response signed over it.
///
/// `code` is the TOTP code that goes out; `None` means the current one, and
/// an empty one is what a key-based device sends.
async fn handshake(
    tunnel: &Tunnel,
    client: &TwoFactorAuth,
    code: Option<String>,
    device: Option<&str>,
) -> AuthMessage {
    handshake_in(tunnel, client, code, device, Format::LegacyJson)
        .await
        .0
}

/// The same handshake, in the form the client speaks, and the forms the
/// answers came back in.
///
/// The forms are returned because they are the point: the server answers in
/// the form the client asked in, and a test that only looked at the message
/// would not notice a server that answered in the wrong one.
async fn handshake_in(
    tunnel: &Tunnel,
    client: &TwoFactorAuth,
    code: Option<String>,
    device: Option<&str>,
    format: Format,
) -> (AuthMessage, Format, Format) {
    let (mut send, mut recv) = tunnel.conn.open_bi().await.expect("open_bi");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    write_message_in(
        &mut send,
        &AuthMessage::Start {
            client_id: CLIENT_ID.to_string(),
            timestamp,
            device_id: None,
            version: None,
        },
        format,
    )
    .await;

    let (challenge, challenge_format) = read_message_in(&mut recv).await;
    let AuthMessage::Challenge { nonce } = challenge else {
        panic!("the server answers with a challenge, got {challenge:?}");
    };

    // The nonce is the server's random challenge, read off the wire — not a
    // value this file makes up. The code-scanning query reads the buffer it
    // arrived in as a hard-coded one, and the challenge is then "a nonce" that
    // is hard-coded.
    // codeql[rust/hard-coded-cryptographic-value]
    let signature = client
        .sign_challenge(&nonce, timestamp)
        .expect("the challenge is signed");
    let code = match code {
        Some(code) => code,
        None => client.generate_code().expect("the code is generated"),
    };

    write_message_in(
        &mut send,
        &AuthMessage::Response {
            client_id: CLIENT_ID.to_string(),
            timestamp,
            totp_code: code,
            signature,
            device_id: device.map(str::to_string),
        },
        format,
    )
    .await;

    let (result, result_format) = read_message_in(&mut recv).await;
    (result, challenge_format, result_format)
}

/// Writes one length-prefixed message in the form asked for.
async fn write_message_in(send: &mut SendStream, message: &AuthMessage, format: Format) {
    let bytes = message.to_payload(format).expect("the message serializes");
    send.write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .expect("the length goes out");
    send.write_all(&bytes).await.expect("the message goes out");
}

/// Reads one length-prefixed message, in whatever form it arrived.
async fn read_message_in(recv: &mut RecvStream) -> (AuthMessage, Format) {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.expect("the length comes");
    let len = u32::from_le_bytes(len) as usize;
    // Read into an empty buffer rather than a zero-filled one. The bytes come
    // from the peer, and a buffer of constant bytes is what the code-scanning
    // query reads as a hard-coded cryptographic value — the challenge nonce
    // ends up looking like one, because the query cannot see that
    // `read_exact` overwrites every byte of it.
    let mut buf = Vec::new();
    let mut limited = recv.take(len as u64);
    limited
        .read_to_end(&mut buf)
        .await
        .expect("the message comes");
    assert_eq!(buf.len(), len, "the message is as long as it said");
    AuthMessage::from_payload(&buf).expect("the message parses")
}

/// The close code the server ended the connection with, if it has.
async fn close_code(tunnel: &Tunnel) -> Option<u32> {
    for _ in 0..100 {
        match tunnel.conn.close_reason() {
            Some(iroh::endpoint::ConnectionError::ApplicationClosed(close)) => {
                return Some(close.error_code.into_inner() as u32);
            }
            Some(other) => panic!("the connection was closed another way: {other}"),
            None => {}
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

/// A correct code gets in.
///
/// The whole handshake, over a real connection: the stream that carries
/// AUTH_START, the challenge, the response signed over it, and the answer.
#[tokio::test]
async fn a_correct_code_gets_in() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config());
    let proxy = spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let client =
        TwoFactorAuth::new(CLIENT_ID, SECRET, ClientTotpAlgorithm::SHA1).expect("the client");
    let answer = handshake(&tunnel, &client, None, None).await;

    assert!(
        matches!(answer, AuthMessage::Ok),
        "the handshake succeeded, got {answer:?}"
    );
}

/// A wrong code is refused, and the connection is closed with the code that
/// says the credentials were refused.
#[tokio::test]
async fn a_wrong_code_is_refused() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config());
    let proxy = spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let client =
        TwoFactorAuth::new(CLIENT_ID, SECRET, ClientTotpAlgorithm::SHA1).expect("the client");
    // Signed correctly, so the refusal is about the code and nothing else.
    let answer = handshake(&tunnel, &client, Some("000000".to_string()), None).await;

    assert!(
        matches!(answer, AuthMessage::Failed { .. }),
        "the credentials were refused, got {answer:?}"
    );
    assert_eq!(
        close_code(&tunnel).await,
        Some(3),
        "the connection is closed with the code that says the credentials were refused"
    );
}

/// A client that does not perform the handshake is closed with the code that
/// says the handshake was required.
#[tokio::test]
async fn a_client_that_does_not_handshake_is_closed() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config());
    let proxy = spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // A request, where AUTH_START was expected.
    let (mut send, _recv) = tunnel.conn.open_bi().await.expect("open_bi");
    send.write_all(b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await
        .expect("the request goes out");

    assert_eq!(
        close_code(&tunnel).await,
        Some(2),
        "the connection is closed with the code that says the handshake was required"
    );
    assert!(
        backend.seen().is_empty(),
        "a request that never handshook must not reach a backend"
    );
}

/// The step memory refuses a code from an **earlier** step, and lets the same
/// one through again.
///
/// A code is inside the acceptance window for the whole of its step, so "this
/// code is current" and "this code has been used" are different questions,
/// and only the step tells them apart.
///
/// The rule is one step back, not the same step: a client that opens several
/// connections in the same step sends the same code for each of them — the
/// protocol is chosen at the handshake, so a client that speaks HTTP and L4
/// holds a connection for each — and refusing the second would leave the
/// client with connections it cannot open.
///
/// The refusal is not a **guess**, and it does not count as one. The counter
/// is what stops the guessing, and a code from an earlier step is not
/// something anybody guessed.
#[tokio::test]
async fn an_earlier_steps_code_is_refused_and_the_same_one_again_is_not() {
    // The scenario is about a *step*, and a step is thirty seconds long: a
    // boundary crossed in the middle of the test would put the code of the
    // earlier step two steps behind the server's origin, outside the
    // acceptance window, and the server would count it as a wrong code
    // instead of refusing it. The test and the server share a clock, so the
    // test can see the boundary coming and wait it out.
    wait_for_a_comfortable_step().await;

    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config());
    let proxy =
        spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth.clone()).await;
    let tunnel = Tunnel::dial(proxy.addr.clone()).await;

    let client =
        TwoFactorAuth::new(CLIENT_ID, SECRET, ClientTotpAlgorithm::SHA1).expect("the client");
    let code = client.generate_code().expect("the code is generated");

    // The first use is accepted, and the step it matched on is remembered.
    let answer = handshake(&tunnel, &client, Some(code.clone()), None).await;
    assert!(
        matches!(answer, AuthMessage::Ok),
        "the first use of a code is accepted, got {answer:?}"
    );

    // The same code on a **second connection** is accepted, and it has to be:
    // a client that opens several connections in the same step sends the
    // same code for each of them — the protocol is chosen at the handshake,
    // so a client that speaks HTTP and L4 holds a connection for each — and
    // refusing the second would leave the client with connections it cannot
    // open.
    let second = Tunnel::dial(proxy.addr.clone()).await;
    let answer = handshake(&second, &client, Some(code), None).await;
    assert!(
        matches!(answer, AuthMessage::Ok),
        "the same code on another connection is accepted, got {answer:?}"
    );

    // What **is** refused is a code from an *earlier* step: it is still
    // inside the acceptance window — the window is about how far the clocks
    // may differ, not about whether a code has been used — and the memory of
    // the step is what refuses it.
    let older = Tunnel::dial(proxy.addr.clone()).await;
    let refused = handshake(&older, &client, Some(previous_step_code(SECRET)), None).await;
    assert!(
        matches!(refused, AuthMessage::Failed { .. }),
        "a code from an earlier step is refused, got {refused:?}"
    );

    // And none of it was counted: the counter is for guesses, and a code
    // that has been used already is not one.
    //
    // The guard is scoped to the block on purpose: it is a **read** lock on
    // the same configuration the server takes a **write** lock on for the
    // next handshake, and a reader held across it would keep the server
    // waiting — until its handshake deadline closed the connection with "2FA
    // required".
    {
        let config = auth.config().read().await;
        assert_eq!(
            config.clients[CLIENT_ID].failed_attempts, 0,
            "a refused code is not a guess, and must not be counted as one"
        );
    }

    // The reply for a refused replay is the reply for a wrong code, byte for
    // byte: a distinct message would say that the code was *right* and only
    // too old, which is an oracle — it would tell an attacker that the code
    // it holds is the right one. The reason goes to the log instead.
    let wrong = Tunnel::dial(proxy.addr.clone()).await;
    let wrong_answer = handshake(&wrong, &client, Some("000000".to_string()), None).await;
    let refused_reason = match &refused {
        AuthMessage::Failed { reason } => reason.clone(),
        other => panic!("a refused replay answers with a failure, got {other:?}"),
    };
    let wrong_reason = match &wrong_answer {
        AuthMessage::Failed { reason } => reason.clone(),
        other => panic!("a wrong code answers with a failure, got {other:?}"),
    };
    assert_eq!(
        refused_reason, wrong_reason,
        "a refused replay answers exactly as a wrong code does"
    );
}

/// Waits until the current step has enough of it left for the test to finish.
///
/// A TOTP step is thirty seconds, and the code of the *earlier* step is only
/// refused while the server is still in the step the test started in. A
/// boundary crossed in between puts that code two steps behind, outside the
/// acceptance window, and the server counts it as a wrong code — the test
/// then fails for a reason that has nothing to do with what it is testing.
/// The test and the server share a clock, so the test can see the boundary
/// coming and wait it out.
async fn wait_for_a_comfortable_step() {
    const STEP: u64 = 30;
    const WANTED: u64 = 5;
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let left = STEP - (now % STEP);
        if left >= WANTED {
            return;
        }
        // Past the boundary, and a second into the new step: the server's
        // origin is the new one, and the code of the step before it is
        // inside the window for the next twenty-nine seconds.
        tokio::time::sleep(std::time::Duration::from_secs(left + 1)).await;
    }
}

/// The code of the step **before** this one.
///
/// The client's own generator only makes the current code, and the code of an
/// earlier step is what the memory refuses — so the test makes it itself.
fn previous_step_code(secret: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secret = totp_rs::Secret::try_from_base32(secret).expect("the secret decodes");
    totp_rs::Builder::new()
        .with_secret(secret)
        .build()
        .expect("the generator is built")
        .generate(now - 30)
        .to_string()
}

/// A device that proves itself with a key gets in without a code.
///
/// The device is issued its credential at enrollment, and the answer to the
/// challenge is a signature over it — the TOTP code is empty, because there is
/// no secret to compute one from.
#[tokio::test]
async fn a_device_key_gets_in() {
    let key = iroh::SecretKey::generate();
    let public_key = nexapipe::auth::public_key_hex(&key.public());

    let mut config = auth_config();
    let client = config.clients.get_mut(CLIENT_ID).expect("the client");
    client.secret = SecretString::new(String::new());
    client.devices.insert(
        "laptop".to_string(),
        DeviceAuth {
            secret: SecretString::new(String::new()),
            public_key: Some(public_key),
            created_at: "0".to_string(),
            last_used: None,
            last_used_step: None,
        },
    );

    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(config);
    let proxy = spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let client = TwoFactorAuth::with_key(CLIENT_ID, key, "laptop");
    let answer = handshake(&tunnel, &client, Some(String::new()), Some("laptop")).await;

    assert!(
        matches!(answer, AuthMessage::Ok),
        "the handshake succeeded, got {answer:?}"
    );
}

/// A client that speaks the versioned JSON form completes the handshake.
///
/// The server answers in the form the client asked in: the challenge and the
/// result are both the versioned JSON, and the client reads them without
/// knowing which form to expect.
#[tokio::test]
async fn a_client_that_speaks_the_versioned_json_form_gets_in() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config());
    let proxy = spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let client =
        TwoFactorAuth::new(CLIENT_ID, SECRET, ClientTotpAlgorithm::SHA1).expect("the client");
    let (answer, challenge_format, result_format) =
        handshake_in(&tunnel, &client, None, None, Format::Json).await;

    assert!(
        matches!(answer, AuthMessage::Ok),
        "the handshake succeeded, got {answer:?}"
    );
    assert_eq!(
        challenge_format,
        Format::Json,
        "the challenge came back in the form the client asked in"
    );
    assert_eq!(
        result_format,
        Format::Json,
        "the result came back in the form the client asked in"
    );
}

/// A client that speaks the binary form completes the handshake, and the
/// answers come back in the binary form.
#[tokio::test]
async fn a_client_that_speaks_the_binary_form_gets_in() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config());
    let proxy = spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let client =
        TwoFactorAuth::new(CLIENT_ID, SECRET, ClientTotpAlgorithm::SHA1).expect("the client");
    let (answer, challenge_format, result_format) =
        handshake_in(&tunnel, &client, None, None, Format::Binary).await;

    assert!(
        matches!(answer, AuthMessage::Ok),
        "the handshake succeeded, got {answer:?}"
    );
    assert_eq!(
        challenge_format,
        Format::Binary,
        "the challenge came back in the form the client asked in"
    );
    assert_eq!(
        result_format,
        Format::Binary,
        "the result came back in the form the client asked in"
    );
}

/// A client that announces a version is answered in it.
///
/// The announcement is inside the JSON of the first message, where a server
/// that predates the version byte ignores it — and a server that knows it
/// answers in the version the client asked for.
#[tokio::test]
async fn a_client_that_announces_a_version_is_answered_in_it() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config());
    let proxy = spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let (mut send, mut recv) = tunnel.conn.open_bi().await.expect("open_bi");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // The announcement travels in the JSON, where an old server drops the
    // field it does not know.
    write_message_in(
        &mut send,
        &AuthMessage::Start {
            client_id: CLIENT_ID.to_string(),
            timestamp,
            device_id: None,
            version: Some(nexapipe_proto::auth::VERSION_BINARY),
        },
        Format::LegacyJson,
    )
    .await;

    let (challenge, challenge_format) = read_message_in(&mut recv).await;
    assert!(
        matches!(challenge, AuthMessage::Challenge { .. }),
        "the server answers with a challenge, got {challenge:?}"
    );
    assert_eq!(
        challenge_format,
        Format::Binary,
        "the server answered in the version the client announced"
    );
}

/// The real client, the real server, and the versioned protocol.
///
/// The other tests in this file hand-roll the handshake; this one is the
/// client's own — the same code the Android app and the desktop app call —
/// against a server that knows the binary form. The client announces the
/// version it speaks, the server answers in it, and the handshake completes.
///
/// The three links of that chain are pinned by three tests: this one says the
/// client's own path completes against a real server, the client's unit test
/// says the first message announces the version, and the server's own test
/// says a server answers an announced message in the version that was asked
/// for.
#[tokio::test]
async fn the_client_completes_the_handshake_against_a_server_that_knows_the_binary_form() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config());
    let proxy = spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let client =
        TwoFactorAuth::new(CLIENT_ID, SECRET, ClientTotpAlgorithm::SHA1).expect("the client");
    client
        .authenticate(&tunnel.conn)
        .await
        .expect("the handshake completes");
}
/// A guess at a pending enrollment token is counted — against the enrollment,
/// and not against the client.
///
/// A client id is not a secret: it is in the invite link, in `nexapipe client
/// list` and in whatever the operator pasted into a ticket. So anybody who
/// knows one can send enrollment attempts at a client that is waiting to
/// enroll. While those attempts were counted against the client's
/// authentication counter, the devices that had already enrolled were locked
/// out over a credential they were never sent.
#[tokio::test]
async fn a_wrong_enrollment_token_is_counted_against_the_enrollment_only() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config_with_pending("0123456789abcdef"));
    let proxy =
        spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth.clone()).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // The guess: a token that is not the one that is outstanding.
    let outcome = Enrollment::new(CLIENT_ID, "0123456789abcde0")
        .exchange(&tunnel.conn)
        .await;
    assert!(
        outcome.is_err(),
        "a wrong token is refused, and no credential comes back"
    );

    // What the guess cost. The token's own counter moved; the client's did
    // not, and the client is not locked out of anything.
    let config = auth.config().read().await;
    let client = &config.clients[CLIENT_ID];
    assert_eq!(
        client.enrollment_failed_attempts, 1,
        "the enrollment's own counter moved"
    );
    assert_eq!(
        client.failed_attempts, 0,
        "the client's authentication counter did not: a client id is not a secret, and somebody \
         who knows one must not be able to lock the client's own devices out"
    );
    assert!(
        client.locked_until.is_none(),
        "the client is not locked out"
    );
}

/// Spending the token spends the guesses at it: a successful enrollment clears
/// the enrollment's counter along with the token it belonged to.
///
/// The next invite replaces the token rather than extending it, so a count left
/// over from this one would start the next enrollment one mistake away from a
/// lockout earned by a token that no longer exists — and the state file would
/// carry that count across a restart.
#[tokio::test]
async fn a_spent_token_takes_its_guesses_with_it() {
    let backend = spawn_backend("hello").await;
    let (auth, dir) = auth_state(auth_config_with_pending("0123456789abcdef"));
    // A successful enrollment spends the token by editing the file, so the
    // client it edits has to be there.
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "[auth]\nenabled = true\n\n[auth.clients.{CLIENT_ID}]\nsecret = \"{SECRET}\"\n\
             pending_enrollment = \"0123456789abcdef\"\n"
        ),
    )
    .expect("the config file is written");
    let proxy =
        spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth.clone()).await;

    let tunnel = Tunnel::dial(proxy.addr.clone()).await;
    let outcome = Enrollment::new(CLIENT_ID, "0123456789abcde0")
        .exchange(&tunnel.conn)
        .await;
    assert!(outcome.is_err(), "the wrong token is refused");

    let tunnel = Tunnel::dial(proxy.addr).await;
    Enrollment::new(CLIENT_ID, "0123456789abcdef")
        .exchange(&tunnel.conn)
        .await
        .expect("the right token enrolls");

    let config = auth.config().read().await;
    let client = &config.clients[CLIENT_ID];
    assert_eq!(
        client.enrollment_failed_attempts, 0,
        "the counter went with the token it was counting guesses at"
    );
    assert!(
        client.enrollment_locked_until.is_none(),
        "the enrollment slot is open again"
    );
    drop(config);

    let state = std::fs::read_to_string(dir.path().join("config.state.toml"))
        .expect("the state file is written");
    assert!(
        !state.contains("enrollment_failed_attempts"),
        "the spent guess is not carried into the state file: {state}"
    );
}

/// The token keeps a ceiling: `max_attempts` wrong guesses close the
/// enrollment for the window, and the right token is refused with it.
///
/// The ceiling is what makes the link unguessable rather than merely
/// unshared — and it is the enrollment's ceiling, not the client's.
#[tokio::test]
async fn the_enrollment_token_has_a_ceiling_of_its_own() {
    let backend = spawn_backend("hello").await;
    let (auth, _dir) = auth_state(auth_config_with_pending("0123456789abcdef"));
    let proxy =
        spawn_proxy_with_auth(vec![http_route("app.test", &backend.url)], auth.clone()).await;

    // A refusal closes the connection, so every guess is a new one.
    for _ in 0..3 {
        let tunnel = Tunnel::dial(proxy.addr.clone()).await;
        let outcome = Enrollment::new(CLIENT_ID, "0123456789abcde0")
            .exchange(&tunnel.conn)
            .await;
        assert!(outcome.is_err(), "a wrong token is refused");
    }

    // The right token does not get in either: the slot is closed.
    let tunnel = Tunnel::dial(proxy.addr.clone()).await;
    let outcome = Enrollment::new(CLIENT_ID, "0123456789abcdef")
        .exchange(&tunnel.conn)
        .await;
    assert!(
        outcome.is_err(),
        "the enrollment slot is closed while the window runs"
    );

    let config = auth.config().read().await;
    let client = &config.clients[CLIENT_ID];
    assert!(
        client.enrollment_locked_until.is_some(),
        "the enrollment's own window is running"
    );
    assert_eq!(
        client.failed_attempts, 0,
        "the client's authentication counter did not move"
    );
    assert!(
        client.locked_until.is_none(),
        "the client is not locked out: the devices that already enrolled go on authenticating"
    );
}

/// Accepts connections and holds them open.
///
/// iroh completes an incoming handshake when the application accepts it, so a
/// test that only asks whether the ALPN negotiation worked still has to run an
/// accept loop — without one the client waits for a handshake nobody drives.
fn spawn_acceptor(ep: Endpoint) {
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            tokio::spawn(async move {
                if let Ok(accepting) = incoming.accept() {
                    let _ = accepting.await;
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// ALPN compatibility
// ---------------------------------------------------------------------------

/// A client built before the prefix byte was dropped speaks the legacy ALPN,
/// and a proxy that speaks both still lets it in.
///
/// The proxy accepts the current ALPN and the legacy one, and the client only
/// offers the legacy one — the negotiation has to meet on it.
#[tokio::test]
async fn a_client_that_speaks_the_legacy_alpn_still_reaches_a_proxy() {
    let server = bind_with_alpns(vec![ALPN.to_vec(), ALPN_LEGACY.to_vec()]).await;
    spawn_acceptor(server.clone());
    let client = bind().await;

    let conn = tokio::time::timeout(
        DIAL_TIMEOUT,
        client.connect(dial_address(&server), ALPN_LEGACY),
    )
    .await
    .expect("dialling the proxy timed out")
    .expect("a proxy that speaks both ALPNs takes the legacy one");

    // The connection is up; a stream on it is what the tunnel does next.
    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await
        .expect("write request");
}

/// A proxy that speaks only the legacy ALPN still lets a current client in.
///
/// The current client offers the current ALPN *and* the legacy one, so the
/// negotiation has a protocol in common.
#[tokio::test]
async fn a_client_that_offers_both_alpns_reaches_a_legacy_proxy() {
    let server = bind_with_alpns(vec![ALPN_LEGACY.to_vec()]).await;
    spawn_acceptor(server.clone());
    let client = bind().await;

    let conn = tokio::time::timeout(
        DIAL_TIMEOUT,
        client.connect_with_opts(
            dial_address(&server),
            ALPN,
            ConnectOptions::new().with_additional_alpns(vec![ALPN_LEGACY.to_vec()]),
        ),
    )
    .await
    .expect("dialling the proxy timed out")
    .expect("the dial produced a connecting")
    .await
    .expect("a proxy that speaks the legacy ALPN takes the offer that carries it");

    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await
        .expect("write request");
}

/// Accepting two ALPNs does not loosen the check: a proxy that speaks only the
/// current one still refuses the legacy one.
///
/// Without this, the test above would pass even if the proxy accepted anything.
#[tokio::test]
async fn a_proxy_that_speaks_only_the_current_alpn_refuses_the_legacy_one() {
    let server = bind_with_alpns(vec![ALPN.to_vec()]).await;
    spawn_acceptor(server.clone());
    let client = bind().await;

    let outcome = tokio::time::timeout(
        DIAL_TIMEOUT,
        client.connect(dial_address(&server), ALPN_LEGACY),
    )
    .await
    .expect("dialling the proxy timed out");

    assert!(
        outcome.is_err(),
        "a proxy that speaks only the current ALPN took the legacy one"
    );
}

// ---------------------------------------------------------------------------
// The protocol at the handshake
// ---------------------------------------------------------------------------

/// A client built before the prefix byte was dropped speaks the legacy ALPN,
/// and the server **serves** it rather than refusing it.
///
/// The server's accept list carries the legacy spelling so that a client of
/// that vintage still reaches it, and the protocol it is served as is the
/// generic one — the first byte of each stream decides, the way it always
/// did.
///
/// The test above only asks whether the handshake succeeds. This one asks
/// whether the connection is then *served*, which is the question that
/// matters: a protocol the server cannot name is a connection refused at the
/// door, and the legacy spelling is one its accept list is there for.
#[tokio::test]
async fn a_client_that_speaks_the_legacy_alpn_is_served() {
    let backend = spawn_backend("hello from the backend").await;
    let proxy =
        spawn_proxy_that_reads_the_protocol(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial_with_alpn(proxy.addr, ALPN_LEGACY).await;

    let reply = tunnel
        .exchange(b"GET /hello HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "a client of the older vintage is served, got {:?}",
        status_of(&reply)
    );
    assert_eq!(reply_body(&reply), "hello from the backend");
}

/// **The protocol the connection named decides what it carries.**
///
/// The same bytes — a request — are answered with the tunnel's status byte on
/// a connection that named the L4 protocol, and with the backend's answer on a
/// connection that named the HTTP one. A connection that named nothing is
/// served the way it always was: the first byte decides, and this first byte
/// says "a request".
///
/// This is the point of the change, end to end: the server reads the protocol
/// off the handshake rather than sniffing it off the stream, and a connection
/// that says what it carries is served as what it said.
#[tokio::test]
async fn the_negotiated_protocol_decides_what_the_connection_carries() {
    use nexapipe_proto::Status;
    use nexapipe_proto::protocol::{ALPN_HTTP, ALPN_L4};

    let backend = spawn_backend("hello from the backend").await;
    let proxy =
        spawn_proxy_that_reads_the_protocol(vec![http_route("app.test", &backend.url)]).await;
    let request = b"GET /hello HTTP/1.1\r\nHost: app.test\r\n\r\n";

    // A connection that named the L4 protocol: the bytes are a tunnel's, and
    // a tunnel's preface they are not — so the tunnel path answers with its
    // status byte and nothing else.
    let tunnel = Tunnel::dial_with_alpn(proxy.addr.clone(), ALPN_L4).await;
    let reply = tunnel.exchange(request).await;
    assert_eq!(
        reply.first().copied().map(Status::from_byte),
        Some(Status::BadPreface),
        "the tunnel path answers with its status byte, got {reply:?}"
    );

    // A connection that named the HTTP protocol: the same bytes are a
    // request, and it is served as one.
    let tunnel = Tunnel::dial_with_alpn(proxy.addr.clone(), ALPN_HTTP).await;
    let reply = tunnel.exchange(request).await;
    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "the request path serves what it is given, got {:?}",
        status_of(&reply)
    );
    assert_eq!(reply_body(&reply), "hello from the backend");
}

/// A connection that named nothing is served the way it always was.
///
/// The generic name means "the first byte of each stream decides", so the
/// same request is served as a request — the sniffing path still works, and
/// a client of the older vintage is not left behind.
#[tokio::test]
async fn a_connection_that_named_nothing_is_served_the_way_it_always_was() {
    let backend = spawn_backend("hello from the backend").await;
    let proxy =
        spawn_proxy_that_reads_the_protocol(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial_with_alpn(proxy.addr, ALPN).await;

    let reply = tunnel
        .exchange(b"GET /hello HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "the generic name is served by the first byte, got {:?}",
        status_of(&reply)
    );
    assert_eq!(reply_body(&reply), "hello from the backend");
}

// ---------------------------------------------------------------------------
// PROBE (scratch worktree only): a backend that sends both a length and a
// chunked body must not get to truncate the answer.
// ---------------------------------------------------------------------------

/// A backend that sends both `Transfer-Encoding` and `Content-Length` does not
/// get to decide how much of the answer the client sees.
///
/// RFC 9112 §6.1 rule 3: a message received with both headers has the length
/// overridden by the encoding, and a sender MUST remove the received
/// `Content-Length` before forwarding it. The proxy drops the
/// `Transfer-Encoding` as a hop-by-hop header and used to keep the
/// `Content-Length`, which then described a framing the forwarded body did not
/// have — and the client was served the body cut to that length.
#[tokio::test]
async fn a_backend_that_sends_both_a_length_and_a_chunked_body_is_not_truncated() {
    let backend = spawn_backend_answering(
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;
    let text = String::from_utf8_lossy(&reply).to_string();

    assert!(
        !text.to_lowercase().contains("content-length"),
        "the stale length was forwarded: {text}"
    );
    assert!(
        reply_body(&reply).contains("hello"),
        "the answer was cut to the backend's stale content-length: {text}"
    );
}

/// A backend that sends a length and nothing else keeps its length.
///
/// The rule above is about a message that was framed by an encoding. A
/// message that was framed by its length is forwarded with that length, and
/// the client reads exactly what the backend said it would.
#[tokio::test]
async fn a_backend_that_sends_only_a_length_keeps_it() {
    let backend =
        spawn_backend_answering("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;
    let text = String::from_utf8_lossy(&reply).to_string();

    assert!(
        text.to_lowercase().contains("content-length: 5"),
        "the length was dropped: {text}"
    );
    assert_eq!(reply_body(&reply), "hello", "the body was changed: {text}");
}
