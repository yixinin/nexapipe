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

use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use nexapipe::auth::{AuthConfig, ClientAuth, DeviceAuth};
use nexapipe::config::{Retry, RouteMode, Timeouts};
use nexapipe::conn;
use nexapipe::http;
use nexapipe::l4::FlowLimiter;
use nexapipe::lb::LoadBalancingStrategy;
use nexapipe::routes::{Route, RoutingTable};
use nexapipe_client::auth::{TotpAlgorithm as ClientTotpAlgorithm, TwoFactorAuth};
use nexapipe_proto::auth::AuthMessage;
use nexapipe_proto::secret::SecretString;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The ALPN the proxy endpoint is built with; iroh refuses a connection whose
/// ALPN does not match, so the test client has to ask for the same one.
const ALPN: &[u8] = b"\x05nexapipe";

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
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
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
                        &config,
                        &clients,
                        &limiter,
                        "data-plane-test",
                        None,
                        &request_id,
                        nexapipe::conn::peers::PeerIdentity::default(),
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
        let endpoint = bind().await;
        let conn = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, ALPN))
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
        let (mut send, mut recv) = self.conn.open_bi().await.expect("open_bi");
        for part in parts {
            send.write_all(part).await.expect("write request");
            tokio::time::sleep(Duration::from_millis(50)).await;
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
            failed_attempts: 0,
            locked_until: None,
        },
    );
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

/// Writes one length-prefixed message.
async fn write_message(send: &mut SendStream, message: &AuthMessage) {
    let bytes = message.to_bytes().expect("the message serializes");
    send.write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .expect("the length goes out");
    send.write_all(&bytes).await.expect("the message goes out");
}

/// Reads one length-prefixed message.
async fn read_message(recv: &mut RecvStream) -> AuthMessage {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.expect("the length comes");
    let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
    recv.read_exact(&mut buf).await.expect("the message comes");
    AuthMessage::from_bytes(&buf).expect("the message parses")
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
    let (mut send, mut recv) = tunnel.conn.open_bi().await.expect("open_bi");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    write_message(
        &mut send,
        &AuthMessage::Start {
            client_id: CLIENT_ID.to_string(),
            timestamp,
            device_id: None,
        },
    )
    .await;

    let challenge = read_message(&mut recv).await;
    let AuthMessage::Challenge { nonce } = challenge else {
        panic!("the server answers with a challenge, got {challenge:?}");
    };

    let signature = client
        .sign_challenge(&nonce, timestamp)
        .expect("the challenge is signed");
    let code = match code {
        Some(code) => code,
        None => client.generate_code().expect("the code is generated"),
    };

    write_message(
        &mut send,
        &AuthMessage::Response {
            client_id: CLIENT_ID.to_string(),
            timestamp,
            totp_code: code,
            signature,
            device_id: device.map(str::to_string),
        },
    )
    .await;

    read_message(&mut recv).await
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
