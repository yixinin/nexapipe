//! The tests of the HTTP half that need a backend that speaks TLS.

//! The certificate is made here rather than kept in the repository: a key in the
//! tree is a key somebody has to trust not to be used, and a test that needs one can
//! make one in a millisecond.

use crate::config::BackendProtocol;

use super::client::*;
use super::forward::*;
use crate::http::server::{Incoming, IncomingBody, RequestBody};

use ::http::Request;
use http_body_util::{BodyExt, Full};
use std::sync::Arc;
use tokio::io::AsyncReadExt;

use rcgen::{CertificateParams, IsCa, KeyPair};
use std::convert::Infallible;
use tokio::io::AsyncWriteExt;

/// Hands over `chunks` one read at a time and then either ends the stream
/// or stalls forever — the two shapes a peer that declared a
/// `content-length` can take once the head has been sent.
struct ScriptedReader {
    chunks: std::collections::VecDeque<Vec<u8>>,
    ends: bool,
}

impl ScriptedReader {
    fn pieces(pieces: &[&[u8]], ends: bool) -> Self {
        Self {
            chunks: pieces.iter().map(|p| p.to_vec()).collect(),
            ends,
        }
    }
}

impl tokio::io::AsyncRead for ScriptedReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.chunks.pop_front() {
            Some(chunk) => {
                buf.put_slice(&chunk);
                std::task::Poll::Ready(Ok(()))
            }
            // Nothing left and the peer gave up: end of stream, which is
            // what reports the body as shorter than it claimed to be.
            None if self.ends => std::task::Poll::Ready(Ok(())),
            // Still connected, still silent.
            None => std::task::Poll::Pending,
        }
    }
}

/// The CA that signs the backend's certificate, and the backend's own
/// certificate and key.
struct Pki {
    /// The CA certificate, PEM-encoded, which is what `[backends] ca_file`
    /// points at.
    ca_pem: String,
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
}

/// A CA of our own, and a certificate for `127.0.0.1` signed by it.
fn pki() -> Pki {
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

    Pki {
        ca_pem: ca_cert.pem(),
        server_cert: server_cert.der().to_vec(),
        server_key: server_key.serialize_der(),
    }
}

/// A backend on the loopback address that answers every request with
/// `hello`, over TLS.
///
/// `alpn` is what the backend offers the handshake: `["http/1.1"]` for a
/// backend that speaks one version, `["h2"]` for one that speaks the
/// other and only the other. A client that cannot offer one of them fails
/// the handshake, which is what makes the h2 test a test.
async fn tls_backend(pki: &Pki, alpn: &[&[u8]]) -> u16 {
    let certs = vec![rustls::pki_types::CertificateDer::from(
        pki.server_cert.clone(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::try_from(pki.server_key.clone())
        .expect("a DER private key");
    // The provider is named rather than left to the process-wide default:
    // more than one is compiled in, and rustls refuses to guess which one
    // a process should use.
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("a server configuration");
    server_config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(tls);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(|_req| async {
                            Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                bytes::Bytes::from_static(b"hello"),
                            )))
                        }),
                    )
                    .await;
            });
        }
    });

    port
}

/// The backend is reached over TLS, and the answer comes back.
#[tokio::test]
async fn an_https_backend_is_reached_over_tls() {
    let pki = pki();
    let dir = tempfile::tempdir().expect("a scratch directory");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &pki.ca_pem).expect("the CA file");

    let port = tls_backend(&pki, &[b"http/1.1"]).await;
    let client = create_http_client(std::time::Duration::from_secs(5), Some(ca_path.as_path()))
        .expect("a client");

    let response = client
        .get(format!("https://127.0.0.1:{port}/").parse().expect("a URI"))
        .await
        .expect("the backend answers");
    assert_eq!(response.status(), 200);

    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("the body")
        .to_bytes();
    assert_eq!(body.as_ref(), b"hello");
}

/// A WebSocket owns a raw connection rather than a pooled one, so it cannot
/// use the HTTP client. It still reaches an `https://` backend over TLS,
/// with the same CA file the pooled clients use.
#[tokio::test]
async fn an_https_backend_can_be_reached_as_a_raw_stream() {
    let pki = pki();
    let dir = tempfile::tempdir().expect("a scratch directory");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &pki.ca_pem).expect("the CA file");

    let port = tls_backend(&pki, &[b"http/1.1"]).await;
    let clients = BackendClients::new(std::time::Duration::from_secs(5), Some(ca_path.as_path()))
        .expect("the clients");
    let mut stream = clients
        .connect_stream(
            &format!("https://127.0.0.1:{port}/"),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("the TLS connection is up");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("the request is written");
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .await
        .expect("the answer is read");

    assert!(
        String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 200"),
        "the raw TLS stream should carry the backend's answer: {:?}",
        String::from_utf8_lossy(&reply)
    );
}

/// A certificate nobody vouches for is refused, which is the whole point of
/// checking one.
#[tokio::test]
async fn a_certificate_that_is_not_vouched_for_is_refused() {
    let pki = pki();
    let port = tls_backend(&pki, &[b"http/1.1"]).await;
    // No CA file: the machine's own roots, which know nothing about the
    // certificate this backend just presented.
    let client = create_http_client(std::time::Duration::from_secs(5), None).expect("a client");

    let result = client
        .get(format!("https://127.0.0.1:{port}/").parse().expect("a URI"))
        .await;
    assert!(
        result.is_err(),
        "a certificate signed by an authority this process does not trust must not be \
         accepted: {:?}",
        result.map(|r| r.status())
    );
}

/// A backend that speaks HTTP/2 and nothing else, over TLS.
///
/// The backend offers `h2` and only `h2`, so a client that did not speak
/// it would fail the handshake rather than fall back: the answer coming
/// back is the proof that the connection was HTTP/2.
async fn h2_tls_backend(pki: &Pki) -> u16 {
    let certs = vec![rustls::pki_types::CertificateDer::from(
        pki.server_cert.clone(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::try_from(pki.server_key.clone())
        .expect("a DER private key");
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("a server configuration");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(tls);
                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .timer(hyper_util::rt::TokioTimer::new())
                        .serve_connection(
                            io,
                            hyper::service::service_fn(|_req| async {
                                Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                    bytes::Bytes::from_static(b"hello"),
                                )))
                            }),
                        )
                        .await;
            });
        }
    });

    port
}

/// A backend that speaks HTTP/2 in the clear, and nothing else.
async fn h2c_backend() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .timer(hyper_util::rt::TokioTimer::new())
                        .serve_connection(
                            io,
                            hyper::service::service_fn(|_req| async {
                                Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                    bytes::Bytes::from_static(b"hello"),
                                )))
                            }),
                        )
                        .await;
            });
        }
    });

    port
}

/// A backend that speaks HTTP/2 over TLS is reached over HTTP/2, without
/// anybody having to say so: the handshake agrees on it.
#[tokio::test]
async fn an_https_backend_is_reached_over_http2() {
    let pki = pki();
    let dir = tempfile::tempdir().expect("a scratch directory");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &pki.ca_pem).expect("the CA file");

    let port = h2_tls_backend(&pki).await;
    let clients = BackendClients::new(std::time::Duration::from_secs(5), Some(ca_path.as_path()))
        .expect("the clients");
    let client = clients.for_protocol(BackendProtocol::Http1);

    let response = client
        .get(format!("https://127.0.0.1:{port}/").parse().expect("a URI"))
        .await
        .expect("the backend answers over h2");
    assert_eq!(response.status(), 200);
}

/// A backend that speaks HTTP/2 in the clear is reached over HTTP/2, by
/// the client that starts speaking it — there is no handshake on a
/// cleartext connection to agree on anything.
#[tokio::test]
async fn a_cleartext_backend_is_reached_over_http2() {
    let port = h2c_backend().await;
    let clients =
        BackendClients::new(std::time::Duration::from_secs(5), None).expect("the clients");
    let client = clients.for_protocol(BackendProtocol::H2c);

    let response = client
        .get(format!("http://127.0.0.1:{port}/").parse().expect("a URI"))
        .await
        .expect("the backend answers over h2");
    assert_eq!(response.status(), 200);

    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("the body")
        .to_bytes();
    assert_eq!(body.as_ref(), b"hello");
}

/// A backend on the loopback address that answers every request with
/// `hello`, in the clear.
async fn hello_backend() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(|_req| async {
                            Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                bytes::Bytes::from_static(b"hello"),
                            )))
                        }),
                    )
                    .await;
            });
        }
    });

    port
}

/// A backend that answers every request with the bytes it was given.
///
/// A raw socket rather than a hyper server: what is being checked is the
/// headers the backend sends, and a hyper server writes its own framing and
/// its own `connection` header rather than the awkward ones.
async fn backend_answering(reply: &'static str) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // The head is read before the answer goes out. A socket that
                // is closed with the request still unread in it is closed
                // abortively on Windows — the peer is told to reset rather
                // than to finish — and a request that is still going out
                // then fails instead of getting its answer.
                read_head(&mut stream).await;
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    port
}

/// The head of a request, up to the blank line that ends it.
///
/// Read and thrown away: what a test needs is that the request is out of the
/// way before the answer goes back.
async fn read_head(stream: &mut tokio::net::TcpStream) {
    let mut head = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = match stream.read(&mut buffer).await {
            Ok(read) => read,
            Err(_) => return,
        };
        if read == 0 {
            return;
        }
        head.extend_from_slice(&buffer[..read]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            return;
        }
    }
}

/// A backend that answers with the bytes it was given and records the head
/// of the request it was given.
async fn backend_recording(reply: &'static str) -> (u16, Arc<std::sync::Mutex<Vec<u8>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    let sink = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                // The head, up to the blank line that ends it.
                let mut head = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).await.expect("the request");
                    if read == 0 {
                        break;
                    }
                    head.extend_from_slice(&buffer[..read]);
                    if head.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                sink.lock()
                    .expect("the requests seen")
                    .extend_from_slice(&head);
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    (port, seen)
}

/// An address nothing is listening on.
///
/// The port is taken by a UDP socket, so the connection to it is refused
/// rather than timing out — which is what a backend that is down looks
/// like. A UDP socket rather than a closed TCP one, because a TCP port
/// that is given back can be handed to the next listener that asks for
/// one, and these tests run beside each other.
///
/// The socket is returned so the caller can keep it: the address stays
/// dead for as long as the test holds it.
async fn dead_backend() -> (String, tokio::net::UdpSocket) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a loopback socket");
    let port = socket.local_addr().expect("an address").port();
    (format!("http://127.0.0.1:{port}"), socket)
}

/// A backend that accepts the connection and then says nothing, and how
/// many connections it accepted.
async fn silent_backend() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let counter = accepted.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::spawn(async move {
                // Held open, saying nothing: the request was carried and
                // the answer never came.
                let _stream = stream;
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }
    });

    (port, accepted)
}

/// A backend that sends the head and then stops, so the body is still on
/// the wire when the answer is handed over.
///
/// The head promises sixteen bytes of body and none of them come. The
/// connection is held open, so the answer is a body that has not arrived
/// yet — a backend that is still working on the request.
async fn stalling_backend() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // The head is read before the answer goes out, for the reason
                // `read_head` gives: a socket that is closed with the request
                // still unread in it is closed abortively on Windows — the peer
                // is told to reset rather than to finish — and a request that
                // is still going out then fails instead of getting its answer.
                //
                // This backend used to skip it, and the race it left was won
                // almost every time: the answer was written the moment the
                // connection was accepted, and whether the request had reached
                // the peer by then was a matter of scheduling. A tokio bump
                // that moved the scheduling around was enough to lose it.
                read_head(&mut stream).await;
                // The head, and nothing after it.
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n")
                    .await;
                // Held open: the body never comes.
                let _stream = stream;
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }
    });

    port
}

/// A route table with the given backends, and a retry that tries again.
fn route_table(backends: Vec<String>, attempts: u32) -> Arc<crate::routes::RoutingTable> {
    let timeouts = crate::config::Timeouts {
        connect: std::time::Duration::from_secs(1),
        response: std::time::Duration::from_secs(1),
        deadlines: crate::deadline::Deadlines::default(),
    };
    let route = crate::routes::Route::new(
        "retry.test",
        "/",
        true,
        backends,
        crate::lb::LoadBalancingStrategy::RoundRobin,
        crate::config::RouteMode::Http,
        None,
    );
    Arc::new(crate::routes::RoutingTable::with_settings(
        vec![route],
        timeouts,
        crate::config::Retry {
            attempts,
            backoff: std::time::Duration::ZERO,
        },
    ))
}

fn get_request(host: &str) -> Request<Full<bytes::Bytes>> {
    Request::builder()
        .method("GET")
        .uri(format!("http://{host}/"))
        .header("host", host)
        .body(Full::new(bytes::Bytes::new()))
        .expect("a request")
}

/// A route table whose route rewrites the paths under `pattern`.
///
/// The rewrite is what a route pairs a `path_pattern` with: the paths
/// that match are served somewhere else, and `{}` in the rewrite is where
/// the matched part goes.
///
/// The `{}` holds the part of the path *after* the pattern, separator and
/// all — so a rewrite of `/v2{}` turns `/api/users` into `/v2/users`, and
/// `/v2/{}` would turn it into `/v2//users`. That is the rule the
/// plaintext path has always used, and this change does not alter it; it
/// only makes the tunnel path use the same one.
fn route_table_with_rewrite(
    backend: String,
    pattern: &str,
    rewrite: &str,
) -> Arc<crate::routes::RoutingTable> {
    let timeouts = crate::config::Timeouts {
        connect: std::time::Duration::from_secs(1),
        response: std::time::Duration::from_secs(1),
        deadlines: crate::deadline::Deadlines::default(),
    };
    let route = crate::routes::Route::new(
        "rewrite.test",
        pattern,
        true,
        vec![backend],
        crate::lb::LoadBalancingStrategy::RoundRobin,
        crate::config::RouteMode::Http,
        Some(rewrite.to_string()),
    );
    Arc::new(crate::routes::RoutingTable::with_settings(
        vec![route],
        timeouts,
        crate::config::Retry {
            attempts: 1,
            backoff: std::time::Duration::ZERO,
        },
    ))
}

/// The request as the tunnel path puts it on the wire, for a path the
/// route rewrites.
///
/// The tunnel path is the one that carries real traffic, and it used to
/// forward the path the client asked for without the rewrite — so a route
/// that named one looked configured and did nothing for every client that
/// went through the tunnel. `curl` against the plaintext listener saw the
/// rewrite; the app did not.
#[tokio::test]
async fn the_tunnel_path_forwards_the_rewritten_path() {
    let config = route_table_with_rewrite("http://127.0.0.1:9".to_string(), "/api", "/v2{}");

    let backend_info = config
        .get_backend_with_acl("rewrite.test", "/api/users", None, None)
        .await
        .backend()
        .expect("a route for the host");

    let request = Request::builder()
        .method("GET")
        .uri("http://rewrite.test/api/users")
        .header("host", "rewrite.test")
        .body(())
        .expect("a request");
    let body = RequestBody::<Incoming>::Whole {
        bytes: bytes::Bytes::new(),
        reservation: crate::conn::limits::ByteReservation::empty(),
    };

    let forwarded = build_backend_request_from(&request, &backend_info, &body)
        .expect("a request for the backend");

    assert_eq!(
        forwarded.uri().path(),
        "/v2/users",
        "the tunnel path did not apply the route's rewrite"
    );
}

/// The body that goes to the backend is the body the client sent, not a
/// copy of it.
///
/// It used to be a copy: the buffer stayed alive for the retry, and the
/// request that went out carried a second, byte-for-byte copy of it. So a
/// 64 MiB upload was 128 MiB of memory for as long as the request lived —
/// and the byte budget, which counts the reservation once, said 64 MiB.
#[tokio::test]
async fn the_forwarded_body_is_the_body_the_client_sent() {
    let config = route_table_with_rewrite("http://127.0.0.1:9".to_string(), "/api", "/v2{}");

    let backend_info = config
        .get_backend_with_acl("rewrite.test", "/api/users", None, None)
        .await
        .backend()
        .expect("a route for the host");

    let request = Request::builder()
        .method("POST")
        .uri("http://rewrite.test/api/users")
        .header("host", "rewrite.test")
        .body(())
        .expect("a request");
    let body = RequestBody::<Incoming>::Whole {
        bytes: bytes::Bytes::from_static(b"the body the client sent"),
        reservation: crate::conn::limits::ByteReservation::empty(),
    };

    let forwarded = build_backend_request_from(&request, &backend_info, &body)
        .expect("a request for the backend");
    let forwarded_body = forwarded
        .into_body()
        .collect()
        .await
        .expect("the request carries a body")
        .to_bytes();
    let RequestBody::Whole { bytes, .. } = &body else {
        panic!("the body is whole");
    };

    assert_eq!(forwarded_body, *bytes, "the body is the same body");
    assert_eq!(
        forwarded_body.as_ptr(),
        bytes.as_ptr(),
        "and it is the same memory: a body that was copied would be in the \
         process twice, while the byte budget counts it once"
    );
}

/// A route that names one exact path serves it somewhere else entirely.
///
/// The other shape a rewrite takes: the route matches one path rather than
/// a prefix, and the rewrite has no `{}` to fill — the matched part is
/// the whole path, and the suffix is empty.
#[tokio::test]
async fn an_exact_path_is_rewritten_without_a_suffix() {
    let timeouts = crate::config::Timeouts {
        connect: std::time::Duration::from_secs(1),
        response: std::time::Duration::from_secs(1),
        deadlines: crate::deadline::Deadlines::default(),
    };
    let route = crate::routes::Route::new(
        "rewrite.test",
        "/api/status",
        false,
        vec!["http://127.0.0.1:9".to_string()],
        crate::lb::LoadBalancingStrategy::RoundRobin,
        crate::config::RouteMode::Http,
        Some("/internal/status".to_string()),
    );
    let config = Arc::new(crate::routes::RoutingTable::with_settings(
        vec![route],
        timeouts,
        crate::config::Retry {
            attempts: 1,
            backoff: std::time::Duration::ZERO,
        },
    ));

    let backend_info = config
        .get_backend_with_acl("rewrite.test", "/api/status", None, None)
        .await
        .backend()
        .expect("a route for the path");

    let request = Request::builder()
        .method("GET")
        .uri("http://rewrite.test/api/status")
        .header("host", "rewrite.test")
        .body(())
        .expect("a request");
    let body = RequestBody::<Incoming>::Whole {
        bytes: bytes::Bytes::new(),
        reservation: crate::conn::limits::ByteReservation::empty(),
    };

    let forwarded = build_backend_request_from(&request, &backend_info, &body)
        .expect("a request for the backend");

    assert_eq!(forwarded.uri().path(), "/internal/status");
}

/// A request that failed against one backend is tried against the next.
#[tokio::test]
async fn a_failed_request_is_tried_on_another_backend() {
    let (dead, _guard) = dead_backend().await;
    let port = hello_backend().await;
    let alive = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![dead, alive], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let response = proxy_request(&clients, get_request("retry.test"), config)
        .await
        .expect("the second backend answers");

    assert_eq!(response.status(), 200);
}

/// A request that was carried and lost is not tried again, unless it is
/// safe to send twice.
#[tokio::test]
async fn a_post_that_reached_a_backend_is_not_tried_again() {
    let (port, accepted) = silent_backend().await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let request = Request::builder()
        .method("POST")
        .uri("http://retry.test/")
        .header("host", "retry.test")
        .body(Full::new(bytes::Bytes::new()))
        .expect("a request");
    let result = proxy_request(&clients, request, config).await;

    assert!(
        result.is_err(),
        "the backend never answered, so the request failed"
    );
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "a POST may not be sent twice, so it was tried once"
    );
}

/// The same request, but one that is safe to send twice.
#[tokio::test]
async fn a_get_that_reached_a_backend_is_tried_again() {
    let (port, accepted) = silent_backend().await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let result = proxy_request(&clients, get_request("retry.test"), config).await;

    assert!(result.is_err(), "the backend never answered");
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "a GET may be sent twice, so it was"
    );
}

/// The plaintext path does not hand the client the backend's own hop
/// headers.
///
/// The tunnel path has dropped them for a while; the plaintext path did not,
/// so a `connection: keep-alive` from the backend described a link the client
/// does not have, and a `proxy-authenticate` from the backend was a challenge
/// the client never asked for.
///
/// The header the answer's own `Connection` header names goes with them: the
/// answer says it is for this hop only.
#[tokio::test]
async fn the_plaintext_path_drops_the_backends_own_hop_headers() {
    let port = backend_answering(
        "HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: keep-alive, x-internal\r\nkeep-alive: timeout=5\r\nproxy-authenticate: Basic realm=\"backend\"\r\nx-internal: secret\r\nx-kept: yes\r\n\r\nhello",
    )
    .await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let response = proxy_request(&clients, get_request("retry.test"), config)
        .await
        .expect("the backend answers");

    for dropped in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        // Named in the answer's own `Connection` header.
        "x-internal",
    ] {
        assert!(
            response.headers().get(dropped).is_none(),
            "the hop header arrived: {dropped}"
        );
    }
    assert_eq!(
        response
            .headers()
            .get("x-kept")
            .map(|value| value.to_str().unwrap()),
        Some("yes"),
        "a header that is not hop-by-hop was dropped"
    );
}

/// A header the client named in its own `Connection` header does not reach
/// the backend.
///
/// RFC 9110 §7.6.1: the hop-by-hop headers are the fixed list **and** every
/// header the message's `Connection` header names. A client that says
/// `Connection: X-Internal-Token` is saying that the header is for the hop to
/// this proxy only.
#[tokio::test]
async fn a_header_the_client_named_does_not_reach_the_backend() {
    let (port, seen) = backend_recording("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let request = Request::builder()
        .method("GET")
        .uri("http://retry.test/")
        .header("host", "retry.test")
        .header("connection", "x-internal-token")
        .header("x-internal-token", "secret")
        .header("x-kept", "yes")
        .body(Full::new(bytes::Bytes::new()))
        .expect("a request");

    proxy_request(&clients, request, config)
        .await
        .expect("the backend answers");

    let head = String::from_utf8_lossy(&seen.lock().expect("the requests seen")).to_lowercase();
    assert!(
        !head.contains("x-internal-token"),
        "the header the client named was forwarded: {head}"
    );
    assert!(
        head.contains("x-kept"),
        "a header the client did not name was dropped: {head}"
    );
}

/// A backend that reports how much of a request body had arrived by the
/// time its first byte showed up, and then answers once the body is
/// complete.
///
/// A plain socket rather than a hyper server: what is being checked is
/// *when* the bytes reach the backend, and a socket says so without a
/// body handler in the way.
async fn first_byte_backend() -> (u16, tokio::sync::mpsc::UnboundedReceiver<usize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let mut seen: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut body_bytes;
                let mut expected = None;
                let mut reported = false;

                loop {
                    let n = match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    seen.extend_from_slice(&chunk[..n]);

                    // The head ends at the first blank line; everything
                    // after it is the body.
                    let Some(pos) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let body_start = pos + 4;
                    if expected.is_none() {
                        expected = Some(content_length_of(&seen[..body_start]));
                    }
                    body_bytes = seen.len() - body_start;

                    if !reported && body_bytes > 0 {
                        let _ = tx.send(body_bytes);
                        reported = true;
                    }
                    if body_bytes >= expected.unwrap_or(0) {
                        break;
                    }
                }

                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await;
            });
        }
    });

    (port, rx)
}

/// The length a request head declares, or zero when it declares none.
fn content_length_of(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            return value.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// The backend sees the first byte of an upload while the client is still
/// sending the rest of it.
///
/// The body used to be read whole before the backend was even contacted,
/// so a backend saw nothing at all until the last byte was in. That is a
/// whole transfer of added latency on every upload, and the backend pays
/// it too: it cannot start on the first byte.
#[tokio::test]
async fn the_backend_sees_the_first_byte_before_the_upload_is_finished() {
    let (port, mut first_byte) = first_byte_backend().await;
    let config = route_table(vec![format!("http://127.0.0.1:{port}")], 0);
    let backend_info = config
        .get_backend_with_acl("retry.test", "/", None, None)
        .await
        .backend()
        .expect("a route for the host");
    let clients =
        BackendClients::new(std::time::Duration::from_secs(5), None).expect("the clients");

    // The client sends the first piece and then goes quiet: the rest never
    // arrives, so the body never ends — and the backend still has to see the
    // piece that did.
    let body = RequestBody::Streaming(body_of(
        TestBody::pieces(&[b"the first piece"], false),
        std::time::Duration::from_secs(30),
    ));

    let request = Request::builder()
        .method("POST")
        .uri("http://retry.test/")
        .header("host", "retry.test")
        .header(
            "content-length",
            b"the first piece and the rest".len().to_string(),
        )
        .body(())
        .expect("a request");
    let forwarded = build_backend_request_from(&request, &backend_info, &body)
        .expect("a request for the backend");

    let client = clients.for_protocol(backend_info.protocol).clone();
    let sent = tokio::spawn(async move { client.request(forwarded).await });

    let arrived = tokio::time::timeout(std::time::Duration::from_secs(5), first_byte.recv())
        .await
        .expect("the backend saw the first byte of the body in time")
        .expect("the backend reported the first byte");
    assert!(
        arrived < b"the first piece and the rest".len(),
        "the backend had {arrived} bytes of the body before it saw the first one: the body \
         was buffered instead of streamed"
    );

    // The rest of the upload never comes, so the request never finishes.
    sent.abort();
}

/// A backend that keeps failing is taken out of rotation, and the route
/// answers 503 rather than dialling it again.
///
/// The point of the circuit: the answer comes without a connect timeout,
/// because the proxy already knows the backend is down.
#[tokio::test]
async fn a_backend_that_keeps_failing_is_taken_out_of_rotation() {
    let (dead, _guard) = dead_backend().await;
    let timeouts = crate::config::Timeouts {
        connect: std::time::Duration::from_secs(1),
        response: std::time::Duration::from_secs(1),
        deadlines: crate::deadline::Deadlines::default(),
    };
    let route = crate::routes::Route::new(
        "circuit.test",
        "/",
        true,
        vec![dead],
        crate::lb::LoadBalancingStrategy::RoundRobin,
        crate::config::RouteMode::Http,
        None,
    )
    .with_circuit_breaker(crate::config::CircuitBreaker {
        enabled: true,
        failure_threshold: 2,
        reset: std::time::Duration::from_secs(60),
    });
    let config = Arc::new(crate::routes::RoutingTable::with_settings(
        vec![route],
        timeouts,
        crate::config::Retry::default(),
    ));
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    // The first two requests fail against the backend.
    for _ in 0..2 {
        let result = proxy_request(&clients, get_request("circuit.test"), config.clone()).await;
        assert!(
            result.is_err(),
            "the backend is not there, so the request fails"
        );
    }

    // The third finds the circuit open, and the route says so instead of
    // dialling a backend that is known to be down.
    let response = proxy_request(&clients, get_request("circuit.test"), config)
        .await
        .expect("the route answers");
    assert_eq!(
        response.status(),
        503,
        "a route whose only backend is out of rotation has nothing to offer"
    );
}

/// A backend stays busy for as long as its response is out there.
///
/// The count is what `least_conn` balances on, and a response whose body
/// has not been read yet is a request the backend is still working on. A
/// balancer that cannot see that hands the next request to a backend that
/// is already busy.
#[tokio::test]
async fn a_backend_stays_busy_until_its_response_is_dropped() {
    let port = hello_backend().await;
    let backend = format!("http://127.0.0.1:{port}");
    let route = crate::routes::Route::new(
        "busy.test",
        "/",
        true,
        vec![backend.clone()],
        crate::lb::LoadBalancingStrategy::RoundRobin,
        crate::config::RouteMode::Http,
        None,
    );
    let config = Arc::new(crate::routes::RoutingTable::new(vec![route]));
    let pool = config.routes().await[0].backend_pool().clone();
    let clients =
        BackendClients::new(std::time::Duration::from_secs(5), None).expect("the clients");

    let request = Request::builder()
        .method("GET")
        .uri("http://busy.test/")
        .header("host", "busy.test")
        .body(Full::new(bytes::Bytes::new()))
        .expect("a request");
    let response = proxy_request(&clients, request, config.clone())
        .await
        .expect("the backend answers");

    assert_eq!(
        pool.outstanding(&backend).await,
        1,
        "the response is still out there, so the backend is still busy with it"
    );

    drop(response);

    assert_eq!(
        pool.outstanding(&backend).await,
        0,
        "the body is gone, so the backend is free again"
    );
}

/// A backend stays busy on the tunnel path for as long as its answer is
/// out there.
///
/// The count is what `least_conn` balances on, and an answer whose body has
/// not been read yet is a request the backend is still working on.
///
/// The plaintext path has always held the lease with the body. The tunnel
/// path dropped it with the head: the backend info was dropped when
/// `forward` returned and the lease went with it, so the balancer saw an
/// idle backend while its body was still streaming.
///
/// The backend here sends the head and then stops, so the body really is
/// still on the wire when the answer is handed over.
#[tokio::test]
async fn a_backend_stays_busy_until_its_answer_is_dropped_on_the_tunnel_path() {
    let port = stalling_backend().await;
    let backend = format!("http://127.0.0.1:{port}");
    let route = crate::routes::Route::new(
        "busy-tunnel.test",
        "/",
        true,
        vec![backend.clone()],
        crate::lb::LoadBalancingStrategy::RoundRobin,
        crate::config::RouteMode::Http,
        None,
    );
    let config = Arc::new(crate::routes::RoutingTable::new(vec![route]));
    let pool = config.routes().await[0].backend_pool().clone();
    let clients =
        BackendClients::new(std::time::Duration::from_secs(5), None).expect("the clients");

    let ctx = Arc::new(crate::http::server::Context {
        config: config.clone(),
        clients: Arc::new(clients),
        peer: "127.0.0.1:12345".to_string(),
        acl: None,
        request_id: "busy-tunnel".to_string(),
        who: crate::conn::peers::PeerIdentity::default(),
    });

    let request = Request::builder()
        .method("GET")
        .uri("http://busy-tunnel.test/")
        .header("host", "busy-tunnel.test")
        .body(())
        .expect("a request");
    let (host, port) = crate::routes::host_and_port("busy-tunnel.test");
    let path = "/";
    let backend_info = config
        .get_backend(host, path)
        .await
        .backend()
        .expect("the route has a backend");
    let body = RequestBody::Whole {
        bytes: bytes::Bytes::new(),
        reservation: crate::conn::limits::ByteReservation::take(0).expect("the budget"),
    };

    let answer = crate::http::server::forward(
        &ctx,
        &request,
        &request.uri().to_string(),
        &request.method().clone(),
        Some((host, port)),
        path,
        backend_info,
        &body,
        std::time::Instant::now(),
    )
    .await
    .expect("the backend answers");

    assert_eq!(
        pool.outstanding(&backend).await,
        1,
        "the answer is still out there, so the backend is still busy with it"
    );

    let response = answer.into_response();
    drop(response);

    assert_eq!(
        pool.outstanding(&backend).await,
        0,
        "the answer is gone, so the backend is free again"
    );
}

/// The CA file is read at startup, so a file that cannot be read is an
/// error the operator sees rather than a handshake that fails later.
#[test]
fn a_ca_file_that_cannot_be_read_is_refused() {
    let error = create_http_client(
        std::time::Duration::from_secs(1),
        Some(std::path::Path::new("/nonexistent/nexapipe-ca.pem")),
    )
    .expect_err("a CA file that does not exist cannot be used");
    assert!(
        error.to_string().contains("cannot read the CA file"),
        "the message has to name the file: {error}"
    );
}

/// A body over a reader, for the tests that drive one by hand.
///
/// Hyper's own `Incoming` cannot be built by hand — it only exists as what
/// a live connection produced — so the tests that drive a body read one of
/// these instead.
struct TestBody {
    reader: ScriptedReader,
    done: bool,
}

impl TestBody {
    fn pieces(pieces: &[&[u8]], ends: bool) -> Self {
        TestBody {
            reader: ScriptedReader::pieces(pieces, ends),
            done: false,
        }
    }
}

impl hyper::body::Body for TestBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = self.as_mut().get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        let mut buf = vec![0u8; 4096];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        match tokio::io::AsyncRead::poll_read(
            std::pin::Pin::new(&mut this.reader),
            cx,
            &mut read_buf,
        ) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled().len();
                if filled == 0 {
                    this.done = true;
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Ok(hyper::body::Frame::data(
                    bytes::Bytes::copy_from_slice(read_buf.filled()),
                ))))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
        }
    }
}

/// The body, as the proxy holds it, over a budget of the test's own.
fn body_over<B>(
    inner: B,
    deadline: std::time::Duration,
    budget: Arc<crate::conn::limits::ByteBudget>,
) -> IncomingBody<B>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: Into<crate::http::client::BoxError>,
{
    IncomingBody::<B>::with_budget(inner, deadline, budget)
}

/// The body, as the proxy holds it, against the process-wide budget.
fn body_of<B>(inner: B, deadline: std::time::Duration) -> IncomingBody<B>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: Into<crate::http::client::BoxError>,
{
    IncomingBody::<B>::new(inner, deadline)
}

/// A body that is streamed arrives whole.
#[tokio::test]
async fn a_streamed_body_is_read_whole() {
    let body = body_of(
        TestBody::pieces(&[b"hello ".as_slice(), b"body".as_slice()], true),
        std::time::Duration::from_secs(60),
    );
    let collected = body.lend().collect().await.expect("the body is read");
    assert_eq!(collected.to_bytes().as_ref(), b"hello body");
}

/// A body the client cut short ends the body: the backend sees what
/// arrived, and the answer is that the request ended there.
#[tokio::test]
async fn a_body_that_ends_early_ends_the_body() {
    let body = body_of(
        TestBody::pieces(&[b"short"], true),
        std::time::Duration::from_secs(60),
    );
    let collected = body.lend().collect().await.expect("the body is read");
    assert_eq!(collected.to_bytes().as_ref(), b"short");
}

/// A body that never arrives is given up on: the deadline is the same one
/// the buffered path had.
#[tokio::test]
async fn a_body_that_never_arrives_is_given_up_on() {
    let body = body_of(TestBody::pieces(&[], false), std::time::Duration::ZERO);
    let outcome = body.lend().collect().await;
    assert!(outcome.is_err(), "the body should have been given up on");
    assert!(
        outcome
            .expect_err("the body was given up on")
            .to_string()
            .contains("did not finish in time"),
        "the error has to say that the body ran out of time"
    );
}

/// A body that goes silent is given up on at its **own** deadline.
///
/// The deadline is a clock reading, and a clock reading wakes nobody: a
/// body that is only checked when it is polled is never given up on
/// while the client is silent, which is exactly when it should be. The
/// test waits far longer than the deadline and requires the body to have
/// given up on its own rather than when the wait ran out.
#[tokio::test]
async fn a_body_that_goes_silent_is_given_up_on_at_its_deadline() {
    let body = body_of(
        TestBody::pieces(&[], false),
        std::time::Duration::from_millis(300),
    );

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), {
        let lent = body.lend();
        async move { lent.collect().await }
    })
    .await;
    let elapsed = started.elapsed();

    assert!(
        outcome.is_ok(),
        "the body did not give up on its own: it waited for something else to wake it"
    );
    let error = outcome
        .expect("the body gave up before the wait ran out")
        .expect_err("the body should have been given up on");
    assert!(
        error.to_string().contains("did not finish in time"),
        "the error has to say that the body ran out of time: {error}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "the body gave up after {elapsed:?}, which is not its own deadline"
    );
}

/// A body that was never read can be sent again.
///
/// The bytes of a streamed body are on the client's stream, and a request
/// that failed before the body was touched — a connection that was
/// refused, say — has not spent them. Building the request must not spend
/// them either: the request is built before it is sent.
#[tokio::test]
async fn a_body_that_was_never_read_can_be_sent_again() {
    let body = body_of(
        TestBody::pieces(&[b"the body"], true),
        std::time::Duration::from_secs(60),
    );

    assert!(
        body.may_retry(),
        "a body nobody read is still on the client's stream"
    );
}

/// A body that was read cannot be sent again.
///
/// The bytes came off the client's stream and there is no second copy of
/// them, so a request that carries one cannot be tried on another backend.
#[tokio::test]
async fn a_body_that_was_read_cannot_be_sent_again() {
    let body = body_of(
        TestBody::pieces(&[b"the body"], true),
        std::time::Duration::from_secs(60),
    );
    let _ = body.lend().collect().await.expect("the body is read");

    assert!(
        !body.may_retry(),
        "a body that was read is gone, and there is no second copy of it"
    );
}

/// A streamed body that outgrows the budget is refused.
///
/// The budget is the process's: it is what stops one upload from holding the
/// whole process's memory. A body that does not fit in it is refused rather
/// than truncated, and what it had is given back.
#[tokio::test]
async fn a_streamed_body_that_outgrows_the_budget_is_refused() {
    let budget = Arc::new(crate::conn::limits::ByteBudget::new(8));
    let body = body_over(
        TestBody::pieces(&[b"0123456789abcdef".as_slice()], true),
        std::time::Duration::from_secs(60),
        budget.clone(),
    );

    let outcome = body.lend().collect().await;
    assert!(
        outcome.is_err(),
        "a body that does not fit in the budget is refused"
    );
    assert_eq!(
        budget.held(),
        0,
        "the refused body hands its reservation back"
    );
}

/// The budget counts the bytes that have arrived, not the bytes the
/// client promised.
///
/// A promise is not a reservation: a client that declares a large body
/// and sends nothing holds nothing, which is what the buffered path did
/// as well. What has arrived is counted, so the process budget still
/// knows what it is holding.
#[tokio::test]
async fn the_budget_counts_the_bytes_that_arrived() {
    let budget = Arc::new(crate::conn::limits::ByteBudget::new(1024 * 1024));
    let body = body_over(
        TestBody::pieces(&[b"0123456789".as_slice()], false),
        std::time::Duration::from_secs(60),
        budget.clone(),
    );

    let mut lent = body.lend();
    let frame = lent
        .frame()
        .await
        .expect("a frame")
        .expect("the frame is not an error");
    assert_eq!(frame.into_data().expect("data").as_ref(), b"0123456789");
    assert_eq!(
        budget.held(),
        10,
        "the budget counts what arrived, not what the client promised"
    );
}

/// A body that is given up on hands its reservation back.
///
/// One stalled upload must not shrink the process budget for every other
/// request behind it.
#[tokio::test]
async fn a_body_that_is_given_up_on_hands_its_reservation_back() {
    let budget = Arc::new(crate::conn::limits::ByteBudget::new(1024 * 1024));
    let body = body_over(
        TestBody::pieces(&[], false),
        std::time::Duration::ZERO,
        budget.clone(),
    );

    let outcome = body.lend().collect().await;
    assert!(outcome.is_err(), "the body should have been given up on");
    assert_eq!(
        budget.held(),
        0,
        "the body that was given up on hands its reservation back"
    );
}

/// The plaintext path does not hand the client a length that describes
/// another body.
///
/// A backend that sends both a `Transfer-Encoding` and a `Content-Length` has
/// its length overridden by the encoding (RFC 9112 §6.1, rule 3), and the
/// received `Content-Length` has to be removed before the answer is
/// forwarded. The `Transfer-Encoding` is dropped as a hop-by-hop header, so a
/// length left behind describes a framing the forwarded body does not have —
/// and the client is served the body cut to that length.
#[tokio::test]
async fn the_plaintext_path_drops_a_length_that_the_encoding_overrode() {
    let port = backend_answering(
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let response = proxy_request(&clients, get_request("retry.test"), config)
        .await
        .expect("the backend answers");

    assert!(
        response.headers().get("content-length").is_none(),
        "the stale length was forwarded: {:?}",
        response.headers()
    );
    assert!(
        response.headers().get("transfer-encoding").is_none(),
        "the hop header was forwarded: {:?}",
        response.headers()
    );

    let body = response
        .into_body()
        .collect()
        .await
        .expect("the body")
        .to_bytes();
    assert_eq!(body.as_ref(), b"hello", "the body was cut");
}

/// A backend that sends a length and nothing else keeps it.
///
/// The rule above is about a message that was framed by an encoding. A
/// message framed by its length is forwarded with that length.
#[tokio::test]
async fn the_plaintext_path_keeps_a_length_that_framed_the_body() {
    let port = backend_answering("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello").await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let response = proxy_request(&clients, get_request("retry.test"), config)
        .await
        .expect("the backend answers");

    assert_eq!(
        response
            .headers()
            .get("content-length")
            .map(|value| value.to_str().unwrap()),
        Some("5"),
        "the length was dropped"
    );
}

/// A client that asks for gzip is answered with it.
///
/// The whole negotiation is here, end to end: the header the client sends,
/// the header that goes back, and the bytes that come with it.
#[tokio::test]
async fn a_client_that_asks_for_gzip_is_answered_with_it() {
    let port = backend_answering(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello",
    )
    .await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let request = Request::builder()
        .method("GET")
        .uri("http://retry.test/")
        .header("host", "retry.test")
        .header("accept-encoding", "gzip")
        .body(Full::new(bytes::Bytes::new()))
        .expect("a request");

    let response = proxy_request(&clients, request, config)
        .await
        .expect("the backend answers");

    assert_eq!(
        response
            .headers()
            .get("content-encoding")
            .map(|value| value.to_str().unwrap()),
        Some("gzip"),
        "the body was not compressed"
    );

    let body = response
        .into_body()
        .collect()
        .await
        .expect("the body")
        .to_bytes();
    let mut decoded = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&body[..]), &mut decoded)
        .expect("the body is gzip");
    assert_eq!(decoded, "hello", "the body did not survive the round trip");
}

/// A client that refuses gzip is answered without it.
///
/// RFC 9110 §12.5.3: `gzip;q=0` is the client saying it cannot decode gzip.
/// A body it cannot read is a body it silently drops, so the answer has to go
/// out in the clear.
#[tokio::test]
async fn a_client_that_refuses_gzip_is_answered_without_it() {
    let port = backend_answering(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello",
    )
    .await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let request = Request::builder()
        .method("GET")
        .uri("http://retry.test/")
        .header("host", "retry.test")
        .header("accept-encoding", "gzip;q=0")
        .body(Full::new(bytes::Bytes::new()))
        .expect("a request");

    let response = proxy_request(&clients, request, config)
        .await
        .expect("the backend answers");

    assert!(
        response.headers().get("content-encoding").is_none(),
        "the body was compressed anyway: {:?}",
        response.headers()
    );

    let body = response
        .into_body()
        .collect()
        .await
        .expect("the body")
        .to_bytes();
    assert_eq!(body.as_ref(), b"hello", "the body was changed");
}

/// The same route table, with a body deadline a test can wait out.
fn route_table_with_body_deadline(
    backends: Vec<String>,
    attempts: u32,
    body: std::time::Duration,
) -> Arc<crate::routes::RoutingTable> {
    let deadlines = crate::deadline::Deadlines {
        body,
        ..crate::deadline::Deadlines::default()
    };
    let timeouts = crate::config::Timeouts {
        connect: std::time::Duration::from_secs(1),
        response: std::time::Duration::from_secs(1),
        deadlines,
    };
    let route = crate::routes::Route::new(
        "retry.test",
        "/",
        true,
        backends,
        crate::lb::LoadBalancingStrategy::RoundRobin,
        crate::config::RouteMode::Http,
        None,
    );
    Arc::new(crate::routes::RoutingTable::with_settings(
        vec![route],
        timeouts,
        crate::config::Retry {
            attempts,
            backoff: std::time::Duration::ZERO,
        },
    ))
}

/// A body over the limit is refused with 413, not with a 502.
///
/// The request never reached a backend, so there is no backend to blame: a
/// 502 says the far end is down, and a client that reads it that way may
/// send the same body again. The tunnel path answers the same failure with
/// 413, and the two paths are the same proxy.
#[tokio::test]
async fn a_body_over_the_limit_is_refused_with_413() {
    let port = hello_backend().await;
    let backend = format!("http://127.0.0.1:{port}");
    let config = route_table(vec![backend], 1);
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    let request = Request::builder()
        .method("POST")
        .uri("http://retry.test/")
        .header("host", "retry.test")
        .body(Full::new(bytes::Bytes::from(vec![
            0u8;
            super::body::MAX_REQUEST_BODY
                + 1
        ])))
        .expect("a request");

    let response = proxy_request(&clients, request, config)
        .await
        .expect("the request is answered");

    assert_eq!(
        response.status(),
        413,
        "a body over the limit was not refused as too large"
    );
}

/// A body that does not arrive in time is refused with 408, not with a 502.
///
/// The same request, the same reasoning: the backend was never asked, so it
/// is not the one that failed.
#[tokio::test]
async fn a_body_that_does_not_arrive_in_time_is_refused_with_408() {
    let port = hello_backend().await;
    let backend = format!("http://127.0.0.1:{port}");
    let config =
        route_table_with_body_deadline(vec![backend], 1, std::time::Duration::from_millis(50));
    let clients =
        BackendClients::new(std::time::Duration::from_secs(1), None).expect("the clients");

    // A body that never yields and never ends: the read waits for it until
    // the deadline is over.
    let body = http_body_util::StreamBody::new(futures_util::stream::pending::<
        Result<hyper::body::Frame<bytes::Bytes>, std::convert::Infallible>,
    >());

    let request = Request::builder()
        .method("POST")
        .uri("http://retry.test/")
        .header("host", "retry.test")
        .body(body)
        .expect("a request");

    let response = proxy_request(&clients, request, config)
        .await
        .expect("the request is answered");

    assert_eq!(
        response.status(),
        408,
        "a body that did not arrive was not refused as a timeout"
    );
}
