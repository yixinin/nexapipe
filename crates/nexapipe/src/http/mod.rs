use crate::config::BackendProtocol;
use crate::routes::{BackendInfo, BackendLookup, RoutingTable};
use ::http::{Method, Request, Response, StatusCode};
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_util::{StreamExt, TryStreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// Client used to reach backends.
///
/// Speaks HTTP/1.1 to every backend and HTTP/2 to the ones that offer it: an
/// `https://` backend negotiates h2 through ALPN, and a cleartext one is
/// spoken to over HTTP/1.1 unless its route asks for h2c.
///
/// One client serves both schemes. The connector reads the scheme off the
/// request URI, and the pool keeps one set of connections per scheme and
/// authority — so an `http://` and an `https://` backend on the same host are
/// two sets, and neither is handed a connection the other opened.
///
/// TLS here is a client-side thing: this process never holds a certificate and
/// never terminates a session. It *originates* one towards a backend the route
/// names as `https://`, and checks the certificate it gets back.
pub type HttpClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<bytes::Bytes>,
>;

/// Builds the client the proxy reaches backends through.
///
/// The connect deadline comes from `[timeouts] connect_secs` and lives inside the
/// connector, so it applies to every dial this client makes — including the ones
/// made after the response head arrives, for a pooled connection that was closed
/// meanwhile. It is a builder setting, not something a caller passes per request,
/// because that is the only place the transport enforces it.
///
/// `ca_file` names a PEM file of extra CA certificates to trust when verifying
/// an `https://` backend. It is the machine's own roots *plus* that file: a
/// backend signed by an internal authority needs the internal authority, and
/// everything else keeps working.
pub fn create_http_client(
    connect_timeout: std::time::Duration,
    ca_file: Option<&std::path::Path>,
) -> anyhow::Result<HttpClient> {
    Ok(create_http_client_with_tls(
        tls_client_config(ca_file)?,
        connect_timeout,
    ))
}

/// The HTTP/1.1 client around a TLS configuration that is already built.
///
/// Split out so [`BackendClients`] can build the trust store once and hand a
/// clone to each client, rather than reading the machine's roots (and the
/// operator's CA file) twice for the same process.
fn create_http_client_with_tls(
    tls: rustls::ClientConfig,
    connect_timeout: std::time::Duration,
) -> HttpClient {
    let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(std::time::Duration::from_secs(30)));
    http_connector.set_connect_timeout(Some(connect_timeout));
    // The connector is handed the URI of the backend, `https://` included, and
    // it is the one that decides to put TLS on top of the socket. A connector
    // that insists on `http://` would refuse the address before the TLS layer
    // ever saw it.
    http_connector.enforce_http(false);

    // The connector is what decides between plaintext and TLS, and it decides
    // by the scheme of the URI it is handed — so the same client reaches an
    // `http://` backend and an `https://` one.
    //
    // `enable_all_versions` is also what puts the protocols on the table: the
    // ALPN list the handshake offers is `h2` first and `http/1.1` second, so a
    // backend that speaks h2 gets it and a backend that does not falls back to
    // HTTP/1.1 without anybody having to say which it is.
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);

    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Some(std::time::Duration::from_secs(120)))
        .http1_title_case_headers(true)
        .http1_ignore_invalid_headers_in_responses(true)
        // The HTTP/2 settings are the same idea as the HTTP/1 ones above: a
        // pooled connection is kept while it answers and dropped when it stops
        // answering. Without them an h2 connection to a backend that went away
        // stays in the pool until something else notices.
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .http2_keep_alive_timeout(std::time::Duration::from_secs(10))
        // The pool's own idle reaper needs a clock as well. The `timer` above
        // is the h2 half's -- HTTP/2 carries its own timeouts, and without one
        // the client panics the first time it negotiates h2. The pool is
        // separate: without a timer of its own, an idle connection to a
        // backend that stopped answering is only reaped when something else
        // notices, and the `pool_idle_timeout` above is enforced lazily, at
        // the next checkout.
        .pool_timer(hyper_util::rt::TokioTimer::new())
        // The h2 half needs a clock of its own: an HTTP/2 connection
        // carries its own timeouts — a ping that has to be answered, a
        // stream that has to be reset — and without a timer the client
        // panics the first time it negotiates h2 with a backend.
        .timer(hyper_util::rt::TokioTimer::new())
        .build(connector)
}

/// The clients the proxy reaches backends through.
///
/// Two of them, because the protocol to the backend is a property of the route
/// and not of the process: a backend that speaks HTTP/2 in the clear is reached
/// with a client that starts speaking h2, and everything else is reached with
/// the client that speaks HTTP/1.1 and negotiates h2 over TLS when a backend
/// offers it.
///
/// The two are separate objects rather than one client that decides per
/// request, because the protocol is decided when the connection is made and
/// not when the request is sent: a pooled connection is a connection to one
/// backend in one protocol, and a client that mixed the two would hand an h1
/// connection to a backend that only speaks h2.
#[derive(Clone)]
pub struct BackendClients {
    /// HTTP/1.1, and HTTP/2 where a backend negotiates it over TLS.
    http: Arc<HttpClient>,
    /// HTTP/2 in the clear, with prior knowledge.
    h2c: Arc<HttpClient>,
    /// TLS for a connection that is not the pooled client's: a WebSocket holds
    /// one connection for the whole session, and its handshake is HTTP/1.1.
    /// The ALPN list this carries is `http/1.1` alone.
    tls: Arc<rustls::ClientConfig>,
}

impl BackendClients {
    /// Builds both clients, with the same connect deadline and the same trust
    /// store.
    pub fn new(
        connect_timeout: std::time::Duration,
        ca_file: Option<&std::path::Path>,
    ) -> anyhow::Result<Self> {
        let tls = tls_client_config(ca_file)?;
        let mut websocket_tls = tls.clone();
        // A WebSocket upgrade is HTTP/1.1. Offering h2 here would let a
        // backend agree to a protocol this path cannot speak, so the raw
        // connection asks for the one version it can carry.
        websocket_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(BackendClients {
            http: Arc::new(create_http_client_with_tls(tls.clone(), connect_timeout)),
            h2c: Arc::new(create_h2c_client_with_tls(tls, connect_timeout)),
            tls: Arc::new(websocket_tls),
        })
    }

    /// The client that speaks this protocol.
    pub fn for_protocol(&self, protocol: BackendProtocol) -> &HttpClient {
        match protocol {
            BackendProtocol::Http1 => &self.http,
            BackendProtocol::H2c => &self.h2c,
        }
    }

    /// Opens one connection to a backend, for a WebSocket session.
    ///
    /// This is not the pooled client: a WebSocket holds its connection for the
    /// whole conversation, so it needs the socket itself rather than a request
    /// the pool may reuse. An `https://` backend is still reached over a TLS
    /// session this process originates and verifies, with the same trust store
    /// as the pooled clients; a cleartext one is handed back as it is.
    pub(crate) async fn connect_stream(
        &self,
        backend_url: &str,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<BackendStream> {
        let url = url::Url::parse(backend_url)
            .map_err(|e| anyhow::anyhow!("invalid backend URL: {e}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("backend URL missing host"))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(80);
        let scheme = url.scheme().to_string();

        let connect = async {
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|e| anyhow::anyhow!("failed to connect to backend: {e}"))?;
            // A WebSocket carries its own message framing; Nagle would only add
            // latency to every frame.
            let _ = tcp.set_nodelay(true);

            match scheme.as_str() {
                "http" => Ok(BackendStream::Plain(tcp)),
                "https" => {
                    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                        .map_err(|e| {
                            anyhow::anyhow!("cannot verify the backend certificate for {host}: {e}")
                        })?;
                    let connector = tokio_rustls::TlsConnector::from(self.tls.clone());
                    let tls = connector
                        .connect(server_name, tcp)
                        .await
                        .map_err(|e| anyhow::anyhow!("TLS handshake with backend failed: {e}"))?;
                    Ok(BackendStream::Tls(Box::new(tls)))
                }
                other => anyhow::bail!(
                    "backend {backend_url} uses {other}://, which cannot carry a WebSocket"
                ),
            }
        };

        tokio::time::timeout(connect_timeout, connect)
            .await
            .map_err(|_| anyhow::anyhow!("timed out connecting to backend {host}:{port}"))?
    }
}

/// A dedicated backend connection, for a flow that owns it for its lifetime.
///
/// Plain or TLS, so the WebSocket path does not have to know which one it got
/// after the dial: it writes the upgrade request and pipes the session either
/// way.
pub(crate) enum BackendStream {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for BackendStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            BackendStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BackendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            BackendStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            BackendStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            BackendStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            BackendStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Builds the client that speaks HTTP/2 in the clear, with prior knowledge.
///
/// The other name for this is h2c, and the "prior knowledge" is the whole
/// point: a cleartext connection has no handshake to negotiate a protocol in,
/// so the client has to know that the backend speaks h2 and start speaking it.
/// A backend that does not answer h2 gets a connection reset, which is a
/// failure the route's own configuration is responsible for avoiding.
pub fn create_h2c_client(
    connect_timeout: std::time::Duration,
    ca_file: Option<&std::path::Path>,
) -> anyhow::Result<HttpClient> {
    Ok(create_h2c_client_with_tls(
        tls_client_config(ca_file)?,
        connect_timeout,
    ))
}

/// The h2c client around a TLS configuration that is already built.
fn create_h2c_client_with_tls(
    tls: rustls::ClientConfig,
    connect_timeout: std::time::Duration,
) -> HttpClient {
    let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(std::time::Duration::from_secs(30)));
    http_connector.set_connect_timeout(Some(connect_timeout));
    // As in `create_http_client`: the connector is handed the URI and does not
    // get to refuse the scheme.
    http_connector.enforce_http(false);

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);

    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        // The one setting that makes this client h2: every connection it
        // opens is an h2 connection, whatever the peer says or does not say.
        .http2_only(true)
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Some(std::time::Duration::from_secs(120)))
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .http2_keep_alive_timeout(std::time::Duration::from_secs(10))
        // The pool's own idle reaper needs a clock as well. The `timer` above
        // is the h2 half's -- HTTP/2 carries its own timeouts, and without one
        // the client panics the first time it negotiates h2. The pool is
        // separate: without a timer of its own, an idle connection to a
        // backend that stopped answering is only reaped when something else
        // notices, and the `pool_idle_timeout` above is enforced lazily, at
        // the next checkout.
        .pool_timer(hyper_util::rt::TokioTimer::new())
        // The clock the h2 half needs, for the same reason the other client
        // has one: an h2 connection times things on its own.
        .timer(hyper_util::rt::TokioTimer::new())
        .build(connector)
}

/// The TLS configuration a backend handshake is made with.
///
/// The certificate is verified against the machine's own trust store, and there
/// is no way to turn that off: a proxy that connects to a backend without
/// checking who it is talking to is a proxy that can be redirected by whoever
/// answers the name. A backend whose certificate this process cannot verify is
/// a backend this proxy does not reach.
///
/// The provider is named rather than left to the process-wide default, so the
/// client does not depend on the order things happen to be installed in — the
/// iroh handshake installs a provider of its own, and the two must not race.
fn tls_client_config(ca_file: Option<&std::path::Path>) -> anyhow::Result<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_root_certificates(root_store(ca_file)?)
        .with_no_client_auth())
}

/// The certificates a backend's certificate is checked against.
///
/// The machine's own roots rather than a list this project ships: a
/// certificate the browser on the same machine trusts is a certificate this
/// proxy trusts, and a bundled list goes stale without anybody noticing.
///
/// A host with no roots of its own — a minimal container image without
/// `ca-certificates`, say — falls back to Mozilla's bundled ones, because a
/// proxy that cannot verify anything is a proxy that cannot reach an
/// `https://` backend at all. The fallback is a weaker guarantee and says so
/// in the log, rather than turning every handshake into a message about a
/// missing issuer.
fn root_store(ca_file: Option<&std::path::Path>) -> anyhow::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();

    // The platform loader reports what it could not read alongside what it
    // read, rather than failing as a whole: one unreadable store on a machine
    // with several is still a store.
    let native = rustls_native_certs::load_native_certs();
    if !native.certs.is_empty() {
        let mut rejected = 0usize;
        for cert in native.certs {
            if roots.add(cert).is_err() {
                rejected += 1;
            }
        }
        tracing::info!(
            "Loaded {} CA certificates from the system trust store ({rejected} rejected)",
            roots.len()
        );
    } else {
        tracing::warn!(
            "The system trust store holds no usable certificates ({} errors); falling back to \
             Mozilla's bundled roots for backend TLS",
            native.errors.len()
        );
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    // The file the operator named is read here rather than at the first
    // handshake: a CA file that cannot be read is a config that cannot work,
    // and the operator should read about it at startup rather than in the log
    // of a request that failed to verify.
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("cannot read the CA file {}: {e}", path.display()))?;
        let mut reader = std::io::BufReader::new(pem.as_slice());
        let certs = rustls_pemfile::certs(&mut reader)
            .map_err(|e| anyhow::anyhow!("cannot parse the CA file {}: {e}", path.display()))?;
        if certs.is_empty() {
            anyhow::bail!(
                "the CA file {} holds no certificates; it should hold one or more PEM-encoded \
                 certificates",
                path.display()
            );
        }
        let mut rejected = 0usize;
        for cert in certs {
            if roots
                .add(rustls::pki_types::CertificateDer::from(cert))
                .is_err()
            {
                rejected += 1;
            }
        }
        tracing::info!(
            "Loaded the CA file {} ({} certificates, {rejected} rejected)",
            path.display(),
            roots.len()
        );
    }

    Ok(roots)
}

const MAX_COMPRESS_SIZE: usize = 1024 * 1024;

/// The error a proxied response body can fail with.
///
/// `hyper::Error` cannot be built outside hyper — it has no public
/// constructor, only `From<hyper::error::Parse>`, which is private — so a body
/// that has to fail on its own cannot use it. A backend that answers with a
/// head and then goes silent is exactly such a case, and the failure has to be
/// reported rather than swallowed: a body that simply ends is a truncated
/// response, and a truncated chunked response is one the client cannot tell
/// from a whole one.
#[derive(Debug)]
pub enum BodyError {
    /// The backend sent nothing for longer than the idle deadline.
    Idle(std::time::Duration),
    /// The connection to the backend failed.
    Hyper(hyper::Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::Idle(idle) => {
                write!(f, "backend sent nothing for {idle:?} mid-body")
            }
            BodyError::Hyper(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BodyError::Idle(_) => None,
            BodyError::Hyper(e) => Some(e),
        }
    }
}

impl From<hyper::Error> for BodyError {
    fn from(e: hyper::Error) -> Self {
        BodyError::Hyper(e)
    }
}

/// The body a proxied response carries.
pub type ProxyBody = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BodyError>;

/// The backend's response body, with the gap between its frames bounded.
///
/// Idle, not a phase deadline: what is bounded is the gap, so it re-arms on
/// every frame — which is what lets an SSE stream or a long transfer stay open
/// for as long as both ends want, while a backend that sent the head and then
/// went silent cannot hold this slot and its backend lease forever. The value
/// comes from `[timeouts] response_idle_secs` through the caller.
///
/// The stream is the body a client is handed, so the failure it reports is
/// the one the client sees: hyper aborts the connection rather than writing a
/// complete-looking response that is missing its tail.
fn idle_bounded<B>(
    body: B,
    idle: std::time::Duration,
) -> impl futures_util::Stream<Item = Result<hyper::body::Frame<bytes::Bytes>, BodyError>>
where
    B: hyper::body::Body<Data = bytes::Bytes>,
    B::Error: Into<BodyError>,
{
    let frames = http_body_util::BodyExt::into_data_stream(body).map_ok(hyper::body::Frame::data);
    // `timeout` re-arms on every item, which is the idle semantics wanted
    // here. Both `StreamExt` traits have a `timeout`-shaped surface, so the
    // call is made by its full path rather than by an import.
    let timed = tokio_stream::StreamExt::timeout(frames, idle);
    timed.map(move |item| match item {
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => {
            tracing::warn!("Backend sent nothing for {idle:?} mid-body, ending the response body");
            Err(BodyError::Idle(idle))
        }
    })
}

/// The largest request body this proxy will read into memory.
///
/// `content-length` is whatever the client says it is, and the request is
/// buffered whole before it is forwarded, so taking the declaration at face
/// value lets a client choose how much this process allocates — one stream at a
/// time, and a peer can open many. Well past any ordinary upload; a deployment
/// that needs to push larger bodies should stream them instead of raising this.
///
/// This bounds one request. How many such bodies may be held at once is
/// [`ByteBudget`](crate::conn::limits::ByteBudget)'s, which is why a body is
/// only read once it has been given a reservation from it.
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

/// Whether a request header may be forwarded to the backend.
///
/// Two groups are dropped. Hop-by-hop headers describe one connection, not the
/// message (RFC 7230 6.1): `connection: keep-alive` is about the client's link
/// to this proxy, and forwarding it asks the backend to keep *its* link open
/// for a request that arrived over a different one. `transfer-encoding` is in
/// the same group and has to go: the body has already been read whole and is
/// sent as a single buffer, so a leftover `chunked` would disagree with the
/// framing on the wire.
///
/// `proxy-authorization` is in the same group and is the one that matters most:
/// it is a credential for *this* proxy, and forwarding it hands that credential
/// to a third-party server. `proxy-authenticate` goes with it — it is the
/// challenge this proxy answers, and the backend has no business seeing it.
///
/// `expect: 100-continue` is dropped for a different reason. The proxy reads
/// the body before it ever asks the backend anything, so the client's
/// expectation was answered by this process — and a backend told to expect
/// more would wait for bytes that are already here.
///
/// The WebSocket handshake does not use this: it is the one request that
/// *must* carry `upgrade` and `connection`, because switching protocols is
/// exactly what it is asking the backend for.
fn forwards_request_header(name: &str) -> bool {
    ![
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "expect",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
}

/// Whether a response header may be forwarded to the client.
///
/// The same rule as the request direction, and for the same reason: a
/// hop-by-hop header describes one connection, not the message (RFC 9110
/// §7.6.1). A `connection: keep-alive` from the backend is about the
/// backend's link to this process, and forwarding it tells the client to keep
/// *its* link open for a response that arrived over a different one.
///
/// `transfer-encoding` is in the same group and has to go: the body is framed
/// below, and a leftover `chunked` would disagree with the framing on the wire.
///
/// The list is the RFC's, which is not the request direction's list: a request
/// carries `expect` and `proxy-connection`, which are not response headers,
/// and the two directions carry the proxy authentication headers, which are.
fn forwards_response_header(name: &str) -> bool {
    ![
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
}

///
/// The request body is a parameter rather than `Incoming` so that the path can
/// be driven by something other than a live connection — a test, mostly. The
/// body is read whole either way, and what comes back does not depend on where
/// the request came from.
pub async fn proxy_request<B>(
    clients: &BackendClients,
    req: Request<B>,
    config: Arc<RoutingTable>,
) -> Result<Response<ProxyBody>, anyhow::Error>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    // Answered, not raised: no `Host` means no route can match, which is the
    // same answer as a host no route matches — and the caller maps an `Err`
    // from here to a 502, which would blame a backend for a request that never
    // got as far as choosing one.
    let Some(host) = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(crate::routes::host_without_port)
        // Owned, because the request is moved into the body read below and
        // the host is needed after that.
        .map(str::to_string)
    else {
        return Ok(create_error_response(
            StatusCode::NOT_FOUND,
            "Missing host header",
        ));
    };

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path())
        // Owned, for the same reason the host is: the request is moved into
        // the body read below, and the path is needed after that.
        .to_string();

    let accept_encoding = req
        .headers()
        .get("accept-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let headers_clone = req.headers().clone();
    let method = req.method().clone();

    // The first backend is chosen before the body is read, so a request for a
    // host nobody serves is answered without reading what it carries.
    let mut backend_info: BackendInfo = match config.get_backend(&host, &path).await {
        BackendLookup::Found(info) => info,
        // No route serves this host: saying 404 beats guessing at one.
        BackendLookup::NoRoute => {
            return Ok(create_error_response(
                hyper::StatusCode::NOT_FOUND,
                &format!("No route for host {host}"),
            ));
        }
        // The route is configured and every backend behind it is unhealthy. 503
        // rather than 404, because the difference is which file the operator has
        // to open: nothing here is misconfigured, something downstream is down.
        BackendLookup::Unavailable => {
            tracing::warn!("No healthy backend behind {host}{path}, answering 503");
            return Ok(create_error_response(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                &format!("No healthy backend for host {host}"),
            ));
        }
    };

    // Read once, for every attempt: the body cannot be read twice, and what
    // goes out is the same bytes whichever backend receives it.
    //
    // Held for as long as the buffered body is alive — see `read_body_limited`.
    // Dropping it here rather than at the end of the function is deliberate and
    // is what makes the budget mean what it says.
    let (body, _body_reservation) = read_body_limited(
        req.into_body(),
        MAX_REQUEST_BODY,
        config.timeouts().deadlines.body,
    )
    .await?;

    let attempts = config.retry().attempts;
    let backoff = config.retry().backoff;
    // The backends that already failed this request. A retry asks somebody
    // else, because the one that just failed is the one most likely to fail
    // again.
    let mut tried: Vec<String> = Vec::new();
    let mut attempt = 0u32;

    loop {
        let outcome = attempt_backend(
            clients,
            &config,
            &backend_info,
            &method,
            &headers_clone,
            &path,
            &body,
        )
        .await;

        let response = match outcome {
            Ok(response) => {
                // The backend answered, so it is up: the circuit is told, and
                // a backend that was out of rotation comes back into it.
                backend_info.report_success();
                response
            }
            Err(failure) => {
                // Only a failure that says the backend is unreachable counts
                // against it. A response that broke halfway is a different
                // thing: the backend did answer.
                if failure.backend_is_down() {
                    backend_info.report_failure();
                }

                // Two questions, and the failure answers both: may this be
                // tried again at all, and is there another backend to try it
                // on.
                if attempt >= attempts || !failure.retry.may_retry(&method) {
                    return Err(failure.error);
                }
                attempt += 1;

                tracing::warn!(
                    "Request to {} failed ({}); trying another backend ({attempt}/{attempts})",
                    backend_info.url,
                    failure.error,
                );

                tried.push(backend_info.url.to_string());
                match config.get_backend_excluding(&host, &path, &tried).await {
                    BackendLookup::Found(info) => backend_info = info,
                    // Nobody else to ask. The failure is the answer: the pool
                    // being empty is a consequence of it, not a new fact.
                    BackendLookup::NoRoute | BackendLookup::Unavailable => {
                        return Err(failure.error);
                    }
                }

                if !backoff.is_zero() {
                    tokio::time::sleep(backoff).await;
                }
                continue;
            }
        };

        let content_encoding = response.headers().get("content-encoding");
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok());

        // The idle deadline covers the body as well as the head: a backend that
        // answers and then goes silent must not hold this request open. The
        // streaming path has always bounded this; the plaintext listener had no
        // bound at all, so a backend that sent the head and stalled kept the
        // request — and the connection — for as long as it liked.
        let idle = config.timeouts().deadlines.response_idle;

        // The lease moves out of the backend info and into the body, because
        // the work against that backend is not over when the response head
        // arrives: a body that is still streaming is a backend that is still
        // busy. See `LeasedBody`.
        let lease = backend_info.take_lease();

        if content_encoding.is_none()
            && should_compress(content_type)
            && let Some(encodings) = accept_encoding
            && encodings.contains("gzip")
        {
            // The whole body is read and compressed here, so the backend is
            // done with it before the answer goes out: the lease goes back
            // with the `backend_info` that is dropped at the end of this
            // function.
            return compress_response(response, "gzip", idle).await;
        }

        return Ok(response.map(|body| {
            let body = http_body_util::StreamBody::new(idle_bounded(body, idle)).boxed_unsync();
            http_body_util::BodyExt::boxed_unsync(LeasedBody {
                inner: body,
                _lease: lease,
            })
        }));
    }
}

/// A message with its first letter capitalised.
///
/// The reasons the backend's address can fail with are written in the lower
/// case, because the tunnel path says them in the lower case. This path says
/// them with a capital, and the two are the same reason in two wordings.
fn capitalised(message: &str) -> String {
    let mut chars = message.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// One attempt at one backend: the answer, or the reason there was none.
///
/// Split out of [`proxy_request`] so that the retry loop above it is about
/// retrying and this is about asking. The request is rebuilt for every
/// attempt, because the backend it goes to may be a different one.
async fn attempt_backend(
    clients: &BackendClients,
    config: &RoutingTable,
    backend_info: &BackendInfo,
    method: &Method,
    headers: &::http::HeaderMap,
    path: &str,
    body: &bytes::Bytes,
) -> Result<Response<hyper::body::Incoming>, ProxyFailure> {
    // The client is picked by the protocol the route speaks to its backends,
    // which is decided by the route rather than by the request: a backend that
    // speaks h2 in the clear is reached with the h2c client, everything else
    // with the one that speaks HTTP/1.1 and negotiates h2 over TLS.
    let client = clients.for_protocol(backend_info.protocol);
    let response_deadline = config.timeouts().response;

    let rewritten_path = backend_info.rewritten_path(path);

    // The origin was parsed when the pool was built, so this is a borrow of
    // it rather than a `Url::parse` per request.
    //
    // The reason is capitalised for this path: it said "Invalid backend URL"
    // here and "invalid backend URL" on the tunnel path, and the operator
    // reads both.
    let origin: &str = match &backend_info.origin {
        Ok(origin) => origin,
        Err(reason) => return Err(anyhow::anyhow!("{}", capitalised(reason)).into()),
    };

    // The host and the port on their own, which is how this path named the
    // backend that did not answer.
    let host_and_port = match origin.split_once("://") {
        Some((_, rest)) => rest,
        None => origin,
    };

    let new_uri = format!("{origin}{rewritten_path}")
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let mut builder = Request::builder().method(method.clone()).uri(new_uri);

    for (name, value) in headers.iter() {
        // Preserve the client's original Host header so backend virtual-host
        // routing works; drop the rest that only meant something for the hop
        // from the client to here.
        if !forwards_request_header(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }

    let proxied_req = builder.body(Full::new(body.clone()))?;

    tracing::debug!(
        "Proxying request: {} {} -> {origin}",
        proxied_req.method(),
        proxied_req.uri(),
    );

    match tokio::time::timeout(response_deadline, client.request(proxied_req)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => Err(ProxyFailure {
            error: anyhow::anyhow!("backend request failed: {e}"),
            partial: None,
            // A connect error means the request was never carried: the
            // connection was refused, the name did not resolve, the handshake
            // failed. Nothing reached the backend, so asking again is free of
            // consequence whatever the request was. Anything else means the
            // request was sent and the answer did not come, which only an
            // idempotent request may be asked twice.
            retry: if e.is_connect() {
                Retryability::Always
            } else {
                Retryability::IfIdempotent
            },
        }),
        Err(_) => Err(ProxyFailure {
            error: anyhow::anyhow!(
                "backend {host_and_port} did not respond within {response_deadline:?}"
            ),
            partial: None,
            // The request was carried: the deadline expired after it went out.
            retry: Retryability::IfIdempotent,
        }),
    }
}

/// A response body that keeps its backend busy until the body is done.
///
/// The lease is what the balancer counts, and a backend that is still
/// streaming a response is still busy with it. A balancer that cannot see
/// that hands the next request to a backend that is already working, which
/// is the whole failure `least_conn` exists to avoid.
///
/// Holding the lease in the body is what makes the count true: the body is
/// dropped when the client has read it — or when the connection goes away
/// instead — and the backend is free again then. The streaming path has
/// always held its lease for the whole flow; this is the same rule on the
/// path that did not.
struct LeasedBody {
    inner: ProxyBody,
    /// Kept, never read: dropping it is what releases the backend.
    _lease: Option<crate::lb::BackendLease>,
}

impl hyper::body::Body for LeasedBody {
    type Data = bytes::Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }
}

/// Reads a request body whole, refusing one past `limit` or past what the
/// process can hold at once.
///
/// Returns the reservation as well as the bytes, and the caller has to keep it:
/// dropping it gives the bytes back, so the total the budget reports is what is
/// held *now* rather than what was ever read. A caller that answers the request
/// and returns is exactly the lifetime a buffered body has.
///
/// The size is not known up front — a chunked request says nothing about how
/// much is coming — so the limit has to be enforced while reading rather than
/// by checking a `content-length` header the client is free to understate.
///
/// The deadline over the read is likewise total rather than per frame, so a
/// client that trickles one byte before each expiry renews nothing.
async fn read_body_limited<B>(
    body: B,
    limit: usize,
    body_deadline: std::time::Duration,
) -> anyhow::Result<(bytes::Bytes, crate::conn::limits::ByteReservation)>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut body = body;
    let mut bytes: Vec<u8> = Vec::new();
    // Claimed as the frames arrive rather than up front: see `ByteReservation`.
    let mut reservation = crate::conn::limits::ByteReservation::empty();
    // A deadline over the whole read, not per frame: this is the path the
    // plaintext listener takes, and it had no bound at all, so a client that
    // opened a socket and then sent a byte of body every few seconds held the
    // connection, the task and the buffer indefinitely. The iroh path has always
    // bounded this read; this is the same bound, in one place. The value comes
    // from `[timeouts] body_secs` through the caller, not from here.
    let deadline_at = tokio::time::Instant::now() + body_deadline;
    loop {
        // A `loop` rather than `while let`, so that the deadline's own expiry is
        // told apart from the end of the body.
        let frame =
            match tokio::time::timeout_at(deadline_at, http_body_util::BodyExt::frame(&mut body))
                .await
            {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "request body did not finish within {}s",
                        body_deadline.as_secs()
                    ));
                }
            };
        let frame = frame.map_err(|e| anyhow::anyhow!("failed to read the request body: {}", e))?;
        // Anything that is not a data frame — trailers — carries no body bytes.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if bytes.len() + data.len() > limit {
            return Err(anyhow::anyhow!(
                "request body is over the {limit} byte limit"
            ));
        }
        reservation.grow(data.len())?;
        bytes.extend_from_slice(&data);
    }
    Ok((bytes.into(), reservation))
}

fn should_compress(content_type: Option<&str>) -> bool {
    if let Some(ct) = content_type {
        ct.starts_with("text/")
            || ct.contains("application/json")
            || ct.contains("application/javascript")
            || ct.contains("application/xml")
            || ct.contains("application/xhtml")
    } else {
        false
    }
}

async fn compress_response(
    response: Response<hyper::body::Incoming>,
    encoding: &str,
    idle: std::time::Duration,
) -> anyhow::Result<Response<ProxyBody>> {
    let (parts, body) = response.into_parts();
    let mut body = body;
    let mut bytes: Vec<u8> = Vec::new();

    // Read only as far as the limit, so the decision to compress is made with
    // the size known rather than after the whole body has been collected. How
    // large a response is cannot be asked up front: a chunked one declares no
    // length at all, and a backend is free to send past the one it declared.
    //
    // The idle bound is the one the uncompressed path uses: a backend that
    // sends the head and then goes silent must not hold this read open either.
    loop {
        let frame =
            match tokio::time::timeout(idle, http_body_util::BodyExt::frame(&mut body)).await {
                Ok(Some(frame)) => frame,
                // The body finished: this is the end, not a failure.
                Ok(None) => break,
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "backend sent nothing for {idle:?} mid-body"
                    ));
                }
            };
        let frame =
            frame.map_err(|e| anyhow::anyhow!("failed to read the response body: {}", e))?;
        // Anything that is not a data frame — trailers — carries no body bytes.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        bytes.extend_from_slice(&data);
        if bytes.len() > MAX_COMPRESS_SIZE {
            tracing::debug!(
                "Response past {} bytes, forwarding the rest uncompressed",
                MAX_COMPRESS_SIZE
            );
            // What has been read still goes out, ahead of the body handed on:
            // dropping it would truncate the response. From here the rest is
            // streamed rather than held, so a large response costs one frame.
            let read = futures_util::stream::once(futures_util::future::ready(Ok::<_, BodyError>(
                hyper::body::Frame::data(bytes::Bytes::from(bytes)),
            )));
            let rest = idle_bounded(body, idle);
            return Ok(Response::from_parts(
                parts,
                http_body_util::StreamBody::new(read.chain(rest)).boxed_unsync(),
            ));
        }
    }

    // Compressing up to `MAX_COMPRESS_SIZE` bytes is straight CPU work, and it
    // used to run on whichever worker happened to be serving this request: a
    // tokio worker stalls every task scheduled behind it, so one compressible
    // response became a delay on unrelated ones. `spawn_blocking` hands it to a
    // thread built for it and leaves the worker free.
    let compressed_bytes = tokio::task::spawn_blocking(move || {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bytes)?;
        encoder.finish()
    })
    .await
    .map_err(|e| anyhow::anyhow!("the gzip encoder did not run: {e}"))??;

    let mut new_parts = parts;
    new_parts.headers.remove("content-encoding");
    new_parts.headers.remove("content-length");
    new_parts.headers.insert(
        "content-encoding",
        encoding
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid content-encoding {:?}: {}", encoding, e))?,
    );

    Ok(Response::from_parts(
        new_parts,
        http_body_util::BodyExt::boxed_unsync(
            Full::new(compressed_bytes.into()).map_err(|_| unreachable!()),
        ),
    ))
}

pub fn create_error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(http_body_util::BodyExt::boxed_unsync(
            Full::new(message.as_bytes().to_vec().into()).map_err(|_| unreachable!()),
        ))
        .unwrap()
}

pub fn is_websocket_request(req: &Request<Incoming>) -> bool {
    if let Some(upgrade) = req.headers().get("upgrade")
        && let Ok(upgrade_str) = upgrade.to_str()
        && upgrade_str.to_lowercase() == "websocket"
        && let Some(connection) = req.headers().get("connection")
        && let Ok(connection_str) = connection.to_str()
    {
        return connection_str.to_lowercase().contains("upgrade");
    }
    false
}

pub fn is_websocket_request_static(req: &Request<()>) -> bool {
    if let Some(upgrade) = req.headers().get("upgrade")
        && let Ok(upgrade_str) = upgrade.to_str()
        && upgrade_str.to_lowercase() == "websocket"
        && let Some(connection) = req.headers().get("connection")
        && let Ok(connection_str) = connection.to_str()
    {
        return connection_str.to_lowercase().contains("upgrade");
    }
    false
}

/// What one proxied request came to.
///
/// The streaming path writes the response straight into the QUIC stream, so
/// there is no `Response` left for the caller to inspect; without this the
/// tunnel path — the one every client actually uses — could not be logged at
/// all.
#[derive(Debug, Clone, Copy)]
pub struct ProxySummary {
    pub status: u16,
    /// Response headers plus body payload, excluding chunk framing.
    ///
    /// What reached the client, counted at each successful write rather than
    /// at each byte formatted: a partially streamed response reports the part
    /// that was flushed, not the length it was going to be.
    pub bytes_sent: usize,
}

/// A proxied request that did not finish.
///
/// The streaming path writes as it goes, so by the time something fails the
/// status line — and possibly half the body — is already on the wire. Reporting
/// every failure as a 502 with zero bytes claims a response was never sent when
/// the client is holding part of one, which is the worst possible thing for an
/// access log to say about a request: it points the reader at the backend for a
/// problem that happened after the backend answered. What had arrived when it
/// broke is carried here instead, and is `None` only when nothing had.
#[derive(Debug)]
pub struct ProxyFailure {
    pub error: anyhow::Error,
    pub partial: Option<ProxySummary>,
    /// What may be done about this failure.
    pub retry: Retryability,
}

/// What may be done about a failed attempt.
///
/// The question is never "did it fail" but "may it be tried again", and the
/// answer depends on two things that are easy to confuse:
///
/// - **Did the request reach the backend?** A connection that was refused
///   never carried it, so the backend did not act on it and asking again is
///   free of consequence — whatever the request was.
/// - **Is the request safe to send twice?** A `GET` is. A `POST` that
///   charges a card is not, and the only way to know is what the method says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryability {
    /// The request was never carried to the backend. It may be tried again
    /// whatever it is.
    Always,
    /// The request was carried and no answer came. It may be tried again only
    /// if sending it twice is safe, which is what an idempotent method is.
    IfIdempotent,
    /// Nothing may be tried again: the client already has part of the answer,
    /// or the failure says nothing about the backend.
    Never,
}

impl ProxyFailure {
    /// Whether this failure says the backend is unreachable.
    ///
    /// A failure after the answer started is not the backend's fault: it
    /// answered, and the connection broke on the way back. Neither is a
    /// request that never left this process.
    pub fn backend_is_down(&self) -> bool {
        self.partial.is_none() && self.retry != Retryability::Never
    }
}

impl Retryability {
    /// Whether this failure may be tried again for this method.
    pub fn may_retry(self, method: &Method) -> bool {
        match self {
            Retryability::Always => true,
            Retryability::IfIdempotent => is_idempotent(method),
            Retryability::Never => false,
        }
    }
}

/// Whether sending this request twice is safe.
///
/// The idempotent methods of RFC 9110: the same request may be sent again
/// without the server doing the work twice. Everything else — `POST` above
/// all — may not, which is why a request that was carried and lost is only
/// retried when its method says it is safe.
pub fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

impl From<anyhow::Error> for ProxyFailure {
    fn from(error: anyhow::Error) -> Self {
        ProxyFailure {
            error,
            partial: None,
            retry: Retryability::Never,
        }
    }
}

impl From<::http::Error> for ProxyFailure {
    fn from(error: ::http::Error) -> Self {
        ProxyFailure::from(anyhow::anyhow!("{error}"))
    }
}

impl ProxyFailure {
    /// A failure before any of the answer reached the client.
    ///
    /// `retry` is what the failure says about trying again: a request that was
    /// never carried may be, and one that was carried and lost may only be
    /// when the method is idempotent. This is the same distinction
    /// [`proxy_request`] makes, for the tunnel path.
    pub(crate) fn unanswered(error: anyhow::Error, retry: Retryability) -> Self {
        ProxyFailure {
            error,
            partial: None,
            retry,
        }
    }

    /// A failure that happened `written` bytes into a `status` response.
    ///
    /// Used on the paths where the count is of bytes the client actually
    /// received: a buffer that was filled but never flushed has not arrived, so
    /// it is not in here.
    fn after(status: StatusCode, written: usize, error: anyhow::Error) -> Self {
        ProxyFailure {
            error,
            partial: Some(ProxySummary {
                status: status.as_u16(),
                bytes_sent: written,
            }),
            // The client has part of the answer, so there is nothing to try
            // again: it would be a second answer to a request that was already
            // answered.
            retry: Retryability::Never,
        }
    }
}

// One more argument than clippy allows: the alternative is a struct bundling the
// client with its deadlines, which every caller would have to build in order to
// pass the same two things — see the note on `conn::handle_bidi_stream`.
#[allow(clippy::too_many_arguments)]
/// The body of a request, read once and ready to be sent to a backend.
///
/// Read outside the attempt, because the bytes come off the client's stream
/// and that stream has them only once: a retry that had to read them again
/// would wait for bytes that are never coming.
pub struct RequestBody {
    /// The bytes, whole.
    ///
    /// **Shared, not owned twice.** The body is read into a buffer, and the
    /// request that goes to the backend used to be handed a *copy* of it: the
    /// buffer stayed alive for the retry, and the copy was thrown away with
    /// the attempt. So the process held the body twice over for as long as
    /// the request lived, while the byte budget counted it once.
    ///
    /// A [`Bytes`] is the same buffer with a reference count, so the retry
    /// takes another reference to the same bytes rather than a second copy of
    /// them, and the peak is what the budget says it is.
    pub bytes: bytes::Bytes,
    /// The length to declare to the backend, when the client declared none.
    ///
    /// A chunked request has no length of its own; the proxy reads the chunks
    /// and sends one buffer with a length of its own.
    pub content_length: Option<usize>,
    /// Held for as long as the body is alive, so the process budget counts
    /// what it holds now rather than what it ever read. See
    /// [`crate::conn::limits::ByteReservation`].
    pub reservation: crate::conn::limits::ByteReservation,
}

/// Reads the body of a request off the client's stream.
///
/// The bytes that arrived with the head are `body_data`; the rest is read
/// here. What comes back is whole: either every byte the client promised, or
/// an error — a body that stops halfway is a request that was never sent.
pub async fn read_request_body(
    req: &Request<()>,
    recv: &mut iroh::endpoint::RecvStream,
    body_data: Vec<u8>,
    timeouts: crate::config::Timeouts,
) -> Result<RequestBody, ProxyFailure> {
    // A chunked body is sent as one buffer with a length of our own, so only a
    // request whose `content-length` we could not read takes that path. One we
    // could read is forwarded with the header it arrived with.
    let declared_length = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let chunked = declared_length.is_none() && request_is_chunked(req);

    let mut full_body = body_data;
    // Held for as long as the body is alive, which is until the request is
    // done: the buffer is handed to the backend and dropped with the request.
    // Same rule as `read_body_limited` on the plaintext path, and the reason
    // the two are worth keeping in step — one without the other leaves the
    // process budget counting a fraction of what it actually holds.
    let (reservation, content_length) = if let Some(content_length) = declared_length {
        // Checked before the body is read, not after: `content_length` is the
        // size of the buffer this is about to fill.
        if content_length > MAX_REQUEST_BODY {
            return Err(ProxyFailure::from(anyhow::anyhow!(
                "request body of {content_length} bytes is over the {MAX_REQUEST_BODY} byte limit"
            )));
        }
        let reservation = read_remaining_request_body(
            recv,
            &mut full_body,
            content_length,
            timeouts.deadlines.body,
        )
        .await?;
        (reservation, None)
    } else if chunked {
        // A chunked body declares no length, so without this branch the request
        // went out carrying only the bytes that happened to arrive with the
        // head — and `transfer-encoding` is not forwarded, so the backend was
        // handed a body with no framing at all and no way to know it was
        // truncated. Decode the chunks and send one buffer with a length.
        let reservation = read_chunked_request_body(
            recv,
            &mut full_body,
            timeouts.deadlines.body,
            crate::conn::limits::body_budget(),
        )
        .await?;
        (reservation, Some(full_body.len()))
    } else {
        (crate::conn::limits::ByteReservation::empty(), None)
    };

    // The body is complete at this point in every branch above, and this is the
    // only place it is whole: what goes out is a reconstructed request with its
    // own framing, so its size on the way out is not what arrived.
    crate::metrics::METRICS.record_bytes_received(full_body.len() as u64);

    Ok(RequestBody {
        // The buffer is handed over rather than copied: the body is read into
        // it once, and the request that goes to the backend takes a reference
        // to the same bytes.
        bytes: bytes::Bytes::from(full_body),
        content_length,
        reservation,
    })
}

/// The request as it goes to the backend.
///
/// The path is the one the route rewrote it to — a route that pairs a
/// `path_pattern` with a `path_rewrite` serves the matched paths somewhere
/// else, and this is where that happens on the tunnel path. It used to happen
/// only on the plaintext path, so a rewrite looked configured and did nothing
/// for every real client.
///
/// The headers are the client's own, minus the ones that only meant something
/// for the hop from the client to here.
fn build_backend_request(
    req: &Request<()>,
    backend_info: &BackendInfo,
    body: &RequestBody,
) -> Result<Request<Full<bytes::Bytes>>, anyhow::Error> {
    // The origin was parsed when the pool was built, so this is a borrow of
    // it rather than a `Url::parse` per request.
    let origin: &str = match &backend_info.origin {
        Ok(origin) => origin,
        Err(reason) => return Err(anyhow::anyhow!("{}", reason)),
    };

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(req.uri().path());

    let rewritten_path = backend_info.rewritten_path(path);

    let new_uri = format!("{origin}{rewritten_path}")
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("Invalid URI: {}", e))?;

    let mut builder = Request::builder().method(req.method()).uri(new_uri);

    // A chunked body is sent as one buffer with a length of our own, so only a
    // request whose `content-length` we could not read takes that path. One we
    // could read is forwarded with the header it arrived with.
    let chunked = body.content_length.is_some();

    for (name, value) in req.headers() {
        // Preserve the client's original Host header so backend virtual-host
        // routing works. The body below is read whole and sent as one buffer,
        // so `transfer-encoding` and friends must not claim otherwise.
        if !forwards_request_header(name.as_str()) {
            continue;
        }
        // Dropped rather than overwritten: a second `content-length` on one
        // request is what lets a proxy and a backend disagree about where the
        // body ends, and an unreadable one is exactly the case that survives
        // the filter above.
        if chunked && name == "content-length" {
            continue;
        }
        builder = builder.header(name, value);
    }

    // The length the proxy declares for a body the client did not give one
    // for. The client's own `content-length` is dropped above, because this
    // one is the truth.
    if let Some(content_length) = body.content_length {
        builder = builder.header("content-length", content_length);
    }

    // The body is shared, not copied: the request that goes to the backend
    // takes a reference to the same bytes the retry would use, so a body is
    // in memory once however many attempts are made.
    Ok(builder.body(Full::new(body.bytes.clone()))?)
}

// One more argument than clippy allows: the alternative is a struct bundling the
// client with its deadlines, which every caller would have to build in order to
// pass the same two things — see the note on `conn::handle_bidi_stream`.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_to_backend_streaming(
    clients: &BackendClients,
    // How long the backend may take to answer. Not read off the client, because
    // it is not the client's: the client owns the deadline for every dial, this
    // is the one for a single answer. See `crate::config::Timeouts`.
    timeouts: crate::config::Timeouts,
    req: &Request<()>,
    // Where this request goes, and how it gets there. The route decided both:
    // the address, the protocol, and the rewrite the path goes through.
    //
    // This used to be the URL and the protocol as two separate arguments, with
    // the rewrite left out — which is how a route that named a `path_rewrite`
    // looked configured and did nothing here.
    backend_info: &BackendInfo,
    body: &RequestBody,
    send: &mut iroh::endpoint::SendStream,
    request_id: &str,
) -> Result<ProxySummary, ProxyFailure> {
    let client = clients.for_protocol(backend_info.protocol);

    let proxied_req = build_backend_request(req, backend_info, body)?;

    tracing::debug!(
        "Proxying request via client (streaming): {} {}",
        proxied_req.method(),
        proxied_req.uri()
    );

    // The same deadline `proxy_request` uses — one number for one thing. Without
    // it a backend that accepts the connection and then never sends a head keeps
    // this task, and the stream slot it holds, alive forever.
    let response_deadline = timeouts.response;
    let response = match tokio::time::timeout(response_deadline, client.request(proxied_req)).await
    {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            tracing::error!("Failed to send request: {:?}", e);
            // A connect error means the request was never carried: the
            // connection was refused, the name did not resolve, the handshake
            // failed. Anything else means the request went out and the answer
            // did not come, which only an idempotent request may be asked
            // twice. The tunnel path needs this exactly as the plaintext one
            // does, or `[retry]` would only work on one of them.
            let retry = if e.is_connect() {
                Retryability::Always
            } else {
                Retryability::IfIdempotent
            };
            return Err(ProxyFailure::unanswered(
                anyhow::anyhow!("failed to send request: {e:?}"),
                retry,
            ));
        }
        Err(_) => {
            return Err(ProxyFailure::unanswered(
                anyhow::anyhow!("backend did not respond within {:?}", response_deadline),
                // The request was carried: the deadline expired after it went
                // out.
                Retryability::IfIdempotent,
            ));
        }
    };

    let (parts, body) = response.into_parts();

    let status = parts.status;
    let status_text = status.canonical_reason().unwrap_or("Unknown");

    let mut response_buf = Vec::new();
    response_buf
        .extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status_text).as_bytes());

    // Whether the backend framed the body with a transfer coding of its own
    // that is not `chunked`. Such a body is still encoded when it arrives, and
    // the header that says so is dropped below, so it is not framed again
    // either.
    let other_transfer_coding = parts
        .headers
        .get("transfer-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|v| !v.to_lowercase().split(',').any(|c| c.trim() == "chunked"))
        .unwrap_or(false);
    let has_content_length = parts.headers.get("content-length").is_some();

    for (name, value) in parts.headers.iter() {
        // The name is **already** lower case: HTTP header names are
        // case-insensitive and the parser folds them, so this is a borrow and
        // not a copy. It used to be a `to_lowercase` per header, which is an
        // allocation for every header of every response.
        let name_lower = name.as_str();
        // A header that belongs to the hop between the backend and this
        // process does not belong on the hop between this process and the
        // client.
        if !forwards_response_header(name_lower) {
            continue;
        }
        // Dropped, not duplicated: the id we write below is the one our own
        // access log records, and a second one from the backend would leave
        // whoever reads the response guessing which to quote.
        if name_lower == "x-request-id" {
            continue;
        }
        response_buf.extend_from_slice(name.as_str().as_bytes());
        response_buf.extend_from_slice(b": ");
        response_buf.extend_from_slice(value.as_bytes());
        response_buf.extend_from_slice(b"\r\n");
    }

    // Whether the body is framed for the client, which is a question about
    // what the *client* can be told rather than about what the backend said.
    //
    // The client on the other end of the tunnel speaks HTTP/1.1, and HTTP/1.1
    // has no way to say "the body ends when this stream ends": a body with no
    // length has to be chunked, or the client waits for a connection close
    // that never comes. A backend that speaks HTTP/2 never sends a length at
    // all — the stream carries the end — so a response from an h2 backend is
    // exactly the case that has to be framed here. A backend that sent no
    // length over HTTP/1.1 means the same thing, and is framed the same way.
    //
    // A bodyless response has no body to frame. RFC 9110 §6.1 forbids a
    // `transfer-encoding` on a 204 or a 304, and a client told "chunked"
    // waits for the terminator of a body that is not there. A `HEAD` request
    // asks for the head of a response whose body is not sent, whatever the
    // status says — so it is not framed either.
    let status_allows_a_body = !status.is_informational()
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED;
    let use_chunked = status_allows_a_body
        && !has_content_length
        && !other_transfer_coding
        && *req.method() != Method::HEAD;
    if use_chunked {
        response_buf.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    // The id the caller gave this request, so a client can name the access log
    // line that goes with the answer it got. Built by hand like the rest of
    // this buffer: there is no `http::Response` here to hang a header on.
    response_buf.extend_from_slice(b"x-request-id: ");
    response_buf.extend_from_slice(request_id.as_bytes());
    response_buf.extend_from_slice(b"\r\n");
    response_buf.extend_from_slice(b"\r\n");

    // Counted once it is on the wire, not when it is formatted: `bytes_sent`
    // is what the access log reports as delivered, and a header that failed to
    // write reached nobody.
    let mut bytes_sent = 0;
    if let Err(e) = send.write_all(&response_buf).await {
        return Err(ProxyFailure::from(anyhow::anyhow!(
            "failed to write the response head: {e}"
        )));
    }
    bytes_sent += response_buf.len();

    // Body chunks used to go out as one `write_all` per hyper chunk (plus three more per
    // chunk when the response is chunk-encoded). Each of those turns into its own QUIC
    // STREAM frame, so a 64 KiB hyper chunk produced ~4 tiny frames instead of one. Coalesce
    // into a buffer and flush at 64 KiB: same latency profile for streamed responses, a
    // large drop in frame count and `SendStream` wakeups for bulk transfer.
    //
    // The header above is still written separately so that a slow producer
    // (SSE, long-poll) is not held back until 64 KiB accumulate.
    const RESPONSE_FLUSH_THRESHOLD: usize = 64 * 1024;
    // Started small rather than at the threshold: the threshold is a latency
    // bound, not an expected size, and most responses never come near it —
    // reserving it up front took 64 KiB from every streamed response, most of
    // which then went back unused. Growing costs the same few reallocs the
    // large responses would have paid anyway.
    const INITIAL_FLUSH_CAPACITY: usize = 8 * 1024;
    let mut out = Vec::with_capacity(INITIAL_FLUSH_CAPACITY);

    // Bytes the client has actually received, as opposed to `out`, which holds
    // what is being coalesced and may still be lost: a body that died half way
    // is reported as the half that arrived, not as the whole that was intended.
    let mut body_stream = http_body_util::BodyExt::into_data_stream(body);
    // Idle, not a phase deadline: see `Deadlines::response_idle`. What is being
    // bounded is the gap between chunks, so this re-arms on every chunk — which
    // is what lets an SSE stream or a WebSocket stay open for as long as both
    // ends want, while a backend that accepted the request and then went silent
    // cannot hold this slot and its backend lease forever. The value comes from
    // `[timeouts] response_idle_secs` through the `timeouts` argument.
    let response_idle = timeouts.deadlines.response_idle;
    loop {
        // A `loop` rather than `while let`: the three outcomes — a chunk, the
        // end of the body, and the backend going quiet — are told apart here,
        // and only the first two are ordinary iteration.
        let chunk = match tokio::time::timeout(response_idle, body_stream.next()).await {
            Ok(Some(chunk)) => chunk,
            // The body finished: this is the end, not a failure, and it must not
            // be mistaken for one.
            Ok(None) => break,
            Err(_) => {
                // The backend went quiet mid-body, which is a failure and not an
                // end: returning here rather than breaking out is what keeps the
                // two apart. Breaking would fall through to the chunked
                // terminator and `send.finish()` below, and the client would
                // get a body that is syntactically complete and silently
                // truncated — a truncated stream it has no way to tell from a
                // whole one, and an access line recording a success.
                //
                // `bytes_sent` is what the client actually received, so it is
                // still reported rather than zero.
                tracing::warn!(
                    "Backend sent nothing for {response_idle:?} mid-body, ending the stream \
                     after {bytes_sent} bytes"
                );
                return Err(ProxyFailure::after(
                    status,
                    bytes_sent,
                    anyhow::anyhow!("backend sent nothing for {response_idle:?} mid-body"),
                ));
            }
        };
        match chunk {
            Ok(data) => {
                if use_chunked {
                    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
                    out.extend_from_slice(&data);
                    out.extend_from_slice(b"\r\n");
                } else {
                    out.extend_from_slice(&data);
                }
                if out.len() >= RESPONSE_FLUSH_THRESHOLD {
                    if let Err(e) = send.write_all(&out).await {
                        return Err(ProxyFailure::after(status, bytes_sent, e.into()));
                    }
                    bytes_sent += out.len();
                    out.clear();
                }
            }
            Err(e) => {
                tracing::debug!("Streaming response read error: {}", e);
                return Err(ProxyFailure::after(status, bytes_sent, e.into()));
            }
        }
    }

    if use_chunked {
        out.extend_from_slice(b"0\r\n\r\n");
    }
    if !out.is_empty() {
        if let Err(e) = send.write_all(&out).await {
            return Err(ProxyFailure::after(status, bytes_sent, e.into()));
        }
        bytes_sent += out.len();
    }

    if let Err(e) = send.finish() {
        return Err(ProxyFailure::after(status, bytes_sent, e.into()));
    }

    Ok(ProxySummary {
        status: status.as_u16(),
        bytes_sent,
    })
}

/// The longest line a chunk header may be.
///
/// A chunk size is a hex number with optional extensions, so anything past a
/// few dozen bytes is malformed; the cap keeps a stream that never sends a
/// CRLF from growing this buffer without bound.
const MAX_CHUNK_HEADER: usize = 1024;

/// How many bytes of a chunked body `input` decodes on its own.
///
/// Returns the decoded bytes, how much of `input` was used up, and whether the
/// terminating zero chunk was seen. Bytes belonging to an incomplete chunk are
/// *not* reported as used: the caller keeps them and hands them back with
/// whatever it reads next. `limit` is how much body is still allowed.
fn decode_chunks(input: &[u8], limit: usize) -> Result<(Vec<u8>, usize, bool), anyhow::Error> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut used = 0usize;

    loop {
        let Some(rel) = input[pos..].windows(2).position(|w| w == b"\r\n") else {
            // Still waiting for the line, which is normal while the header is
            // arriving — but only for so long. Without this the caller keeps
            // appending every read to its buffer, and a peer that never sends
            // a CRLF grows it without bound.
            if input.len() - pos > MAX_CHUNK_HEADER {
                return Err(anyhow::anyhow!(
                    "chunk header longer than {MAX_CHUNK_HEADER} bytes"
                ));
            }
            return Ok((out, used, false));
        };
        if rel > MAX_CHUNK_HEADER {
            return Err(anyhow::anyhow!(
                "chunk header longer than {MAX_CHUNK_HEADER} bytes"
            ));
        }

        let size = parse_chunk_size(&input[pos..pos + rel])?;
        let after_header = pos + rel + 2;

        // The zero chunk ends the body. What follows is the trailer section,
        // which is not forwarded: an empty one (the usual case) is consumed so
        // the stream is left clean, and a real one is left untouched — this
        // request owns the stream, so there is nothing after it to keep in
        // step with.
        if size == 0 {
            let done = input.len() >= after_header + 2
                && &input[after_header..after_header + 2] == b"\r\n";
            return Ok((
                out,
                if done { after_header + 2 } else { after_header },
                true,
            ));
        }

        // Neither check may add: `size` comes from the client and
        // `usize::from_str_radix` accepts values near `usize::MAX`, so
        // `out.len() + size` and `size + 2` overflow — a panic in a debug
        // build, and in release a bound that wraps and then lets the slice
        // below run off the end.
        if size > limit || out.len() > limit - size {
            return Err(anyhow::anyhow!(
                "chunked request body is over the {limit} byte limit"
            ));
        }
        // What is left after the header, so "is there a whole chunk here" is a
        // subtraction of two lengths instead of an addition that can wrap.
        let remaining = input.len() - after_header;
        if remaining < size || remaining - size < 2 {
            return Ok((out, used, false));
        }

        out.extend_from_slice(&input[after_header..after_header + size]);
        if &input[after_header + size..after_header + size + 2] != b"\r\n" {
            return Err(anyhow::anyhow!("chunk data is not followed by CRLF"));
        }

        pos = after_header + size + 2;
        used = pos;
    }
}

/// The size a chunk header declares, in bytes.
fn parse_chunk_size(header: &[u8]) -> Result<usize, anyhow::Error> {
    let text = std::str::from_utf8(header)
        .map_err(|_| anyhow::anyhow!("chunk header is not valid UTF-8"))?;
    let digits = text.split(';').next().unwrap_or("").trim();
    if digits.is_empty() {
        return Err(anyhow::anyhow!("chunk header declares no size"));
    }
    usize::from_str_radix(digits, 16)
        .map_err(|_| anyhow::anyhow!("{digits:?} is not a hexadecimal chunk size"))
}

/// Reads a chunked request body off an iroh stream, leaving the de-chunked
/// bytes in `body`.
///
/// Whatever arrived with the head is already the start of the chunk stream, so
/// it is handed to the decoder first and only then is more read.
///
/// A chunked body declares no length, so the reservation grows as the bytes
/// arrive rather than being taken up front — there is no honest moment at which
/// this knows how much it wants. Returns the reservation, which the caller keeps
/// for the lifetime of the body.
///
/// Generic over the reader so the accounting can be tested without an endpoint;
/// callers pass an iroh receive stream. The budget is a parameter for the same
/// reason: the accounting is only observable against a budget of the test's
/// own, because the process-wide one is shared with every other test in this
/// binary.
async fn read_chunked_request_body<R>(
    recv: &mut R,
    body: &mut Vec<u8>,
    body_deadline: std::time::Duration,
    budget: &std::sync::Arc<crate::conn::limits::ByteBudget>,
) -> Result<crate::conn::limits::ByteReservation, anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut pending = std::mem::take(body);
    let mut buf = [0u8; 8192];
    // The bytes that came with the head are the beginning of the chunk stream,
    // so they are held the same way the rest of it is: charged while they wait
    // to be decoded.
    let mut reservation = crate::conn::limits::ByteReservation::take_from(budget, pending.len())?;

    // A phase deadline, not a per-read one: a peer sending one chunk before
    // each expiry renews a per-read bound forever, and this holds a stream slot
    // for as long as it keeps doing so. The value comes from
    // `[timeouts] body_secs` through the caller.
    let deadline_at = tokio::time::Instant::now() + body_deadline;

    loop {
        let (decoded, used, complete) =
            decode_chunks(&pending, MAX_REQUEST_BODY.saturating_sub(body.len()))?;
        // The framing of the chunks that just decoded is gone: only the
        // payload is left, and it was already charged as part of the raw bytes
        // it came from. So the difference goes back to the budget, and the
        // reservation keeps meaning "the bytes held right now" — the raw
        // bytes still waiting for their chunk, plus the body decoded so far.
        reservation.shrink(used.saturating_sub(decoded.len()));
        body.extend_from_slice(&decoded);
        pending.drain(..used);
        if complete {
            // Whatever is left in `pending` is the trailer section, which is
            // not forwarded and is dropped with this function. Those bytes are
            // given back rather than counted for as long as the body lives.
            reservation.shrink(pending.len());
            return Ok(reservation);
        }

        let n = match tokio::time::timeout_at(deadline_at, recv.read(&mut buf)).await {
            Ok(result) => result
                .map_err(|e| anyhow::anyhow!("failed to read request body from iroh: {}", e))?,
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "chunked request body did not finish within {}s",
                    body_deadline.as_secs()
                ));
            }
        };
        // A read of zero is the end of the stream: the peer stopped before the
        // terminating chunk, so the body is truncated.
        if n == 0 {
            return Err(anyhow::anyhow!(
                "chunked request body ended before its terminating chunk"
            ));
        }
        // The raw bytes are held while they wait for their chunk to complete,
        // so they are charged while they are held. A peer that declares a
        // 64 MiB chunk and then trickles the data into it holds those bytes
        // for as long as it takes, and the budget has to see them: it is the
        // difference between "this process holds 64 MiB" and "this process
        // holds nothing", and the budget is about the first one.
        reservation.grow(n)?;
        pending.extend_from_slice(&buf[..n]);
    }
}

/// Whether the request body is framed as chunks.
fn request_is_chunked(req: &Request<()>) -> bool {
    req.headers()
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_lowercase().contains("chunked"))
}

/// Generic over the reader so the caps below can be tested without an endpoint;
/// callers pass an iroh receive stream.
///
/// Returns the reservation for the bytes it read, and the caller has to keep it
/// for as long as the body is alive — see `read_body_limited`, which does the
/// same on the plaintext path.
///
/// The reservation tracks what is **buffered**, not what is declared. Those are
/// different numbers and the gap between them is the whole design: a peer
/// decides `content-length`, and this process decides how much memory it is
/// willing to hold. Reserving the declared size up front reads well and is
/// wrong — sixteen streams that declare 64 MiB and then send nothing hold the
/// entire 1 GiB budget for five minutes, refusing every honest upload while none
/// of them has a byte in memory. Growing per frame means the budget is always
/// counting real bytes, whether they came with the head or off the wire.
async fn read_remaining_request_body<R>(
    recv: &mut R,
    body: &mut Vec<u8>,
    content_length: usize,
    body_deadline: std::time::Duration,
) -> Result<crate::conn::limits::ByteReservation, anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut remaining = content_length.saturating_sub(body.len());
    let mut buf = [0u8; 8192];

    // What arrived with the head is buffered already — QUIC is a byte stream, so
    // a peer decides how much body rides along with them — and it is charged
    // before any read. `body.len()` and not `min(content_length)`: a peer may
    // overstate or understate its own length, and this path does not discard the
    // excess, so every byte here is memory the process is holding.
    let mut reservation = crate::conn::limits::ByteReservation::take(body.len())?;

    // A deadline over the whole read rather than per read. An idle cap is still
    // wanted for a slow but progressing upload, but on its own it re-arms on
    // every byte, which is exactly what a peer dripping one byte before each
    // expiry wants — and it is not a cap this path can enforce any more, since
    // `REQUEST_BODY_READ_TIMEOUT` is gone. The value comes from
    // `[timeouts] body_secs` through the caller.
    let deadline_at = tokio::time::Instant::now() + body_deadline;

    while remaining > 0 {
        let read = match tokio::time::timeout_at(deadline_at, recv.read(&mut buf)).await {
            Ok(result) => result
                .map_err(|e| anyhow::anyhow!("failed to read request body from iroh: {}", e))?,
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "request body did not finish within {}s: {} of {} bytes arrived",
                    body_deadline.as_secs(),
                    body.len(),
                    content_length
                ));
            }
        };
        // Zero is the reader's end of stream, which is an iroh `None` on the
        // concrete receive stream: the peer gave up before the declared length.
        if read == 0 {
            return Err(anyhow::anyhow!(
                "request body ended before content-length: expected {} bytes, got {}",
                content_length,
                body.len()
            ));
        }

        let take = read.min(remaining);
        // Before the append, so a refused reservation leaves the buffer and the
        // budget agreeing about what is held: `grow` does not accumulate when it
        // refuses, and the `?` drops the reservation on the way out.
        reservation.grow(take)?;
        body.extend_from_slice(&buf[..take]);
        remaining -= take;
    }

    tracing::debug!(
        "Read request body from iroh: {} bytes (content-length {})",
        body.len(),
        content_length
    );
    Ok(reservation)
}

pub fn parse_http_response_legacy(response: &[u8]) -> Result<Response<Vec<u8>>, anyhow::Error> {
    // The end of the header block is looked for in the bytes, never measured
    // off a decoded string: `from_utf8_lossy` turns each invalid byte into
    // U+FFFD, which is three bytes in UTF-8, so every offset computed from the
    // decoded text drifts by two per bad byte and the body started — or ended
    // — in the wrong place. A header with a single non-UTF-8 byte was enough
    // to hand the caller a body sliced out of the middle of the headers.
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response: no end of headers"))?;
    let body_start = header_end + 4;

    // Only the head is decoded, so nothing below can produce an offset again.
    let head = String::from_utf8_lossy(&response[..header_end]);
    let mut lines = head.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response: missing status line"))?;

    let status_parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code = if status_parts.len() >= 2 {
        status_parts[1]
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid status code: {}", e))?
    } else {
        500
    };

    let mut builder = Response::builder().status(status_code);

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    let body = response[body_start..].to_vec();

    Ok(builder.body(body)?)
}

/// Whether the request names more than one host.
///
/// RFC 9110 §7.2: *"A server MUST respond with a 400 (Bad Request) status code
/// to any HTTP/1.1 request message that contains more than one Host header
/// field."*
///
/// This is not pedantry. A request with two `Host` headers is a request whose
/// destination is ambiguous, and the two halves of this proxy used to resolve
/// that ambiguity differently: the route and the access check read the **first**
/// one, and the backend was handed **both**. A client that was allowed for
/// `allowed.example.com` could therefore send that name first and a second
/// name behind it, and a backend that picks the last one would serve the
/// second name's vhost to a request that was authorised for the first.
///
/// Neither of the two listeners this server has can lean on its HTTP parser to
/// catch it: the plaintext one uses hyper, which accepts two `Host` headers
/// and passes them both on, and the tunnel one parses the head by hand. So
/// both check here, and both answer 400.
pub fn names_more_than_one_host(headers: &::http::HeaderMap) -> bool {
    headers.get_all("host").iter().count() > 1
}

/// The request as it arrived, parsed out of the bytes.
///
/// The head only, because the body is read separately and this is the only
/// place the head exists as bytes.
///
/// A request that names more than one host is refused here rather than
/// downstream: the route and the access check read the first `Host` header,
/// and the backend would be handed all of them, so the request that is
/// authorised and the request that is served would be two different requests.
/// See [`names_more_than_one_host`].
pub fn parse_http_request_legacy(buf: &[u8]) -> Result<Request<()>, anyhow::Error> {
    let request_str = String::from_utf8_lossy(buf);
    let mut lines = request_str.split("\r\n");

    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP request: missing request line"))?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("invalid HTTP request line"));
    }

    let method = http::Method::from_bytes(parts[0].as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid HTTP method: {}", e))?;
    let uri = http::Uri::try_from(parts[1]).map_err(|e| anyhow::anyhow!("invalid URI: {}", e))?;

    let mut builder = Request::builder().method(method).uri(uri);
    let mut hosts = 0usize;

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("host") {
                hosts += 1;
                if hosts > 1 {
                    return Err(anyhow::anyhow!(
                        "the request carries more than one Host header"
                    ));
                }
            }
            builder = builder.header(name, value.trim());
        }
    }

    Ok(builder.body(())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deadline::Deadlines;

    /// A reason is capitalised for the path that said it that way.
    ///
    /// The backend's address can fail in two ways, and the two paths that
    /// report it word it differently: the plaintext path says "Invalid
    /// backend URL" and the tunnel path says "invalid backend URL". Both are
    /// the same reason, and the operator reads both.
    #[test]
    fn a_reason_keeps_the_wording_of_the_path_that_says_it() {
        assert_eq!(
            capitalised("invalid backend URL: relative URL without a base"),
            "Invalid backend URL: relative URL without a base"
        );
        assert_eq!(
            capitalised("backend URL missing host"),
            "Backend URL missing host"
        );
        // A message that is already capitalised is left alone.
        assert_eq!(
            capitalised("Backend URL missing host"),
            "Backend URL missing host"
        );
        // And an empty one stays empty rather than panicking.
        assert_eq!(capitalised(""), "");
    }

    /// A request that names more than one host is refused.
    ///
    /// The route and the access check read the **first** `Host` header and the
    /// backend was handed **all** of them, so a request that was authorised for
    /// one host could be served as another. RFC 9110 §7.2 asks for a 400.
    #[test]
    fn a_request_with_more_than_one_host_is_refused() {
        let head = b"GET /x HTTP/1.1\r\nHost: allowed.example\r\nHost: internal.example\r\n\r\n";
        let err = parse_http_request_legacy(head).expect_err("two hosts are not one host");
        assert!(
            err.to_string().contains("more than one Host"),
            "the refusal does not say why: {err}"
        );
    }

    /// One host is one host.
    #[test]
    fn a_request_with_one_host_is_accepted() {
        let head = b"GET /x HTTP/1.1\r\nHost: allowed.example\r\n\r\n";
        let request = parse_http_request_legacy(head).expect("one host is fine");
        assert_eq!(request.headers().get("host").unwrap(), "allowed.example");
    }

    /// The check the plaintext listener uses, on the headers hyper hands it.
    ///
    /// hyper accepts two `Host` headers and passes both on, so the plaintext
    /// path has to make this check itself.
    #[test]
    fn the_host_count_is_seen_in_the_headers() {
        let mut headers = ::http::HeaderMap::new();
        assert!(
            !names_more_than_one_host(&headers),
            "no host is not two hosts"
        );

        headers.append("host", "a.example".parse().unwrap());
        assert!(
            !names_more_than_one_host(&headers),
            "one host is not two hosts"
        );

        headers.append("host", "b.example".parse().unwrap());
        assert!(
            names_more_than_one_host(&headers),
            "two hosts are two hosts"
        );
    }

    /// A body of `len` bytes, which is what the limit has to be checked against.
    fn body_of(len: usize) -> Full<bytes::Bytes> {
        Full::new(bytes::Bytes::from(vec![b'x'; len]))
    }

    /// `read_remaining_request_body` with the default `[timeouts]` body budget:
    /// what these tests exercise is the cap and the reservation, not the
    /// configured length of the deadline.
    async fn read_body<R>(
        recv: &mut R,
        body: &mut Vec<u8>,
        content_length: usize,
    ) -> Result<crate::conn::limits::ByteReservation, anyhow::Error>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        read_remaining_request_body(recv, body, content_length, Deadlines::default().body).await
    }

    #[tokio::test]
    async fn a_body_within_the_limit_is_read_whole() {
        let (read, reservation) = read_body_limited(body_of(10), 10, Deadlines::default().body)
            .await
            .unwrap();
        assert_eq!(read.len(), 10);
        assert_eq!(reservation.bytes(), 10, "the body is held for its lifetime");
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused() {
        // One frame is enough to exceed it, so this is the case the old
        // `collect()` could not catch without first holding all of it.
        let err = read_body_limited(body_of(11), 10, Deadlines::default().body)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("over the 10 byte limit"));
    }

    #[tokio::test]
    async fn an_empty_body_is_within_any_limit() {
        let (read, reservation) = read_body_limited(body_of(0), 0, Deadlines::default().body)
            .await
            .unwrap();
        assert!(read.is_empty());
        assert_eq!(reservation.bytes(), 0);
    }

    #[tokio::test]
    async fn a_refused_body_hands_its_reservation_back() {
        // Asserted through the reservation this call returns rather than by
        // reading the process-wide total: that total is shared with every other
        // test in this binary, which run concurrently, so a "same as before"
        // comparison here would mostly be measuring the other tests.
        //
        // What this pins is that the per-request limit refuses *before* anything
        // is reserved, so there is nothing to leak. The direct statement about
        // the budget's own arithmetic is `ByteBudget::bodies_are_bounded_across_the_process`.
        let refused = read_body_limited(body_of(4096), 16, Deadlines::default().body).await;
        assert!(refused.is_err(), "a body over the limit must be refused");
    }

    /// A chunked body of one or more `chunks`, terminated the usual way.
    fn chunked(chunks: &[&str]) -> Vec<u8> {
        let mut raw = Vec::new();
        for chunk in chunks {
            raw.extend_from_slice(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes());
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        raw
    }

    #[test]
    fn a_chunked_body_is_decoded_whole() {
        let raw = chunked(&["hello", " world"]);
        let (body, used, complete) = decode_chunks(&raw, 1024).unwrap();
        assert_eq!(body, b"hello world");
        assert!(complete);
        assert_eq!(used, raw.len());
    }

    #[test]
    fn a_chunk_header_may_carry_extensions() {
        let raw = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        let (body, _, complete) = decode_chunks(raw, 1024).unwrap();
        assert_eq!(body, b"hello");
        assert!(complete);
    }

    #[test]
    fn an_incomplete_chunk_is_left_for_the_next_read() {
        // What a stream split mid-chunk looks like: the reader must keep the
        // bytes it could not decode and hand them back with the next read.
        let raw = chunked(&["hello", " world"]);
        // Three bytes into the second chunk's data: its header arrived, the
        // payload did not.
        let split = 16;

        let (first, used, complete) = decode_chunks(&raw[..split], 1024).unwrap();
        assert_eq!(first, b"hello");
        assert!(!complete);
        assert!(used < split);

        let mut pending = raw[used..split].to_vec();
        pending.extend_from_slice(&raw[split..]);
        let (body, _, complete) = decode_chunks(&pending, 1024).unwrap();
        assert_eq!(body, b" world");
        assert!(complete);
    }

    #[test]
    fn the_body_ends_at_the_zero_chunk() {
        // Trailers are not forwarded, so they must not be swallowed either:
        // anything after the zero chunk is not part of what was decoded.
        let mut raw = chunked(&["hello"]);
        raw.extend_from_slice(b"X-Trailer: done\r\n\r\n");
        let (body, used, complete) = decode_chunks(&raw, 1024).unwrap();
        assert_eq!(body, b"hello");
        assert!(complete);
        assert_eq!(&raw[used..], b"X-Trailer: done\r\n\r\n");
    }

    #[test]
    fn a_chunked_body_over_the_limit_is_refused() {
        let raw = chunked(&["hello"]);
        let err = decode_chunks(&raw, 4).unwrap_err();
        assert!(err.to_string().contains("over the 4 byte limit"));
    }

    /// Hands out the pieces it was given, and records what the budget held
    /// each time it was asked for more.
    ///
    /// The samples are the point: they are the moments *between* reads, which
    /// is when the bytes that have arrived but have not decoded yet are held.
    struct SamplingReader {
        pieces: std::collections::VecDeque<Vec<u8>>,
        budget: std::sync::Arc<crate::conn::limits::ByteBudget>,
        samples: Vec<usize>,
    }

    impl SamplingReader {
        fn new(budget: &std::sync::Arc<crate::conn::limits::ByteBudget>, pieces: &[&[u8]]) -> Self {
            Self {
                pieces: pieces.iter().map(|p| p.to_vec()).collect(),
                budget: budget.clone(),
                samples: Vec::new(),
            }
        }
    }

    impl tokio::io::AsyncRead for SamplingReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let held = self.budget.held();
            self.samples.push(held);
            match self.pieces.pop_front() {
                Some(chunk) => {
                    buf.put_slice(&chunk);
                    std::task::Poll::Ready(Ok(()))
                }
                None => std::task::Poll::Ready(Ok(())),
            }
        }
    }

    /// `read_chunked_request_body` against a budget of the test's own.
    ///
    /// The process-wide one is shared with every other test in this binary,
    /// which run concurrently, so a total read from it would mostly be
    /// measuring the other tests.
    async fn read_chunked<R>(
        recv: &mut R,
        body: &mut Vec<u8>,
        budget: &std::sync::Arc<crate::conn::limits::ByteBudget>,
    ) -> Result<crate::conn::limits::ByteReservation, anyhow::Error>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        read_chunked_request_body(recv, body, Deadlines::default().body, budget).await
    }

    /// A chunked body is charged for the bytes that are still in flight.
    ///
    /// The bytes of a chunk that has not decoded yet are held: the peer sent
    /// them and the process has them in memory. It used to charge only what a
    /// chunk decoded, which left every byte of an unfinished chunk outside
    /// the budget — a peer that declares a 64 MiB chunk and then trickles the
    /// data into it was invisible to the ceiling.
    #[tokio::test(start_paused = true)]
    async fn a_chunked_body_charges_the_bytes_that_are_still_in_flight() {
        let budget = std::sync::Arc::new(crate::conn::limits::ByteBudget::new(1024 * 1024));
        // A chunk header and the first two bytes of its data: the chunk
        // cannot decode yet, so these five bytes wait for the rest of it.
        let mut reader = SamplingReader::new(&budget, &[b"5\r\nhe", b"llo\r\n", b"0\r\n\r\n"]);
        let mut body = Vec::new();

        let reservation = read_chunked(&mut reader, &mut body, &budget)
            .await
            .expect("the body is read");

        assert_eq!(body, b"hello");
        assert_eq!(
            reader.samples,
            vec![0, 5, 5],
            "the five bytes of the unfinished chunk are charged while they wait, and the \
             framing of the decoded one is given back"
        );

        // And the accounting ends where it should: the decoded body is held
        // and nothing else — the framing is gone and the terminator was never
        // part of the body.
        assert_eq!(reservation.bytes(), body.len());
        assert_eq!(budget.held(), reservation.bytes());

        drop(reservation);
        assert_eq!(
            budget.held(),
            0,
            "a dropped reservation gives its bytes back"
        );
    }

    /// A chunked body that outgrows the budget is refused while it arrives.
    #[tokio::test(start_paused = true)]
    async fn a_chunked_body_that_outgrows_the_budget_is_refused() {
        let budget = std::sync::Arc::new(crate::conn::limits::ByteBudget::new(8));
        let mut reader = SamplingReader::new(&budget, &[b"5\r\nhello\r\n0\r\n\r\n"]);
        let mut body = Vec::new();

        let err = read_chunked(&mut reader, &mut body, &budget)
            .await
            .expect_err("the body does not fit");

        assert!(err.to_string().contains("does not fit"), "{err}");
        assert_eq!(
            budget.held(),
            0,
            "a refused body hands its reservation back"
        );
    }

    /// The trailer of a chunked body is not held.
    ///
    /// It is not forwarded and it is dropped with the read, so the budget must
    /// not keep counting it for as long as the body lives.
    #[tokio::test(start_paused = true)]
    async fn a_chunked_body_holds_its_body_and_nothing_else() {
        let budget = std::sync::Arc::new(crate::conn::limits::ByteBudget::new(1024 * 1024));
        let mut reader = SamplingReader::new(
            &budget,
            &[b"5\r\nhello\r\n0\r\n\r\nX-Trailer: done\r\n\r\n"],
        );
        let mut body = Vec::new();

        let reservation = read_chunked(&mut reader, &mut body, &budget)
            .await
            .expect("the body is read");

        assert_eq!(body, b"hello");
        assert_eq!(
            reservation.bytes(),
            5,
            "the trailer is not part of the body"
        );
        assert_eq!(
            budget.held(),
            5,
            "and it is not held for the body's lifetime"
        );
    }

    #[test]
    fn a_chunk_size_that_would_overflow_is_refused() {
        // `usize::MAX`, spelled as a chunk size: the old `out.len() + size`
        // wrapped to a small number in release and panicked in debug, so the
        // limit looked satisfied and the slice below ran off the end.
        let err = decode_chunks(b"ffffffffffffffff\r\nhello\r\n", 1024).unwrap_err();
        assert!(err.to_string().contains("over the 1024 byte limit"));

        // Same for the `size + 2` that checked for the trailing CRLF.
        let err = decode_chunks(b"ffffffffffffffff\r\nhello", 1024).unwrap_err();
        assert!(err.to_string().contains("over the 1024 byte limit"));
    }

    #[test]
    fn a_chunk_header_that_never_ends_is_refused() {
        // No CRLF anywhere, so the caller would keep buffering: a peer that
        // sends a header and never terminates it grows it without bound.
        let mut raw = Vec::new();
        raw.extend_from_slice(&b"5;".repeat(MAX_CHUNK_HEADER));
        let err = decode_chunks(&raw, 1024).unwrap_err();
        assert!(err.to_string().contains("chunk header longer than"));

        // A short header that is still arriving is fine — it is not an error
        // to be waiting for the rest of one.
        let (body, used, complete) = decode_chunks(b"5\r", 1024).unwrap();
        assert!(body.is_empty());
        assert_eq!(used, 0);
        assert!(!complete);
    }

    #[test]
    fn a_chunk_header_that_is_not_hexadecimal_is_refused() {
        let err = decode_chunks(b"zz\r\nhello\r\n0\r\n\r\n", 1024).unwrap_err();
        assert!(err.to_string().contains("not a hexadecimal chunk size"));
    }

    #[test]
    fn chunk_data_without_its_crlf_is_refused() {
        let err = decode_chunks(b"5\r\nhelloXX\r\n0\r\n\r\n", 1024).unwrap_err();
        assert!(err.to_string().contains("not followed by CRLF"));
    }

    #[test]
    fn a_chunked_request_is_recognised_by_its_encoding() {
        let chunked_req = Request::builder()
            .header("transfer-encoding", "Chunked")
            .body(())
            .unwrap();
        assert!(request_is_chunked(&chunked_req));

        let plain = Request::builder()
            .header("transfer-encoding", "gzip")
            .body(())
            .unwrap();
        assert!(!request_is_chunked(&plain));
        assert!(!request_is_chunked(&Request::builder().body(()).unwrap()));
    }

    #[test]
    fn legacy_request_parser_keeps_the_request_line_and_headers() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: app.example.com\r\nX-Empty:\r\n\r\n";
        let req = parse_http_request_legacy(raw).unwrap();

        assert_eq!(req.method(), http::Method::GET);
        assert_eq!(req.uri().path(), "/index.html");
        assert_eq!(req.headers()["host"], "app.example.com");
        // A header with no value is still a header.
        assert_eq!(req.headers()["x-empty"], "");
    }

    #[test]
    fn legacy_request_parser_stops_at_the_blank_line() {
        let raw = b"POST /api HTTP/1.1\r\nHost: a\r\n\r\nnot-a-header";
        let req = parse_http_request_legacy(raw).unwrap();

        assert_eq!(req.method(), http::Method::POST);
        assert_eq!(req.headers().len(), 1);
    }

    #[test]
    fn legacy_request_parser_rejects_a_request_line_without_a_target() {
        assert!(parse_http_request_legacy(b"GET\r\nHost: a\r\n\r\n").is_err());
    }

    #[test]
    fn legacy_response_parser_splits_status_headers_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello";
        let res = parse_http_response_legacy(raw).unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["content-type"], "text/plain");
        assert_eq!(res.body().as_slice(), b"hello".as_slice());
    }

    #[test]
    fn legacy_response_parser_leaves_no_body_when_there_is_none() {
        let res = parse_http_response_legacy(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();

        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(res.body().is_empty());
    }

    #[test]
    fn legacy_response_parser_falls_back_to_500_without_a_status_code() {
        let res = parse_http_response_legacy(b"HTTP/1.1\r\n\r\n").unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(res.body().is_empty());
    }

    /// What the offset arithmetic used to get wrong: `from_utf8_lossy` turns
    /// one invalid byte into a three-byte U+FFFD, so a header carrying binary
    /// data shifted `body_start` and the body came out of the middle of the
    /// headers — or was empty.
    #[test]
    fn legacy_response_parser_finds_the_body_behind_a_non_utf8_header() {
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Binary: ".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(b"\r\n\r\nbody-bytes");

        let res = parse_http_response_legacy(&raw).unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.body().as_slice(), b"body-bytes".as_slice());
    }

    #[test]
    fn legacy_response_parser_rejects_a_response_with_no_end_of_headers() {
        // Truncated: there is no place where the body could start, and
        // guessing one used to be how it silently returned an empty body.
        assert!(parse_http_response_legacy(b"HTTP/1.1 200 OK\r\nX-A: 1\r\n").is_err());
    }

    #[test]
    fn hop_by_hop_headers_do_not_reach_the_backend() {
        for dropped in [
            "connection",
            "Proxy-Connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "expect",
            // A credential for this proxy: forwarding it hands it to a
            // third-party server.
            "proxy-authorization",
            "Proxy-Authorization",
            "proxy-authenticate",
        ] {
            assert!(
                !forwards_request_header(dropped),
                "{dropped} belongs to this hop only"
            );
        }
        for kept in ["host", "accept", "content-length", "sec-websocket-key"] {
            assert!(forwards_request_header(kept), "{kept} is the message's own");
        }
    }

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

        /// Queues `total` bytes as `piece`-sized chunks.
        ///
        /// For a body too large to hand over as one slice — the reader's own
        /// buffer is 8 KiB, so a single larger chunk is a test bug rather than a
        /// large body.
        fn feed(&mut self, piece: usize, total: usize) -> &mut Self {
            let piece = piece.max(1);
            let mut left = total;
            while left > 0 {
                let n = piece.min(left);
                self.chunks.push_back(vec![b'x'; n]);
                left -= n;
            }
            self
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

    /// The clock is paused, so the deadline is reached without the test waiting
    /// for it: what is being checked is that there is a bound at all.
    #[tokio::test(start_paused = true)]
    async fn a_declared_body_that_stops_arriving_is_given_up_on() {
        let mut reader = ScriptedReader::pieces(&[b"a-few-bytes"], false);
        let mut body = Vec::new();

        let err = read_body(&mut reader, &mut body, 64).await.unwrap_err();

        assert!(err.to_string().contains("did not finish within"), "{err}");
        assert_eq!(body, b"a-few-bytes");
    }

    /// The reservation a declared body takes is given back when the read fails,
    /// so one stalled upload does not permanently shrink the process budget for
    /// every other request behind it.
    ///
    /// Asserted by asking for a body twice and requiring both to be admitted,
    /// rather than by watching the process-wide total: that total is shared with
    /// every other test in this binary, which run concurrently, so a "same as
    /// before" comparison here would mostly be measuring the other tests.
    #[tokio::test(start_paused = true)]
    async fn a_declared_body_that_never_arrives_returns_its_reservation() {
        const DECLARED: usize = 4096;

        // The first read holds a reservation and then fails on the deadline: it
        // was told 4096 bytes and never got them.
        let mut stalled = ScriptedReader::pieces(&[b"a-few-bytes"], false);
        let mut stalled_body = Vec::new();
        assert!(
            read_body(&mut stalled, &mut stalled_body, DECLARED)
                .await
                .is_err(),
            "the read must not succeed"
        );

        // The second is a body that actually arrives, and it is admitted at the
        // same declared size. Had the first leaked its reservation, this would
        // be competing with it for the same budget rather than starting clean.
        let mut complete = ScriptedReader::pieces(&[&vec![b'x'; DECLARED]], true);
        let mut complete_body = Vec::new();
        read_body(&mut complete, &mut complete_body, DECLARED)
            .await
            .expect("the budget took the same size back");
        assert_eq!(complete_body.len(), DECLARED);
    }

    /// Bytes that arrived with the head are charged to the budget even though this
    /// function never reads a byte for them.
    ///
    /// QUIC is a byte stream, so how much body rides along with the head is the
    /// peer's choice — the head loop can hand this function a buffer already
    /// holding the whole body. Those bytes are held and are going to the
    /// backend, so a reservation of `remaining` alone (which is zero here)
    /// would leave the entire body uncounted on every stream a peer chose to
    /// send in one segment.
    #[tokio::test(start_paused = true)]
    async fn bytes_that_arrived_with_the_head_are_charged_too() {
        const DECLARED: usize = 8192;

        // The peer sent head and body in one segment: the buffer holds all
        // `DECLARED` bytes, so `remaining` is zero and a reservation of
        // `remaining` takes nothing at all. The body is still forwarded.
        let mut reader = ScriptedReader::pieces(&[], true);
        let mut body = vec![b'x'; DECLARED];

        let reservation = read_body(&mut reader, &mut body, DECLARED)
            .await
            .expect("a declared size inside the budget is admitted");
        assert_eq!(body.len(), DECLARED);
        assert!(
            reservation.bytes() >= DECLARED,
            "the {} bytes already in the buffer were charged {}",
            DECLARED,
            reservation.bytes()
        );
    }

    /// The reservation is the bytes this reader is holding, which is not the
    /// declared length and not the bytes still owed.
    ///
    /// Observable directly because the read succeeds: the head carried more body
    /// than the header declared, so nothing is left to read and the reservation
    /// is returned intact. A reservation of the declared length would report 4
    /// here for 8 KiB of live buffer — the undercount this whole change is about.
    #[tokio::test(start_paused = true)]
    async fn the_reservation_counts_the_buffer_and_not_the_declared_length() {
        const BUFFERED: usize = 8192;

        // Declares less than the head already delivered. Legal on a byte stream:
        // the extra bytes ride along either way and this path does not discard
        // them, so they are memory the process is holding.
        let mut reader = ScriptedReader::pieces(&[], true);
        let mut body = vec![b'x'; BUFFERED];

        let reservation = read_body(&mut reader, &mut body, 4)
            .await
            .expect("nothing is owed, so nothing fails");
        assert_eq!(body.len(), BUFFERED);
        assert_eq!(
            reservation.bytes(),
            BUFFERED,
            "every buffered byte is charged, whatever the header claimed"
        );
    }

    /// The reservation a declared body takes is what the caller holds, and it
    /// covers the bytes actually buffered rather than the promise.
    #[tokio::test(start_paused = true)]
    async fn a_body_that_arrives_is_charged_for_what_it_carried() {
        const DECLARED: usize = 4096;

        let mut reader = ScriptedReader::pieces(&[&vec![b'x'; DECLARED]], true);
        let mut body = Vec::new();

        let reservation = read_body(&mut reader, &mut body, DECLARED)
            .await
            .expect("a body inside the budget is admitted");
        assert_eq!(body.len(), DECLARED);
        assert_eq!(
            reservation.bytes(),
            DECLARED,
            "every buffered byte is charged exactly once"
        );
    }

    /// A body that outgrows the process budget is refused while it grows.
    #[tokio::test(start_paused = true)]
    async fn a_body_larger_than_the_process_budget_is_refused() {
        // A body that has outgrown the process budget is refused as it grows, not
        // because of what it declared. `usize::MAX` only proves the counter does
        // not overflow on the way there: the reader charges per frame, so the
        // refusal arrives when a frame will not fit, however many bytes were
        // promised.
        let mut reader = ScriptedReader::pieces(&[], true);
        // 8 KiB pieces, matching the reader's own buffer, totalling more than
        // the 1 GiB process budget — so the refusal arrives on a frame rather
        // than at the end of the stream.
        reader.feed(8192, 1024 * 1024 * 1024 + 1024 * 1024);
        let mut body: Vec<u8> = Vec::new();

        let err = read_body(&mut reader, &mut body, usize::MAX)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("does not fit"),
            "expected a budget refusal, got: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_declared_body_that_keeps_arriving_is_read_whole() {
        let mut reader = ScriptedReader::pieces(&[b"abc", b"de"], true);
        // Two bytes came in with the head, so five are still owed.
        let mut body = b"xx".to_vec();

        read_body(&mut reader, &mut body, 7).await.unwrap();

        assert_eq!(body, b"xxabcde");
    }

    #[tokio::test(start_paused = true)]
    async fn a_declared_body_that_ends_early_is_an_error() {
        let mut reader = ScriptedReader::pieces(&[b"abc"], true);
        let mut body = Vec::new();

        let err = read_body(&mut reader, &mut body, 16).await.unwrap_err();

        assert!(
            err.to_string().contains("ended before content-length"),
            "{err}"
        );
    }

    /// A body that produces `frames` frames and then goes silent.
    ///
    /// What a backend that answered with a head and then stopped looks like to
    /// the proxy: the frames that did arrive are delivered, and then nothing
    /// comes — not an end, and not an error either.
    struct StallingBody {
        frames: usize,
        sent: usize,
    }

    impl hyper::body::Body for StallingBody {
        type Data = bytes::Bytes;
        type Error = hyper::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            if self.sent < self.frames {
                self.sent += 1;
                std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(
                    bytes::Bytes::from_static(b"chunk"),
                ))))
            } else {
                // Silence: no frame, and no end of the body either.
                std::task::Poll::Pending
            }
        }
    }

    /// A body that produces a frame every `gap` and never ends.
    struct DrippingBody {
        gap: std::time::Duration,
        timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    }

    impl DrippingBody {
        fn new(gap: std::time::Duration) -> Self {
            Self { gap, timer: None }
        }
    }

    impl hyper::body::Body for DrippingBody {
        type Data = bytes::Bytes;
        type Error = hyper::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            if self.timer.is_none() {
                self.timer = Some(Box::pin(tokio::time::sleep(self.gap)));
            }
            let timer = self.timer.as_mut().expect("a timer was just set");
            if timer.as_mut().poll(cx).is_pending() {
                return std::task::Poll::Pending;
            }
            self.timer = None;
            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(
                bytes::Bytes::from_static(b"chunk"),
            ))))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_backend_that_goes_silent_mid_body_ends_at_the_idle_deadline() {
        // The observation this test exists for: `response_idle_secs` has to
        // reach the response body of the plaintext listener, not merely the
        // streamed one. A backend that sent the head and then went silent used
        // to hold the request — and the connection — for as long as it liked.
        let idle = std::time::Duration::from_secs(120);
        let mut body = Box::pin(idle_bounded(StallingBody { frames: 1, sent: 0 }, idle));

        // The frame the backend did send arrives.
        let first = tokio::time::timeout(std::time::Duration::from_secs(200), body.next())
            .await
            .expect("the frame must arrive")
            .expect("the body must not end");
        assert!(
            first.is_ok(),
            "the frame the backend sent must pass through: {first:?}"
        );

        // Then the backend goes silent, and the gap is bounded.
        let second = tokio::time::timeout(std::time::Duration::from_secs(200), body.next())
            .await
            .expect("the idle deadline must end the body")
            .expect("the body must not end");
        match second {
            Err(BodyError::Idle(d)) => assert_eq!(d, idle),
            other => panic!("expected an idle failure, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_backend_that_drips_within_the_idle_deadline_stays_open() {
        // The other half of the same rule: the deadline is idle, not a phase
        // deadline, so it re-arms on every frame. A backend that keeps saying
        // something — an SSE feed, a long transfer — is not cut off.
        let idle = std::time::Duration::from_secs(120);
        let mut body = Box::pin(idle_bounded(
            DrippingBody::new(std::time::Duration::from_secs(100)),
            idle,
        ));

        for _ in 0..3 {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(200), body.next())
                .await
                .expect("a frame must arrive")
                .expect("the body must not end");
            assert!(
                frame.is_ok(),
                "a frame within the idle deadline must pass through: {frame:?}"
            );
        }
    }
}

/// A backend that speaks TLS, and the client that reaches it.
///
/// The certificate is made here rather than kept in the repository: a key in
/// the tree is a key somebody has to trust not to be used, and a test that
/// needs one can make one in a millisecond.
#[cfg(test)]
mod transport {
    use super::*;
    use rcgen::{CertificateParams, IsCa, KeyPair};
    use std::convert::Infallible;
    use tokio::io::AsyncWriteExt;

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
        let clients =
            BackendClients::new(std::time::Duration::from_secs(5), Some(ca_path.as_path()))
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
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
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
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
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
        let clients =
            BackendClients::new(std::time::Duration::from_secs(5), Some(ca_path.as_path()))
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
        let body = RequestBody {
            bytes: bytes::Bytes::new(),
            content_length: None,
            reservation: crate::conn::limits::ByteReservation::empty(),
        };

        let forwarded = build_backend_request(&request, &backend_info, &body)
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
        let body = RequestBody {
            bytes: bytes::Bytes::from_static(b"the body the client sent"),
            content_length: None,
            reservation: crate::conn::limits::ByteReservation::empty(),
        };

        let forwarded = build_backend_request(&request, &backend_info, &body)
            .expect("a request for the backend");
        let forwarded_body = forwarded
            .body()
            .clone()
            .into_inner()
            .expect("the request carries a body");

        assert_eq!(forwarded_body, body.bytes, "the body is the same body");
        assert_eq!(
            forwarded_body.as_ptr(),
            body.bytes.as_ptr(),
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
        let body = RequestBody {
            bytes: bytes::Bytes::new(),
            content_length: None,
            reservation: crate::conn::limits::ByteReservation::empty(),
        };

        let forwarded = build_backend_request(&request, &backend_info, &body)
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
}
