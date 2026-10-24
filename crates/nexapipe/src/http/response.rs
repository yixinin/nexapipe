//! What a response is, and what went wrong.
//!
//! The summary and the failure are what the rest of the proxy reasons about:
//! one says what was forwarded, the other says why it was not, and whether
//! trying somebody else is worth it.

use ::http::{Method, Request, Response, StatusCode};

use flate2::Compression;

use flate2::write::GzEncoder;

use http_body_util::{BodyExt, Full};

use hyper::body::Incoming;

use futures_util::StreamExt;
use std::io::Write;

use super::*;

pub(super) const MAX_COMPRESS_SIZE: usize = 1024 * 1024;

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
///
/// The third group is what the response's own `Connection` header names — the
/// response's, not the request's: the two are read apart, as RFC 9110 §7.6.1
/// treats them.
pub(super) fn forwards_response_header(name: &str, connection: &ConnectionNamed) -> bool {
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
        && !connection.names(name)
}

/// The headers of a backend's answer that the client may see.
///
/// The hop-by-hop ones are dropped — the fixed list of RFC 9110 §7.6.1 and
/// every header the answer's own `Connection` header names — and the rest are
/// kept as they are, duplicates and all.
///
/// One place, so that both paths hand the client the same headers for the
/// same answer: the plaintext listener and the tunnel path forward the same
/// backend answers, and a header that one of them drops and the other does not
/// is a header whose presence depends on the path the request took.
pub(super) fn forwarded_response_headers(headers: &::http::HeaderMap) -> ::http::HeaderMap {
    let connection = ConnectionNamed::of(headers);
    let mut forwarded = ::http::HeaderMap::new();
    for (name, value) in headers.iter() {
        if !forwards_response_header(name.as_str(), &connection) {
            continue;
        }
        forwarded.append(name.clone(), value.clone());
    }
    forwarded
}

/// A message with its first letter capitalised.
///
/// The reasons the backend's address can fail with are written in the lower
/// case, because the tunnel path says them in the lower case. This path says
/// them with a capital, and the two are the same reason in two wordings.
pub(super) fn capitalised(message: &str) -> String {
    let mut chars = message.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

pub(super) fn should_compress(content_type: Option<&str>) -> bool {
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

/// Whether the client said it can take a gzip body.
///
/// RFC 9110 §12.5.3: a content coding is acceptable when the client names it
/// and the quality value it gives it is not zero. `gzip;q=0` is the client
/// saying it cannot decode gzip, and answering with one anyway hands it a
/// body it did not ask for and cannot read.
///
/// The header is a list, not a word: `br, gzip;q=0.5` asks for br first and
/// accepts gzip at half a weight, and a `gzip;q=0` in the middle of a list
/// refuses gzip while the rest of the list stands.
pub(super) fn accepts_gzip(accept_encoding: Option<&str>) -> bool {
    let Some(header) = accept_encoding else {
        return false;
    };
    header.split(',').any(|coding| {
        let mut parts = coding.split(';');
        let name = parts.next().unwrap_or_default().trim();
        if !name.eq_ignore_ascii_case("gzip") {
            return false;
        }
        // The quality value: a coding with no `q` is asked for at full weight,
        // and one whose `q` cannot be read is not asked for at all.
        let quality = parts.find_map(|parameter| {
            let (name, value) = parameter.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("q")
                .then_some(value.trim())
        });
        match quality {
            None => true,
            Some(value) => value.parse::<f32>().is_ok_and(|quality| quality > 0.0),
        }
    })
}

pub(super) async fn compress_response(
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
}
