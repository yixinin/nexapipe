//! Forwarding a request to a backend.
//!
//! The path a request takes: read it, pick a backend, send it, and forward
//! what comes back — with the body streamed rather than collected, so a
//! large upload is never held in memory whole.

use crate::routes::{BackendInfo, BackendLookup, RoutingTable};

use ::http::header::HeaderValue;
use ::http::{Method, Request, Response, StatusCode};

use http_body_util::combinators::UnsyncBoxBody;

use http_body_util::BodyExt;

use std::sync::Arc;
use std::time::Duration;

use super::*;

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
            && accepts_gzip(accept_encoding.as_deref())
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

/// One attempt at one backend: the answer, or the reason there was none.
///
/// Split out of [`proxy_request`] so that the retry loop above it is about
/// retrying and this is about asking. The request is rebuilt for every
/// attempt, because the backend it goes to may be a different one.
pub(super) async fn attempt_backend(
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

    // The headers the client named in its own `Connection` header are
    // hop-by-hop for this request, and they do not go to the backend.
    let connection = ConnectionNamed::of(headers);
    for (name, value) in headers.iter() {
        // Preserve the client's original Host header so backend virtual-host
        // routing works; drop the rest that only meant something for the hop
        // from the client to here.
        if !forwards_request_header(name.as_str(), &connection) {
            continue;
        }
        builder = builder.header(name, value);
    }

    let proxied_req = builder.body(full_body(body.clone()))?;

    tracing::debug!(
        "Proxying request: {} {} -> {origin}",
        proxied_req.method(),
        proxied_req.uri(),
    );

    match tokio::time::timeout(response_deadline, client.request(proxied_req)).await {
        Ok(Ok(response)) => {
            // The headers the client may see: the ones that describe the
            // answer rather than the hop, and the same ones the tunnel path
            // forwards — a backend's `connection: keep-alive` describes the
            // backend's link to this process, not the client's.
            //
            // The filter is applied here, where the answer arrives, so that
            // the compressed answer and the plain one are filtered alike.
            let mut response = response;
            let headers = forwarded_response_headers(response.headers());
            *response.headers_mut() = headers;
            Ok(response)
        }
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
/// The head of the request that goes to the backend.
///
/// The backend's own origin, the rewritten path, and the client's headers that
/// may be forwarded — and the length the proxy declares for the body it
/// carries, which is the truth rather than the client's own header.
fn backend_request_builder(
    req: &Request<()>,
    backend_info: &BackendInfo,
    content_length: Option<usize>,
) -> Result<http::request::Builder, anyhow::Error> {
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

    // Whether the proxy declares the length itself.
    //
    // A chunked body is sent as one buffer with a length of our own, so only a
    // request whose `content-length` we could not read takes that path. One we
    // could read is forwarded with the header it arrived with — and a body
    // that is still being read carries the length the client gave, so the
    // proxy states it again rather than passing the client's own header on.
    let declares_own_length = content_length.is_some();

    // The headers the client named in its own `Connection` header are
    // hop-by-hop for this request, and they do not go to the backend.
    let connection = ConnectionNamed::of(req.headers());
    for (name, value) in req.headers() {
        // Preserve the client's original Host header so backend virtual-host
        // routing works. The body below is sent with a length of the proxy's
        // own — whole, or streamed — so `transfer-encoding` and friends must
        // not claim otherwise.
        if !forwards_request_header(name.as_str(), &connection) {
            continue;
        }
        // Dropped rather than overwritten: a second `content-length` on one
        // request is what lets a proxy and a backend disagree about where the
        // body ends, and an unreadable one is exactly the case that survives
        // the filter above.
        if declares_own_length && name == "content-length" {
            continue;
        }
        builder = builder.header(name, value);
    }

    // The length the proxy declares for the body it carries. The client's own
    // `content-length` is dropped above, because this one is the truth.
    if let Some(content_length) = content_length {
        builder = builder.header("content-length", content_length);
    }

    Ok(builder)
}

/// The answer a backend gave, before hyper writes it.
///
/// The bytes that reached the client are counted as they go out, so the access
/// log reports what was delivered rather than what was intended.
pub struct Answer {
    response: Response<hyper::body::Incoming>,
    bytes_sent: Arc<std::sync::atomic::AtomicUsize>,
    idle: Duration,
    /// What the access log says, once the answer is over.
    report: Option<crate::http::server::AccessReport>,
    /// The backend's lease, held until the answer's body is done.
    ///
    /// The work against a backend is not over when the response head is in:
    /// the body may still be streaming, and a backend that is still streaming
    /// is still busy. The balancer counts a backend as busy until the flow
    /// that is using it releases the lease, so the lease belongs with the
    /// body rather than with the head. The plaintext path has always kept it
    /// there; see [`LeasedBody`].
    lease: Option<crate::lb::BackendLease>,
}

impl Answer {
    /// The status the client is getting.
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    /// How many bytes reached the client.
    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The answer, and what the access log says about it.
    ///
    /// The line is written when the answer is over — that is, when the body
    /// has been written — because the bytes it reports are the bytes that
    /// reached the client, and they are not known before then.
    pub fn with_report(mut self, report: crate::http::server::AccessReport) -> Self {
        self.report = Some(report);
        self
    }

    /// The answer, and the backend's lease.
    ///
    /// The lease is what the balancer counts, and it is released when the
    /// body is dropped — which is when the work against that backend is
    /// really over.
    pub fn with_lease(mut self, lease: Option<crate::lb::BackendLease>) -> Self {
        self.lease = lease;
        self
    }

    /// The answer, as hyper writes it.
    pub fn into_response(self) -> Response<crate::http::body::ProxyBody> {
        let Answer {
            response,
            bytes_sent,
            idle,
            report,
            lease,
        } = self;
        let (parts, body) = response.into_parts();
        let body = UnsyncBoxBody::new(crate::http::server::CountedBody::new(
            body, bytes_sent, idle, report,
        ));
        // The lease rides with the body: the backend is busy until the body
        // is done, and not one moment longer.
        let body = http_body_util::BodyExt::boxed_unsync(LeasedBody {
            inner: body,
            _lease: lease,
        });
        Response::from_parts(parts, body)
    }
}

/// Forward a request to a backend and hand the answer back.
///
/// The answer is **returned**, not written: hyper writes it, which is the
/// point of the tunnel path running on hyper's codec — the status line, the
/// headers and the framing are hyper's, and they are the ones every other
/// HTTP server sends.
pub async fn proxy_to_backend(
    clients: &BackendClients,
    timeouts: crate::config::Timeouts,
    req: &Request<()>,
    backend_info: &BackendInfo,
    body: &crate::http::server::RequestBody,
    request_id: &str,
) -> Result<Answer, ProxyFailure> {
    let client = clients.for_protocol(backend_info.protocol);

    // When the body has to be finished by. It is the same deadline the
    // hand-written path had for the same phase — the client's own `[timeouts]
    // body_secs` — and it is taken once per attempt, because an attempt is an
    // attempt.
    let body_deadline_at = tokio::time::Instant::now() + timeouts.deadlines.body;

    let proxied_req = build_backend_request_from(req, backend_info, body)?;

    tracing::debug!(
        "Proxying request via client (streaming): {} {}",
        proxied_req.method(),
        proxied_req.uri()
    );

    // The **body** has its own deadline (`[timeouts] body_secs`): the client
    // may take that long to send the body. The **response** has its own
    // (`[timeouts] response_secs`): the backend may take that long to answer,
    // and that clock runs from the moment the body was sent, because a backend
    // cannot answer before it has the body.
    //
    // **A body that is already here is a different case.** It was read from
    // the client before this point, so there is no upload left to bound and
    // the upload deadline must not be polled: it would fire on a body that
    // was never going to be uploaded, and it would cut the request off with a
    // message about a body that had already arrived. The answer's clock
    // starts now instead — the body goes out as the request does.
    let streaming = matches!(body, crate::http::server::RequestBody::Streaming(_));
    let answer_deadline_at = if streaming {
        body_deadline_at + timeouts.response
    } else {
        tokio::time::Instant::now() + timeouts.response
    };

    let mut request = Box::pin(client.request(proxied_req));
    let mut upload_deadline = Box::pin(tokio::time::sleep_until(body_deadline_at));
    let mut answer_deadline = Box::pin(tokio::time::sleep_until(answer_deadline_at));
    let mut answer_armed = false;

    let response = futures_util::future::poll_fn(|cx| {
        use std::task::Poll;

        // The request itself.
        if let Poll::Ready(result) = request.as_mut().poll(cx) {
            return Poll::Ready(match result {
                Ok(response) => Ok(response),
                Err(e) => {
                    tracing::error!("Failed to send request: {:?}", e);
                    // A body that ran out of time is not a backend that
                    // failed, and the error says so.
                    if body.did_time_out() {
                        Err(ProxyFailure::unanswered(
                            anyhow::anyhow!(
                                "the request body did not finish in time (the body's deadline \
                                 is {:?})",
                                timeouts.deadlines.body
                            ),
                            Retryability::IfIdempotent,
                        ))
                    } else {
                        // A connect error means the request was never carried;
                        // anything else means it went out and the answer did
                        // not come.
                        let retry = if e.is_connect() {
                            Retryability::Always
                        } else {
                            Retryability::IfIdempotent
                        };
                        Err(ProxyFailure::unanswered(
                            anyhow::anyhow!("failed to send request: {e:?}"),
                            retry,
                        ))
                    }
                }
            });
        }

        // The body may have gone out while the request was being polled: the
        // answer's deadline runs from that moment, not from the start.
        if !answer_armed && body.has_been_sent() {
            answer_deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + timeouts.response);
            answer_armed = true;
        }

        // The upload's own deadline: the body has to be finished by then. Only a
        // body that is still on the client's stream has an upload to wait
        // for.
        if streaming && upload_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(ProxyFailure::unanswered(
                anyhow::anyhow!(
                    "the request body did not finish in time (the body's deadline is {:?})",
                    timeouts.deadlines.body
                ),
                Retryability::IfIdempotent,
            )));
        }

        // The answer's deadline.
        if answer_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(ProxyFailure::unanswered(
                anyhow::anyhow!("backend did not respond within {:?}", timeouts.response),
                Retryability::IfIdempotent,
            )));
        }

        Poll::Pending
    })
    .await;

    let response = response?;
    let (parts, body) = response.into_parts();

    // The headers the client may see: the ones that describe the answer
    // rather than the hop. `forwarded_response_headers` drops the hop-by-hop
    // ones, and the id the caller gave this request is the one that goes out
    // — a second one from the backend would leave whoever reads the response
    // guessing which to quote.
    let mut headers = forwarded_response_headers(&parts.headers);
    headers.remove("x-request-id");
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(request_id).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    let mut parts = parts;
    parts.headers = headers;

    Ok(Answer {
        response: Response::from_parts(parts, body),
        bytes_sent: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        idle: timeouts.deadlines.response_idle,
        report: None,
        lease: None,
    })
}

/// Builds the request that goes to the backend, with the body hyper read.
///
/// The head is built the way the hand-written path built it — the backend's
/// own origin, the rewritten path, the client's headers that may be forwarded
/// — and the body is the one the client sent.
///
/// The length the proxy declares is the length of the body it carries, and
/// that is the one the client's own header is replaced with:
///
/// - a body that is **here** is sent with a length of its own, because the
///   bytes are the whole of it;
/// - a body that is **still arriving** is sent with the length the client
///   declared, because that length is the truth.
pub(super) fn build_backend_request_from<B>(
    req: &Request<()>,
    backend_info: &BackendInfo,
    body: &crate::http::server::RequestBody<B>,
) -> Result<Request<HttpBody>, anyhow::Error>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: Into<BoxError>,
{
    let (content_length, http_body) = match body {
        crate::http::server::RequestBody::Whole { bytes, .. } => {
            (Some(bytes.len()), full_body(bytes.clone()))
        }
        crate::http::server::RequestBody::Streaming(inner) => {
            let length = req
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok());
            (length, UnsyncBoxBody::new(inner.lend()))
        }
    };
    let builder = backend_request_builder(req, backend_info, content_length)?;
    Ok(builder.body(http_body)?)
}
