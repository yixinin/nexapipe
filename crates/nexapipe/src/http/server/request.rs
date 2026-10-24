//! What a request is answered with: the rules it is held to, and the
//! refusals it can be turned away with.
//!
//! The verdict comes before the body is read, and the access line is written
//! when the answer is over.

use std::convert::Infallible;
use std::sync::Arc;

use hyper::{Request, Response, StatusCode};

use super::Context;
use super::Incoming;
use super::body::read_request_body;
use super::forward;
use crate::routes::{BackendInfo, BackendLookup};

/// The service: one request, one answer.
///
/// The status the client was told is recorded on the request's span, because
/// what the client was told is part of what the request was: the plaintext
/// listener and the L4 tunnel both record it, and a span that never gets a
/// status is a span that says the request never finished.
///
/// The span is the request's own: the service opened it around this future,
/// so the fields filled in here belong to this request and not to the last one
/// on the stream.
pub(super) async fn handle(
    req: Request<Incoming>,
    ctx: Arc<Context>,
) -> Result<Response<crate::http::body::ProxyBody>, Infallible> {
    let span = tracing::Span::current();
    let method = req.method().as_str().to_string();
    let target = req.uri().to_string();
    crate::log::record_request_on_span(&span, &method, &target);

    let response = handle_one(req, ctx).await?;
    span.record("status", response.status().as_u16() as u64);
    Ok(response)
}

/// One request, one answer.
async fn handle_one(
    req: Request<Incoming>,
    ctx: Arc<Context>,
) -> Result<Response<crate::http::body::ProxyBody>, Infallible> {
    let (parts, body) = req.into_parts();
    let request = Request::from_parts(parts.clone(), ());

    // The head's size, as far as the proxy can tell: hyper parsed the head
    // and does not hand the raw bytes over. What it parsed is what went on
    // the wire, so it is measured from that.
    crate::metrics::METRICS.record_bytes_received(head_size(&request) as u64);

    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(crate::routes::host_and_port);

    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path());

    // **A request that names more than one host is refused here.**
    //
    // The route and the access check read the **first** `Host` header, and
    // the backend would be handed **all** of them, so the host that was
    // authorised and the host that would be served would be two different
    // hosts. Hyper accepts two `Host` headers and passes them both on, and
    // the plaintext listener has always caught this itself — so this path has
    // to catch it too, or the same request is refused on one listener and
    // served on the other.
    //
    // RFC 9110 §7.2 asks for a 400, and that is what this is.
    if crate::http::names_more_than_one_host(request.headers()) {
        tracing::warn!(
            "Refusing a request from {} that carries more than one Host header",
            ctx.peer
        );
        crate::metrics::METRICS.record_request(StatusCode::BAD_REQUEST.as_u16(), 0);
        crate::log::log_access(
            &ctx.request_id,
            &ctx.peer,
            request.method().as_str(),
            request.uri().path(),
            StatusCode::BAD_REQUEST.as_u16(),
            0,
            0,
            Some(&ctx.who),
        );
        return Ok(refusal(StatusCode::BAD_REQUEST));
    }

    // **The verdict comes before the body is read.** A request for a host no
    // route serves has nothing to forward to, and reading its body first is
    // work nobody asked for. Hyper has not read the body either — it is a
    // stream, and it is only read when it is polled — so the bytes are still
    // on the client's side when the answer goes out.
    let lookup: BackendLookup<BackendInfo> = match host {
        Some((h, port)) => {
            ctx.config
                .get_backend_with_acl(h, path, port, ctx.acl.as_deref())
                .await
        }
        None => BackendLookup::NoRoute,
    };

    let unavailable = matches!(lookup, BackendLookup::Unavailable);
    let status = if unavailable {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::NOT_FOUND
    };

    let Some(backend_info) = lookup.backend() else {
        tracing::warn!(
            "Refusing host={:?}: {}, answering {}",
            host,
            if unavailable {
                "no healthy backend behind a route that matches"
            } else {
                "no route matches"
            },
            status.as_u16()
        );
        crate::metrics::METRICS.record_request(status.as_u16(), 0);
        crate::log::log_access(
            &ctx.request_id,
            &ctx.peer,
            request.method().as_str(),
            request.uri().path(),
            status.as_u16(),
            0,
            0,
            Some(&ctx.who),
        );
        return Ok(refusal(status));
    };

    tracing::debug!(
        "Request: host={:?}, path={} -> backend={}",
        host,
        path,
        backend_info.url
    );

    // A WebSocket upgrade: the client wants the connection to become a
    // conversation rather than a request. It is answered before the body is
    // read — there is no body — and the session that follows is two byte
    // streams moved either way.
    if crate::http::websocket::is_upgrade(&request) {
        return Ok(upgrade(Request::from_parts(parts, body), ctx, backend_info).await);
    }

    let started = std::time::Instant::now();
    let method = request.method().clone();
    let request_target = request.uri().to_string();

    // The body, in the shape the backend is sent it in.
    let body = match read_request_body(request.headers(), body, ctx.config.timeouts()).await {
        Ok(body) => body,
        Err(failure) => {
            // The request never went anywhere: there is no backend to blame
            // and no answer to give but the refusal.
            tracing::warn!("Could not read the request body: {}", failure.message);
            crate::metrics::METRICS.record_request(failure.status.as_u16(), 0);
            crate::log::log_access(
                &ctx.request_id,
                &ctx.peer,
                method.as_str(),
                &request_target,
                failure.status.as_u16(),
                started.elapsed().as_millis() as u64,
                0,
                Some(&ctx.who),
            );
            return Ok(crate::http::response::create_error_response(
                failure.status,
                failure.message,
            ));
        }
    };

    match forward(
        &ctx,
        &request,
        &request_target,
        &method,
        host,
        path,
        backend_info,
        &body,
        started,
    )
    .await
    {
        Ok(answer) => Ok(answer.into_response()),
        Err(failure) => {
            // What the client was actually told, when it was told anything: a
            // failure that broke halfway still put a status line and part of a
            // body on the wire, and the log has to say so.
            let status = failure
                .partial
                .as_ref()
                .map(|p| p.status)
                .unwrap_or(StatusCode::BAD_GATEWAY.as_u16());
            let bytes_sent = failure.partial.as_ref().map(|p| p.bytes_sent).unwrap_or(0);
            crate::metrics::METRICS.record_request(status, 0);
            crate::log::log_access(
                &ctx.request_id,
                &ctx.peer,
                method.as_str(),
                &request_target,
                status,
                started.elapsed().as_millis() as u64,
                bytes_sent,
                Some(&ctx.who),
            );
            Ok(crate::http::response::create_error_response(
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                "502 Bad Gateway",
            ))
        }
    }
}

/// A WebSocket upgrade, answered.
///
/// Hyper hands the client's side of the connection over once the `101` is
/// written, so the answer and the session are two things: the answer is what
/// the client is waiting for, and the session is what happens after it.
async fn upgrade(
    request: Request<Incoming>,
    ctx: Arc<Context>,
    backend_info: BackendInfo,
) -> Response<crate::http::body::ProxyBody> {
    let (parts, body) = request.into_parts();
    let head = Request::from_parts(parts.clone(), ());
    let started = std::time::Instant::now();

    // Hyper hands the client's side over once the `101` is written, so this
    // has to be asked for **before** the answer goes out.
    let upgraded = hyper::upgrade::on(Request::from_parts(parts, body));

    let handshake = match crate::http::websocket::handshake(
        &ctx.clients,
        &backend_info,
        &head,
        ctx.config.timeouts(),
    )
    .await
    {
        Ok(handshake) => handshake,
        Err(failure) => {
            tracing::warn!("The WebSocket upgrade failed: {}", failure.error);
            crate::metrics::METRICS.record_request(502, 0);
            crate::log::log_access(
                &ctx.request_id,
                &ctx.peer,
                head.method().as_str(),
                head.uri().path(),
                502,
                0,
                0,
                Some(&ctx.who),
            );
            return crate::http::response::create_error_response(
                StatusCode::BAD_GATEWAY,
                "502 Bad Gateway",
            );
        }
    };

    // The backend refused the upgrade: the client gets the backend's own
    // answer, which is an ordinary response and not a session.
    if handshake.status != 101 {
        tracing::debug!(
            "WebSocket handshake failed with backend, status: {}",
            handshake.status
        );
        crate::metrics::METRICS.record_request(handshake.status, 0);
        // The access log says what the client was told, and here the client
        // was told what the backend said: a refused upgrade is an ordinary
        // response, and a log with no line for it is a log that cannot say
        // which upgrades were refused.
        crate::log::log_access(
            &ctx.request_id,
            &ctx.peer,
            head.method().as_str(),
            head.uri().path(),
            handshake.status,
            started.elapsed().as_millis() as u64,
            // The body of the refusal goes to the client with the status, so
            // the log says how many bytes it carried.
            handshake.refusal_body_len(),
            Some(&ctx.who),
        );
        return handshake.refusal_response();
    }

    let response = handshake.upgrade_response();
    let backend = handshake.backend;
    let trailing = handshake.trailing;
    let idle = ctx.config.timeouts().deadlines.response_idle;

    // The session, in its own task: it outlives the answer, and the answer is
    // what the client is waiting for.
    tokio::spawn(async move {
        match upgraded.await {
            Ok(client) => crate::http::websocket::pump(client, backend, trailing, idle).await,
            Err(e) => tracing::debug!("The upgraded stream did not arrive: {e}"),
        }
    });

    crate::metrics::METRICS.record_request(101, 0);
    // The session is not a request any more — it has no end this log can
    // describe — but the answer that started it is one, and the line for it
    // says the tunnel came up.
    crate::log::log_access(
        &ctx.request_id,
        &ctx.peer,
        head.method().as_str(),
        head.uri().path(),
        101,
        started.elapsed().as_millis() as u64,
        0,
        Some(&ctx.who),
    );
    response
}

/// A refusal, as an answer.
fn refusal(status: StatusCode) -> Response<crate::http::body::ProxyBody> {
    let message = match status {
        StatusCode::NOT_FOUND => "404 Not Found",
        StatusCode::SERVICE_UNAVAILABLE => "503 Service Unavailable",
        _ => "400 Bad Request",
    };
    crate::http::response::create_error_response(status, message)
}

/// The size of the head on the wire, as far as the proxy can tell.
///
/// Hyper parsed the head and does not hand the raw bytes over. What it
/// parsed is what went on the wire, so the head is measured from that: the
/// request line, and every header with the four bytes of framing around it.
fn head_size(request: &Request<()>) -> usize {
    let mut size =
        request.method().as_str().len() + request.uri().to_string().len() + "HTTP/1.1\r\n".len();
    for (name, value) in request.headers() {
        size += name.as_str().len() + value.as_bytes().len() + ": \r\n".len();
    }
    size + "\r\n".len()
}
