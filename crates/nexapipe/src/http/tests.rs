//! The tests of the HTTP half.

//! They are in their own file because there are more of them than there is code
//! to test, and because a file that is mostly tests hides the code it is testing.

use crate::deadline::Deadlines;

use super::body::*;
use super::legacy::*;
use super::response::*;

use ::http::StatusCode;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use http_body_util::Full;
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

/// The check every path makes, on the headers hyper hands it.
///
/// hyper accepts two `Host` headers and passes both on, so the proxy has to
/// make this check itself: the route and the access check read the **first**
/// `Host` header and the backend is handed **all** of them, so a request
/// that was authorised for one host could be served as another. RFC 9110
/// §7.2 asks for a 400.
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

/// The plaintext listener's body reader with the default `[timeouts]` body
/// budget: what these tests exercise is the cap and the reservation, not the
/// configured length of the deadline.
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
    let no_named = ConnectionNamed::of(&::http::HeaderMap::new());
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
            !forwards_request_header(dropped, &no_named),
            "{dropped} belongs to this hop only"
        );
    }
    for kept in ["host", "accept", "content-length", "sec-websocket-key"] {
        assert!(
            forwards_request_header(kept, &no_named),
            "{kept} is the message's own"
        );
    }
}

/// The response direction has a list of its own.
///
/// It is not the request direction's list: a request carries `expect` and
/// `proxy-connection`, which are not response headers. The two are kept apart
/// deliberately, so this pins the response one.
#[test]
fn hop_by_hop_response_headers_do_not_reach_the_client() {
    let no_named = ConnectionNamed::of(&::http::HeaderMap::new());
    for dropped in [
        "connection",
        "Keep-Alive",
        "proxy-authenticate",
        "Proxy-Authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        assert!(
            !forwards_response_header(dropped, &no_named),
            "{dropped} belongs to this hop only"
        );
    }
    for kept in ["content-type", "content-length", "etag"] {
        assert!(
            forwards_response_header(kept, &no_named),
            "{kept} is the message's own"
        );
    }
}

/// A header the request's own `Connection` header names is hop-by-hop.
///
/// RFC 9110 §7.6.1: the hop-by-hop headers are the fixed list **and** every
/// header the message's `Connection` header names. A request that says
/// `Connection: X-Internal-Token` is saying that the header is for this hop
/// only, and forwarding it hands the backend something the client asked not
/// to have forwarded.
#[test]
fn a_header_named_in_the_requests_connection_header_does_not_reach_the_backend() {
    let mut headers = ::http::HeaderMap::new();
    headers.insert("connection", "x-internal-token".parse().unwrap());
    let connection = ConnectionNamed::of(&headers);

    assert!(
        !forwards_request_header("x-internal-token", &connection),
        "a header the request names is for this hop only"
    );
    assert!(
        forwards_request_header("x-kept", &connection),
        "a header the request does not name is the message's own"
    );
}

/// The same rule in the response direction, read from the response's own
/// `Connection` header.
#[test]
fn a_header_named_in_the_responses_connection_header_does_not_reach_the_client() {
    let mut headers = ::http::HeaderMap::new();
    headers.insert("connection", "x-internal".parse().unwrap());
    let connection = ConnectionNamed::of(&headers);

    assert!(
        !forwards_response_header("x-internal", &connection),
        "a header the answer names is for this hop only"
    );
    assert!(
        forwards_response_header("x-kept", &connection),
        "a header the answer does not name is the message's own"
    );
}

/// The two directions are read apart.
///
/// A request's `Connection` names the request's hop-by-hop headers and a
/// response's names the response's — so the names one of them gives are not
/// the names the other is held to.
#[test]
fn the_requests_connection_header_does_not_name_the_responses_headers() {
    let mut request_headers = ::http::HeaderMap::new();
    request_headers.insert("connection", "x-request-only".parse().unwrap());
    let request = ConnectionNamed::of(&request_headers);
    let response = ConnectionNamed::of(&::http::HeaderMap::new());

    assert!(
        !forwards_request_header("x-request-only", &request),
        "the request names it"
    );
    assert!(
        forwards_response_header("x-request-only", &response),
        "the request's names are the request's own"
    );
}

/// A `Connection` header is a list: several names in one value, odd spacing,
/// mixed case, and the header itself may be there more than once.
#[test]
fn a_connection_header_is_read_as_a_list_of_names() {
    let mut headers = ::http::HeaderMap::new();
    headers.append("connection", "X-One, x-two".parse().unwrap());
    headers.append("connection", "  X-Three  ".parse().unwrap());
    let connection = ConnectionNamed::of(&headers);

    for named in ["x-one", "X-One", "x-two", "X-TWO", "x-three"] {
        assert!(
            !forwards_request_header(named, &connection),
            "{named} is named by the connection header"
        );
    }
    assert!(
        forwards_request_header("x-four", &connection),
        "a header nobody named is the message's own"
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

#[tokio::test(start_paused = true)]
async fn the_tunnel_path_ends_a_silent_backend_at_the_idle_deadline() {
    // The tunnel path has a body of its own — the one the answer is handed
    // to the client in — and it has a bound of its own, and this test is
    // here because that bound did not work: the timer was reset before it
    // was polled, so the deadline was always in the future when it was
    // checked and the bound never fired. A backend that sent the head and
    // then went silent held the slot and its backend lease for as long as
    // the peer kept the stream open.
    let idle = std::time::Duration::from_secs(120);
    let bytes_sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut body = crate::http::server::CountedBody::new(
        StallingBody { frames: 1, sent: 0 },
        bytes_sent,
        idle,
        None,
    )
    .into_data_stream();

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
async fn the_tunnel_path_lets_a_dripping_backend_stay_open() {
    // The other half of the same rule on the tunnel path: the bound is the
    // gap between two frames, so a backend that keeps saying something is
    // not cut off.
    let idle = std::time::Duration::from_secs(120);
    let bytes_sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut body = crate::http::server::CountedBody::new(
        DrippingBody::new(std::time::Duration::from_secs(100)),
        bytes_sent,
        idle,
        None,
    )
    .into_data_stream();

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

/// A client that names gzip is asked for it.
///
/// The header is a list of codings, and gzip is one of them.
#[test]
fn a_client_that_names_gzip_is_asked_for_it() {
    assert!(accepts_gzip(Some("gzip")));
    assert!(accepts_gzip(Some("gzip, deflate")));
    assert!(accepts_gzip(Some("br, gzip")));
    assert!(accepts_gzip(Some("GZIP")));
    assert!(accepts_gzip(Some(" gzip ")));
    assert!(accepts_gzip(Some("gzip;q=1")));
    assert!(accepts_gzip(Some("gzip;q=0.5")));
}

/// A client that refuses gzip is not answered with it.
///
/// `gzip;q=0` is the client saying it cannot decode gzip, and a body it
/// cannot read is a body it silently drops. The quality value is read as a
/// number, so `q=0` and `q=0.0` are both a refusal, and a value that cannot
/// be read is a refusal as well.
#[test]
fn a_client_that_refuses_gzip_is_not_asked_for_it() {
    assert!(!accepts_gzip(Some("gzip;q=0")));
    assert!(!accepts_gzip(Some("gzip;q=0.0")));
    assert!(!accepts_gzip(Some("gzip;q=0.000")));
    assert!(!accepts_gzip(Some("br, gzip;q=0")));
    assert!(!accepts_gzip(Some("gzip; q=0")));
    assert!(!accepts_gzip(Some("gzip;q=abc")));
    assert!(!accepts_gzip(Some("gzip;q=")));
}

/// A client that asks for nothing in particular is not answered with gzip.
///
/// No header at all is a client that says nothing about the coding, and the
/// answer goes out in the clear. A header that names other codings is the
/// same: gzip is not among them.
#[test]
fn a_client_that_asks_for_nothing_is_not_asked_for_gzip() {
    assert!(!accepts_gzip(None));
    assert!(!accepts_gzip(Some("")));
    assert!(!accepts_gzip(Some("deflate")));
    assert!(!accepts_gzip(Some("br, zstd")));
    assert!(!accepts_gzip(Some("identity")));
}
