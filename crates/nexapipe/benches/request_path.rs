//! The server's request path: a request arriving, a route being found, a
//! backend being chosen, and the answer coming back.
//!
//! `route_lookup` measures the walk over the routes and nothing else — the
//! backends are never dialled. This bench measures the whole of the server's
//! work for one request: the lookup, the balancer, the URI the backend is
//! reached at, and the round trip to it. Those are where the per-request costs
//! live, and until now none of them had a number.
//!
//! The backend is a loopback HTTP server, so the bench needs no network. The
//! server's own client is pooled, so the connection to the backend is
//! established before the clock starts and what is measured is the request
//! rather than the price of opening the connection.
//!
//! ## The counting allocator
//!
//! The bench installs a global allocator that counts allocations, and the
//! second measurement it reports is **how many allocations one request
//! makes** — the number that says whether the route lookup, the balancer and
//! the URI construction are worth their cost.
//!
//! The count is returned to criterion as a duration in nanoseconds, so the
//! report reads `1240 ns` for a request that made 1240 allocations. That is
//! the encoding, and it is deliberate: the number belongs in the report where
//! the times are, and a reader who knows it reads it correctly.
//!
//! What is counted is what happens **between the request going in and the
//! response head coming out**: the lookup, the balancer, the URI, and the
//! request that is built from them. The response body is a lazy stream and is
//! not part of it, and neither is anything the bench itself allocated.
//!
//! ## What this bench is not
//!
//! It is the server's **plaintext listener** path, driven through
//! `http::proxy_request`. The QUIC tunnel path — the one a real client uses —
//! reaches the same backend through `http::proxy_to_backend_streaming`, and
//! shares the part of the work this bench is about: the route lookup, the
//! balancer, the origin and the URI. The two paths build the backend request
//! through different functions, so the header copying and the body handling
//! are **not** shared — this bench measures the plaintext one. What the
//! tunnel adds on top is the transport, and the transport is not what the
//! numbers here are about.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use nexapipe::config::RouteMode;
use nexapipe::http::{BackendClients, proxy_request};
use nexapipe::lb::LoadBalancingStrategy;
use nexapipe::routes::{Route, RoutingTable};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The host the request asks for.
const HOST: &str = "app.test";

/// The path it asks for.
const PATH: &str = "/resource";

/// What the backend answers with.
const BODY: &str = "the body the backend answered with";

// ---------------------------------------------------------------------------
// The counting allocator
// ---------------------------------------------------------------------------

/// Whether the allocator is counting at all.
///
/// Off while the *time* is being measured: the check is one relaxed load per
/// allocation, which is small, but "small" is not "nothing" and the time this
/// bench reports should not carry it.
static COUNTING: AtomicBool = AtomicBool::new(false);

/// How many allocations the process has made since the counter was last read.
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, with a counter on top of it.
struct CountingAllocator;

// SAFETY: every method forwards to `System` unchanged and only counts on the
// way past. The counting is an atomic increment on a static, which is safe
// from any thread and does not touch the memory the allocator handed out.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the layout is the caller's, and `System.alloc` takes it as is.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: as above, with the pointer the caller handed in.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer and the layout are the caller's, unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// One allocation, counted.
fn count() {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

/// A backend that answers every request with the same thing.
///
/// The connection is kept open, because the server's client pools them: a
/// backend that closed after every answer would put a TCP handshake in the
/// middle of every measurement.
async fn serve_backend(listener: TcpListener) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                BODY.len(),
                BODY
            );
            let mut buf = vec![0u8; 16 * 1024];
            let mut pending: Vec<u8> = Vec::new();
            loop {
                // Every request that is already whole in the buffer is answered
                // before another read: a request that arrived in two reads
                // must not wait for a third.
                while let Some(end) = head_end(&pending) {
                    pending.drain(..end);
                    if socket.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                pending.extend_from_slice(&buf[..n]);
            }
        });
    }
}

/// Where the request head ends, if it has ended.
fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// The request the bench makes.
fn request() -> Request<Full<Bytes>> {
    Request::builder()
        .method("GET")
        .uri(format!("http://{HOST}{PATH}"))
        .header("host", HOST)
        .body(Full::new(Bytes::new()))
        .expect("the request is well formed")
}

/// The routing table the request is served from: one HTTP route to the backend.
///
/// The path pattern is `/`, which is the catch-all a route uses to say "any
/// path" — `/*` is not a wildcard, it is a literal `/*` prefix, and a route
/// with it serves nothing.
fn table(backend: &str) -> Arc<RoutingTable> {
    Arc::new(RoutingTable::new(vec![Route::new(
        HOST,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    )]))
}

/// One request, and how many allocations it made on the way.
///
/// The count is taken around `proxy_request` alone: the response head and
/// everything that decided it, and nothing the bench allocated around it.
async fn one(clients: &BackendClients, routes: &Arc<RoutingTable>) -> (Bytes, usize) {
    // The request is built **before** the counter is read. Building it is the
    // bench's own work -- the URI it formats, the headers it writes -- and the
    // metric is the server's: the lookup, the balancer, the URI the backend is
    // reached at, and the request built from them. Counting the bench's own
    // work would make the number a statement about the bench.
    let req = request();
    let routes = routes.clone();

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let response: Response<_> = proxy_request(clients, req, routes)
        .await
        .expect("the request is answered");
    let count = ALLOCATIONS.load(Ordering::Relaxed) - before;

    assert_eq!(response.status(), 200, "the backend answered");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("the body arrives")
        .to_bytes();
    (body, count)
}

fn request_path(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("request_path");

    group.bench_function("request", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                // The backend, and the table that points at it.
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let backend = listener.local_addr().unwrap();
                tokio::spawn(serve_backend(listener));
                let clients =
                    BackendClients::new(Duration::from_secs(5), None).expect("the clients");
                let routes = table(&format!("http://{backend}"));

                // One request before the clock starts: it opens the pooled
                // connection to the backend, and what is measured here is the
                // request rather than the price of opening the connection.
                black_box(one(&clients, &routes).await);

                let start = Instant::now();
                for _ in 0..iters {
                    black_box(one(&clients, &routes).await);
                }
                start.elapsed()
            })
        })
    });

    group.bench_function("allocations_per_request", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let backend = listener.local_addr().unwrap();
                tokio::spawn(serve_backend(listener));
                let clients =
                    BackendClients::new(Duration::from_secs(5), None).expect("the clients");
                let routes = table(&format!("http://{backend}"));

                black_box(one(&clients, &routes).await);

                COUNTING.store(true, Ordering::Relaxed);
                // The count is the **sum of the counted windows**, not the
                // difference of the counter over the whole loop: the loop
                // also holds the bench's own work -- the request it builds and
                // the response body it drains -- and the metric says those are
                // not part of it. Criterion divides by the number of
                // iterations, so the sum is the per-request figure.
                let mut count = 0usize;
                for _ in 0..iters {
                    let (body, per_request) = one(&clients, &routes).await;
                    black_box(body);
                    count += per_request;
                }
                COUNTING.store(false, Ordering::Relaxed);

                // The count is the result. It is returned as nanoseconds so
                // that it lands in criterion's report next to the times, and
                // the encoding is written down in the file's own header.
                Duration::from_nanos(count as u64)
            })
        })
    });

    group.finish();
}

criterion_group!(benches, request_path);
criterion_main!(benches);
