//! How many QUIC connections a hundred concurrent flows open.
//!
//! The client keeps a pool of connections to each backend, and a flow
//! **borrows** one of them: the pool keeps the connection, and the flow
//! holds a handle to it until the flow ends. iroh's connection handle is a
//! cheap clone — *"may be cloned to obtain another handle to the same
//! connection"* — so a hundred flows share one connection, and a flow that
//! ends has nothing to give back.
//!
//! That is the number worth having. The transport is built for it: one
//! connection can carry 1024 bi-streams, so the number of connections a
//! client opens is a property of the flow model, not of the network.
//!
//! This bench opens a hundred concurrent L4 flows to one backend and counts
//! the connections the far side is given. The far side counts its own
//! accepts, so the number does not depend on anything the client reports
//! about itself.
//!
//! It also measures the time those flows take to open, because that is what
//! the number costs: before a flow borrowed its connection, every one of
//! them paid for a QUIC handshake.
//!
//! The far side is an iroh endpoint on this host, bound to the loopback
//! interface, so the bench needs no network and no relay.
//!
//! ## What the count is
//!
//! The count is the number of connections the far side accepted **while the
//! flows were open**. The bench waits for the count to stop moving before
//! reading it, because a connection whose handshake has finished on this side
//! may not have been accepted on the other yet.
//!
//! Each round opens its flows on a **fresh pool**, so a round starts with an
//! empty pool and the count is the connections that round needed — not the
//! ones a previous round left behind. The endpoint is shared between rounds;
//! the pool is not.
//!
//! ## The encoding of the count
//!
//! The count is returned to criterion as a duration in nanoseconds, so the
//! report reads `100 ns` for a hundred flows that opened a hundred
//! connections. That is the encoding, and it is deliberate: the number
//! belongs in the report next to the times, and a reader who knows the
//! encoding reads it correctly.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use criterion::{Criterion, criterion_group, criterion_main};
use iroh::Endpoint;
use iroh::endpoint::presets;
use nexapipe_client::IrohConnectionPool;
use nexapipe_client::endpoint_group::EndpointGroup;
use nexapipe_client::l4::open_tcp;
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// The ALPN the tunnel speaks. The same bytes the client uses.
const ALPN: &[u8] = b"\x05nexapipe";

/// The host the flows ask for.
const HOST: &str = "db.test";

/// The port they ask for.
const PORT: u16 = 5432;

/// How many flows are open at once.
///
/// A hundred is the shape worth measuring: an app with a few connections is
/// not the case that matters, and a phone with a TUN device opens one flow
/// per connection it makes.
const FLOWS: usize = 100;

/// How long the bench waits before it reads the far side's count again.
///
/// The handshake finishes on this side before the far side has necessarily
/// accepted the connection, so the count is read only once it has settled.
const SETTLE: Duration = Duration::from_millis(20);

/// How many times the bench waits for it to settle before reading it anyway.
const SETTLE_ROUNDS: usize = 100;

/// The far side of the tunnel: an echo that speaks the L4 framing, and counts
/// the connections it is given.
///
/// The count is taken when the connection is accepted, which is the moment
/// the far side knows a connection exists at all.
async fn serve(endpoint: Endpoint, connections: Arc<AtomicUsize>) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(accepting) = incoming.accept() else {
            continue;
        };
        let Ok(connection) = accepting.await else {
            continue;
        };
        connections.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            // One bi-stream per flow, and a flow per bi-stream.
            loop {
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };
                tokio::spawn(async move {
                    // The preface: magic, version, proto, host length, the host,
                    // and the port — so its length is known once the fourth
                    // byte has been read.
                    let mut header = [0u8; 4];
                    if recv.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let mut rest = vec![0u8; usize::from(header[3]) + 2];
                    if recv.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    // `Ok` — the flow is open. The client waits for this byte
                    // before it sends anything, so it has to come first.
                    if send.write_all(&[0x00]).await.is_err() {
                        return;
                    }
                    // Hold the flow open for as long as the client keeps it:
                    // a flow that ended here would not be a flow.
                    let mut sink = [0u8; 1];
                    let _ = recv.read(&mut sink).await;
                });
            }
        });
    }
}

/// Waits until the far side's count has moved and then stopped moving, and
/// returns it.
///
/// Both halves matter, and the first one is the one that is easy to get
/// wrong. A count that has not moved **yet** looks exactly like a count that
/// has stopped moving, and the far side's accept loop runs in its own task:
/// the handshake can be finished on this side while the far side has not
/// accepted the connection yet. Reading the count then would report that the
/// round opened no connections at all.
///
/// So the count has to have moved past `before` before "it has stopped
/// moving" means anything — and it has to have stopped moving for **two**
/// windows, because a hundred connections arriving at once can leave a gap
/// in the middle of the storm.
async fn settled(connections: &AtomicUsize, before: usize) -> usize {
    let mut last = connections.load(Ordering::Relaxed);
    let mut stable = 0;
    for _ in 0..SETTLE_ROUNDS {
        tokio::time::sleep(SETTLE).await;
        let now = connections.load(Ordering::Relaxed);
        if now == last {
            stable += 1;
            if stable >= 2 && now > before {
                return now;
            }
        } else {
            stable = 0;
        }
        last = now;
    }
    last
}

/// The two ends of the bench, and the count the far side keeps.
struct Harness {
    /// This side's endpoint. Shared between rounds: only the pool is fresh.
    client: Endpoint,
    /// The far side's endpoint.
    ///
    /// Kept here so that the harness can close it: the accept loop below
    /// owns a copy of it, and an endpoint that is only released when a task
    /// that never ends is dropped stays open — with its socket — for the life
    /// of the process. One of those per iteration is a leak that grows with
    /// the sample count.
    server: Endpoint,
    /// The far side's accept task, stopped when the harness is stopped.
    server_task: tokio::task::JoinHandle<()>,
    /// Where the far side is.
    server_addr: iroh::EndpointAddr,
    /// How many connections the far side has been given.
    connections: Arc<AtomicUsize>,
}

impl Harness {
    async fn start() -> Self {
        // The far side.
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the far side binds");
        let server_addr = server.addr();
        let connections = Arc::new(AtomicUsize::new(0));
        let server_task = tokio::spawn(serve(server.clone(), connections.clone()));

        // This side.
        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");

        Self {
            client,
            server,
            server_task,
            server_addr,
            connections,
        }
    }

    /// Stops the far side: the accept task ends and the endpoint closes.
    ///
    /// The task owns a copy of the endpoint and loops on `accept()` for as
    /// long as it is open, so the two have to go together — the task would
    /// otherwise keep the accept loop running on a closed endpoint.
    async fn stop(self) {
        self.server_task.abort();
        self.server.close().await;
    }

    /// One round: a hundred flows opened at once, and how many connections
    /// that took.
    ///
    /// The round runs on a **fresh pool**, so it starts with an empty one and
    /// the count is what this round needed. The endpoint is shared; the pool
    /// is not, and dropping it at the end of the round takes the connections
    /// the round opened with it.
    async fn round(&self) -> (usize, Duration) {
        let pool =
            IrohConnectionPool::new_with_endpoint(self.client.clone(), self.server_addr.clone());
        let group = Arc::new(EndpointGroup::new_with_single_pool(pool).await);

        let before = self.connections.load(Ordering::Relaxed);

        let start = Instant::now();
        let mut tasks = Vec::with_capacity(FLOWS);
        for _ in 0..FLOWS {
            let group = group.clone();
            tasks.push(tokio::spawn(
                async move { open_tcp(&group, HOST, PORT).await },
            ));
        }
        let mut flows = Vec::with_capacity(FLOWS);
        for task in tasks {
            let flow = task
                .await
                .expect("the task is not cancelled")
                .expect("the flow opens");
            flows.push(flow);
        }
        let elapsed = start.elapsed();

        // The count is read only once it has stopped moving, and the flows
        // are still open: a connection that was closed before the count was
        // read would not be one the round needed.
        let after = settled(&self.connections, before).await;
        let opened = after - before;
        // A round that opened no connection has measured nothing, and
        // criterion would report it as a zero-time sample — a diagnosis that
        // names the symptom rather than the cause. The cause is here.
        assert!(
            opened > 0,
            "the far side accepted no connection: the round measured nothing"
        );

        // The flows end here, and with them the pool and the connections the
        // round opened.
        drop(flows);

        (opened, elapsed)
    }
}

fn flow_connections(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("flow_connections");

    // A hundred flows, each paying for a handshake today, makes a round take
    // about a second — so criterion's default of a hundred samples would take
    // two minutes for a bench that measures one number. Ten samples is enough
    // for the statistics, and the count it produces does not move at all.
    group.sample_size(10);

    group.bench_function("connections", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let harness = Harness::start().await;

                let mut total = 0usize;
                for _ in 0..iters {
                    let (opened, _) = harness.round().await;
                    total += opened;
                }
                black_box(&harness);

                // The far side is stopped here, not left to the end of the
                // process: criterion calls this once per sample, and every
                // one of them would otherwise leave an endpoint and an
                // accept task behind.
                harness.stop().await;

                // The count is the result. It is returned as nanoseconds so
                // that it lands in criterion's report next to the times, and
                // the encoding is written down in this file's own header.
                Duration::from_nanos(total as u64)
            })
        })
    });

    group.bench_function("open_flows", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let harness = Harness::start().await;

                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let (_, elapsed) = harness.round().await;
                    total += elapsed;
                }
                black_box(&harness);

                harness.stop().await;

                total
            })
        })
    });

    group.finish();
}

criterion_group!(benches, flow_connections);
criterion_main!(benches);
