//! What the health table is allowed to say about a backend.
//!
//! The health table answers one question: **is this backend answering?** A
//! verdict in it steers the balancer away from a backend and tells the UI
//! that the tunnel has nowhere to send anything — so only evidence that the
//! *backend* failed may be written there.
//!
//! A client-local refusal is not such evidence: the pool being full and the
//! credential being replaced are facts about this process, and the backend is
//! as healthy as it was a moment earlier.

use nexapipe_client::connection_pool::IrohConnectionPool;
use nexapipe_client::endpoint_group::EndpointGroup;

use iroh::Endpoint;
use iroh::endpoint::presets;
use nexapipe_proto::ALPN_NEXAPIPE;
use nexapipe_proto::protocol::Protocol;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A far side that accepts connections, holds them open, and never reads a
/// byte off them.
///
/// The connections stay open on purpose: the far side has to be **alive and
/// holding connections** for the test to mean anything — a backend that is
/// refusing connections for its own reasons is a different case, and one the
/// health table is right about.
async fn serve_holding(endpoint: Endpoint, accepted: Arc<AtomicUsize>) {
    while let Some(incoming) = endpoint.accept().await {
        let accepted = accepted.clone();
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            accepted.fetch_add(1, Ordering::Relaxed);
            // Hold the connection open. Nothing is read off it, so it stays
            // exactly as healthy as a connection that is being used.
            let _ = connection.closed().await;
        });
    }
}

/// A client endpoint on the loopback.
async fn client_endpoint() -> Endpoint {
    Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds")
}

/// A pool over a far side that accepts connections and holds them open.
async fn pool_over_a_live_peer() -> (IrohConnectionPool, Arc<AtomicUsize>) {
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn(serve_holding(server, accepted.clone()));

    let pool = IrohConnectionPool::new_with_endpoint(client_endpoint().await, server_addr);
    (pool, accepted)
}

/// Waits for the far side's count to reach `n`.
///
/// The far side counts a connection in its own task, so a count read straight
/// after a handshake is a race rather than a measurement.
async fn wait_for_accepted(accepted: &AtomicUsize, n: usize) {
    for _ in 0..250 {
        if accepted.load(Ordering::Relaxed) >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the far side did not take {n} connection(s)");
}

/// **A pool that is full is a fact about this client, not about the
/// backend.**
///
/// The pool holds ten connections per protocol, and the eleventh request is
/// refused — but the backend is answering, it is holding ten live
/// connections open, and it would take the eleventh happily. Writing "the
/// backend is down" into the health table over that refusal says something
/// false: the balancer stops sending traffic to a backend that is up, and the
/// UI says the tunnel has nowhere to send anything.
#[tokio::test]
async fn a_full_pool_does_not_mark_the_backend_unreachable() {
    let (pool, accepted) = pool_over_a_live_peer().await;
    let group = EndpointGroup::new_with_single_pool(pool.clone()).await;

    // Fill the pool: each request is marked as carrying as many flows as the
    // server allows, so the pool has to open a connection of its own for the
    // next one.
    for _ in 0..10 {
        let borrowed = pool
            .get_connection(Protocol::Http)
            .await
            .expect("the pool opens a connection");
        borrowed.borrow.saturate();
    }

    // The far side is up and holding every one of those connections open.
    wait_for_accepted(&accepted, 10).await;

    // The eleventh request cannot be served: the pool has no room left.
    let refused = group
        .get_connection("example.test", Protocol::Http)
        .await
        .expect_err("the pool is full and refuses the request");
    assert!(
        refused.to_string().contains("pool is full"),
        "the refusal should name the full pool, not the backend: {refused}"
    );

    // **The verdict that must not be written.** The backend answered every
    // one of those requests' handshakes and is holding the connections open.
    let snapshot = group.health_snapshot();
    assert!(
        snapshot.nodes.iter().all(|node| node.reachable),
        "a client-local refusal must not mark the backend unreachable: {snapshot:?}"
    );
    assert_eq!(
        snapshot.unreachable_ids(),
        "",
        "the backend was holding live connections and is called unreachable: {snapshot:?}"
    );
}

/// **A backend that cannot be dialled is still a backend that is down.**
///
/// The other half of the rule: the fix above must not have turned the health
/// table into a table that never says anything. A dial that fails is
/// evidence about the backend, and it is the only evidence a request has.
///
/// The backend here is a node ID nobody is answering for — the ordinary
/// "the server is offline" case.
#[tokio::test]
async fn a_dial_that_fails_marks_the_backend_unreachable() {
    let offline: iroh::EndpointId = iroh::SecretKey::generate()
        .public()
        .to_string()
        .parse()
        .expect("a generated public key is a valid node ID");

    let pool = IrohConnectionPool::new_with_endpoint(client_endpoint().await, offline.into());
    let group = EndpointGroup::new_with_single_pool(pool).await;

    let failed = group
        .get_connection("example.test", Protocol::Http)
        .await
        .expect_err("nobody answers for that node ID");
    assert!(
        !failed.to_string().contains("pool is full"),
        "the failure should be the backend's, not the pool's: {failed}"
    );

    let snapshot = group.health_snapshot();
    assert_eq!(snapshot.nodes.len(), 1, "{snapshot:?}");
    assert!(
        !snapshot.nodes[0].reachable,
        "a backend that refused the handshake is unreachable: {snapshot:?}"
    );
    assert_eq!(
        snapshot.unreachable_ids(),
        snapshot.nodes[0].node.to_string(),
        "{snapshot:?}"
    );
}
