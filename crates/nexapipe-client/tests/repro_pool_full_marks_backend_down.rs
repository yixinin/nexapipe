//! Verification artefact (throwaway worktree only).
//!
//! Does a *client-local* failure — the per-protocol connection ceiling — get
//! recorded in the shared health table as "the backend is down"?

use nexapipe_client::{EndpointGroup, IrohConnectionPool};
use nexapipe_proto::protocol::Protocol;
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::test]
async fn a_pool_that_is_full_marks_a_live_backend_unreachable() {
    let server = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![b"nexapipe".to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let accepted = accepted.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let accepted = accepted.clone();
                tokio::spawn(async move {
                    let Ok(accepting) = incoming.accept() else {
                        return;
                    };
                    let Ok(connection) = accepting.await else {
                        return;
                    };
                    accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // Hold the connection open for the life of the test.
                    let _ = connection.closed().await;
                });
            }
        });
    }

    let client = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![b"nexapipe".to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = IrohConnectionPool::new_with_endpoint(client, server_addr);
    let group = EndpointGroup::new_with_single_pool(pool).await;

    // Before anything goes wrong, the health table knows nothing.
    let before = group.health_snapshot();
    println!("health before: {:?}", before.nodes);
    assert!(before.nodes.is_empty(), "the table starts empty");

    // Borrow until the pool refuses: MAX_FLOWS_PER_CONNECTION borrows per
    // connection, MAX_CONNECTIONS_PER_PROTOCOL connections per protocol.
    let mut held = Vec::new();
    let mut failure = None;
    for _ in 0..5000 {
        match group.get_connection("pool.test", Protocol::L4).await {
            Ok(c) => held.push(c),
            Err(e) => {
                failure = Some(e);
                break;
            }
        }
    }

    let failure = failure.expect("the pool eventually refuses");
    println!("the failure the group returned: {failure}");
    println!(
        "the far side accepted {} connection(s) and is holding them open",
        accepted.load(std::sync::atomic::Ordering::Relaxed)
    );

    let after = group.health_snapshot();
    println!("health after: {:?}", after.nodes);

    // The backend is alive and answering — ten connections are open to it —
    // but the health table now says it is unreachable.
    assert!(
        after.nodes.iter().any(|n| !n.reachable),
        "the health table did not mark the backend unreachable (nodes: {:?})",
        after.nodes
    );
    assert!(
        after.nodes.iter().any(|n| n.consecutive_failures > 0),
        "the failure counter did not move"
    );

    drop(held);
}
