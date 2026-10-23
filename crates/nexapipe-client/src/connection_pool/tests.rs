//! The tests of the connection pool.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.
use super::borrow::{MAX_FLOWS_PER_CONNECTION, is_idle_since};
use super::link_status::is_measured_rtt;
use super::{
    ALPN_NEXAPIPE, ALPN_NEXAPIPE_LEGACY, BorrowState, CONNECTION_IDLE_TIMEOUT, DialOutcome,
    IrohConnectionPool, LinkKind, LinkStatus, MAX_CONNECTIONS_PER_PROTOCOL, PoolRefusal,
    connections_for, encode_link_status, identity_changed, may_pool, may_publish,
};
use crate::auth::{Enrollment, TotpAlgorithm, TwoFactorAuth};
#[cfg(feature = "local-proxy")]
use crate::endpoint_group::EndpointGroup;
use iroh::Endpoint;
use iroh::endpoint::presets;
use nexapipe_proto::auth::{Algorithm, AuthMessage, Format};
use nexapipe_proto::protocol::Protocol;
use nexapipe_proto::secret::SecretString;
use nexapipe_proto::{L4Proto, Preface};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Notify, mpsc, watch};

/// The far side of a tunnel: answers the preface, and counts the
/// connections it is given.
///
/// The count is the far side's own, so the number a test reads does not
/// depend on anything the client says about itself.
async fn serve_counting(endpoint: Endpoint, accepted: Arc<AtomicUsize>) {
    while let Some(incoming) = endpoint.accept().await {
        // A copy for the task: the counter is shared, the handle is not
        // moved out of the loop.
        let accepted = accepted.clone();
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            accepted.fetch_add(1, Ordering::Relaxed);

            // One bi-stream per flow.
            loop {
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };
                tokio::spawn(async move {
                    // The preface: its length is known once the fourth
                    // byte has been read.
                    let mut header = [0u8; 4];
                    if recv.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let mut rest = vec![0u8; usize::from(header[3]) + 2];
                    if recv.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    // `Ok` — the flow is open.
                    if send.write_all(&[0x00]).await.is_err() {
                        return;
                    }
                    let mut sink = [0u8; 1];
                    let _ = recv.read(&mut sink).await;
                });
            }
        });
    }
}

/// Wait for the far side's count to reach `n`.
///
/// The far side counts a connection in its own task, and the client's
/// handshake can complete before that task has run — so a count read
/// straight after the handshake is a race, not a measurement. A test that
/// wants the count waits for it.
async fn wait_for_accepted(accepted: &AtomicUsize, n: usize) {
    for _ in 0..250 {
        if accepted.load(Ordering::Relaxed) >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the far side did not take {n} connection(s)");
}

/// The pool reaches a server that speaks only the legacy ALPN.
///
/// The client offers the current ALPN *and* the legacy one, so a server
/// built before the prefix byte was dropped is still reachable. This is the
/// client half of the compatibility the server's own test suite covers from
/// the other side — `a_client_that_speaks_the_legacy_alpn_is_served`, in
/// `crates/nexapipe/tests/data_plane.rs`, is the server's half: the same
/// spelling, and the connection is not only made but **served**.
#[tokio::test]
async fn the_pool_reaches_a_server_that_speaks_only_the_legacy_alpn() {
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE_LEGACY.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn(serve_counting(server, accepted.clone()));

    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = IrohConnectionPool::new_with_endpoint(client, server_addr);

    let conn = pool
        .get_connection(Protocol::Legacy)
        .await
        .expect("the pool reaches a server that speaks only the legacy ALPN");

    // The connection has to carry something, not merely be made: the far
    // side counts a connection in its own task, and that task can run
    // after the client's handshake has already completed — so the count is
    // read only once the far side has answered a preface, which it does
    // only after it has counted the connection.
    let (mut send, mut recv) = conn.conn.open_bi().await.expect("the flow opens");
    let preface = Preface::new(L4Proto::Tcp, "db.test", 5432)
        .to_bytes()
        .expect("the preface encodes");
    send.write_all(&preface)
        .await
        .expect("the preface is written");
    let mut status = [0u8; 1];
    recv.read_exact(&mut status)
        .await
        .expect("the far side answers the preface");
    assert_eq!(status[0], 0x00, "the far side opened the flow");

    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "the far side took the connection"
    );
    drop(conn);
}

/// **The pool reaches a server that speaks only the generic ALPN, even
/// though the client asked for a protocol by name.**
///
/// The per-protocol names are newer than the generic one, so a server that
/// predates them answers with the generic one — and a connection
/// negotiated with it is served the way it always was, by the first byte
/// of each stream. The bytes the client writes are the bytes the sniff
/// looks for, so the flow still opens.
///
/// The fallback is real, and it is implicit: nothing says out loud that
/// the server fell back. This test is the proof that it works.
#[tokio::test]
async fn the_pool_reaches_a_server_that_speaks_only_the_generic_alpn() {
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn(serve_counting(server, accepted.clone()));

    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = IrohConnectionPool::new_with_endpoint(client, server_addr);

    // The client asks for L4 by name; the server only knows the generic
    // one, and the negotiation lands there.
    let conn = pool
        .get_connection(Protocol::L4)
        .await
        .expect("the pool reaches a server that speaks only the generic ALPN");

    // The flow has to open, not merely be made: the bytes the client
    // writes are the bytes the sniff looks for, so the generic path
    // serves them the way it always did.
    let (mut send, mut recv) = conn.conn.open_bi().await.expect("the flow opens");
    let preface = Preface::new(L4Proto::Tcp, "db.test", 5432)
        .to_bytes()
        .expect("the preface encodes");
    send.write_all(&preface)
        .await
        .expect("the preface is written");
    let mut status = [0u8; 1];
    recv.read_exact(&mut status)
        .await
        .expect("the far side answers the preface");
    assert_eq!(status[0], 0x00, "the far side opened the flow");

    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "the far side took the connection"
    );
    drop(conn);
}

/// A pool over a loopback endpoint, and the count the far side keeps.
async fn pool_harness() -> (IrohConnectionPool, Arc<AtomicUsize>) {
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn(serve_counting(server, accepted.clone()));

    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = IrohConnectionPool::new_with_endpoint(client, server_addr);

    (pool, accepted)
}

/// **A protocol is a connection.**
///
/// The protocol is chosen at the handshake, so a client that speaks two
/// of them holds a connection for each: the far side is given one
/// connection per protocol, and not one connection carrying both.
///
/// This is the price of the choice, and it is worth a test: a pool that
/// handed out the same connection for both would be serving an L4 tunnel
/// on a connection the server believes carries HTTP.
#[tokio::test]
async fn a_protocol_is_a_connection_of_its_own() {
    let (pool, accepted) = pool_harness().await;

    let _http = pool
        .get_connection(Protocol::Http)
        .await
        .expect("the HTTP connection opens");
    let _l4 = pool
        .get_connection(Protocol::L4)
        .await
        .expect("the L4 connection opens");

    // The far side counts its own accepts, so the number does not depend
    // on anything the client reports about itself. The count is read
    // after a wait for it: the connection is made on this side, and the
    // far side counts its accepts in its own task, so a count read
    // straight after the dial can be one short.
    wait_for_accepted(&accepted, 2).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "one connection per protocol: the far side was given one for each"
    );

    // And the same protocol again is the same connection.
    let _another = pool
        .get_connection(Protocol::Http)
        .await
        .expect("the HTTP connection opens");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "a second flow of the same protocol rides the connection it already has"
    );
}

/// A backend that answers the authentication handshake, and issues a
/// credential of its own.
///
/// A connection is authenticated when it is made, so a test that wants a
/// connection of a given identity needs a server that answers the
/// handshake. This one checks nothing: it issues a challenge and says the
/// credential is good. The credential it enrolls is one of another
/// client, so an enrollment changes the identity of the pool.
async fn auth_backend() -> Endpoint {
    let ep = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server = ep.clone();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                let Ok(accepting) = incoming.accept() else {
                    return;
                };
                let Ok(conn) = accepting.await else {
                    return;
                };
                // One stream at a time: the enrollment and the handshake
                // that follows it share one stream.
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    while let Some((message, format)) = read_auth_message(&mut recv).await {
                        match message {
                            AuthMessage::EnrollStart { client_id, .. } => {
                                let issue = AuthMessage::EnrollIssue {
                                    client_id,
                                    secret: SecretString::new(
                                        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
                                    ),
                                    algorithm: Algorithm::Sha1,
                                    digits: 6,
                                    period: 30,
                                    device_id: None,
                                };
                                write_auth_message(&mut send, &issue, format).await;
                            }
                            AuthMessage::Start { .. } => {
                                let challenge = AuthMessage::Challenge {
                                    nonce: vec![1, 2, 3, 4],
                                };
                                write_auth_message(&mut send, &challenge, format).await;
                            }
                            AuthMessage::Response { .. } => {
                                write_auth_message(&mut send, &AuthMessage::Ok, format).await;
                                break;
                            }
                            _ => break,
                        }
                    }
                }
            });
        }
    });
    ep
}

/// Reads one length-prefixed authentication message.
async fn read_auth_message(recv: &mut iroh::endpoint::RecvStream) -> Option<(AuthMessage, Format)> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.ok()?;
    let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
    recv.read_exact(&mut buf).await.ok()?;
    AuthMessage::from_payload(&buf).ok()
}

/// Writes one length-prefixed authentication message.
async fn write_auth_message(
    send: &mut iroh::endpoint::SendStream,
    message: &AuthMessage,
    format: Format,
) {
    let bytes = message.to_payload(format).expect("the message serializes");
    send.write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .expect("the message is written");
    send.write_all(&bytes)
        .await
        .expect("the message is written");
}

/// A pool over a backend that answers the authentication handshake.
async fn auth_pool_harness() -> IrohConnectionPool {
    let server = auth_backend().await;
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    IrohConnectionPool::new_with_endpoint(client, server.addr())
}

/// Waits for a connection to be closed, and says whether it was.
async fn wait_for_close(conn: &iroh::endpoint::Connection) -> bool {
    for _ in 0..50 {
        if conn.close_reason().is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// The credential an enrollment buys goes through the same check.
///
/// The enrollment writes the pool's credential itself, and a write that
/// skipped the check would change the identity without the pool hearing
/// about it: the connections of the old identity would carry on as if
/// nothing had happened.
#[tokio::test]
async fn an_enrollment_of_another_identity_closes_the_old_connections() {
    let pool = auth_pool_harness().await;
    pool.set_two_factor(Some(credential(
        "client-001",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        None,
    )))
    .await;

    // A connection of client-001.
    let conn = pool
        .get_connection(Protocol::Http)
        .await
        .expect("the connection is made");

    // The enrollment is only spent on a **new** connection, and the pool
    // hands out the one it has as long as it has room on it. Filling the
    // connection is what makes the next request dial — and the connection
    // it dials is the one that spends the token.
    {
        let connections = pool.inner.connections.lock().await;
        for pooled in connections.iter() {
            pooled
                .state
                .borrows
                .store(MAX_FLOWS_PER_CONNECTION, Ordering::Release);
        }
    }

    // The next dial spends the enrollment token, and the credential it
    // buys belongs to another client.
    pool.set_enrollment(Some(Enrollment::new("client-002", "enrollment-token")))
        .await;
    let next = pool
        .get_connection(Protocol::Http)
        .await
        .expect("the enrollment connection is made");

    assert_ne!(
        next.conn.stable_id(),
        conn.conn.stable_id(),
        "the enrollment opened a connection of its own"
    );
    assert!(
        wait_for_close(&conn.conn).await,
        "the connection of the identity that is gone was not told the identity changed"
    );
}

/// A backend that holds the authentication handshake open until the test
/// lets it finish.
///
/// The client takes its credential **before** the handshake and runs the
/// handshake afterwards — so a handshake that is held open runs under the
/// credential of the moment it started. That is the window the tests here
/// need: the credential can be replaced while the handshake is still
/// running, and the connection that comes out of it belongs to the
/// identity that is gone.
///
/// The connection is handed to the test when the far side reads the
/// `AUTH_START` — which the client writes *after* it has taken the
/// credential, so the test knows which credential the handshake is running
/// under before it does anything.
async fn stalling_auth_backend() -> (
    Endpoint,
    mpsc::UnboundedReceiver<iroh::endpoint::Connection>,
    Arc<Notify>,
) {
    let ep = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server = ep.clone();
    let (accepted_tx, accepted_rx) = mpsc::unbounded_channel();
    let release = Arc::new(Notify::new());
    let release_task = release.clone();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(conn) = accepting.await else {
                return;
            };
            let accepted_tx = accepted_tx.clone();
            let release = release_task.clone();
            tokio::spawn(async move {
                // One stream at a time: the enrollment and the handshake
                // that follows it share one stream.
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    while let Some((message, format)) = read_auth_message(&mut recv).await {
                        match message {
                            AuthMessage::Start { .. } => {
                                // The client has presented its credential
                                // by now, so the test may act on it.
                                let _ = accepted_tx.send(conn.clone());
                                // The handshake waits here, until the test
                                // lets it finish.
                                release.notified().await;
                                let challenge = AuthMessage::Challenge {
                                    nonce: vec![1, 2, 3, 4],
                                };
                                write_auth_message(&mut send, &challenge, format).await;
                            }
                            AuthMessage::Response { .. } => {
                                write_auth_message(&mut send, &AuthMessage::Ok, format).await;
                                break;
                            }
                            _ => break,
                        }
                    }
                }
            });
        }
    });

    (ep, accepted_rx, release)
}

/// A pool over a backend that holds the authentication handshake open.
///
/// The pool is given the credential of client-001, so that the handshake
/// has something to authenticate.
async fn stalling_auth_pool_harness() -> (
    IrohConnectionPool,
    mpsc::UnboundedReceiver<iroh::endpoint::Connection>,
    Arc<Notify>,
) {
    let (server, accepted, release) = stalling_auth_backend().await;
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = IrohConnectionPool::new_with_endpoint(client, server.addr());
    pool.set_two_factor(Some(credential(
        "client-001",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        None,
    )))
    .await;

    (pool, accepted, release)
}

/// **A connection of a credential that has been replaced does not come
/// back to the pool.**
///
/// The credential is replaced while the handshake is still running: the
/// connection that comes out of that handshake was authenticated as the
/// identity that is gone. Pooling it would keep serving traffic under an
/// identity the operator has replaced — so it is closed instead, and the
/// dial that made it is told so.
#[tokio::test]
async fn a_connection_of_a_replaced_credential_does_not_come_back_to_the_pool() {
    let (pool, mut accepted, release) = stalling_auth_pool_harness().await;

    // The dial runs while the credential is still the one of client-001.
    let dialing = {
        let pool = pool.clone();
        tokio::spawn(async move { pool.get_connection(Protocol::Http).await })
    };

    // The far side has the credential: it read the AUTH_START, which the
    // client writes after it has taken the credential.
    let server_conn = accepted
        .recv()
        .await
        .expect("the far side has the connection");

    // The credential is replaced while the handshake is still running.
    pool.set_two_factor(Some(credential(
        "client-002",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        None,
    )))
    .await;

    // Let the handshake finish. The connection comes out of it
    // authenticated as client-001.
    release.notify_one();

    // The dial does not get a connection: the one it made belongs to an
    // identity that is gone.
    let outcome = dialing.await.expect("the dial is not cancelled");
    assert!(
        outcome.is_err(),
        "the connection of the identity that is gone was handed out"
    );

    // And the pool does not keep it.
    assert!(
        pool.inner.connections.lock().await.is_empty(),
        "the connection of the identity that is gone came back to the pool"
    );

    // And it was closed rather than left open on the network.
    assert!(
        wait_for_close(&server_conn).await,
        "the connection of the identity that is gone was left open"
    );
}

/// A dial that finishes with the credential unchanged is pooled as
/// before.
///
/// The fix above compares a generation, and a comparison that moved on
/// every dial would empty the pool. A dial whose credential did not change
/// has nothing to be refused for.
#[tokio::test]
async fn a_dial_that_finishes_with_the_credential_unchanged_is_pooled() {
    let (pool, mut accepted, release) = stalling_auth_pool_harness().await;

    // The same handshake, held open and released — but the credential is
    // not replaced.
    let dialing = {
        let pool = pool.clone();
        tokio::spawn(async move { pool.get_connection(Protocol::Http).await })
    };
    let _server_conn = accepted
        .recv()
        .await
        .expect("the far side has the connection");
    release.notify_one();

    let borrowed = dialing
        .await
        .expect("the dial is not cancelled")
        .expect("the connection is made");
    assert_eq!(
        pool.inner.connections.lock().await.len(),
        1,
        "the connection is pooled"
    );
    drop(borrowed);
}

/// The two ends of a tunnel, and the count the far side keeps.
#[cfg(feature = "local-proxy")]
async fn harness() -> (Arc<EndpointGroup>, Arc<AtomicUsize>) {
    let (pool, accepted) = pool_harness().await;
    let group = Arc::new(EndpointGroup::new_with_single_pool(pool).await);

    (group, accepted)
}

/// Two concurrent flows share one connection.
///
/// A flow **borrows** a connection from the pool rather than taking it out
/// of it, so two flows to one backend are one connection and not two. The
/// far side counts what it is given, which is the number that matters: it
/// is what the peer sees.
#[cfg(feature = "local-proxy")]
#[tokio::test]
async fn two_concurrent_flows_share_one_connection() {
    let (group, accepted) = harness().await;

    let mut tasks = Vec::new();
    for _ in 0..2 {
        let group = group.clone();
        tasks.push(tokio::spawn(async move {
            crate::l4::open_tcp(&group, "db.test", 5432).await
        }));
    }
    let mut flows = Vec::new();
    for task in tasks {
        flows.push(
            task.await
                .expect("the task is not cancelled")
                .expect("the flow opens"),
        );
    }

    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "two flows to one backend should share one connection"
    );

    // And the connection is still there for the next flow: the flows
    // borrowed it, they did not take it away.
    drop(flows);
    let next = crate::l4::open_tcp(&group, "db.test", 5432)
        .await
        .expect("the next flow opens");
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "a flow that ended should not take the connection with it"
    );
    drop(next);
}

/// A borrow is given back when it ends — on the pool's own path too.
///
/// The count is shared with the pool, so a caller that borrowed a
/// connection and dropped it has to leave the count where it was: a
/// connection nobody is riding may be closed as idle, and one that is
/// ridden must not be. The count that never comes back down is what
/// makes a connection look busy for the rest of its life.
#[tokio::test]
async fn a_borrow_is_given_back_when_it_ends() {
    let (pool, _accepted) = pool_harness().await;

    let borrowed = pool
        .get_connection(Protocol::Http)
        .await
        .expect("the connection is borrowed");
    assert_eq!(
        pool.borrow_counts().await,
        vec![1],
        "the borrow is counted while it is held"
    );

    drop(borrowed);
    assert_eq!(
        pool.borrow_counts().await,
        vec![0],
        "the borrow is given back when it ends"
    );
}

/// A connection that has just carried a flow is fresh, not stale.
///
/// The idle timeout is about how long a connection has been sitting
/// **unused**, and the moment it became unused is the moment the last
/// flow ended — a moment only the borrower can see. A connection that
/// carried a ten-minute flow and was stamped when it was handed out
/// would look stale the instant the flow ended, and the next flow would
/// pay for a fresh handshake.
///
/// The clock is paused so that "a moment ago" and "ten minutes ago" are
/// exact rather than approximate.
#[tokio::test(start_paused = true)]
async fn the_last_borrow_refreshes_the_last_use_stamp() {
    let state = Arc::new(BorrowState::new());
    let borrow = state
        .try_borrow()
        .expect("there is room for one borrow on a fresh connection");

    // Ten minutes of use: the connection is old, and the stamp says so.
    tokio::time::advance(Duration::from_secs(600)).await;
    assert!(
        state.is_idle_for(CONNECTION_IDLE_TIMEOUT),
        "the stamp is ten minutes old while the flow is running"
    );

    // The flow ends.
    drop(borrow);

    assert!(
        !state.is_idle_for(CONNECTION_IDLE_TIMEOUT),
        "a connection whose last flow just ended is fresh again"
    );
}

/// A connection that is full is not handed out again.
///
/// The server counts the flows on a connection and refuses the one that
/// does not fit, so a client that piles every flow onto one connection
/// runs into a ceiling it cannot see. The pool opens another connection
/// instead, and hands the flow that does not fit to it.
#[tokio::test]
async fn a_full_connection_is_not_handed_out_again() {
    let (pool, accepted) = pool_harness().await;

    let mut borrows = Vec::new();
    for _ in 0..MAX_FLOWS_PER_CONNECTION {
        borrows.push(
            pool.get_connection(Protocol::Http)
                .await
                .expect("the connection is borrowed"),
        );
    }
    // Give the far side a moment to count the connection: its own task
    // can run after the handshake has already completed.
    wait_for_accepted(&accepted, 1).await;
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "the flows share one connection while it has room"
    );

    // The next one does not fit, so it gets a connection of its own.
    let next = pool
        .get_connection(Protocol::Http)
        .await
        .expect("the connection is borrowed");
    // Give the far side a moment to accept the second connection.
    wait_for_accepted(&accepted, 2).await;
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        2,
        "a connection that is full is not handed out again"
    );

    drop(next);
    drop(borrows);
}

/// A dial that was cancelled does not poison the next request.
///
/// The shared dial lives in a slot, and a dialer that is dropped takes
/// its channel with it: the slot is then holding a channel that nobody
/// will ever answer. The next caller has to dial again rather than be
/// handed a failure that no dial produced.
#[tokio::test]
async fn a_cancelled_dial_does_not_poison_the_next_request() {
    let (pool, _accepted) = pool_harness().await;

    // What a cancelled dial leaves behind: a slot holding a channel whose
    // sender is gone.
    {
        let (tx, rx) = watch::channel(None::<DialOutcome>);
        drop(tx);
        pool.inner.dialing.lock().await.insert(Protocol::Http, rx);
    }

    // The next request dials again, and is served.
    let borrowed = pool
        .get_connection(Protocol::Http)
        .await
        .expect("the next request dials again");
    drop(borrowed);
}

/// A credential for `client_id`, optionally naming a device.
fn credential(client_id: &str, secret: &str, device: Option<&str>) -> TwoFactorAuth {
    let auth =
        TwoFactorAuth::new(client_id, secret, TotpAlgorithm::SHA1).expect("a valid base32 secret");
    match device {
        Some(device) => auth.with_device(device),
        None => auth,
    }
}

/// A different secret under the same name is the same account.
///
/// A rotation changes the seed and nothing else, so the connections that
/// were authenticated as that account still stand for it — and dropping
/// the pool would close every request in flight over a rotation.
#[test]
fn a_rotated_secret_is_the_same_identity() {
    let before = credential("client-001", "JBSWY3DPEHPK3PXP", None);
    let after = credential("client-001", "KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP", None);

    assert!(!identity_changed(Some(&before), Some(&after)));
}

/// A different client is a different account, and the connections
/// authenticated as the old one are not the new one's.
#[test]
fn a_different_client_is_a_different_identity() {
    let before = credential("client-001", "JBSWY3DPEHPK3PXP", None);
    let after = credential("client-002", "JBSWY3DPEHPK3PXP", None);

    assert!(identity_changed(Some(&before), Some(&after)));
}

/// A different device of the same client is a different credential, and a
/// connection authenticated as one device is not the other's.
#[test]
fn a_different_device_is_a_different_identity() {
    let before = credential("client-001", "JBSWY3DPEHPK3PXP", Some("laptop"));
    let after = credential("client-001", "JBSWY3DPEHPK3PXP", Some("phone"));

    assert!(identity_changed(Some(&before), Some(&after)));
}

/// A named device and the client it belongs to are different identities:
/// the named one answers with a secret of its own, the unnamed one with
/// the client's.
#[test]
fn a_named_device_is_not_the_client_it_belongs_to() {
    let unnamed = credential("client-001", "JBSWY3DPEHPK3PXP", None);
    let named = credential("client-001", "JBSWY3DPEHPK3PXP", Some("laptop"));

    assert!(identity_changed(Some(&unnamed), Some(&named)));
}

/// Going from a credential to none, and from none to a credential, are
/// both changes.
#[test]
fn dropping_or_adding_a_credential_is_a_change() {
    let auth = credential("client-001", "JBSWY3DPEHPK3PXP", None);

    assert!(identity_changed(Some(&auth), None));
    assert!(identity_changed(None, Some(&auth)));
    assert!(!identity_changed(None, None));
}

/// A connection is idle since it was last used, not since it was dialled.
///
/// The clock is paused so that "a moment ago" and "61 seconds ago" are
/// exact rather than approximate.
#[tokio::test(start_paused = true)]
async fn a_connection_is_idle_since_it_was_last_used() {
    let now = tokio::time::Instant::now();

    assert!(
        !is_idle_since(now, CONNECTION_IDLE_TIMEOUT),
        "a connection that was just handed back is not idle"
    );

    // Used for ten minutes, and handed back a second ago: the connection is
    // old, and it is not idle. The timeout measures how long the connection
    // has been sitting **unused**, not how old it is.
    let ten_minutes_of_use = tokio::time::Duration::from_secs(600);
    let handed_back_a_second_ago = now - tokio::time::Duration::from_secs(1);
    assert!(
        !is_idle_since(handed_back_a_second_ago, CONNECTION_IDLE_TIMEOUT),
        "a connection that was used for {ten_minutes_of_use:?} and handed back a second ago \
         is not idle"
    );

    assert!(
        is_idle_since(
            now - tokio::time::Duration::from_secs(61),
            CONNECTION_IDLE_TIMEOUT
        ),
        "a connection that has been sitting for longer than the timeout is idle"
    );
}

/// A watcher that started before the network changed must not publish: the
/// reading it holds is the round trip of the network that is gone.
#[test]
fn a_watcher_from_an_older_generation_does_not_publish() {
    assert!(
        may_publish(3, 3),
        "the generation the watcher started in may publish"
    );
    assert!(
        !may_publish(4, 3),
        "a generation that moved on may not publish"
    );
}

/// quinn's estimator starts every path at the transport's initial RTT and
/// replaces it once the path has something to say, so a path that was
/// selected a moment ago reads as that guess. It is a number nobody
/// measured, and the UI has to be able to say so.
#[test]
fn quinns_initial_guess_is_not_a_measurement() {
    // The guess itself is not a measurement.
    assert!(!is_measured_rtt(crate::transport::INITIAL_RTT));
    // A reading that differs from the guess is one.
    assert!(is_measured_rtt(Duration::from_millis(334)));
    assert!(is_measured_rtt(Duration::from_millis(20)));
}

/// The UI draws whole milliseconds: a reading that would be drawn as zero
/// is not a number anybody made either.
#[test]
fn a_reading_below_a_millisecond_is_not_drawn_as_zero() {
    assert!(!is_measured_rtt(Duration::from_micros(0)));
    assert!(!is_measured_rtt(Duration::from_micros(999)));
    assert!(is_measured_rtt(Duration::from_millis(1)));
}

/// The name crosses the JNI and Tauri boundaries, so the two sides can only stay in sync
/// if `as_str` and `parse` agree — and an unfamiliar spelling must degrade to `Unknown`
/// rather than fail, because the value only ever feeds an icon.
#[test]
fn link_kind_name_round_trips() {
    for kind in [LinkKind::Direct, LinkKind::Relay, LinkKind::Unknown] {
        assert_eq!(LinkKind::parse(kind.as_str()), kind);
    }
    assert_eq!(LinkKind::parse(""), LinkKind::Unknown);
    assert_eq!(LinkKind::parse("hole-punched"), LinkKind::Unknown);
}

#[test]
fn link_kind_serializes_in_snake_case() {
    assert_eq!(
        serde_json::to_string(&LinkKind::Direct).unwrap(),
        "\"direct\""
    );
    assert_eq!(
        serde_json::to_string(&LinkKind::Relay).unwrap(),
        "\"relay\""
    );
    assert_eq!(
        serde_json::to_string(&LinkKind::Unknown).unwrap(),
        "\"unknown\""
    );
}

/// A link with no path is nothing at all — not a direct link with no
/// latency, which is what a caller would draw as "0 ms".
#[test]
fn a_link_with_no_path_has_neither_a_kind_nor_a_latency() {
    let status = LinkStatus::default();
    assert_eq!(status.kind, LinkKind::Unknown);
    assert_eq!(status.rtt, None);
}

/// The reading crosses the JNI boundary as `<id>=<kind>/<rtt>`, and the
/// Kotlin side reads it back. The form is a contract between the two
/// halves, so it is pinned here: the Kotlin decoder has its own tests,
/// and a form only one side tests can drift apart without anything
/// failing.
#[test]
fn a_link_reading_carries_the_kind_and_the_round_trip() {
    let id = iroh::SecretKey::generate().public();
    let status = LinkStatus {
        kind: LinkKind::Relay,
        rtt: Some(Duration::from_millis(15)),
    };

    assert_eq!(encode_link_status(&id, &status), format!("{}=relay/15", id));
}

/// A reading with no sample says so, rather than saying zero — a zero
/// would be drawn as a round trip of no time at all.
#[test]
fn a_link_reading_without_a_sample_says_so() {
    let id = iroh::SecretKey::generate().public();
    let status = LinkStatus {
        kind: LinkKind::Direct,
        rtt: None,
    };

    assert_eq!(encode_link_status(&id, &status), format!("{}=direct/-", id));
}

/// The pool's ceiling is counted **per protocol**.
///
/// A connection carries one protocol, so the connections of one protocol
/// cannot carry another's flows and cannot stand in for it. A protocol
/// that needs a connection of its own is therefore not refused because
/// another protocol's connections are sitting in the pool.
#[test]
fn the_ceiling_is_counted_per_protocol() {
    let http = [Protocol::Http; MAX_CONNECTIONS_PER_PROTOCOL];
    let l4 = [Protocol::L4; MAX_CONNECTIONS_PER_PROTOCOL];

    // HTTP is at its own ceiling, and is refused.
    assert!(!may_pool(Protocol::Http, http.iter().copied()));
    // L4 is not refused for it: a connection opened for HTTP cannot carry
    // an L4 flow, so it cannot stand in for one.
    assert!(may_pool(Protocol::L4, http.iter().copied()));

    // Both protocols at their ceilings: the pool holds twice the number,
    // and each is still counted on its own.
    let both: Vec<Protocol> = http.iter().chain(l4.iter()).copied().collect();
    assert!(!may_pool(Protocol::Http, both.iter().copied()));
    assert!(!may_pool(Protocol::L4, both.iter().copied()));
    assert!(may_pool(Protocol::Tls, both.iter().copied()));
}

/// **The pool's ceiling is counted per protocol, end to end.**
///
/// The test above counts the pool's own bookkeeping; this one goes
/// through the pool itself — a connection is established, and the pool
/// decides whether to keep it. The refusal is checked for what it is: a
/// connection that was closed on the spot is refused too, and that is a
/// different failure with a different cause.
///
/// The pool is filled by hand here rather than through `get_connection`,
/// because the ceiling is only reached when a protocol's connections are
/// all full — and a flow makes a connection full at two hundred.
#[tokio::test]
async fn the_ceiling_is_refused_for_that_protocol_alone() {
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_counting(server, Arc::new(AtomicUsize::new(0))));

    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_NEXAPIPE.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = IrohConnectionPool::new_with_endpoint(client.clone(), server_addr.clone());

    // Fill the pool for one protocol.
    for _ in 0..MAX_CONNECTIONS_PER_PROTOCOL {
        let conn = client
            .connect(server_addr.clone(), ALPN_NEXAPIPE)
            .await
            .expect("the connection opens");
        assert!(
            pool.pool_connection(
                conn,
                Arc::new(BorrowState::new()),
                Protocol::Http,
                generation(&pool),
            )
            .await
            .is_ok(),
            "the connection is pooled"
        );
    }

    // The next one for that protocol is refused: its own ceiling is
    // reached, and the refusal is the ceiling's and not a closed
    // connection's.
    let conn = client
        .connect(server_addr.clone(), ALPN_NEXAPIPE)
        .await
        .expect("the connection opens");
    assert!(
        matches!(
            pool.pool_connection(
                conn,
                Arc::new(BorrowState::new()),
                Protocol::Http,
                generation(&pool),
            )
            .await,
            Err(PoolRefusal::Full)
        ),
        "the protocol's own ceiling is reached"
    );

    // And another protocol is not refused: the ceiling was never global.
    let conn = client
        .connect(server_addr.clone(), ALPN_NEXAPIPE)
        .await
        .expect("the connection opens");
    assert!(
        pool.pool_connection(
            conn,
            Arc::new(BorrowState::new()),
            Protocol::L4,
            generation(&pool),
        )
        .await
        .is_ok(),
        "another protocol's ceiling is its own"
    );
}

/// The pool's current credential generation.
///
/// A connection that is pooled by hand has to say which generation it
/// belongs to, or it is refused for being of an identity that is gone.
fn generation(pool: &IrohConnectionPool) -> u64 {
    pool.inner.credential_generation.load(Ordering::Acquire)
}

/// The count is of the connections of **that** protocol, and of no other.
#[test]
fn a_protocol_is_counted_on_its_own() {
    let held = [Protocol::Http, Protocol::L4, Protocol::Http];

    assert_eq!(connections_for(Protocol::Http, held.iter().copied()), 2);
    assert_eq!(connections_for(Protocol::L4, held.iter().copied()), 1);
    assert_eq!(connections_for(Protocol::Tls, held.iter().copied()), 0);
}
