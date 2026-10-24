//! Opening a stream, and opening it again when it does not work.
//!
//! A stream to a peer is not made once: the peer may be busy, the path may
//! be down, and the connection may have been refused. The retry is what
//! turns "it did not work" into "it did not work for a reason the client can
//! be told about".

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::ClientError;
use crate::endpoint_group::{EndpointGroup, PooledConnection};

use iroh::EndpointId;
use iroh::endpoint::{RecvStream, SendStream};

use nexapipe_proto::protocol::Protocol;

use std::sync::Arc;

/// Open a new iroh bi-stream for `host`, optionally writing `initial_data` as
/// the first bytes of the request/tunnel payload.
///
/// Retries `open_bi` / initial-write failures up to [`OPEN_ATTEMPTS`]
/// times, discarding the stale pooled connection on each failure so the retry
/// gets a fresh connection.
///
/// "Discarding" is the whole point, and it is what the retry buys: a
/// connection whose path died still looks open to QUIC (`close_reason()` stays
/// `None` until the idle timeout expires), so handing one back to the pool
/// hands it to the next attempt — the pool is last-in-first-out — and the
/// request fails [`OPEN_ATTEMPTS`] times on the same dead connection. Dropping
/// the last handle closes it for real, and the next attempt dials again.
///
/// The cost is that a timeout is retried like any other failure, so one
/// request can now wait [`OPEN_ATTEMPTS`] × [`STREAM_OPERATION_TIMEOUT`]
/// before it gives up. Not retrying was worse: a half-open connection then
/// stayed broken for every later request too.
///
/// Shared with [`crate::l4`]: the L4 tunnel needs the same recovery, and the
/// preface it passes as `initial_data` is written by exactly this code path.
pub(crate) async fn open_stream_with_retry(
    endpoint_group: &Arc<EndpointGroup>,
    host: &str,
    initial_data: Option<&[u8]>,
    protocol: Protocol,
) -> Result<(PooledConnection, SendStream, RecvStream), ClientError> {
    open_stream_with_retry_until(
        endpoint_group,
        host,
        initial_data,
        protocol,
        tokio::time::Instant::now() + STREAM_OPERATION_TIMEOUT * OPEN_ATTEMPTS as u32,
    )
    .await
}

/// [`open_stream_with_retry`], with the caller's deadline.
///
/// **One budget for every attempt.** Each attempt used to have a timeout of
/// its own, and there are three of them, so opening a stream could take a
/// minute and a half — and the caller had three of those as well.
///
/// The budget covers the whole attempt: the open, and the initial write with
/// it. A write waits for the peer's flow-control credit, so a peer that takes
/// the stream and stops reading would otherwise leave the attempt running
/// past its own deadline.
pub(crate) async fn open_stream_with_retry_until(
    endpoint_group: &Arc<EndpointGroup>,
    host: &str,
    initial_data: Option<&[u8]>,
    protocol: Protocol,
    deadline: tokio::time::Instant,
) -> Result<(PooledConnection, SendStream, RecvStream), ClientError> {
    let mut last_err: Option<ClientError> = None;
    // Whose health each attempt is spent on, kept so that running out of
    // attempts can name the backend that ran out. Recording the failure as it
    // happens would condemn a backend for having been idle: see
    // [`PooledConnection::discard`].
    let mut tried: Vec<EndpointId> = Vec::new();

    for _attempt in 1..=OPEN_ATTEMPTS {
        // The budget is gone: another attempt would time out at once, and the
        // backend it would be spent on is not the one that ran out of time.
        // Stopping here keeps the health accounting honest — a backend that
        // was never dialled must not be recorded as having failed.
        if tokio::time::Instant::now() >= deadline {
            last_err = Some(ClientError::TimeoutError);
            break;
        }

        let pooled_conn = match endpoint_group.get_connection(host, protocol).await {
            Ok(conn) => conn,
            Err(e) => {
                // Leaving the loop before every attempt is spent must not lose
                // what those attempts found out. The group that could not offer
                // another connection has itself recorded what it learned about
                // the backend it was reaching for; without this the backends
                // named in `tried` keep every later request dialling them for
                // another full round of attempts first.
                endpoint_group.record_request_failures(&tried);
                return Err(e);
            }
        };
        let tried_node = pooled_conn.node();
        let conn = pooled_conn.conn().clone();

        let (mut send, recv) = match tokio::time::timeout_at(deadline, conn.open_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                jni_log!(
                    "[DEBUG:local-proxy] open_bi failed (attempt {}/{}): {}, retrying on a fresh connection",
                    _attempt,
                    OPEN_ATTEMPTS,
                    e
                );
                last_err = Some(anyhow::anyhow!(e).into());
                tried.extend(tried_node);
                // Closed rather than dropped: another handle is held by the
                // path watcher, so dropping this one would leave the
                // connection open until that task got around to it.
                pooled_conn.discard(b"the connection could not open a stream");
                continue;
            }
            Err(_) => {
                jni_log!(
                    "[DEBUG:local-proxy] open_bi timed out (attempt {}/{}), retrying on a fresh connection",
                    _attempt,
                    OPEN_ATTEMPTS
                );
                // A stream that never opened is a connection that does not
                // work, whether or not QUIC has noticed it yet — the same
                // stale-connection case as the branch above, so it gets the
                // same treatment rather than ending the loop on the first
                // attempt.
                last_err = Some(ClientError::TimeoutError);
                tried.extend(tried_node);
                pooled_conn.discard(b"the connection never opened a stream");
                continue;
            }
        };

        // **The write is inside the attempt's budget, like the open.**
        //
        // A write waits for the peer to grant flow-control credit: a peer
        // that takes the stream and then stops reading leaves the write
        // pending for good, and the payload is not small — the HTTP path
        // sends the filtered head plus the body that came with it, and the
        // TLS path the whole ClientHello. The budget that covers `open_bi`
        // has to cover this too, or the attempt never ends and the request
        // hangs instead of failing.
        if let Some(data) = initial_data {
            match tokio::time::timeout_at(deadline, send.write_all(data)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    jni_log!(
                        "[DEBUG:local-proxy] initial write failed (attempt {}/{}): {}, retrying on a fresh connection",
                        _attempt,
                        OPEN_ATTEMPTS,
                        e
                    );
                    last_err = Some(e.into());
                    tried.extend(tried_node);
                    // Same reasoning as the `open_bi` failures: a connection that
                    // could not take the first bytes is not one to hand back.
                    pooled_conn.discard(b"the connection would not take the first bytes");
                    continue;
                }
                Err(_) => {
                    jni_log!(
                        "[DEBUG:local-proxy] initial write timed out (attempt {}/{}), retrying on a fresh connection",
                        _attempt,
                        OPEN_ATTEMPTS
                    );
                    // A write that ran out of the budget is a connection that
                    // does not work, the same verdict the `open_bi` timeout
                    // reaches — and the same treatment: the connection goes,
                    // and the attempt ends within the budget rather than
                    // hanging in it.
                    last_err = Some(ClientError::TimeoutError);
                    tried.extend(tried_node);
                    pooled_conn.discard(b"the connection never took the first bytes");
                    continue;
                }
            }
        }

        return Ok((pooled_conn, send, recv));
    }

    // Every attempt spent and not one served. "Down" is now the most generous
    // reading left, and it is the reading the next request needs: continuing to
    // hand out these backends would spend another three attempts each on
    // connections nobody asked for. The next successful probe clears it.
    endpoint_group.record_request_failures(&tried);

    Err(last_err.unwrap_or_else(|| {
        ClientError::ConnectionError(format!(
            "Failed to open stream to {} after {} attempts",
            host, OPEN_ATTEMPTS
        ))
    }))
}

/// Ends the tasks it holds when it is dropped.
///
/// Dropping a `JoinHandle` detaches its task instead of cancelling it, so a
/// handler that spawns the two halves of a tunnel and is then aborted by
/// [`LocalProxy::stop`] used to leave both halves running: still holding the
/// client socket and the pooled connection the stop was meant to release.
/// The guard dies with the aborted future, and what it does is immediate.
pub(super) struct TunnelTasks(pub(super) Vec<tokio::task::AbortHandle>);

impl Drop for TunnelTasks {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

const STREAM_OPERATION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);

/// Number of attempts for opening a fresh iroh bi-stream for a new request.
/// If the pooled connection is stale (already closed by the peer), `open_bi` or
/// the initial `write_all` can fail; we discard that connection and retry with a
/// fresh one instead of failing the whole request.
pub(crate) const OPEN_ATTEMPTS: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::connection_pool::IrohConnectionPool;

    use iroh::Endpoint;
    use iroh::EndpointAddr;
    use iroh::endpoint::presets;
    use iroh::endpoint::{QuicTransportConfig, VarInt};

    use nexapipe_proto::ALPN_NEXAPIPE;

    use std::net::SocketAddr;
    use std::time::Duration;

    /// The window the far side below advertises: small enough that a payload
    /// bigger than it cannot be written in one go.
    const PEER_WINDOW: u32 = 16 * 1024;

    /// A far side that accepts the streams it is given and never reads a byte
    /// off them.
    ///
    /// The window it advertises is small and nothing is ever read, so the
    /// credit is never given back: the sender's write stalls once the window
    /// is spent. That is the case the attempt's budget has to cover.
    ///
    /// The streams are **kept**, not dropped: dropping a receive stream tells
    /// the peer to stop sending on it, and the write would then fail with
    /// "stopped" instead of stalling — a different case entirely.
    async fn serve_without_reading() -> EndpointAddr {
        let transport = QuicTransportConfig::builder()
            .stream_receive_window(VarInt::from_u32(PEER_WINDOW))
            .receive_window(VarInt::from_u32(4 * PEER_WINDOW))
            .build();

        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN_NEXAPIPE.to_vec()])
            .transport_config(transport)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the far side binds");
        let addr = endpoint.addr();

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(accepting) = incoming.accept() else {
                        return;
                    };
                    let Ok(connection) = accepting.await else {
                        return;
                    };
                    tokio::spawn(async move {
                        let mut held = Vec::new();
                        while let Ok(streams) = connection.accept_bi().await {
                            // Accepted, and kept: never read, so the window is
                            // never extended.
                            held.push(streams);
                        }
                    });
                });
            }
        });

        addr
    }

    /// **The initial write is part of the attempt, and the attempt's budget
    /// covers it.**
    ///
    /// The budget was applied to `open_bi` but not to the write that follows
    /// it, and a write waits for the peer to grant flow-control credit: a
    /// peer that takes the stream and then stops reading leaves the write
    /// pending for good. The request then hangs instead of failing at the
    /// budget — and the payload is not small on the HTTP and TLS paths.
    #[tokio::test]
    async fn the_initial_write_is_bounded_by_the_attempt_deadline() {
        let server_addr = serve_without_reading().await;

        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN_NEXAPIPE.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");
        let pool = IrohConnectionPool::new_with_endpoint(client, server_addr);
        let group = Arc::new(EndpointGroup::new_with_single_pool(pool).await);

        // Bigger than the window the far side gave: the write cannot finish
        // without credit that never comes.
        let payload = vec![0x41u8; 1024 * 1024];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            open_stream_with_retry_until(
                &group,
                "example.test",
                Some(&payload),
                Protocol::Http,
                deadline,
            ),
        )
        .await;

        let result = outcome.expect("the attempt's deadline did not bound the write");
        match result {
            Err(e) => assert!(
                matches!(e, ClientError::TimeoutError),
                "the write should have run out of the attempt's budget: {e}"
            ),
            Ok(_) => panic!("the write finished against a peer that never reads"),
        }
    }
}
