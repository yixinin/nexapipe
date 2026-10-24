//! The dial path: how a flow gets a connection, and what happens to the
//! connection that comes back.

use iroh::Endpoint;
use iroh::endpoint::{ConnectError, ConnectOptions, Connection};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::watch;

use crate::ClientError;
use nexapipe_proto::protocol::Protocol;

use super::path_watcher::spawn_path_watcher;
use super::paths::PathHealth;
use super::pool::{PooledConnection, drop_stale_connections};
use super::selection::{PoolRefusal, may_pool};
use super::{
    AUTH_REQUIRED_CLOSE_CODE, AUTH_REQUIRED_GRACE, BorrowState, BorrowedConnection,
    CONNECTION_TIMEOUT, DialOutcome, IrohConnectionPool, MAX_CONNECTIONS_PER_PROTOCOL,
    PEER_NOT_ALLOWED_CLOSE_CODE, PRECONNECT_CONNECT_TIMEOUT, PRECONNECT_TIMEOUT, alpns,
};

/// A connection, and the credential generation it was authenticated under.
///
/// The generation is what says whether the connection still stands for the
/// pool's identity: a credential change moves it, and a connection of an
/// older generation was authenticated as an identity that is gone.
struct Authenticated {
    /// The connection itself.
    conn: Connection,
    /// The generation of the credential the handshake ran for.
    generation: u64,
}

impl IrohConnectionPool {
    /// The endpoint to dial from, cloned out of the mutex.
    ///
    /// A copy, not a guard: the QUIC handshake — and the 2FA stream that
    /// follows it — runs for up to [`CONNECTION_TIMEOUT`], and `close_all`
    /// needs the very same lock to close the endpoint. Holding the guard
    /// across the handshake made shutdown lose that race, and the loser is not
    /// the one you want: the JNI layer gives `close_all` eight seconds
    /// (`CLOSE_ALL_TIMEOUT` in `jni.rs`) and then moves on, so the endpoint
    /// stayed open for the rest of the process. `Endpoint` is a handle over
    /// shared state, so cloning costs nothing and still dials from the
    /// endpoint this pool was built with.
    async fn endpoint(&self) -> Option<Endpoint> {
        self.inner.ep.lock().await.clone()
    }

    /// Connect to the backend and run the 2FA handshake when configured.
    /// `timeout` is the budget for the QUIC handshake itself; see
    /// [`PRECONNECT_CONNECT_TIMEOUT`] for why a warm-up uses a tighter one than
    /// [`CONNECTION_TIMEOUT`].
    ///
    /// The connection comes back with the generation of the credential it
    /// was authenticated under: the handshake takes as long as the server
    /// takes, and the credential may be replaced while it runs.
    async fn connect_and_auth(
        &self,
        ep: &Endpoint,
        timeout: tokio::time::Duration,
        protocol: Protocol,
    ) -> Result<Authenticated, ClientError> {
        let started = tokio::time::Instant::now();
        // **The protocol this connection is for, first**, and the two generic
        // names beside it: a server that does not know the per-protocol names
        // takes the generic one, which says "the first byte of each stream
        // decides", and a server built before the prefix byte was dropped
        // takes the older spelling.
        //
        // The order of the *offer* does not decide anything — QUIC's
        // negotiation picks the first of the **accept side's** entries that
        // the peer also offers — so what matters is that the server's list
        // has the per-protocol names in front of the generic one, and that
        // the client offers the one it wants.
        //
        // The address lookup and the handshake are both inside the timeout, the way
        // they were when `connect` did the whole thing; `connect_with_opts` splits
        // the two apart, so the block puts them back together.
        let conn = tokio::time::timeout(timeout, async {
            let connecting = ep
                .connect_with_opts(
                    self.inner.endpoint_addr.clone(),
                    protocol.alpn(),
                    ConnectOptions::new().with_additional_alpns(alpns(protocol)[1..].to_vec()),
                )
                .await
                .map_err(ConnectError::from)?;
            connecting.await.map_err(ConnectError::from)
        })
        .await
        .map_err(|_| {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "connect to {} timed out after {}s (no QUIC handshake)",
                self.backend_id(),
                timeout.as_secs()
            );
            ClientError::TimeoutError
        })?
        .map_err(|e| {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "connect to {} failed after {:.1}s: {}",
                self.backend_id(),
                started.elapsed().as_secs_f32(),
                e
            );
            #[cfg(not(feature = "tracing"))]
            let _ = started;

            // A `[peers]` allow-list refuses inside the QUIC handshake, so the
            // only place its verdict shows up is the error from `connect`
            // itself — there is no connection left to ask. Turn it into the same
            // actionable sentence the 2FA refusals produce, instead of a bare
            // "connection lost".
            if let Some(reason) = peer_not_allowed_reason(&e) {
                return ClientError::AuthenticationFailed(reason);
            }
            ClientError::ConnectionFailed(e.to_string())
        })?;

        // **What was negotiated**, which is not always what was asked for.
        //
        // A server that does not know the per-protocol names answers with the
        // generic one, and a server built before the prefix byte was dropped
        // answers with the older spelling. Both are served the way they always
        // were — the first byte of each stream decides — so the connection
        // works either way, and the bytes the client writes are the bytes the
        // sniff looks for. It is a real fallback, and an implicit one, so it is
        // worth saying out loud: a server that fell back is a server that is
        // still sniffing.
        if conn.alpn() != protocol.alpn() {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "the server negotiated {:?} rather than {}, and will decide by the first byte",
                String::from_utf8_lossy(conn.alpn()),
                protocol.name()
            );
        }

        // Enrollment first: a token is spent once, and it buys the credential
        // the connection is authenticated with — on the stream the enrollment
        // was made on, so the handshake that follows needs no stream of its
        // own. It only runs while there are no credentials.
        let enrollment = self.inner.enrollment.lock().await.clone();
        if let Some(enrollment) = enrollment {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "Enrolling with a one-time token as client '{}'",
                enrollment.client_id()
            );
            match enrollment.exchange(&conn).await {
                Ok(issued) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        "Enrollment succeeded for client '{}'; the token is spent",
                        issued.client_id()
                    );
                    // The credential changes here, so it goes through the one
                    // place that writes it: the identity comparison and the
                    // drop of the connections of the identity that is gone
                    // have to happen with it.
                    //
                    // The generation comes back with the write. It is the one
                    // the issued credential is filed under, read under the lock
                    // the credential is written under, so the two cannot come
                    // from different moments. Reading it here instead — after
                    // the lock is released — would read it a moment later, and
                    // a write that landed in between would have moved it: the
                    // connection would carry the generation of a credential it
                    // never authenticated with, and the pool would take it for
                    // the identity that replaced this one.
                    let generation = self.set_credential(Some(issued.clone())).await;
                    *self.inner.enrollment.lock().await = None;
                    *self.inner.issued.lock().await = Some(issued);
                    // **The enrollment authenticated this connection already.**
                    //
                    // `exchange` ends with the ordinary handshake, on the very
                    // stream the enrollment was made on: the server reads
                    // ENROLL_START and AUTH_START in order off one bi-stream,
                    // and the second message is what authenticates the client.
                    //
                    // So there is nothing left to authenticate, and the block
                    // below must not run. It would open a *second* stream for
                    // the handshake, and a second stream arrives at the server
                    // looking like data sent before any credential: the server
                    // serves it as data, the AUTH_START bytes are parsed as an
                    // HTTP request, and the connection is closed with "invalid
                    // HTTP method parsed". The enrollment succeeds and the
                    // connection dies with it — which is what left a device
                    // that had just enrolled without a working connection.
                    //
                    // The generation is the one the issued credential is filed
                    // under, so the two cannot come from different moments.
                    return Ok(Authenticated { conn, generation });
                }
                Err(e) => {
                    conn.close(0u32.into(), b"2FA enrollment failed");
                    #[cfg(feature = "tracing")]
                    tracing::warn!("2FA enrollment failed: {}", e);
                    return Err(e);
                }
            }
        }

        // **The credential, and the generation it belongs to, together.**
        //
        // The generation is read under the lock the credential is read
        // under, so the two cannot be from different moments: a connection
        // is authenticated as the identity whose generation it carries, and
        // the pool can tell later whether that identity is still the one it
        // is on.
        let (two_factor, generation) = {
            let slot = self.inner.two_factor.lock().await;
            (
                slot.clone(),
                self.inner.credential_generation.load(Ordering::Acquire),
            )
        };
        if let Some(auth) = two_factor {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "Authenticating connection with 2FA as client '{}'",
                auth.client_id()
            );
            if let Err(e) = auth.authenticate(&conn).await {
                conn.close(0u32.into(), b"2FA authentication failed");
                #[cfg(feature = "tracing")]
                tracing::warn!("2FA authentication failed: {}", e);
                return Err(e);
            }
            #[cfg(feature = "tracing")]
            tracing::info!(
                "2FA authentication succeeded for client '{}'",
                auth.client_id()
            );
        }

        Ok(Authenticated { conn, generation })
    }

    /// A connection to carry a flow on.
    ///
    /// **The connection stays in the pool.** A flow borrows a handle to it and
    /// gives it back by dropping the handle; the pool's own handle is what
    /// keeps it alive.
    ///
    /// That is the whole change, and it is small because iroh's `Connection`
    /// is a cheap clonable handle — *"May be cloned to obtain another handle
    /// to the same connection"* — so borrowing one costs a reference count
    /// and nothing else. Before this, a flow **took** the connection out of
    /// the pool and held it until the flow ended, so a hundred concurrent
    /// flows needed a hundred connections and each of them paid for a QUIC
    /// handshake. The transport is built for the opposite: one connection
    /// carries 1024 bi-streams.
    ///
    /// A dial is **shared**: everything that asks while one is in progress
    /// waits for that one rather than starting its own, so a hundred flows
    /// arriving together make one connection between them and not a hundred.
    ///
    /// A connection that is already carrying as many flows as it may is not
    /// handed out again: the pool opens another connection instead, so the
    /// server's own ceiling — the number of L4 flows it allows on one
    /// connection — is never the client's problem.
    pub async fn get_connection(
        &self,
        protocol: Protocol,
    ) -> Result<BorrowedConnection, crate::error::ClientError> {
        loop {
            // A pooled connection with room for another flow is the cheap
            // answer, and it is the answer the whole change is about.
            if let Some(borrowed) = self.borrow_pooled(protocol).await {
                return Ok(borrowed);
            }

            // No connection has room: another one is needed. The dial is
            // shared, so a hundred flows arriving together make one
            // connection between them and not a hundred.
            let (conn, state) = self.dial_shared(protocol).await?;

            // The shared dial may have produced a connection that is already
            // full — a hundred flows can join one dial and fill it — so the
            // borrow is taken only if there is room for it, and the loop
            // dials again otherwise.
            if let Some(borrow) = state.try_borrow() {
                return Ok(BorrowedConnection { conn, borrow });
            }
        }
    }

    /// Borrows a pooled connection that has room for another flow.
    ///
    /// The connection with the **fewest** flows on it is the one handed out,
    /// so a hundred flows spread over the connections the pool has instead
    /// of piling onto the newest one.
    async fn borrow_pooled(&self, protocol: Protocol) -> Option<BorrowedConnection> {
        let mut connections = self.inner.connections.lock().await;

        // Drop stale connections before handing one out: anything already
        // closed by the peer, or idle for longer than
        // CONNECTION_IDLE_TIMEOUT.
        drop_stale_connections(&mut connections);

        let pooled = connections
            .iter()
            // A connection carries one protocol: the one it was opened with.
            .filter(|pooled| pooled.protocol == protocol)
            .filter(|pooled| pooled.state.has_room())
            .min_by_key(|pooled| pooled.state.borrow_count())?;

        // The room was there a moment ago; another flow may have taken the
        // last seat in between, in which case this caller dials.
        let borrow = pooled.state.try_borrow()?;
        Some(BorrowedConnection {
            conn: pooled.conn.clone(),
            borrow,
        })
    }

    /// Dials the backend, sharing the dial with everything that asked for a
    /// connection while it was running.
    ///
    /// One dial, one result: the callers that were waiting when it finished
    /// get that result — the connection, or the failure. That matters most
    /// for the failure: a backend that is down would otherwise be dialled
    /// once per flow, and a hundred flows would spend a hundred dial
    /// timeouts on the same answer.
    async fn dial_shared(
        &self,
        protocol: Protocol,
    ) -> Result<(Connection, Arc<BorrowState>), crate::error::ClientError> {
        loop {
            let (tx, rx) = watch::channel(None::<DialOutcome>);

            // Take the slot for this protocol, or join the one that is there.
            let (tx, rx) = {
                let mut dialing = self.inner.dialing.lock().await;
                match dialing.get(&protocol) {
                    Some(joined) => {
                        // Someone else is dialling the same protocol. Our
                        // sender goes away — so the channel closes if they do
                        // — and we wait on theirs.
                        drop(tx);
                        (None, joined.clone())
                    }
                    None => {
                        dialing.insert(protocol, rx.clone());
                        (Some(tx), rx)
                    }
                }
            };

            // A copy of the receiver, for the cleanup below: the waiting arm
            // takes the original.
            let channel = rx.clone();

            let outcome = match tx {
                Some(tx) => {
                    // We are the dialer.
                    let outcome = self.dial(protocol).await;
                    let _ = tx.send(Some(outcome.clone()));
                    Some(outcome)
                }
                None => {
                    // Someone else is dialling: wait for their answer.
                    let mut rx = rx;
                    loop {
                        if let Some(outcome) = (*rx.borrow_and_update()).clone() {
                            break Some(outcome);
                        }
                        if rx.changed().await.is_err() {
                            // The dialer is gone: its channel closed without
                            // an answer. That is a dial that was cancelled —
                            // the proxy stopped, the task was aborted — and
                            // not a failure a dial produced.
                            break None;
                        }
                    }
                }
            };

            // The slot is cleared either way: on success the connection is in the
            // pool and the next caller borrows it, and on failure the next caller
            // tries again rather than being handed a failure that has already been
            // paid for. The callers that were waiting when it failed share that
            // failure — they are watching the same channel.
            self.clear_dial_slot(protocol, &channel).await;

            match outcome {
                Some(outcome) => return outcome,
                None => {
                    // The dial this caller was waiting for was cancelled. The
                    // slot is free again, so this caller dials instead of
                    // being handed a failure that no dial ever produced.
                    continue;
                }
            }
        }
    }

    /// Clears the shared-dial slot, if it still holds `channel`.
    ///
    /// The check matters: a slot that another dial has taken in the meantime
    /// belongs to that dial, and clearing it would let two dials run at once.
    async fn clear_dial_slot(
        &self,
        protocol: Protocol,
        channel: &watch::Receiver<Option<DialOutcome>>,
    ) {
        let mut dialing = self.inner.dialing.lock().await;
        if let Some(current) = dialing.get(&protocol)
            && current.same_channel(channel)
        {
            dialing.remove(&protocol);
        }
    }

    /// Dials the backend and puts the connection in the pool.
    async fn dial(
        &self,
        protocol: Protocol,
    ) -> Result<(Connection, Arc<BorrowState>), crate::error::ClientError> {
        let ep = self.endpoint().await.ok_or_else(|| {
            crate::error::ClientError::InvalidConfig("Endpoint has been closed".to_string())
        })?;

        let authenticated = self
            .connect_and_auth(&ep, CONNECTION_TIMEOUT, protocol)
            .await?;
        let conn = authenticated.conn.clone();
        let paths = Arc::new(PathHealth::default());
        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone(), paths.clone());

        let state = Arc::new(BorrowState::new());
        match self
            .pool_connection(
                conn.clone(),
                state.clone(),
                protocol,
                authenticated.generation,
                paths,
            )
            .await
        {
            Ok(()) => Ok((conn, state)),
            // The pool is full, so the connection was closed on the spot.
            // Handing it out would be handing out a connection that is
            // already closed.
            //
            // **Its own variant, because it says nothing about the backend.**
            // The backend answered the handshake and is holding the
            // connections it already has; it is this process that ran out of
            // its own slots. A caller that keeps a health table must not
            // read this as the backend being down.
            Err(PoolRefusal::Full) => Err(ClientError::PoolFull(
                "the connection pool is full for this protocol".to_string(),
            )),
            Err(PoolRefusal::Closed) => Err(ClientError::ConnectionFailed(
                "the connection was closed as soon as it was established".to_string(),
            )),
            // The credential was replaced while the handshake was running:
            // the connection is authenticated as an identity that is gone,
            // and it was closed rather than pooled.
            //
            // **Its own variant, because it says nothing about the backend.**
            // A rotation on this side raced the dial; the backend did what
            // it was asked to do.
            Err(PoolRefusal::Replaced) => Err(ClientError::CredentialReplaced(
                "the credential was replaced while the connection was being made".to_string(),
            )),
        }
    }

    /// Ensure at least one live connection to the backend is cached in the
    /// pool, establishing one if the pool is empty. Used for pre-connect /
    /// warm-up so the first real request does not pay the QUIC/relay handshake
    /// latency. Returns true if a connection is available in the pool
    /// afterwards.
    pub async fn preconnect(&self) -> bool {
        {
            let connections = self.inner.connections.lock().await;
            if let Some(pooled) = connections.last()
                && pooled.is_live()
            {
                return true;
            }
        }

        // One deadline for the whole preconnect. The observation below is part
        // of it, not a wait that starts once the connect is over: a backend that
        // was merely slow used to be cancelled in the middle of that
        // observation and reported unreachable.
        let started = tokio::time::Instant::now();
        let deadline = started + PRECONNECT_TIMEOUT;

        let authenticated = {
            let Some(ep) = self.endpoint().await else {
                return false;
            };
            match tokio::time::timeout_at(
                deadline,
                self.connect_and_auth(&ep, PRECONNECT_CONNECT_TIMEOUT, Protocol::Http),
            )
            .await
            {
                Ok(Ok(authenticated)) => authenticated,
                Ok(Err(e)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("preconnect to {} failed: {}", self.backend_id(), e);
                    #[cfg(not(feature = "tracing"))]
                    let _ = &e;
                    return false;
                }
                Err(_) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("preconnect timed out");
                    return false;
                }
            }
        };
        let Authenticated { conn, generation } = authenticated;

        // A client without credentials never opens the auth stream, so a
        // completed QUIC handshake tells it nothing: whether the connection can
        // ever carry traffic is the server's call, and it answers by closing
        // once its handshake deadline passes. Watch for that instead of
        // reporting a connection the server already refused as a warm one.
        if self.inner.two_factor.lock().await.is_none() {
            // Only what is left of the budget, so the observation is never what
            // pushes the preconnect past it. It still gets the whole grace
            // whenever the connect kept to its own, which is the case that has
            // to work.
            let grace =
                AUTH_REQUIRED_GRACE.min(PRECONNECT_TIMEOUT.saturating_sub(started.elapsed()));
            if let Some(reason) = wait_for_auth_required(&conn, grace).await {
                #[cfg(feature = "tracing")]
                tracing::warn!("preconnect refused by the server: {}", reason);
                #[cfg(not(feature = "tracing"))]
                let _ = &reason;
                *self.inner.auth_required.lock().await = Some(reason);
                return false;
            }
        }

        let paths = Arc::new(PathHealth::default());
        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone(), paths.clone());
        self.pool_connection(
            conn,
            Arc::new(BorrowState::new()),
            Protocol::Http,
            generation,
            paths,
        )
        .await
        .is_ok()
    }

    /// Puts a connection in the pool.
    ///
    /// Called when a connection is **established**, not when a flow ends: the
    /// pool keeps the connection and the flows borrow it, so there is nothing
    /// to give back at the end of a flow.
    ///
    /// `generation` is the generation of the credential the connection was
    /// authenticated under, and it is what says whether the connection still
    /// stands for the pool's identity.
    ///
    /// Returns why the connection could not be pooled — it was already
    /// closed, the pool is full, or the credential it was authenticated
    /// under has been replaced. The caller has to know: handing out a
    /// connection that was closed on the spot is handing out a failure.
    pub(super) async fn pool_connection(
        &self,
        conn: Connection,
        state: Arc<BorrowState>,
        protocol: Protocol,
        generation: u64,
        paths: Arc<PathHealth>,
    ) -> Result<(), PoolRefusal> {
        // Never pool a connection that has already been closed: handing it out
        // again would just fail on the next request. The background watcher also
        // reaps such connections, but checking here avoids re-inserting them.
        if conn.close_reason().is_some() {
            return Err(PoolRefusal::Closed);
        }

        let mut connections = self.inner.connections.lock().await;
        // **Whose identity is this connection?**
        //
        // The generation is compared under the lock that holds the pool, so
        // the comparison and the pooling are one step: a credential that is
        // replaced while the connection is on its way in cannot slip
        // between them.
        //
        // A connection of an older generation was authenticated as an
        // identity that is gone — the credential was replaced while its
        // handshake was running. It is closed rather than pooled: it would
        // carry traffic under an identity the operator has replaced, and
        // handing it out would hand that identity out with it.
        if self.inner.credential_generation.load(Ordering::Acquire) != generation {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "the credential to {} was replaced while the connection was being made; closing it",
                self.backend_id()
            );
            conn.close(0u32.into(), b"the credential was replaced");
            return Err(PoolRefusal::Replaced);
        }
        if may_pool(protocol, connections.iter().map(|pooled| pooled.protocol)) {
            connections.push(PooledConnection {
                conn,
                state,
                protocol,
                paths,
            });
            return Ok(());
        }

        // This protocol's own connections are at the ceiling, so this one is
        // closed on the spot. Dropping the handle would close it just as
        // surely, but silently: the peer would see a connection that vanished
        // with no reason attached, which is indistinguishable from a crash on
        // this side.
        //
        // **Nothing is riding it**: a connection is pooled the moment it is
        // established, and the flows that borrow it are counted on its entry.
        // The pool holds one connection per protocol in practice — the second
        // one only arrives when the first is full or has died — so this is the
        // tail of a tail.
        #[cfg(feature = "tracing")]
        tracing::debug!(
            "Connection pool is full for {} ({} connections), closing the connection that came back",
            protocol.name(),
            MAX_CONNECTIONS_PER_PROTOCOL
        );
        conn.close(0u32.into(), b"connection pool full");
        Err(PoolRefusal::Full)
    }
}

/// Waits for a backend that demands 2FA to say so.
///
/// Returns the reason the server gave when it closes the connection with
/// [`AUTH_REQUIRED_CLOSE_CODE`], and `None` when the connection stays up — or
/// dies for any other reason, which is not what this is looking for.
/// `grace` is however much of the preconnect budget is left rather than
/// [`AUTH_REQUIRED_GRACE`] itself: the caller owns the deadline, so it decides
/// how much of it this wait may spend. Passing the full constant is only right
/// when the connect has kept to its own budget.
async fn wait_for_auth_required(conn: &Connection, grace: tokio::time::Duration) -> Option<String> {
    let closed = tokio::select! {
        _ = tokio::time::sleep(grace) => return None,
        error = conn.closed() => error,
    };

    match closed {
        iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == AUTH_REQUIRED_CLOSE_CODE as u64 =>
        {
            Some(String::from_utf8_lossy(&close.reason).into_owned())
        }
        _ => None,
    }
}

/// The text to show when the server's `[peers]` allow-list refused this Node ID.
///
/// Read off the `connect` failure rather than a connection, because the refusal
/// happens inside the QUIC handshake: `after_handshake` closes with
/// [`PEER_NOT_ALLOWED_CLOSE_CODE`] and the connection is never handed to the
/// client at all. iroh surfaces that as an `ApplicationClosed` carrying the
/// code, so matching on it here is the only place the client can learn why.
fn peer_not_allowed_reason(error: &iroh::endpoint::ConnectError) -> Option<String> {
    let iroh::endpoint::ConnectError::Connection { source, meta: _ } = error else {
        return None;
    };
    let iroh::endpoint::ConnectionError::ApplicationClosed(close) = source else {
        return None;
    };
    if close.error_code.into_inner() != PEER_NOT_ALLOWED_CLOSE_CODE as u64 {
        return None;
    }
    Some(String::from_utf8_lossy(&close.reason).into_owned())
}
