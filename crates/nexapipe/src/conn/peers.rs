//! Who is connected right now.
//!
//! The metrics module counts connections — how many, and over what kind of
//! path — but a count cannot answer "is *this* peer here", which is what the
//! management surface is asked. This is the other half: the set of peers being
//! served, with what is known about each.
//!
//! # Why a guard and not an explicit removal
//!
//! A connection ends in more ways than it has `return`s: the peer goes away,
//! a stream errors, the task is cancelled, authentication is refused. Each of
//! those would need its own removal call, and one missed would leave a peer
//! listed as connected forever. [`PeerGuard`] takes it out of the map on
//! `Drop` instead, the same way [`crate::shutdown::InFlightGuard`] reports a
//! connection as no longer in flight.
//!
//! # Why every connection is its own entry
//!
//! One peer can hold two connections at once: a reconnect that lands before the
//! connection it replaces has finished going away. Each gets an entry of its
//! own, with its own `connected_for`, because "how long has this one been open"
//! is a question about a connection and not about a peer. The alternative —
//! one entry per endpoint id, overwritten on the second `insert` — loses the
//! first connection the moment the second ends, listing a peer that is still
//! connected as no longer connected.
//!
//! Entries are still grouped by endpoint id, because that is what an operator
//! recognises: a Node ID they can compare against their client list.
//!
//! # How revocation reaches a connection that is already open
//!
//! Striking a credential out of `[auth]` must stop the traffic it is carrying
//! now, not only its next dial — otherwise removing a device changes what it
//! can do later and nothing else. Each entry therefore carries the sending half
//! of a [`tokio::sync::watch`] channel the connection task owns the other half
//! of: [`PeerRegistry::close_where`] flips it, and the task, which is the only
//! holder of the [`Connection`](iroh::endpoint::Connection), is what actually
//! closes.
//!
//! A signal rather than a connection handle, because owning the socket from two
//! places means either can close it and neither learns about it — and because a
//! `watch::Sender` can be created in a test without an endpoint to dial.
//! [`PeerRegistry::insert`] takes the sender, so nothing here knows or cares
//! how the task ends once told.
use crate::metrics::PathKind;
use iroh::EndpointId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// What [`PeerRegistry::insert`] takes to be able to reach a connection later.
///
/// `false` is "keep serving"; [`PeerRegistry::close_where`] sends `true`, and
/// the connection task closes itself and returns.
pub type Revoked = watch::Sender<bool>;

/// A sender the task created, for the caller that does not have a real
/// connection to hand to [`PeerRegistry::insert`]: every test here cares about
/// who is listed, and none about revoking.
#[cfg(test)]
fn no_signal() -> Revoked {
    watch::channel(false).0
}

/// Who a connection authenticated as.
///
/// Both halves, because a client id on its own cannot tell two devices of the
/// same client apart, and telling them apart is the only thing per-device
/// credentials are for. `None` is the honest answer for a connection that was
/// never asked to authenticate: 2FA is optional, and a peer that connects with
/// it off has no identity to report — the same as a device that has no name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The client id the handshake was answered for.
    pub client_id: Option<String>,
    /// The device name it sent, `None` for the device that has none.
    pub device: Option<String>,
}

/// One peer currently being served.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's endpoint id, as it is printed everywhere else.
    pub endpoint_id: EndpointId,
    /// How long this connection has been open.
    pub connected_for: Duration,
    /// How its traffic is currently reaching us.
    pub path: PathKind,
    /// Who it authenticated as, if anybody asked it to.
    pub identity: PeerIdentity,
}

/// What the registry keeps per connection.
#[derive(Debug, Clone)]
struct Peer {
    /// Tells two connections from the same peer apart, so ending one does not
    /// end the other. Never reused.
    id: u64,
    since: Instant,
    path: PathKind,
    identity: PeerIdentity,
    /// Flipped when `[auth]` stops carrying the credential this connection
    /// authenticated with. The task watching the other end owns the socket and
    /// does the closing; nothing else here touches it.
    revoked: Revoked,
}

/// The set of peers with a connection being served right now.
///
/// Cloning shares the map rather than copying it, so it can be handed to the
/// listener and to every connection task without either outliving the other.
#[derive(Debug, Clone, Default)]
pub struct PeerRegistry {
    peers: Arc<RwLock<HashMap<EndpointId, Vec<Peer>>>>,
    /// Hands out the ids that keep one connection's `Drop` from taking another
    /// connection's entry with it.
    next_id: Arc<AtomicU64>,
}

impl PeerRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a peer, and returns the guard that takes it out again.
    ///
    /// Called once the connection is actually being served — after the 2FA
    /// handshake — because a peer that was refused is not connected, and
    /// listing it would make "who is connected" include peers that were turned
    /// away.
    ///
    /// `revoked` is how this entry is later reached; see [`Self::close_where`].
    pub fn insert(
        &self,
        endpoint_id: EndpointId,
        path: PathKind,
        identity: PeerIdentity,
        revoked: Revoked,
    ) -> PeerGuard {
        // Starts at 1 so a default-initialised id is never a real one.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let mut peers = write(&self.peers);
        peers.entry(endpoint_id).or_default().push(Peer {
            id,
            since: Instant::now(),
            path,
            identity,
            revoked,
        });
        PeerGuard {
            registry: self.clone(),
            endpoint_id,
            id,
        }
    }

    /// Moves a peer's connections to another path, because hole punching
    /// succeeded or the direct path was lost.
    ///
    /// Every connection under the endpoint id moves together. Two connections
    /// from one peer share a socket and therefore a fate — one does not punch
    /// through while the other stays relayed — and the event that reports the
    /// change does not say which connection it belongs to.
    ///
    /// A no-op for a peer that is not in the map: the task that follows path
    /// events outlives the handshake, so between a refused connection and its
    /// removal it can still be told about a path.
    pub fn set_path(&self, endpoint_id: &EndpointId, path: PathKind) {
        if let Some(peers) = write(&self.peers).get_mut(endpoint_id) {
            for peer in peers.iter_mut() {
                peer.path = path;
            }
        }
    }

    /// Signals every connection whose identity `matches`, and reports how many.
    ///
    /// This is how revocation reaches a credential that is already connected:
    /// `nexapipe client revoke` edits the config, the next reload notices what
    /// is gone from `[auth]`, and this tells anything that authenticated as it
    /// to stop. The connection tasks do the closing themselves — they own the
    /// sockets — so how many are counted here is how many were told, which is
    /// not the same instant as how many have finished going away.
    ///
    /// Nothing is removed from the map: the task ends on its own and its
    /// [`PeerGuard`] takes the entry out, exactly as for any other ending.
    pub fn close_where(&self, matches: impl Fn(&PeerIdentity) -> bool) -> usize {
        // A read lock, and `send_replace` does not await: revocation must not
        // queue behind anything long enough for the answer to stop being
        // useful, and the tasks being told to stop are trying to take the write
        // lock themselves to drop their entries.
        let mut signaled = 0;
        for peer in read(&self.peers).values().flatten() {
            if matches(&peer.identity) {
                peer.revoked.send_replace(true);
                signaled += 1;
            }
        }
        signaled
    }

    /// Every connection, oldest first within an endpoint id so the answer is
    /// stable between two calls that saw nothing change.
    pub fn snapshot(&self) -> Vec<PeerInfo> {
        let peers = read(&self.peers);
        let mut entries: Vec<(EndpointId, Peer)> = peers
            .iter()
            .flat_map(|(endpoint_id, entries)| {
                entries.iter().map(move |peer| (*endpoint_id, peer.clone()))
            })
            .collect();
        // Ordered by when a connection was added, not by how long it has been
        // open: `since` is fixed at insert time, whereas a lifetime read from a
        // clock moves between two entries, so two calls a moment apart could
        // order them differently.
        entries.sort_by_key(|(_, peer)| peer.since);
        // One reading for every entry, taken before any of them are measured.
        // Reading the clock per entry instead compares two lives that were
        // taken at different moments: the gap between them is the gap between
        // the two reads subtracted from the gap between the two inserts, which
        // is negative whenever a write maps slower than a peer reconnects — a
        // preemption between the two `elapsed()` calls is enough, so this is
        // the listing reporting an older connection as younger under load, and
        // nothing about either connection has changed. A snapshot answers what
        // was true at one instant; reading the clock once is what makes it one.
        let now = Instant::now();
        entries
            .into_iter()
            .map(|(endpoint_id, peer)| PeerInfo {
                endpoint_id,
                connected_for: now.duration_since(peer.since),
                path: peer.path,
                identity: peer.identity.clone(),
            })
            .collect()
    }

    /// How many connections are being served, which is how many entries
    /// [`Self::snapshot`] returns. One peer reconnecting while its old
    /// connection is still going away counts twice.
    pub fn len(&self) -> usize {
        read(&self.peers).values().map(Vec::len).sum()
    }

    /// Whether anybody is connected.
    pub fn is_empty(&self) -> bool {
        read(&self.peers).values().all(Vec::is_empty)
    }

    fn remove(&self, endpoint_id: &EndpointId, id: u64) {
        let mut peers = write(&self.peers);
        let empty = match peers.get_mut(endpoint_id) {
            Some(entries) => {
                entries.retain(|peer| peer.id != id);
                entries.is_empty()
            }
            None => false,
        };
        // The key goes with its last connection, or `is_empty` would have to
        // look inside every entry to answer.
        if empty {
            peers.remove(endpoint_id);
        }
    }
}

/// One peer's place in the registry, released when the connection ends.
#[derive(Debug)]
pub struct PeerGuard {
    registry: PeerRegistry,
    endpoint_id: EndpointId,
    id: u64,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.endpoint_id, self.id);
    }
}

/// Takes the write lock, or poisons it.
///
/// Panicking on a poisoned lock rather than swallowing it: the map is only ever
/// read and written in a few lines that cannot panic in between, so a poisoned
/// lock means a bug elsewhere, and silently serving a stale peer list would
/// hide it.
fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

/// Takes the read lock, or recovers from a poisoned one. See [`read`].
fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two different endpoint ids, because two entries are what "a set" tests.
    fn ids() -> (EndpointId, EndpointId) {
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        (a, b)
    }

    /// A peer is listed from the moment it is inserted, and gone once the guard
    /// is dropped: the whole contract of the guard is that no early return can
    /// leave one behind.
    #[test]
    fn a_peer_is_listed_only_while_its_guard_lives() {
        let registry = PeerRegistry::new();
        let (a, b) = ids();

        let guard_a = registry.insert(a, PathKind::Relay, PeerIdentity::default(), no_signal());
        let _guard_b = registry.insert(b, PathKind::Direct, PeerIdentity::default(), no_signal());
        assert_eq!(registry.len(), 2);

        drop(guard_a);
        let listed = registry.snapshot();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].endpoint_id, b);
        assert_eq!(listed[0].path, PathKind::Direct);
    }

    /// A peer that reconnects before its old connection has finished going away
    /// holds two connections at once, and ending the newer one must not take
    /// the older with it. This is what per-connection entries are for: with one
    /// entry per endpoint id, the second `insert` would overwrite the first and
    /// that connection's `Drop` would remove it, listing a peer as gone while
    /// it is still being served.
    #[test]
    fn a_second_connection_from_one_peer_does_not_end_the_first() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        let first = registry.insert(a, PathKind::Relay, PeerIdentity::default(), no_signal());
        let second = registry.insert(a, PathKind::Direct, PeerIdentity::default(), no_signal());
        assert_eq!(registry.len(), 2, "one peer, two connections");

        drop(second);
        let listed = registry.snapshot();
        assert_eq!(
            listed.len(),
            1,
            "the first connection went away with the second"
        );
        assert_eq!(listed[0].endpoint_id, a);
        assert_eq!(listed[0].path, PathKind::Relay);

        drop(first);
        assert!(registry.is_empty(), "the peer outlived its last connection");
    }

    /// The list is oldest first, and the order does not depend on when this
    /// runs: `connected_for` is measured while the snapshot is taken, so
    /// ordering by it would list a reconnect above the connection it follows.
    #[test]
    fn a_reconnect_is_listed_after_the_connection_it_follows() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        let first = registry.insert(a, PathKind::Relay, PeerIdentity::default(), no_signal());
        let second = registry.insert(a, PathKind::Direct, PeerIdentity::default(), no_signal());

        let listed = registry.snapshot();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].path, PathKind::Relay, "the newer came first");
        assert_eq!(listed[1].path, PathKind::Direct);
        assert!(
            listed[0].connected_for >= listed[1].connected_for,
            "the older connection reports a shorter life: {:?} then {:?}",
            listed[0].connected_for,
            listed[1].connected_for
        );

        drop(first);
        drop(second);
    }

    /// Two devices of one client differ only by the name they answered under,
    /// which is why the identity is carried as both halves: a client id on its
    /// own cannot tell them apart, and telling them apart is the whole of what
    /// a per-device credential is for.
    #[test]
    fn two_devices_of_one_client_are_told_apart_by_name() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        let laptop = PeerIdentity {
            client_id: Some("alice".to_string()),
            device: Some("laptop".to_string()),
        };
        let phone = PeerIdentity {
            client_id: Some("alice".to_string()),
            device: Some("phone".to_string()),
        };

        let _first = registry.insert(a, PathKind::Relay, laptop, no_signal());
        let _second = registry.insert(a, PathKind::Direct, phone, no_signal());

        let listed = registry.snapshot();
        assert_eq!(listed[0].identity.client_id.as_deref(), Some("alice"));
        assert_eq!(listed[0].identity.device.as_deref(), Some("laptop"));
        assert_eq!(listed[1].identity.client_id.as_deref(), Some("alice"));
        assert_eq!(listed[1].identity.device.as_deref(), Some("phone"));
    }

    /// The path is updated in place, because a connection that starts relayed
    /// and hole punches is still one peer.
    #[test]
    fn a_peer_stays_one_entry_when_its_path_changes() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        let _guard = registry.insert(a, PathKind::Relay, PeerIdentity::default(), no_signal());
        registry.set_path(&a, PathKind::Direct);

        let listed = registry.snapshot();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, PathKind::Direct);
    }

    /// Updating a peer that was already removed must not put it back: the path
    /// task outlives the connection it was started for.
    #[test]
    fn a_path_change_does_not_resurrect_a_removed_peer() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        drop(registry.insert(a, PathKind::Relay, PeerIdentity::default(), no_signal()));
        registry.set_path(&a, PathKind::Direct);

        assert!(registry.is_empty(), "a removed peer came back");
    }

    /// Revoking one device leaves its siblings untouched, which is the whole
    /// point of the table: `client revoke <id> --device laptop` must not reach
    /// `phone`, and must not reach the device that names none either — that one
    /// authenticates against the client's own `secret`, not a device entry.
    #[test]
    fn revoking_one_device_leaves_the_others_alone() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        let laptop = PeerIdentity {
            client_id: Some("alice".to_string()),
            device: Some("laptop".to_string()),
        };
        let phone = PeerIdentity {
            client_id: Some("alice".to_string()),
            device: Some("phone".to_string()),
        };
        let unnamed = PeerIdentity {
            client_id: Some("alice".to_string()),
            device: None,
        };

        let (laptop_tx, mut laptop_rx) = watch::channel(false);
        let (phone_tx, mut phone_rx) = watch::channel(false);
        let (unnamed_tx, mut unnamed_rx) = watch::channel(false);

        let laptop = registry.insert(a, PathKind::Relay, laptop, laptop_tx);
        let phone = registry.insert(a, PathKind::Direct, phone, phone_tx);
        let unnamed = registry.insert(a, PathKind::Direct, unnamed, unnamed_tx);

        let closed = registry.close_where(|identity| identity.device.as_deref() == Some("laptop"));
        assert_eq!(closed, 1, "only the one device was signaled");

        assert!(*laptop_rx.borrow_and_update(), "laptop was not signaled");
        assert!(!*phone_rx.borrow_and_update(), "phone was signaled too");
        assert!(
            !*unnamed_rx.borrow_and_update(),
            "the unnamed device was signaled too"
        );

        // Still listed: being told to stop and having stopped are two moments,
        // and the second is the task's to report by dropping its guard.
        assert_eq!(registry.len(), 3);
        drop((laptop, phone, unnamed));
    }

    /// Striking the whole client out reaches every device under it, including
    /// the device that has no name: it answered with the client's own `secret`,
    /// and that secret is what goes.
    #[test]
    fn revoking_a_client_reaches_every_device_under_it() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        let (_device_tx, mut device_rx) = watch::channel(false);
        let (_unnamed_tx, mut unnamed_rx) = watch::channel(false);
        let (_other_tx, mut other_rx) = watch::channel(false);

        let device = registry.insert(
            a,
            PathKind::Relay,
            PeerIdentity {
                client_id: Some("alice".to_string()),
                device: Some("laptop".to_string()),
            },
            _device_tx,
        );
        let unnamed = registry.insert(
            a,
            PathKind::Direct,
            PeerIdentity {
                client_id: Some("alice".to_string()),
                device: None,
            },
            _unnamed_tx,
        );
        let other = registry.insert(
            a,
            PathKind::Direct,
            PeerIdentity {
                client_id: Some("bob".to_string()),
                device: None,
            },
            _other_tx,
        );

        let closed =
            registry.close_where(|identity| identity.client_id.as_deref() == Some("alice"));
        assert_eq!(closed, 2, "every device of alice, and only those");

        assert!(*device_rx.borrow_and_update());
        assert!(*unnamed_rx.borrow_and_update());
        assert!(!*other_rx.borrow_and_update(), "bob was signaled too");

        drop((device, unnamed, other));
    }

    /// A peer that never authenticated has nothing to revoke, so the answer is
    /// nothing to close rather than everybody: 2FA is optional, and a
    /// connection with no identity is not a connection `revoke` can name.
    #[test]
    fn revocation_skips_connections_that_named_nobody() {
        let registry = PeerRegistry::new();
        let (a, _) = ids();

        let (_tx, mut rx) = watch::channel(false);
        let unnamed = registry.insert(a, PathKind::Relay, PeerIdentity::default(), _tx);

        let closed =
            registry.close_where(|identity| identity.client_id.as_deref() == Some("alice"));
        assert_eq!(closed, 0);
        assert!(!*rx.borrow_and_update());

        drop(unnamed);
    }
}
