//! A server-side allow-list of client public keys.
//!
//! The per-peer cap in [`super::limits`] answers *how much* a peer may open; 2FA
//! in [`super`] answers *who* a peer is; this answers *whether it may be here at
//! all*, and it is the only one of the three that runs before the QUIC handshake
//! has finished.
//!
//! Without it the Node ID is a reachability credential and nothing else is
//! checked: on a server started with `[auth] enabled = false` — which is the
//! default, and what `config.toml.example` ships — anybody who learns the Node
//! ID (or holds a ticket) completes the handshake and reaches every route. 2FA,
//! when it is on, closes that by demanding an HMAC over the connection's nonce
//! keyed with the client's secret, but it is a second factor the operator has to
//! turn on; this one is checked unconditionally when it is configured.
//!
//! The check lives in [`EndpointHooks::after_handshake`] rather than in the
//! accept loop, which buys one property worth stating: rejecting here happens
//! *before* [`iroh::endpoint::Endpoint::accept`] ever yields the connection, so a
//! refused peer never reaches `handle_incoming`, never takes a
//! [`super::limits::ConnectionLimiter`] slot and never gets a task. That is
//! strictly cheaper than any gate built on top of the accept, which is why the
//! comparison is not simply folded into `handle_incoming` where the other two
//! already are.
//!
//! `before_connect` is the wrong hook: it exists for *outgoing* connections and
//! is called from `Endpoint::connect`, so it can never see an inbound peer.

use iroh::EndpointId;
use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks};
use std::collections::HashSet;

/// Which peers may hold a connection at all.
///
/// `None` means no allow-list is configured and every peer passes — the
/// behaviour of every build before this feature, kept as the default so an
/// operator who never writes `[peers]` sees nothing change.
#[derive(Debug)]
pub struct PeerAllowList {
    allowed: Option<HashSet<EndpointId>>,
}

/// The close code a refused peer is sent, in the same register as the 2FA ones
/// in `auth_close_code`.
///
/// It travels in the CONNECTION_CLOSE frame, so the client can read it and say
/// "this Node ID is not in the server's allow list" rather than reporting a
/// mysterious connection loss.
///
/// The number lives in [`nexapipe_proto::auth::close_code`], which the client
/// links too: it used to be written down here and kept in step with the
/// client's copy by hand, exactly like the codes it sits next to.
pub use nexapipe_proto::auth::close_code::PEER_NOT_ALLOWED as PEER_NOT_ALLOWED_CLOSE_CODE;

/// The reason sent with [`PEER_NOT_ALLOWED_CLOSE_CODE`].
///
/// A fixed string that reflects nothing about the peer: the refusal is
/// diagnosable without telling a scanner whether a given Node ID is close to one
/// on the list, the same rule `perform_authentication` follows with its single
/// "Invalid TOTP code".
const PEER_NOT_ALLOWED_REASON: &[u8] = b"this peer is not in the server's allow list";

impl PeerAllowList {
    /// Wraps the configured Node IDs. `None` or an empty set is the "no
    /// restriction" case; a caller that wants to refuse everybody passes a set
    /// containing an id no peer can hold.
    pub fn new(allowed: Option<HashSet<EndpointId>>) -> Self {
        Self { allowed }
    }

    /// Whether an allow-list is configured at all.
    pub fn is_configured(&self) -> bool {
        self.allowed.is_some()
    }

    /// Whether the configured list is empty, i.e. refuses every peer.
    ///
    /// Unreachable through the config file — an empty `allow` is rejected at load
    /// time — but the type still has to answer the question a `len` method makes
    /// a reader ask.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many peers are on the list, for the startup log.
    pub fn len(&self) -> usize {
        self.allowed.as_ref().map_or(0, HashSet::len)
    }

    /// Whether `peer` may hold a connection.
    ///
    /// Split out from the hook so the policy is testable without an iroh
    /// endpoint: the hook is an `async fn` on a live [`Connection`], which no
    /// test can construct, while this is a set lookup.
    pub fn allows(&self, peer: &EndpointId) -> bool {
        match &self.allowed {
            Some(allowed) => allowed.contains(peer),
            // No list configured: every peer passes, which is what makes this
            // feature opt-in.
            None => true,
        }
    }
}

impl EndpointHooks for PeerAllowList {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let peer = conn.remote_id();
        if self.allows(&peer) {
            return AfterHandshakeOutcome::accept();
        }

        tracing::warn!("Refusing connection from {peer}: it is not in the [peers] allow list");
        AfterHandshakeOutcome::Reject {
            error_code: PEER_NOT_ALLOWED_CLOSE_CODE.into(),
            reason: PEER_NOT_ALLOWED_REASON.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer id to check against.
    ///
    /// Derived from a secret key rather than written out as bytes: an
    /// `EndpointId` is an ed25519 public key, and arbitrary bytes are not one.
    fn peer(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// The default has to stay permissive: every deployment that predates this
    /// feature has no `[peers]` section, and none of them may start refusing
    /// connections after an upgrade.
    #[test]
    fn no_list_configured_lets_every_peer_through() {
        let list = PeerAllowList::new(None);

        assert!(!list.is_configured());
        assert!(list.allows(&peer(1)));
        assert!(list.allows(&peer(2)));
    }

    #[test]
    fn a_configured_list_lets_only_its_members_through() {
        let allowed = HashSet::from([peer(1), peer(2)]);
        let list = PeerAllowList::new(Some(allowed));

        assert!(list.is_configured());
        assert_eq!(list.len(), 2);
        assert!(list.allows(&peer(1)));
        assert!(list.allows(&peer(2)));
        assert!(!list.allows(&peer(3)));
    }

    /// A configured but empty list refuses everybody. Unreachable through the
    /// config file — an empty `allow` is rejected at parse time, because
    /// "restrict to nobody" written by accident locks the operator out of their
    /// own server — but the type still has to mean something, and this is it.
    #[test]
    fn a_configured_empty_list_refuses_everybody() {
        let list = PeerAllowList::new(Some(HashSet::new()));

        assert!(list.is_configured());
        assert_eq!(list.len(), 0);
        assert!(!list.allows(&peer(1)));
    }

    /// The close code has to stay distinct from the 2FA ones: a client that sees
    /// it must not conclude "I sent a bad TOTP code" and rotate a working
    /// secret.
    #[test]
    fn the_close_code_is_distinct_from_the_2fa_ones() {
        assert!(![2, 3, 4].contains(&PEER_NOT_ALLOWED_CLOSE_CODE));
    }
}
