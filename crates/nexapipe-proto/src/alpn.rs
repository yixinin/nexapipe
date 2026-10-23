//! The ALPN identifiers the client and the server agree on.
//!
//! The ALPN is the name QUIC's protocol negotiation carries. It travels in the
//! Initial packet, where a middlebox on the path can read it, which makes it a
//! fingerprint of this protocol on the wire — and a fingerprint is all it was
//! ever meant to be.
//!
//! It used to be `b"\x05nexapipe"`: the L4 preface's first byte in front of the
//! name. That byte was never part of a length encoding. The preface's magic
//! byte is [`crate::PREFACE_MAGIC`], and it is read off the **stream**, long after
//! the ALPN has been agreed; the ALPN is a name, not a header. Putting the
//! byte in front of the name made the protocol a nine-byte string that began
//! with a control byte, and it bought nothing.
//!
//! Both spellings live here because the two ends have to agree on one of them,
//! and the agreement is exactly the kind of thing that costs a connection when
//! one side grows a constant and the other does not:
//!
//! * the **server** accepts both — its list is ordered current-first, and
//!   QUIC picks the first of the *server's* entries that the client also
//!   offers;
//! * the **client** offers the current one, and the legacy one as an
//!   additional ALPN, so it reaches a server of either vintage.
//!
//! The legacy spelling goes once nothing in the field speaks it any more.

/// The ALPN this build speaks.
///
/// The name, and nothing else.
pub const ALPN_NEXAPIPE: &[u8] = b"nexapipe";

/// The ALPN clients built before the prefix byte was dropped use.
///
/// The server accepts it so that a client of the older vintage still reaches
/// it, and the client offers it so that it still reaches a server of the older
/// vintage. Drop it once neither is true.
pub const ALPN_NEXAPIPE_LEGACY: &[u8] = b"\x05nexapipe";

/// Both spellings, current first.
///
/// The **server's** order is what decides the negotiation: QUIC picks the first
/// of the accept side's entries that the peer also offers. So the current
/// spelling has to be first here, and the client's own offer order does not
/// matter — what the client does is *offer* both.
pub const ALPN_NEXAPIPE_ALL: [&[u8]; 2] = [ALPN_NEXAPIPE, ALPN_NEXAPIPE_LEGACY];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_alpn_is_the_name_alone() {
        assert_eq!(ALPN_NEXAPIPE, b"nexapipe");
    }

    #[test]
    fn the_legacy_alpn_is_the_name_with_the_prefix_byte() {
        assert_eq!(ALPN_NEXAPIPE_LEGACY, b"\x05nexapipe");
        // The prefix byte is the preface's magic byte, and it is not part of a
        // length encoding — it is the first byte of the *stream*.
        assert_eq!(ALPN_NEXAPIPE_LEGACY[0], crate::PREFACE_MAGIC);
    }

    #[test]
    fn the_current_alpn_is_offered_first() {
        // The accept side's order is what QUIC negotiates on, so this list has
        // to start with the current spelling.
        assert_eq!(ALPN_NEXAPIPE_ALL[0], ALPN_NEXAPIPE);
        assert_eq!(ALPN_NEXAPIPE_ALL[1], ALPN_NEXAPIPE_LEGACY);
    }
}
