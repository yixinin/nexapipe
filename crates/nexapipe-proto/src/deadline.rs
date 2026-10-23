//! The phase budgets the client and the server both use.
//!
//! # Why this is here and not in either of them
//!
//! Three of these numbers were written down twice — once in the server and
//! once in the client — and the client's copy said so itself: *"the constants
//! are therefore restated rather than imported, and a change to one side has
//! to be made on the other by hand."* Hand-syncing a number is the same
//! failure mode as hand-syncing a protocol, one size smaller: the two ends
//! disagree about how long a phase lasts, and nothing reports it.
//!
//! The three that are shared are the ones a phase's length is the same
//! everywhere: how long a request head may take to arrive, how long a TLS
//! ClientHello may take to arrive, and how long an established stream may
//! run. The rest — a body budget, an idle timeout — are one side's own
//! business and stay there.
//!
//! # What a budget is for
//!
//! A **phase deadline** is taken once and shared by every read inside it, so a
//! client that trickles a byte before each expiry renews nothing. An **idle
//! timeout** re-arms on every read, and is correct only where the phase is
//! meant to stay open — a CONNECT tunnel to a backend that is working, for
//! instance. The distinction is the server's module's; the client draws it
//! too, and the numbers below are the same either way.

/// Seconds the client may take to send its request head.
///
/// One value for the whole head, not per read. The local proxy reads until it
/// finds `\r\n\r\n`, and a per-read timeout there is exactly what a client
/// that sends one byte of `Host:` every twenty seconds wants: the read that
/// arrives resets the clock, so the connection, its task and its slot stay
/// pinned to a client that is never going to finish.
pub const HEADER_SECS: u64 = 30;

/// Seconds a TLS ClientHello may take to arrive.
///
/// The client sends a five-byte record header and then the record body. Reading
/// the header tells us how long the body is, and the read that fetched it had
/// no bound at all — so a client that sent the five bytes and nothing else
/// held the connection open indefinitely.
pub const TLS_HELLO_SECS: u64 = 10;

/// Seconds a proxied byte copy may run before it is abandoned.
///
/// Long by design: this covers an established CONNECT tunnel or a raw TCP
/// flow, where silence is normal and the session is meant to last. It exists
/// so that a copy loop cannot hold its resources for the life of the process,
/// not to shape traffic.
pub const STREAM_SECS: u64 = 3600;

#[cfg(test)]
mod tests {
    use super::*;

    /// The three that are shared, and the two that are not: a budget that
    /// changed on one side only is the thing this module exists to stop.
    #[test]
    fn the_shared_budgets_are_the_ones_both_sides_agree_on() {
        assert_eq!(HEADER_SECS, 30);
        assert_eq!(TLS_HELLO_SECS, 10);
        assert_eq!(STREAM_SECS, 3600);
    }
}
