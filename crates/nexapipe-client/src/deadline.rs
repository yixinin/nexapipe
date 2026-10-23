//! How long each phase of a local proxied connection may take.
//!
//! The client's counterpart to the server's `deadline` module, and deliberately
//! the same shape: the local proxy runs on a phone and on a desktop, in front of
//! whatever is on the machine, and its listener is a plain TCP socket that any
//! local process can open. Two of the five timeout gaps in the 2026-10-10 audit
//! were here.
//!
//! The three constants both sides use live in `nexapipe-proto`, which they both
//! link — so they are imported rather than restated, and a change to one is a
//! change to both. What is left here is this side's own budget, and the
//! distinction below.
//!
//! The distinction the server's module draws is drawn here too:
//!
//! * A **phase deadline** is taken once and shared by every read inside it, so a
//!   client that trickles a byte before each expiry renews nothing.
//! * An **idle timeout** re-arms on every read, and is correct only where the
//!   phase is meant to stay open — a CONNECT tunnel to a backend that is working,
//!   for instance.

use std::time::Duration;

/// Seconds the client may take to send its request head.
///
/// One value for the whole head, not per read. The local proxy reads until it
/// finds `\r\n\r\n`, and a per-read timeout there is exactly what a client that
/// sends one byte of `Host:` every twenty seconds wants: the read that arrives
/// resets the clock, so the connection, its task and its slot stay pinned to a
/// client that is never going to finish.
pub const HEADER_SECS: u64 = nexapipe_proto::HEADER_SECS;

/// Seconds a TLS ClientHello may take to arrive.
///
/// The client sends a five-byte record header and then the record body. Reading
/// the header tells us how long the body is, and the read that fetches it had no
/// bound at all — so a client that sent the five bytes and nothing else held the
/// connection open indefinitely.
pub const TLS_HELLO_SECS: u64 = nexapipe_proto::TLS_HELLO_SECS;

/// Seconds a proxied byte copy may run before it is abandoned.
///
/// Long by design: this covers an established CONNECT tunnel or a raw TCP flow,
/// where silence is normal and the session is meant to last. It exists so that a
/// copy loop cannot hold its resources for the life of the process, not to shape
/// traffic.
pub const STREAM_SECS: u64 = nexapipe_proto::STREAM_SECS;

/// The phase budgets, as durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadlines {
    pub header: Duration,
    pub tls_hello: Duration,
    pub stream: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Self {
            header: Duration::from_secs(HEADER_SECS),
            tls_hello: Duration::from_secs(TLS_HELLO_SECS),
            stream: Duration::from_secs(STREAM_SECS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_budget_is_a_total_and_the_stream_one_is_long() {
        let d = Deadlines::default();
        assert_eq!(d.header, Duration::from_secs(30));
        assert_eq!(d.tls_hello, Duration::from_secs(10));
        // A stream is an established session, so it is not bounded like a header.
        assert!(
            d.stream > d.header,
            "a proxy tunnel has to outlive the time it takes to type a request"
        );
    }
}
