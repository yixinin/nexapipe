//! One place that says how long each phase of a proxied request may take.
//!
//! Every timeout in this workspace used to be written at the point of use, which
//! is how the five gaps in the 2026-10-10 audit happened: a place that needed a
//! deadline either forgot one or wrote a per-read one without noticing that a
//! per-read timeout re-arms. A peer sending one byte before each expiry renews
//! it forever, and the slot, the backend lease and the task stay pinned to a
//! client that is never going to finish.
//!
//! The distinction this module exists to keep is:
//!
//! * A **phase deadline** is computed once, at the start of the phase, and
//!   every read inside it is measured against that same instant. It expires
//!   whether or not bytes are moving, which is the property a slowloris needs
//!   and a per-read timeout does not have.
//! * An **idle timeout** is re-armed on every read, and is only correct where
//!   the phase is *supposed* to be open-ended — a live WebSocket or a long
//!   stream from a backend that is working. Those are named as idle on purpose,
//!   so that a reader can tell at the call site which kind of bound it has.
//!
//! Every constant here is a default that a deployment can raise: the six keys of
//! [`Overrides`] are read from the server's `[timeouts]` section (`header_secs`,
//! `body_secs`, `response_idle_secs`, `l4_flow_secs`, `l4_idle_secs`,
//! `tls_hello_secs`) and [`crate::config::Timeouts`] carries the resolved
//! [`Deadlines`] to every call site. A key left out means the default, and the
//! per-route `flow_timeout_secs` still overrides `l4_flow` for one route alone.
//! The client library's counterpart module restates the constants and does not
//! read configuration; raising one of these on the server does not move the
//! client's own copies.
//!
//! Said plainly here because a module that documents tunables it does not honour
//! is worse than one that documents none. None of them is a quota either way:
//! expiry is a diagnostic ("this stopped moving") rather than a policy, and every
//! one is longer than a healthy request on a slow link.

use std::time::Duration;

// The three budgets the client and the server both use are named in
// `nexapipe-proto`, which both sides link: they used to be written down twice
// and kept in step by hand, which is the same failure mode as a protocol
// written down twice, one size smaller. The three that are only this side's
// business — the body budget and the two idle timeouts — stay here.

/// Seconds a client may take to send its request head.
///
/// Covers the whole head, not each read of it: a peer that opens a connection
/// and then trickles a byte of `Host:` every few seconds is holding a slot, a
/// task and a connection slot, and a per-read timeout is exactly what it wants.
pub const DEFAULT_HEADER_SECS: u64 = nexapipe_proto::HEADER_SECS;

/// Seconds a client may take to send a request body once the head is in.
///
/// Separate from the head because a large upload legitimately takes longer than
/// a header does, and a single budget for both would either be too short for
/// uploads or too long to protect against a stalled one.
pub const DEFAULT_BODY_SECS: u64 = 300;

/// Seconds a backend response body may stay silent before it is treated as dead.
///
/// **Idle, not a phase deadline**, and deliberately so: a streamed response and
/// a server-sent-events stream are supposed to be open for as long as the two
/// ends want. (A WebSocket is not among them — `conn` diverts an upgrade to its
/// own handler before the body loop is reached.) What must not be possible is a
/// backend that accepted the request, sent the head, and then said nothing at
/// all — that pins the slot and the backend lease forever. The gap between two
/// chunks is the thing being bounded, so this re-arms on every chunk by design.
pub const DEFAULT_RESPONSE_IDLE_SECS: u64 = 120;

/// Seconds an L4 tunnel may run before it is closed.
///
/// A **phase** deadline, unlike the response idle above, because an L4 flow has
/// no protocol-level end: a TCP connection to a backend that never closes and
/// never sends is indistinguishable, from here, from one that is being used.
/// Bounding the whole flow is what stops a peer from renewing it indefinitely
/// by making the tunnel technically active. Raise it for long-lived SSH or a
/// database session over the tunnel.
pub const DEFAULT_L4_FLOW_SECS: u64 = nexapipe_proto::STREAM_SECS;

/// Seconds between two UDP datagrams in either direction before the flow is
/// considered idle.
///
/// **Idle**, because a UDP flow has no "complete" to wait for; this bounds the
/// gap, not the flow. It is the one place a re-arming timer is the correct
/// shape.
pub const DEFAULT_L4_IDLE_SECS: u64 = 60;

/// Seconds a TLS ClientHello may take to arrive.
///
/// The client sends the record header and then the body of it, and a peer that
/// sends the five header bytes and nothing else would otherwise hold the
/// connection open indefinitely with no read deadline at all.
pub const DEFAULT_TLS_HELLO_SECS: u64 = nexapipe_proto::TLS_HELLO_SECS;

/// The per-phase budgets, resolved.
///
/// A struct rather than loose constants so that a caller cannot accidentally use
/// the body budget for a header read: the names are the documentation, and a
/// `Duration` passed to the wrong phase is exactly the mistake this module is
/// here to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadlines {
    pub header: Duration,
    pub body: Duration,
    pub response_idle: Duration,
    pub l4_flow: Duration,
    pub l4_idle: Duration,
    pub tls_hello: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Self::resolve(&Overrides::default())
    }
}

impl Deadlines {
    /// The deadlines a caller asked for, with every default filled in.
    pub fn resolve(overrides: &Overrides) -> Self {
        Self {
            header: or(overrides.header_secs, DEFAULT_HEADER_SECS),
            body: or(overrides.body_secs, DEFAULT_BODY_SECS),
            response_idle: or(overrides.response_idle_secs, DEFAULT_RESPONSE_IDLE_SECS),
            l4_flow: or(overrides.l4_flow_secs, DEFAULT_L4_FLOW_SECS),
            l4_idle: or(overrides.l4_idle_secs, DEFAULT_L4_IDLE_SECS),
            tls_hello: or(overrides.tls_hello_secs, DEFAULT_TLS_HELLO_SECS),
        }
    }

    /// Wraps a phase in a deadline that does not re-arm.
    ///
    /// The returned future is what every caller should reach for in place of
    /// wrapping a single read in a timeout: the instant is taken once, here, and
    /// everything inside shares it.
    pub async fn phase<T>(
        &self,
        deadline: Duration,
        what: &'static str,
        future: impl std::future::Future<Output = T>,
    ) -> Result<T, PhaseExpired> {
        match tokio::time::timeout(deadline, future).await {
            Ok(value) => Ok(value),
            Err(_) => Err(PhaseExpired { what }),
        }
    }
}

/// A phase that ran out of time.
///
/// Carries the phase name rather than a formatted string so that callers can
/// decide how to report it — a log line on the server, a `jni_log!` on Android —
/// without this module having to know which it is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseExpired {
    pub what: &'static str,
}

impl std::fmt::Display for PhaseExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} did not finish within its deadline", self.what)
    }
}

impl std::error::Error for PhaseExpired {}

/// What a deployment wrote, all optional.
///
/// Every key absent means "the default", so an empty table changes nothing —
/// the same rule `[timeouts]` already follows.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Overrides {
    pub header_secs: Option<u64>,
    pub body_secs: Option<u64>,
    pub response_idle_secs: Option<u64>,
    pub l4_flow_secs: Option<u64>,
    pub l4_idle_secs: Option<u64>,
    pub tls_hello_secs: Option<u64>,
}

/// The longest wait any of these accepts: a day spent waiting for a header is
/// not a slow client, it is one that is never going to send one.
pub const MAX_SECS: u64 = 86_400;

fn or(value: Option<u64>, default: u64) -> Duration {
    Duration::from_secs(value.unwrap_or(default).min(MAX_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_overrides_means_the_documented_defaults() {
        let d = Deadlines::default();
        assert_eq!(d.header, Duration::from_secs(DEFAULT_HEADER_SECS));
        assert_eq!(d.body, Duration::from_secs(DEFAULT_BODY_SECS));
        assert_eq!(
            d.response_idle,
            Duration::from_secs(DEFAULT_RESPONSE_IDLE_SECS)
        );
        assert_eq!(d.l4_flow, Duration::from_secs(DEFAULT_L4_FLOW_SECS));
        assert_eq!(d.l4_idle, Duration::from_secs(DEFAULT_L4_IDLE_SECS));
        assert_eq!(d.tls_hello, Duration::from_secs(DEFAULT_TLS_HELLO_SECS));
    }

    #[test]
    fn one_override_leaves_the_others_alone() {
        let d = Deadlines::resolve(&Overrides {
            header_secs: Some(5),
            ..Default::default()
        });
        assert_eq!(d.header, Duration::from_secs(5));
        assert_eq!(d.body, Duration::from_secs(DEFAULT_BODY_SECS));
    }

    #[test]
    fn an_absurd_override_is_capped_rather_than_refused() {
        // The cap is a backstop for callers that never ran the config
        // validation, not the policy: `ProxyConfig::validate_timeouts` refuses
        // anything past `MAX_SECS` (and zero) at load, where the operator is
        // looking. The cap is high enough that no legitimate configuration
        // meets it.
        let d = Deadlines::resolve(&Overrides {
            body_secs: Some(u64::MAX),
            ..Default::default()
        });
        assert_eq!(d.body, Duration::from_secs(MAX_SECS));
    }

    #[tokio::test]
    async fn a_phase_deadline_expires_even_while_bytes_keep_arriving() {
        // The property a per-read timeout lacks, stated as a test: work that
        // never stops does not renew the deadline, because the deadline was
        // taken once when the phase began.
        let started = std::time::Instant::now();
        let trickle = async {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let err = Deadlines::default()
            .phase(Duration::from_millis(50), "the trickle", trickle)
            .await
            .unwrap_err();
        assert_eq!(err.what, "the trickle");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "it expired on the deadline, not on the work finishing"
        );
    }

    #[tokio::test]
    async fn work_that_finishes_in_time_is_returned() {
        let got = Deadlines::default()
            .phase(Duration::from_secs(5), "quick work", async { 42usize })
            .await
            .unwrap();
        assert_eq!(got, 42);
    }

    #[test]
    fn an_expired_phase_names_itself() {
        assert_eq!(
            PhaseExpired { what: "the body" }.to_string(),
            "the body did not finish within its deadline"
        );
    }
}
