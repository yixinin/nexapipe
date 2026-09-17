//! Shared QUIC transport tuning for the server and every client build.
//!
//! # Why this exists
//!
//! iroh ships a transport config that is explicitly documented as being "tuned for a
//! 100Mbps link with a 100ms round trip time". Concretely
//! (`noq_proto::config::TransportConfig::default`) that means:
//!
//! ```text
//! EXPECTED_RTT        = 100 ms
//! MAX_STREAM_BANDWIDTH= 12.5 MB/s
//! stream_receive_window = 12.5 MB/s * 100 ms = 1.25 MB
//! receive_window        = VarInt::MAX      (effectively unlimited)
//! send_window           = 8 * 1.25 MB      = 10 MB
//! initial_mtu/min_mtu   = 1200
//! congestion controller = Cubic
//! ```
//!
//! Nexapipe maps **exactly one inner TCP connection onto one QUIC bi-stream**, so
//! `stream_receive_window` is the throughput ceiling of every single connection:
//!
//! ```text
//! 1.25 MB / 200 ms RTT ~= 6.25 MB/s ~= 50 Mbps
//! ```
//!
//! That is the dominant transport-level bottleneck, and it is the one this module raises.
//! `receive_window` is already `VarInt::MAX` and `send_window` is already 10 MB, so neither
//! is worth touching beyond a modest bump.
//!
//! # Deliberately left alone
//!
//! `max_concurrent_multipath_paths`, `max_remote_nat_traversal_addresses`,
//! `default_path_keep_alive_interval` and `default_path_max_idle_timeout` are *not* exposed
//! here. iroh's own docs warn that overriding them breaks hole punching, because they drive
//! iroh's QUIC-multipath based NAT traversal. `QuicTransportConfig::builder()` seeds them with
//! iroh's values and we never overwrite them.
//!
//! # Overriding for A/B tests
//!
//! Values are read from the environment once per endpoint construction, so a tuning
//! experiment does not need a rebuild:
//!
//! | variable                        | default | meaning                                |
//! |---------------------------------|---------|----------------------------------------|
//! | `NEXAPIPE_QUIC_STREAM_WINDOW`   | 4194304 | per-stream receive window, bytes       |
//! | `NEXAPIPE_QUIC_SEND_WINDOW`     | 16777216| connection send window, bytes          |
//! | `NEXAPIPE_QUIC_INITIAL_MTU`     | 0       | 0 = keep iroh's 1200; else 1200..=65535|
//! | `NEXAPIPE_QUIC_KEEPALIVE_MS`    | 0       | 0 = keep iroh's 5s                     |
//!
//! Android has no useful environment, so it always runs the compiled-in defaults.

use iroh::endpoint::{QuicTransportConfig, VarInt};
use std::time::Duration;

/// Per-stream receive window. 4 MiB sustains ~160 Mbps at 200 ms RTT and ~320 Mbps at
/// 100 ms RTT, instead of iroh's ~50 Mbps / ~100 Mbps.
///
/// Worst-case buffer memory is `max_concurrent_bidi_streams * stream_receive_window`
/// (100 * 4 MiB = 400 MiB) and only materialises if 100 streams are simultaneously
/// blocked on an application that refuses to read — which this proxy never does for long.
pub const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 4 * 1024 * 1024;

/// Connection-wide send window. iroh's 10 MB is already generous; 16 MB gives two full
/// 4 MiB streams plus headroom for the control streams without letting one stream
/// monopolise the connection buffer.
pub const DEFAULT_SEND_WINDOW: u64 = 16 * 1024 * 1024;

/// Fallback used when an override is nonsense (e.g. a varint that is too large).
const FALLBACK_STREAM_RECEIVE_WINDOW: u64 = 1_250_000;

const ENV_STREAM_WINDOW: &str = "NEXAPIPE_QUIC_STREAM_WINDOW";
const ENV_SEND_WINDOW: &str = "NEXAPIPE_QUIC_SEND_WINDOW";
const ENV_INITIAL_MTU: &str = "NEXAPIPE_QUIC_INITIAL_MTU";
const ENV_KEEPALIVE_MS: &str = "NEXAPIPE_QUIC_KEEPALIVE_MS";

/// Tunable subset of [`QuicTransportConfig`] that nexapipe actually wants to control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportTuning {
    /// Per-stream flow control window in bytes.
    pub stream_receive_window: u64,
    /// Connection-wide send window in bytes.
    pub send_window: u64,
    /// `None` keeps iroh's initial MTU (1200) and its MTU discovery ramp.
    pub initial_mtu: Option<u16>,
    /// `None` keeps iroh's connection keep-alive (5 s).
    pub keep_alive_interval: Option<Duration>,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            stream_receive_window: DEFAULT_STREAM_RECEIVE_WINDOW,
            send_window: DEFAULT_SEND_WINDOW,
            initial_mtu: None,
            keep_alive_interval: None,
        }
    }
}

impl TransportTuning {
    /// Compiled-in defaults, with optional `NEXAPIPE_QUIC_*` overrides applied.
    ///
    /// Unparsable or out-of-range values are ignored (with a warning) rather than being
    /// clamped silently, so a typo during an A/B run shows up immediately instead of
    /// producing a measurement you cannot explain.
    pub fn from_env() -> Self {
        let mut tuning = Self::default();

        if let Some(v) = env_u64(ENV_STREAM_WINDOW) {
            if v >= 64 * 1024 {
                tuning.stream_receive_window = v;
            } else {
                warn_ignored(ENV_STREAM_WINDOW, v);
            }
        }
        if let Some(v) = env_u64(ENV_SEND_WINDOW) {
            if v >= 64 * 1024 {
                tuning.send_window = v;
            } else {
                warn_ignored(ENV_SEND_WINDOW, v);
            }
        }
        if let Some(v) = env_u64(ENV_INITIAL_MTU) {
            // 0 means "leave it to iroh".
            if v == 0 {
                tuning.initial_mtu = None;
            } else if (1200..=65535).contains(&v) {
                tuning.initial_mtu = Some(v as u16);
            } else {
                warn_ignored(ENV_INITIAL_MTU, v);
            }
        }
        if let Some(v) = env_u64(ENV_KEEPALIVE_MS) {
            if v > 0 {
                tuning.keep_alive_interval = Some(Duration::from_millis(v));
            } else {
                tuning.keep_alive_interval = None;
            }
        }

        tuning
    }

    /// Build the [`QuicTransportConfig`] for this tuning.
    ///
    /// Starts from `QuicTransportConfig::builder()`, which is seeded from iroh's defaults
    /// (keep-alives, multipath, NAT-traversal, handshake migration), so anything not listed
    /// above keeps iroh's value.
    pub fn transport_config(&self) -> QuicTransportConfig {
        let mut builder = QuicTransportConfig::builder()
            .stream_receive_window(varint(self.stream_receive_window, ENV_STREAM_WINDOW))
            .send_window(self.send_window);

        if let Some(mtu) = self.initial_mtu {
            builder = builder.initial_mtu(mtu);
        }
        if let Some(keep_alive) = self.keep_alive_interval {
            builder = builder.keep_alive_interval(keep_alive);
        }

        builder.build()
    }

    /// One-line summary for the startup log, so the numbers in a benchmark run are auditable.
    pub fn describe(&self) -> String {
        format!(
            "stream_receive_window={}B send_window={}B initial_mtu={} keep_alive={}",
            self.stream_receive_window,
            self.send_window,
            self.initial_mtu
                .map(|m| m.to_string())
                .unwrap_or_else(|| "iroh-default".to_string()),
            self.keep_alive_interval
                .map(|d| format!("{:?}", d))
                .unwrap_or_else(|| "iroh-default".to_string()),
        )
    }
}

/// Convenience wrapper: environment-overridden defaults as a ready-to-use transport config.
pub fn transport_config() -> QuicTransportConfig {
    TransportTuning::from_env().transport_config()
}

/// Convenience wrapper that also returns the tuning used, for logging at the call site.
pub fn transport_config_with_tuning() -> (QuicTransportConfig, TransportTuning) {
    let tuning = TransportTuning::from_env();
    (tuning.transport_config(), tuning)
}

fn env_u64(key: &str) -> Option<u64> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<u64>() {
        Ok(v) => Some(v),
        Err(_) => {
            warn_ignored(key, trimmed);
            None
        }
    }
}

fn varint(value: u64, what: &str) -> VarInt {
    match VarInt::from_u64(value) {
        Ok(v) => v,
        Err(_) => {
            warn_ignored(what, value);
            // 1.25 MB is always a valid varint, so this cannot panic.
            VarInt::from_u64(FALLBACK_STREAM_RECEIVE_WINDOW)
                .expect("fallback window fits in a QUIC varint")
        }
    }
}

fn warn_ignored(what: &str, value: impl std::fmt::Display) {
    #[cfg(feature = "tracing")]
    tracing::warn!(
        "Ignoring invalid QUIC transport override {}={}, keeping default",
        what,
        value
    );
    #[cfg(not(feature = "tracing"))]
    {
        let _ = (what, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_raise_the_stream_window_above_iroh() {
        let tuning = TransportTuning::default();
        assert_eq!(tuning.stream_receive_window, 4 * 1024 * 1024);
        assert!(tuning.stream_receive_window > 1_250_000);
        // Not exposed: multipath / NAT traversal must stay on iroh's values.
        assert_eq!(tuning.initial_mtu, None);
    }

    #[test]
    fn transport_config_builds_from_defaults() {
        let _ = TransportTuning::default().transport_config();
    }

    #[test]
    fn describe_is_stable() {
        let text = TransportTuning::default().describe();
        assert!(text.contains("stream_receive_window=4194304B"), "{text}");
        assert!(text.contains("initial_mtu=iroh-default"), "{text}");
    }
}
