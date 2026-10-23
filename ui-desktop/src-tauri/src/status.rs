//! Status payloads shared by the Tauri command surface and the service IPC channel.
//!
//! These types replace the packed string the status command used to return (`"true:tun"`), which
//! forced the frontend to split on `:` and made the mode vocabulary drift between the two
//! backends. There is now exactly one definition, serialized identically in both directions.

use serde::{Deserialize, Serialize};

use nexapipe_client::LinkKind;

use crate::proxy::manager::ProxyMode;

/// How the proxy is currently forwarding traffic.
///
/// `Starting`, `Stopped` and `Unknown` describe the absence of a live mode rather than a mode of
/// their own, but the UI renders all five on a single status line, so they live in one enum
/// instead of forcing the frontend to combine two fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyModeKind {
    /// Accepted as well: a service binary built before this refactor sent `format!("{:?}")`,
    /// i.e. TitleCase. Keeping the alias means an already-installed service keeps answering
    /// correctly until it is restarted on the new binary, instead of failing to deserialize and
    /// silently degrading to process mode.
    #[serde(alias = "Tun")]
    Tun,
    #[serde(alias = "LocalProxy")]
    LocalProxy,
    Starting,
    Stopped,
    /// The state could not be read.
    ///
    /// Not the same as [`ProxyModeKind::Stopped`]: "stopped" is a fact, and this is the absence
    /// of one. The service owns the tunnel when the app runs in service mode, so a failed read
    /// of the service's state leaves the question open — and a question that is open must not be
    /// answered with "stopped", because answering it that way is what starts a second tunnel
    /// over a live one.
    Unknown,
}

impl From<ProxyMode> for ProxyModeKind {
    fn from(mode: ProxyMode) -> Self {
        match mode {
            ProxyMode::Tun => ProxyModeKind::Tun,
            ProxyMode::LocalProxy => ProxyModeKind::LocalProxy,
        }
    }
}

/// The result of `get_proxy_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyStatus {
    /// Whether traffic is actually being forwarded. See [`ProxyStatus::starting`]: a manager that
    /// exists but has no mode yet is *not* running.
    pub running: bool,
    pub mode: ProxyModeKind,
}

impl ProxyStatus {
    /// The manager exists and is bringing the tunnel up.
    ///
    /// Both backends used to disagree here — process mode reported `running: false`, service mode
    /// reported `running: true` for the same situation. The process-mode reading is the honest
    /// one: nothing is being forwarded yet, so the UI must not claim it is.
    pub fn starting() -> Self {
        Self {
            running: false,
            mode: ProxyModeKind::Starting,
        }
    }

    /// No manager at all: the proxy has never been started, or has been stopped.
    pub fn stopped() -> Self {
        Self {
            running: false,
            mode: ProxyModeKind::Stopped,
        }
    }

    /// The state could not be read, and this process cannot say what it is.
    ///
    /// The service owns the tunnel when the app runs in service mode, so a
    /// failed read of the service's state leaves the question open. Answering
    /// it with "stopped" would be a guess — and the guess is what starts a
    /// second tunnel over a live one.
    pub fn unknown() -> Self {
        Self {
            running: false,
            mode: ProxyModeKind::Unknown,
        }
    }

    /// The manager has reached a live mode.
    pub fn running_with(mode: ProxyMode) -> Self {
        Self {
            running: true,
            mode: mode.into(),
        }
    }
}

/// How one configured node currently reaches its backend.
///
/// `link` is the **runtime** answer read off the path iroh actually selected, not the
/// configured relay mode: a node may be allowed to use a relay and still connect directly,
/// which is exactly what the user wants to see.
///
/// These fields reach TypeScript, where `EndpointLink` in `src/types/index.ts` spells every
/// multi-word key camelCase. Tauri does not rewrite a command result's keys, so this struct has
/// to ask for the conversion explicitly or `endpointId` arrives as `endpoint_id` and the frontend
/// reads `undefined`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointLink {
    /// The ticket or endpoint ID exactly as the node was configured, so the UI can match a link
    /// to the node it came from. A ticket is opaque to the frontend, so the resolved endpoint
    /// ID alone would not be enough to key on.
    pub connection: String,
    /// The backend's endpoint ID; a ticket resolves to the node it names.
    pub endpoint_id: String,
    /// `direct`, `relay`, or `unknown` when the backend has no selected path yet.
    pub link: LinkKind,
    /// The round-trip time of the path carrying the traffic, in milliseconds.
    ///
    /// `None` when iroh has no sample yet — a path that has just opened, or a
    /// relay that does not report one. It is not a zero, and the UI must not
    /// draw it as one.
    pub rtt_ms: Option<u64>,
}

/// What the last probe of one configured node found.
///
/// One entry per configured node, keyed by `connection` exactly as [`EndpointLink`] keys
/// itself, so the UI can pair a reading with the node it came from.
///
/// Sent in this shape and not as `nexapipe_client::endpoint_group::NodeHealth`, which carries
/// `std::time::Instant`s: an `Instant` is a reading of *this* process's monotonic clock, so a
/// timestamp off it says nothing in another process — and the service, which is the other end
/// of IPC, is another process. Every timestamp is therefore flattened here into the elapsed
/// duration the UI actually prints: whole seconds, or `None` for "never".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeHealthStatus {
    /// The ticket or endpoint ID exactly as the node was configured — see
    /// [`EndpointLink::connection`].
    pub connection: String,
    /// Whether it answered its last probe. `false` before the first probe has run: a backend
    /// that has not been asked has not answered.
    pub reachable: bool,
    /// How many probes in a row have failed. Zero while the node answers.
    pub consecutive_failures: u32,
    /// How long it has been since it last answered — `None` while it is up, and `None` when it
    /// has never answered, which is not the same as "down for no time at all".
    pub down_for_secs: Option<u64>,
    /// How long ago it was last asked — `None` before the first probe, which is up to the
    /// probe interval plus its jitter after a start.
    pub since_last_probe_secs: Option<u64>,
}

/// What one configured node has carried, and how many flows it carries right now.
///
/// One entry per node, keyed by `connection` exactly as [`EndpointLink`] and
/// [`NodeHealthStatus`] key themselves, so a link, a health reading and a volume for one node can
/// be paired.
///
/// Every byte figure is cumulative since the counters started — since the proxy was started, in
/// practice — and no rate crosses: a rate is two readings and a division, and the only caller
/// already polls, so it does the subtraction on its own side.
///
/// A node the counters have nothing for is *absent* rather than zero: "has carried nothing" and
/// "is carrying nothing right now" are different facts, and only the caller can say which one it
/// is looking at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeTrafficStatus {
    /// The ticket or endpoint ID exactly as the node was configured — see
    /// [`EndpointLink::connection`].
    pub connection: String,
    /// Bytes this machine has put into the tunnel towards this node, cumulative.
    pub sent: u64,
    /// Bytes that have come back from it, cumulative.
    pub received: u64,
    /// Flows open through it right now. The only figure here that ever goes down.
    pub active: u64,
}

/// How many open flows one `get_active_flows` answer carries at most.
///
/// The cap belongs to the payload rather than to the caller: a list is for a person, a browser
/// opening two hundred sockets at once is ordinary, and a table with thousands of rows redrawn
/// every few seconds is not a thing anyone can read. `ActiveFlowPage::total` still reports the
/// real count, so nothing is hidden by it.
pub const FLOW_PAGE_LIMIT: usize = 200;

/// One connection the proxy has open right now, as a UI lists it.
///
/// The counterpart to [`NodeTrafficStatus`], which counts the same bytes added up per node:
/// this is one row per *connection*, with the node it reaches named the same way a link and a
/// health reading name theirs, so the two views can be lined up.
///
/// `kind` crosses as a string rather than an enum because the list of doors a flow can come in
/// by is the client library's, and a second vocabulary for it in the shell would be a second
/// place to change when one is added. See `nexapipe_client::flow::FlowKind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveFlow {
    /// Stable while the flow is open, and never reused after it ends — so a row that is asked
    /// to close is the row that was listed, not whichever one now sits at that index.
    pub id: u64,
    /// The ticket or endpoint ID exactly as the node was configured — see
    /// [`EndpointLink::connection`]. `None` when the flow reaches a backend this configuration
    /// does not name, which the UI shows by the endpoint ID alone rather than by dropping the
    /// row.
    pub connection: Option<String>,
    /// The backend's endpoint ID.
    pub endpoint_id: String,
    /// Which door the bytes came in by: `http`, `connect`, `websocket`, `tls`, `tun_tcp`,
    /// `tun_udp`.
    pub kind: String,
    /// Where they are going, as the client named it. `None` when it never said.
    pub target: Option<String>,
    /// Where they came from. `None` when the socket did not say.
    pub source: Option<String>,
    /// Whole seconds since the flow opened.
    pub open_for_secs: u64,
    /// Bytes this machine has put into the tunnel through this flow. Cumulative.
    pub sent: u64,
    /// Bytes that have come back through it. Cumulative.
    pub received: u64,
}

/// The answer to `get_active_flows`.
///
/// `total` and `limit` come back with the rows rather than being left for the caller to infer,
/// because the rows are capped: a UI that says "200 of 1 431" is telling the truth about a busy
/// tunnel, and one that printed a round 200 would be quietly claiming otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveFlowPage {
    pub flows: Vec<ActiveFlow>,
    /// How many flows are open in total, which may be more than `flows.len()`.
    pub total: usize,
    /// The cap this page was read under — the caller's, echoed back so a page can say what it
    /// was cropped to without keeping a second copy of the number.
    pub limit: usize,
}

impl ActiveFlowPage {
    /// Nothing open, and no cap worth naming: the answer when nothing is running.
    pub fn empty() -> Self {
        Self {
            flows: Vec::new(),
            total: 0,
            limit: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_mode_vocabularies() {
        for (raw, expected) in [
            (r#""tun""#, ProxyModeKind::Tun),
            (r#""Tun""#, ProxyModeKind::Tun),
            (r#""local_proxy""#, ProxyModeKind::LocalProxy),
            (r#""LocalProxy""#, ProxyModeKind::LocalProxy),
            (r#""starting""#, ProxyModeKind::Starting),
            (r#""stopped""#, ProxyModeKind::Stopped),
        ] {
            let parsed: ProxyModeKind = serde_json::from_str(raw).unwrap();
            assert_eq!(parsed, expected, "failed to parse {raw}");
        }
    }

    #[test]
    fn serializes_modes_in_snake_case() {
        let status = ProxyStatus::running_with(ProxyMode::LocalProxy);
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            r#"{"running":true,"mode":"local_proxy"}"#
        );
    }

    /// **An unreadable state is not a stopped one.**
    ///
    /// The frontend asks "is it stopped?" before it starts a tunnel by itself, and a state
    /// that could not be read must not answer that question. "Stopped" is a fact and
    /// "unknown" is the absence of one, so the two have to be different values on the wire —
    /// and the unknown one has to say so.
    #[test]
    fn an_unreadable_state_is_not_a_stopped_one() {
        let status = ProxyStatus::unknown();
        assert!(
            !status.running,
            "a state that could not be read is not forwarding traffic"
        );
        assert_eq!(
            status.mode,
            ProxyModeKind::Unknown,
            "the state is unknown, and it says so"
        );
        assert_ne!(
            status.mode,
            ProxyModeKind::Stopped,
            "unknown is not stopped: the difference is the whole point"
        );
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            r#"{"running":false,"mode":"unknown"}"#
        );
        let parsed: ProxyStatus =
            serde_json::from_str(r#"{"running":false,"mode":"unknown"}"#).unwrap();
        assert_eq!(parsed.mode, ProxyModeKind::Unknown);
    }

    /// The frontend keys nodes off `connection` and reads `link` as one of three fixed
    /// spellings, so the wire shape has to stay put — and the round-trip time
    /// arrives as a number or as `null`, never as a zero standing in for "not
    /// measured".
    #[test]
    fn serializes_endpoint_links() {
        let link = EndpointLink {
            connection: "node1ticket".to_string(),
            endpoint_id: "0123456789abcdef".to_string(),
            link: LinkKind::Relay,
            rtt_ms: Some(23),
        };
        assert_eq!(
            serde_json::to_string(&link).unwrap(),
            r#"{"connection":"node1ticket","endpointId":"0123456789abcdef","link":"relay","rttMs":23}"#
        );

        let unmeasured = EndpointLink {
            rtt_ms: None,
            ..link
        };
        assert_eq!(
            serde_json::to_string(&unmeasured).unwrap(),
            r#"{"connection":"node1ticket","endpointId":"0123456789abcdef","link":"relay","rttMs":null}"#
        );
    }

    /// The frontend keys health off `connection`, the same string a link carries, and reads the
    /// two durations as optional seconds — so both the key spelling and the `null`s have to
    /// hold.
    #[test]
    fn serializes_node_health() {
        let health = NodeHealthStatus {
            connection: "node1ticket".to_string(),
            reachable: false,
            consecutive_failures: 3,
            down_for_secs: Some(90),
            since_last_probe_secs: None,
        };
        assert_eq!(
            serde_json::to_string(&health).unwrap(),
            r#"{"connection":"node1ticket","reachable":false,"consecutiveFailures":3,"downForSecs":90,"sinceLastProbeSecs":null}"#
        );
    }

    /// The frontend groups rows by `connection`, reads `id` back when it asks for one to be
    /// closed, and reads the two `Option`s as `string | null` — so the camelCase keys and the
    /// `null`s both have to hold.
    #[test]
    fn serializes_active_flows() {
        let page = ActiveFlowPage {
            flows: vec![ActiveFlow {
                id: 7,
                connection: Some("node1ticket".to_string()),
                endpoint_id: "0123456789abcdef".to_string(),
                kind: "connect".to_string(),
                target: Some("example.com:443".to_string()),
                source: None,
                open_for_secs: 90,
                sent: 1_048_576,
                received: 512,
            }],
            total: 431,
            limit: 200,
        };
        assert_eq!(
            serde_json::to_string(&page).unwrap(),
            r#"{"flows":[{"id":7,"connection":"node1ticket","endpointId":"0123456789abcdef","kind":"connect","target":"example.com:443","source":null,"openForSecs":90,"sent":1048576,"received":512}],"total":431,"limit":200}"#
        );
    }

    /// A page with nothing in it still says how many there were and what the cap was: a UI that
    /// read `0` as "no reading" would draw "no connections" over a backend it never asked.
    #[test]
    fn an_empty_page_is_not_the_same_as_no_reading() {
        let page = ActiveFlowPage::empty();
        assert_eq!(page.total, 0);
        assert!(page.flows.is_empty());
    }

    /// The frontend pairs a volume with a link and a health reading by `connection`, and reads
    /// all three figures as plain numbers — so the camelCase spelling has to hold.
    #[test]
    fn serializes_node_traffic() {
        let traffic = NodeTrafficStatus {
            connection: "node1ticket".to_string(),
            sent: 1_048_576,
            received: 512,
            active: 3,
        };
        assert_eq!(
            serde_json::to_string(&traffic).unwrap(),
            r#"{"connection":"node1ticket","sent":1048576,"received":512,"active":3}"#
        );
    }
}
