//! The pools of one domain.
//!
//! A domain is served by a pool of connections rather than by one, and the
//! pool is what decides which connection a request goes out on.

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::ClientError;
use crate::connection_pool::IrohConnectionPool;
use crate::flow::FlowRegistry;
use crate::lb::{LoadBalancer, LoadBalancingStrategy, RandomBalancer, RoundRobinBalancer};
use crate::traffic::TrafficTable;

use iroh::EndpointId;

use nexapipe_proto::protocol::Protocol;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::PooledConnection;
use super::health::NodeHealth;

pub struct DomainPools {
    pub(super) pools: Vec<Arc<IrohConnectionPool>>,
    pub(super) balancer: Box<dyn LoadBalancer + Sync + Send>,
    /// What the probe last found, shared with the group rather than copied.
    ///
    /// One domain's pools are a subset of the group's backends, and the probe
    /// asks each backend once whoever serves it, so there is one table and
    /// every domain reads it.
    pub(super) health: Arc<Mutex<HashMap<EndpointId, NodeHealth>>>,
    /// Same sharing, same reason: a backend is charged by whoever served it,
    /// so its counters live with the group and not with this domain.
    pub(super) traffic: TrafficTable,
    /// Where the flows opened through these pools are listed. Shared with the
    /// group for the same reason the traffic table is: one backend's flows are
    /// one fact, and a domain is only ever a subset of the backends.
    pub(super) flows: Arc<FlowRegistry>,
}

impl DomainPools {
    pub fn new(
        pools: Vec<Arc<IrohConnectionPool>>,
        strategy: LoadBalancingStrategy,
        health: Arc<Mutex<HashMap<EndpointId, NodeHealth>>>,
        traffic: TrafficTable,
        flows: Arc<FlowRegistry>,
    ) -> Self {
        let balancer: Box<dyn LoadBalancer + Sync + Send> = match strategy {
            LoadBalancingStrategy::RoundRobin => Box::new(RoundRobinBalancer::new()),
            LoadBalancingStrategy::Random => Box::new(RandomBalancer::new()),
        };
        Self {
            pools,
            balancer,
            health,
            traffic,
            flows,
        }
    }

    /// Which backends may be handed out: every one the health table does not
    /// say is down.
    ///
    /// A backend that has never been asked is included — "not asked" is not
    /// "not answering", and refusing on it would leave the group unusable for
    /// the interval before the first probe round and after every restart.
    pub(super) fn candidates(&self) -> Vec<bool> {
        let health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.pools
            .iter()
            .map(|pool| {
                health
                    .get(&pool.backend_id())
                    .is_none_or(|node| node.reachable)
            })
            .collect()
    }

    /// Which pool serves the next request. Decided here, and only here, because
    /// every caller reaches a backend through this one method.
    ///
    /// A domain with several backends and nothing answering refuses without
    /// dialling: the answer is already known, and a connect timeout would only
    /// deliver this refusal late. A domain with one is handed out anyway —
    /// refusing the only backend there is buys nothing and turns every request
    /// into a failure, which is the rule the server already follows for the
    /// same case.
    pub(super) fn choose(&self) -> Result<usize, ClientError> {
        if self.pools.is_empty() {
            return Err(ClientError::InvalidConfig(
                "No endpoint pools configured".to_string(),
            ));
        }

        let candidates = self.candidates();
        if let Some(index) = self.balancer.select(&candidates) {
            return Ok(index);
        }

        if self.pools.len() == 1 {
            return Ok(0);
        }

        Err(ClientError::ConnectionFailed(format!(
            "no backend is answering: {}",
            self.node_ids()
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    pub async fn get_connection(
        &self,
        protocol: Protocol,
    ) -> Result<PooledConnection, ClientError> {
        let index = self.choose()?;
        let pool = &self.pools[index];
        let backend_id = pool.backend_id();

        // Said here rather than left to the caller, because this is the only
        // place that knows which backend refused — the caller gets an error
        // without a name in it — and because nobody else says it: the retry
        // loops above only ever observe connections that were handed to them.
        //
        // A backend that cannot be dialled leaves no connection to discover
        // later, so without this line failure to reach one would never reach
        // the health table at all: another request would come along and spend a
        // full connect timeout on the same backend before trying a different
        // one, which is exactly the cost health-aware routing exists to avoid.
        //
        // Counting failure to connect, or to authenticate, as "down" reads as
        // harsh, and it is the same verdict the probe reaches: `preconnect`
        // connects and authenticates too, from the same pool, so nothing here
        // can mark a backend down that the next probe then marks back up.
        //
        // **A refusal this client made is not a verdict about the backend.**
        // Three of the failures this pool reports are about this process and
        // not about anybody's backend: `InvalidConfig` is this process having
        // let go of its own side, `PoolFull` is this process having run out
        // of its own connection slots, and `CredentialReplaced` is this
        // process having rotated a credential under a dial that was already
        // running. The backend answered the handshake in every one of them.
        //
        // Calling any of the three "down" would paint the whole node list
        // unreachable each time a tunnel stops, would flip `any_reachable()`
        // off for a backend that is up, and — with a domain that has several
        // backends — would steer every later request to the other backends
        // until the next probe round, 30 to 35 seconds away.
        //
        // The verdict is written only by evidence that the *backend* failed:
        // a dial or handshake that did not come about, or a probe.
        match pool.get_connection(protocol).await {
            Ok(borrowed) => Ok(PooledConnection::tracked(
                borrowed.conn,
                index,
                backend_id,
                self.traffic.clone(),
                self.flows.clone(),
                borrowed.borrow,
            )),
            Err(
                e @ (ClientError::InvalidConfig(_)
                | ClientError::PoolFull(_)
                | ClientError::CredentialReplaced(_)),
            ) => Err(e),
            Err(e) => {
                record_outcome(&self.health, backend_id, false);
                Err(e)
            }
        }
    }

    /// The backend node IDs this domain load-balances across (the configured
    /// `server_node_id`s), one per pool.
    pub fn node_ids(&self) -> Vec<EndpointId> {
        self.pools.iter().map(|p| p.backend_id()).collect()
    }
}

/// Folds one answer, or one failure, into the health table, logging the changes.
///
/// Two callers, one fact: the background probe asks every backend whether it
/// still answers, and a request that could not be served after spending every
/// attempt it had says the same thing
/// about the same backend. Keeping them in one place is what stops
/// `health_snapshot()` from having two meanings of "down".
///
/// Not reachable from a connection: the two callers are the probe task and the
/// retry loop that ran out of attempts, and both already hold the group.
pub(super) fn record_outcome(
    health: &Mutex<HashMap<EndpointId, NodeHealth>>,
    backend_id: EndpointId,
    answered: bool,
) {
    let mut health = health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = health.entry(backend_id).or_insert(NodeHealth {
        node: backend_id,
        // Not "unknown": a backend that has not been probed has not answered,
        // and the caller asking is about to be told so.
        reachable: false,
        consecutive_failures: 0,
        last_ok: None,
        last_probe: None,
    });

    let was_reachable = entry.reachable;
    entry.last_probe = Some(Instant::now());

    if answered {
        entry.consecutive_failures = 0;
        entry.last_ok = Some(Instant::now());
        entry.reachable = true;
        if !was_reachable {
            jni_log!("[health] Node {} answers again", backend_id);
            #[cfg(feature = "tracing")]
            tracing::info!("backend {} answers again", backend_id);
        }
        return;
    }

    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    entry.reachable = false;
    // The first failure is news. So is every tenth one — a backend that has
    // been down for an hour has failed a hundred times, and a log line per
    // failure would bury everything else.
    if was_reachable || entry.consecutive_failures % PROBE_REMINDER_EVERY == 1 {
        jni_log!(
            // Not "probes in a row": this counter also counts requests that got
            // nowhere, and calling those probes would make an operator looking
            // into one failed request go and read the probe instead.
            "[health] Node {} did not answer ({} failures in a row)",
            backend_id,
            entry.consecutive_failures
        );
        #[cfg(feature = "tracing")]
        tracing::warn!(
            "backend {} did not answer ({} failures in a row)",
            backend_id,
            entry.consecutive_failures
        );
    }
}

/// A persistently dead backend is reported once, then every this-many probes.
///
/// A backend that has been down for an hour has failed a hundred probes. Saying
/// so a hundred times buries everything else in the log; saying it once hides
/// the fact that it is still down.
const PROBE_REMINDER_EVERY: u32 = 10;
