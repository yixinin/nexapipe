use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
}

impl LoadBalancingStrategy {
    /// The strategy a name asks for.
    ///
    /// Refused rather than guessed, for the reason the server's own parser
    /// refuses: a strategy the configuration does not name is a deployment
    /// that runs differently from the one in the file, and nothing says so —
    /// the traffic still flows, just not the way the configuration claims.
    ///
    /// The spellings are the server's, so a configuration that names one
    /// means the same thing on both sides of the tunnel. `least_conn` is the
    /// server's alone: it picks a backend out of a pool that tracks what each
    /// backend is doing, and a client picking a node out of a list has no such
    /// thing to pick the least of — so it is refused here, by name, rather
    /// than quietly answered with round-robin.
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.trim() {
            "round_robin" | "RoundRobin" | "roundrobin" => Ok(Self::RoundRobin),
            "random" | "Random" => Ok(Self::Random),
            "least_conn" | "LeastConn" | "leastconn" => Err(
                "least_conn is a server-side strategy: it picks the least loaded backend of a \
                 route, and a client picks a node of a list it does not measure"
                    .to_string(),
            ),
            other => Err(format!(
                "strategy {other:?} is not a load balancing strategy; expected \"round_robin\" \
                 (the default) or \"random\""
            )),
        }
    }
}

pub struct RoundRobinBalancer {
    index: AtomicUsize,
}

impl Default for RoundRobinBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            index: AtomicUsize::new(0),
        }
    }

    /// The next backend that is not known to be down, or `None` when every one
    /// is.
    ///
    /// One step per candidate at most, and the counter keeps moving even when
    /// every index it lands on is skipped: a caller that comes back after a
    /// failure has to be able to reach a backend that answers, and a rotation
    /// that stopped on a dead index would hand out the same dead connection
    /// however many times it was asked.
    pub fn select(&self, candidates: &[bool]) -> Option<usize> {
        let count = candidates.len();
        if count == 0 {
            return None;
        }
        for _ in 0..count {
            let current = self.index.fetch_add(1, Ordering::Relaxed);
            let index = current % count;
            if candidates[index] {
                return Some(index);
            }
        }
        None
    }
}

pub struct RandomBalancer;

impl Default for RandomBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomBalancer {
    pub fn new() -> Self {
        Self
    }

    /// One of the backends that is not known to be down, or `None` when every
    /// one is.
    ///
    /// Counting the usable ones and walking to the nth, rather than picking an
    /// index and scanning forward: scanning forward gives a backend a share
    /// proportional to the size of the gap in front of it, so one dead backend
    /// would quietly double the traffic of the one behind it.
    pub fn select(&self, candidates: &[bool]) -> Option<usize> {
        let usable = candidates.iter().filter(|candidate| **candidate).count();
        if usable == 0 {
            return None;
        }
        let nth = fastrand::usize(0..usable);
        candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| **candidate)
            .nth(nth)
            .map(|(index, _)| index)
    }
}

/// Chooses which of a domain's backends serves the next request.
///
/// `candidates` is one flag per backend: true where nothing has said the
/// backend is down. `None` means every one of them is, and what that is worth
/// is the caller's decision rather than the balancer's — see
/// [`crate::endpoint_group::DomainPools::get_connection`].
pub trait LoadBalancer {
    fn select(&self, candidates: &[bool]) -> Option<usize>;
}

impl LoadBalancer for RoundRobinBalancer {
    fn select(&self, candidates: &[bool]) -> Option<usize> {
        self.select(candidates)
    }
}

impl LoadBalancer for RandomBalancer {
    fn select(&self, candidates: &[bool]) -> Option<usize> {
        self.select(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the whole exercise: a backend the probe found dead does not
    /// get another request until it answers again.
    #[test]
    fn the_rotation_skips_a_backend_that_is_down() {
        let balancer = RoundRobinBalancer::new();
        let candidates = [true, false, true];

        let chosen: Vec<usize> = (0..4)
            .map(|_| balancer.select(&candidates).expect("two backends are up"))
            .collect();

        assert!(chosen.iter().all(|index| candidates[*index]), "{chosen:?}");
        // Skipping must not mean sticking: both healthy backends still serve.
        assert!(chosen.contains(&0) && chosen.contains(&2), "{chosen:?}");
    }

    #[test]
    fn every_backend_down_is_none_not_the_first_one() {
        let candidates = [false, false];
        assert_eq!(RoundRobinBalancer::new().select(&candidates), None);
        assert_eq!(RandomBalancer::new().select(&candidates), None);
        assert_eq!(RoundRobinBalancer::new().select(&[]), None);
        assert_eq!(RandomBalancer::new().select(&[]), None);
    }

    /// A random choice that scans forward from a random index would favour the
    /// backend behind a dead one; every usable backend has to stay equally
    /// likely.
    #[test]
    fn the_random_choice_only_ever_returns_a_usable_index() {
        let balancer = RandomBalancer::new();
        let candidates = [true, false, false, true];

        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let index = balancer.select(&candidates).expect("two backends are up");
            assert!(candidates[index], "picked a backend that is down");
            seen.insert(index);
        }

        assert_eq!(
            seen.len(),
            2,
            "both healthy backends must be reachable: {seen:?}"
        );
    }

    /// The two names a client has, under every spelling the server accepts.
    ///
    /// The spellings are the server's, so a configuration that names one means
    /// the same thing on both sides of the tunnel — and the server accepts
    /// `RoundRobin` and `roundrobin` as well as `round_robin`, so the client
    /// has to as well.
    #[test]
    fn a_name_the_server_understands_is_understood_here_too() {
        for name in ["round_robin", "RoundRobin", "roundrobin"] {
            assert_eq!(
                LoadBalancingStrategy::from_name(name),
                Ok(LoadBalancingStrategy::RoundRobin),
                "{name}"
            );
        }
        for name in ["random", "Random"] {
            assert_eq!(
                LoadBalancingStrategy::from_name(name),
                Ok(LoadBalancingStrategy::Random),
                "{name}"
            );
        }
    }

    /// The name is read the way a configuration is written: with the spaces a
    /// hand-written file puts around it.
    #[test]
    fn a_name_with_spaces_around_it_is_still_the_name() {
        assert_eq!(
            LoadBalancingStrategy::from_name("  round_robin  "),
            Ok(LoadBalancingStrategy::RoundRobin)
        );
        assert_eq!(
            LoadBalancingStrategy::from_name("\trandom\n"),
            Ok(LoadBalancingStrategy::Random)
        );
    }

    /// `least_conn` is the server's alone, and it is refused **by name**.
    ///
    /// A client picks a node out of a list it does not measure, so there is no
    /// "least loaded" to pick — and answering with round-robin instead would
    /// be a deployment that runs differently from the one the file says, with
    /// nothing reporting it. The refusal says what the name is, so the
    /// operator does not have to guess why it was turned down.
    #[test]
    fn least_conn_is_refused_by_name_rather_than_answered_with_round_robin() {
        for name in ["least_conn", "LeastConn", "leastconn"] {
            let error = LoadBalancingStrategy::from_name(name)
                .expect_err("a client has no least-loaded backend to pick");
            assert!(
                error.contains("least_conn"),
                "the refusal names the strategy it turned down: {error}"
            );
            assert!(
                error.contains("server-side"),
                "and says whose strategy it is: {error}"
            );
        }
    }

    /// A name nobody supports is refused, and the refusal says what is
    /// supported.
    ///
    /// This is the message an operator sees when the local proxy refuses to
    /// start over a misspelled `strategy`, so it has to be enough to fix the
    /// file with.
    #[test]
    fn an_unknown_name_is_refused_with_the_names_that_are_supported() {
        let error = LoadBalancingStrategy::from_name("round-robin")
            .expect_err("a hyphen is not the name of a strategy");
        assert!(error.contains("round-robin"), "{error}");
        assert!(error.contains("round_robin"), "{error}");
        assert!(error.contains("random"), "{error}");
    }
}
