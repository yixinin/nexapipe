//! Virtual IP ↔ domain mapping for the TUN device.
//!
//! # Why a mapping and not the payload
//!
//! The tunnel used to send every connection to one virtual proxy address and
//! recover the destination from the payload: SNI out of a TLS `ClientHello`,
//! `Host` out of an HTTP request. That only works while the first bytes of a
//! connection are one of those two things, and it never worked for UDP at all —
//! a datagram to `10.0.1.3:3478` says nothing about whose traffic it is. A raw
//! TCP protocol (a database wire protocol, MQTT, a game) has no host name in it
//! either. And the port was never on the wire, so every flow looked like 443.
//!
//! So the DNS answers handed to the application carry a distinct address per
//! domain instead:
//!
//! ```text
//! dns.example.com   -> 10.0.1.16
//! turn.example.com  -> 10.0.1.17
//! ```
//!
//! The address is inside the TUN route (`10.0.1.0/24`), so the packets come
//! back to us, and the reverse lookup answers "which domain" — which is what
//! picks the route on the server. The port is then carried by the flow's own
//! packet rather than guessed.
//!
//! # The address range
//!
//! `.16` … `.254`. The addresses below `.16` belong to the Kotlin side of the
//! VPN: `.1` is the TUN interface, `.2` the DNS server the system resolver
//! points at, `.3` the legacy virtual proxy address. Every address handed out
//! here stays inside the single route the VPN installs, so nothing has to be
//! renegotiated with the platform when a domain is resolved.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::MutexGuard;

/// First address handed out.
const VIRTUAL_IP_FIRST: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 16);

/// Last address handed out — the top of `10.0.1.0/24`.
const VIRTUAL_IP_LAST: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 254);

/// Size of the address pool (`.16` … `.254` inclusive).
pub const VIRTUAL_IP_COUNT: usize = 239;

/// Which domain an address belongs to, and back again.
///
/// Both directions are kept because both are needed: the forward one so a
/// domain keeps the address it already handed out (the application may hold a
/// connection on it), the reverse one because that is the only thing a packet
/// carries.
#[derive(Debug)]
pub struct IpMapping {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// The direction the packet path needs.
    ip_to_domain: HashMap<u32, String>,
    /// The direction that keeps a domain's address stable across queries.
    domain_to_ip: HashMap<String, u32>,
    /// Next address to hand out; wraps around the pool.
    next: u32,
}

impl Default for IpMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl IpMapping {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                ip_to_domain: HashMap::new(),
                domain_to_ip: HashMap::new(),
                next: u32::from(VIRTUAL_IP_FIRST),
            }),
        }
    }

    /// The address `domain` resolves to, allocating one on first use.
    ///
    /// A domain that already has an address keeps it: the application may be
    /// holding a connection open against it, and moving the address would break
    /// that connection's replies.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let key = normalise(domain);
        let mut inner = self.locked();

        if let Some(&ip) = inner.domain_to_ip.get(&key) {
            return Ipv4Addr::from(ip);
        }

        let ip = inner.next;
        inner.next = if ip >= u32::from(VIRTUAL_IP_LAST) {
            u32::from(VIRTUAL_IP_FIRST)
        } else {
            ip + 1
        };

        // The pool can be exhausted, and reusing an address a second name still
        // claims would make the reverse lookup ambiguous — two domains, one
        // address, whichever asked last wins, and packets land on the wrong
        // route. So the previous owner is evicted: DNS answers live for 60 s, so
        // its next query (or the one after) simply allocates a fresh address.
        if let Some(previous) = inner.ip_to_domain.insert(ip, key.clone()) {
            inner.domain_to_ip.remove(&previous);
        }
        inner.domain_to_ip.insert(key, ip);

        Ipv4Addr::from(ip)
    }

    /// The domain an address was handed out for, or `None` for an address this
    /// mapping never issued (which includes `.1`/`.2`/`.3`, the fixed ones).
    pub fn lookup_domain(&self, ip: &Ipv4Addr) -> Option<String> {
        self.locked().ip_to_domain.get(&u32::from(*ip)).cloned()
    }

    /// Number of live mappings.
    pub fn len(&self) -> usize {
        self.locked().domain_to_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A poisoned lock still holds a consistent table, so recovering from one is
    /// better than taking the whole tunnel down: every critical section here is
    /// a handful of `HashMap` calls and nothing that can panic in between, so
    /// there is no half-applied update for the poison flag to protect us from.
    fn locked(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Fold a name to the form both maps are keyed on.
///
/// DNS names are case-insensitive and a fully qualified name may carry a
/// trailing dot; `Example.COM.` and `example.com` are the same name and must not
/// get two addresses.
fn normalise(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_same_name_always_gets_the_same_address() {
        let mapping = IpMapping::new();
        let first = mapping.allocate("dns.example.com");
        assert_eq!(mapping.allocate("dns.example.com"), first);
        // Case and the trailing dot are spelling, not identity.
        assert_eq!(mapping.allocate("DNS.Example.com."), first);
        assert_eq!(mapping.len(), 1);
    }

    #[test]
    fn different_names_get_different_addresses() {
        let mapping = IpMapping::new();
        let a = mapping.allocate("a.test");
        let b = mapping.allocate("b.test");
        assert_ne!(a, b);
        assert_eq!(mapping.len(), 2);
    }

    #[test]
    fn the_reverse_lookup_is_the_inverse_of_allocate() {
        let mapping = IpMapping::new();
        for name in ["a.test", "b.test", "c.test"] {
            let ip = mapping.allocate(name);
            assert_eq!(mapping.lookup_domain(&ip).as_deref(), Some(name));
        }
    }

    #[test]
    fn an_address_we_never_handed_out_maps_to_nothing() {
        let mapping = IpMapping::new();
        mapping.allocate("a.test");
        // The three fixed addresses the Kotlin side owns, plus a free slot.
        for ip in [
            Ipv4Addr::new(10, 0, 1, 1),
            Ipv4Addr::new(10, 0, 1, 2),
            Ipv4Addr::new(10, 0, 1, 3),
            Ipv4Addr::new(10, 0, 1, 200),
            Ipv4Addr::new(8, 8, 8, 8),
        ] {
            assert_eq!(mapping.lookup_domain(&ip), None, "{ip}");
        }
    }

    #[test]
    fn every_address_stays_inside_the_tun_route() {
        // The VPN installs exactly one route (10.0.1.0/24). An address outside
        // it would be sent to the physical network instead of to us, so the
        // whole pool has to be inside it.
        let mapping = IpMapping::new();
        let mut seen = HashSet::new();
        for i in 0..VIRTUAL_IP_COUNT {
            let ip = mapping.allocate(&format!("host{i}.test"));
            let octets = ip.octets();
            assert_eq!(&octets[..3], &[10, 0, 1], "{ip} is outside 10.0.1.0/24");
            assert!(
                (16..=254).contains(&octets[3]),
                "{ip} does not belong to the pool"
            );
            assert!(seen.insert(ip), "{ip} was handed out twice");
        }
        assert_eq!(seen.len(), VIRTUAL_IP_COUNT);
    }

    #[test]
    fn running_out_of_addresses_recycles_instead_of_breaking_the_lookup() {
        let mapping = IpMapping::new();
        let first = mapping.allocate("first.test");
        // Fill the rest of the pool, so the cursor is now back at the start.
        for i in 0..VIRTUAL_IP_COUNT - 1 {
            mapping.allocate(&format!("host{i}.test"));
        }
        assert_eq!(mapping.len(), VIRTUAL_IP_COUNT);

        let recycled = mapping.allocate("late.test");
        assert_eq!(recycled, first, "the pool should wrap around");

        // The address now belongs to exactly one name. `first.test` was evicted
        // rather than left pointing at an address it no longer owns.
        assert_eq!(mapping.lookup_domain(&recycled).as_deref(), Some("late.test"));
        assert_eq!(mapping.len(), VIRTUAL_IP_COUNT);
        assert_ne!(mapping.allocate("first.test"), recycled);
    }
}
