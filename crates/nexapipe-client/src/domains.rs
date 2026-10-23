//! The list of names a client proxies, and the one rule that decides membership.
//!
//! # One rule, two ends
//!
//! The client asks "is this name one of mine?" and the server asks "is this
//! name one a route serves?". The two answers have to agree, or a name the
//! client decides to tunnel is a name the server has no route for: the tunnel
//! carries it, the server answers `NoRoute`, and the failure looks like the
//! tunnel is broken rather than like the two halves spelled the pattern
//! differently.
//!
//! So the rule is the server's, and it lives in `nexapipe-proto` — see
//! `nexapipe_proto::host` for the rule and for the three answers it replaced.

use nexapipe_proto::{host_matches_any, pattern_error};

/// Whether `host` is one of the names this client proxies.
///
/// A bare domain is that name and not its subdomains, and `*.example.com` is
/// its subdomains and not the name — the same spelling the server's route
/// patterns use, so a pattern can be copied from one list to the other.
pub fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    host_matches_any(proxy_domains, host)
}

/// The key a domain is stored and looked up under.
///
/// A name and the same name with a trailing dot are the same name, and DNS
/// names are case-insensitive, so both are folded away on the way in and on
/// the way out.
///
/// This is the client's own fold, and it is not the route rule in
/// `nexapipe-proto`: that one compares names the way DNS does — ASCII case
/// only, and the surrounding whitespace left alone — while this one also takes
/// the whitespace off. The difference is deliberate: a name that arrives with
/// whitespace around it is a name a configuration written by hand will not
/// match, and forgiving it here is what makes the two agree.
pub fn fold_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

/// What a list of patterns is worth saying, when a client starts with one.
#[derive(Debug, Default, Clone)]
pub struct DomainNotes {
    /// Patterns that match nothing, each with the reason.
    ///
    /// A wildcard without a dot (`*example.com`) is one of these. The client
    /// used to read it as a bare `ends_with`, so it matched `notexample.com`
    /// as well — a host belonging to somebody else entirely. The server has
    /// always refused the spelling; the client refusing it too is what makes
    /// the two agree, and it is worth a warning because the list now matches
    /// nothing at all.
    pub unusable: Vec<(String, String)>,
    /// Patterns that name one host where a reader may expect a whole tree.
    ///
    /// A bare domain (`example.com`) means that name and not its subdomains.
    /// It used to mean both on the client, while the server read it as the
    /// name alone, so a subdomain the client tunneled was a name the server
    /// had no route for. A user who wants the subdomains writes
    /// `*.example.com`, which is what the server's route patterns have always
    /// said.
    pub narrowed: Vec<String>,
}

/// The notes a list of patterns is worth.
pub fn domain_notes(patterns: &[String]) -> DomainNotes {
    let mut notes = DomainNotes::default();
    for pattern in patterns {
        if let Some(why) = pattern_error(pattern) {
            notes.unusable.push((pattern.clone(), why));
            continue;
        }
        // A bare domain: one name, where "this site and everything under it"
        // is what a reader may take it for. The catch-all is not narrowed —
        // it means every name, which is what it says.
        if !pattern.starts_with('*') {
            notes.narrowed.push(pattern.clone());
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(patterns: &[&str]) -> Vec<String> {
        patterns.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn a_bare_domain_is_that_name_and_not_its_subdomains() {
        let domains = list(&["example.com"]);
        assert!(should_proxy_domain("example.com", &domains));
        assert!(!should_proxy_domain("www.example.com", &domains));
        assert!(!should_proxy_domain("notexample.com", &domains));
    }

    #[test]
    fn a_wildcard_is_the_subdomains_and_not_the_apex() {
        let domains = list(&["*.example.com"]);
        assert!(should_proxy_domain("www.example.com", &domains));
        assert!(!should_proxy_domain("example.com", &domains));
    }

    #[test]
    fn a_wildcard_without_a_dot_matches_nothing() {
        // The spelling the server refuses: as a bare `ends_with` it also
        // matched `notexample.com`, which is a host belonging to somebody else.
        let domains = list(&["*example.com"]);
        assert!(!should_proxy_domain("notexample.com", &domains));
        assert!(!should_proxy_domain("example.com", &domains));
    }

    #[test]
    fn the_notes_say_what_changed() {
        let notes = domain_notes(&list(&["example.com", "*.other.test", "*third.test", "*"]));
        assert_eq!(notes.unusable.len(), 1);
        assert_eq!(notes.unusable[0].0, "*third.test");
        assert_eq!(notes.narrowed, vec!["example.com".to_string()]);
    }

    #[test]
    fn an_empty_list_proxies_nothing() {
        assert!(!should_proxy_domain("example.com", &[]));
    }
}
