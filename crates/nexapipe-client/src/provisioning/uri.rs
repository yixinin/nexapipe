//! The link's own plumbing.
//!
//! The query parameters as they were written, the percent encoding that
//! keeps them intact, and the domain list they carry.

use anyhow::{Result, bail};
use nexapipe_proto::normalize_pattern;
use nexapipe_proto::secret::SecretString;

/// Splits a comma-separated parameter. `domains=` with no value is empty,
/// `domains=a,,b` is an error: an empty entry means a mistyped code.
pub(super) fn comma_list(raw: &str) -> Result<Vec<String>> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            bail!("the domain list {raw:?} contains an empty entry");
        }
        out.push(part.to_string());
    }
    Ok(out)
}

/// Folds the domain list into the patterns the client matches with, keeping
/// the order, which matters because the first matching domain usually wins
/// elsewhere.
///
/// The list is a list of *patterns*, not a list of names: the server's route
/// patterns are what ends up in an invite, and the client matches them with
/// the rule in `nexapipe-proto`. So the fold is that rule's fold
/// ([`normalize_pattern`]) and not the host fold.
///
/// The difference is the catch-all. `*.`, `*..` and `[*]` all fold to `*`, and
/// a pattern that means "every host" where the invite said something narrower
/// is the one mistake this must not make: folded into `*`, such a pattern
/// hands the client the catch-all and the client proxies every host. Kept in
/// its own shape, it matches nothing — which is what the shared rule says a
/// pattern that folds into the catch-all does.
pub(super) fn normalize_domains(domains: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(domains.len());
    for raw in domains {
        let domain = normalize_pattern(raw.trim());
        if domain.is_empty() {
            bail!("the domain list contains an empty entry");
        }
        if domain
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#'))
        {
            bail!("{domain:?} is not a valid domain");
        }
        if !out
            .iter()
            .any(|existing: &String| existing.as_str() == domain.as_ref())
        {
            out.push(domain.into_owned());
        }
    }
    Ok(out)
}

/// Query parameters as written, so `%2C` stays distinguishable from `,` and a
/// repeated key keeps both occurrences.
///
/// The values are [`SecretString`]s: an invite's parameters are the invite, and
/// two of them — the seed and the enrollment token — are credentials outright.
/// Holding them in a `Secret` means the whole set is wiped when the
/// parameters are dropped, which is as soon as the invite has been read.
#[derive(Debug, Default)]
pub(super) struct QueryParams(Vec<(String, SecretString)>);

impl QueryParams {
    pub(super) fn first(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    pub(super) fn has_any(&self, keys: [&str; 5]) -> bool {
        keys.iter().any(|key| self.first(key).is_some())
    }
}

pub(super) fn parse_query(query: &str) -> Result<QueryParams> {
    let mut out = Vec::new();
    if query.trim().is_empty() {
        return Ok(QueryParams(out));
    }

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.is_empty() {
            bail!("malformed parameter {pair:?} in the invite code");
        }
        out.push((
            // The *name* of a parameter is folded to lower case; its value is
            // not, because a value is a credential and a credential's case is
            // part of it. Folding the name is what keeps a code that carries
            // a credential under a differently-cased name from losing it: an
            // unmatched name is an unknown parameter, and unknown parameters
            // are dropped — so `Secret=…` would have been dropped and the
            // invite would have imported as an endpoint with no second
            // factor at all, while the app that reads the same code kept the
            // credential and authenticated with it.
            percent_decode(key)?.to_ascii_lowercase(),
            // The decoded value is a copy of what the link carried, and for
            // two of the parameters it is a credential — so it goes into the
            // wrapper rather than into a `String` that is dropped unwiped.
            SecretString::new(percent_decode(value)?),
        ));
    }
    Ok(QueryParams(out))
}

const UNRESERVED_EXTRA: [char; 1] = [','];

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'-' | b'.' | b'_' | b'~')
        || UNRESERVED_EXTRA.contains(&(byte as char))
}

/// Percent-encodes everything that is not unreserved. Non-ASCII is written as
/// its UTF-8 bytes, which is what the standard wants in a URI.
pub(super) fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if is_unreserved(*byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The inverse of [`percent_encode`]. `+` stays literal on purpose.
pub(super) fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .ok_or_else(|| anyhow::anyhow!("truncated escape sequence in {value:?}"))?;
                let text = std::str::from_utf8(hex)
                    .map_err(|_| anyhow::anyhow!("malformed escape sequence in {value:?}"))?;
                let byte = u8::from_str_radix(text, 16).map_err(|_| {
                    anyhow::anyhow!("malformed escape sequence \\%{text} in {value:?}")
                })?;
                out.push(byte);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }

    String::from_utf8(out).map_err(|e| anyhow::anyhow!("the invite code is not valid UTF-8 ({e})"))
}
