//! Endpoint invitations: one `nexapipe://` link carrying everything a client
//! needs before it can talk to an endpoint.
//!
//! ## Grammar
//!
//! ```text
//! nexapipe://endpoint/<node-id>?v=1&name=Home&domains=a.example,b.example
//!     &relay=https%3A%2F%2Frelay.example
//!     &client=client-001&issuer=NexaPipe&secret=JBSWY3DPEHPK3PXP
//!     &algorithm=SHA1&digits=6&period=30
//!
//! nexapipe://ticket/<endpoint-ticket>?v=1&domains=a.example
//! ```
//!
//! The two hosts say how the peer is reached: `endpoint` carries only a stable
//! Node ID and leaves address discovery to the network, `ticket` carries an
//! address-bearing ticket. Everything else is shared:
//!
//! | parameter | meaning |
//! | --- | --- |
//! | `v` | Schema version. `1` today; anything newer is rejected. |
//! | `name` | Human label for the endpoint. Purely cosmetic. |
//! | `domains` | Comma-separated domains to route through this endpoint. |
//! | `relay` | Relay URL the endpoint is reachable through. A hint only. |
//! | `client` | 2FA client id, the key the server looks the secret up by. |
//! | `issuer` | 2FA issuer label (defaults to [`DEFAULT_ISSUER`]). |
//! | `secret` | Base32 TOTP secret. Required for a 2FA invite. |
//! | `algorithm` | `SHA1` (default), `SHA256` or `SHA512`. |
//! | `digits` | Code length, `6` by default. |
//! | `period` | Time step in seconds, `30` by default. |
//! | `otpauth` | Alternative to the six parameters above: an entire standard `otpauth://` URI. Used when the flat form is absent. |
//!
//! ## Encoding
//!
//! Values are percent-encoded (everything outside the RFC 3986 unreserved set
//! plus `,` — the list separator — becomes `%XX`), so an invite survives a QR
//! code, a chat message and a text file unchanged. `+` is *not* treated as a
//! space, which form decoders would do; Base32 secrets contain neither.
//!
//! Unknown parameters are ignored, so a newer server can add fields without
//! breaking older apps; when a parameter repeats, the first occurrence wins.
//! Everything else is rejected with a message meant to be shown to a user,
//! since the common way to get here is scanning a code off a screen.

use std::fmt;

use anyhow::{Result, bail};
use iroh::EndpointId;
use iroh_tickets::endpoint::EndpointTicket;

use crate::auth::TotpAlgorithm;

/// Issuer label used when an invite does not name one.
pub const DEFAULT_ISSUER: &str = "NexaPipe";

/// Scheme of an invitation link.
pub const INVITE_SCHEME: &str = "nexapipe";

/// Only version understood by this build.
pub const INVITE_VERSION: u32 = 1;

/// The host selecting a bare Node ID.
pub const NODE_ID_HOST: &str = "endpoint";

/// The host selecting a full endpoint ticket.
pub const TICKET_HOST: &str = "ticket";

/// Past roughly this length a printed code needs a QR version that stops being
/// comfortable to scan off a screen; the CLI calls it out, nothing is rejected.
pub const RECOMMENDED_URI_LIMIT: usize = 400;

/// Where [`EndpointInvite::target`] points: either a stable Node ID, which needs
/// discovery to become an address, or a ticket that already carries addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointTarget {
    /// 64 hex characters identifying the endpoint.
    NodeId(String),
    /// A full endpoint ticket, validated on parse but kept verbatim so decision
    /// logic elsewhere (relay mode, address pinning) can inspect it as text.
    Ticket(String),
}

impl EndpointTarget {
    /// The node ID of a [`Self::NodeId`] target; tickets are opaque here.
    pub fn node_id(&self) -> Option<EndpointId> {
        match self {
            Self::NodeId(id) => id.parse().ok(),
            Self::Ticket(_) => None,
        }
    }

    /// The host component this target is written as.
    pub fn host(&self) -> &'static str {
        match self {
            Self::NodeId(_) => NODE_ID_HOST,
            Self::Ticket(_) => TICKET_HOST,
        }
    }

    /// Builds a Node ID target, rejecting anything iroh would not accept.
    pub fn node_id_target(id: &str) -> Result<Self> {
        let trimmed = id.trim();
        trimmed
            .parse::<EndpointId>()
            .map_err(|e| anyhow::anyhow!("{trimmed:?} is not a Node ID ({e})"))?;
        Ok(Self::NodeId(trimmed.to_string()))
    }

    /// Builds a ticket target, rejecting strings that are not tickets.
    pub fn ticket_target(ticket: &str) -> Result<Self> {
        let trimmed = ticket.trim();
        trimmed
            .parse::<EndpointTicket>()
            .map_err(|e| anyhow::anyhow!("not a valid endpoint ticket ({e})"))?;
        Ok(Self::Ticket(trimmed.to_string()))
    }

    /// The value as it appears after the `/` of the link.
    fn as_str(&self) -> &str {
        match self {
            Self::NodeId(id) => id,
            Self::Ticket(ticket) => ticket,
        }
    }
}

impl fmt::Display for EndpointTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The 2FA half of an invite: everything [`OtpAuth`](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
/// style codes carry, in the flat form described above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteTotp {
    pub issuer: String,
    pub client_id: String,
    /// Upper-case Base32 without padding.
    pub secret: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u32,
}

impl InviteTotp {
    /// Credentials with the parameters this library defaults to.
    pub fn new(client_id: &str, secret: &str) -> Result<Self> {
        Self::with_params(
            DEFAULT_ISSUER,
            client_id,
            secret,
            TotpAlgorithm::SHA1,
            6,
            30,
        )
    }

    /// Credentials with every parameter spelled out.
    pub fn with_params(
        issuer: &str,
        client_id: &str,
        secret: &str,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u32,
    ) -> Result<Self> {
        let issuer = issuer.trim();
        if issuer.is_empty() {
            bail!("the 2FA issuer is empty");
        }
        let client_id = client_id.trim();
        if client_id.is_empty() {
            bail!("the 2FA client id is empty");
        }
        let secret = normalize_secret(secret)?;
        if !(6..=8).contains(&digits) {
            bail!("{digits} digits per code is not supported (expected 6 to 8)");
        }
        if period == 0 {
            bail!("the 2FA period cannot be 0 seconds");
        }

        Ok(Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            secret,
            algorithm,
            digits,
            period,
        })
    }

    /// Parameters that cannot be honored once the code has been imported.
    ///
    /// [`crate::auth::TwoFactorAuth`] is built with a six-digit code over a
    /// 30 second step, so anything else in the invite is silently discarded by
    /// the generated codes; importing is the moment to say so.
    pub fn client_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.digits != 6 {
            warnings.push(format!(
                "{} digits per code is ignored: the client always generates 6-digit codes",
                self.digits
            ));
        }
        if self.period != 30 {
            warnings.push(format!(
                "a {} second step is ignored: the client always uses a 30 second step",
                self.period
            ));
        }
        warnings
    }

    /// Flat parameters, in the order [`EndpointInvite::to_uri`] writes them.
    fn to_params(&self) -> Vec<(&'static str, String)> {
        vec![
            ("client", self.client_id.clone()),
            ("issuer", self.issuer.clone()),
            ("secret", self.secret.clone()),
            ("algorithm", self.algorithm.name().to_ascii_uppercase()),
            ("digits", self.digits.to_string()),
            ("period", self.period.to_string()),
        ]
    }
}

/// A complete endpoint invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInvite {
    pub target: EndpointTarget,
    pub name: Option<String>,
    pub domains: Vec<String>,
    pub relay: Option<String>,
    pub totp: Option<InviteTotp>,
}

impl EndpointInvite {
    /// An invite for `target` routing `domains`, with nothing optional set.
    pub fn new(target: EndpointTarget, domains: &[String]) -> Result<Self> {
        Ok(Self {
            target,
            name: None,
            domains: normalize_domains(domains)?,
            relay: None,
            totp: None,
        })
    }

    /// Labels the endpoint. Empty names are dropped rather than erroring.
    pub fn with_name(mut self, name: &str) -> Self {
        let name = name.trim();
        self.name = (!name.is_empty()).then(|| name.to_string());
        self
    }

    /// Adds a relay hint. An empty or malformed value is ignored, not trusted.
    pub fn with_relay(mut self, relay: Option<&str>) -> Self {
        match relay.map(str::trim) {
            Some(relay) if !relay.is_empty() && url::Url::parse(relay).is_ok() => {
                self.relay = Some(relay.to_string());
            }
            _ => self.relay = None,
        }
        self
    }

    /// Attaches 2FA credentials.
    pub fn with_totp(mut self, totp: Option<InviteTotp>) -> Self {
        self.totp = totp;
        self
    }

    /// Renders the canonical link. Optional fields that are unset or empty are
    /// left out, so two invites with the same shape always compare equal.
    pub fn to_uri(&self) -> String {
        let mut params: Vec<(&str, String)> = vec![("v", INVITE_VERSION.to_string())];

        if let Some(name) = &self.name {
            params.push(("name", name.clone()));
        }
        if !self.domains.is_empty() {
            params.push(("domains", self.domains.join(",")));
        }
        if let Some(relay) = &self.relay {
            params.push(("relay", relay.clone()));
        }
        if let Some(totp) = &self.totp {
            params.extend(totp.to_params());
        }

        let query = params
            .iter()
            .map(|(key, value)| format!("{key}={}", percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&");

        format!(
            "{scheme}://{host}/{value}?{query}",
            scheme = INVITE_SCHEME,
            host = self.target.host(),
            value = percent_encode(self.target.as_str()),
        )
    }

    /// Reads back a link produced by [`Self::to_uri`].
    pub fn from_uri(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let prefix = format!("{INVITE_SCHEME}://");
        if !raw
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(&prefix))
        {
            bail!("not a {INVITE_SCHEME}:// invite code");
        }
        let body = &raw[prefix.len()..];

        // A trailing fragment is not part of the code; some QR encoders add one
        // when the payload is pasted into a browser-like URL.
        let body = body.split('#').next().unwrap_or(body);
        let (path, query) = match body.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (body, None),
        };

        // One empty segment is tolerated: a link typed into a browser-like
        // field often comes back as `.../<node-id>/?v=1`.
        let (host, value) = path.split_once('/').unwrap_or((path, ""));
        let target = match_percent_host(host, &percent_decode(value.trim_end_matches('/'))?)?;

        let params = query.map(parse_query).transpose()?.unwrap_or_default();
        if let Some(version) = params.first("v") {
            let version: u32 = version
                .parse()
                .map_err(|_| anyhow::anyhow!("invite version {version:?} is not a number"))?;
            if version != INVITE_VERSION {
                bail!(
                    "unsupported invite version {version} (this build understands {INVITE_VERSION})"
                );
            }
        }

        let domains = params
            .first("domains")
            .map(comma_list)
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            target,
            name: params.first("name").map(|name| name.trim().to_string()),
            domains: normalize_domains(&domains)?,
            relay: match params.first("relay").map(str::trim) {
                Some(relay) if !relay.is_empty() => {
                    url::Url::parse(relay)
                        .map_err(|e| anyhow::anyhow!("the relay URL {relay:?} is invalid ({e})"))?;
                    Some(relay.to_string())
                }
                _ => None,
            },
            totp: totp_from_params(&params)?,
        })
    }

    /// Warnings worth showing right after an import.
    pub fn client_warnings(&self) -> Vec<String> {
        self.totp
            .as_ref()
            .map(|totp| totp.client_warnings())
            .unwrap_or_default()
    }
}

/// Builds a target out of the host component and the decoded path.
fn match_percent_host(host: &str, value: &str) -> Result<EndpointTarget> {
    let host = host.trim();
    if host.eq_ignore_ascii_case(NODE_ID_HOST) {
        EndpointTarget::node_id_target(value)
    } else if host.eq_ignore_ascii_case(TICKET_HOST) {
        EndpointTarget::ticket_target(value)
    } else {
        bail!("unknown invite kind {host:?} (expected {NODE_ID_HOST:?} or {TICKET_HOST:?})");
    }
}

/// The 2FA block of the invite, if any.
///
/// The flat form wins; `otpauth` is only consulted when no `secret` was given,
/// which is how codes produced by a generic authenticator interop layer read.
fn totp_from_params(params: &QueryParams) -> Result<Option<InviteTotp>> {
    if params.first("secret").is_none() && params.first("otpauth").is_some() {
        return otpauth_totp(params.first("otpauth").unwrap_or_default());
    }

    if params.first("secret").is_some()
        && params.first("client").is_none()
        && params.first("otpauth").is_none()
    {
        bail!("the invite carries a 2FA secret but no client id");
    }
    let Some(secret) = params.first("secret") else {
        // No secret at all: either a plain endpoint share, or a mistake.
        if params.has_any(["client", "issuer", "algorithm", "digits", "period"]) {
            bail!("the invite carries 2FA parameters but no secret");
        }
        return Ok(None);
    };
    if params.first("client").is_none() {
        bail!("the invite carries a 2FA secret but no client id");
    }

    Ok(Some(InviteTotp::with_params(
        params.first("issuer").unwrap_or(DEFAULT_ISSUER),
        params.first("client").unwrap_or_default(),
        secret,
        parse_algorithm(params.first("algorithm"))?,
        parse_number(params.first("digits"), 6, "digits")?,
        parse_number(params.first("period"), 30, "period")?,
    )?))
}

/// Reads the algorithm name.
///
/// Stricter than [`TotpAlgorithm::from_name`], which falls back to SHA1 to
/// survive a half-filled config file: an invite is a finished artifact, so a
/// name nobody supports is an error, not a silent downgrade to a weaker code.
fn parse_algorithm(name: Option<&str>) -> Result<TotpAlgorithm> {
    match name.map(str::trim) {
        None | Some("") => Ok(TotpAlgorithm::SHA1),
        Some(name) if name.eq_ignore_ascii_case("sha1") => Ok(TotpAlgorithm::SHA1),
        Some(name) if name.eq_ignore_ascii_case("sha256") => Ok(TotpAlgorithm::SHA256),
        Some(name) if name.eq_ignore_ascii_case("sha512") => Ok(TotpAlgorithm::SHA512),
        Some(other) => bail!("unsupported algorithm {other:?} (expected SHA1, SHA256 or SHA512)"),
    }
}

/// Reads a nested standard `otpauth://` URI into the same structure.
///
/// The client id comes from the label after the `issuer:` prefix, exactly as
/// the authenticator apps read it.
fn otpauth_totp(uri: &str) -> Result<Option<InviteTotp>> {
    let uri = uri.trim();
    let prefix = "otpauth://";
    if !uri
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        bail!("the otpauth parameter is not an otpauth:// URI");
    }
    let rest = &uri[prefix.len()..];
    let (label, query) = match rest.split_once('?') {
        Some((label, query)) => (label, Some(query)),
        None => (rest, None),
    };

    // Standard URIs carry a type segment in front of the label
    // (`otpauth://totp/Issuer:client?...`); anything before the last `/` is
    // that, not part of the label.
    let label = label.rsplit('/').next().unwrap_or(label);
    let label = percent_decode(label)?;
    let (issuer_label, client_id) = match label.split_once(':') {
        Some((issuer, client)) => (Some(issuer.to_string()), client.to_string()),
        None => (None, label.clone()),
    };

    let params = query.map(parse_query).transpose()?.unwrap_or_default();
    let secret = params
        .first("secret")
        .ok_or_else(|| anyhow::anyhow!("the embedded otpauth:// URI carries no secret"))?;

    Ok(Some(InviteTotp::with_params(
        issuer_label
            .as_deref()
            .or(params.first("issuer"))
            .unwrap_or(DEFAULT_ISSUER),
        &client_id,
        secret,
        parse_algorithm(params.first("algorithm"))?,
        parse_number(params.first("digits"), 6, "digits")?,
        parse_number(params.first("period"), 30, "period")?,
    )?))
}

fn parse_number(value: Option<&str>, default: u32, field: &str) -> Result<u32> {
    match value {
        Some(value) => value
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("{field} must be a number, got {value:?}")),
        None => Ok(default),
    }
}

/// Cleans up the Base32 secret the way [`crate::auth::TwoFactorAuth`] expects
/// it: no spaces, no padding, upper case, and nothing outside the alphabet.
fn normalize_secret(raw: &str) -> Result<String> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let secret = compact.trim_end_matches('=').to_ascii_uppercase();

    if secret.is_empty() {
        bail!("the 2FA secret is empty");
    }
    if secret.len() < 8 {
        bail!("the 2FA secret {secret:?} is too short (at least 8 characters)");
    }
    if !secret.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        bail!("the 2FA secret {secret:?} is not Base32");
    }
    Ok(secret)
}

/// Splits a comma-separated parameter. `domains=` with no value is empty,
/// `domains=a,,b` is an error: an empty entry means a mistyped code.
fn comma_list(raw: &str) -> Result<Vec<String>> {
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

/// Lower cases, trims trailing dots and deduplicates, keeping the order, which
/// matters because the first matching domain usually wins elsewhere.
fn normalize_domains(domains: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(domains.len());
    for raw in domains {
        let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            bail!("the domain list contains an empty entry");
        }
        if domain
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#'))
        {
            bail!("{domain:?} is not a valid domain");
        }
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    Ok(out)
}

/// Query parameters as written, so `%2C` stays distinguishable from `,` and a
/// repeated key keeps both occurrences.
#[derive(Debug, Default)]
struct QueryParams(Vec<(String, String)>);

impl QueryParams {
    fn first(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    fn has_any(&self, keys: [&str; 5]) -> bool {
        keys.iter().any(|key| self.first(key).is_some())
    }
}

fn parse_query(query: &str) -> Result<QueryParams> {
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
        out.push((percent_decode(key)?, percent_decode(value)?));
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
fn percent_encode(value: &str) -> String {
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
fn percent_decode(value: &str) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A Node ID nobody is listening on.
    ///
    /// Derived from a fixed seed instead of being random: every test compares a
    /// parsed invite against the one it was built from, which only works when
    /// the identity is stable. It has to be a real public key, because parsing
    /// a Node ID checks that the point is valid, not just that it is 64 hex
    /// characters.
    fn node_id() -> String {
        iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string()
    }

    /// A real ticket, produced by the same encoder the app reads back, so the
    /// round trip exercises the format rather than a made-up sample.
    fn ticket() -> String {
        let id: EndpointId = node_id().parse().expect("the test node ID is well formed");
        EndpointTicket::new(id.into()).to_string()
    }

    fn invite() -> EndpointInvite {
        EndpointInvite::new(
            EndpointTarget::NodeId(node_id().to_string()),
            &["a.example".to_string(), "b.example".to_string()],
        )
        .unwrap()
        .with_name("Home")
        .with_totp(Some(
            InviteTotp::new("client-001", "jbswy3dpehpk3pxp").unwrap(),
        ))
    }

    #[test]
    fn round_trips_every_field() {
        let parsed = EndpointInvite::from_uri(&invite().to_uri()).unwrap();
        assert_eq!(parsed, invite());
    }

    #[test]
    fn round_trips_a_bare_endpoint() {
        let invite = EndpointInvite::new(
            EndpointTarget::NodeId(node_id().to_string()),
            &["a.example".to_string()],
        )
        .unwrap();
        let uri = invite.to_uri();
        assert_eq!(
            uri,
            format!(
                "{INVITE_SCHEME}://{NODE_ID_HOST}/{}?v=1&domains=a.example",
                invite.target
            )
        );
        assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite);
    }

    #[test]
    fn round_trips_a_ticket_target() {
        let target = EndpointTarget::Ticket(ticket());
        let invite = EndpointInvite::new(target.clone(), &["a.example".to_string()]).unwrap();
        let uri = invite.to_uri();
        assert!(
            uri.starts_with(&format!("{INVITE_SCHEME}://{TICKET_HOST}/")),
            "{uri}"
        );
        assert_eq!(EndpointInvite::from_uri(&uri).unwrap().target, target);
    }

    #[test]
    fn leaves_optional_fields_out_of_the_uri() {
        let invite =
            EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[]).unwrap();
        let uri = invite.to_uri();
        assert!(!uri.contains("name="), "{uri}");
        assert!(!uri.contains("domains="), "{uri}");
        assert!(!uri.contains("relay="), "{uri}");
        assert!(!uri.contains("secret="), "{uri}");
    }

    #[test]
    fn accepts_any_case_of_the_scheme() {
        let uri = invite().to_uri().replace("nexapipe://", "NEXAPIPE://");
        assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite());
    }

    #[test]
    fn percent_decodes_values() {
        let invite = invite()
            .with_name("My VPN @ home")
            .with_relay(Some("https://relay.example"));
        let uri = invite.to_uri();
        assert!(uri.contains("My%20VPN%20%40%20home"), "{uri}");
        assert!(uri.contains("https%3A%2F%2Frelay.example"), "{uri}");
        assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite);
    }

    #[test]
    fn keeps_the_comma_separator_readable() {
        let uri = invite().to_uri();
        assert!(uri.contains("domains=a.example,b.example"), "{uri}");
    }

    #[test]
    fn tolerates_percent_encoded_commas() {
        let uri = invite().to_uri().replace(
            "domains=a.example,b.example",
            "domains=a.example%2Cb.example",
        );
        assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite());
    }

    #[test]
    fn ignores_unknown_parameters_for_forward_compatibility() {
        let uri = format!(
            "{}&strike=magnet&relay=https%3A%2F%2Frelay.example",
            invite().to_uri()
        );
        let parsed = EndpointInvite::from_uri(&uri).unwrap();
        assert_eq!(parsed.relay.as_deref(), Some("https://relay.example"));
        assert_eq!(parsed.domains, invite().domains);
    }

    #[test]
    fn keeps_the_first_occurrence_of_a_repeated_parameter() {
        let base = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[]).unwrap();
        let uri = format!("{}&domains=a.example&domains=b.example", base.to_uri());
        assert_eq!(
            EndpointInvite::from_uri(&uri).unwrap().domains,
            vec!["a.example".to_string()]
        );
    }

    #[test]
    fn drops_a_trailing_fragment() {
        let uri = format!("{}#/from-a-browser", invite().to_uri());
        assert_eq!(EndpointInvite::from_uri(&uri).unwrap(), invite());
    }

    #[test]
    fn rejects_another_scheme() {
        let error = EndpointInvite::from_uri("https://example.com/?v=1").unwrap_err();
        assert!(
            error.to_string().contains("not a nexapipe:// invite code"),
            "{error}"
        );
    }

    #[test]
    fn rejects_an_unknown_host() {
        let error =
            EndpointInvite::from_uri(&format!("{INVITE_SCHEME}://server/abc?v=1")).unwrap_err();
        assert!(error.to_string().contains("unknown invite kind"), "{error}");
    }

    #[test]
    fn rejects_a_future_version() {
        let error = EndpointInvite::from_uri(&format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?v=2",
            node_id()
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains("unsupported invite version 2"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_node_id_that_is_not_hex() {
        let error = EndpointInvite::from_uri(&format!("{INVITE_SCHEME}://{NODE_ID_HOST}/nope?v=1"))
            .unwrap_err();
        assert!(error.to_string().contains("is not a Node ID"), "{error}");
    }

    #[test]
    fn node_id_lookups_work_on_built_targets() {
        let id = node_id();
        let target = EndpointTarget::node_id_target(&id).unwrap();
        assert_eq!(target.node_id().unwrap().to_string(), id);
    }

    #[test]
    fn normalizes_domains() {
        let invite = EndpointInvite::new(
            EndpointTarget::NodeId(node_id().to_string()),
            &[
                " A.example. ".to_string(),
                "a.example".to_string(),
                "B.EXAMPLE".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            invite.domains,
            vec!["a.example".to_string(), "b.example".to_string()]
        );
    }

    #[test]
    fn rejects_broken_domain_lists() {
        fn error_for(list: &str) -> String {
            let uri = format!(
                "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?domains={list}",
                node_id()
            );
            EndpointInvite::from_uri(&uri).unwrap_err().to_string()
        }
        assert!(
            error_for("a,,b").contains("empty entry"),
            "{}",
            error_for("a,,b")
        );
        assert!(
            error_for("a%2Fb").contains("is not a valid domain"),
            "{}",
            error_for("a%2Fb")
        );
    }

    #[test]
    fn rejects_a_relay_that_is_not_a_url() {
        let uri = format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?relay=not-a-url",
            node_id()
        );
        let error = EndpointInvite::from_uri(&uri).unwrap_err();
        assert!(error.to_string().contains("is invalid"), "{error}");
    }

    #[test]
    fn normalizes_the_secret() {
        let totp = InviteTotp::new("client-001", " jbswy3dpehpk3pxp== ").unwrap();
        assert_eq!(totp.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.issuer, DEFAULT_ISSUER);
    }

    #[test]
    fn rejects_a_secret_that_is_not_base32() {
        let error = InviteTotp::new("client-001", "hello-there").unwrap_err();
        assert!(error.to_string().contains("is not Base32"), "{error}");

        let error = InviteTotp::new("client-001", "ab").unwrap_err();
        assert!(error.to_string().contains("too short"), "{error}");
    }

    #[test]
    fn needs_a_client_id_next_to_the_secret() {
        let uri = format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?secret=JBSWY3DPEHPK3PXP",
            node_id()
        );
        let error = EndpointInvite::from_uri(&uri).unwrap_err();
        assert!(error.to_string().contains("no client id"), "{error}");
    }

    #[test]
    fn needs_a_secret_next_to_the_other_two_factor_parameters() {
        let uri = format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?client=client-001",
            node_id()
        );
        let error = EndpointInvite::from_uri(&uri).unwrap_err();
        assert!(error.to_string().contains("no secret"), "{error}");
    }

    #[test]
    fn reads_a_nested_otpauth_uri() {
        let embedded = "otpauth%3A%2F%2Ftotp%2FNexaPipe%3Aclient-001%3Fsecret%3DJBSWY3DPEHPK3PXP\
                        %26issuer%3DNexaPipe%26algorithm%3DSHA256";
        let uri = format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?otpauth={embedded}",
            node_id()
        );
        let parsed = EndpointInvite::from_uri(&uri).unwrap();
        let totp = parsed.totp.unwrap();
        assert_eq!(totp.client_id, "client-001");
        assert_eq!(totp.issuer, "NexaPipe");
        assert_eq!(totp.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.algorithm, TotpAlgorithm::SHA256);
    }

    #[test]
    fn rejects_an_algorithm_the_client_cannot_generate() {
        let uri = format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?client=client-001\
             &secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            node_id()
        );
        let error = EndpointInvite::from_uri(&uri).unwrap_err();
        assert!(
            error.to_string().contains("unsupported algorithm"),
            "{error}"
        );

        // The default is SHA1, and the name is case insensitive.
        let uri = format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?client=client-001\
             &secret=JBSWY3DPEHPK3PXP&algorithm=sha256",
            node_id()
        );
        let parsed = EndpointInvite::from_uri(&uri).unwrap();
        assert_eq!(
            parsed.totp.unwrap().algorithm,
            TotpAlgorithm::SHA256,
            "unknown algorithms would silently become weaker codes"
        );
    }

    /// A code printed by `nexapipe --generate-invite`, byte for byte.
    ///
    /// The Android client reimplements this module in Kotlin and reads exactly
    /// these bytes, so the same fixture anchors both test suites: change the
    /// grammar on either side and one of them fails.
    #[test]
    fn reads_a_code_printed_by_the_server() {
        let uri = "nexapipe://endpoint/a612286b30098f67db06783c45004e43cf182e06806540e7e6260a0f009a7063\
                   ?v=1&name=Home&domains=example.com,api.example.com\
                   &relay=https%3A%2F%2Frelay.example.com\
                   &client=client-001&issuer=NexaPipe&secret=JBSWY3DPEHPK3PXP\
                   &algorithm=SHA256&digits=6&period=30";
        let invite = EndpointInvite::from_uri(uri).unwrap();

        assert_eq!(
            invite.target,
            EndpointTarget::NodeId(
                "a612286b30098f67db06783c45004e43cf182e06806540e7e6260a0f009a7063".to_string()
            )
        );
        assert_eq!(invite.name.as_deref(), Some("Home"));
        assert_eq!(invite.domains, ["example.com", "api.example.com"]);
        assert_eq!(invite.relay.as_deref(), Some("https://relay.example.com"));

        let totp = invite.totp.as_ref().unwrap();
        assert_eq!(totp.client_id, "client-001");
        assert_eq!(totp.issuer, "NexaPipe");
        assert_eq!(totp.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.algorithm, TotpAlgorithm::SHA256);
        assert_eq!((totp.digits, totp.period), (6, 30));

        // The same code comes back out of `to_uri`, so a client can re-share
        // what it scanned.
        assert_eq!(EndpointInvite::from_uri(&invite.to_uri()).unwrap(), invite);
    }

    #[test]
    fn warns_about_two_factor_parameters_the_client_drops() {
        let totp = InviteTotp::with_params(
            DEFAULT_ISSUER,
            "client-001",
            "JBSWY3DPEHPK3PXP",
            TotpAlgorithm::SHA512,
            8,
            60,
        )
        .unwrap();
        let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
            .unwrap()
            .with_totp(Some(totp.clone()));

        let warnings = invite.client_warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("ignored"), "{warnings:?}");

        assert!(
            InviteTotp::new("client-001", "JBSWY3DPEHPK3PXP")
                .unwrap()
                .client_warnings()
                .is_empty()
        );
    }
}
