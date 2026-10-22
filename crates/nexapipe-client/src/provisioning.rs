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
use nexapipe_proto::normalize_pattern;

use crate::auth::TotpAlgorithm;
use nexapipe_proto::secret::SecretString;

/// Issuer label used when an invite does not name one.
pub const DEFAULT_ISSUER: &str = "NexaPipe";

/// Scheme of an invitation link.
pub const INVITE_SCHEME: &str = "nexapipe";

/// Only version understood by this build.
pub const INVITE_VERSION: u32 = 1;

/// Version of an invite that carries an enrollment token instead of a secret.
///
/// Separate from [`INVITE_VERSION`] on purpose: an app that has never heard of
/// enrollment must refuse the code rather than read it as a `v=1` invite with
/// no credentials in it, which is what "ignore unknown parameters" would
/// otherwise turn it into — a scan that looks successful and connects to
/// nothing.
pub const ENROLLMENT_INVITE_VERSION: u32 = 2;

/// The host selecting a bare Node ID.
pub const NODE_ID_HOST: &str = "endpoint";

/// The host selecting a full endpoint ticket.
pub const TICKET_HOST: &str = "ticket";

/// Past roughly this length a printed code needs a QR version that stops being
/// comfortable to scan off a screen; the CLI calls it out, nothing is rejected.
pub const RECOMMENDED_URI_LIMIT: usize = 400;

/// The hard limit on an invite code.
///
/// [`RECOMMENDED_URI_LIMIT`] is what a person can read off a screen; this is
/// what a parser will look at. A code past it is not a code anybody will
/// read, and parsing it is work an attacker gets for free.
pub const MAX_URI_LEN: usize = 4 * 1024;

/// Whether a relay hint names a relay this client could reach.
///
/// The hint is only a hint — the URL is applied later, and a hint that names
/// nothing usable is dropped rather than obeyed. But "usable" is a question
/// with an answer, and the answer is not "the URL parser accepted it":
///
/// - the scheme has to be one the relay code can dial — `https` and `http`,
///   because a self-hosted relay over plain HTTP is a supported deployment,
///   and `wss` and `ws` for the same reason;
/// - it has to name a host;
/// - it must not name an n0-operated relay, for the reason
///   [`crate::relay::RelayModeSpec`] refuses one.
fn is_usable_relay_hint(relay: &str) -> bool {
    let Ok(url) = relay.parse::<iroh::RelayUrl>() else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        return false;
    }
    if url.host_str().is_none_or(str::is_empty) {
        return false;
    }
    !crate::relay::is_n0_relay(&url)
}

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

/// What a [`fmt::Debug`] prints instead of a credential.
///
/// Nothing in this module is meant to be logged, but a parse error or a UI
/// binding that formats an invite with `{:?}` should not turn into a copy of
/// the second factor in a log file. [`EndpointInvite::to_uri`] still writes
/// secrets in the clear: that URI *is* the invite, and a redacted one would
/// scan to nothing.
const REDACTED: &str = "***";

/// The 2FA half of an invite: everything [`OtpAuth`](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
/// style codes carry, in the flat form described above.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteTotp {
    pub issuer: String,
    pub client_id: String,
    /// Upper-case Base32 without padding.
    ///
    /// A [`SecretString`]: an invite that carries a secret carries a working
    /// credential, and this one is wiped when the invite is dropped.
    pub secret: SecretString,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u32,
}

impl fmt::Debug for InviteTotp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteTotp")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("secret", &REDACTED)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
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
            ("secret", self.secret.expose_secret_cloned()),
            ("algorithm", self.algorithm.name().to_ascii_uppercase()),
            ("digits", self.digits.to_string()),
            ("period", self.period.to_string()),
        ]
    }
}

/// A one-time enrollment token, in place of [`InviteTotp`].
///
/// What travels in the link is not the credential: the holder exchanges it for
/// one on first connect ([`crate::auth::Enrollment::exchange`]), and the server
/// burns it in the same breath. A copied link therefore stops being a
/// credential the first time it is used, instead of staying one until somebody
/// rotates the secret by hand.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteEnrollment {
    pub client_id: String,
    /// Opaque to the client: generated by the server, compared by the server.
    ///
    /// A [`SecretString`]: the link that carries this token is the credential
    /// until it is spent, and the token is wiped when the invite is dropped.
    pub token: SecretString,
}

impl fmt::Debug for InviteEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteEnrollment")
            .field("client_id", &self.client_id)
            .field("token", &REDACTED)
            .finish()
    }
}

impl InviteEnrollment {
    pub fn new(client_id: &str, token: &str) -> Result<Self> {
        let client_id = client_id.trim();
        if client_id.is_empty() {
            bail!("the enrollment client id is empty");
        }
        let token = token.trim();
        if token.is_empty() {
            bail!("the enrollment token is empty");
        }
        Ok(Self {
            client_id: client_id.to_string(),
            token: SecretString::new(token.to_string()),
        })
    }

    /// Parameters, in the order [`EndpointInvite::to_uri`] writes them.
    fn to_params(&self) -> Vec<(&'static str, String)> {
        vec![
            ("client", self.client_id.clone()),
            ("enroll", self.token.expose_secret_cloned()),
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
    /// Set instead of [`Self::totp`] by an invite that hands out an enrollment
    /// token; the two are mutually exclusive by construction.
    pub enrollment: Option<InviteEnrollment>,
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
            enrollment: None,
        })
    }

    /// Labels the endpoint. Empty names are dropped rather than erroring.
    pub fn with_name(mut self, name: &str) -> Self {
        let name = name.trim();
        self.name = (!name.is_empty()).then(|| name.to_string());
        self
    }

    /// Adds a relay hint. A hint that names no usable relay is ignored, not
    /// trusted.
    pub fn with_relay(mut self, relay: Option<&str>) -> Self {
        match relay.map(str::trim) {
            Some(relay) if !relay.is_empty() && is_usable_relay_hint(relay) => {
                self.relay = Some(relay.to_string());
            }
            _ => self.relay = None,
        }
        self
    }

    /// Attaches 2FA credentials.
    ///
    /// Clears any enrollment: an invite hands out either the secret or a token
    /// standing in for it, never both.
    pub fn with_totp(mut self, totp: Option<InviteTotp>) -> Self {
        if totp.is_some() {
            self.enrollment = None;
        }
        self.totp = totp;
        self
    }

    /// Attaches a one-time enrollment token instead of the credentials.
    ///
    /// Clears any [`InviteTotp`] for the same reason [`Self::with_totp`] clears
    /// the enrollment.
    pub fn with_enrollment(mut self, enrollment: Option<InviteEnrollment>) -> Self {
        if enrollment.is_some() {
            self.totp = None;
        }
        self.enrollment = enrollment;
        self
    }

    /// Renders the canonical link. Optional fields that are unset or empty are
    /// left out, so two invites with the same shape always compare equal.
    pub fn to_uri(&self) -> String {
        // v=2 says "this code carries an enrollment token", and v=1 says it
        // does not, so an app that only knows v=1 refuses a v=2 code instead of
        // reading it as an endpoint share with the credentials missing.
        let version = if self.enrollment.is_some() {
            ENROLLMENT_INVITE_VERSION
        } else {
            INVITE_VERSION
        };
        let mut params: Vec<(&str, String)> = vec![("v", version.to_string())];

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
        if let Some(enrollment) = &self.enrollment {
            params.extend(enrollment.to_params());
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
        // A code past the hard limit is not a code anybody will read, and
        // parsing it is work an attacker gets for free.
        if raw.len() > MAX_URI_LEN {
            anyhow::bail!(
                "the invite code is {} bytes, past the {MAX_URI_LEN} byte limit",
                raw.len()
            );
        }
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
        // A version is not decoration: v=2 codes carry a token where v=1 codes
        // carry a secret, so accepting an unknown version is how a newer code
        // comes to be read as an older one with its credentials missing.
        let version = match params.first("v") {
            Some(version) => {
                let version: u32 = version
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invite version {version:?} is not a number"))?;
                if version != INVITE_VERSION && version != ENROLLMENT_INVITE_VERSION {
                    bail!(
                        "unsupported invite version {version} (this build understands \
                         {INVITE_VERSION} and {ENROLLMENT_INVITE_VERSION})"
                    );
                }
                version
            }
            None => INVITE_VERSION,
        };

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
                    if !is_usable_relay_hint(relay) {
                        anyhow::bail!(
                            "the relay hint {relay:?} is invalid: it does not name a relay this \
                             client can reach"
                        );
                    }
                    Some(relay.to_string())
                }
                _ => None,
            },
            totp: totp_from_params(&params)?,
            enrollment: enrollment_from_params(&params, version)?,
        })
    }

    /// Whether this invite hands out a token instead of a secret.
    pub fn is_enrollment(&self) -> bool {
        self.enrollment.is_some()
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
        // No secret at all: either a plain endpoint share, or a mistake — and
        // an enrollment is the one shape that carries a client id without one.
        if params.first("enroll").is_none()
            && params.has_any(["client", "issuer", "algorithm", "digits", "period"])
        {
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

/// The enrollment block of the invite, if any.
///
/// `enroll` is only meaningful in a v=2 code: an app that understands v=1
/// ignores unknown parameters, so a token smuggled into a v=1 code would be
/// dropped silently and the scan would import a credential-less endpoint.
fn enrollment_from_params(params: &QueryParams, version: u32) -> Result<Option<InviteEnrollment>> {
    let Some(token) = params.first("enroll") else {
        return Ok(None);
    };
    if version < ENROLLMENT_INVITE_VERSION {
        bail!("the invite carries an enrollment token but is version {version}");
    }
    // Both spellings, not just `secret`: `otpauth` is the parameter an app
    // that copied an otpauth:// URI into the link would carry, and it is a
    // secret by another name. Letting it through yields an invite holding a
    // credential *and* a token for one that is about to be issued, which is
    // two answers to "what does this client authenticate with".
    if params.first("secret").is_some() || params.first("otpauth").is_some() {
        bail!("the invite carries both an enrollment token and a 2FA secret");
    }
    let Some(client_id) = params.first("client") else {
        bail!("the invite carries an enrollment token but no client id");
    };
    InviteEnrollment::new(client_id, token).map(Some)
}

/// Reads the algorithm name.
///
/// The same parser the configuration path uses — see
/// [`TotpAlgorithm::try_from_name`] — so the two cannot drift apart: an invite
/// and a config that name the same algorithm have to be read the same way.
///
/// An absent name is the default, `sha1`, which is what a URI that leaves the
/// parameter out means.
fn parse_algorithm(name: Option<&str>) -> Result<TotpAlgorithm> {
    Ok(TotpAlgorithm::try_from_name(name.unwrap_or_default())?)
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
///
/// The spellings it passes through are copies of the secret, so they are
/// [`SecretString`]s: each is wiped when it goes out of scope, rather than
/// being left in the heap for the allocator to hand out again.
fn normalize_secret(raw: &str) -> Result<SecretString> {
    let compact = SecretString::new(
        raw.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );
    let secret = SecretString::new(compact.as_str().trim_end_matches('=').to_ascii_uppercase());

    if secret.as_str().is_empty() {
        bail!("the 2FA secret is empty");
    }
    // The secret itself is left out of both messages: these errors are shown
    // to a user and end up in logs, and this module redacts the secret
    // everywhere else it prints an invite.
    if secret.as_str().len() < 8 {
        bail!(
            "the 2FA secret is too short: {} characters, at least 8",
            secret.as_str().len()
        );
    }
    if !secret
        .as_str()
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
    {
        bail!("the 2FA secret is not Base32");
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
fn normalize_domains(domains: &[String]) -> Result<Vec<String>> {
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
struct QueryParams(Vec<(String, SecretString)>);

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
        out.push((
            percent_decode(key)?,
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
    /// A relay hint that names no relay this client can reach is refused.
    ///
    /// The URL parser accepting it is not the question: the hint is applied
    /// later, as a relay URL, and a hint that names nothing usable is not a
    /// hint.
    #[test]
    fn a_relay_hint_that_names_no_relay_is_refused() {
        for hint in [
            "ftp://relay.example.com",
            "file:///etc/passwd",
            "foo://relay.example.com",
            "https://",
            "https://aps1-1.relay.n0.iroh.link",
        ] {
            assert!(
                !is_usable_relay_hint(hint),
                "{hint:?} is not a relay this client can reach"
            );

            let uri = format!(
                "nexapipe://endpoint/{}?v=1&relay={}",
                node_id(),
                percent_encode(hint)
            );
            assert!(
                EndpointInvite::from_uri(&uri).is_err(),
                "a code carrying {hint:?} is refused"
            );
        }
    }

    /// A hint that names a relay this client can reach is kept.
    ///
    /// A self-hosted relay over plain HTTP is a supported deployment, so
    /// `http://` is as good as `https://` here.
    #[test]
    fn a_relay_hint_that_names_a_relay_is_kept() {
        for hint in [
            "https://relay.example.com",
            "http://relay.example.com",
            "wss://relay.example.com",
        ] {
            assert!(is_usable_relay_hint(hint), "{hint:?} is usable");
        }

        let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
            .unwrap()
            .with_relay(Some("https://relay.example.com"));
        assert_eq!(invite.relay.as_deref(), Some("https://relay.example.com"));
    }

    /// A hint that names no relay is dropped rather than obeyed.
    #[test]
    fn a_hint_that_names_no_relay_is_dropped_rather_than_obeyed() {
        let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
            .unwrap()
            .with_relay(Some("ftp://relay.example.com"));
        assert!(
            invite.relay.is_none(),
            "a hint that names no relay is not kept"
        );
    }

    /// A code past the hard limit is refused rather than parsed.
    #[test]
    fn a_code_past_the_hard_limit_is_refused() {
        let long = "x".repeat(MAX_URI_LEN + 1);
        let uri = format!("nexapipe://endpoint/{long}");
        let error = EndpointInvite::from_uri(&uri).expect_err("the code is past the limit");
        assert!(error.to_string().contains("past the"), "{error}");
    }

    /// The invite path and the configuration path read a name the same way.
    ///
    /// They used to be two parsers: the invite one was strict and the
    /// configuration one fell back to SHA1. A name the invite path refused and
    /// the configuration path accepted was a name the two halves of the client
    /// did not agree about.
    #[test]
    fn the_invite_and_the_configuration_read_a_name_the_same_way() {
        for name in ["sha1", "sha256", "sha512", "SHA1", "SHA256", "SHA512"] {
            let invite = parse_algorithm(Some(name)).expect("the invite path accepts it");
            let config = TotpAlgorithm::try_from_name(name).expect("the config path accepts it");
            assert_eq!(invite, config, "{name:?} is read the same way by both");
        }

        for name in ["sha-256", "SHA3-256", "sha", "sha 256", "sha1x"] {
            assert!(
                parse_algorithm(Some(name)).is_err(),
                "the invite path refuses {name:?}"
            );
            assert!(
                TotpAlgorithm::try_from_name(name).is_err(),
                "the configuration path refuses {name:?}"
            );
        }
    }

    /// An invite that names no algorithm gets the default.
    #[test]
    fn an_invite_that_names_no_algorithm_gets_the_default() {
        assert_eq!(
            parse_algorithm(None).expect("the default"),
            TotpAlgorithm::SHA1
        );
        assert_eq!(
            parse_algorithm(Some("")).expect("the default"),
            TotpAlgorithm::SHA1
        );
    }

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
        // v=2 became real — enrollment — so the version nobody can read is the
        // next one along.
        let error = EndpointInvite::from_uri(&format!(
            "{INVITE_SCHEME}://{NODE_ID_HOST}/{}/?v=3",
            node_id()
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains("unsupported invite version 3"),
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

    /// The domain list is a list of patterns, and the server's route patterns
    /// are what ends up in an invite.
    ///
    /// `*.` is the catch-all in another spelling: folded into `*`, it would
    /// hand the client the catch-all — every host — for a spelling that asked
    /// for something narrower. It keeps its own shape instead, and a pattern
    /// in that shape matches nothing.
    #[test]
    fn a_pattern_that_folds_into_the_catch_all_keeps_its_shape() {
        let invite = EndpointInvite::new(
            EndpointTarget::NodeId(node_id().to_string()),
            &["*.example.com".to_string(), "*.".to_string()],
        )
        .unwrap();
        assert_eq!(
            invite.domains,
            vec!["*.example.com".to_string(), "*.".to_string()]
        );
        // And so the client does not proxy every host on the strength of a
        // spelling that never asked for it.
        let proxied = crate::domains::should_proxy_domain("example.com", &invite.domains);
        assert!(!proxied);
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
        assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
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
    fn a_rejected_secret_is_not_quoted_back() {
        // These errors are shown to a user and end up in logs, so the secret
        // has to stay out of them whatever the reason it was refused.
        for bad in ["hello-there", "ab", "JBSWY3DPEHPK3PX!"] {
            let error = InviteTotp::new("client-001", bad).unwrap_err();
            assert!(!error.to_string().contains(bad), "{error}");
        }
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
        assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
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
        assert_eq!(totp.secret.as_str(), "JBSWY3DPEHPK3PXP");
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

    #[test]
    fn an_enrollment_invite_round_trips_as_v2() {
        let enrollment = InviteEnrollment::new("client-001", "token-abc").unwrap();
        let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
            .unwrap()
            .with_name("Home")
            .with_enrollment(Some(enrollment.clone()));

        let uri = invite.to_uri();
        assert!(uri.contains("v=2"), "{uri}");
        assert!(uri.contains("enroll=token-abc"), "{uri}");
        assert!(!uri.contains("secret="), "{uri}");
        assert!(invite.is_enrollment());

        let parsed = EndpointInvite::from_uri(&uri).unwrap();
        assert_eq!(parsed, invite);
        assert_eq!(parsed.enrollment.as_ref().unwrap(), &enrollment);
        assert!(parsed.totp.is_none());
    }

    /// v=1 apps ignore parameters they do not know, so a token in a v=1 code
    /// would be dropped and the scan would import a credential-less endpoint
    /// that looks like it worked.
    #[test]
    fn a_v1_code_may_not_carry_an_enrollment_token() {
        let uri = format!(
            "nexapipe://endpoint/{}?v=1&client=client-001&enroll=token-abc",
            node_id()
        );
        let err = EndpointInvite::from_uri(&uri).unwrap_err().to_string();
        assert!(err.contains("enrollment"), "{err}");
    }

    /// A code that hands out both is a code that cannot say which one wins.
    #[test]
    fn a_token_and_a_secret_cannot_share_a_code() {
        let uri = format!(
            "nexapipe://endpoint/{}?v=2&client=client-001&enroll=token-abc&secret=JBSWY3DPEHPK3PXP",
            node_id()
        );
        let err = EndpointInvite::from_uri(&uri).unwrap_err().to_string();
        assert!(err.contains("both"), "{err}");

        // Same thing on the way out: whichever was attached last wins.
        let invite = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
            .unwrap()
            .with_totp(Some(
                InviteTotp::new("client-001", "JBSWY3DPEHPK3PXP").unwrap(),
            ))
            .with_enrollment(Some(InviteEnrollment::new("client-001", "tok").unwrap()));
        assert!(invite.totp.is_none());
        assert!(invite.is_enrollment());
    }

    #[test]
    fn an_empty_enrollment_token_is_refused() {
        assert!(InviteEnrollment::new("client-001", "  ").is_err());
        assert!(InviteEnrollment::new("", "tok").is_err());
    }

    /// A secret is a credential, so nothing that formats an invite — a parse
    /// error, a UI binding, a log line — may carry one.
    #[test]
    fn debug_never_prints_the_secret() {
        let totp = InviteTotp::new("client-001", "jbswy3dpehpk3pxp").unwrap();
        let printed = format!("{totp:?}");
        // Static messages, not `{printed}`: an assertion message is a log sink
        // to a scanner, and one that prints the Debug output taints the secret
        // straight into it — even though what it would print is already
        // redacted, which taint tracking cannot see.
        assert!(
            !printed.contains("JBSWY3DPEHPK3PXP"),
            "the secret must not appear in Debug output"
        );
        assert!(
            printed.contains("***"),
            "the redaction marker must appear in Debug output"
        );
    }

    #[test]
    fn debug_never_prints_the_enrollment_token() {
        let enrollment = InviteEnrollment::new("client-001", "tok-abc").unwrap();
        let printed = format!("{enrollment:?}");
        assert!(
            !printed.contains("tok-abc"),
            "the token must not appear in Debug output"
        );
        assert!(
            printed.contains("***"),
            "the redaction marker must appear in Debug output"
        );
    }

    /// The whole invite carries whichever of the two it was given, so its own
    /// `Debug` has to be redacted as well — and the URI must *not* be, because
    /// a redacted invite scans to nothing.
    #[test]
    fn debug_of_a_whole_invite_redacts_the_credential_it_carries() {
        let printed = format!("{:?}", invite());
        assert!(!printed.contains("JBSWY3DPEHPK3PXP"), "{printed}");
        assert!(invite().to_uri().contains("secret=JBSWY3DPEHPK3PXP"));

        let with_token = EndpointInvite::new(EndpointTarget::NodeId(node_id().to_string()), &[])
            .unwrap()
            .with_enrollment(Some(
                InviteEnrollment::new("client-001", "tok-abc").unwrap(),
            ));
        assert!(!format!("{with_token:?}").contains("tok-abc"));
        assert!(with_token.to_uri().contains("enroll=tok-abc"));
    }
}
