//! The TOTP half of an invite.
//!
//! The seed reaches the client in one of two shapes: the flat parameters of
//! the link, or a whole `otpauth://` URI folded into one of them. Both are
//! read here, into the same structure.

use anyhow::{Result, bail};
use nexapipe_proto::secret::SecretString;

use crate::auth::{MIN_SECRET_BYTES, TotpAlgorithm};

use super::DEFAULT_ISSUER;
use super::credential::InviteTotp;
use super::uri::{QueryParams, parse_query, percent_decode};

/// The 2FA block of the invite, if any.
///
/// The flat form wins; `otpauth` is only consulted when no `secret` was given,
/// which is how codes produced by a generic authenticator interop layer read.
pub(super) fn totp_from_params(params: &QueryParams) -> Result<Option<InviteTotp>> {
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

/// Reads the algorithm name.
///
/// The same parser the configuration path uses — see
/// [`TotpAlgorithm::try_from_name`] — so the two cannot drift apart: an invite
/// and a config that name the same algorithm have to be read the same way.
///
/// An absent name is the default, `sha1`, which is what a URI that leaves the
/// parameter out means.
pub(super) fn parse_algorithm(name: Option<&str>) -> Result<TotpAlgorithm> {
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
pub(super) fn normalize_secret(raw: &str) -> Result<SecretString> {
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
    if !secret
        .as_str()
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
    {
        bail!("the 2FA secret is not Base32");
    }
    let decoded = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        secret.as_str(),
    )
    .ok_or_else(|| anyhow::anyhow!("the 2FA secret is not Base32"))?;
    if decoded.len() < MIN_SECRET_BYTES {
        bail!(
            "the 2FA secret decodes to {} byte{}; a TOTP secret is at least {MIN_SECRET_BYTES} bytes",
            decoded.len(),
            if decoded.len() == 1 { "" } else { "s" }
        );
    }
    Ok(secret)
}
