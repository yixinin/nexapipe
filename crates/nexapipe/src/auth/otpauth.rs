//! Standard `otpauth://` enrollment URIs.
//!
//! A QR code that carries a [Key URI Format] link is the portable way to hand
//! 2FA credentials to a phone: `--generate-2fa` prints one, the NexaPipe app
//! scans it, and any third party authenticator app can import it as well.
//!
//! The layout produced here is byte for byte the one the Android client builds
//! in `com.nexa.pipe.otp.OtpAuth.build`, so a code generated on the server and
//! one generated on the phone round trip through the same parser:
//!
//! ```text
//! otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP&issuer=NexaPipe&algorithm=SHA1&digits=6&period=30
//!          |    |          |                                                        |
//!          |    |          +-- account name, read back as the client ID            +-- parameters, all lowercase keys
//!          |    +------------- `issuer:account`, the colon is kept literal
//!          +------------------ TOTP only, HOTP is not implemented by the client
//! ```
//!
//! [Key URI Format]: https://github.com/google/google-authenticator/wiki/Key-Uri-Format

use super::config::AuthConfig;
use anyhow::{Result, bail};

/// Scheme of the key URI format.
pub const SCHEME: &str = "otpauth";

/// Issuer used when `[auth] issuer` is not configured, matching the Android
/// client's `OtpAuth.ISSUER`.
pub const DEFAULT_ISSUER: &str = "NexaPipe";

/// Digits the NexaPipe clients always derive, whatever the server advertises.
pub const CLIENT_DIGITS: u32 = 6;

/// Time step in seconds the NexaPipe clients always use.
pub const CLIENT_PERIOD: u32 = 30;

/// Base32 alphabet (RFC 4648) without padding.
const BASE32_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// One enrollment entry: everything an authenticator app needs to derive the
/// same codes this server expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuthUri {
    /// Label shown by the authenticator app, e.g. `NexaPipe`.
    pub issuer: String,
    /// Client ID as configured in `[auth.clients]`.
    pub client_id: String,
    /// Base32 secret, normalized to the form the clients expect.
    pub secret: String,
    /// Uppercase algorithm name, as the key URI format requires.
    pub algorithm: String,
    /// Number of digits in a code.
    pub digits: u32,
    /// Time step in seconds.
    pub period: u32,
}

impl OtpAuthUri {
    /// Validates and normalizes every part of an entry.
    pub fn new(
        issuer: &str,
        client_id: &str,
        secret: &str,
        algorithm: &str,
        digits: u32,
        period: u32,
    ) -> Result<Self> {
        let issuer = issuer.trim();
        if issuer.is_empty() {
            bail!("the issuer must not be empty");
        }

        let client_id = client_id.trim();
        if client_id.is_empty() {
            bail!("the client ID must not be empty");
        }

        let secret = normalize_secret(secret)
            .ok_or_else(|| anyhow::anyhow!("the secret is not a Base32 string"))?;
        if base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret).is_none() {
            bail!("the secret is not a Base32 string");
        }

        let algorithm = match algorithm.trim().to_ascii_lowercase().as_str() {
            "sha1" => "SHA1",
            "sha256" => "SHA256",
            "sha512" => "SHA512",
            other => bail!(
                "unsupported algorithm {:?}; expected sha1, sha256 or sha512",
                other
            ),
        };

        if digits == 0 || digits > 10 {
            bail!("the digit count must be between 1 and 10, got {}", digits);
        }
        if period == 0 {
            bail!("the time step must be at least one second");
        }

        Ok(Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            secret,
            algorithm: algorithm.to_string(),
            digits,
            period,
        })
    }

    /// Builds an entry from the server's `[auth]` settings, which are what the
    /// TOTP validator actually accepts.
    pub fn from_auth_config(
        issuer: &str,
        client_id: &str,
        secret: &str,
        config: &AuthConfig,
    ) -> Result<Self> {
        Self::new(
            issuer,
            client_id,
            secret,
            config.algorithm.name(),
            config.digits,
            config.time_step,
        )
    }

    /// Renders the entry as an `otpauth://totp/...` URI.
    pub fn to_uri(&self) -> String {
        // The colon separating issuer and account is part of the label syntax
        // and must survive encoding; everything else is escaped. The secret is
        // Base32, so it needs no escaping at all.
        let label = percent_encode(&format!("{}:{}", self.issuer, self.client_id), ":");
        let issuer = percent_encode(&self.issuer, "");
        format!(
            "{SCHEME}://totp/{label}?secret={}&issuer={issuer}&algorithm={}&digits={}&period={}",
            self.secret, self.algorithm, self.digits, self.period
        )
    }

    /// Settings the authenticator app is told about but the NexaPipe clients
    /// cannot honor, because they hardcode 6 digits and a 30 second step.
    pub fn client_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.digits != CLIENT_DIGITS {
            warnings.push(format!(
                "[auth] digits = {} but NexaPipe clients always generate {} digits, \
                 so their codes will not match the server",
                self.digits, CLIENT_DIGITS
            ));
        }
        if self.period != CLIENT_PERIOD {
            warnings.push(format!(
                "[auth] time_step = {} but NexaPipe clients always use {} seconds, \
                 so their codes will not match the server",
                self.period, CLIENT_PERIOD
            ));
        }
        warnings
    }
}

/// Normalizes a Base32 secret to the form the clients expect: uppercase, with
/// whitespace and padding removed. Returns `None` when characters outside the
/// Base32 alphabet are present.
pub fn normalize_secret(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() || !cleaned.chars().all(|c| BASE32_ALPHABET.contains(c)) {
        return None;
    }
    Some(cleaned)
}

/// Percent-encodes `value` for use in a URI, leaving the unreserved set plus
/// every character listed in `keep` untouched. Non-ASCII input is encoded byte
/// by byte, i.e. as UTF-8, which is what the clients decode.
pub fn percent_encode(value: &str, keep: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        let ch = byte as char;
        let unreserved = ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~');
        if unreserved || (ch.is_ascii() && keep.contains(ch)) {
            out.push(ch);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TotpAlgorithm;

    fn entry(client_id: &str) -> OtpAuthUri {
        OtpAuthUri::new("NexaPipe", client_id, "JBSWY3DPEHPK3PXP", "sha1", 6, 30).unwrap()
    }

    /// The exact string the Android client's `OtpAuth.parse` is fed by a QR
    /// code generated here.
    #[test]
    fn builds_the_canonical_uri() {
        assert_eq!(
            entry("client-001").to_uri(),
            "otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP\
             &issuer=NexaPipe&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn uppercases_the_algorithm_and_strips_secret_padding() {
        let uri = OtpAuthUri::new("NexaPipe", "c1", "jbswy3dpehpk3pxp==", "Sha256", 8, 60)
            .unwrap()
            .to_uri();
        assert!(
            uri.ends_with("&algorithm=SHA256&digits=8&period=60"),
            "{uri}"
        );
        assert!(uri.contains("?secret=JBSWY3DPEHPK3PXP&"), "{uri}");
    }

    #[test]
    fn escapes_labels_and_issuers_but_keeps_the_separator() {
        let uri = OtpAuthUri::new(
            "My Company",
            "client 001",
            "JBSWY3DPEHPK3PXP",
            "sha1",
            6,
            30,
        )
        .unwrap()
        .to_uri();
        assert_eq!(
            uri,
            "otpauth://totp/My%20Company:client%20001?secret=JBSWY3DPEHPK3PXP\
             &issuer=My%20Company&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn encodes_non_ascii_client_ids_as_utf8() {
        let uri = entry("手机-01").to_uri();
        assert!(
            uri.starts_with("otpauth://totp/NexaPipe:%E6%89%8B%E6%9C%BA-01?"),
            "{uri}"
        );
    }

    #[test]
    fn encodes_reserved_characters_in_client_ids() {
        assert_eq!(percent_encode("a&b=c?d/e#f", ":"), "a%26b%3Dc%3Fd%2Fe%23f");
    }

    #[test]
    fn rejects_malformed_entries() {
        let secret = "JBSWY3DPEHPK3PXP";
        assert!(OtpAuthUri::new("", "c1", secret, "sha1", 6, 30).is_err());
        assert!(OtpAuthUri::new("NexaPipe", "  ", secret, "sha1", 6, 30).is_err());
        assert!(OtpAuthUri::new("NexaPipe", "c1", "not-base32!", "sha1", 6, 30).is_err());
        assert!(OtpAuthUri::new("NexaPipe", "c1", "", "sha1", 6, 30).is_err());
        assert!(OtpAuthUri::new("NexaPipe", "c1", secret, "md5", 6, 30).is_err());
        assert!(OtpAuthUri::new("NexaPipe", "c1", secret, "sha1", 0, 30).is_err());
        assert!(OtpAuthUri::new("NexaPipe", "c1", secret, "sha1", 6, 0).is_err());
    }

    #[test]
    fn normalizes_secrets_like_the_clients_do() {
        assert_eq!(
            normalize_secret(" jbswy3dp ehpk3pxp==\n").as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(normalize_secret("JBSWY3DPEHPK3PX1"), None);
        assert_eq!(normalize_secret("  "), None);
    }

    #[test]
    fn warns_about_settings_the_clients_ignore() {
        let ok = entry("c1");
        assert!(ok.client_warnings().is_empty());

        let odd = OtpAuthUri::new("NexaPipe", "c1", "JBSWY3DPEHPK3PXP", "sha1", 8, 60).unwrap();
        assert_eq!(odd.client_warnings().len(), 2);
    }

    #[test]
    fn uses_the_server_settings_from_the_auth_config() {
        let config = AuthConfig {
            algorithm: TotpAlgorithm::SHA512,
            digits: 6,
            time_step: 30,
            ..Default::default()
        };
        let uri = OtpAuthUri::from_auth_config("NexaPipe", "c1", "JBSWY3DPEHPK3PXP", &config)
            .unwrap()
            .to_uri();
        assert!(
            uri.contains("&algorithm=SHA512&digits=6&period=30"),
            "{uri}"
        );
    }

    #[test]
    fn defaults_the_issuer_to_the_client_constant() {
        assert_eq!(AuthConfig::default().issuer, DEFAULT_ISSUER);
    }
}
