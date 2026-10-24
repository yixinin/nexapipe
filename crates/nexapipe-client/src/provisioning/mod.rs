//! Endpoint invitations: one `nexapipe://` link carrying everything a client
//! needs before it can talk to an endpoint.
//!
//! ## Grammar
//!
//! ```text
//! nexapipe://endpoint/<node-id>?v=1&name=Home&domains=a.example,b.example
//!     &relay=https%3A%2F%2Frelay.example
//!     &client=client-001&issuer=NexaPipe&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
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

// The four halves of an invite: the invite itself, the credentials it can
// carry, the TOTP half of those, and the link's own plumbing.
mod credential;
mod invite;
mod totp;
mod uri;

#[cfg(test)]
mod tests;

pub use credential::{InviteEnrollment, InviteTotp};
pub use invite::{EndpointInvite, EndpointTarget};

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
