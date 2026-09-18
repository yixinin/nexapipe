//! 2FA authentication module for Nexapipe server.
//!
//! Provides TOTP (Time-based One-Time Password) verification for client connections.

pub mod config;
pub mod otpauth;
pub mod protocol;
pub mod totp;

pub use config::{AuthConfig, ClientAuth, TotpAlgorithm};
pub use otpauth::{DEFAULT_ISSUER, OtpAuthUri};
pub use protocol::{AuthMessage, AuthState};
pub use totp::{AuthError, TotpValidator};
