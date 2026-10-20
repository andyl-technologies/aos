//! Classifies redacted public API session failures as nonauthorizing DATA.
//!
//! An error classification cannot construct a native credential pin, a TLS
//! peer, a registered principal or an authenticated request. Native custody and
//! the actual TLS and request admission engines stay with their owners.

/// Reports redacted public-session configuration, authentication, or currentness failure.
#[derive(Debug, thiserror::Error)]
pub enum PublicApiSessionError {
    /// Protected credential provenance or the closed registration schema is invalid.
    #[error("public API session credentials are invalid")]
    Configuration,
    /// TLS proof, registered identity, HTTP/2 negotiation, or handshake timing failed.
    #[error("public API session authentication failed")]
    Authentication,
    /// The connection, certificate, credential snapshot, or bounded lifetime is no longer current.
    #[error("public API session is no longer current")]
    Stale,
}
