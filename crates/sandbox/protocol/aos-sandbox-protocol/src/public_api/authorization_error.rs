//! Reports structural authorization and provenance DATA refusals.
//!
//! These errors contain no authenticated identity, protected decision or native owner.

/// Reports invalid authenticated request provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidRequestProvenance {
    /// Canonical bytes are empty or exceed their fixed ceiling.
    #[error("canonical request bytes are invalid")]
    InvalidCanonicalRequest,
    /// The resolved action does not carry its exact required fence kind.
    #[error("resolved mutation fence does not match its action")]
    InvalidMutationFence,
}

/// Reports invalid or inconsistently bound authenticated CLI evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CliAuthorizationAdapterError {
    /// An authenticated identity, session, or channel value is absent or oversized.
    #[error("authenticated CLI evidence is invalid")]
    InvalidAuthenticatedEvidence,
    /// Authenticated bytes do not encode the exact closed canonical V1 request schema.
    #[error("authenticated CLI authorization request is invalid or noncanonical")]
    InvalidCanonicalAuthorizationRequest,
    /// Current protected lookup or authorization rejected the requested operation.
    #[error("current protected CLI authorization was rejected")]
    ProtectedAuthorizationRejected,
    /// The authenticated session names a different identity.
    #[error("authenticated CLI identity and session evidence do not match")]
    IdentitySessionMismatch,
    /// The authenticated channel names a different identity or session.
    #[error("authenticated CLI session and channel evidence do not match")]
    SessionChannelMismatch,
    /// Current protected authorization names a different identity, session, or channel.
    #[error("authenticated CLI evidence does not match current protected authorization")]
    ProtectedBindingMismatch,
    /// Authenticated or protected evidence covers different canonical request bytes.
    #[error("canonical CLI request does not match authenticated authorization evidence")]
    RequestBindingMismatch,
    /// Protected authorization covers another authority surface.
    #[error("protected CLI authorization does not cover the requested authority surface")]
    AuthoritySurfaceMismatch,
    /// The resolved mutation differs from the authenticated identity and fence commitment.
    #[error("resolved CLI mutation does not match authenticated identity and fences")]
    MutationBindingMismatch,
    /// Canonical request or resolved-mutation provenance is invalid.
    #[error(transparent)]
    Provenance(#[from] InvalidRequestProvenance),
}
