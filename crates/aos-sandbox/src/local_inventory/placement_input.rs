//! Non-authorizing error DATA shared by placement input and liveness validation.
//!
//! The complete error vocabulary is shared without converting verifier errors
//! into a separate scheduler family or introducing an authority result.

/// Reports malformed, incomplete, or nondeterministic placement inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidPlacementInput {
    /// An identity uses its all-zero sentinel.
    #[error("placement input contains an unspecified identity")]
    UnspecifiedIdentity,
    /// Candidate snapshots are oversized, duplicated, or not ordered by node.
    #[error("placement candidates must be a canonical set of at most 4096 nodes")]
    CandidatesNotCanonical,
    /// Affinity observations are oversized, duplicated, or not ordered by sandbox.
    #[error("affinity observations must be a canonical set of at most 4096 sandboxes")]
    AffinitiesNotCanonical,
    /// The semantic request exceeds the scheduler's bounded feature profile.
    #[error("placement request exceeds the 64-feature scheduler limit")]
    TooManyRequiredFeatures,
    /// A required feature is outside the local closed semantic registry.
    #[error("placement request contains an unknown required feature")]
    UnknownRequiredFeature,
    /// Freshness evaluation has no positive maximum age.
    #[error("placement capability maximum age must be positive")]
    InvalidFreshnessLimit,
    /// A local-live dependency lacks exact current worker and durability evidence.
    #[error("local-live affinity evidence is absent, stale, or unprotected")]
    AffinityNotLive,
}
