//! Retains native Publisher errors and exact canonical DATA projections.

use crate::JournalError;

impl From<aos_sandbox_protocol::policy_data::PublisherPolicyDataError> for PublisherPolicyError {
    fn from(error: aos_sandbox_protocol::policy_data::PublisherPolicyDataError) -> Self {
        match error {
            aos_sandbox_protocol::policy_data::PublisherPolicyDataError::LimitExceeded(dimension) => {
                Self::LimitExceeded(dimension)
            }
            aos_sandbox_protocol::policy_data::PublisherPolicyDataError::InvalidPolicyRevision => {
                Self::InvalidPolicyRevision
            }
            aos_sandbox_protocol::policy_data::PublisherPolicyDataError::CorruptState => Self::CorruptState,
        }
    }
}

/// Reports invalid or unavailable current publisher policy state.
#[derive(Debug, thiserror::Error)]
pub enum PublisherPolicyError {
    /// Store limits are zero or above fixed ceilings.
    #[error("publisher policy limits are invalid")]
    InvalidLimits,
    /// A bounded dimension was exceeded.
    #[error("publisher policy limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Canonical policy bytes or revision metadata are invalid.
    #[error("publisher policy revision is invalid")]
    InvalidPolicyRevision,
    /// A cache-resource binding is malformed.
    #[error("publisher resource binding is invalid")]
    InvalidResourceBinding,
    /// A current generation head is malformed.
    #[error("publisher generation head is invalid")]
    InvalidGenerationHead,
    /// A proposed project-to-revocation-scope mapping has a sentinel or lacks
    /// a current policy or scope head.
    #[error("publisher project revocation binding is invalid")]
    InvalidProjectRevocationBinding,
    /// A current publisher policy has no exact project disclosure identity.
    #[error("publisher project cache-domain binding is invalid")]
    InvalidProjectCacheDomainBinding,
    /// The immutable project-to-revocation-scope mapping already exists.
    #[error("publisher project revocation binding already exists")]
    ProjectRevocationBindingAlreadyExists,
    /// A requested update lost its exact current-generation comparison.
    #[error("publisher policy compare-and-swap failed")]
    CompareAndSwapFailed,
    /// A successor generation is not the exact checked increment.
    #[error("publisher policy generation is not contiguous")]
    NoncontiguousGeneration,
    /// The current generation cannot be incremented without wrapping.
    #[error("publisher policy generation space is exhausted")]
    GenerationExhausted,
    /// An immutable revision key already exists.
    #[error("publisher policy revision already exists")]
    RevisionAlreadyExists,
    /// An immutable resource key already exists.
    #[error("publisher resource binding already exists")]
    ResourceAlreadyExists,
    /// Controller generation attempted to change its immutable principal.
    #[error("publisher controller authority principal differs")]
    ControllerPrincipalMismatch,
    /// A policy grant lacks its exact protected resource-domain binding.
    #[error("publisher policy resource binding is missing or inconsistent")]
    ResourcePolicyMismatch,
    /// The retained namespace is malformed, unknown, or cross-linked incorrectly.
    #[error("publisher policy namespace is corrupt")]
    CorruptState,
    /// Protected journal access or durability failed.
    #[error("publisher policy journal failed: {0}")]
    Journal(#[from] JournalError),
}

impl From<aos_sandbox_protocol::publisher_policy::PublisherPolicySchemaErrorV1> for PublisherPolicyError {
    fn from(error: aos_sandbox_protocol::publisher_policy::PublisherPolicySchemaErrorV1) -> Self {
        use aos_sandbox_protocol::publisher_policy::PublisherPolicySchemaErrorV1 as DataError;
        match error {
            DataError::InvalidLimits => Self::InvalidLimits,
            DataError::LimitExceeded(value) => Self::LimitExceeded(value),
            DataError::InvalidPolicyRevision => Self::InvalidPolicyRevision,
            DataError::InvalidResourceBinding => Self::InvalidResourceBinding,
            DataError::InvalidGenerationHead => Self::InvalidGenerationHead,
            DataError::InvalidProjectRevocationBinding => Self::InvalidProjectRevocationBinding,
            DataError::InvalidProjectCacheDomainBinding => Self::InvalidProjectCacheDomainBinding,
            DataError::ProjectRevocationBindingAlreadyExists => Self::ProjectRevocationBindingAlreadyExists,
            DataError::CompareAndSwapFailed => Self::CompareAndSwapFailed,
            DataError::NoncontiguousGeneration => Self::NoncontiguousGeneration,
            DataError::GenerationExhausted => Self::GenerationExhausted,
            DataError::RevisionAlreadyExists => Self::RevisionAlreadyExists,
            DataError::ResourceAlreadyExists => Self::ResourceAlreadyExists,
            DataError::ControllerPrincipalMismatch => Self::ControllerPrincipalMismatch,
            DataError::ResourcePolicyMismatch => Self::ResourcePolicyMismatch,
            DataError::CorruptState => Self::CorruptState,
        }
    }
}
