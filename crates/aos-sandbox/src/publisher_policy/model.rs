//! Public policy-authority values and bounded preparation contracts.
//!
//! Preparation establishes canonical encoding and base-registry semantic
//! support for required features, including resource-limit enforcement
//! features. It does not prove that a particular publisher host currently has
//! those mechanisms available; online admission must establish that separate
//! platform-readiness fact.

use super::*;

/// Bounds replay and retained policy work below fixed implementation ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherPolicyLimits {
    pub(super) maximum_records: usize,
    pub(super) maximum_record_bytes: usize,
    pub(super) maximum_materialized_bytes: usize,
}

impl PublisherPolicyLimits {
    /// Constructs policy-store limits within fixed implementation ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherPolicyError::InvalidLimits`] for zero or excessive limits.
    pub fn new(
        maximum_records: usize,
        maximum_record_bytes: usize,
        maximum_materialized_bytes: usize,
    ) -> Result<Self, PublisherPolicyError> {
        if maximum_records == 0
            || maximum_records > MAXIMUM_RECORDS
            || maximum_record_bytes == 0
            || maximum_record_bytes > MAXIMUM_RECORD_BYTES
            || maximum_materialized_bytes == 0
            || maximum_materialized_bytes > MAXIMUM_MATERIALIZED_BYTES
        {
            return Err(PublisherPolicyError::InvalidLimits);
        }
        Ok(Self {
            maximum_records,
            maximum_record_bytes,
            maximum_materialized_bytes,
        })
    }
}

impl Default for PublisherPolicyLimits {
    fn default() -> Self {
        Self {
            maximum_records: MAXIMUM_RECORDS,
            maximum_record_bytes: MAXIMUM_RECORD_BYTES,
            maximum_materialized_bytes: MAXIMUM_MATERIALIZED_BYTES,
        }
    }
}

/// Binds one logical cache resource to an immutable project isolation domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherResourceBindingV1 {
    pub(super) resource: ResourceId,
    pub(super) project: ProjectId,
    pub(super) cache_domain: CacheDomain,
    pub(super) isolation_policy: ObjectDigest,
}

impl PublisherResourceBindingV1 {
    /// Constructs an immutable protected resource binding.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherPolicyError::InvalidResourceBinding`] for zero IDs or
    /// commitment, or a non-project disclosure domain.
    pub fn new(
        resource: ResourceId,
        project: ProjectId,
        cache_domain: CacheDomain,
        isolation_policy: ObjectDigest,
    ) -> Result<Self, PublisherPolicyError> {
        if resource.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || cache_domain.kind() != CacheDomainKind::Project
            || cache_domain.domain_id().as_bytes() == &[0; 16]
            || isolation_policy.as_bytes() == &[0; 32]
        {
            return Err(PublisherPolicyError::InvalidResourceBinding);
        }
        Ok(Self {
            resource,
            project,
            cache_domain,
            isolation_policy,
        })
    }

    /// Returns the logical cache resource.
    #[must_use]
    pub const fn resource(&self) -> ResourceId {
        self.resource
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the exact project cache domain.
    #[must_use]
    pub const fn cache_domain(&self) -> CacheDomain {
        self.cache_domain
    }

    /// Returns the configured isolation-policy commitment.
    #[must_use]
    pub const fn isolation_policy(&self) -> ObjectDigest {
        self.isolation_policy
    }
}

/// Identifies the current controller authority principal and generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherControllerHeadV1 {
    /// Controller authority principal used as the capability audience.
    pub principal: PrincipalId,
    /// Contiguous current controller-authority generation.
    pub generation: u64,
}

/// Identifies one current revocation-scope generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherRevocationHeadV1 {
    /// Independently managed revocation scope.
    pub scope: RevocationScopeId,
    /// Contiguous current generation for that scope.
    pub generation: u64,
}

/// Identifies the project disclosure choice in a current publisher revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherProjectCacheDomainHeadV1 {
    pub(super) project: ProjectId,
    pub(super) generation: u64,
    pub(super) policy_digest: ObjectDigest,
    pub(super) domain: CacheDomain,
    pub(super) digest: ObjectDigest,
}

impl PublisherProjectCacheDomainHeadV1 {
    /// Returns the publisher project owning the current policy.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the contiguous current publisher-policy generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the exact current policy descriptor digest.
    #[must_use]
    pub const fn policy_digest(self) -> ObjectDigest {
        self.policy_digest
    }

    /// Returns the current project disclosure domain.
    #[must_use]
    pub const fn domain(self) -> CacheDomain {
        self.domain
    }

    /// Returns the project, generation, policy, and domain commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Identifies the current protected revocation scope for one project.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherProjectRevocationHeadV1 {
    pub(super) project: ProjectId,
    pub(super) scope: RevocationScopeId,
    pub(super) generation: u64,
    pub(super) digest: ObjectDigest,
}

impl PublisherProjectRevocationHeadV1 {
    /// Returns the publisher project bound by the protected mapping.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the independently managed revocation scope.
    #[must_use]
    pub const fn scope(self) -> RevocationScopeId {
        self.scope
    }

    /// Returns its exact current generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the project-bound currentness commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

impl From<aos_sandbox_policy::PublisherPolicyDataError> for PublisherPolicyError {
    fn from(error: aos_sandbox_policy::PublisherPolicyDataError) -> Self {
        match error {
            aos_sandbox_policy::PublisherPolicyDataError::LimitExceeded(dimension) => Self::LimitExceeded(dimension),
            aos_sandbox_policy::PublisherPolicyDataError::InvalidPolicyRevision => Self::InvalidPolicyRevision,
            aos_sandbox_policy::PublisherPolicyDataError::CorruptState => Self::CorruptState,
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
