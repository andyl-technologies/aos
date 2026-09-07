//! Public policy-authority values and bounded preparation contracts.
//!
//! Preparation establishes canonical encoding and base-registry semantic
//! support for required features, including resource-limit enforcement
//! features. It does not prove that a particular publisher host currently has
//! those mechanisms available; online admission must establish that separate
//! platform-readiness fact.

use super::record::{bounded_decode_limits, policy_media_type};
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

/// Freezes one bounded canonical resolved policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPublisherPolicyRevisionV1 {
    pub(super) project: ProjectId,
    pub(super) generation: u64,
    pub(super) not_before: i64,
    pub(super) expires_at: i64,
    pub(super) policy: Policy,
    pub(super) descriptor: ObjectDescriptor,
    pub(super) canonical_policy: Vec<u8>,
}

impl PreparedPublisherPolicyRevisionV1 {
    /// Decodes and freezes controller-resolved canonical policy bytes.
    ///
    /// Caller limits are clamped to publisher-policy hard ceilings before the
    /// core decoder allocates or performs normalized grant validation.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherPolicyError`] for a zero project or generation, an
    /// invalid interval, oversized or malformed policy, non-project cache
    /// domain, or noncanonical bytes.
    pub fn from_canonical_bytes(
        project: ProjectId,
        generation: u64,
        not_before: i64,
        expires_at: i64,
        canonical_policy: &[u8],
        requested_limits: DecodeLimits,
    ) -> Result<Self, PublisherPolicyError> {
        if project.as_bytes() == &[0; 16] || generation == 0 || not_before >= expires_at {
            return Err(PublisherPolicyError::InvalidPolicyRevision);
        }
        if canonical_policy.len() > MAXIMUM_POLICY_BYTES {
            return Err(PublisherPolicyError::LimitExceeded("policy bytes"));
        }
        let policy = decode_policy(canonical_policy, bounded_decode_limits(requested_limits))
            .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
        validate_required_features(policy.required_features())
            .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
        for limit in policy.limits().limits() {
            validate_required_features(std::slice::from_ref(limit.enforcement()))
                .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
        }
        if policy.cache_domain().kind() != CacheDomainKind::Project
            || policy.cache_domain().domain_id().as_bytes() == &[0; 16]
            || encode_policy(&policy) != canonical_policy
        {
            return Err(PublisherPolicyError::InvalidPolicyRevision);
        }
        let canonical_policy = canonical_policy.to_vec();
        let descriptor = descriptor_for_bytes(policy_media_type()?, &canonical_policy);
        Ok(Self {
            project,
            generation,
            not_before,
            expires_at,
            policy,
            descriptor,
            canonical_policy,
        })
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the contiguous policy generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the inclusive policy start time.
    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }

    /// Returns the exclusive policy expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the normalized policy.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Returns the exact canonical policy descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    /// Returns exact canonical policy bytes.
    #[must_use]
    pub fn canonical_policy(&self) -> &[u8] {
        &self.canonical_policy
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
