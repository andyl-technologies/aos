//! Immutable audit evidence for locally provisioned publisher capabilities.
//!
//! These values explain how a channel-bound capability was issued. They are
//! retained for audit and recovery, but are not themselves authentication or
//! authorization proofs. Live session possession and every current authority
//! check remain separate.

use std::io;

use aos_sandbox_core::{
    AuditId, CapabilityRecord, ObjectDigest, Operation, OperationSet, ResourceId, ResourceKind,
    ResourceVector, Selector,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{MAXIMUM_RECORD_BYTES, PublisherAuthorityError};

aos_sandbox_ledger_replay::define_provider_issuance_data_recipe_v1! {
    invalid_metadata: PublisherAuthorityError::InvalidIssuanceMetadata,
    crosslink: PublisherAuthorityError::IssuanceCrosslinkMismatch,
    malformed: PublisherAuthorityError::MalformedRecord
}

/// Supplies the controller-observed facts for one local capability issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceDecisionMetadataDraftV1 {
    /// Audit decision identity, equal byte-for-byte to the capability identity.
    pub decision_id: AuditId,
    /// Controller-minted volatile session identity.
    pub session_id: [u8; 16],
    /// Boot identity paired with the clock observation.
    pub boot_id: [u8; 16],
    /// Protected clock-reader configuration identity.
    pub clock_provenance: [u8; 16],
    /// Observed Unix wall-clock second.
    pub observed_wall_seconds: i64,
    /// Paired `CLOCK_BOOTTIME` nanoseconds.
    pub observed_boottime_nanoseconds: u64,
    /// Effective policy generation used for issuance.
    pub policy_generation: u64,
    /// Controller-authority generation used for issuance.
    pub controller_generation: u64,
    /// Exact logical cache resource authorized by the grant.
    pub cache_resource: ResourceId,
    /// Isolation-policy commitment resolved at issuance.
    pub isolation_policy: ObjectDigest,
}

impl IssuanceDecisionMetadataV1 {
    /// Constructs one immutable controller-observed issuance decision.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError::InvalidIssuanceMetadata`] when an
    /// identity, generation, or digest is zero.
    pub fn new(draft: IssuanceDecisionMetadataDraftV1) -> Result<Self, PublisherAuthorityError> {
        let value = Self {
            decision_id: draft.decision_id,
            session_id: draft.session_id,
            boot_id: draft.boot_id,
            clock_provenance: draft.clock_provenance,
            observed_wall_seconds: draft.observed_wall_seconds,
            observed_boottime_nanoseconds: draft.observed_boottime_nanoseconds,
            policy_generation: draft.policy_generation,
            controller_generation: draft.controller_generation,
            cache_resource: draft.cache_resource,
            isolation_policy: draft.isolation_policy,
        };
        value.validate_fields()?;
        Ok(value)
    }

    /// Returns the audit decision identity.
    #[must_use]
    pub const fn decision_id(&self) -> AuditId {
        self.decision_id
    }

    /// Returns the controller-minted volatile session identity.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 16] {
        self.session_id
    }





    /// Returns the effective policy generation used for issuance.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Returns the controller-authority generation used for issuance.
    #[must_use]
    pub const fn controller_generation(&self) -> u64 {
        self.controller_generation
    }

    /// Returns the exact logical cache resource authorized by the grant.
    #[must_use]
    pub const fn cache_resource(&self) -> ResourceId {
        self.cache_resource
    }

    /// Returns the isolation-policy commitment resolved at issuance.
    #[must_use]
    pub const fn isolation_policy(&self) -> ObjectDigest {
        self.isolation_policy
    }


}

/// Returns immutable audit evidence retained with one capability record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCapabilityIssuanceV1 {
    metadata: IssuanceDecisionMetadataV1,
    claims_digest: ObjectDigest,
    revoked: bool,
    runtime: Option<super::RuntimeIssuanceEvidenceV1>,
}

impl ValidatedCapabilityIssuanceV1 {
    pub(super) const fn new(
        metadata: IssuanceDecisionMetadataV1,
        claims_digest: ObjectDigest,
        revoked: bool,
        runtime: Option<super::RuntimeIssuanceEvidenceV1>,
    ) -> Self {
        Self {
            metadata,
            claims_digest,
            revoked,
            runtime,
        }
    }

    /// Returns the immutable controller-observed decision metadata.
    #[must_use]
    pub const fn metadata(&self) -> &IssuanceDecisionMetadataV1 {
        &self.metadata
    }

    /// Borrows runtime-origin evidence when the issuance originated from a runtime scope.
    ///
    /// Other issuance records return `None`. Historical evidence
    /// does not establish a current holder mapping or restore a live channel.
    #[must_use]
    pub const fn runtime(&self) -> Option<&super::RuntimeIssuanceEvidenceV1> {
        self.runtime.as_ref()
    }

    /// Returns the domain-separated digest of the complete capability claims.
    #[must_use]
    pub const fn claims_digest(&self) -> ObjectDigest {
        self.claims_digest
    }

    /// Reports whether the associated capability has a durable tombstone.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
}
