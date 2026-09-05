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

const CLAIMS_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.publisher-capability-claims.v1\0";

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

/// Records the controller-observed facts behind one local capability issuance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceDecisionMetadataV1 {
    decision_id: AuditId,
    session_id: [u8; 16],
    boot_id: [u8; 16],
    clock_provenance: [u8; 16],
    observed_wall_seconds: i64,
    observed_boottime_nanoseconds: u64,
    policy_generation: u64,
    controller_generation: u64,
    cache_resource: ResourceId,
    isolation_policy: ObjectDigest,
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

    /// Returns the boot identity paired with the clock observation.
    #[must_use]
    pub const fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }

    /// Returns the protected clock-reader configuration identity.
    #[must_use]
    pub const fn clock_provenance(&self) -> [u8; 16] {
        self.clock_provenance
    }

    /// Returns the observed Unix wall-clock second.
    #[must_use]
    pub const fn observed_wall_seconds(&self) -> i64 {
        self.observed_wall_seconds
    }

    /// Returns the paired `CLOCK_BOOTTIME` nanoseconds.
    #[must_use]
    pub const fn observed_boottime_nanoseconds(&self) -> u64 {
        self.observed_boottime_nanoseconds
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

    pub(super) fn validate_for(
        &self,
        capability: &CapabilityRecord,
    ) -> Result<ObjectDigest, PublisherAuthorityError> {
        self.validate_fields()?;
        let claims = capability.claims();
        let expected_operations = OperationSet::one(Operation::Publish);
        let runtime_bound = claims
            .sandbox
            .is_some_and(|sandbox| sandbox.as_bytes() != &[0; 16])
            && claims
                .incarnation
                .is_some_and(|incarnation| incarnation.as_bytes() != &[0; 16])
            && claims
                .assignment_epoch
                .is_some_and(|epoch| epoch.get() != 0);
        let delegation_disabled = claims.delegation.remaining_depth() == 0
            && claims.delegation.maximum_fanout() == 0
            && claims.delegation.resources() == ResourceVector::ZERO;
        let claim_sentinels_absent = claims.issuer.as_bytes() != &[0; 16]
            && claims.holder.as_bytes() != &[0; 16]
            && claims.channel_binding.as_bytes() != &[0; 32]
            && claims.project.as_bytes() != &[0; 16]
            && claims.policy_digest.as_bytes() != &[0; 32]
            && claims.revocation_scope.as_bytes() != &[0; 16]
            && claims.revocation_generation.get() != 0;
        let grant_matches = claims.grants.len() == 1
            && claims.grants[0].id().as_bytes() != &[0; 16]
            && claims.grants[0].resource_kind() == ResourceKind::CachePublish
            && claims.grants[0].operations() == expected_operations
            && claims.grants[0].selector()
                == &Selector::Resource {
                    resource: self.cache_resource,
                }
            && !claims.grants[0].delegable();
        if self.decision_id.as_bytes() != capability.id().as_bytes()
            || claims.parent_decision != self.decision_id
            || claims.issuer != claims.audience
            || claims.root_subject != claims.holder
            || self.observed_wall_seconds < claims.not_before
            || self.observed_wall_seconds >= claims.expires_at
            || !runtime_bound
            || !delegation_disabled
            || !claim_sentinels_absent
            || !grant_matches
        {
            return Err(PublisherAuthorityError::IssuanceCrosslinkMismatch);
        }
        capability_claims_digest(capability)
    }

    fn validate_fields(&self) -> Result<(), PublisherAuthorityError> {
        if self.decision_id.as_bytes() == &[0; 16]
            || self.session_id == [0; 16]
            || self.boot_id == [0; 16]
            || self.clock_provenance == [0; 16]
            || self.policy_generation == 0
            || self.controller_generation == 0
            || self.cache_resource.as_bytes() == &[0; 16]
            || self.isolation_policy.as_bytes() == &[0; 32]
        {
            return Err(PublisherAuthorityError::InvalidIssuanceMetadata);
        }
        Ok(())
    }
}

/// Returns immutable audit evidence retained with one capability record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCapabilityIssuanceV1 {
    metadata: IssuanceDecisionMetadataV1,
    claims_digest: ObjectDigest,
    revoked: bool,
}

impl ValidatedCapabilityIssuanceV1 {
    pub(super) const fn new(
        metadata: IssuanceDecisionMetadataV1,
        claims_digest: ObjectDigest,
        revoked: bool,
    ) -> Self {
        Self {
            metadata,
            claims_digest,
            revoked,
        }
    }

    /// Returns the immutable controller-observed decision metadata.
    #[must_use]
    pub const fn metadata(&self) -> &IssuanceDecisionMetadataV1 {
        &self.metadata
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

pub(super) fn capability_claims_digest(
    capability: &CapabilityRecord,
) -> Result<ObjectDigest, PublisherAuthorityError> {
    let mut writer = ClaimsDigestWriter::new(MAXIMUM_RECORD_BYTES);
    serde_json::to_writer(&mut writer, capability)
        .map_err(|_| PublisherAuthorityError::MalformedRecord)?;
    Ok(ObjectDigest::from_bytes(writer.finish()))
}

struct ClaimsDigestWriter {
    digest: Sha256,
    bytes: usize,
    maximum_bytes: usize,
}

impl ClaimsDigestWriter {
    fn new(maximum_bytes: usize) -> Self {
        let mut digest = Sha256::new();
        digest.update(CLAIMS_DIGEST_DOMAIN);
        Self {
            digest,
            bytes: 0,
            maximum_bytes,
        }
    }

    fn finish(self) -> [u8; 32] {
        self.digest.finalize().into()
    }
}

impl io::Write for ClaimsDigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("capability claims exceed digest bound"))?;
        if next > self.maximum_bytes {
            return Err(io::Error::other("capability claims exceed digest bound"));
        }
        self.digest.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
