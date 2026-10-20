//! Canonical immutable Cache admission model DATA and commitments.
//!
//! Historical source fields and plans are ordinary DATA. They do not issue the
//! Native SourceAuthorization/ImmutableAdmissionPlan wrappers, validate a live
//! capability, observe a clock, admit capacity or authorize publication.

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, OperationId, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{CacheReservationId, ImmutableSealV1, PhysicalPartitionId,
    hash_descriptor_fields_u16_v1, object_descriptor_commitment, validate_object_descriptor};
use super::authority_record::{CacheAuthorityScopeV1, CacheAuthorityRecordDataErrorV1};

/// Records historical commitments to one immutable source revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAuthorizationDataV1 {
    /// Historical protected source-record commitment.
    pub release_digest: ObjectDigest,
    /// Historical immutable source revision.
    pub source_revision: ObjectDigest,
    /// Complete historical immutable object descriptor.
    pub descriptor: ObjectDescriptor,
    /// Historical immutable source seal.
    pub source_seal: ObjectDigest,
    /// Historical authority generation.
    pub authority_generation: u64,
    /// Historical authority expiry; no current clock observation.
    pub valid_until: u64,
}

impl SourceAuthorizationDataV1 {
    /// Derives the historical source scope and record commitment.
    ///
    /// # Errors
    ///
    /// Returns the scope DATA error for invalid historical coordinates.
    pub fn authority_binding(
        &self,
        partition: PhysicalPartitionId,
    ) -> Result<(CacheAuthorityScopeV1, ObjectDigest), CacheAuthorityRecordDataErrorV1> {
        let scope = CacheAuthorityScopeV1::new(
            partition,
            source_authority_subject(&self.descriptor, self.source_revision, self.source_seal),
            None,
            self.source_revision,
            partition.backing().root(),
            self.authority_generation,
            self.valid_until,
        )?;
        Ok((scope, self.release_digest))
    }

    /// Reconstructs historical source fields without issuing Native authority.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionDataErrorV1`] for an incomplete source commitment.
    pub fn recover_historical(
        release_digest: ObjectDigest,
        source_revision: ObjectDigest,
        descriptor: ObjectDescriptor,
        source_seal: ObjectDigest,
        authority_generation: u64,
        valid_until: u64,
    ) -> Result<Self, AdmissionDataErrorV1> {
        let source = Self {
            release_digest,
            source_revision,
            descriptor,
            source_seal,
            authority_generation,
            valid_until,
        };
        source.validate()?;
        Ok(source)
    }

    /// Validates the complete historical source commitment.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionDataErrorV1`] for malformed or sentinel source DATA.
    pub fn validate(&self) -> Result<(), AdmissionDataErrorV1> {
        if self.release_digest.as_bytes() == &[0; 32]
            || self.source_revision.as_bytes() == &[0; 32]
            || validate_object_descriptor(&self.descriptor).is_err()
            || self.source_seal.as_bytes() == &[0; 32]
            || self.authority_generation == 0
            || self.valid_until == 0
        {
            return Err(AdmissionDataErrorV1::InvalidPlan);
        }
        Ok(())
    }
}

/// Describes the historical immutable admission commitment before effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableAdmissionPlanDataV1 {
    /// Idempotent admission operation.
    pub operation: OperationId,
    /// Exact capacity reservation.
    pub reservation: CacheReservationId,
    /// Attributed project.
    pub project: ProjectId,
    /// Exact physical isolation partition.
    pub partition: PhysicalPartitionId,
    /// Complete portable object identity and exact size.
    pub descriptor: ObjectDescriptor,
    /// Historical immutable source commitments; no current authority.
    pub source: SourceAuthorizationDataV1,
    /// Seal that the prepared destination must produce.
    pub expected_seal: ImmutableSealV1,
    /// Worst-case allocation charged before any effect.
    pub reserved_bytes: u64,
    /// Current admission policy revision.
    pub policy_revision: ObjectDigest,
    /// Current protected root generation.
    pub root_generation: u64,
    /// Exact protected root custody record digest.
    pub root_custody: ObjectDigest,
    /// Commitment to the exact ordered initial pin set.
    pub initial_pins_digest: ObjectDigest,
    /// Digest of the complete normalized request.
    pub request_digest: ObjectDigest,
    /// Domain-separated digest of this plan.
    pub digest: ObjectDigest,
}

impl ImmutableAdmissionPlanDataV1 {
    /// Derives the historical admission scope without checking currentness.
    ///
    /// # Errors
    ///
    /// Returns the scope DATA error for invalid historical coordinates.
    pub fn authority_scope(&self) -> Result<CacheAuthorityScopeV1, CacheAuthorityRecordDataErrorV1> {
        Ok(CacheAuthorityScopeV1::new(
            self.partition,
            self.digest,
            Some(self.operation),
            self.digest,
            self.root_custody,
            self.root_generation,
            self.source.valid_until,
        )?)
    }

    /// Builds the canonical historical immutable-admission plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionDataErrorV1`] for incomplete bindings or invalid seal.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: OperationId,
        reservation: CacheReservationId,
        project: ProjectId,
        partition: PhysicalPartitionId,
        descriptor: ObjectDescriptor,
        source: SourceAuthorizationDataV1,
        expected_seal: ImmutableSealV1,
        reserved_bytes: u64,
        policy_revision: ObjectDigest,
        root_generation: u64,
        root_custody: ObjectDigest,
        initial_pins_digest: ObjectDigest,
        request_digest: ObjectDigest,
    ) -> Result<Self, AdmissionDataErrorV1> {
        source.validate()?;
        expected_seal.validate()?;
        let mut plan = Self {
            operation,
            reservation,
            project,
            partition,
            descriptor,
            source,
            expected_seal,
            reserved_bytes,
            policy_revision,
            root_generation,
            root_custody,
            initial_pins_digest,
            request_digest,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        plan.digest = admission_digest(&plan);
        plan.validate()?;
        Ok(plan)
    }

    /// Validates the exact historical immutable-admission commitment.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionDataErrorV1`] for mismatched bindings or invalid seal.
    pub fn validate(&self) -> Result<(), AdmissionDataErrorV1> {
        self.source.validate()?;
        self.expected_seal.validate()?;
        if self.operation.as_bytes() == &[0; 16]
            || self.project.as_bytes() == &[0; 16]
            || validate_object_descriptor(&self.descriptor).is_err()
            || self.source.descriptor != self.descriptor
            || self.reserved_bytes < self.descriptor.encoded_size()
            || self.policy_revision.as_bytes() == &[0; 32]
            || self.root_generation == 0
            || self.root_custody.as_bytes() == &[0; 32]
            || self.initial_pins_digest.as_bytes() == &[0; 32]
            || self.request_digest.as_bytes() == &[0; 32]
            || self.digest != admission_digest(self)
        {
            return Err(AdmissionDataErrorV1::InvalidPlan);
        }
        Ok(())
    }
}

/// Reports malformed historical source or immutable-admission DATA.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionDataErrorV1 {
    /// Source or admission facts are incomplete or incorrectly committed.
    #[error("cache admission plan is invalid")]
    InvalidPlan,
    /// The historical immutable seal fails catalog validation.
    #[error(transparent)]
    Catalog(#[from] super::CatalogError),
}

fn admission_digest(plan: &ImmutableAdmissionPlanDataV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.admission-plan.v1\0");
    hasher.update(plan.operation.as_bytes());
    hasher.update(plan.reservation.as_bytes());
    hasher.update(plan.project.as_bytes());
    hasher.update(plan.partition.digest().as_bytes());
    hash_descriptor_fields_u16_v1(&mut hasher, &plan.descriptor);
    hasher.update(plan.source.release_digest.as_bytes());
    hasher.update(plan.source.source_revision.as_bytes());
    hash_descriptor_fields_u16_v1(&mut hasher, &plan.source.descriptor);
    hasher.update(plan.source.source_seal.as_bytes());
    hasher.update(plan.source.authority_generation.to_be_bytes());
    hasher.update(plan.source.valid_until.to_be_bytes());
    hasher.update([plan.expected_seal.profile as u8]);
    hasher.update(plan.expected_seal.measurement.as_bytes());
    hasher.update(plan.reserved_bytes.to_be_bytes());
    hasher.update(plan.policy_revision.as_bytes());
    hasher.update(plan.root_generation.to_be_bytes());
    hasher.update(plan.root_custody.as_bytes());
    hasher.update(plan.initial_pins_digest.as_bytes());
    hasher.update(plan.request_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits exact historical source facts without resolving current authority.
pub fn source_authority_subject(
    descriptor: &ObjectDescriptor,
    source_revision: ObjectDigest,
    source_seal: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.source-authority-subject.v1\0");
    hasher.update(object_descriptor_commitment(descriptor).as_bytes());
    hasher.update(source_revision.as_bytes());
    hasher.update(source_seal.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

