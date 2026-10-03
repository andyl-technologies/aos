//! Immutable object admission and atomic projection transitions.
//!
//! Admission binds the object, source authorization, partition, reservation,
//! and expected immutable seal before effects.  Completion converts capacity,
//! inserts the committed catalog entry, and acquires initial pins as one pure
//! state transition.  A caller must persist the corresponding canonical record
//! set atomically before replacing its live projection.

use std::collections::BTreeMap;

use super::accounting::{
    AccountingError, CacheAccountingV1, CacheReservationId, CacheReservationV1, ReservationStateV1,
};
use super::catalog::{
    BackingObjectIdentityV1, CatalogEntryV1, CatalogError, CatalogPresenceV1, ImmutableSealV1,
    canonical_name_digest,
};
use super::domain::{
    CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1,
    PhysicalPartitionId, VerifiedCacheCapabilityV1, object_descriptor_commitment,
    validate_object_descriptor,
};
use super::pin::{CachePinLedgerV1, CachePinV1, PinError};
use aos_sandbox_core::{
    AttachmentId, ObjectDescriptor, ObjectDigest, OperationId, ProjectId, ViewId,
};

mod digest;

pub use digest::initial_pin_set_digest;
use digest::{
    admission_digest, admission_progress_digest, prepared_artifact_subject,
    source_authority_subject, stage_rank,
};

const MAXIMUM_INITIAL_PINS: usize = 65_536;

/// Commits admission to an independently verified immutable source revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAuthorizationV1 {
    pub(crate) release_digest: ObjectDigest,
    pub(crate) source_revision: ObjectDigest,
    pub(crate) descriptor: ObjectDescriptor,
    pub(crate) source_seal: ObjectDigest,
    pub(crate) authority_generation: u64,
    pub(crate) valid_until: u64,
}

impl SourceAuthorizationV1 {
    pub(crate) fn authority_binding(
        &self,
        partition: PhysicalPartitionId,
    ) -> Result<(CacheAuthorityScopeV1, ObjectDigest), AdmissionError> {
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

    pub(crate) fn recover_historical(
        release_digest: ObjectDigest,
        source_revision: ObjectDigest,
        descriptor: ObjectDescriptor,
        source_seal: ObjectDigest,
        authority_generation: u64,
        valid_until: u64,
    ) -> Result<Self, AdmissionError> {
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

    /// Issues source authorization only from a current protected capability.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when scope, source facts, or protected
    /// currentness do not exactly match.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        source_revision: ObjectDigest,
        descriptor: ObjectDescriptor,
        source_seal: ObjectDigest,
        authority_generation: u64,
        valid_until: u64,
        now: u64,
    ) -> Result<Self, AdmissionError> {
        validate_object_descriptor(&descriptor).map_err(|_| AdmissionError::InvalidPlan)?;
        let scope = CacheAuthorityScopeV1::new(
            partition,
            source_authority_subject(&descriptor, source_revision, source_seal),
            None,
            source_revision,
            partition.backing().root(),
            authority_generation,
            valid_until,
        )?;
        owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Source, scope, now)?;
        let authorization = Self {
            release_digest: capability.record_digest(),
            source_revision,
            descriptor,
            source_seal,
            authority_generation,
            valid_until,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    /// Validates complete, non-sentinel source authority.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidPlan`] for missing commitments or a
    /// zero authority generation/lifetime.
    pub fn validate(&self) -> Result<(), AdmissionError> {
        if self.release_digest.as_bytes() == &[0; 32]
            || self.source_revision.as_bytes() == &[0; 32]
            || validate_object_descriptor(&self.descriptor).is_err()
            || self.source_seal.as_bytes() == &[0; 32]
            || self.authority_generation == 0
            || self.valid_until == 0
        {
            return Err(AdmissionError::InvalidPlan);
        }
        Ok(())
    }

    fn validate_current(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        now: u64,
    ) -> Result<(), AdmissionError> {
        let scope = CacheAuthorityScopeV1::new(
            partition,
            source_authority_subject(&self.descriptor, self.source_revision, self.source_seal),
            None,
            self.source_revision,
            partition.backing().root(),
            self.authority_generation,
            self.valid_until,
        )?;
        owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Source, scope, now)?;
        if capability.record_digest() != self.release_digest {
            return Err(AdmissionError::InvalidPlan);
        }
        Ok(())
    }
}

/// Describes a completely authorized immutable admission before effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableAdmissionPlanV1 {
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
    /// Independently resolved immutable source authority.
    pub source: SourceAuthorizationV1,
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

impl ImmutableAdmissionPlanV1 {
    pub(crate) fn authority_scope(&self) -> Result<CacheAuthorityScopeV1, AdmissionError> {
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

    /// Constructs a validated immutable admission plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidPlan`] for sentinel facts, insufficient
    /// reservation, or a derived digest inconsistency.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: OperationId,
        reservation: CacheReservationId,
        project: ProjectId,
        partition: PhysicalPartitionId,
        descriptor: ObjectDescriptor,
        source: SourceAuthorizationV1,
        expected_seal: ImmutableSealV1,
        reserved_bytes: u64,
        policy_revision: ObjectDigest,
        root_generation: u64,
        root_custody: ObjectDigest,
        initial_pins_digest: ObjectDigest,
        request_digest: ObjectDigest,
    ) -> Result<Self, AdmissionError> {
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

    /// Validates an externally decoded admission plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidPlan`] when any immutable binding is
    /// absent or the digest is not the canonical derived value.
    pub fn validate(&self) -> Result<(), AdmissionError> {
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
            return Err(AdmissionError::InvalidPlan);
        }
        Ok(())
    }
}

/// Records a prepared private destination that is not yet catalog-visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedArtifactV1 {
    /// Exact admission plan digest.
    plan_digest: ObjectDigest,
    /// Opaque protected-root-relative destination identity.
    backing: BackingObjectIdentityV1,
    /// Re-observed immutable seal on the completed destination.
    seal: ImmutableSealV1,
    /// Exact physical allocated bytes.
    allocated_bytes: u64,
    /// Digest of close-writers, seal, fsync, and no-replace preparation evidence.
    preparation_evidence: ObjectDigest,
    /// Digest of the exact parent-synced preparation progress record.
    progress_digest: ObjectDigest,
    root_generation: u64,
    root_custody: ObjectDigest,
    canonical_name: ObjectDigest,
}

impl PreparedArtifactV1 {
    /// Constructs a final prepared artifact from parent-synced progress.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when progress does not bind the plan at the
    /// exact parent-synced stage or physical facts mismatch.
    pub fn from_parent_synced(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &ImmutableAdmissionPlanV1,
        progress: &AdmissionProgressV1,
        backing: BackingObjectIdentityV1,
        seal: ImmutableSealV1,
        allocated_bytes: u64,
        now: u64,
    ) -> Result<Self, AdmissionError> {
        if progress.plan_digest != plan.digest || progress.stage != AdmissionStageV1::ParentSynced {
            return Err(AdmissionError::InvalidProgress);
        }
        let root_custody = plan.root_custody;
        let canonical_name = canonical_name_digest(plan.partition, &plan.descriptor);
        let subject = prepared_artifact_subject(
            plan,
            progress.digest,
            backing,
            seal,
            allocated_bytes,
            root_custody,
            canonical_name,
        );
        let authority_scope = CacheAuthorityScopeV1::new(
            plan.partition,
            subject,
            Some(plan.operation),
            plan.digest,
            plan.root_custody,
            plan.root_generation,
            plan.source.valid_until,
        )?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Admission,
            authority_scope,
            now,
        )?;
        Self {
            plan_digest: plan.digest,
            backing,
            seal,
            allocated_bytes,
            preparation_evidence: capability.record_digest(),
            progress_digest: progress.digest,
            root_generation: plan.root_generation,
            root_custody,
            canonical_name,
        }
        .validate_for(plan)
    }

    /// Validates that preparation matches one exact immutable plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::ArtifactMismatch`] for any mismatched or
    /// incomplete physical fact.
    pub fn validate_for(self, plan: &ImmutableAdmissionPlanV1) -> Result<Self, AdmissionError> {
        if self.plan_digest != plan.digest
            || self.seal != plan.expected_seal
            || self.allocated_bytes == 0
            || self.allocated_bytes > plan.reserved_bytes
            || self.preparation_evidence.as_bytes() == &[0; 32]
            || self.progress_digest.as_bytes() == &[0; 32]
            || self.root_generation != plan.root_generation
            || self.root_custody != plan.root_custody
            || self.canonical_name != canonical_name_digest(plan.partition, &plan.descriptor)
        {
            return Err(AdmissionError::ArtifactMismatch);
        }
        Ok(self)
    }

    fn validate_current(
        self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &ImmutableAdmissionPlanV1,
        now: u64,
    ) -> Result<(), AdmissionError> {
        let subject = prepared_artifact_subject(
            plan,
            self.progress_digest,
            self.backing,
            self.seal,
            self.allocated_bytes,
            self.root_custody,
            self.canonical_name,
        );
        let scope = CacheAuthorityScopeV1::new(
            plan.partition,
            subject,
            Some(plan.operation),
            plan.digest,
            plan.root_custody,
            plan.root_generation,
            plan.source.valid_until,
        )?;
        owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Admission, scope, now)?;
        if capability.record_digest() != self.preparation_evidence {
            return Err(AdmissionError::ArtifactMismatch);
        }
        Ok(())
    }
}

/// Selects the closed immutable-publication effect sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdmissionStageV1 {
    /// Capacity and immutable plan are durable; no allocation occurred.
    Reserved = 1,
    /// A fresh private destination was created beneath protected root custody.
    PrivateDestinationCreated = 2,
    /// Exact bounded source bytes were transferred into the private destination.
    ContentTransferred = 3,
    /// Digest, size, media type, source, and tree relationship were verified.
    ContentVerified = 4,
    /// Every writable description was authoritatively closed.
    WritersClosed = 5,
    /// Immutability was enabled and its exact measurement re-observed.
    SealEnabledAndVerified = 6,
    /// The immutable destination inode or snapshot was durably synchronized.
    InodeSynced = 7,
    /// Canonical naming completed with no-replace semantics.
    CanonicalNamePublished = 8,
    /// The canonical parent directory was durably synchronized.
    ParentSynced = 9,
    /// Catalog visibility, pins, and residency accounting committed atomically.
    CatalogCommitted = 10,
    /// Interruption left the exact physical effect outcome unknown.
    Uncertain = 11,
    /// A mismatched artifact was isolated from consumers.
    Quarantined = 12,
    /// A proved pre-effect or safely removed artifact released its reservation.
    Aborted = 13,
}

/// Tracks exact immutable-publication progress without granting effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionProgressV1 {
    /// Exact immutable admission plan.
    pub plan_digest: ObjectDigest,
    /// Current closed publication stage.
    pub stage: AdmissionStageV1,
    /// Last non-uncertain stage, used to prevent recovery rollback.
    pub last_certain_stage: AdmissionStageV1,
    /// Monotone progress generation.
    pub generation: u64,
    /// Exact predecessor progress digest, absent only at generation one.
    pub predecessor: Option<ObjectDigest>,
    /// Trusted effect or observation evidence for this stage.
    pub evidence: ObjectDigest,
    /// Digest of this complete progress record.
    pub digest: ObjectDigest,
}

impl AdmissionProgressV1 {
    /// Constructs the no-effect durable state for an admitted plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidProgress`] for sentinel plan/evidence.
    pub fn reserved(
        plan_digest: ObjectDigest,
        admission_evidence: ObjectDigest,
    ) -> Result<Self, AdmissionError> {
        let mut progress = Self {
            plan_digest,
            stage: AdmissionStageV1::Reserved,
            last_certain_stage: AdmissionStageV1::Reserved,
            generation: 1,
            predecessor: None,
            evidence: admission_evidence,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        progress.digest = admission_progress_digest(&progress);
        progress.validate()?;
        Ok(progress)
    }

    /// Advances one exact adjacent publication stage.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidProgress`] for non-adjacent, terminal,
    /// or evidence-free transitions.
    pub fn advance(
        &self,
        next_stage: AdmissionStageV1,
        evidence: ObjectDigest,
    ) -> Result<Self, AdmissionError> {
        if self.stage == AdmissionStageV1::Uncertain
            || stage_rank(next_stage) != stage_rank(self.stage).saturating_add(1)
            || stage_rank(next_stage) > stage_rank(AdmissionStageV1::ParentSynced)
        {
            return Err(AdmissionError::InvalidProgress);
        }
        self.successor(next_stage, next_stage, evidence)
    }

    /// Marks an entered effect as ambiguous without releasing capacity.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidProgress`] for no-effect or terminal
    /// states and sentinel evidence.
    pub fn mark_uncertain(&self, evidence: ObjectDigest) -> Result<Self, AdmissionError> {
        if matches!(
            self.stage,
            AdmissionStageV1::Reserved
                | AdmissionStageV1::CatalogCommitted
                | AdmissionStageV1::Uncertain
                | AdmissionStageV1::Quarantined
                | AdmissionStageV1::Aborted
        ) {
            return Err(AdmissionError::InvalidProgress);
        }
        self.successor(AdmissionStageV1::Uncertain, self.stage, evidence)
    }

    /// Resolves ambiguity from fresh exact physical observation.
    ///
    /// Recovery may retain or advance the last certain stage, quarantine a
    /// mismatch, or prove an abort. It may not move physical history backwards
    /// or declare catalog commitment on its own.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidProgress`] for an unsafe resolution.
    pub fn resolve_uncertainty(
        &self,
        observed_stage: AdmissionStageV1,
        evidence: ObjectDigest,
    ) -> Result<Self, AdmissionError> {
        if self.stage != AdmissionStageV1::Uncertain
            || observed_stage == AdmissionStageV1::Uncertain
            || observed_stage == AdmissionStageV1::CatalogCommitted
            || (stage_rank(observed_stage) < stage_rank(self.last_certain_stage)
                && !matches!(
                    observed_stage,
                    AdmissionStageV1::Quarantined | AdmissionStageV1::Aborted
                ))
        {
            return Err(AdmissionError::InvalidProgress);
        }
        self.successor(observed_stage, observed_stage, evidence)
    }

    /// Terminates before catalog commit after proving no reachable artifact remains.
    ///
    /// Reserved progress needs only a no-effect decision. Any later stage needs
    /// authoritative cleanup/absence evidence; the evidence digest is retained.
    /// Uncertain progress may abort only after recovery establishes absence.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidProgress`] after catalog commit or from
    /// an already terminal state.
    pub(crate) fn abort(&self, absence_evidence: ObjectDigest) -> Result<Self, AdmissionError> {
        if matches!(
            self.stage,
            AdmissionStageV1::CatalogCommitted
                | AdmissionStageV1::Quarantined
                | AdmissionStageV1::Aborted
        ) {
            return Err(AdmissionError::InvalidProgress);
        }
        self.successor(
            AdmissionStageV1::Aborted,
            AdmissionStageV1::Aborted,
            absence_evidence,
        )
    }

    fn catalog_committed(&self, evidence: ObjectDigest) -> Result<Self, AdmissionError> {
        if self.stage != AdmissionStageV1::ParentSynced {
            return Err(AdmissionError::InvalidProgress);
        }
        self.successor(
            AdmissionStageV1::CatalogCommitted,
            AdmissionStageV1::CatalogCommitted,
            evidence,
        )
    }

    fn successor(
        &self,
        stage: AdmissionStageV1,
        last_certain_stage: AdmissionStageV1,
        evidence: ObjectDigest,
    ) -> Result<Self, AdmissionError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(AdmissionError::InvalidProgress)?;
        let mut next = Self {
            plan_digest: self.plan_digest,
            stage,
            last_certain_stage,
            generation,
            predecessor: Some(self.digest),
            evidence,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        next.digest = admission_progress_digest(&next);
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn validate(&self) -> Result<(), AdmissionError> {
        if self.plan_digest.as_bytes() == &[0; 32]
            || self.generation == 0
            || (self.generation == 1) != self.predecessor.is_none()
            || self.evidence.as_bytes() == &[0; 32]
            || (self.stage != AdmissionStageV1::Uncertain && self.stage != self.last_certain_stage)
            || (self.stage == AdmissionStageV1::Uncertain
                && !(2..=9).contains(&stage_rank(self.last_certain_stage)))
            || self.digest != admission_progress_digest(self)
        {
            return Err(AdmissionError::InvalidProgress);
        }
        Ok(())
    }
}

/// Returns the atomically released reservation and authority-bound abort record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortedAdmissionV1 {
    /// Released reservation generation.
    pub reservation: CacheReservationV1,
    /// Terminal progress carrying protected cleanup/absence evidence.
    pub progress: AdmissionProgressV1,
}

/// Returns a committed entry together with its terminal publication progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationCommitV1 {
    /// Newly committed or exactly replayed catalog entry.
    pub catalog: CatalogEntryV1,
    /// Terminal progress record binding the catalog commit.
    pub progress: AdmissionProgressV1,
}

/// Holds the complete pure projection updated by admission transactions.
#[derive(Clone, Debug)]
pub struct CacheAdmissionStateV1 {
    limits: AdmissionLimitsV1,
    /// Checked quota and reservation projection.
    accounting: CacheAccountingV1,
    /// Exact pin obligations.
    pins: CachePinLedgerV1,
    catalog: BTreeMap<ObjectDescriptor, CatalogEntryV1>,
    plans: BTreeMap<OperationId, ImmutableAdmissionPlanV1>,
    watermark_requirements: BTreeMap<CacheReservationId, WatermarkRequirementV1>,
}

/// Retains the exact low-water reclamation gate created by a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatermarkRequirementV1 {
    /// Reservation that first crossed high water.
    pub reservation: CacheReservationId,
    /// Exact admission plan owning the reservation.
    pub plan_digest: ObjectDigest,
    /// Bytes that had to be reclaimed to reach low water.
    pub required_bytes: u64,
    /// Exact physically observed reclaimed bytes applied so far.
    pub credited_bytes: u64,
}

/// Bounds retained catalog tombstones and immutable admission plans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimitsV1 {
    /// Maximum committed, deleting, quarantined, and evicted catalog records.
    pub maximum_catalog_entries: usize,
    /// Maximum retained immutable admission plans.
    pub maximum_plans: usize,
}

impl AdmissionLimitsV1 {
    /// Validates fixed projection bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Capacity`] for zero or excessive limits.
    pub fn validate(self) -> Result<Self, AdmissionError> {
        if self.maximum_catalog_entries == 0
            || self.maximum_catalog_entries > 1_000_000
            || self.maximum_plans == 0
            || self.maximum_plans > 1_000_000
        {
            return Err(AdmissionError::Capacity);
        }
        Ok(self)
    }
}

impl CacheAdmissionStateV1 {
    /// Replays a complete bounded admission projection.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for malformed plans/catalog, duplicate
    /// identities, partition mismatch, or inconsistent pin accounting.
    pub fn replay(
        limits: AdmissionLimitsV1,
        accounting: CacheAccountingV1,
        pins: CachePinLedgerV1,
        catalog: impl IntoIterator<Item = CatalogEntryV1>,
        plans: impl IntoIterator<Item = ImmutableAdmissionPlanV1>,
        watermark_requirements: impl IntoIterator<Item = WatermarkRequirementV1>,
    ) -> Result<Self, AdmissionError> {
        let limits = limits.validate()?;
        let mut catalog_map = BTreeMap::new();
        let mut backing_identities = std::collections::BTreeSet::new();
        for entry in catalog {
            if catalog_map.len() >= limits.maximum_catalog_entries {
                return Err(AdmissionError::Capacity);
            }
            let entry = entry.validate()?;
            if !backing_identities.insert(entry.backing) {
                return Err(AdmissionError::CatalogCollision);
            }
            if catalog_map
                .insert(entry.descriptor.clone(), entry)
                .is_some()
            {
                return Err(AdmissionError::Conflict);
            }
        }
        let mut plan_map = BTreeMap::new();
        for plan in plans {
            if plan_map.len() >= limits.maximum_plans {
                return Err(AdmissionError::Capacity);
            }
            plan.validate()?;
            if plan.partition != accounting.partition() {
                return Err(AdmissionError::Conflict);
            }
            let reservation = accounting
                .reservation(plan.reservation)
                .ok_or(AdmissionError::Conflict)?;
            if reservation.operation != plan.operation
                || reservation.project != plan.project
                || reservation.partition != plan.partition
                || reservation.descriptor != plan.descriptor
                || reservation.plan_digest != plan.digest
                || reservation.reserved_bytes != plan.reserved_bytes
            {
                return Err(AdmissionError::Conflict);
            }
            if plan_map.insert(plan.operation, plan).is_some() {
                return Err(AdmissionError::Conflict);
            }
        }
        let mut state = Self {
            limits,
            accounting,
            pins,
            catalog: catalog_map,
            plans: plan_map,
            watermark_requirements: BTreeMap::new(),
        };
        for requirement in watermark_requirements {
            if !state.watermark_requirements.is_empty() {
                return Err(AdmissionError::InvalidWatermarkOrder);
            }
            if requirement.required_bytes == 0
                || requirement.credited_bytes >= requirement.required_bytes
                || state.accounting.eviction_requirement()?
                    != requirement
                        .required_bytes
                        .saturating_sub(requirement.credited_bytes)
                || !state
                    .accounting
                    .reservation(requirement.reservation)
                    .is_some_and(|reservation| {
                        matches!(
                            reservation.state,
                            ReservationStateV1::Reserved | ReservationStateV1::Uncertain
                        )
                    })
                || !state.plans.values().any(|plan| {
                    plan.reservation == requirement.reservation
                        && plan.digest == requirement.plan_digest
                })
                || state
                    .watermark_requirements
                    .insert(requirement.reservation, requirement)
                    .is_some()
            {
                return Err(AdmissionError::InvalidWatermarkOrder);
            }
        }
        let eviction_required = state.accounting.eviction_requirement()?;
        if (eviction_required > 0) != (state.watermark_requirements.len() == 1) {
            return Err(AdmissionError::InvalidWatermarkOrder);
        }
        for entry in state.catalog.values() {
            let reservation = state
                .accounting
                .reservation(entry.reservation)
                .ok_or(AdmissionError::Conflict)?;
            let expected_state = if entry.presence == CatalogPresenceV1::Evicted {
                ReservationStateV1::Evicted
            } else {
                ReservationStateV1::Converted
            };
            if reservation.partition != entry.partition
                || reservation.descriptor != entry.descriptor
                || reservation.state != expected_state
                || (reservation.state == ReservationStateV1::Converted
                    && reservation.resident_bytes != entry.allocated_bytes)
            {
                return Err(AdmissionError::Conflict);
            }
        }
        for pin in state.pins.values() {
            if pin.partition != state.accounting.partition() {
                return Err(AdmissionError::PinMismatch);
            }
            if pin.kind != super::pin::CachePinKindV1::SourceRetention {
                let entry = state
                    .catalog
                    .get(&pin.object)
                    .ok_or(AdmissionError::PinMismatch)?;
                if entry.partition != pin.partition
                    || entry.presence != CatalogPresenceV1::Committed
                {
                    return Err(AdmissionError::PinMismatch);
                }
            }
        }
        state.refresh_pin_accounting()?;
        Ok(state)
    }

    /// Atomically reserves capacity and records one immutable plan.
    ///
    /// Exact operation replay returns its retained plan. No allocation is
    /// authorized until this transition has been durably committed.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for conflicting reuse or quota exhaustion.
    pub fn admit(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        source_capability: &VerifiedCacheCapabilityV1,
        admission_capability: &VerifiedCacheCapabilityV1,
        plan: ImmutableAdmissionPlanV1,
        now: u64,
    ) -> Result<ImmutableAdmissionPlanV1, AdmissionError> {
        plan.validate()?;
        if plan.partition != self.accounting.partition() {
            return Err(AdmissionError::Conflict);
        }
        if now == 0 || now >= plan.source.valid_until {
            return Err(AdmissionError::SourceAuthorityExpired);
        }
        plan.source
            .validate_current(owner, source_capability, plan.partition, now)?;
        let admission_scope = plan.authority_scope()?;
        owner.validate_for_effect_at(
            admission_capability,
            CacheAuthorityPurposeV1::Admission,
            admission_scope,
            now,
        )?;
        if let Some(existing) = self.plans.get(&plan.operation) {
            return if existing == &plan {
                Ok(existing.clone())
            } else {
                Err(AdmissionError::Conflict)
            };
        }
        if self.plans.len() >= self.limits.maximum_plans {
            return Err(AdmissionError::Capacity);
        }
        if !self.watermark_requirements.is_empty() {
            return Err(AdmissionError::InvalidWatermarkOrder);
        }
        let mut next = self.clone();
        next.accounting.reserve(
            plan.reservation,
            plan.operation,
            plan.project,
            plan.descriptor.clone(),
            plan.reserved_bytes,
            plan.digest,
        )?;
        let required_bytes = next.accounting.eviction_requirement()?;
        if required_bytes > 0 {
            next.watermark_requirements.insert(
                plan.reservation,
                WatermarkRequirementV1 {
                    reservation: plan.reservation,
                    plan_digest: plan.digest,
                    required_bytes,
                    credited_bytes: 0,
                },
            );
        }
        next.refresh_pin_accounting()?;
        next.plans.insert(plan.operation, plan.clone());
        *self = next;
        Ok(plan)
    }

    /// Atomically commits catalog visibility, capacity conversion, and pins.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for a mismatched artifact, reservation CAS,
    /// catalog collision, pin conflict, or quota failure. The original state is
    /// unchanged on every error.
    pub fn commit_publication(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        operation: OperationId,
        plan_digest: ObjectDigest,
        expected_reservation_digest: ObjectDigest,
        progress: AdmissionProgressV1,
        artifact: PreparedArtifactV1,
        initial_pins: impl IntoIterator<Item = (CachePinV1, VerifiedCacheCapabilityV1)>,
        now: u64,
    ) -> Result<PublicationCommitV1, AdmissionError> {
        let plan = self
            .plans
            .get(&operation)
            .ok_or(AdmissionError::UnknownPlan)?
            .clone();
        if plan.digest != plan_digest {
            return Err(AdmissionError::Conflict);
        }
        artifact.validate_current(owner, capability, &plan, now)?;
        if self.watermark_requirements.contains_key(&plan.reservation) {
            return Err(AdmissionError::InvalidWatermarkOrder);
        }
        artifact.validate_for(&plan)?;
        if progress.plan_digest != plan.digest
            || progress.stage != AdmissionStageV1::ParentSynced
            || artifact.progress_digest != progress.digest
        {
            return Err(AdmissionError::InvalidProgress);
        }
        let initial_pins = initial_pins
            .into_iter()
            .take(MAXIMUM_INITIAL_PINS + 1)
            .collect::<Vec<_>>();
        if initial_pins.len() > MAXIMUM_INITIAL_PINS {
            return Err(AdmissionError::PinMismatch);
        }
        let pin_records = initial_pins
            .iter()
            .map(|(pin, _)| pin.clone())
            .collect::<Vec<_>>();
        if initial_pin_set_digest(&pin_records)? != plan.initial_pins_digest {
            return Err(AdmissionError::PinMismatch);
        }
        for (pin, pin_capability) in &initial_pins {
            pin.validate_current(owner, pin_capability, now)?;
        }

        if let Some(existing) = self.catalog.get(&plan.descriptor) {
            let pins_match = pin_records.iter().all(|pin| {
                self.pins
                    .pin(pin.id)
                    .is_some_and(|retained| retained == pin)
            });
            return if pins_match
                && existing.partition == plan.partition
                && existing.descriptor == plan.descriptor
                && existing.seal == artifact.seal
                && existing.backing == artifact.backing
                && existing.allocated_bytes == artifact.allocated_bytes
                && existing.root_custody == plan.root_custody
                && existing.publication == plan.operation
                && existing.presence == CatalogPresenceV1::Committed
            {
                Ok(PublicationCommitV1 {
                    catalog: existing.clone(),
                    progress: progress.catalog_committed(existing.digest)?,
                })
            } else {
                Err(AdmissionError::CatalogCollision)
            };
        }
        if self.catalog.len() >= self.limits.maximum_catalog_entries {
            return Err(AdmissionError::Capacity);
        }
        if self
            .catalog
            .values()
            .any(|entry| entry.backing == artifact.backing && entry.descriptor != plan.descriptor)
        {
            return Err(AdmissionError::CatalogCollision);
        }
        let reservation = self
            .accounting
            .reservation(plan.reservation)
            .ok_or(AdmissionError::Conflict)?;
        if reservation.digest != expected_reservation_digest
            || reservation.plan_digest != plan.digest
            || reservation.reserved_bytes != plan.reserved_bytes
            || reservation.descriptor != plan.descriptor
        {
            return Err(AdmissionError::Conflict);
        }

        let mut next = self.clone();
        next.accounting.transition(
            plan.reservation,
            expected_reservation_digest,
            ReservationStateV1::Converted,
            artifact.allocated_bytes,
        )?;
        for (pin, pin_capability) in initial_pins {
            if pin.partition != plan.partition || pin.object != plan.descriptor {
                return Err(AdmissionError::PinMismatch);
            }
            next.pins.acquire(owner, &pin_capability, pin, now)?;
        }
        next.refresh_pin_accounting()?;
        let entry = CatalogEntryV1::committed(
            plan.partition,
            plan.descriptor,
            artifact.seal,
            artifact.backing,
            artifact.allocated_bytes,
            plan.root_custody,
            plan.root_generation,
            plan.operation,
            plan.reservation,
        )?;
        next.catalog.insert(entry.descriptor.clone(), entry.clone());
        let progress = progress.catalog_committed(entry.digest)?;
        *self = next;
        Ok(PublicationCommitV1 {
            catalog: entry,
            progress,
        })
    }

    /// Atomically retains an ambiguous effect and its full reservation charge.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for operation/plan mismatch, non-uncertain
    /// progress, or a stale reservation generation.
    pub fn mark_uncertain(
        &mut self,
        operation: OperationId,
        expected_reservation_digest: ObjectDigest,
        progress: &AdmissionProgressV1,
    ) -> Result<CacheReservationV1, AdmissionError> {
        let plan = self
            .plans
            .get(&operation)
            .ok_or(AdmissionError::UnknownPlan)?;
        if progress.plan_digest != plan.digest || progress.stage != AdmissionStageV1::Uncertain {
            return Err(AdmissionError::InvalidProgress);
        }
        let mut next = self.clone();
        let reservation = next.accounting.transition(
            plan.reservation,
            expected_reservation_digest,
            ReservationStateV1::Uncertain,
            0,
        )?;
        next.refresh_pin_accounting()?;
        *self = next;
        Ok(reservation)
    }

    /// Atomically releases a reservation after proved pre-commit absence.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for operation/plan mismatch, terminal
    /// progress, stale reservation generation, or an already committed catalog.
    pub fn abort_admission(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        operation: OperationId,
        expected_reservation_digest: ObjectDigest,
        progress: &AdmissionProgressV1,
        now: u64,
    ) -> Result<AbortedAdmissionV1, AdmissionError> {
        let plan = self
            .plans
            .get(&operation)
            .ok_or(AdmissionError::UnknownPlan)?;
        if progress.plan_digest != plan.digest
            || matches!(
                progress.stage,
                AdmissionStageV1::CatalogCommitted
                    | AdmissionStageV1::Quarantined
                    | AdmissionStageV1::Aborted
            )
            || self.catalog.contains_key(&plan.descriptor)
        {
            return Err(AdmissionError::InvalidProgress);
        }
        let scope = CacheAuthorityScopeV1::new(
            plan.partition,
            progress.digest,
            Some(plan.operation),
            plan.digest,
            plan.root_custody,
            progress.generation,
            capability.scope().valid_until(),
        )?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::AdmissionCleanup,
            scope,
            now,
        )?;
        let aborted_progress = progress.abort(capability.record_digest())?;
        let mut next = self.clone();
        let reservation = next.accounting.transition(
            plan.reservation,
            expected_reservation_digest,
            ReservationStateV1::Released,
            0,
        )?;
        next.watermark_requirements.remove(&plan.reservation);
        next.refresh_pin_accounting()?;
        *self = next;
        Ok(AbortedAdmissionV1 {
            reservation,
            progress: aborted_progress,
        })
    }

    /// Returns a committed catalog entry without granting disclosure.
    #[must_use]
    pub fn catalog_entry(&self, object: &ObjectDescriptor) -> Option<&CatalogEntryV1> {
        self.catalog.get(object)
    }

    /// Finds the sole active logical pin for one consumer and object.
    ///
    /// The returned state does not prove current source or drain authority.
    #[must_use]
    pub fn logical_consumer_pin(
        &self,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
    ) -> Option<&CachePinV1> {
        self.pins.logical_consumer_pin(
            self.accounting.partition(),
            object,
            project,
            view,
            attachment,
        )
    }

    /// Selects an unreserved pin ID above this partition's compaction floor.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if no further pin ID can be represented.
    pub fn next_pin_id(&self) -> Result<super::pin::CachePinId, AdmissionError> {
        Ok(self.pins.next_pin_id()?)
    }

    /// Borrows checked accounting without allowing a partial mutation.
    #[must_use]
    pub const fn accounting(&self) -> &CacheAccountingV1 {
        &self.accounting
    }

    /// Borrows retained pins without allowing a partial mutation.
    #[must_use]
    pub const fn pins(&self) -> &CachePinLedgerV1 {
        &self.pins
    }

    /// Atomically acquires one pin and validates all project/node pin quotas.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for pin conflict or quota exhaustion, leaving
    /// the original projection unchanged.
    pub fn acquire_pin(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        pin: CachePinV1,
        now: u64,
    ) -> Result<(), AdmissionError> {
        pin.clone().validate()?;
        if pin.partition != self.accounting.partition() {
            return Err(AdmissionError::PinMismatch);
        }
        if pin.kind != super::pin::CachePinKindV1::SourceRetention {
            let entry = self
                .catalog
                .get(&pin.object)
                .ok_or(AdmissionError::UnknownObject)?;
            if entry.partition != pin.partition || entry.presence != CatalogPresenceV1::Committed {
                return Err(AdmissionError::PinMismatch);
            }
        }
        let mut next = self.clone();
        next.pins.acquire(owner, capability, pin, now)?;
        next.refresh_pin_accounting()?;
        *self = next;
        Ok(())
    }

    /// Atomically renews the sole logical pin for a consumer and object.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the old pin is absent, the consumer or
    /// runtime fence changed, the catalog is no longer committed, or current
    /// pin-acquisition authority cannot validate the renewed lease.
    pub fn renew_logical_pin(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        pin: CachePinV1,
        now: u64,
    ) -> Result<(), AdmissionError> {
        pin.clone().validate()?;
        if pin.kind != super::pin::CachePinKindV1::LogicalLease
            || pin.partition != self.accounting.partition()
        {
            return Err(AdmissionError::PinMismatch);
        }
        let entry = self
            .catalog
            .get(&pin.object)
            .ok_or(AdmissionError::UnknownObject)?;
        if entry.partition != pin.partition || entry.presence != CatalogPresenceV1::Committed {
            return Err(AdmissionError::PinMismatch);
        }

        let mut next = self.clone();
        next.pins.renew_logical(owner, capability, pin, now)?;
        next.refresh_pin_accounting()?;
        *self = next;
        Ok(())
    }

    /// Atomically releases one pin after exact drain evidence.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for absent/mismatched pin or invalid physical
    /// drain evidence, leaving the original projection unchanged.
    pub fn release_pin(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        id: super::pin::CachePinId,
        expected_evidence: ObjectDigest,
        drain: super::pin::PinDrainEvidenceV1,
        now: u64,
    ) -> Result<super::pin::ReleasedCachePinV1, AdmissionError> {
        let mut next = self.clone();
        let released = next
            .pins
            .release(owner, capability, id, expected_evidence, drain, now)?;
        next.refresh_pin_accounting()?;
        *self = next;
        Ok(released)
    }

    /// Atomically tombstones catalog residency and releases physical byte charge.
    ///
    /// This method is valid only after exact independent reclamation evidence
    /// has been validated by the eviction state machine.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for stale catalog/reservation generations or
    /// invalid state, leaving the original projection unchanged.
    pub(crate) fn finalize_eviction(
        &mut self,
        object: &ObjectDescriptor,
        expected_catalog: ObjectDigest,
        expected_reservation: ObjectDigest,
        expected_reclaimed_bytes: u64,
        watermark_reservation: Option<CacheReservationId>,
    ) -> Result<(ObjectDigest, u64), AdmissionError> {
        let current = self
            .catalog
            .get(object)
            .ok_or(AdmissionError::UnknownObject)?
            .clone();
        if current.digest != expected_catalog
            || current.presence != CatalogPresenceV1::Deleting
            || current.allocated_bytes != expected_reclaimed_bytes
        {
            return Err(AdmissionError::Conflict);
        }
        if self.pins.blocks_eviction(current.partition, object) {
            return Err(AdmissionError::PinMismatch);
        }
        let evicted = current.transition(CatalogPresenceV1::Evicted)?;
        let mut next = self.clone();
        next.accounting.transition(
            current.reservation,
            expected_reservation,
            ReservationStateV1::Evicted,
            0,
        )?;
        next.refresh_pin_accounting()?;
        next.catalog.insert(object.clone(), evicted.clone());
        if let Some(reservation) = watermark_reservation {
            next.credit_watermark_reclamation(reservation, current.allocated_bytes)?;
        }
        *self = next;
        Ok((evicted.digest, current.allocated_bytes))
    }

    /// Applies exact observed allocated bytes until at least the low-water gate.
    ///
    /// Each receipt is exact. The final indivisible object may take total credit
    /// beyond the byte target; that excess is real reclamation, not estimated
    /// credit, and closes the gate without being carried into another request.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidWatermarkOrder`] if the reservation has
    /// no pending gate or checked accumulation overflows.
    pub(crate) fn credit_watermark_reclamation(
        &mut self,
        reservation: CacheReservationId,
        reclaimed_bytes: u64,
    ) -> Result<(), AdmissionError> {
        let requirement = self
            .watermark_requirements
            .get_mut(&reservation)
            .ok_or(AdmissionError::InvalidWatermarkOrder)?;
        requirement.credited_bytes = requirement
            .credited_bytes
            .checked_add(reclaimed_bytes)
            .ok_or(AdmissionError::InvalidWatermarkOrder)?;
        if requirement.credited_bytes >= requirement.required_bytes {
            self.watermark_requirements.remove(&reservation);
        }
        Ok(())
    }

    /// Returns the remaining minimum reclamation target for a reservation.
    #[must_use]
    pub fn watermark_reclamation_remaining(&self, reservation: CacheReservationId) -> Option<u64> {
        self.watermark_requirements
            .get(&reservation)
            .map(|requirement| {
                requirement
                    .required_bytes
                    .saturating_sub(requirement.credited_bytes)
            })
    }

    /// Applies one exact catalog successor for eviction or quarantine.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the entry is absent or its expected digest
    /// conflicts with current state.
    pub(crate) fn replace_catalog_entry(
        &mut self,
        expected: ObjectDigest,
        successor: CatalogEntryV1,
    ) -> Result<(), AdmissionError> {
        let key = successor.descriptor.clone();
        let current = self
            .catalog
            .get(&key)
            .ok_or(AdmissionError::UnknownObject)?;
        if current.digest != expected || successor.predecessor != Some(expected) {
            return Err(AdmissionError::Conflict);
        }
        successor.clone().validate()?;
        self.catalog.insert(key, successor);
        Ok(())
    }

    fn refresh_pin_accounting(&mut self) -> Result<(), AdmissionError> {
        let (projects, node) = self.pins.usage()?;
        self.accounting = self.accounting.with_pin_usage(&projects, node)?;
        Ok(())
    }
}

/// Reports immutable admission and atomic projection failures.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// An admission plan is incomplete or internally inconsistent.
    #[error("cache admission plan is invalid")]
    InvalidPlan,
    /// An operation or retained identity was reused with different facts.
    #[error("cache admission conflicts with retained state")]
    Conflict,
    /// No retained plan has the requested digest.
    #[error("cache admission plan is absent")]
    UnknownPlan,
    /// Source authority expired before admission was durably accepted.
    #[error("cache source authority expired")]
    SourceAuthorityExpired,
    /// No catalog object has the requested identity.
    #[error("cache catalog object is absent")]
    UnknownObject,
    /// Prepared physical facts do not match the immutable plan.
    #[error("cache prepared artifact mismatches admission")]
    ArtifactMismatch,
    /// A canonical object identity already names different physical facts.
    #[error("cache catalog identity collision")]
    CatalogCollision,
    /// An initial pin does not name the admitted object and partition.
    #[error("cache admission pin mismatches object")]
    PinMismatch,
    /// Retained catalog or admission-plan capacity is exhausted.
    #[error("cache admission retained-state capacity is exhausted")]
    Capacity,
    /// Immutable publication progress is malformed or transitions unsafely.
    #[error("cache admission progress is invalid")]
    InvalidProgress,
    /// Checked capacity accounting rejected the transition.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    /// Catalog validation rejected the transition.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// Pin validation rejected the transition.
    #[error(transparent)]
    Pin(#[from] PinError),
    /// Protected cache authority verification failed.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityError),
    /// Admission attempted to commit before its reserve-to-low-water gate.
    #[error("cache admission violates reserve, evict, reclaim ordering")]
    InvalidWatermarkOrder,
}
