//! Immutable object admission and atomic projection transitions.
//!
//! Admission binds the object, source authorization, partition, reservation,
//! and expected immutable seal before effects.  Completion converts capacity,
//! inserts the committed catalog entry, and acquires initial pins as one pure
//! state transition.  A caller must persist the corresponding canonical record
//! set atomically before replacing its live projection.

use std::collections::BTreeMap;

use aos_sandbox_protocol::cache_state::{
    AccountingError, BackingObjectIdentityV1, CacheAccountingV1, CacheReservationId,
    CacheReservationV1, CatalogEntryV1, CatalogError, CatalogPresenceV1, ImmutableSealV1,
    PhysicalPartitionId, ReservationStateV1, canonical_name_digest, object_descriptor_commitment,
    validate_object_descriptor,
};

use super::domain::{
    CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1,
    VerifiedCacheCapabilityV1,
};
use super::pin::{CachePinLedgerV1, CachePinV1, PinError};
use aos_sandbox_core::{
    AttachmentId, ObjectDescriptor, ObjectDigest, OperationId, ProjectId, ViewId,
};

pub use aos_sandbox_protocol::cache_state::admission_progress::{
    AdmissionProgressV1, AdmissionStageV1, WatermarkRequirementV1,
};

use aos_sandbox_protocol::cache_state::admission_data::{
    SourceAuthorizationDataV1, ImmutableAdmissionPlanDataV1, source_authority_subject,
};

mod digest;

pub use digest::initial_pin_set_digest;
use digest::prepared_artifact_subject;

const MAXIMUM_INITIAL_PINS: usize = 65_536;

/// Retains verifier-issued source authority over its canonical historical DATA.
///
/// Historical DATA cannot construct this Native wrapper.
///
/// ```compile_fail
/// fn issue(data: aos_sandbox_protocol::cache_state::admission_data::SourceAuthorizationDataV1) {
///     let _ = aos_sandbox::cache_residency::admission::SourceAuthorizationV1(data);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAuthorizationV1(SourceAuthorizationDataV1);

impl std::ops::Deref for SourceAuthorizationV1 {
    type Target = SourceAuthorizationDataV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SourceAuthorizationV1 {
    pub(crate) fn authority_binding(
        &self,
        partition: PhysicalPartitionId,
    ) -> Result<(CacheAuthorityScopeV1, ObjectDigest), AdmissionError> {
        self.0
            .authority_binding(partition)
            .map_err(|error| AdmissionError::Authority(error.into()))
    }

    pub(crate) fn recover_historical(
        release_digest: ObjectDigest,
        source_revision: ObjectDigest,
        descriptor: ObjectDescriptor,
        source_seal: ObjectDigest,
        authority_generation: u64,
        valid_until: u64,
    ) -> Result<Self, AdmissionError> {
        Ok(Self(SourceAuthorizationDataV1::recover_historical(
            release_digest, source_revision, descriptor, source_seal,
            authority_generation, valid_until,
        )?))
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
        let scope = crate::cache_residency::domain::new_cache_authority_scope_v1(
            partition,
            source_authority_subject(&descriptor, source_revision, source_seal),
            None,
            source_revision,
            partition.backing().root(),
            authority_generation,
            valid_until,
        )?;
        owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Source, scope, now)?;
        let authorization = SourceAuthorizationDataV1 {
            release_digest: capability.record_digest(),
            source_revision,
            descriptor,
            source_seal,
            authority_generation,
            valid_until,
        };
        authorization.validate()?;
        Ok(Self(authorization))
    }

    /// Validates complete, non-sentinel source authority.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidPlan`] for missing commitments or a
    /// zero authority generation/lifetime.
    pub fn validate(&self) -> Result<(), AdmissionError> {
        self.0.validate().map_err(AdmissionError::from)
    }
}

/// Retains a Native admission plan constructed from its source-authority wrapper.
///
/// Historical DATA cannot construct this Native wrapper.
///
/// ```compile_fail
/// fn issue(data: aos_sandbox_protocol::cache_state::admission_data::ImmutableAdmissionPlanDataV1) {
///     let _ = aos_sandbox::cache_residency::admission::ImmutableAdmissionPlanV1(data);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableAdmissionPlanV1(ImmutableAdmissionPlanDataV1);

impl std::ops::Deref for ImmutableAdmissionPlanV1 {
    type Target = ImmutableAdmissionPlanDataV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ImmutableAdmissionPlanV1 {
    pub(crate) const fn historical_data_v1(&self) -> &ImmutableAdmissionPlanDataV1 {
        &self.0
    }

    pub(crate) fn into_historical_data_v1(self) -> ImmutableAdmissionPlanDataV1 {
        self.0
    }

    pub(crate) fn authority_scope(&self) -> Result<CacheAuthorityScopeV1, AdmissionError> {
        self.0
            .authority_scope()
            .map_err(|error| AdmissionError::Authority(error.into()))
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
        Ok(Self(ImmutableAdmissionPlanDataV1::new(
            operation, reservation, project, partition, descriptor, source.0,
            expected_seal, reserved_bytes, policy_revision, root_generation,
            root_custody, initial_pins_digest, request_digest,
        )?))
    }

    /// Validates an externally decoded admission plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::InvalidPlan`] when any immutable binding is
    /// absent or the digest is not the canonical derived value.
    pub fn validate(&self) -> Result<(), AdmissionError> {
        self.0.validate().map_err(AdmissionError::from)
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
        let authority_scope = crate::cache_residency::domain::new_cache_authority_scope_v1(
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
        let scope = crate::cache_residency::domain::new_cache_authority_scope_v1(
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
        validate_source_current(&plan.source, owner, source_capability, plan.partition, now)?;
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
        let plan = plan.0;
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
        let scope = crate::cache_residency::domain::new_cache_authority_scope_v1(
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

impl From<aos_sandbox_protocol::cache_state::admission_progress::AdmissionProgressErrorV1>
    for AdmissionError
{
    fn from(_: aos_sandbox_protocol::cache_state::admission_progress::AdmissionProgressErrorV1) -> Self {
        Self::InvalidProgress
    }
}

fn validate_source_current(
    source: &SourceAuthorizationDataV1,
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    partition: PhysicalPartitionId,
    now: u64,
) -> Result<(), AdmissionError> {
    let scope = crate::cache_residency::domain::new_cache_authority_scope_v1(
        partition,
        source_authority_subject(&source.descriptor, source.source_revision, source.source_seal),
        None,
        source.source_revision,
        partition.backing().root(),
        source.authority_generation,
        source.valid_until,
    )?;
    owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Source, scope, now)?;
    if capability.record_digest() != source.release_digest {
        return Err(AdmissionError::InvalidPlan);
    }
    Ok(())
}

impl From<aos_sandbox_protocol::cache_state::admission_data::AdmissionDataErrorV1> for AdmissionError {
    fn from(error: aos_sandbox_protocol::cache_state::admission_data::AdmissionDataErrorV1) -> Self {
        use aos_sandbox_protocol::cache_state::admission_data::AdmissionDataErrorV1;
        match error {
            AdmissionDataErrorV1::InvalidPlan => Self::InvalidPlan,
            AdmissionDataErrorV1::Catalog(error) => Self::Catalog(error),
        }
    }
}

#[cfg(test)]
mod historical_representation_tests {
    use super::*;

    #[test]
    fn native_wrappers_keep_exact_inline_historical_representation() {
        assert_eq!(std::mem::size_of::<SourceAuthorizationV1>(), std::mem::size_of::<SourceAuthorizationDataV1>());
        assert_eq!(std::mem::align_of::<SourceAuthorizationV1>(), std::mem::align_of::<SourceAuthorizationDataV1>());
        assert_eq!(std::mem::size_of::<ImmutableAdmissionPlanV1>(), std::mem::size_of::<ImmutableAdmissionPlanDataV1>());
        assert_eq!(std::mem::align_of::<ImmutableAdmissionPlanV1>(), std::mem::align_of::<ImmutableAdmissionPlanDataV1>());
    }
}
