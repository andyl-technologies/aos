//! Frozen-candidate two-phase eviction with race restoration.
//!
//! Selection is advisory and freezes exact catalog generations.  Each selected
//! object is rechecked for pins before its canonical name is moved to deleting
//! state.  Unlink occurs outside the metadata transaction.  Ambiguous unlink
//! never credits bytes; a raced pin restores the exact deleting entry before a
//! destructive effect is admitted.

use std::collections::BTreeSet;

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use super::accounting::CacheReservationId;
use super::admission::{AdmissionError, CacheAdmissionStateV1};
use super::catalog::{BackingObjectIdentityV1, CatalogEntryV1, CatalogPresenceV1};
use super::domain::{
    CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1,
    PhysicalPartitionId, VerifiedCacheCapabilityV1, object_descriptor_commitment,
    validate_object_descriptor,
};

/// Captures one bounded advisory eviction candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvictionCandidateV1 {
    /// Complete immutable object descriptor.
    pub descriptor: ObjectDescriptor,
    /// Catalog generation digest frozen during selection.
    pub catalog_digest: ObjectDigest,
    /// Opaque backing identity to re-observe before effects.
    pub backing: BackingObjectIdentityV1,
    /// Exact protected root custody generation.
    pub root_custody: ObjectDigest,
    /// Deterministic canonical-name commitment.
    pub canonical_name: ObjectDigest,
    /// Physical bytes expected to become reclaimable.
    pub physical_bytes: u64,
    /// Reachability state frozen before the deleting transition.
    pub original_presence: CatalogPresenceV1,
    /// Last-use generation used only for deterministic ordering.
    pub last_use_generation: u64,
    /// Fair-share pressure class, lower values evict first.
    pub pressure_class: u32,
}

/// Stores one immutable, bounded candidate set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenEvictionPlanV1 {
    /// Idempotent eviction operation.
    pub(crate) operation: OperationId,
    /// Physical partition that selection may affect.
    pub(crate) partition: PhysicalPartitionId,
    /// Catalog generation observed before selection.
    pub(crate) catalog_generation: u64,
    /// Current authority permitting eviction within this partition.
    pub(crate) authority_digest: ObjectDigest,
    pub(crate) authority_scope: CacheAuthorityScopeV1,
    /// Reservation whose reserve-to-low-water gate this plan satisfies.
    pub(crate) target_reservation: Option<CacheReservationId>,
    /// Low-water byte target for the transaction.
    pub(crate) target_reclaim_bytes: u64,
    /// Ordered exact candidate set.
    pub(crate) candidates: Vec<EvictionCandidateV1>,
    /// Digest of the complete frozen plan.
    pub(crate) digest: ObjectDigest,
}

impl FrozenEvictionPlanV1 {
    pub(crate) const fn authority_binding(&self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.authority_digest)
    }

    pub(crate) fn recover_historical(
        operation: OperationId,
        partition: PhysicalPartitionId,
        catalog_generation: u64,
        authority_digest: ObjectDigest,
        target_reservation: Option<CacheReservationId>,
        target_reclaim_bytes: u64,
        candidates: Vec<EvictionCandidateV1>,
        valid_until: u64,
    ) -> Result<Self, EvictionError> {
        let planned_bytes = validate_frozen_candidates(&candidates)?;
        let authority_plan = eviction_candidate_binding(
            operation,
            partition,
            catalog_generation,
            target_reservation,
            target_reclaim_bytes,
            &candidates,
        );
        let authority_scope = CacheAuthorityScopeV1::new(
            partition,
            authority_plan,
            Some(operation),
            authority_plan,
            partition.backing().root(),
            catalog_generation,
            valid_until,
        )?;
        let mut plan = Self {
            operation,
            partition,
            catalog_generation,
            authority_digest,
            authority_scope,
            target_reservation,
            target_reclaim_bytes,
            candidates,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        plan.digest = eviction_plan_digest(&plan);
        if operation.as_bytes() == &[0; 16]
            || authority_digest.as_bytes() == &[0; 32]
            || target_reclaim_bytes == 0
            || planned_bytes < target_reclaim_bytes
        {
            return Err(EvictionError::InvalidPlan);
        }
        Ok(plan)
    }

    /// Returns the canonical frozen candidate-set commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn contains_candidate(&self, candidate: &EvictionCandidateV1) -> bool {
        self.candidates
            .binary_search_by(|retained| compare_candidates(retained, candidate))
            .ok()
            .and_then(|index| self.candidates.get(index))
            .is_some_and(|retained| retained == candidate)
    }

    /// Freezes an already-filtered candidate set under fixed bounds.
    ///
    /// The caller supplies only entries in the permitted physical partition;
    /// this constructor checks committed reachability, zero current pins, exact
    /// identity uniqueness, ordering, and sufficient planned bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError`] for malformed, pinned, cross-partition,
    /// duplicate, oversized, or insufficient candidate sets.
    pub fn freeze(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        operation: OperationId,
        partition: PhysicalPartitionId,
        catalog_generation: u64,
        target_reservation: Option<CacheReservationId>,
        valid_until: u64,
        now: u64,
        target_reclaim_bytes: u64,
        maximum_candidates: usize,
        state: &CacheAdmissionStateV1,
        candidates: impl IntoIterator<Item = (ObjectDescriptor, u64, u32)>,
    ) -> Result<Self, EvictionError> {
        if operation.as_bytes() == &[0; 16]
            || catalog_generation == 0
            || target_reclaim_bytes == 0
            || maximum_candidates == 0
            || maximum_candidates > 65_536
        {
            return Err(EvictionError::InvalidPlan);
        }
        if let Some(target_reservation) = target_reservation {
            let remaining = state
                .watermark_reclamation_remaining(target_reservation)
                .ok_or(EvictionError::InvalidWatermarkOrder)?;
            if remaining != target_reclaim_bytes {
                return Err(EvictionError::InvalidWatermarkOrder);
            }
            state
                .accounting()
                .reservation(target_reservation)
                .ok_or(EvictionError::InvalidWatermarkOrder)?;
        }
        let mut frozen = Vec::new();
        let mut candidate_identities = BTreeSet::new();
        let mut planned_bytes = 0_u64;
        for (descriptor, last_use_generation, pressure_class) in candidates {
            if frozen.len() >= maximum_candidates {
                return Err(EvictionError::CandidateLimit);
            }
            if last_use_generation == 0 {
                return Err(EvictionError::InvalidPlan);
            }
            let entry = state
                .catalog_entry(&descriptor)
                .ok_or(EvictionError::UnknownObject)?;
            if entry.partition != partition
                || !matches!(
                    entry.presence,
                    CatalogPresenceV1::Committed | CatalogPresenceV1::Quarantined
                )
                || (target_reservation.is_none()
                    && entry.presence != CatalogPresenceV1::Quarantined)
            {
                return Err(EvictionError::PartitionOrStateMismatch);
            }
            if state.pins().blocks_eviction(partition, &descriptor) {
                return Err(EvictionError::Pinned);
            }
            if !candidate_identities.insert(descriptor.clone()) {
                return Err(EvictionError::DuplicateCandidate);
            }
            planned_bytes = planned_bytes
                .checked_add(entry.allocated_bytes)
                .ok_or(EvictionError::Overflow)?;
            frozen.push(EvictionCandidateV1 {
                descriptor,
                catalog_digest: entry.digest,
                backing: entry.backing,
                root_custody: entry.root_custody,
                canonical_name: entry.canonical_name,
                physical_bytes: entry.allocated_bytes,
                original_presence: entry.presence,
                last_use_generation,
                pressure_class,
            });
        }
        frozen.sort_by_key(|candidate| {
            (
                candidate.pressure_class,
                candidate.last_use_generation,
                candidate.descriptor.clone(),
            )
        });
        if planned_bytes < target_reclaim_bytes {
            return Err(EvictionError::InsufficientCandidates);
        }
        let authority_plan = eviction_candidate_binding(
            operation,
            partition,
            catalog_generation,
            target_reservation,
            target_reclaim_bytes,
            &frozen,
        );
        let authority_scope = CacheAuthorityScopeV1::new(
            partition,
            authority_plan,
            Some(operation),
            authority_plan,
            partition.backing().root(),
            catalog_generation,
            valid_until,
        )?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Eviction,
            authority_scope,
            now,
        )?;
        let mut plan = Self {
            operation,
            partition,
            catalog_generation,
            authority_digest: capability.record_digest(),
            authority_scope,
            target_reservation,
            target_reclaim_bytes,
            candidates: frozen,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        plan.digest = eviction_plan_digest(&plan);
        Ok(plan)
    }

    fn validate_current(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        now: u64,
    ) -> Result<(), EvictionError> {
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Eviction,
            self.authority_scope,
            now,
        )?;
        if capability.record_digest() != self.authority_digest {
            return Err(EvictionError::InvalidPlan);
        }
        Ok(())
    }
}

/// Selects one candidate's durable two-phase state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EvictionCandidateStateV1 {
    /// Frozen but not yet rechecked for a deleting rename.
    Selected = 1,
    /// A raced pin made the candidate ineligible before rename.
    RestoredBeforeEffect = 2,
    /// The catalog and canonical name are in deleting state.
    Deleting = 3,
    /// Unlink may have happened; no bytes may be credited.
    UnlinkAmbiguous = 4,
    /// Filesystem reports removal but reclamation is not yet proved.
    RemovedAwaitingReclaim = 5,
    /// Backing storage independently proved the bytes reclaimable.
    Reclaimed = 6,
    /// A pre-unlink pin race restored committed catalog reachability.
    RestoredAfterRename = 7,
    /// Validation contradiction quarantined the backing instead of deleting it.
    Quarantined = 8,
}

/// Tracks one frozen candidate through exact effects and recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvictionProgressV1 {
    /// Frozen operation digest.
    pub(crate) plan_digest: ObjectDigest,
    /// Exact candidate.
    pub(crate) candidate: EvictionCandidateV1,
    /// Current closed state.
    pub(crate) state: EvictionCandidateStateV1,
    /// Latest catalog digest after a rename/restore/quarantine.
    pub(crate) current_catalog_digest: ObjectDigest,
    /// Opaque digest of the latest trusted observation.
    pub(crate) evidence: Option<ObjectDigest>,
    /// Bytes proved reclaimable, zero until terminal reclamation.
    pub(crate) reclaimed_bytes: u64,
}

impl EvictionProgressV1 {
    pub(crate) fn recover_historical(
        plan: &FrozenEvictionPlanV1,
        candidate: EvictionCandidateV1,
        state: EvictionCandidateStateV1,
        current_catalog_digest: ObjectDigest,
        evidence: Option<ObjectDigest>,
        reclaimed_bytes: u64,
    ) -> Result<Self, EvictionError> {
        if !plan.contains_candidate(&candidate) || current_catalog_digest.as_bytes() == &[0; 32] {
            return Err(EvictionError::InvalidTransition);
        }
        let needs_evidence = matches!(
            state,
            EvictionCandidateStateV1::UnlinkAmbiguous
                | EvictionCandidateStateV1::RemovedAwaitingReclaim
                | EvictionCandidateStateV1::Reclaimed
                | EvictionCandidateStateV1::Quarantined
        );
        if needs_evidence != evidence.is_some()
            || evidence.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || (state == EvictionCandidateStateV1::Reclaimed
                && reclaimed_bytes != candidate.physical_bytes)
            || (state != EvictionCandidateStateV1::Reclaimed && reclaimed_bytes != 0)
        {
            return Err(EvictionError::InvalidTransition);
        }
        Ok(Self {
            plan_digest: plan.digest,
            candidate,
            state,
            current_catalog_digest,
            evidence,
            reclaimed_bytes,
        })
    }

    /// Returns the closed current candidate state.
    #[must_use]
    pub const fn state(&self) -> EvictionCandidateStateV1 {
        self.state
    }

    /// Returns exact physically observed reclaimed allocated bytes.
    #[must_use]
    pub const fn reclaimed_bytes(&self) -> u64 {
        self.reclaimed_bytes
    }

    /// Starts progress for an exact member of a frozen plan.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError::CandidateNotFrozen`] if the candidate is absent.
    pub fn selected(
        plan: &FrozenEvictionPlanV1,
        descriptor: &ObjectDescriptor,
    ) -> Result<Self, EvictionError> {
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| &candidate.descriptor == descriptor)
            .ok_or(EvictionError::CandidateNotFrozen)?
            .clone();
        Ok(Self {
            plan_digest: plan.digest,
            current_catalog_digest: candidate.catalog_digest,
            candidate,
            state: EvictionCandidateStateV1::Selected,
            evidence: None,
            reclaimed_bytes: 0,
        })
    }

    /// Rechecks current pins and atomically moves an eligible entry to deleting.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError`] for stale catalog identity or invalid progress.
    pub fn prepare_unlink(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        state: &mut CacheAdmissionStateV1,
        now: u64,
    ) -> Result<(), EvictionError> {
        plan.validate_current(owner, capability, now)?;
        if self.plan_digest != plan.digest {
            return Err(EvictionError::InvalidPlan);
        }
        if self.state != EvictionCandidateStateV1::Selected {
            return Err(EvictionError::InvalidTransition);
        }
        let entry = state
            .catalog_entry(&self.candidate.descriptor)
            .ok_or(EvictionError::UnknownObject)?
            .clone();
        if entry.digest != self.candidate.catalog_digest
            || entry.backing != self.candidate.backing
            || entry.root_custody != self.candidate.root_custody
            || entry.canonical_name != self.candidate.canonical_name
            || entry.presence != self.candidate.original_presence
        {
            return Err(EvictionError::StaleCandidate);
        }
        if state
            .pins()
            .blocks_eviction(entry.partition, &self.candidate.descriptor)
        {
            self.state = EvictionCandidateStateV1::RestoredBeforeEffect;
            return Ok(());
        }
        let deleting = entry.transition(CatalogPresenceV1::Deleting)?;
        state.replace_catalog_entry(entry.digest, deleting.clone())?;
        self.current_catalog_digest = deleting.digest;
        self.state = EvictionCandidateStateV1::Deleting;
        Ok(())
    }

    /// Rechecks for a pin race immediately before destructive unlink.
    ///
    /// A newly acquired pin restores committed reachability and denies unlink.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError`] for stale or invalid progress.
    pub fn recheck_before_unlink(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        state: &mut CacheAdmissionStateV1,
        now: u64,
    ) -> Result<UnlinkAdmissionV1, EvictionError> {
        plan.validate_current(owner, capability, now)?;
        if self.plan_digest != plan.digest {
            return Err(EvictionError::InvalidPlan);
        }
        if self.state != EvictionCandidateStateV1::Deleting {
            return Err(EvictionError::InvalidTransition);
        }
        let entry = state
            .catalog_entry(&self.candidate.descriptor)
            .ok_or(EvictionError::UnknownObject)?
            .clone();
        if entry.digest != self.current_catalog_digest
            || entry.backing != self.candidate.backing
            || entry.root_custody != self.candidate.root_custody
            || entry.canonical_name != self.candidate.canonical_name
            || entry.presence != CatalogPresenceV1::Deleting
        {
            return Err(EvictionError::StaleCandidate);
        }
        if state
            .pins()
            .blocks_eviction(entry.partition, &self.candidate.descriptor)
        {
            let restored = entry.transition(self.candidate.original_presence)?;
            state.replace_catalog_entry(entry.digest, restored.clone())?;
            self.current_catalog_digest = restored.digest;
            self.state = EvictionCandidateStateV1::RestoredAfterRename;
            return Ok(UnlinkAdmissionV1::DeniedAndRestored);
        }
        Ok(UnlinkAdmissionV1::Authorized(AuthorizedUnlinkV1 {
            plan_digest: self.plan_digest,
            descriptor: self.candidate.descriptor.clone(),
            backing: self.candidate.backing,
            root_custody: self.candidate.root_custody,
            canonical_name: self.candidate.canonical_name,
            deleting_catalog_digest: self.current_catalog_digest,
        }))
    }

    /// Applies an exact unlink observation without over-crediting ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError`] for an observation that does not bind the
    /// current plan, object, backing identity, and deleting generation.
    pub fn observe_unlink(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        state: &mut CacheAdmissionStateV1,
        observation: UnlinkObservationV1,
        now: u64,
    ) -> Result<(), EvictionError> {
        observation.validate_current(owner, capability, plan, self, now)?;
        if self.state != EvictionCandidateStateV1::Deleting
            || observation.plan_digest != self.plan_digest
            || observation.descriptor != self.candidate.descriptor
            || observation.backing != self.candidate.backing
            || observation.root_custody != self.candidate.root_custody
            || observation.canonical_name != self.candidate.canonical_name
            || observation.deleting_catalog_digest != self.current_catalog_digest
            || observation.evidence.as_bytes() == &[0; 32]
        {
            return Err(EvictionError::ObservationMismatch);
        }
        if observation.outcome == UnlinkOutcomeV1::IdentityMismatch {
            let entry = state
                .catalog_entry(&self.candidate.descriptor)
                .ok_or(EvictionError::UnknownObject)?
                .clone();
            if entry.digest != self.current_catalog_digest
                || entry.presence != CatalogPresenceV1::Deleting
            {
                return Err(EvictionError::StaleCandidate);
            }
            let quarantined = entry.transition(CatalogPresenceV1::Quarantined)?;
            state.replace_catalog_entry(entry.digest, quarantined.clone())?;
            self.current_catalog_digest = quarantined.digest;
        }
        self.evidence = Some(observation.evidence);
        self.state = match observation.outcome {
            UnlinkOutcomeV1::RemovedOrAlreadyAbsent => {
                EvictionCandidateStateV1::RemovedAwaitingReclaim
            }
            UnlinkOutcomeV1::Ambiguous | UnlinkOutcomeV1::StillPresentExact => {
                EvictionCandidateStateV1::UnlinkAmbiguous
            }
            UnlinkOutcomeV1::IdentityMismatch => EvictionCandidateStateV1::Quarantined,
        };
        Ok(())
    }

    /// Resolves an ambiguous unlink from a fresh exact observation.
    ///
    /// A clearly removed backing advances toward reclamation. An identity
    /// mismatch quarantines. A clearly retained exact backing may become
    /// eligible for another pre-unlink pin recheck only with fresh current
    /// authority and proof the old attempt is fenced. Continued ambiguity does
    /// not advance.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError`] for mismatched evidence or missing retry
    /// authority.
    pub fn resolve_ambiguous_unlink(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        observation_capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        state: &mut CacheAdmissionStateV1,
        observation: UnlinkObservationV1,
        retry: Option<(EvictionRetryAuthorityV1, &VerifiedCacheCapabilityV1)>,
        now: u64,
    ) -> Result<(), EvictionError> {
        observation.validate_current(owner, observation_capability, plan, self, now)?;
        if self.state != EvictionCandidateStateV1::UnlinkAmbiguous
            || observation.plan_digest != self.plan_digest
            || observation.descriptor != self.candidate.descriptor
            || observation.backing != self.candidate.backing
            || observation.root_custody != self.candidate.root_custody
            || observation.canonical_name != self.candidate.canonical_name
            || observation.deleting_catalog_digest != self.current_catalog_digest
            || observation.evidence.as_bytes() == &[0; 32]
        {
            return Err(EvictionError::ObservationMismatch);
        }
        match observation.outcome {
            UnlinkOutcomeV1::RemovedOrAlreadyAbsent => {
                self.state = EvictionCandidateStateV1::RemovedAwaitingReclaim;
            }
            UnlinkOutcomeV1::Ambiguous => {}
            UnlinkOutcomeV1::StillPresentExact => {
                let (retry, retry_capability) =
                    retry.ok_or(EvictionError::InvalidRetryAuthority)?;
                retry.validate_current(owner, retry_capability, plan, self, now)?;
                if retry.plan_digest != self.plan_digest
                    || retry.deleting_catalog_digest != self.current_catalog_digest
                    || retry.observation != observation.evidence
                    || retry.digest != retry_authority_digest(&retry)
                {
                    return Err(EvictionError::InvalidRetryAuthority);
                }
                self.state = EvictionCandidateStateV1::Deleting;
            }
            UnlinkOutcomeV1::IdentityMismatch => {
                let entry = state
                    .catalog_entry(&self.candidate.descriptor)
                    .ok_or(EvictionError::UnknownObject)?
                    .clone();
                if entry.digest != self.current_catalog_digest
                    || entry.presence != CatalogPresenceV1::Deleting
                {
                    return Err(EvictionError::StaleCandidate);
                }
                let quarantined = entry.transition(CatalogPresenceV1::Quarantined)?;
                state.replace_catalog_entry(entry.digest, quarantined.clone())?;
                self.current_catalog_digest = quarantined.digest;
                self.state = EvictionCandidateStateV1::Quarantined;
            }
        }
        self.evidence = Some(observation.evidence);
        Ok(())
    }

    /// Credits bytes only after independent backing reclamation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError`] for premature, mismatched, or inexact credit.
    pub fn confirm_reclaimed(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        state: &mut CacheAdmissionStateV1,
        expected_reservation_digest: ObjectDigest,
        evidence: ReclamationEvidenceV1,
        now: u64,
    ) -> Result<(), EvictionError> {
        evidence.validate_current(owner, capability, plan, self, now)?;
        if self.state != EvictionCandidateStateV1::RemovedAwaitingReclaim
            || evidence.plan_digest != self.plan_digest
            || evidence.backing != self.candidate.backing
            || evidence.reclaimable_bytes != self.candidate.physical_bytes
            || evidence.digest.as_bytes() == &[0; 32]
        {
            return Err(EvictionError::ObservationMismatch);
        }
        let (catalog_digest, physically_reclaimed) = state.finalize_eviction(
            &self.candidate.descriptor,
            self.current_catalog_digest,
            expected_reservation_digest,
            evidence.reclaimable_bytes,
            evidence.target_reservation,
        )?;
        if physically_reclaimed != evidence.reclaimable_bytes {
            return Err(EvictionError::ObservationMismatch);
        }
        self.current_catalog_digest = catalog_digest;
        self.state = EvictionCandidateStateV1::Reclaimed;
        self.evidence = Some(evidence.digest);
        self.reclaimed_bytes = evidence.reclaimable_bytes;
        Ok(())
    }
}

/// Reports whether a destructive unlink may be issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnlinkAdmissionV1 {
    /// A pin race restored committed reachability; no unlink may occur.
    DeniedAndRestored,
    /// Exact current facts permit one idempotent unlink attempt.
    Authorized(AuthorizedUnlinkV1),
}

/// Carries the opaque exact effect binding for one authorized unlink attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedUnlinkV1 {
    plan_digest: ObjectDigest,
    descriptor: ObjectDescriptor,
    backing: BackingObjectIdentityV1,
    root_custody: ObjectDigest,
    canonical_name: ObjectDigest,
    deleting_catalog_digest: ObjectDigest,
}

impl AuthorizedUnlinkV1 {
    /// Returns the frozen plan commitment authorizing this effect.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the complete immutable object selected for unlink.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    /// Returns the exact backing identity authorized for unlink.
    #[must_use]
    pub const fn backing(&self) -> BackingObjectIdentityV1 {
        self.backing
    }

    /// Returns the protected root custody commitment for resolution.
    #[must_use]
    pub const fn root_custody(&self) -> ObjectDigest {
        self.root_custody
    }

    /// Returns the canonical-name commitment authorized for resolution.
    #[must_use]
    pub const fn canonical_name(&self) -> ObjectDigest {
        self.canonical_name
    }

    /// Returns the exact deleting catalog generation.
    #[must_use]
    pub const fn deleting_catalog_digest(&self) -> ObjectDigest {
        self.deleting_catalog_digest
    }
}

/// Selects a trusted unlink observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlinkOutcomeV1 {
    /// The exact backing was removed or proved already absent.
    RemovedOrAlreadyAbsent,
    /// Interruption prevents determining whether removal occurred.
    Ambiguous,
    /// The exact backing remains in deleting state and no unlink occurred.
    StillPresentExact,
    /// The resolved root/name no longer names the expected backing.
    IdentityMismatch,
}

/// Authorizes retry only after ambiguity, old-attempt fencing, and reobservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvictionRetryAuthorityV1 {
    /// Frozen eviction plan being resumed.
    plan_digest: ObjectDigest,
    /// Exact deleting catalog generation.
    deleting_catalog_digest: ObjectDigest,
    /// Fresh current authority for this partition and object.
    current_authority: ObjectDigest,
    /// Proof the prior executor/effect attempt cannot still mutate backing.
    old_attempt_fence: ObjectDigest,
    /// Fresh exact observation that the backing remains in deleting state.
    observation: ObjectDigest,
    /// Digest of the complete retry decision.
    digest: ObjectDigest,
    authority_scope: CacheAuthorityScopeV1,
}

impl EvictionRetryAuthorityV1 {
    /// Constructs a fresh exact retry authority.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError::InvalidRetryAuthority`] for any sentinel fact.
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        progress: &EvictionProgressV1,
        old_attempt_fence: ObjectDigest,
        observation: ObjectDigest,
        now: u64,
    ) -> Result<Self, EvictionError> {
        if progress.state != EvictionCandidateStateV1::UnlinkAmbiguous {
            return Err(EvictionError::InvalidRetryAuthority);
        }
        let scope = eviction_effect_scope(
            plan,
            progress,
            retry_subject(progress, old_attempt_fence, observation),
            capability.scope().generation(),
            capability.scope().valid_until(),
        )?;
        owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Retry, scope, now)?;
        let mut authority = Self {
            plan_digest: plan.digest,
            deleting_catalog_digest: progress.current_catalog_digest,
            current_authority: capability.record_digest(),
            old_attempt_fence,
            observation,
            digest: ObjectDigest::from_bytes([0; 32]),
            authority_scope: scope,
        };
        authority.digest = retry_authority_digest(&authority);
        if [
            authority.plan_digest,
            authority.deleting_catalog_digest,
            authority.current_authority,
            authority.old_attempt_fence,
            authority.observation,
            authority.digest,
        ]
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(EvictionError::InvalidRetryAuthority);
        }
        Ok(authority)
    }

    pub(crate) fn validate_current(
        self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        progress: &EvictionProgressV1,
        now: u64,
    ) -> Result<(), EvictionError> {
        if progress.state != EvictionCandidateStateV1::UnlinkAmbiguous
            || self.authority_scope
                != eviction_effect_scope(
                    plan,
                    progress,
                    retry_subject(progress, self.old_attempt_fence, self.observation),
                    self.authority_scope.generation(),
                    self.authority_scope.valid_until(),
                )?
            || self.current_authority != capability.record_digest()
        {
            return Err(EvictionError::InvalidRetryAuthority);
        }
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Retry,
            self.authority_scope,
            now,
        )?;
        Ok(())
    }

    pub(crate) fn matches_observation_and_successor(
        self,
        observation: &UnlinkObservationV1,
        previous: &EvictionProgressV1,
        next: &EvictionProgressV1,
        catalog: Option<&CatalogEntryV1>,
    ) -> bool {
        observation.outcome == UnlinkOutcomeV1::StillPresentExact
            && observation.evidence == self.observation
            && self.plan_digest == previous.plan_digest
            && self.deleting_catalog_digest == previous.current_catalog_digest
            && next.plan_digest == previous.plan_digest
            && next.candidate == previous.candidate
            && next.state == EvictionCandidateStateV1::Deleting
            && next.current_catalog_digest == previous.current_catalog_digest
            && next.evidence == Some(observation.evidence)
            && next.reclaimed_bytes == 0
            && catalog.is_some_and(|entry| {
                entry.descriptor == previous.candidate.descriptor
                    && entry.presence == CatalogPresenceV1::Deleting
                    && entry.digest == previous.current_catalog_digest
            })
    }
}

/// Binds an unlink result to the exact authorized effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnlinkObservationV1 {
    /// Frozen plan digest.
    plan_digest: ObjectDigest,
    /// Complete immutable object descriptor.
    descriptor: ObjectDescriptor,
    /// Opaque backing identity observed beneath the protected root.
    backing: BackingObjectIdentityV1,
    /// Exact protected root custody generation.
    root_custody: ObjectDigest,
    /// Deterministic canonical-name commitment observed for unlink.
    canonical_name: ObjectDigest,
    /// Exact deleting catalog generation.
    deleting_catalog_digest: ObjectDigest,
    /// Closed unlink result.
    outcome: UnlinkOutcomeV1,
    /// Digest of the trusted syscall observation.
    evidence: ObjectDigest,
    authority_scope: CacheAuthorityScopeV1,
}

impl UnlinkObservationV1 {
    pub(crate) const fn authority_binding(&self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.evidence)
    }

    pub(crate) fn matches_successor(
        &self,
        previous: &EvictionProgressV1,
        next: &EvictionProgressV1,
        catalog: Option<&CatalogEntryV1>,
    ) -> bool {
        if self.plan_digest != previous.plan_digest
            || self.descriptor != previous.candidate.descriptor
            || self.backing != previous.candidate.backing
            || self.root_custody != previous.candidate.root_custody
            || self.canonical_name != previous.candidate.canonical_name
            || self.deleting_catalog_digest != previous.current_catalog_digest
            || next.plan_digest != previous.plan_digest
            || next.candidate != previous.candidate
            || next.evidence != Some(self.evidence)
            || next.reclaimed_bytes != 0
        {
            return false;
        }
        let deleting_catalog_unchanged = || {
            catalog.is_some_and(|entry| {
                entry.descriptor == previous.candidate.descriptor
                    && entry.presence == CatalogPresenceV1::Deleting
                    && entry.digest == previous.current_catalog_digest
            })
        };
        match self.outcome {
            UnlinkOutcomeV1::RemovedOrAlreadyAbsent => {
                next.state == EvictionCandidateStateV1::RemovedAwaitingReclaim
                    && next.current_catalog_digest == previous.current_catalog_digest
                    && deleting_catalog_unchanged()
            }
            UnlinkOutcomeV1::Ambiguous | UnlinkOutcomeV1::StillPresentExact => {
                next.state == EvictionCandidateStateV1::UnlinkAmbiguous
                    && next.current_catalog_digest == previous.current_catalog_digest
                    && deleting_catalog_unchanged()
            }
            UnlinkOutcomeV1::IdentityMismatch => {
                next.state == EvictionCandidateStateV1::Quarantined
                    && catalog.is_some_and(|entry| {
                        entry.descriptor == previous.candidate.descriptor
                            && entry.presence == CatalogPresenceV1::Quarantined
                            && entry.predecessor == Some(previous.current_catalog_digest)
                            && entry.digest == next.current_catalog_digest
                    })
            }
        }
    }

    /// Issues an unlink observation from the exact current protected scope.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError`] for a stale capability or non-deleting progress.
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        progress: &EvictionProgressV1,
        outcome: UnlinkOutcomeV1,
        now: u64,
    ) -> Result<Self, EvictionError> {
        if !matches!(
            progress.state,
            EvictionCandidateStateV1::Deleting | EvictionCandidateStateV1::UnlinkAmbiguous
        ) {
            return Err(EvictionError::InvalidTransition);
        }
        let scope = eviction_effect_scope(
            plan,
            progress,
            unlink_subject(progress, outcome),
            capability.scope().generation(),
            capability.scope().valid_until(),
        )?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::UnlinkObservation,
            scope,
            now,
        )?;
        Ok(Self {
            plan_digest: plan.digest,
            descriptor: progress.candidate.descriptor.clone(),
            backing: progress.candidate.backing,
            root_custody: progress.candidate.root_custody,
            canonical_name: progress.candidate.canonical_name,
            deleting_catalog_digest: progress.current_catalog_digest,
            outcome,
            evidence: capability.record_digest(),
            authority_scope: scope,
        })
    }

    pub(crate) fn validate_current(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        progress: &EvictionProgressV1,
        now: u64,
    ) -> Result<(), EvictionError> {
        let scope = eviction_effect_scope(
            plan,
            progress,
            unlink_subject(progress, self.outcome),
            self.authority_scope.generation(),
            self.authority_scope.valid_until(),
        )?;
        if scope != self.authority_scope || capability.record_digest() != self.evidence {
            return Err(EvictionError::ObservationMismatch);
        }
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::UnlinkObservation,
            scope,
            now,
        )?;
        Ok(())
    }
}

/// Proves exact physical space is reclaimable after removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclamationEvidenceV1 {
    /// Frozen plan digest.
    plan_digest: ObjectDigest,
    /// Exact backing object.
    backing: BackingObjectIdentityV1,
    target_reservation: Option<CacheReservationId>,
    /// Bytes independently reported reclaimable.
    reclaimable_bytes: u64,
    /// Digest of the backing-filesystem observation.
    digest: ObjectDigest,
    authority_scope: CacheAuthorityScopeV1,
}

impl ReclamationEvidenceV1 {
    pub(crate) const fn authority_binding(self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.digest)
    }

    pub(crate) fn matches_successor(
        self,
        previous: &EvictionProgressV1,
        next: &EvictionProgressV1,
        catalog: Option<&CatalogEntryV1>,
    ) -> bool {
        self.plan_digest == previous.plan_digest
            && self.backing == previous.candidate.backing
            && self.reclaimable_bytes == previous.candidate.physical_bytes
            && next.plan_digest == previous.plan_digest
            && next.candidate == previous.candidate
            && next.state == EvictionCandidateStateV1::Reclaimed
            && next.evidence == Some(self.digest)
            && next.reclaimed_bytes == self.reclaimable_bytes
            && catalog.is_some_and(|entry| {
                entry.descriptor == previous.candidate.descriptor
                    && entry.presence == CatalogPresenceV1::Evicted
                    && entry.predecessor == Some(previous.current_catalog_digest)
                    && entry.digest == next.current_catalog_digest
            })
    }

    /// Issues exact allocated-byte reclamation evidence from protected state.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionError`] for stale scope or an inexact byte observation.
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        progress: &EvictionProgressV1,
        physically_reclaimed_allocated_bytes: u64,
        now: u64,
    ) -> Result<Self, EvictionError> {
        if progress.state != EvictionCandidateStateV1::RemovedAwaitingReclaim
            || physically_reclaimed_allocated_bytes != progress.candidate.physical_bytes
        {
            return Err(EvictionError::ObservationMismatch);
        }
        let scope = eviction_effect_scope(
            plan,
            progress,
            reclamation_subject(progress, physically_reclaimed_allocated_bytes),
            capability.scope().generation(),
            capability.scope().valid_until(),
        )?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Reclamation,
            scope,
            now,
        )?;
        Ok(Self {
            plan_digest: plan.digest,
            backing: progress.candidate.backing,
            target_reservation: plan.target_reservation,
            reclaimable_bytes: physically_reclaimed_allocated_bytes,
            digest: capability.record_digest(),
            authority_scope: scope,
        })
    }

    pub(crate) fn validate_current(
        self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        plan: &FrozenEvictionPlanV1,
        progress: &EvictionProgressV1,
        now: u64,
    ) -> Result<(), EvictionError> {
        let scope = eviction_effect_scope(
            plan,
            progress,
            reclamation_subject(progress, self.reclaimable_bytes),
            self.authority_scope.generation(),
            self.authority_scope.valid_until(),
        )?;
        if scope != self.authority_scope || capability.record_digest() != self.digest {
            return Err(EvictionError::ObservationMismatch);
        }
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Reclamation,
            scope,
            now,
        )?;
        Ok(())
    }
}

/// Reports eviction planning, race, and evidence failures.
#[derive(Debug, thiserror::Error)]
pub enum EvictionError {
    /// Plan identifiers or bounds are malformed.
    #[error("cache eviction plan is invalid")]
    InvalidPlan,
    /// Candidate capacity exceeds the configured bound.
    #[error("cache eviction candidate limit exceeded")]
    CandidateLimit,
    /// Candidate bytes cannot reach the requested low-water target.
    #[error("cache eviction has insufficient candidates")]
    InsufficientCandidates,
    /// A candidate is duplicated in the frozen set.
    #[error("cache eviction candidate is duplicated")]
    DuplicateCandidate,
    /// The requested object is absent from the catalog.
    #[error("cache eviction object is absent")]
    UnknownObject,
    /// A candidate crosses partitions or is not committed.
    #[error("cache eviction candidate partition or state mismatches")]
    PartitionOrStateMismatch,
    /// A candidate has a correctness pin.
    #[error("cache eviction candidate is pinned")]
    Pinned,
    /// Checked candidate byte arithmetic overflowed.
    #[error("cache eviction byte arithmetic overflow")]
    Overflow,
    /// An object is not in the frozen candidate set.
    #[error("cache eviction candidate was not frozen")]
    CandidateNotFrozen,
    /// Catalog state changed after candidate selection.
    #[error("cache eviction candidate is stale")]
    StaleCandidate,
    /// The requested progress transition is illegal.
    #[error("cache eviction progress transition is invalid")]
    InvalidTransition,
    /// Physical evidence does not bind the exact current effect.
    #[error("cache eviction observation mismatches")]
    ObservationMismatch,
    /// Retry lacks fresh authority, old-attempt fencing, or exact observation.
    #[error("cache eviction retry authority is invalid")]
    InvalidRetryAuthority,
    /// Integrated admission/catalog state rejected the change.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// Catalog transition validation failed.
    #[error(transparent)]
    Catalog(#[from] super::catalog::CatalogError),
    /// Protected eviction capability verification failed.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityError),
    /// Eviction was not bound to an outstanding reserve-to-low-water gate.
    #[error("cache eviction watermark ordering is invalid")]
    InvalidWatermarkOrder,
}

fn eviction_plan_digest(plan: &FrozenEvictionPlanV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.eviction-plan.v1\0");
    hasher.update(plan.operation.as_bytes());
    hasher.update(plan.partition.digest().as_bytes());
    hasher.update(plan.catalog_generation.to_be_bytes());
    hasher.update(plan.authority_digest.as_bytes());
    hasher.update(plan.authority_scope.subject().as_bytes());
    hasher.update(plan.authority_scope.plan().as_bytes());
    hasher.update(plan.authority_scope.generation().to_be_bytes());
    hasher.update(plan.authority_scope.valid_until().to_be_bytes());
    hasher.update(
        plan.target_reservation
            .map_or([0; 16], |reservation| *reservation.as_bytes()),
    );
    hasher.update(plan.target_reclaim_bytes.to_be_bytes());
    hasher.update((plan.candidates.len() as u32).to_be_bytes());
    for candidate in &plan.candidates {
        let media = candidate.descriptor.media_type().as_str().as_bytes();
        hasher.update((media.len() as u16).to_be_bytes());
        hasher.update(media);
        hasher.update(candidate.descriptor.digest().as_bytes());
        hasher.update(candidate.descriptor.encoded_size().to_be_bytes());
        hasher.update(candidate.catalog_digest.as_bytes());
        hasher.update(candidate.backing.as_bytes());
        hasher.update(candidate.root_custody.as_bytes());
        hasher.update(candidate.canonical_name.as_bytes());
        hasher.update(candidate.physical_bytes.to_be_bytes());
        hasher.update([candidate.original_presence as u8]);
        hasher.update(candidate.last_use_generation.to_be_bytes());
        hasher.update(candidate.pressure_class.to_be_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn validate_frozen_candidates(candidates: &[EvictionCandidateV1]) -> Result<u64, EvictionError> {
    if candidates.is_empty() || candidates.len() > 65_536 {
        return Err(EvictionError::CandidateLimit);
    }
    let mut identities = BTreeSet::new();
    let mut previous_order = None;
    let mut planned_bytes = 0_u64;
    for candidate in candidates {
        let order = (
            candidate.pressure_class,
            candidate.last_use_generation,
            candidate.descriptor.clone(),
        );
        if validate_eviction_candidate(candidate).is_err()
            || !identities.insert(candidate.descriptor.clone())
            || previous_order
                .as_ref()
                .is_some_and(|previous| previous >= &order)
        {
            return Err(EvictionError::InvalidPlan);
        }
        planned_bytes = planned_bytes
            .checked_add(candidate.physical_bytes)
            .ok_or(EvictionError::Overflow)?;
        previous_order = Some(order);
    }
    Ok(planned_bytes)
}

pub(crate) fn validate_eviction_candidate(
    candidate: &EvictionCandidateV1,
) -> Result<(), EvictionError> {
    if validate_object_descriptor(&candidate.descriptor).is_err()
        || candidate.catalog_digest.as_bytes() == &[0; 32]
        || candidate.root_custody.as_bytes() == &[0; 32]
        || candidate.canonical_name.as_bytes() == &[0; 32]
        || candidate.physical_bytes == 0
        || candidate.last_use_generation == 0
        || !matches!(
            candidate.original_presence,
            CatalogPresenceV1::Committed | CatalogPresenceV1::Quarantined
        )
    {
        return Err(EvictionError::InvalidPlan);
    }
    Ok(())
}

fn compare_candidates(
    left: &EvictionCandidateV1,
    right: &EvictionCandidateV1,
) -> std::cmp::Ordering {
    left.pressure_class
        .cmp(&right.pressure_class)
        .then_with(|| left.last_use_generation.cmp(&right.last_use_generation))
        .then_with(|| left.descriptor.cmp(&right.descriptor))
}

fn eviction_candidate_binding(
    operation: OperationId,
    partition: PhysicalPartitionId,
    catalog_generation: u64,
    target_reservation: Option<CacheReservationId>,
    target_reclaim_bytes: u64,
    candidates: &[EvictionCandidateV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.eviction-candidate-binding.v1\0");
    hasher.update(operation.as_bytes());
    hasher.update(partition.digest().as_bytes());
    hasher.update(catalog_generation.to_be_bytes());
    hasher.update(target_reservation.map_or([0; 16], |reservation| *reservation.as_bytes()));
    hasher.update(target_reclaim_bytes.to_be_bytes());
    hasher.update((candidates.len() as u32).to_be_bytes());
    for candidate in candidates {
        hasher.update(object_descriptor_commitment(&candidate.descriptor).as_bytes());
        hasher.update(candidate.catalog_digest.as_bytes());
        hasher.update(candidate.backing.as_bytes());
        hasher.update(candidate.physical_bytes.to_be_bytes());
        hasher.update([candidate.original_presence as u8]);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn eviction_effect_scope(
    plan: &FrozenEvictionPlanV1,
    progress: &EvictionProgressV1,
    subject: ObjectDigest,
    generation: u64,
    valid_until: u64,
) -> Result<CacheAuthorityScopeV1, EvictionError> {
    if progress.plan_digest != plan.digest {
        return Err(EvictionError::InvalidPlan);
    }
    Ok(CacheAuthorityScopeV1::new(
        plan.partition,
        subject,
        Some(plan.operation),
        plan.digest,
        progress.candidate.root_custody,
        generation,
        valid_until,
    )?)
}

fn retry_subject(
    progress: &EvictionProgressV1,
    old_attempt_fence: ObjectDigest,
    observation: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.eviction-retry-subject.v1\0");
    hasher.update(object_descriptor_commitment(&progress.candidate.descriptor).as_bytes());
    hasher.update(progress.current_catalog_digest.as_bytes());
    hasher.update(old_attempt_fence.as_bytes());
    hasher.update(observation.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn unlink_subject(progress: &EvictionProgressV1, outcome: UnlinkOutcomeV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.unlink-observation-subject.v1\0");
    hasher.update(object_descriptor_commitment(&progress.candidate.descriptor).as_bytes());
    hasher.update(progress.current_catalog_digest.as_bytes());
    hasher.update(progress.candidate.backing.as_bytes());
    hasher.update([outcome as u8]);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn reclamation_subject(progress: &EvictionProgressV1, bytes: u64) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.reclamation-observation-subject.v1\0");
    hasher.update(object_descriptor_commitment(&progress.candidate.descriptor).as_bytes());
    hasher.update(progress.current_catalog_digest.as_bytes());
    hasher.update(progress.candidate.backing.as_bytes());
    hasher.update(bytes.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn retry_authority_digest(authority: &EvictionRetryAuthorityV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.eviction-retry-authority.v1\0");
    hasher.update(authority.plan_digest.as_bytes());
    hasher.update(authority.deleting_catalog_digest.as_bytes());
    hasher.update(authority.current_authority.as_bytes());
    hasher.update(authority.old_attempt_fence.as_bytes());
    hasher.update(authority.observation.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
