//! Canonical historical frozen-candidate and eviction-progress DATA.
//!
//! Candidate commitments and reconstructed progress supply historical facts.
//! They do not issue Native frozen-plan/progress wrappers, current capability,
//! unlink admission, retry authority or physical reclamation evidence.

use std::collections::BTreeSet;
use aos_sandbox_model::{ObjectDescriptor, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};
use super::{BackingObjectIdentityV1, CacheReservationId, CatalogPresenceV1, PhysicalPartitionId,
    hash_descriptor_fields_u16_v1, object_descriptor_commitment, validate_object_descriptor};
use super::authority_record::{CacheAuthorityScopeV1, CacheAuthorityRecordDataErrorV1};

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
pub struct FrozenEvictionPlanDataV1 {
    /// Idempotent eviction operation.
    pub operation: OperationId,
    /// Historical physical partition selected by this plan.
    pub partition: PhysicalPartitionId,
    /// Catalog generation observed before selection.
    pub catalog_generation: u64,
    /// Historical authority-record commitment; no current permission.
    pub authority_digest: ObjectDigest,
    /// Historical eviction scope; no current permission.
    pub authority_scope: CacheAuthorityScopeV1,
    /// Reservation whose reserve-to-low-water gate this plan satisfies.
    pub target_reservation: Option<CacheReservationId>,
    /// Low-water byte target for the transaction.
    pub target_reclaim_bytes: u64,
    /// Ordered exact candidate set.
    pub candidates: Vec<EvictionCandidateV1>,
    /// Digest of the complete frozen plan.
    pub digest: ObjectDigest,
}

impl FrozenEvictionPlanDataV1 {
    /// Returns the exact historical eviction-scope and record commitments.
    #[must_use]
    pub const fn authority_binding(&self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.authority_digest)
    }

    /// Reconstructs exact historical eviction DATA without issuing Native authority.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionDataErrorV1`] for invalid historical bindings or bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_historical(
        operation: OperationId,
        partition: PhysicalPartitionId,
        catalog_generation: u64,
        authority_digest: ObjectDigest,
        target_reservation: Option<CacheReservationId>,
        target_reclaim_bytes: u64,
        candidates: Vec<EvictionCandidateV1>,
        valid_until: u64,
    ) -> Result<Self, EvictionDataErrorV1> {
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
            return Err(EvictionDataErrorV1::InvalidPlan);
        }
        Ok(plan)
    }

    /// Tests exact membership in the historical ordered candidate set.
    pub fn contains_candidate(&self, candidate: &EvictionCandidateV1) -> bool {
        self.candidates
            .binary_search_by(|retained| compare_candidates(retained, candidate))
            .ok()
            .and_then(|index| self.candidates.get(index))
            .is_some_and(|retained| retained == candidate)
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
pub struct EvictionProgressDataV1 {
    /// Frozen operation digest.
    pub plan_digest: ObjectDigest,
    /// Exact candidate.
    pub candidate: EvictionCandidateV1,
    /// Current closed state.
    pub state: EvictionCandidateStateV1,
    /// Latest catalog digest after a rename/restore/quarantine.
    pub current_catalog_digest: ObjectDigest,
    /// Opaque digest of the latest trusted observation.
    pub evidence: Option<ObjectDigest>,
    /// Historically observed reclaimable bytes, zero before terminal reclamation.
    pub reclaimed_bytes: u64,
}

impl EvictionProgressDataV1 {
    /// Reconstructs exact historical eviction DATA without issuing Native authority.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionDataErrorV1`] for invalid historical bindings or bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_historical(
        plan: &FrozenEvictionPlanDataV1,
        candidate: EvictionCandidateV1,
        state: EvictionCandidateStateV1,
        current_catalog_digest: ObjectDigest,
        evidence: Option<ObjectDigest>,
        reclaimed_bytes: u64,
    ) -> Result<Self, EvictionDataErrorV1> {
        if !plan.contains_candidate(&candidate) || current_catalog_digest.as_bytes() == &[0; 32] {
            return Err(EvictionDataErrorV1::InvalidTransition);
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
            return Err(EvictionDataErrorV1::InvalidTransition);
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

    /// Reconstructs exact historical eviction DATA without issuing Native authority.
    ///
    /// # Errors
    ///
    /// Returns [`EvictionDataErrorV1`] for invalid historical bindings or bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn selected(
        plan: &FrozenEvictionPlanDataV1,
        descriptor: &ObjectDescriptor,
    ) -> Result<Self, EvictionDataErrorV1> {
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| &candidate.descriptor == descriptor)
            .ok_or(EvictionDataErrorV1::CandidateNotFrozen)?
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
}

/// Reports malformed historical eviction models and commitments.
#[derive(Debug, thiserror::Error)]
pub enum EvictionDataErrorV1 {
    /// Frozen plan bindings or candidate commitments are invalid.
    #[error("cache eviction plan is invalid")]
    InvalidPlan,
    /// Historical candidate cardinality exceeds the hard bound.
    #[error("cache eviction candidate limit exceeded")]
    CandidateLimit,
    /// Checked candidate byte arithmetic overflows.
    #[error("cache eviction byte arithmetic overflow")]
    Overflow,
    /// Historical candidate progress contradicts its frozen plan.
    #[error("cache eviction progress transition is invalid")]
    InvalidTransition,
    /// The requested object is absent from the historical frozen set.
    #[error("cache eviction candidate was not frozen")]
    CandidateNotFrozen,
    /// Historical authority-scope coordinates are invalid.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityRecordDataErrorV1),
}

/// Computes or validates the exact historical eviction plan digest.
#[doc(hidden)]
pub fn eviction_plan_digest(plan: &FrozenEvictionPlanDataV1) -> ObjectDigest {
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
        hash_descriptor_fields_u16_v1(&mut hasher, &candidate.descriptor);
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

/// Computes or validates the exact historical validate frozen candidates.
///
/// # Errors
///
/// Returns [`EvictionDataErrorV1`] for invalid candidates, bounds or arithmetic.
#[doc(hidden)]
pub fn validate_frozen_candidates(candidates: &[EvictionCandidateV1]) -> Result<u64, EvictionDataErrorV1> {
    if candidates.is_empty() || candidates.len() > 65_536 {
        return Err(EvictionDataErrorV1::CandidateLimit);
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
            return Err(EvictionDataErrorV1::InvalidPlan);
        }
        planned_bytes = planned_bytes
            .checked_add(candidate.physical_bytes)
            .ok_or(EvictionDataErrorV1::Overflow)?;
        previous_order = Some(order);
    }
    Ok(planned_bytes)
}

/// Computes or validates the exact historical validate eviction candidate.
///
/// # Errors
///
/// Returns [`EvictionDataErrorV1`] for invalid candidates, bounds or arithmetic.
#[doc(hidden)]
pub fn validate_eviction_candidate(
    candidate: &EvictionCandidateV1,
) -> Result<(), EvictionDataErrorV1> {
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
        return Err(EvictionDataErrorV1::InvalidPlan);
    }
    Ok(())
}

/// Computes or validates the exact historical compare candidates.
#[doc(hidden)]
pub fn compare_candidates(
    left: &EvictionCandidateV1,
    right: &EvictionCandidateV1,
) -> std::cmp::Ordering {
    left.pressure_class
        .cmp(&right.pressure_class)
        .then_with(|| left.last_use_generation.cmp(&right.last_use_generation))
        .then_with(|| left.descriptor.cmp(&right.descriptor))
}

/// Computes or validates the exact historical eviction candidate binding.
#[doc(hidden)]
pub fn eviction_candidate_binding(
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


#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{CacheDomainId, MediaType, model::{CacheDomain, CacheDomainKind}};
    use crate::cache_state::{CacheNodeIdV1, ProtectedBackingIdentityV1};

    fn candidate(identity: u8) -> EvictionCandidateV1 {
        EvictionCandidateV1 {
            descriptor: ObjectDescriptor::new(MediaType::new("application/octet-stream").unwrap(), ObjectDigest::from_bytes([identity; 32]), 1),
            catalog_digest: ObjectDigest::from_bytes([2; 32]),
            backing: BackingObjectIdentityV1::from_bytes([3; 32]).unwrap(),
            root_custody: ObjectDigest::from_bytes([4; 32]),
            canonical_name: ObjectDigest::from_bytes([5; 32]),
            physical_bytes: 4,
            original_presence: CatalogPresenceV1::Committed,
            last_use_generation: 1,
            pressure_class: 0,
        }
    }

    fn partition() -> PhysicalPartitionId {
        PhysicalPartitionId::derive(
            CacheNodeIdV1::from_bytes([1; 16]).unwrap(),
            ProtectedBackingIdentityV1::new(
                ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]), ObjectDigest::from_bytes([5; 32]),
            ).unwrap(),
            CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([6; 16])),
            ObjectDigest::from_bytes([7; 32]),
        ).unwrap()
    }

    #[test]
    fn frozen_candidates_reject_duplicates_reordering_and_byte_overflow() {
        let first = candidate(1);
        let second = candidate(2);
        assert_eq!(validate_frozen_candidates(&[first.clone(), second.clone()]).unwrap(), 8);
        assert!(matches!(validate_frozen_candidates(&[second.clone(), first.clone()]), Err(EvictionDataErrorV1::InvalidPlan)));
        assert!(matches!(validate_frozen_candidates(&[first.clone(), first.clone()]), Err(EvictionDataErrorV1::InvalidPlan)));

        let mut huge = first;
        huge.physical_bytes = u64::MAX;
        assert!(matches!(validate_frozen_candidates(&[huge, second]), Err(EvictionDataErrorV1::Overflow)));
    }

    #[test]
    fn historical_reclamation_requires_exact_frozen_candidate_evidence_and_bytes() {
        let candidate = candidate(1);
        let plan = FrozenEvictionPlanDataV1::recover_historical(
            OperationId::from_bytes([1; 16]), partition(), 1,
            ObjectDigest::from_bytes([2; 32]), None, 4, vec![candidate.clone()], 100,
        ).unwrap();
        let evidence = Some(ObjectDigest::from_bytes([3; 32]));
        let catalog = candidate.catalog_digest;

        assert!(EvictionProgressDataV1::recover_historical(&plan, candidate.clone(), EvictionCandidateStateV1::Reclaimed, catalog, evidence, 4).is_ok());
        assert!(matches!(EvictionProgressDataV1::recover_historical(&plan, candidate.clone(), EvictionCandidateStateV1::Reclaimed, catalog, None, 4), Err(EvictionDataErrorV1::InvalidTransition)));
        assert!(matches!(EvictionProgressDataV1::recover_historical(&plan, candidate.clone(), EvictionCandidateStateV1::Reclaimed, catalog, evidence, 3), Err(EvictionDataErrorV1::InvalidTransition)));
        assert!(matches!(EvictionProgressDataV1::recover_historical(&plan, candidate, EvictionCandidateStateV1::Deleting, catalog, None, 4), Err(EvictionDataErrorV1::InvalidTransition)));
    }
}
