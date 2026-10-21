//! Retains the original verified Cache selection through the new Held lane.
//!
//! The surrounding Cache loan keeps the real State/Hold/clock/physical owners.
//! This owner stores only the existing Replay verification/selection, offers
//! no effect method and is never reconstructed by decoding historical bytes.

use super::*;
use crate::protected_owner::CurrentProjectPhysicalCacheHeadV1;
use aos_sandbox_protocol::cache_state::NodeCacheQuotaV1;

pub(crate) struct CacheHeldSelectionV1 {
    snapshot: ProtectedJournalSnapshot,
    state_next: u64,
    partitions: CacheReplayPartitionEvidenceMapV1,
    view: VerifiedCacheAuthorityViewV1,
    selected: CurrentProjectPhysicalCacheHeadV1,
    quota: ObjectDigest,
    node_quotas: Vec<NodeCacheQuotaV1>,
}

impl CacheHeldSelectionV1 {
    // verify_replay retains one collected effect-observation map. A second
    // encoded lane covers its current canonical observation validation while
    // that complete map remains live. Other authority rows are not cloned by
    // this consumer; Native whole-row audits are separately priced.
    pub(crate) fn observation_receiving_demand_v1(
        journal: &Journal,
    ) -> Result<aos_sandbox_model::ResourceVector, crate::RecoveryError> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use crate::RecoveryError;

        let mut bytes = 0_usize;
        let mut rows = 0_usize;
        for (key, value) in journal.records(RecordNamespace::DesiredState) {
            if key.starts_with(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX) {
                bytes = bytes.checked_add(key.len()).and_then(|bytes| bytes.checked_add(value.len()))
                    .ok_or(RecoveryError::Capacity)?;
                rows = rows.checked_add(1).ok_or(RecoveryError::Capacity)?;
            }
        }
        let slots = if rows == 0 { 0 } else {
            rows.checked_mul(3).and_then(|rows| rows.checked_add(11)).ok_or(RecoveryError::Capacity)?
        };
        let carriers = slots.checked_mul(std::mem::size_of::<(Vec<u8>, Vec<u8>, [usize; 6])>())
            .ok_or(RecoveryError::Capacity)?;
        let memory = bytes.checked_mul(2).and_then(|bytes| bytes.checked_add(carriers))
            .ok_or(RecoveryError::Capacity)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| RecoveryError::Capacity)?)
            .with(D::MetadataEntries, u64::try_from(slots).map_err(|_| RecoveryError::Capacity)?))
    }

    pub(crate) fn selected(&self) -> CurrentProjectPhysicalCacheHeadV1 {
        self.selected
    }

    pub(crate) fn quota(&self) -> ObjectDigest { self.quota }

    /// Borrows the complete quota rows retained by the original selection.
    pub(crate) fn node_quotas(&self) -> &[NodeCacheQuotaV1] {
        &self.node_quotas
    }

    pub(crate) fn require_physical_limits(
        &self,
        limits: crate::CacheOwnerLimitsV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if !limits.matches_node_quotas(&self.node_quotas) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

impl ProtectedCacheResidencyReplayAuthorityV1 {
    // This fixed observational consumer shares verify_replay, protected replay,
    // reconstruct_cache_history and the existing unique selection recipe. The
    // genuine J supplier admits the same actual rows before calling it.
    pub(crate) fn capture_create_storage_selection_v1(
        &self,
        state: &mut Journal,
        original: &mut crate::CacheHeldSelectionOriginalV1<'_>,
        clock: &CacheClockWriterReadbackGuard<'_>,
        project: ProjectId,
    ) -> Result<CacheHeldSelectionV1, CacheResidencyProtectedJournalErrorV1> {
        clock.require_create_storage_time_authority_v1(&self.current_time)?;
        let mut journal = self.journal.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        clock.require_create_storage_targets_v1(state, &journal)?;
        // The genuine Cache continuation already completed all five paid
        // whole Native audits under its held writers. Rejoin that original
        // directly; the legacy borrowed gate performs additional unretained
        // native opens and is not this selected lane's custody adapter.
        original.require_targets(state, &journal)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let authority = journal.claim_cache_authority_v1()?;
        let snapshot = authority.snapshot()?;
        let partitions = self.partitions.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?.clone();
        let owner = CacheAuthorityOwner::new(&authority, self.owner_scope, self.maximum_record_bytes)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let view = verify_replay(&authority, &owner, self.owner_scope, self.limits,
            &partitions, Vec::new(), clock.create_storage_unix_seconds_v1()?)?;
        drop(owner);
        authority.validate_snapshot_for_effect(&snapshot)?;
        let projection = CacheResidencyProtectedJournalV1::claim(state, view.validator.clone())?.replay()?;
        let inventories = reconstruct_cache_history(projection.records(), &view.validator)?;
        let selection = crate::protected_owner::current_inventory_selection(
            project, &inventories,
        );
        // These successful temporary inventories and their projection are
        // actually disposed before retaining only the existing selected view.
        drop(inventories);
        drop(projection);
        let (selected, quota, node_quotas) = selection?;
        Ok(CacheHeldSelectionV1 {
            snapshot, state_next: state.snapshot_sequence(), partitions, view,
            selected, quota, node_quotas,
        })
    }

    // This read-only bookend intentionally does not ask an ordinary mutation
    // gate to admit the new persistent Held row. The actual surrounding loan
    // separately proves that exact HOLD pair/suffix and all original names.
    pub(crate) fn recheck_create_storage_selection_v1(
        &self,
        state: &Journal,
        clock: &CacheClockWriterReadbackGuard<'_>,
        selection: &CacheHeldSelectionV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        clock.require_create_storage_time_authority_v1(&self.current_time)?;
        let mut journal = self.journal.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        clock.require_create_storage_targets_v1(state, &journal)?;
        let authority = journal.claim_cache_authority_v1()?;
        authority.validate_snapshot_for_effect(&selection.snapshot)?;
        if state.snapshot_sequence() != selection.state_next {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        let partitions = self.partitions.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if *partitions != selection.partitions {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        drop(partitions);
        let owner = CacheAuthorityOwner::new(&authority, self.owner_scope, self.maximum_record_bytes)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        validate_current(&owner, &[], &selection.view, clock.create_storage_unix_seconds_v1()?)?;
        authority.validate_snapshot_for_effect(&selection.snapshot)?;
        clock.require_create_storage_targets_v1(state, &journal)?;
        clock.require_create_storage_hold_v1()
    }
}
