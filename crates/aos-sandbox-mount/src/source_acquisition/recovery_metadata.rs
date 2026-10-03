//! Pure replay-derived Mount recovery indexes.
//!
//! These four DATA outputs describe cold scheduling and retained replacement
//! stages only. Derivation borrows the table and cannot construct, reset or
//! authorize live runtime custody.

use super::{
    BackendRecoveryReplacementV2, ProviderAttemptStateV2, ProviderMethodV2, ProviderStatusV2,
    SourceAcquisitionPhaseV2, SourceAcquisitionTableV2, state_error,
};
use crate::Result;

/// Holds only table-derived recovery metadata, never retained capabilities.
pub(super) struct RecoveryMetadata {
    pub(super) cold_pending_attempts: Vec<[u8; 32]>,
    pub(super) cold_released_rows: Vec<[u8; 32]>,
    pub(super) pending_backend_recovery_replacement: Option<BackendRecoveryReplacementV2>,
    pub(super) pending_inventory_recovery_replacement:
        Option<([u8; 16], [u8; 16], Option<[u8; 32]>, [u8; 32])>,
}

impl RecoveryMetadata {
    /// Derives the existing cold ordering and unique replacement stages.
    ///
    /// # Errors
    ///
    /// Rejects multiple unresolved backend stages before checking for multiple
    /// unresolved Inventory stages, preserving cold-constructor error ordering.
    pub(super) fn derive(table: &SourceAcquisitionTableV2) -> Result<Self> {
        let mut cold_pending_attempts: Vec<_> = table
            .provider_attempts
            .values()
            .filter(|attempt| {
                matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                    || (matches!(
                        attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed { .. }
                    ) && table
                        .acquisitions
                        .get(&attempt.owner.owner_id())
                        .is_some_and(|row| {
                            let terminal_attempt_matches = match attempt.method {
                                ProviderMethodV2::Acquire => {
                                    row.acquire_lineage.tail.id == attempt.attempt_id
                                }
                                ProviderMethodV2::Release => row
                                    .release_lineage
                                    .as_ref()
                                    .is_some_and(|lineage| lineage.tail.id == attempt.attempt_id),
                                ProviderMethodV2::Inventory => false,
                            };
                            terminal_attempt_matches
                                && matches!(
                                    row.phase,
                                    SourceAcquisitionPhaseV2::PendingQuery
                                        | SourceAcquisitionPhaseV2::DescriptorCustodied
                                        | SourceAcquisitionPhaseV2::Active
                                        | SourceAcquisitionPhaseV2::Consumed
                                        | SourceAcquisitionPhaseV2::Releasing
                                        | SourceAcquisitionPhaseV2::Faulted
                                )
                        }))
            })
            .map(|attempt| attempt.attempt_id)
            .collect();
        // Restore the retained Acquire descriptor before resolving its Release.
        cold_pending_attempts.sort_by_key(|attempt_id| {
            table
                .provider_attempts
                .get(attempt_id)
                .map_or(3, |attempt| match (&attempt.method, &attempt.state) {
                    (ProviderMethodV2::Acquire, _) => 0,
                    (ProviderMethodV2::Release, ProviderAttemptStateV2::Reserved) => 1,
                    (
                        ProviderMethodV2::Release,
                        ProviderAttemptStateV2::DispositionConsumed {
                            status: ProviderStatusV2::Complete,
                            ..
                        },
                    ) => 2,
                    _ => 3,
                })
        });
        let cold_released_rows = table
            .acquisitions
            .values()
            .filter(|row| row.phase == SourceAcquisitionPhaseV2::Released)
            .map(|row| row.acquisition_id)
            .collect();
        let mut backend_recovery_replacements = table
            .provider_attempts
            .values()
            .filter_map(|attempt| {
                if !matches!(
                    attempt.state,
                    ProviderAttemptStateV2::SupersededIndeterminate { .. }
                ) {
                    return None;
                }
                let acquisition_id = attempt.owner.owner_id();
                let row = table.acquisitions.get(&acquisition_id)?;
                let tail = match attempt.method {
                    ProviderMethodV2::Acquire => Some(row.acquire_lineage.tail),
                    ProviderMethodV2::Release => {
                        row.release_lineage.as_ref().map(|lineage| lineage.tail)
                    }
                    ProviderMethodV2::Inventory => None,
                }?;
                (tail.id == attempt.attempt_id
                    && tail.revision == attempt.revision
                    && tail.record_digest == attempt.record_digest)
                    .then_some(BackendRecoveryReplacementV2 {
                        acquisition_id,
                        expected_revision: row.revision,
                        expected_digest: row.record_digest,
                        method: attempt.method,
                        predecessor_signed_request_digest: attempt.signed_request_digest,
                    })
            })
            .collect::<Vec<_>>();
        if backend_recovery_replacements.len() > 1 {
            return Err(state_error(
                "multiple backend recovery replacement stages are unresolved",
            ));
        }
        let pending_backend_recovery_replacement = backend_recovery_replacements.pop();
        let mut inventory_replacements = table
            .provider_heads
            .values()
            .filter_map(|head| {
                if head.pending_attempt.is_some() {
                    return None;
                }
                let tail = head
                    .recovery_barrier
                    .as_ref()
                    .and_then(|barrier| barrier.recovery_inventory_tail)
                    .or(head.last_inventory_attempt)?;
                let attempt = table.provider_attempts.get(&tail.id).filter(|attempt| {
                    attempt.revision == tail.revision
                        && attempt.record_digest == tail.record_digest
                        && attempt.method == ProviderMethodV2::Inventory
                        && matches!(
                            attempt.state,
                            ProviderAttemptStateV2::SupersededIndeterminate { .. }
                        )
                })?;
                Some((
                    head.scope.holder_authority_id,
                    head.scope.provider_authority_id,
                    head.recovery_barrier
                        .as_ref()
                        .map(|barrier| barrier.root_attempt.id),
                    attempt.signed_request_digest,
                ))
            })
            .collect::<Vec<_>>();
        if inventory_replacements.len() > 1 {
            return Err(state_error(
                "multiple Inventory recovery replacement stages are unresolved",
            ));
        }
        let pending_inventory_recovery_replacement = inventory_replacements.pop();
        Ok(Self {
            cold_pending_attempts,
            cold_released_rows,
            pending_backend_recovery_replacement,
            pending_inventory_recovery_replacement,
        })
    }
}
