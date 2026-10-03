//! Durable Mount settlement of a Provider-terminal native no-dispatch Acquire.

use aos_sandbox::journal::ProtectedJournalAuthority;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    MutationTagV2, native_recovery_settlement_digest_v2, validate_mount_source_state_graph_v2,
    validate_native_no_dispatch_absent_resolution_v2,
};
use aos_sandbox_source_provider_protocol::RecoveryCurrentnessQueryV1;
use aos_sandbox_source_provider_security::AuthenticatedRootMountNativeRecoveryUnavailableV1;

use super::SourceAcquisitionTableV2;
use super::format::state_error;
use super::model::{
    AcquisitionRecoveryV2, ProviderAttemptStateV2, ProviderMethodV2, ProviderQueryOwnerV2,
    RecordRefV2, RecoveryResolutionV2, SourceAcquisitionPhaseV2, StoredRecordV2,
};
use super::reservation::{sealed_attempt, sealed_head, sealed_row};
use super::transition::{MutationIdentityV2, next_revision, prepare_mutation};
use crate::Result;

impl SourceAcquisitionTableV2 {
    /// Settles one dead native Acquire only after Provider's signed terminal cut.
    ///
    /// The signed proof is move-only, the current protected graph must match
    /// this table exactly, and the three-record Mount replacement is atomic.
    /// An ambiguous journal commit stays fail-closed until cold replay.
    ///
    /// # Errors
    ///
    /// Rejects a changed attempt, another acquisition or signer session,
    /// unresolved Provider recovery shape, stale journal, or commit failure.
    #[doc(hidden)]
    pub fn settle_native_no_dispatch_recovery_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        acquisition_id: ObjectDigest,
        proof: AuthenticatedRootMountNativeRecoveryUnavailableV1,
    ) -> Result<()> {
        let current =
            validate_mount_source_state_graph_v2(journal.mount_source_acquisition_records()?)?;
        if current.acquisitions != self.acquisitions
            || current.provider_heads != self.provider_heads
            || current.provider_sessions != self.provider_sessions
            || current.provider_attempts != self.provider_attempts
            || current.holder_sequences != self.holder_sequences
        {
            return Err(state_error(
                "Mount native recovery table differs from protected journal",
            ));
        }

        let (canonical_query, signed_settlement) = proof.into_protected_records();
        let query = RecoveryCurrentnessQueryV1::from_canonical_bytes(&canonical_query)
            .map_err(|_| state_error("native recovery query is malformed"))?;
        let row = self
            .acquisitions
            .get(acquisition_id.as_bytes())
            .filter(|row| {
                row.phase == SourceAcquisitionPhaseV2::PendingQuery
                    && row.acquisition_id == *acquisition_id.as_bytes()
                    && row.acquire_lineage.root == row.acquire_lineage.tail
                    && row.acquire_terminal_attempt.is_none()
                    && row.evidence.is_none()
            })
            .ok_or_else(|| state_error("native recovery acquisition is no longer pending"))?;
        let old_attempt = self
            .provider_attempts
            .get(&row.acquire_lineage.root.id)
            .filter(|attempt| {
                attempt.record_digest == row.acquire_lineage.root.record_digest
                    && attempt.revision == row.acquire_lineage.root.revision
                    && attempt.method == ProviderMethodV2::Acquire
                    && attempt.owner
                        == ProviderQueryOwnerV2::Acquire {
                            acquisition_id: row.acquisition_id,
                        }
                    && attempt.previous_attempt_id.is_none()
                    && matches!(
                        attempt.state,
                        ProviderAttemptStateV2::AbandonedIndeterminate {
                            resolution: None,
                            ..
                        } | ProviderAttemptStateV2::AbandonedIndeterminate {
                            resolution: Some(RecoveryResolutionV2::RetryAcquireSameIntent { .. }),
                            ..
                        } | ProviderAttemptStateV2::SupersededIndeterminate { .. }
                    )
            })
            .ok_or_else(|| state_error("native recovery attempt is not indeterminate"))?;
        let head = self
            .provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .filter(|head| {
                head.pending_attempt.is_none()
                    && head.next_request_sequence == head.next_response_sequence
            })
            .ok_or_else(|| state_error("native recovery head is no longer idle"))?;
        let current_session = self
            .provider_sessions
            .get(&head.current_session_id)
            .ok_or_else(|| state_error("native recovery current session is missing"))?;
        let predecessor_matches = match &old_attempt.state {
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: None, ..
            } => {
                matches!(
                    row.recovery,
                    AcquisitionRecoveryV2::InventoryRequired { root_attempt }
                        if root_attempt == row.acquire_lineage.root
                ) && head.recovery_barrier.as_ref().is_some_and(|barrier| {
                    barrier.root_attempt == row.acquire_lineage.root
                        && barrier.required_session_id == head.current_session_id
                })
            }
            ProviderAttemptStateV2::SupersededIndeterminate { .. } => {
                matches!(row.recovery, AcquisitionRecoveryV2::Ready)
                    && head.recovery_barrier.is_none()
            }
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: Some(RecoveryResolutionV2::RetryAcquireSameIntent { .. }),
                ..
            } => {
                // Inventory absence alone never settles the old flight. This
                // branch also consumes the existing authenticated dedicated
                // no-dispatch proof and retains the complete exact prior3.
                validate_native_no_dispatch_absent_resolution_v2(old_attempt, &current)?;
                matches!(
                    row.recovery,
                    AcquisitionRecoveryV2::RetryPermitted { root_attempt }
                        if root_attempt == row.acquire_lineage.root
                ) && head.recovery_barrier.is_none()
            }
            _ => false,
        };
        if !predecessor_matches
            || query.session_binding().as_bytes() != &current_session.session_binding
            || query.acquisition_id() != acquisition_id
            || query.original_signed_request_digest().as_bytes()
                != &old_attempt.signed_request_digest
            || query.original_attempt_digest().as_bytes() != &old_attempt.record_digest
        {
            return Err(state_error(
                "native recovery query is not the protected old attempt",
            ));
        }

        let mut next_attempt = old_attempt.clone();
        next_attempt.revision = next_revision(old_attempt.revision)?;
        next_attempt.state = ProviderAttemptStateV2::NativeNoDispatchSettled {
            prior_state: Box::new(old_attempt.state.clone()),
            canonical_query,
            signed_settlement: signed_settlement.clone(),
            settlement_session_id: head.current_session_id,
        };
        next_attempt.record_digest = [0; 32];
        let next_attempt = sealed_attempt(next_attempt)?;
        let terminal = RecordRefV2 {
            id: next_attempt.attempt_id,
            revision: next_attempt.revision,
            record_digest: next_attempt.record_digest,
        };

        let mut next_row = row.clone();
        next_row.revision = next_revision(row.revision)?;
        next_row.phase = SourceAcquisitionPhaseV2::Faulted;
        next_row.faulted_from = Some(SourceAcquisitionPhaseV2::PendingQuery);
        next_row.fault_digest = Some(native_recovery_settlement_digest_v2(&signed_settlement));
        next_row.recovery = AcquisitionRecoveryV2::Ready;
        next_row.acquire_lineage.root = terminal;
        next_row.acquire_lineage.tail = terminal;
        next_row.record_digest = [0; 32];
        let next_row = sealed_row(next_row)?;

        let mut next_head = head.clone();
        next_head.revision = next_revision(head.revision)?;
        next_head.recovery_barrier = None;
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        let (transaction, tentative) = prepare_mutation(
            self,
            MutationIdentityV2 {
                tag: MutationTagV2::NativeNoDispatchSettlement,
                holder_id: row.scope.holder_authority_id,
                provider_id: row.scope.provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&row.scope.holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: Some(row.acquisition_id),
                next_row_revision: Some(next_row.revision),
                attempt_id: Some(next_attempt.attempt_id),
                next_attempt_revision: Some(next_attempt.revision),
                session_id: None,
            },
            vec![
                StoredRecordV2::ProviderQueryAttempt {
                    value: next_attempt,
                },
                StoredRecordV2::Acquisition { value: next_row },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )?;
        let preflight = journal.preflight_transactions(core::slice::from_ref(&transaction))?;
        journal.validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))?;
        journal.commit(&transaction)?;

        let committed =
            validate_mount_source_state_graph_v2(journal.mount_source_acquisition_records()?)?;
        if committed.acquisitions != tentative.acquisitions
            || committed.provider_heads != tentative.provider_heads
            || committed.provider_attempts != tentative.provider_attempts
            || committed.provider_sessions != tentative.provider_sessions
            || committed.holder_sequences != tentative.holder_sequences
        {
            return Err(state_error(
                "native recovery settlement lacks exact protected readback",
            ));
        }
        *self = tentative;
        Ok(())
    }
}
