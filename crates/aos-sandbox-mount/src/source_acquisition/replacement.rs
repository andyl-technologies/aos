//! Authenticated idle SourceProvider session replacement for AOSMSA02.
//!
//! Replacement preserves stable scope, Inventory floor, observation ordinal,
//! projection, and holder-wide acquisition sequence. Only session-scoped
//! request/response heads reset to one, and cached reconciliation is invalidated.

use aos_sandbox::journal::ProtectedJournalAuthority;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_security::{
    CurrentRootMountSourceProviderSessionV1, DeadProviderExecutionV1, ProviderExecutionDeathKindV2,
};

use super::SourceAcquisitionTableV2;
use super::format::{
    MutationTagV2, death_digest, provider_head_key, provider_session_key, put_record, state_error,
};
use super::model::*;
use super::reservation::{sealed_attempt, sealed_head, sealed_row};
use super::security::session_from_projection;
use super::transition::{MutationIdentityV2, commit_mutation, next_revision, record_ref};
use crate::Result;

impl SourceAcquisitionTableV2 {
    /// Replaces one idle provider session under fresh protected authentication.
    ///
    /// # Errors
    ///
    /// Returns an error for an outstanding attempt/recovery barrier, stale
    /// protected records, changed stable scope, generation rollback or
    /// equal-generation equivocation, reused session identity, or commit failure.
    #[doc(hidden)]
    pub(crate) fn replace_idle_provider_session_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
    ) -> Result<()> {
        let identity = (holder_authority_id, provider_authority_id);
        let current_head = self
            .provider_heads
            .get(&identity)
            .filter(|head| {
                head.pending_attempt.is_none()
                    && head.recovery_barrier.is_none()
                    && head.next_request_sequence == head.next_response_sequence
            })
            .cloned()
            .ok_or_else(|| state_error("provider session replacement requires an idle head"))?;
        let predecessor = self
            .provider_sessions
            .get(&current_head.current_session_id)
            .filter(|session| session.record_digest == current_head.current_session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("provider session replacement predecessor is absent"))?;
        let head_record = record_bytes(StoredRecordV2::ProviderHead {
            value: current_head.clone(),
        })?;
        let predecessor_record = record_bytes(StoredRecordV2::ProviderSession {
            value: predecessor.clone(),
        })?;
        let plan = live_successor
            .replacement_mount_provider_session_plan_v2(
                journal,
                journal.snapshot()?,
                provider_head_key(holder_authority_id, provider_authority_id),
                head_record,
                provider_session_key(predecessor.session_id),
                predecessor_record,
                ObjectDigest::from_bytes(predecessor.session_id),
                ObjectDigest::from_bytes(predecessor.session_binding),
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("protected provider replacement planning failed"))?;
        let successor = session_from_projection(plan.session(), Some(predecessor.session_id))?;
        if successor.scope != predecessor.scope
            || successor.session_id == predecessor.session_id
            || self.provider_sessions.contains_key(&successor.session_id)
            || !monotonic(
                predecessor.root_mount_authority_generation,
                predecessor.root_mount_authority_digest,
                successor.root_mount_authority_generation,
                successor.root_mount_authority_digest,
            )
            || !monotonic(
                predecessor.provider_authority_generation,
                predecessor.provider_authority_digest,
                successor.provider_authority_generation,
                successor.provider_authority_digest,
            )
            || !monotonic(
                predecessor.route_generation,
                predecessor.route_digest,
                successor.route_generation,
                successor.route_digest,
            )
            || !monotonic(
                predecessor.trust_generation,
                predecessor.trust_digest,
                successor.trust_generation,
                successor.trust_digest,
            )
            || !monotonic(
                predecessor.revocation_generation,
                predecessor.revocation_digest,
                successor.revocation_generation,
                successor.revocation_digest,
            )
        {
            return Err(state_error(
                "provider successor session rolls back or equivocates protected history",
            ));
        }
        let mut next_head = current_head.clone();
        next_head.revision = next_revision(current_head.revision)?;
        next_head.holder_authority_generation = successor.root_mount_authority_generation;
        next_head.holder_authority_digest = successor.root_mount_authority_digest;
        next_head.provider_authority_generation = successor.provider_authority_generation;
        next_head.provider_authority_digest = successor.provider_authority_digest;
        next_head.current_session_id = successor.session_id;
        next_head.current_session_record_digest = successor.record_digest;
        next_head.next_request_sequence = 1;
        next_head.next_response_sequence = 1;
        next_head.last_reconciliation = None;
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::IdleReplacement,
                holder_id: holder_authority_id,
                provider_id: provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: None,
                next_row_revision: None,
                attempt_id: None,
                next_attempt_revision: None,
                session_id: Some(successor.session_id),
            },
            vec![
                StoredRecordV2::ProviderSession { value: successor },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )
    }

    /// Suspends one indeterminate request and installs a proven successor session.
    ///
    /// The move-only death proof is consumed by the protected session planner.
    /// The same transaction abandons the exact Reserved attempt, installs the
    /// immutable successor session, creates or advances the recovery barrier,
    /// and marks an acquisition owner as requiring recovery Inventory.
    ///
    /// # Errors
    ///
    /// Returns an error unless the proof names the exact current provider
    /// execution and Reserved attempt, the successor monotonically extends the
    /// stable scope, and all replacement records validate and commit atomically.
    #[doc(hidden)]
    pub(crate) fn suspend_dead_attempt_and_replace_session_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        predecessor_death: DeadProviderExecutionV1,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
    ) -> Result<()> {
        let identity = (holder_authority_id, provider_authority_id);
        let current_head = self
            .provider_heads
            .get(&identity)
            .cloned()
            .ok_or_else(|| state_error("dead provider replacement head is absent"))?;
        let current_attempt_ref = current_head
            .pending_attempt
            .ok_or_else(|| state_error("dead provider replacement has no Reserved attempt"))?;
        let current_attempt = self
            .provider_attempts
            .get(&current_attempt_ref.id)
            .filter(|attempt| {
                attempt.revision == current_attempt_ref.revision
                    && attempt.record_digest == current_attempt_ref.record_digest
                    && attempt.session_id == current_head.current_session_id
                    && matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
            })
            .cloned()
            .ok_or_else(|| state_error("dead provider replacement attempt is not current"))?;
        let predecessor = self
            .provider_sessions
            .get(&current_head.current_session_id)
            .filter(|session| session.record_digest == current_head.current_session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("dead provider predecessor session is absent"))?;
        let head_record = record_bytes(StoredRecordV2::ProviderHead {
            value: current_head.clone(),
        })?;
        let predecessor_record = record_bytes(StoredRecordV2::ProviderSession {
            value: predecessor.clone(),
        })?;
        let protected_death = predecessor_death.into_durable_projection();
        let (old_boot_id, old_pid, old_start_time_ticks, old_process_instance) =
            protected_death.old_execution();
        let (observed_kernel_boot_id, _) = protected_death.observation();
        let protected_execution_digest = protected_death.process_execution_digest();
        if (
            old_boot_id,
            old_pid,
            old_start_time_ticks,
            old_process_instance,
        ) != (
            predecessor.kernel_boot_id,
            predecessor.provider_execution.pid,
            predecessor.provider_execution.start_time_ticks,
            predecessor.provider_process_instance,
        ) {
            return Err(state_error(
                "provider death projection differs from retained execution",
            ));
        }
        if protected_execution_digest.as_bytes()
            != &predecessor.provider_execution.process_execution_digest
        {
            return Err(state_error(
                "provider death projection changes the retained execution digest",
            ));
        }
        let proof_kind = match protected_death.kind() {
            ProviderExecutionDeathKindV2::PidfdExited => {
                DeadProviderExecutionProofKindV2::PidfdExited
            }
            ProviderExecutionDeathKindV2::BootReplaced => {
                DeadProviderExecutionProofKindV2::BootReplaced
            }
        };
        let mut durable_death = DeadProviderExecutionProjectionV2 {
            proof_kind,
            old_session_id: predecessor.session_id,
            old_session_record_digest: predecessor.record_digest,
            node_id: predecessor.node_id,
            old_kernel_boot_id: predecessor.kernel_boot_id,
            provider_process_instance: predecessor.provider_process_instance,
            process_execution_digest: *protected_execution_digest.as_bytes(),
            observed_kernel_boot_id,
            death_evidence_digest: [0; 32],
        };
        durable_death.death_evidence_digest = death_digest(&durable_death)?;
        let plan = live_successor
            .dead_replacement_mount_provider_session_plan_v2(
                journal,
                journal.snapshot()?,
                provider_head_key(holder_authority_id, provider_authority_id),
                head_record,
                provider_session_key(predecessor.session_id),
                predecessor_record,
                ObjectDigest::from_bytes(predecessor.session_id),
                ObjectDigest::from_bytes(predecessor.session_binding),
                protected_death,
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("protected dead-provider replacement planning failed"))?;
        let successor = session_from_projection(plan.session(), Some(predecessor.session_id))?;
        validate_successor(&predecessor, &successor, &self.provider_sessions)?;

        let existing_barrier = current_head.recovery_barrier.as_ref();
        let root_attempt_id = existing_barrier.map_or(current_attempt.attempt_id, |barrier| {
            barrier.root_attempt.id
        });
        if existing_barrier.is_some()
            && !matches!(
                &current_attempt.intent,
                ProviderIntentV2::Inventory { value }
                    if value.recovery_root_attempt_id == Some(root_attempt_id)
            )
        {
            return Err(state_error(
                "repeated provider death is not the required recovery Inventory",
            ));
        }
        let mut next_attempt = current_attempt.clone();
        next_attempt.revision = 2;
        next_attempt.state = ProviderAttemptStateV2::AbandonedIndeterminate {
            dead_execution: durable_death,
            successor_session_id: successor.session_id,
            recovery_root_attempt_id: root_attempt_id,
            outcome_may_exist: true,
            resolution: None,
        };
        next_attempt.record_digest = [0; 32];
        let next_attempt = sealed_attempt(next_attempt)?;
        let next_attempt_ref = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: next_attempt.clone(),
        })?;
        let root_ref = existing_barrier.map_or(next_attempt_ref, |barrier| barrier.root_attempt);

        let next_row = match current_attempt.owner {
            ProviderQueryOwnerV2::Acquire { acquisition_id }
            | ProviderQueryOwnerV2::Release { acquisition_id }
                if existing_barrier.is_none() =>
            {
                let current_row = self
                    .acquisitions
                    .get(&acquisition_id)
                    .cloned()
                    .ok_or_else(|| state_error("dead provider attempt owner row is absent"))?;
                let mut row = current_row.clone();
                row.revision = next_revision(current_row.revision)?;
                match current_attempt.method {
                    ProviderMethodV2::Acquire => row.acquire_lineage.tail = next_attempt_ref,
                    ProviderMethodV2::Release => {
                        row.release_lineage
                            .as_mut()
                            .ok_or_else(|| state_error("dead Release lineage is absent"))?
                            .tail = next_attempt_ref;
                    }
                    ProviderMethodV2::Inventory => {
                        return Err(state_error("Inventory attempt has an acquisition owner"));
                    }
                }
                row.recovery = AcquisitionRecoveryV2::InventoryRequired {
                    root_attempt: root_ref,
                };
                row.record_digest = [0; 32];
                Some(sealed_row(row)?)
            }
            ProviderQueryOwnerV2::Inventory => None,
            _ => {
                return Err(state_error(
                    "recovery barrier cannot replace another acquisition attempt",
                ));
            }
        };

        let mut next_head = current_head.clone();
        next_head.revision = next_revision(current_head.revision)?;
        next_head.holder_authority_generation = successor.root_mount_authority_generation;
        next_head.holder_authority_digest = successor.root_mount_authority_digest;
        next_head.provider_authority_generation = successor.provider_authority_generation;
        next_head.provider_authority_digest = successor.provider_authority_digest;
        next_head.current_session_id = successor.session_id;
        next_head.current_session_record_digest = successor.record_digest;
        next_head.next_request_sequence = 1;
        next_head.next_response_sequence = 1;
        next_head.pending_attempt = None;
        next_head.last_reconciliation = None;
        next_head.recovery_barrier = Some(RecoveryBarrierV2 {
            root_attempt: root_ref,
            baseline_inventory_ordinal: existing_barrier
                .map_or(current_head.inventory_observation_ordinal, |barrier| {
                    barrier.baseline_inventory_ordinal
                }),
            required_session_id: successor.session_id,
            recovery_inventory_tail: existing_barrier.map(|_| next_attempt_ref),
            replacement_count: existing_barrier.map_or(Ok(1), |barrier| {
                barrier
                    .replacement_count
                    .checked_add(1)
                    .ok_or_else(|| state_error("provider replacement count is exhausted"))
            })?,
        });
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        let acquisition_id = next_row.as_ref().map(|row| row.acquisition_id);
        let next_row_revision = next_row.as_ref().map(|row| row.revision);
        let mut records = vec![
            StoredRecordV2::ProviderQueryAttempt {
                value: next_attempt,
            },
            StoredRecordV2::ProviderSession { value: successor },
        ];
        if let Some(row) = next_row {
            records.push(StoredRecordV2::Acquisition { value: row });
        }
        records.push(StoredRecordV2::ProviderHead {
            value: next_head.clone(),
        });
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::DeadReplacement,
                holder_id: holder_authority_id,
                provider_id: provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id,
                next_row_revision,
                attempt_id: Some(next_attempt_ref.id),
                next_attempt_revision: Some(next_attempt_ref.revision),
                session_id: Some(next_head.current_session_id),
            },
            records,
        )
    }
}

fn record_bytes(record: StoredRecordV2) -> Result<Vec<u8>> {
    put_record(&record)?
        .value()
        .map(ToOwned::to_owned)
        .ok_or_else(|| state_error("AOSMSA02 record materialized as a delete"))
}

const fn monotonic(
    old_generation: u64,
    old_digest: [u8; 32],
    new_generation: u64,
    new_digest: [u8; 32],
) -> bool {
    new_generation > old_generation
        || (new_generation == old_generation && new_digest == old_digest)
}

fn validate_successor(
    predecessor: &SourceProviderSessionV2,
    successor: &SourceProviderSessionV2,
    sessions: &std::collections::BTreeMap<[u8; 32], SourceProviderSessionV2>,
) -> Result<()> {
    if successor.scope != predecessor.scope
        || successor.session_id == predecessor.session_id
        || sessions.contains_key(&successor.session_id)
        || !monotonic(
            predecessor.root_mount_authority_generation,
            predecessor.root_mount_authority_digest,
            successor.root_mount_authority_generation,
            successor.root_mount_authority_digest,
        )
        || !monotonic(
            predecessor.provider_authority_generation,
            predecessor.provider_authority_digest,
            successor.provider_authority_generation,
            successor.provider_authority_digest,
        )
        || !monotonic(
            predecessor.route_generation,
            predecessor.route_digest,
            successor.route_generation,
            successor.route_digest,
        )
        || !monotonic(
            predecessor.trust_generation,
            predecessor.trust_digest,
            successor.trust_generation,
            successor.trust_digest,
        )
        || !monotonic(
            predecessor.revocation_generation,
            predecessor.revocation_digest,
            successor.revocation_generation,
            successor.revocation_digest,
        )
    {
        return Err(state_error(
            "provider successor session rolls back or equivocates protected history",
        ));
    }
    Ok(())
}
