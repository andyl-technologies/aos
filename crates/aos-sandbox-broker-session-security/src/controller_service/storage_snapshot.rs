//! Controller custody for the grouped Storage snapshot effect.
//!
//! The source reservation precedes the first Storage Apply. Process-local
//! custody retains the predecessor and exact session exchange across retries;
//! protected source custody prevents a replacement dispatch after restart.

use aos_sandbox::lifecycle::{
    LifecycleAtomicDatasetSnapshotPlanV1, LifecycleAtomicSnapshotSourceAdmissionV1,
    LifecycleAtomicSnapshotSourceCompletionV1, LifecycleAtomicSnapshotSourceRecoveryV1,
    LifecycleAtomicSnapshotSourceStoreV1, LifecycleAuthenticatedStorageInventoryV1,
    LifecycleEffectDomainV1, LifecycleEffectObservationV1, LifecycleMethodV1,
    LifecycleProtectedRecordKindV1, LifecycleSnapshotBarrierV1, LiveRuntimeFenceV1,
    lifecycle_protected_key_v1,
};
use aos_sandbox::{EffectFailure, Journal, PreparedAuthorityEffectV1};
use aos_sandbox_core::{ObjectDigest, OperationId};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};

use super::{
    ProductionEffectExecutor, current_lifecycle_time, lifecycle_plan_resource_id,
    lifecycle_progress_transaction_id, missing_broker_session, production_authority_effect_timing,
};
use crate::recovery::ProtectedPriorAtomicStorageHistoryV1;
use crate::{
    DormantAtomicStorageInventoryCompletionV1, DormantAtomicStorageInventoryFinishProgressV1,
    DormantAtomicStorageInventoryFinishRecoveryV1, DormantAtomicStorageInventoryPredecessorV1,
};

/// Retains the exact signed predecessor and request until source progress commits.
pub(super) struct PendingAtomicSnapshotV1 {
    operation: OperationId,
    operation_record: ObjectDigest,
    plan: LifecycleAtomicDatasetSnapshotPlanV1,
    fence: LiveRuntimeFenceV1,
    authority: PreparedAuthorityEffectV1,
    predecessor_inventory: LifecycleAuthenticatedStorageInventoryV1,
    predecessor_outcome: AuthenticatedBrokerMethodOutcomeV1,
    phase: AtomicSnapshotPhaseV1,
}

enum AtomicSnapshotPhaseV1 {
    Group(DormantAtomicStorageInventoryPredecessorV1),
    Finish(DormantAtomicStorageInventoryFinishRecoveryV1),
    Complete(DormantAtomicStorageInventoryCompletionV1),
    Progress(LifecycleEffectObservationV1),
    Rejected,
}

impl ProductionEffectExecutor {
    pub(super) fn advance_storage_lifecycle_effect(
        &mut self,
        operation_id: OperationId,
        journal: &mut Journal,
    ) -> Result<bool, EffectFailure> {
        let (operation_key, operation_record, observation) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(permanent)?;
            let (operation_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(permanent)?
                .ok_or_else(|| permanent("lifecycle operation is absent"))?;
            if !matches!(
                current.operation().phase(),
                aos_sandbox::lifecycle::LifecyclePhaseV1::Preparing
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Completing
            ) {
                return Ok(false);
            }
            let method = current.operation().intent().method();
            if !matches!(
                method,
                LifecycleMethodV1::Snapshot | LifecycleMethodV1::Hibernate
            ) {
                return Ok(false);
            }

            let project = current.operation().project();
            let coordination_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                lifecycle_plan_resource_id(operation_id, b"coordination-lineage"),
                operation_id,
            )
            .map_err(permanent)?;
            let coordination = owner
                .current_coordination(&coordination_key)
                .map_err(permanent)?
                .ok_or_else(|| permanent("snapshot coordination is absent"))?;
            let fence = coordination.coordination().transaction().live_fence();
            let barrier =
                LifecycleSnapshotBarrierV1::from_current_transaction(&current, &coordination)
                    .map_err(permanent)?;
            let effect = barrier.next_effect(&current).map_err(permanent)?;
            if effect.domain() != LifecycleEffectDomainV1::Storage {
                return Ok(false);
            }

            let boot_inventory_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage"),
                operation_id,
            )
            .map_err(permanent)?;
            let challenge = owner
                .begin_boot_inventory_bootstrap(&operation_key, &boot_inventory_key)
                .map_err(permanent)?;
            let operation_record = current.record();

            if self.pending_atomic_snapshot.is_none() {
                let pending_sources = LifecycleAtomicSnapshotSourceStoreV1::new(journal)
                    .pending_reservations()
                    .map_err(retryable)?;
                if pending_sources
                    .iter()
                    .any(|(reserved_operation, _)| *reserved_operation != operation_id)
                {
                    return Err(retryable(
                        "another reserved Storage group holds the session",
                    ));
                }
                match LifecycleAtomicSnapshotSourceStoreV1::new(journal)
                    .recover(operation_id)
                    .map_err(retryable)?
                {
                    LifecycleAtomicSnapshotSourceRecoveryV1::Absent => {}
                    LifecycleAtomicSnapshotSourceRecoveryV1::Pending {
                        request_id,
                        request_packet,
                        predecessor_packet,
                        session,
                    } => {
                        let mut sessions = self
                            .sessions
                            .lock()
                            .map_err(|_| retryable("broker session lock is poisoned"))?;
                        let storage = sessions
                            .storage
                            .as_mut()
                            .ok_or_else(missing_broker_session)?;
                        let history = storage.recover_prior_atomic_snapshot_history(
                            request_id,
                            request_packet,
                            predecessor_packet,
                            session,
                        )?;
                        return Err(match history {
                            ProtectedPriorAtomicStorageHistoryV1::Absent
                            | ProtectedPriorAtomicStorageHistoryV1::Incomplete => retryable(
                                "reserved Storage group lacks an adjacent terminal successor",
                            ),
                            ProtectedPriorAtomicStorageHistoryV1::Complete { .. } => {
                                // The packet trio survives, but the old signed hello and
                                // verified transcript do not. Do not treat raw history as a
                                // newly authenticated successor or roll this session over.
                                retryable(
                                    "signed Storage trio awaits historical semantic reconstruction",
                                )
                            }
                        });
                    }
                    LifecycleAtomicSnapshotSourceRecoveryV1::Complete { .. } => {
                        let observation = LifecycleAtomicSnapshotSourceStoreV1::new(journal)
                            .recover_complete_observation(&current, &barrier)
                            .map_err(permanent)?;
                        drop(effect);
                        drop(current);
                        drop(coordination);
                        drop(owner);
                        return self.commit_storage_snapshot_progress(
                            operation_id,
                            operation_key,
                            operation_record,
                            observation,
                        );
                    }
                }

                let mut sessions = self
                    .sessions
                    .lock()
                    .map_err(|_| retryable("broker session lock is poisoned"))?;
                let storage = sessions
                    .storage
                    .as_mut()
                    .ok_or_else(missing_broker_session)?;
                let predecessor = storage
                    .begin_atomic_snapshot_inventory()
                    .map_err(retryable)?;
                let plan = barrier
                    .atomic_dataset_snapshot_plan(&current, predecessor.inventory())
                    .map_err(permanent)?;
                let timing = production_authority_effect_timing()
                    .ok_or_else(|| retryable("Storage authority clock is unavailable"))?;
                let authority = aos_sandbox::prepare_atomic_storage_lifecycle_authority_effect_v1(
                    journal, self.node, fence, &plan, timing,
                )
                .map_err(permanent)?;
                let admission = LifecycleAtomicSnapshotSourceStoreV1::new(journal).reserve(
                    &current,
                    &barrier,
                    &plan,
                    predecessor.inventory(),
                    predecessor.outcome(),
                    fence,
                    &authority,
                );
                let admission = match admission {
                    Ok(admission) => admission,
                    Err(error) => {
                        // The source commit may have succeeded despite its I/O error.
                        self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                            operation: operation_id,
                            operation_record: operation_record.digest(),
                            plan,
                            fence,
                            authority,
                            predecessor_inventory: predecessor.inventory().clone(),
                            predecessor_outcome: predecessor.outcome().clone(),
                            phase: AtomicSnapshotPhaseV1::Rejected,
                        });
                        return Err(retryable(error));
                    }
                };
                if admission != LifecycleAtomicSnapshotSourceAdmissionV1::Reserved {
                    return Err(retryable(
                        "Storage source reservation already owns the exact group request",
                    ));
                }
                self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                    operation: operation_id,
                    operation_record: operation_record.digest(),
                    plan,
                    fence,
                    authority,
                    predecessor_inventory: predecessor.inventory().clone(),
                    predecessor_outcome: predecessor.outcome().clone(),
                    phase: AtomicSnapshotPhaseV1::Group(predecessor),
                });
            }

            let mut pending = self
                .pending_atomic_snapshot
                .take()
                .ok_or_else(|| retryable("Storage source custody is absent"))?;
            let current_plan =
                barrier.atomic_dataset_snapshot_plan(&current, &pending.predecessor_inventory);
            if pending.operation != operation_id
                || pending.operation_record != operation_record.digest()
                || pending.fence != fence
                || !matches!(current_plan, Ok(ref plan) if plan == &pending.plan)
            {
                self.pending_atomic_snapshot = Some(pending);
                return Err(permanent(
                    "retained Storage group differs from lifecycle state",
                ));
            }

            let phase = match pending.phase {
                AtomicSnapshotPhaseV1::Group(mut predecessor) => {
                    let mut sessions = self
                        .sessions
                        .lock()
                        .map_err(|_| retryable("broker session lock is poisoned"))?;
                    let storage = sessions
                        .storage
                        .as_mut()
                        .ok_or_else(missing_broker_session)?;
                    match storage.apply_atomic_snapshot_group(
                        &effect,
                        &pending.plan,
                        &mut predecessor,
                        fence,
                        &pending.authority,
                    ) {
                        Ok(group) => {
                            let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } =
                                group.result()
                            else {
                                self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                                    phase: AtomicSnapshotPhaseV1::Rejected,
                                    ..pending
                                });
                                return Err(permanent("Storage rejected the reserved group"));
                            };
                            let receipt =
                                match aos_sandbox_protocol::decode_atomic_storage_snapshot_response(
                                    exact_body,
                                ) {
                                    Ok(receipt) => receipt,
                                    Err(error) => {
                                        self.pending_atomic_snapshot =
                                            Some(PendingAtomicSnapshotV1 {
                                                phase: AtomicSnapshotPhaseV1::Rejected,
                                                ..pending
                                            });
                                        return Err(permanent(error));
                                    }
                                };
                            let progress = storage.finish_atomic_snapshot_inventory(
                                &challenge,
                                &current,
                                &pending.plan,
                                ObjectDigest::from_bytes(receipt.program()),
                                ObjectDigest::from_bytes(receipt.observation()),
                                predecessor,
                                group,
                            );
                            let progress = match progress {
                                Ok(progress) => progress,
                                Err(error) => {
                                    self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                                        phase: AtomicSnapshotPhaseV1::Rejected,
                                        ..pending
                                    });
                                    return Err(retryable(error));
                                }
                            };
                            finish_phase(progress)
                        }
                        Err(error) => {
                            let phase = if matches!(&error, EffectFailure::Permanent(_)) {
                                AtomicSnapshotPhaseV1::Rejected
                            } else {
                                AtomicSnapshotPhaseV1::Group(predecessor)
                            };
                            self.pending_atomic_snapshot =
                                Some(PendingAtomicSnapshotV1 { phase, ..pending });
                            return Err(error);
                        }
                    }
                }
                AtomicSnapshotPhaseV1::Finish(recovery) => {
                    let mut sessions = self
                        .sessions
                        .lock()
                        .map_err(|_| retryable("broker session lock is poisoned"))?;
                    let storage = sessions
                        .storage
                        .as_mut()
                        .ok_or_else(missing_broker_session)?;
                    let group = recovery.group_outcome();
                    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } =
                        group.result()
                    else {
                        self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                            phase: AtomicSnapshotPhaseV1::Rejected,
                            ..pending
                        });
                        return Err(permanent("retained Storage group is not successful"));
                    };
                    let receipt =
                        match aos_sandbox_protocol::decode_atomic_storage_snapshot_response(
                            exact_body,
                        ) {
                            Ok(receipt) => receipt,
                            Err(error) => {
                                self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                                    phase: AtomicSnapshotPhaseV1::Rejected,
                                    ..pending
                                });
                                return Err(permanent(error));
                            }
                        };
                    let progress = storage.resume_atomic_snapshot_inventory(
                        &challenge,
                        &current,
                        &pending.plan,
                        ObjectDigest::from_bytes(receipt.program()),
                        ObjectDigest::from_bytes(receipt.observation()),
                        recovery,
                    );
                    let progress = match progress {
                        Ok(progress) => progress,
                        Err(error) => {
                            self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                                phase: AtomicSnapshotPhaseV1::Rejected,
                                ..pending
                            });
                            return Err(retryable(error));
                        }
                    };
                    finish_phase(progress)
                }
                AtomicSnapshotPhaseV1::Rejected => {
                    self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                        phase: AtomicSnapshotPhaseV1::Rejected,
                        ..pending
                    });
                    return Err(permanent("Storage group has a terminal rejected outcome"));
                }
                phase => phase,
            };
            pending.phase = phase;

            if let AtomicSnapshotPhaseV1::Complete(completion) = &pending.phase {
                let result = LifecycleAtomicSnapshotSourceStoreV1::new(journal).complete(
                    &current,
                    &barrier,
                    &pending.plan,
                    &pending.predecessor_inventory,
                    &pending.predecessor_outcome,
                    fence,
                    &pending.authority,
                    completion.group_outcome(),
                    completion.successor_outcome(),
                    completion.successor().clone(),
                );
                let observation = match result {
                    Ok(
                        LifecycleAtomicSnapshotSourceCompletionV1::Recorded(observation)
                        | LifecycleAtomicSnapshotSourceCompletionV1::Replay(observation),
                    ) => observation,
                    Err(error) => {
                        self.pending_atomic_snapshot = Some(pending);
                        return Err(retryable(error));
                    }
                };
                pending.phase = AtomicSnapshotPhaseV1::Progress(observation);
            }

            let observation = match pending.phase {
                AtomicSnapshotPhaseV1::Progress(observation) => observation,
                phase => {
                    pending.phase = phase;
                    self.pending_atomic_snapshot = Some(pending);
                    return Err(retryable(
                        "Storage successor query retains exact recovery custody",
                    ));
                }
            };
            self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                phase: AtomicSnapshotPhaseV1::Progress(observation),
                ..pending
            });
            (operation_key, operation_record, observation)
        };

        self.commit_storage_snapshot_progress(
            operation_id,
            operation_key,
            operation_record,
            observation,
        )
    }

    fn commit_storage_snapshot_progress(
        &mut self,
        operation_id: OperationId,
        operation_key: aos_sandbox::lifecycle::LifecycleProtectedJournalKeyV1,
        operation_record: aos_sandbox::lifecycle::LifecycleRecordDigestV1,
        observation: LifecycleEffectObservationV1,
    ) -> Result<bool, EffectFailure> {
        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(permanent)?;
            let transaction_id = lifecycle_progress_transaction_id(
                operation_id,
                operation_record.digest(),
                b"storage-atomic-snapshot-success",
            );
            let prepared = owner
                .prepare_successful_effect_progress(
                    &operation_key,
                    transaction_id,
                    observation,
                    current_lifecycle_time()?,
                )
                .map_err(permanent)?;
            owner.commit_effect_progress(prepared).map_err(permanent)?
        };
        self.settle_lifecycle_progress(operation_id, outcome)?;
        self.pending_atomic_snapshot = None;
        Ok(true)
    }
}

fn finish_phase(progress: DormantAtomicStorageInventoryFinishProgressV1) -> AtomicSnapshotPhaseV1 {
    match progress {
        DormantAtomicStorageInventoryFinishProgressV1::Complete(completion) => {
            AtomicSnapshotPhaseV1::Complete(completion)
        }
        DormantAtomicStorageInventoryFinishProgressV1::RecoveryRequired(recovery) => {
            AtomicSnapshotPhaseV1::Finish(recovery)
        }
    }
}

fn permanent(error: impl ToString) -> EffectFailure {
    EffectFailure::Permanent(error.to_string())
}

fn retryable(error: impl ToString) -> EffectFailure {
    EffectFailure::Retryable(error.to_string())
}
