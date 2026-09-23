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
    checkpoint: ObjectDigest,
    predecessor_inventory: LifecycleAuthenticatedStorageInventoryV1,
    predecessor_outcome: AuthenticatedBrokerMethodOutcomeV1,
    phase: AtomicSnapshotPhaseV1,
}

enum AtomicSnapshotPhaseV1 {
    // Local-only proof that no Method25 send followed an ambiguous source write.
    Reserve(DormantAtomicStorageInventoryPredecessorV1),
    Group(DormantAtomicStorageInventoryPredecessorV1),
    Finish(DormantAtomicStorageInventoryFinishRecoveryV1),
    Complete(DormantAtomicStorageInventoryCompletionV1),
    // The group is terminal; only its protected history may complete custody.
    Recover,
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

            let recover_in_process = self
                .pending_atomic_snapshot
                .as_ref()
                .is_some_and(|pending| {
                    pending.operation == operation_id
                        && matches!(pending.phase, AtomicSnapshotPhaseV1::Recover)
                });
            if self.pending_atomic_snapshot.is_none() || recover_in_process {
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
                    LifecycleAtomicSnapshotSourceRecoveryV1::Absent if recover_in_process => {
                        return Err(permanent(
                            "successful Storage group lost its durable source reservation",
                        ));
                    }
                    LifecycleAtomicSnapshotSourceRecoveryV1::Absent => {}
                    LifecycleAtomicSnapshotSourceRecoveryV1::Pending {
                        request_id,
                        request_packet,
                        predecessor_packet,
                        session,
                        checkpoint,
                    } => {
                        let mut sessions = self
                            .sessions
                            .lock()
                            .map_err(|_| retryable("broker session lock is poisoned"))?;
                        let storage = sessions
                            .storage
                            .as_mut()
                            .ok_or_else(missing_broker_session)?;
                        let history = storage.recover_verified_atomic_snapshot_history(
                            request_id,
                            request_packet,
                            predecessor_packet,
                            session,
                            checkpoint,
                        )?;
                        let predecessor = match &history {
                            crate::recovery::ProtectedVerifiedAtomicStorageHistoryV1::Complete {
                                predecessor,
                                ..
                            }
                            | crate::recovery::ProtectedVerifiedAtomicStorageHistoryV1::GroupCommitted {
                                predecessor,
                                ..
                            } => predecessor.clone(),
                            _ => {
                                return Err(retryable(
                                    "reserved Storage group has no authenticated result",
                                ));
                            }
                        };
                        let predecessor_inventory =
                            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(
                                &predecessor,
                            )
                            .map_err(permanent)?;
                        let plan = barrier
                            .atomic_dataset_snapshot_plan(&current, &predecessor_inventory)
                            .map_err(permanent)?;
                        let (completion, uses_status_evidence) = match history {
                            crate::recovery::ProtectedVerifiedAtomicStorageHistoryV1::Complete {
                                ..
                            } => (
                                storage
                                    .recover_verified_atomic_snapshot_completion(
                                        request_id,
                                        request_packet,
                                        predecessor_packet,
                                        session,
                                        checkpoint,
                                        &challenge,
                                        &current,
                                        &plan,
                                    )?
                                    .ok_or_else(|| {
                                        retryable("verified Storage trio changed during recovery")
                                    })?,
                                false,
                            ),
                            crate::recovery::ProtectedVerifiedAtomicStorageHistoryV1::GroupCommitted {
                                predecessor,
                                group,
                            } => {
                                storage.archive_verified_atomic_snapshot_history(
                                    request_id,
                                    request_packet,
                                    predecessor_packet,
                                    session,
                                    checkpoint,
                                )?;
                                let completion = storage.recover_verified_atomic_snapshot_status(
                                    predecessor,
                                    group,
                                    &challenge,
                                    &current,
                                    &plan,
                                )?;
                                (completion, true)
                            }
                            _ => return Err(retryable("protected Storage history changed")),
                        };
                        drop(sessions);
                        let mut source = LifecycleAtomicSnapshotSourceStoreV1::new(journal);
                        let complete = if uses_status_evidence {
                            LifecycleAtomicSnapshotSourceStoreV1::complete_verified_status
                        } else {
                            LifecycleAtomicSnapshotSourceStoreV1::complete_verified_history
                        };
                        let result = complete(
                            &mut source,
                            &current,
                            &barrier,
                            &plan,
                            &predecessor_inventory,
                            completion.predecessor_outcome(),
                            fence,
                            checkpoint,
                            completion.group_outcome(),
                            completion.successor_outcome(),
                            completion.successor().clone(),
                        )
                        .map_err(retryable)?;
                        let observation = match result {
                            LifecycleAtomicSnapshotSourceCompletionV1::Recorded(observation)
                            | LifecycleAtomicSnapshotSourceCompletionV1::Replay(observation) => {
                                observation
                            }
                        };
                        drop(effect);
                        drop(current);
                        drop(coordination);
                        drop(owner);
                        self.retire_completed_atomic_snapshot_archive(request_id)?;
                        return self.commit_storage_snapshot_progress(
                            operation_id,
                            operation_key,
                            operation_record,
                            observation,
                        );
                    }
                    LifecycleAtomicSnapshotSourceRecoveryV1::Complete { request_id, .. } => {
                        let observation = LifecycleAtomicSnapshotSourceStoreV1::new(journal)
                            .recover_complete_observation(&current, &barrier)
                            .map_err(permanent)?;
                        drop(effect);
                        drop(current);
                        drop(coordination);
                        drop(owner);
                        self.retire_completed_atomic_snapshot_archive(request_id)?;
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
                let checkpoint = storage.historical_checkpoint_digest()?;
                let predecessor_inventory = predecessor.inventory().clone();
                let predecessor_outcome = predecessor.outcome().clone();
                let admission = LifecycleAtomicSnapshotSourceStoreV1::new(journal)
                    .reserve_with_checkpoint(
                        &current,
                        &barrier,
                        &plan,
                        predecessor.inventory(),
                        predecessor.outcome(),
                        fence,
                        &authority,
                        checkpoint,
                    );
                let (phase, failure) = match admission {
                    Ok(LifecycleAtomicSnapshotSourceAdmissionV1::Reserved) => {
                        (AtomicSnapshotPhaseV1::Group(predecessor), None)
                    }
                    Ok(_) => (
                        AtomicSnapshotPhaseV1::Rejected,
                        Some(retryable(
                            "Storage source reservation already owns the exact group request",
                        )),
                    ),
                    Err(aos_sandbox::lifecycle::LifecycleAtomicSnapshotSourceErrorV1::Journal(
                        error,
                    )) => (
                        AtomicSnapshotPhaseV1::Reserve(predecessor),
                        Some(retryable(error)),
                    ),
                    Err(error) => (AtomicSnapshotPhaseV1::Rejected, Some(permanent(error))),
                };
                self.pending_atomic_snapshot = Some(PendingAtomicSnapshotV1 {
                    operation: operation_id,
                    operation_record: operation_record.digest(),
                    plan,
                    fence,
                    authority,
                    checkpoint,
                    predecessor_inventory,
                    predecessor_outcome,
                    phase,
                });
                if let Some(failure) = failure {
                    return Err(failure);
                }
            }

            // An ambiguous source write is locally retryable only while the
            // original signed Storage session remains in custody.
            let reserve_checkpoint = if self
                .pending_atomic_snapshot
                .as_ref()
                .is_some_and(|pending| matches!(pending.phase, AtomicSnapshotPhaseV1::Reserve(_)))
            {
                let sessions = self
                    .sessions
                    .lock()
                    .map_err(|_| retryable("broker session lock is poisoned"))?;
                Some(
                    sessions
                        .storage
                        .as_ref()
                        .ok_or_else(missing_broker_session)?
                        .historical_checkpoint_digest()?,
                )
            } else {
                None
            };
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

            if matches!(pending.phase, AtomicSnapshotPhaseV1::Reserve(_)) {
                let reserved =
                    std::mem::replace(&mut pending.phase, AtomicSnapshotPhaseV1::Rejected);
                let AtomicSnapshotPhaseV1::Reserve(predecessor) = reserved else {
                    self.pending_atomic_snapshot = Some(pending);
                    return Err(permanent("Storage reservation custody changed"));
                };
                if reserve_checkpoint != Some(pending.checkpoint) {
                    self.pending_atomic_snapshot = Some(pending);
                    return Err(permanent("Storage reservation session changed"));
                }
                let admission = LifecycleAtomicSnapshotSourceStoreV1::new(journal)
                    .reserve_with_checkpoint(
                        &current,
                        &barrier,
                        &pending.plan,
                        &pending.predecessor_inventory,
                        &pending.predecessor_outcome,
                        fence,
                        &pending.authority,
                        pending.checkpoint,
                    );
                match admission {
                    Ok(LifecycleAtomicSnapshotSourceAdmissionV1::Reserved)
                    | Ok(LifecycleAtomicSnapshotSourceAdmissionV1::RecoverPending) => {
                        pending.phase = AtomicSnapshotPhaseV1::Group(predecessor);
                        self.pending_atomic_snapshot = Some(pending);
                        return Err(retryable("Storage source reservation is durable"));
                    }
                    Ok(LifecycleAtomicSnapshotSourceAdmissionV1::RecoverComplete) => {
                        self.pending_atomic_snapshot = Some(pending);
                        return Err(permanent(
                            "Storage source completed before local group dispatch",
                        ));
                    }
                    Err(aos_sandbox::lifecycle::LifecycleAtomicSnapshotSourceErrorV1::Journal(
                        error,
                    )) => {
                        pending.phase = AtomicSnapshotPhaseV1::Reserve(predecessor);
                        self.pending_atomic_snapshot = Some(pending);
                        return Err(retryable(error));
                    }
                    Err(error) => {
                        self.pending_atomic_snapshot = Some(pending);
                        return Err(permanent(error));
                    }
                }
            }

            let phase = match pending.phase {
                AtomicSnapshotPhaseV1::Reserve(_) => {
                    self.pending_atomic_snapshot = Some(pending);
                    return Err(permanent("Storage reservation custody was not reconciled"));
                }
                AtomicSnapshotPhaseV1::Group(mut predecessor) => {
                    let mut sessions = match self.sessions.lock() {
                        Ok(sessions) => sessions,
                        Err(_) => {
                            pending.phase = AtomicSnapshotPhaseV1::Group(predecessor);
                            self.pending_atomic_snapshot = Some(pending);
                            return Err(retryable("broker session lock is poisoned"));
                        }
                    };
                    let Some(storage) = sessions.storage.as_mut() else {
                        pending.phase = AtomicSnapshotPhaseV1::Group(predecessor);
                        self.pending_atomic_snapshot = Some(pending);
                        return Err(missing_broker_session());
                    };
                    match storage.apply_atomic_snapshot_group(
                        &effect,
                        &pending.plan,
                        &mut predecessor,
                        fence,
                        &pending.authority,
                    ) {
                        Ok(group) => {
                            let (program, observation) = match snapshot_receipt_digests(
                                &group,
                                "Storage rejected the reserved group",
                            ) {
                                Ok(digests) => digests,
                                Err(error) => {
                                    pending.phase = AtomicSnapshotPhaseV1::Rejected;
                                    self.pending_atomic_snapshot = Some(pending);
                                    return Err(error);
                                }
                            };
                            let progress = storage.finish_atomic_snapshot_inventory(
                                &challenge,
                                &current,
                                &pending.plan,
                                program,
                                observation,
                                predecessor,
                                group,
                            );
                            let progress = match progress {
                                Ok(progress) => progress,
                                Err(error) => {
                                    // The group is terminal. Retry from its protected
                                    // history, never from another Method25 dispatch.
                                    pending.phase = AtomicSnapshotPhaseV1::Recover;
                                    self.pending_atomic_snapshot = Some(pending);
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
                    let mut sessions = match self.sessions.lock() {
                        Ok(sessions) => sessions,
                        Err(_) => {
                            pending.phase = AtomicSnapshotPhaseV1::Finish(recovery);
                            self.pending_atomic_snapshot = Some(pending);
                            return Err(retryable("broker session lock is poisoned"));
                        }
                    };
                    let Some(storage) = sessions.storage.as_mut() else {
                        pending.phase = AtomicSnapshotPhaseV1::Finish(recovery);
                        self.pending_atomic_snapshot = Some(pending);
                        return Err(missing_broker_session());
                    };
                    let group = recovery.group_outcome();
                    let (program, observation) = match snapshot_receipt_digests(
                        group,
                        "retained Storage group is not successful",
                    ) {
                        Ok(digests) => digests,
                        Err(error) => {
                            pending.phase = AtomicSnapshotPhaseV1::Rejected;
                            self.pending_atomic_snapshot = Some(pending);
                            return Err(error);
                        }
                    };
                    let progress = storage.resume_atomic_snapshot_inventory(
                        &challenge,
                        &current,
                        &pending.plan,
                        program,
                        observation,
                        recovery,
                    );
                    let progress = match progress {
                        Ok(progress) => progress,
                        Err(error) => {
                            pending.phase = AtomicSnapshotPhaseV1::Recover;
                            self.pending_atomic_snapshot = Some(pending);
                            return Err(retryable(error));
                        }
                    };
                    finish_phase(progress)
                }
                AtomicSnapshotPhaseV1::Rejected => {
                    pending.phase = AtomicSnapshotPhaseV1::Rejected;
                    self.pending_atomic_snapshot = Some(pending);
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

    fn retire_completed_atomic_snapshot_archive(
        &self,
        request_id: [u8; 16],
    ) -> Result<(), EffectFailure> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        let storage = sessions
            .storage
            .as_mut()
            .ok_or_else(missing_broker_session)?;
        storage.retire_atomic_snapshot_archive(request_id)
    }
}

fn snapshot_receipt_digests(
    group: &AuthenticatedBrokerMethodOutcomeV1,
    rejected_message: &'static str,
) -> Result<(ObjectDigest, ObjectDigest), EffectFailure> {
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = group.result() else {
        return Err(permanent(rejected_message));
    };
    let receipt = aos_sandbox_protocol::decode_atomic_storage_snapshot_response(exact_body)
        .map_err(permanent)?;

    Ok((
        ObjectDigest::from_bytes(receipt.program()),
        ObjectDigest::from_bytes(receipt.observation()),
    ))
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
