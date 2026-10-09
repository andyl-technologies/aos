//! Original lifecycle plan binding, progress, publication and stable identities.
//!
//! Every protected owner and broker-session borrow remains inside its original
//! method frame. The seven identity helpers retain the same canonical domains,
//! byte order, fixed widths and nonzero rule, without granting authority.

use super::*;

#[cfg(test)]
mod tests;

impl ProductionEffectExecutor {
    pub(super) fn bind_lifecycle_plan(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        let coordinated_snapshot = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (_, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "admitted lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            matches!(
                current.operation().intent(),
                aos_sandbox::lifecycle::LifecycleIntentV1::Snapshot { .. }
                    | aos_sandbox::lifecycle::LifecycleIntentV1::Hibernate { .. }
            ) && current.operation().plan_is_unbound()
        };
        if coordinated_snapshot {
            self.ensure_snapshot_retention_ledger(operation_id)?;
            self.ensure_snapshot_coordination(operation_id)?;
        }

        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "admitted lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if !current.operation().plan_is_unbound() {
                return Ok(());
            }

            let steps = match current.operation().intent() {
                aos_sandbox::lifecycle::LifecycleIntentV1::Stop { .. } => {
                    LifecycleSuspensionPlanV1::planned_stop_steps(&current)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                }
                aos_sandbox::lifecycle::LifecycleIntentV1::SuspendMemory { .. } => {
                    LifecycleSuspensionPlanV1::planned_memory_suspend_steps(&current)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                }
                aos_sandbox::lifecycle::LifecycleIntentV1::Resume {
                    source: aos_sandbox::lifecycle::LifecycleResumeSourceV1::Memory { fence },
                    ..
                } => {
                    let observation = owner
                        .current_suspend_observation_for_fence(
                            current.operation().project(),
                            *fence,
                        )
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "protected suspension observation is absent".to_owned(),
                            )
                        })?;
                    let inventory_lineage =
                        lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage");
                    let boot_inventory_key = lifecycle_protected_key_v1(
                        LifecycleProtectedRecordKindV1::Auxiliary,
                        current.operation().project(),
                        inventory_lineage,
                        operation_id,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let challenge = owner
                        .begin_boot_inventory_bootstrap(&current_key, &boot_inventory_key)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let runtime = {
                        let mut sessions = self.sessions.lock().map_err(|_| {
                            EffectFailure::Retryable("broker session lock is poisoned".to_owned())
                        })?;
                        let host = sessions.host.as_mut().ok_or_else(missing_broker_session)?;
                        host.bootstrap_runtime_inventory(&challenge)
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    };
                    let liveness = owner
                        .bind_authenticated_runtime_liveness(&current_key, &runtime)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    LifecycleSuspensionPlanV1::planned_memory_resume_steps(
                        &current,
                        &observation,
                        &liveness,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                }
                aos_sandbox::lifecycle::LifecycleIntentV1::Snapshot { .. }
                | aos_sandbox::lifecycle::LifecycleIntentV1::Hibernate { .. } => {
                    let project = current.operation().project();
                    let coordination_lineage =
                        lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
                    let coordination_key = lifecycle_protected_key_v1(
                        LifecycleProtectedRecordKindV1::Auxiliary,
                        project,
                        coordination_lineage,
                        operation_id,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let coordination = owner
                        .current_coordination(&coordination_key)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "snapshot coordination is absent after protected publication"
                                    .to_owned(),
                            )
                        })?;
                    if matches!(
                        current.operation().intent(),
                        aos_sandbox::lifecycle::LifecycleIntentV1::Snapshot { .. }
                    ) {
                        LifecycleSnapshotBarrierV1::planned_snapshot_steps(&current, &coordination)
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    } else {
                        LifecycleSuspensionPlanV1::planned_hibernate_steps(&current, &coordination)
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    }
                }
                _ => return Ok(()),
            };
            let transaction_id =
                lifecycle_plan_binding_transaction_id(operation_id, current.record().digest());
            let prepared = owner
                .prepare_plan_binding(&current_key, transaction_id, steps)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };

        self.settle_lifecycle_progress(operation_id, outcome)
    }

    pub(super) fn ensure_initial_lifecycle_reservation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "bound lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if current.operation().phase() != aos_sandbox::lifecycle::LifecyclePhaseV1::Accepted
                || current.operation().plan_is_unbound()
            {
                return Ok(());
            }
            let current_record = current.record();
            drop(current);
            let started_at = current_lifecycle_time()?;
            let transaction_id =
                lifecycle_initial_reservation_transaction_id(operation_id, current_record.digest());
            let prepared = owner
                .prepare_initial_lifecycle_progress(&current_key, transaction_id, started_at)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };

        self.settle_lifecycle_progress(operation_id, outcome)
    }

    pub(super) fn advance_controller_lifecycle_effect(
        &mut self,
        operation_id: OperationId,
    ) -> Result<bool, EffectFailure> {
        let (current_key, current_record, observation, observed_at) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if !matches!(
                current.operation().phase(),
                aos_sandbox::lifecycle::LifecyclePhaseV1::Preparing
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Completing
            ) {
                return Ok(false);
            }

            let effect = match current.operation().intent().method() {
                aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory => {
                    LifecycleSuspensionPlanV1::suspend(&current, None)
                        .and_then(|plan| plan.next_effect(&current))
                }
                aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot
                | aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate => {
                    let coordination_lineage =
                        lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
                    let coordination_key = lifecycle_protected_key_v1(
                        LifecycleProtectedRecordKindV1::Auxiliary,
                        current.operation().project(),
                        coordination_lineage,
                        operation_id,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let coordination = owner
                        .current_coordination(&coordination_key)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "snapshot coordination is absent during effect dispatch".to_owned(),
                            )
                        })?;
                    let barrier = LifecycleSnapshotBarrierV1::from_current_transaction(
                        &current,
                        &coordination,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    if current.operation().intent().method()
                        == aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot
                    {
                        barrier.next_effect(&current)
                    } else {
                        LifecycleSuspensionPlanV1::suspend(&current, Some(barrier))
                            .and_then(|plan| plan.next_effect(&current))
                    }
                }
                _ => return Ok(false),
            }
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if effect.domain() != aos_sandbox::lifecycle::LifecycleEffectDomainV1::Controller {
                return Ok(false);
            }
            let result = ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(b"aos.sandbox.lifecycle.controller-effect-result.v1\0")
                    .chain_update(effect.canonical_body())
                    .chain_update(current.record().digest().as_bytes())
                    .finalize()
                    .into(),
            );
            let inventory = current.projection_root();
            let observation = effect
                .observe_controller_readback(result, inventory)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            (
                current_key,
                current.record(),
                observation,
                current_lifecycle_time()?,
            )
        };

        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let transaction_id = lifecycle_progress_transaction_id(
                operation_id,
                current_record.digest(),
                b"controller-effect-success",
            );
            let prepared = owner
                .prepare_successful_effect_progress(
                    &current_key,
                    transaction_id,
                    observation,
                    observed_at,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };
        self.settle_lifecycle_progress(operation_id, outcome)?;
        Ok(true)
    }

    pub(super) fn advance_runtime_lifecycle_effect(
        &mut self,
        operation_id: OperationId,
        journal: &mut Journal,
    ) -> Result<bool, EffectFailure> {
        let (current_key, current_record, observation, observed_at, publish_coordination) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if !matches!(
                current.operation().phase(),
                aos_sandbox::lifecycle::LifecyclePhaseV1::Preparing
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Completing
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Compensating
            ) {
                return Ok(false);
            }

            let method = current.operation().intent().method();
            let inventory_lineage =
                lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage");
            let boot_inventory_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                current.operation().project(),
                inventory_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let challenge = owner
                .begin_boot_inventory_bootstrap(&current_key, &boot_inventory_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (effect, fence) = match method {
                aos_sandbox::lifecycle::LifecycleMethodV1::Stop => {
                    let fence = match current.operation().intent() {
                        aos_sandbox::lifecycle::LifecycleIntentV1::Stop { fence, .. } => *fence,
                        _ => {
                            return Err(EffectFailure::Permanent(
                                "stop method has a different intent".to_owned(),
                            ));
                        }
                    };
                    let effect = LifecycleSuspensionPlanV1::stop(&current)
                        .and_then(|plan| plan.next_effect(&current))
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    (effect, fence)
                }
                aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory => {
                    let fence = match current.operation().intent() {
                        aos_sandbox::lifecycle::LifecycleIntentV1::SuspendMemory {
                            fence, ..
                        } => *fence,
                        _ => {
                            return Err(EffectFailure::Permanent(
                                "memory-suspend method has a different intent".to_owned(),
                            ));
                        }
                    };
                    let effect = LifecycleSuspensionPlanV1::suspend(&current, None)
                        .and_then(|plan| plan.next_effect(&current))
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    (effect, fence)
                }
                aos_sandbox::lifecycle::LifecycleMethodV1::Resume => {
                    let fence = match current.operation().intent() {
                        aos_sandbox::lifecycle::LifecycleIntentV1::Resume {
                            source:
                                aos_sandbox::lifecycle::LifecycleResumeSourceV1::Memory { fence },
                            ..
                        } => *fence,
                        _ => return Ok(false),
                    };
                    let observation = owner
                        .current_suspend_observation_for_fence(current.operation().project(), fence)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "protected suspension observation is absent".to_owned(),
                            )
                        })?;
                    let runtime = {
                        let mut sessions = self.sessions.lock().map_err(|_| {
                            EffectFailure::Retryable("broker session lock is poisoned".to_owned())
                        })?;
                        let host = sessions.host.as_mut().ok_or_else(missing_broker_session)?;
                        host.bootstrap_runtime_inventory(&challenge)
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    };
                    let liveness = owner
                        .bind_authenticated_runtime_liveness(&current_key, &runtime)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let effect =
                        LifecycleSuspensionPlanV1::resume_memory(&current, &observation, &liveness)
                            .and_then(|plan| plan.next_effect(&current))
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    (effect, fence)
                }
                aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot
                | aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate => {
                    let coordination_lineage =
                        lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
                    let coordination_key = lifecycle_protected_key_v1(
                        LifecycleProtectedRecordKindV1::Auxiliary,
                        current.operation().project(),
                        coordination_lineage,
                        operation_id,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let coordination = owner
                        .current_coordination(&coordination_key)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "snapshot coordination is absent during runtime dispatch"
                                    .to_owned(),
                            )
                        })?;
                    let fence = coordination.coordination().transaction().live_fence();
                    let barrier = LifecycleSnapshotBarrierV1::from_current_transaction(
                        &current,
                        &coordination,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let effect = if method == aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot {
                        barrier.next_effect(&current)
                    } else {
                        LifecycleSuspensionPlanV1::suspend(&current, Some(barrier))
                            .and_then(|plan| plan.next_effect(&current))
                    }
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    (effect, fence)
                }
                _ => return Ok(false),
            };
            if effect.domain() != aos_sandbox::lifecycle::LifecycleEffectDomainV1::Runtime {
                return Ok(false);
            }
            let runtime_action = match (method, effect.step(), effect.ordinal()) {
                (aos_sandbox::lifecycle::LifecycleMethodV1::Stop, 0, 6) => {
                    RuntimeAction::RUNTIME_ACTION_STOP
                }
                (aos_sandbox::lifecycle::LifecycleMethodV1::Resume, 0, 9) => {
                    RuntimeAction::RUNTIME_ACTION_THAW
                }
                (aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory, 2, 3)
                | (aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot, 2, 3)
                | (aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate, 2 | 5, 3) => {
                    RuntimeAction::RUNTIME_ACTION_FREEZE
                }
                (aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot, 5, 6)
                | (aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate, 5, 6) => {
                    RuntimeAction::RUNTIME_ACTION_THAW
                }
                (aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate, 8, 6) => {
                    RuntimeAction::RUNTIME_ACTION_STOP
                }
                _ => {
                    return Err(EffectFailure::Permanent(
                        "runtime lifecycle cursor has no broker action".to_owned(),
                    ));
                }
            };
            let publish_coordination = method
                == aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot
                || (method == aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate
                    && effect.step() == 5);
            let timing = production_authority_effect_timing().ok_or_else(|| {
                EffectFailure::Retryable(
                    "current clock cannot safely attenuate lifecycle authority".to_owned(),
                )
            })?;
            let authority = prepare_runtime_lifecycle_authority_effect_v1(
                journal,
                self.node,
                fence,
                runtime_action,
                timing,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            let host = sessions.host.as_mut().ok_or_else(missing_broker_session)?;
            if !host.lifecycle_runtime_ready() {
                return Err(EffectFailure::Retryable(
                    "protected Host session is completing earlier work".to_owned(),
                ));
            }
            let observation = host
                .apply_lifecycle_runtime(challenge, effect, fence, runtime_action, &authority)
                .map_err(|error| {
                    // Once request custody begins, retrying from the lifecycle
                    // cursor could mint a different authenticated identity.
                    // Fail this outer operation closed instead.
                    EffectFailure::Permanent(format!(
                        "authenticated Host runtime lifecycle effect did not settle: {error}"
                    ))
                })?;
            drop(sessions);
            (
                current_key,
                current.record(),
                observation,
                current_lifecycle_time()?,
                publish_coordination,
            )
        };

        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let transaction_id = lifecycle_progress_transaction_id(
                operation_id,
                current_record.digest(),
                b"runtime-effect-success",
            );
            let prepared = owner
                .prepare_successful_effect_progress(
                    &current_key,
                    transaction_id,
                    observation,
                    observed_at,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };
        self.settle_lifecycle_progress(operation_id, outcome)?;
        if publish_coordination {
            self.publish_snapshot_coordination_observation(
                operation_id,
                current_record,
                observation,
            )?;
        }
        Ok(true)
    }

    pub(super) fn advance_terminal_lifecycle_publication(
        &mut self,
        operation_id: OperationId,
        journal: &mut Journal,
    ) -> Result<bool, EffectFailure> {
        let (
            current_key,
            boot_inventory_key,
            observation_key,
            boot_is_current,
            observation_is_current,
        ) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            let is_memory_resume = matches!(
                current.operation().intent(),
                aos_sandbox::lifecycle::LifecycleIntentV1::Resume {
                    source: aos_sandbox::lifecycle::LifecycleResumeSourceV1::Memory { .. },
                    ..
                }
            );
            let method = current.operation().intent().method();
            if current.operation().terminal_result()
                != Some(aos_sandbox::lifecycle::LifecycleTerminalResultV1::Succeeded)
                || (method != aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
                    && !is_memory_resume)
            {
                return Ok(false);
            }
            let project = current.operation().project();
            let inventory_lineage =
                lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage");
            let observation_lineage =
                lifecycle_plan_resource_id(operation_id, b"suspend-observation-lineage");
            let boot_inventory_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                inventory_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let observation_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                observation_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let boot_is_current = owner
                .current_boot_inventory(&boot_inventory_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_some();
            let observation_is_current = method
                == aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
                && owner
                    .current_suspend_observation(&observation_key)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    .is_some();
            (
                current_key,
                boot_inventory_key,
                observation_key,
                boot_is_current,
                observation_is_current,
            )
        };
        if observation_is_current {
            return Ok(false);
        }

        let operation_lineage = lifecycle_plan_resource_id(operation_id, b"operation-lineage");
        if !boot_is_current {
            // Another lifecycle bootstrap must not roll the Storage session
            // while an exact grouped request still owns its signed history.
            if self.pending_atomic_snapshot.is_some() {
                return Err(EffectFailure::Retryable(
                    "Storage session is reserved for an atomic snapshot".to_owned(),
                ));
            }
            self.ensure_lifecycle_inventory_owners()?;
            let challenge = {
                let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                    &mut self.source_domains,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                owner
                    .begin_boot_inventory_bootstrap(&current_key, &boot_inventory_key)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            };
            let storage_fence = aos_sandbox::begin_authenticated_storage_inventory_v1(journal)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (runtime, mounts, storage_outcome, storage_inventory, network) = {
                let mut sessions = self.sessions.lock().map_err(|_| {
                    EffectFailure::Retryable("broker session lock is poisoned".to_owned())
                })?;
                if sessions.host.is_none()
                    || sessions.mount.is_none()
                    || sessions.storage.is_none()
                    || sessions.network.is_none()
                {
                    return Err(EffectFailure::Retryable(
                        "lifecycle inventory sessions are not connected".to_owned(),
                    ));
                }
                let host = sessions.host.as_mut().ok_or_else(missing_broker_session)?;
                if !host.lifecycle_runtime_ready() {
                    return Err(EffectFailure::Retryable(
                        "protected Host session is completing earlier work".to_owned(),
                    ));
                }
                let runtime = host
                    .bootstrap_runtime_inventory(&challenge)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                let mounts = sessions
                    .mount
                    .as_mut()
                    .ok_or_else(missing_broker_session)?
                    .bootstrap_inventory_pair(&challenge)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                let storage_owner = sessions
                    .storage
                    .as_mut()
                    .ok_or_else(missing_broker_session)?;
                let storage_outcome = storage_owner
                    .current_inventory_observation()
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                let storage_inventory = storage_owner
                    .bootstrap_inventory_pair(&challenge)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                let network = sessions
                    .network
                    .as_mut()
                    .ok_or_else(missing_broker_session)?
                    .bootstrap_inventory_pair(&challenge)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                (runtime, mounts, storage_outcome, storage_inventory, network)
            };
            let storage = aos_sandbox::complete_authenticated_storage_inventory_v1(
                journal,
                storage_fence,
                &storage_outcome,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let transfer_inventory = self
                .transfer_inventory
                .as_mut()
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "protected Transfer inventory owner is unavailable".to_owned(),
                    )
                })?
                .lifecycle_transfer_inventory()
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let outcome = {
                let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                    &mut self.source_domains,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                owner
                    .publish_boot_inventory_bootstrap_from_protected_owners(
                        journal,
                        &current_key,
                        &boot_inventory_key,
                        challenge,
                        &runtime,
                        &mounts,
                        &storage,
                        &storage_inventory,
                        &network,
                        self.cache_inventory.as_mut().ok_or_else(|| {
                            EffectFailure::Permanent(
                                "protected Cache inventory owner is unavailable".to_owned(),
                            )
                        })?,
                        self.transfer_inventory.as_mut().ok_or_else(|| {
                            EffectFailure::Permanent(
                                "protected Transfer inventory owner is unavailable".to_owned(),
                            )
                        })?,
                        &transfer_inventory,
                        lifecycle_plan_transaction_id(operation_id, b"boot-inventory-publication"),
                        lifecycle_plan_resource_id(operation_id, b"boot-inventory-atomic-join"),
                        operation_lineage,
                        lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage"),
                        current_lifecycle_time()?,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            };
            self.settle_lifecycle_progress(operation_id, outcome)?;
            return Ok(true);
        }

        let is_memory_resume = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let current = owner
                .current_operation(&current_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "terminal lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            matches!(
                current.operation().intent(),
                aos_sandbox::lifecycle::LifecycleIntentV1::Resume {
                    source: aos_sandbox::lifecycle::LifecycleResumeSourceV1::Memory { .. },
                    ..
                }
            )
        };
        if is_memory_resume {
            return Ok(false);
        }

        let disposition = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let publication = owner
                .publish_suspend_observation(
                    &current_key,
                    &boot_inventory_key,
                    &observation_key,
                    lifecycle_plan_transaction_id(operation_id, b"suspend-observation-publication"),
                    lifecycle_plan_resource_id(operation_id, b"suspend-observation-atomic-join"),
                    operation_lineage,
                    lifecycle_plan_resource_id(operation_id, b"suspend-observation-lineage"),
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            auxiliary_publication_disposition(publication)
        };
        self.settle_auxiliary_publication(operation_id, disposition, "suspend observation")?;
        Ok(true)
    }

    pub(super) fn advance_lifecycle_semantic_commit(
        &mut self,
        operation_id: OperationId,
        journal: &Journal,
    ) -> Result<bool, EffectFailure> {
        let (current_key, current_record, phase, semantic_commit) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            let phase = current.operation().phase();
            if !matches!(
                phase,
                aos_sandbox::lifecycle::LifecyclePhaseV1::Prepared
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::ReadyToCommit
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Committed
            ) {
                return Ok(false);
            }
            if !matches!(
                current.operation().intent().method(),
                aos_sandbox::lifecycle::LifecycleMethodV1::Stop
                    | aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
                    | aos_sandbox::lifecycle::LifecycleMethodV1::Resume
            ) {
                return Ok(false);
            }
            let semantic_commit =
                if phase == aos_sandbox::lifecycle::LifecyclePhaseV1::ReadyToCommit {
                    Some(
                        aos_sandbox::lifecycle::lifecycle_desired_state_semantic_commit_v1(
                            journal,
                            current.operation(),
                            current_lifecycle_time()?,
                        )
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?,
                    )
                } else {
                    None
                };
            (current_key, current.record(), phase, semantic_commit)
        };

        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let transaction_id = lifecycle_progress_transaction_id(
                operation_id,
                current_record.digest(),
                match phase {
                    aos_sandbox::lifecycle::LifecyclePhaseV1::Prepared => b"commit-readiness",
                    aos_sandbox::lifecycle::LifecyclePhaseV1::ReadyToCommit => b"semantic-commit",
                    aos_sandbox::lifecycle::LifecyclePhaseV1::Committed => b"postcommit-progress",
                    _ => {
                        return Err(EffectFailure::Permanent(
                            "invalid lifecycle semantic phase".to_owned(),
                        ));
                    }
                },
            );
            let prepared = match phase {
                aos_sandbox::lifecycle::LifecyclePhaseV1::Prepared => {
                    owner.prepare_semantic_commit_readiness(&current_key, transaction_id)
                }
                aos_sandbox::lifecycle::LifecyclePhaseV1::ReadyToCommit => owner
                    .prepare_semantic_commit(
                        &current_key,
                        transaction_id,
                        semantic_commit.ok_or_else(|| {
                            EffectFailure::Permanent(
                                "lifecycle semantic witness is absent".to_owned(),
                            )
                        })?,
                    ),
                aos_sandbox::lifecycle::LifecyclePhaseV1::Committed => owner
                    .prepare_postcommit_progress(
                        &current_key,
                        transaction_id,
                        current_lifecycle_time()?,
                    ),
                _ => {
                    return Err(EffectFailure::Permanent(
                        "invalid lifecycle semantic phase".to_owned(),
                    ));
                }
            }
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };
        self.settle_lifecycle_progress(operation_id, outcome)?;
        Ok(true)
    }

    pub(super) fn lifecycle_terminal_receipt(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<EffectReceipt>, EffectFailure> {
        let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
            &mut self.source_domains,
        )
        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        let Some((_, current)) = owner
            .current_operation_by_id(operation_id)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Ok(None);
        };
        if current.operation().terminal_result()
            != Some(aos_sandbox::lifecycle::LifecycleTerminalResultV1::Succeeded)
        {
            return Ok(None);
        }
        if matches!(
            current.operation().intent().method(),
            aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
                | aos_sandbox::lifecycle::LifecycleMethodV1::Resume
        ) {
            let boot_inventory_lineage =
                lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage");
            let boot_inventory_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                current.operation().project(),
                boot_inventory_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if owner
                .current_boot_inventory(&boot_inventory_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_none()
            {
                return Ok(None);
            }
        }
        if current.operation().intent().method()
            == aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
        {
            let observation_lineage =
                lifecycle_plan_resource_id(operation_id, b"suspend-observation-lineage");
            let observation_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                current.operation().project(),
                observation_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if owner
                .current_suspend_observation(&observation_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_none()
            {
                return Ok(None);
            }
        }
        let bytes = [
            b"AOSLIF01".as_slice(),
            operation_id.as_bytes(),
            current.record().digest().as_bytes(),
        ]
        .concat();
        EffectReceipt::new(bytes)
            .map(Some)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    /// Parks the original ambiguous lifecycle progress until its protected recovery.
    ///
    /// # Errors
    ///
    /// Returns the original retryable refusal when the commit outcome is unknown.
    pub(in crate::controller_service) fn settle_lifecycle_progress(
        &mut self,
        operation_id: OperationId,
        outcome: LifecycleProgressCommitOutcomeV1,
    ) -> Result<(), EffectFailure> {
        match outcome {
            LifecycleProgressCommitOutcomeV1::Applied(_) => Ok(()),
            LifecycleProgressCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                self.pending_source_commit = Some(PendingSourceCommit {
                    operation_id,
                    receipt: None,
                    pending,
                });
                Err(EffectFailure::Retryable(
                    "protected lifecycle progress durability is unknown".to_owned(),
                ))
            }
        }
    }
}

/// Derives the original domain-separated lifecycle plan resource identity.
pub(in crate::controller_service) fn lifecycle_plan_resource_id(
    operation: OperationId,
    purpose: &[u8],
) -> ResourceId {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-resource.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    ResourceId::from_bytes(nonzero_lifecycle_id_from_digest(digest))
}

pub(super) fn lifecycle_progress_resource_id(
    operation: OperationId,
    current_record: ObjectDigest,
    purpose: &[u8],
) -> ResourceId {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.progress-resource.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    ResourceId::from_bytes(nonzero_lifecycle_id_from_digest(digest))
}

pub(super) fn lifecycle_plan_transaction_id(operation: OperationId, purpose: &[u8]) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    nonzero_lifecycle_id_from_digest(digest)
}

fn lifecycle_plan_binding_transaction_id(
    operation: OperationId,
    current_record: ObjectDigest,
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-binding-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .finalize()
        .into();
    nonzero_lifecycle_id_from_digest(digest)
}

fn lifecycle_initial_reservation_transaction_id(
    operation: OperationId,
    current_record: ObjectDigest,
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.initial-reservation-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .finalize()
        .into();
    nonzero_lifecycle_id_from_digest(digest)
}

/// Derives the original progress transaction identity from the current record.
pub(in crate::controller_service) fn lifecycle_progress_transaction_id(
    operation: OperationId,
    current_record: ObjectDigest,
    purpose: &[u8],
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.progress-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    nonzero_lifecycle_id_from_digest(digest)
}

fn nonzero_lifecycle_id_from_digest(digest: [u8; 32]) -> [u8; 16] {
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    identity
}
