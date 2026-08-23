//! Precommit staging for the production QEMU action ledger.

use super::*;

/// Owns every QEMU action record needed after the backend commit becomes visible.
pub(in crate::production_fault_runtime) struct StagedQemuActionLedger {
    actions: Vec<(ContentHash, ResolvedBindingAction)>,
}

impl ProductionFaultRuntime {
    #[cfg(test)]
    pub(in crate::production_fault_runtime) fn update_qemu_action_ledger(
        &mut self,
        actions: &[ResolvedBindingAction],
        commits: Vec<(ContentHash, CommittedQemuActionEvidence)>,
    ) -> Result<(), ProductionFaultRuntimeError> {
        let staged = self.stage_qemu_action_ledger(actions)?;
        self.commit_staged_qemu_action_ledger(staged, commits)
    }

    pub(in crate::production_fault_runtime) fn stage_qemu_action_ledger(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<StagedQemuActionLedger, ProductionFaultRuntimeError> {
        let is_node = |action: &&ResolvedBindingAction| {
            matches!(action.effect.specification(), EffectSpecification::Node(_))
        };
        let node_action_count = actions.iter().filter(is_node).count();
        let retained = actions
            .iter()
            .filter(is_node)
            .filter(|action| {
                matches!(
                    action.kind,
                    BindingActionKind::UpsertPersistent | BindingActionKind::Apply
                )
            })
            .count();
        let persistent = actions
            .iter()
            .filter(is_node)
            .filter(|action| action.kind == BindingActionKind::UpsertPersistent)
            .count();
        let current = self.qemu_issued_actions.len();
        self.resource_limits.reserve(
            "event_records",
            u64::try_from(current).map_err(|_| FaultResourceLimitError::Representation {
                field: "event_records",
                value: u64::MAX,
            })?,
            u64::try_from(retained).map_err(|_| FaultResourceLimitError::Representation {
                field: "event_records",
                value: u64::MAX,
            })?,
        )?;
        self.qemu_issued_actions
            .try_reserve(retained)
            .map_err(|_| ledger_allocation(current, retained, self.resource_limits))?;
        self.qemu_action_commits
            .try_reserve(retained)
            .map_err(|_| {
                ledger_allocation(
                    self.qemu_action_commits.len(),
                    retained,
                    self.resource_limits,
                )
            })?;
        self.qemu_active_rule_ids
            .try_reserve(persistent)
            .map_err(|_| {
                ledger_allocation(
                    self.qemu_active_rule_ids.len(),
                    persistent,
                    self.resource_limits,
                )
            })?;

        let mut staged = Vec::new();
        staged
            .try_reserve_exact(node_action_count)
            .map_err(|_| ledger_allocation(current, node_action_count, self.resource_limits))?;
        for action in actions.iter().filter(is_node) {
            let identity = action.id();
            if staged
                .iter()
                .any(|(candidate, _action)| *candidate == identity)
                || (action.kind != BindingActionKind::RemovePersistent
                    && self.qemu_issued_actions.get(&identity).is_some())
            {
                return Err(FaultExecutionError::CheckpointPresence.into());
            }
            if action.kind == BindingActionKind::RemovePersistent
                && !self.qemu_active_rule_ids.iter().any(|active_id| {
                    self.qemu_issued_actions
                        .get(active_id)
                        .is_some_and(|active| {
                            active.binding == action.binding
                                && active.target == action.target
                                && active.phase == action.phase
                        })
                })
            {
                return Err(FaultExecutionError::CheckpointPresence.into());
            }
            staged.push((
                identity,
                try_clone_action(action, || {
                    ledger_allocation(current, node_action_count, self.resource_limits)
                })?,
            ));
        }
        Ok(StagedQemuActionLedger { actions: staged })
    }

    pub(in crate::production_fault_runtime) fn commit_staged_qemu_action_ledger(
        &mut self,
        staged: StagedQemuActionLedger,
        mut commits: Vec<(ContentHash, CommittedQemuActionEvidence)>,
    ) -> Result<(), ProductionFaultRuntimeError> {
        if commits.len() != staged.actions.len()
            || staged.actions.iter().any(|(action_id, _action)| {
                !commits.iter().any(|(identity, _)| identity == action_id)
            })
        {
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        for (identity, action) in staged.actions {
            let commit = take_qemu_commit(&mut commits, identity)
                .ok_or(FaultExecutionError::CheckpointPresence)?;
            match action.kind {
                BindingActionKind::UpsertPersistent | BindingActionKind::Apply => {
                    if self
                        .qemu_issued_actions
                        .try_insert(identity, action)
                        .map_err(|_| {
                            ledger_allocation(
                                self.qemu_issued_actions.len(),
                                1,
                                self.resource_limits,
                            )
                        })?
                        .is_some()
                        || self
                            .qemu_action_commits
                            .try_insert(identity, commit)
                            .map_err(|_| {
                                ledger_allocation(
                                    self.qemu_action_commits.len(),
                                    1,
                                    self.resource_limits,
                                )
                            })?
                            .is_some()
                    {
                        return Err(FaultExecutionError::CheckpointPresence.into());
                    }
                    let retained = self
                        .qemu_issued_actions
                        .get(&identity)
                        .ok_or(FaultExecutionError::CheckpointPresence)?;
                    if retained.kind == BindingActionKind::UpsertPersistent {
                        self.qemu_active_rule_ids.retain(|active_id| {
                            self.qemu_issued_actions
                                .get(active_id)
                                .is_none_or(|active| {
                                    active_id == &identity
                                        || active.binding != retained.binding
                                        || active.target != retained.target
                                        || active.phase != retained.phase
                                })
                        });
                        self.qemu_active_rule_ids
                            .try_insert(identity)
                            .map_err(|_| {
                                ledger_allocation(
                                    self.qemu_active_rule_ids.len(),
                                    1,
                                    self.resource_limits,
                                )
                            })?;
                    }
                }
                BindingActionKind::RemovePersistent => {
                    let prior_len = self.qemu_active_rule_ids.len();
                    self.qemu_active_rule_ids.retain(|active_id| {
                        self.qemu_issued_actions
                            .get(active_id)
                            .is_none_or(|active| {
                                active.binding != action.binding
                                    || active.target != action.target
                                    || active.phase != action.phase
                            })
                    });
                    if self.qemu_active_rule_ids.len() == prior_len {
                        return Err(FaultExecutionError::CheckpointPresence.into());
                    }
                }
            }
        }
        if commits.is_empty() {
            Ok(())
        } else {
            Err(FaultExecutionError::CheckpointPresence.into())
        }
    }
}

fn ledger_allocation(
    current: usize,
    requested: usize,
    limits: FaultResourceLimits,
) -> ProductionFaultRuntimeError {
    FaultResourceLimitError::Exceeded {
        field: "event_records",
        current: u64::try_from(current).unwrap_or(u64::MAX),
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: limits.event_records,
        hard: FaultResourceLimits::compiled_maximum().event_records,
    }
    .into()
}
