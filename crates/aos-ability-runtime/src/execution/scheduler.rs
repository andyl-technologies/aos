//! Deterministic derivation of graph records and bounded executable work.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use aos_ability_model::{
    AbilityValue, BranchSelection, MergeRecord, PlanNodeKey, ScopedOperationKey,
    SkippedOperationRecord,
};

use crate::execution::{
    ExecutionEventKind, ExecutionTransaction, InputResolutionError, OperationState, RecoveryAction,
    TransactionError,
};

/// Supplies one operation and its durable next action in dispatch order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyOperation {
    operation: ScopedOperationKey,
    action: RecoveryAction,
}

impl ReadyOperation {
    /// Returns the ready operation's scoped plan identity.
    #[must_use]
    pub const fn operation(&self) -> &ScopedOperationKey {
        &self.operation
    }

    /// Returns the next action selected from durable replay.
    #[must_use]
    pub const fn action(&self) -> &RecoveryAction {
        &self.action
    }
}

impl ExecutionTransaction<'_> {
    /// Persists deterministic graph decisions and returns a bounded work batch.
    ///
    /// One forward pass through the validator's topological order derives branch
    /// selections, excluded operations, and merge results from already durable
    /// outputs. The returned keys cover ordinary admission and all recovery,
    /// release, failure-settlement, and intervention actions. Inputs resolve
    /// individually during admission, avoiding aggregate fanout copies here.
    ///
    /// # Errors
    ///
    /// Returns an error when a derived checked event cannot be constructed or
    /// durably appended.
    pub fn schedule_ready(
        &mut self,
        maximum_work: NonZeroUsize,
    ) -> Result<Vec<ReadyOperation>, TransactionError> {
        let dispatch_order = self.plan().dispatch_order().to_vec();
        let blocked_operations = self.durably_blocked_operations();
        let mut ready = Vec::with_capacity(maximum_work.get().min(dispatch_order.len()));

        for node in dispatch_order {
            match &node {
                PlanNodeKey::Operation { key } => {
                    if self.derive_skip(key)? {
                        continue;
                    }
                    if ready.len() == maximum_work.get() || self.operation_is_skipped(key) {
                        continue;
                    }
                    let operation = self
                        .plan()
                        .operation(key)
                        .ok_or(TransactionError::OperationMissing)?;
                    let action = self.next_action_with_blocked(key, &blocked_operations)?;
                    if !self.branch_is_active(&operation.branch_context)
                        && action != RecoveryAction::SettleFailureBeforeEffect
                    {
                        continue;
                    }
                    let is_initial_admission = action == RecoveryAction::Admit;
                    if action == RecoveryAction::None
                        || (is_initial_admission && self.check_operation_ready(key).is_err())
                    {
                        continue;
                    }
                    ready.push(ReadyOperation {
                        operation: key.clone(),
                        action,
                    });
                }
                PlanNodeKey::Decision { key } => self.derive_decision(key, &node)?,
                PlanNodeKey::Merge { key } => self.derive_merge(key, &node)?,
            }
        }

        Ok(ready)
    }

    fn derive_skip(&mut self, key: &ScopedOperationKey) -> Result<bool, TransactionError> {
        if self.operation_is_skipped(key)
            || !matches!(self.history(key)?.state(), OperationState::Pending)
        {
            return Ok(self.operation_is_skipped(key));
        }
        let operation = self
            .plan()
            .operation(key)
            .ok_or(TransactionError::OperationMissing)?;
        let excluded = operation.branch_context.iter().find_map(|membership| {
            self.selected_branch(&membership.decision)
                .filter(|selected| *selected != &membership.alternative)
                .map(|selected| (membership.decision.clone(), selected.clone(), key.clone()))
        });
        let Some((decision, selected_alternative, operation)) = excluded else {
            return Ok(false);
        };
        self.append(ExecutionEventKind::OperationSkipped {
            transaction: self.transaction().clone(),
            skipped: SkippedOperationRecord {
                operation,
                decision,
                selected_alternative,
            },
        })?;
        Ok(true)
    }

    fn derive_decision(
        &mut self,
        key: &ScopedOperationKey,
        node: &PlanNodeKey,
    ) -> Result<(), TransactionError> {
        if self.selected_branch(key).is_some() {
            return Ok(());
        }
        let decision = self
            .plan()
            .decision(key)
            .ok_or_else(|| scheduling_error("dispatch order names an unknown decision"))?;
        if !self.branch_is_active(&decision.branch_context) || !self.node_is_ready(node) {
            return Ok(());
        }
        let alternative = match self.selected_decision_alternative(decision) {
            Ok(alternative) => alternative,
            Err(_) => return Ok(()),
        };
        let selector = AbilityValue::new(self.result_value(&decision.selector.result)?.clone())
            .map_err(|source| {
                scheduling_error(format!("decision evidence is not bounded: {source}"))
            })?;
        self.append(ExecutionEventKind::BranchSelected {
            transaction: self.transaction().clone(),
            selection: BranchSelection {
                decision: key.clone(),
                alternative,
                selector_evidence: selector,
            },
        })
    }

    fn derive_merge(
        &mut self,
        key: &ScopedOperationKey,
        node: &PlanNodeKey,
    ) -> Result<(), TransactionError> {
        if self.merge_is_complete(key) {
            return Ok(());
        }
        let merge = self
            .plan()
            .merge(key)
            .ok_or_else(|| scheduling_error("dispatch order names an unknown merge"))?;
        if !self.branch_is_active(&merge.branch_context) || !self.node_is_ready(node) {
            return Ok(());
        }
        let Some(alternative) = self.selected_branch(&merge.decision).cloned() else {
            return Ok(());
        };
        match self.preflight_merge_outputs(merge, &alternative) {
            Ok(()) => {}
            Err(InputResolutionError::ResultUnavailable) => return Ok(()),
            Err(source) => {
                return Err(scheduling_error(format!(
                    "merged outputs exceed the checked aggregate bounds: {source}"
                )));
            }
        }
        let mut outputs = BTreeMap::new();
        for (port, merged_output) in &merge.outputs {
            let source = merged_output
                .alternatives
                .get(&alternative)
                .ok_or_else(|| scheduling_error("checked merge lacks its selected alternative"))?;
            let value = match self.result_value(source) {
                Ok(value) => value,
                Err(_) => return Ok(()),
            };
            let value = AbilityValue::new(value.clone()).map_err(|source| {
                scheduling_error(format!("merge output is not bounded: {source}"))
            })?;
            outputs.insert(port.clone(), value);
        }
        self.plan()
            .validate_merge_outputs(key, &outputs)
            .map_err(|source| {
                scheduling_error(format!(
                    "derived merge outputs violate the checked schema: {source}"
                ))
            })?;
        self.append(ExecutionEventKind::MergeCompleted {
            transaction: self.transaction().clone(),
            merged: MergeRecord {
                merge: key.clone(),
                decision: merge.decision.clone(),
                alternative,
                outputs,
            },
        })
    }
}

fn scheduling_error(reason: impl Into<String>) -> TransactionError {
    TransactionError::Scheduling {
        reason: reason.into(),
    }
}
