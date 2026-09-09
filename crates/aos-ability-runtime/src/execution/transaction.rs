//! Owning transaction boundary for checked plans, journals, and replay state.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use aos_ability_model::{
    compare_resource_ids, DecisionNode, DecisionPredicate, DependencyKind, LocalKey, MergeRecord,
    OperationId, PlanNodeKey, ResultProducerKey, RetryPolicy, ScopedOperationKey, TransactionId,
};
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use thiserror::Error;

use crate::adapter::{
    PlanRetentionReceipt, RootRetentionReceipt, TrustedPlanStore, TrustedRootStore,
};
use crate::execution::{
    ExecutionEvent, ExecutionEventKind, OperationHistory, OperationState, StateError,
};
use crate::journal::{FileJournal, JournalError, JournalLimits, JournalOpenResult};

/// Reports why a checked execution transaction could not be opened or advanced.
#[derive(Debug, Error)]
pub enum TransactionError {
    /// The checked graph still carries unresolved deployment obligations.
    #[error("checked effect plan is not executable")]
    PlanNotExecutable,
    /// Summing operation recovery limits exceeded the version-1 integer range.
    #[error("effect plan total recovery budget is not representable")]
    RecoveryBudgetOverflow,
    /// The checked plan requests retry delay that this runtime cannot yet enforce durably.
    #[error("nonzero retry backoff is not supported by this runtime")]
    UnsupportedRetryBackoff,
    /// The trusted closure store could not retain required recovery artifacts.
    #[error("recovery artifact retention failed: {0}")]
    RootRetention(#[source] anyhow::Error),
    /// The trusted plan store could not retain reloadable validation inputs.
    #[error("checked-plan retention failed: {0}")]
    PlanRetention(#[source] anyhow::Error),
    /// The protected journal could not be opened, recovered, or appended.
    #[error("execution journal failure: {0}")]
    Journal(#[from] JournalError),
    /// A digest-valid event violates the per-operation finite state machine.
    #[error(transparent)]
    State(#[from] StateError),
    /// A digest-valid event does not belong to this exact transaction and plan.
    #[error("invalid transaction history at record {sequence}: {reason}")]
    InvalidHistory {
        /// Identifies the rejected journal sequence.
        sequence: u64,
        /// Explains the violated transaction invariant.
        reason: String,
    },
    /// The requested operation is absent from the checked plan.
    #[error("operation is absent from the checked effect plan")]
    OperationMissing,
    /// Checked graph metadata or ready input derivation could not advance.
    #[error("execution scheduling failed: {reason}")]
    Scheduling {
        /// Explains the checked derivation failure.
        reason: String,
    },
    /// This process already owns a live token for the operation attempt.
    #[error("operation attempt already has a live reservation token")]
    OperationAlreadyLive,
    /// The process-local live-token registry was poisoned.
    #[error("live reservation registry is unavailable")]
    LiveRegistryPoisoned,
}

/// Owns the exact checked plan, protected journal, and its derived replay state.
///
/// This value is the live admission boundary. Callers cannot combine replay
/// state from one journal with a different checked plan or journal writer.
pub struct ExecutionTransaction<'plan> {
    plan: &'plan CheckedEffectPlan,
    journal: FileJournal<ExecutionEvent>,
    replay: ReplayState,
    retention: RootRetentionReceipt,
    plan_retention: PlanRetentionReceipt,
    session: Arc<()>,
    live_reservations: Arc<Mutex<BTreeSet<(ScopedOperationKey, std::num::NonZeroU32)>>>,
}

impl std::fmt::Debug for ExecutionTransaction<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionTransaction")
            .field("plan", &self.plan.id())
            .field("transaction", &self.replay.transaction)
            .field("elapsed_millis", &self.replay.elapsed_millis)
            .field("journal", &self.journal)
            .finish_non_exhaustive()
    }
}

impl<'plan> ExecutionTransaction<'plan> {
    /// Opens and validates the complete journal against one checked plan.
    ///
    /// An empty journal is initialized with the exact plan, retained artifact
    /// closures, and the aggregate finite recovery budget before this function
    /// returns. Existing records are checked in one pass against every plan
    /// operation, decision, branch, and merge identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is not executable, requests unsupported
    /// retry backoff, its aggregate budget overflows, the journal is unavailable
    /// or corrupt, or a digest-valid record violates the checked plan or finite
    /// state machines.
    pub fn open<RootStore>(
        plan: &'plan CheckedEffectPlan,
        transaction: TransactionId,
        path: impl AsRef<Path>,
        limits: JournalLimits,
        root_store: &mut RootStore,
    ) -> Result<Self, TransactionError>
    where
        RootStore: TrustedRootStore + TrustedPlanStore,
    {
        if !plan.is_executable() {
            return Err(TransactionError::PlanNotExecutable);
        }
        if plan.operations().iter().any(|operation| {
            matches!(
                operation.recovery.retry,
                RetryPolicy::Bounded {
                    backoff_millis,
                    ..
                } if backoff_millis != 0
            )
        }) {
            return Err(TransactionError::UnsupportedRetryBackoff);
        }

        let total_recovery_millis = aggregate_recovery_budget(plan)?;
        let runtime_artifacts = required_runtime_artifacts(plan);
        let retained_roots = retained_roots(&runtime_artifacts);
        let plan_retention = root_store
            .retain_plan(&transaction, plan)
            .map_err(|source| TransactionError::PlanRetention(anyhow::Error::new(source)))?;
        if plan_retention.transaction() != &transaction || plan_retention.plan() != plan.id() {
            return Err(invalid(
                1,
                "plan-store receipt does not match the transaction and checked plan",
            ));
        }
        let opened: JournalOpenResult<ExecutionEvent> = FileJournal::open(path, limits)?;
        let mut replay = ReplayState::new(
            plan,
            transaction.clone(),
            plan_retention.bundle(),
            retained_roots.clone(),
            total_recovery_millis,
        );

        for record in opened.recovery.records() {
            replay.apply(plan, record.sequence(), record.body().body())?;
        }

        let retention = root_store
            .retain(&transaction, &runtime_artifacts)
            .map_err(|source| TransactionError::RootRetention(anyhow::Error::new(source)))?;
        if retention.transaction() != &transaction || retention.roots() != retained_roots {
            return Err(invalid(
                replay.next_sequence,
                "root-store receipt does not match the transaction and checked artifacts",
            ));
        }

        let mut execution = Self {
            plan,
            journal: opened.journal,
            replay,
            retention,
            plan_retention,
            session: Arc::new(()),
            live_reservations: Arc::new(Mutex::new(BTreeSet::new())),
        };
        if execution.replay.next_sequence == 1 {
            execution.append(ExecutionEventKind::TransactionPlanned {
                transaction,
                plan: plan.id(),
                plan_bundle: execution.plan_retention.bundle(),
                retained_roots,
                total_recovery_millis,
            })?;
        } else if !execution.replay.planned {
            return Err(invalid(1, "first record is not the transaction plan root"));
        }

        Ok(execution)
    }

    /// Returns the exact checked plan bound to this journal writer.
    #[must_use]
    pub const fn plan(&self) -> &'plan CheckedEffectPlan {
        self.plan
    }

    /// Returns the durable execution allocation identity.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.replay.transaction
    }

    /// Returns the trusted receipt that gates admission for this open process.
    #[must_use]
    pub const fn retention(&self) -> &RootRetentionReceipt {
        &self.retention
    }

    /// Returns the trusted receipt proving the complete checked plan is reloadable.
    #[must_use]
    pub const fn plan_retention(&self) -> &PlanRetentionReceipt {
        &self.plan_retention
    }

    pub(crate) const fn session(&self) -> &Arc<()> {
        &self.session
    }

    /// Returns the conservative sum of persisted operation recovery time.
    #[must_use]
    pub const fn elapsed_millis(&self) -> u64 {
        self.replay.elapsed_millis
    }

    /// Returns the aggregate finite recovery budget rooted in the journal.
    #[must_use]
    pub const fn total_recovery_millis(&self) -> u64 {
        self.replay.total_recovery_millis
    }

    /// Returns replay state for one exact checked operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is absent from the checked plan.
    pub fn history(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<&OperationHistory, TransactionError> {
        self.replay
            .operations
            .get(operation)
            .ok_or(TransactionError::OperationMissing)
    }

    /// Selects the checked next action for one operation's durable state.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation or its checked outcome descriptor is
    /// unavailable from this exact plan.
    pub fn next_action(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<crate::execution::RecoveryAction, TransactionError> {
        let checked = self
            .plan
            .operation(operation)
            .ok_or(TransactionError::OperationMissing)?;
        let history = self.history(operation)?;
        let action = history.recovery_action(
            &checked.recovery.retry,
            checked.deadline.total_recovery_millis.get(),
        );
        if matches!(
            action,
            crate::execution::RecoveryAction::ReconcileBeforeRetry { .. }
        ) {
            let semantics = self
                .plan
                .operation_outcome_semantics(checked)
                .map_err(|source| TransactionError::Scheduling {
                    reason: format!("operation outcome semantics are unavailable: {source}"),
                })?;
            if semantics.indeterminate
                == aos_ability_model::IndeterminateSemantics::InterventionRequired
            {
                return Ok(crate::execution::RecoveryAction::InterventionRequired);
            }
        }
        Ok(action)
    }

    pub(crate) fn merged_output(
        &self,
        merge: &ScopedOperationKey,
        output: &LocalKey,
    ) -> Option<&aos_ability_model::AbilityValue> {
        self.replay
            .merged
            .get(merge)
            .and_then(|merged| merged.outputs.get(output))
    }

    pub(crate) fn selected_branch(&self, decision: &ScopedOperationKey) -> Option<&LocalKey> {
        self.replay.selections.get(decision)
    }

    pub(crate) fn operation_is_skipped(&self, operation: &ScopedOperationKey) -> bool {
        self.replay.skipped.contains(operation)
    }

    pub(crate) fn merge_is_complete(&self, merge: &ScopedOperationKey) -> bool {
        self.replay.merged.contains_key(merge)
    }

    pub(crate) fn branch_is_active(&self, context: &[aos_ability_model::BranchMembership]) -> bool {
        branch_context_selected(context, &self.replay.selections)
    }

    pub(crate) fn node_is_ready(&self, node: &PlanNodeKey) -> bool {
        ensure_node_predecessors(self.plan, &self.replay, node, self.replay.next_sequence).is_ok()
    }

    pub(crate) fn selected_decision_alternative(
        &self,
        decision: &DecisionNode,
    ) -> Result<LocalKey, TransactionError> {
        selected_alternative(self.plan, &self.replay, decision, self.replay.next_sequence)
    }

    pub(crate) fn result_value(
        &self,
        reference: &aos_ability_model::OperationResultReference,
    ) -> Result<&serde_json::Value, TransactionError> {
        resolve_result_json(&self.replay, reference, self.replay.next_sequence)
    }

    pub(crate) fn provider_assignment_for(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<Option<aos_ability_model::ProviderAssignment>, TransactionError> {
        let operation = self
            .plan
            .operation(operation)
            .ok_or(TransactionError::OperationMissing)?;
        let Some(readiness) = self.plan.provider_readiness(&operation.binding) else {
            return Ok(None);
        };
        let reference = aos_ability_model::OperationResultReference {
            producer: ResultProducerKey::Operation {
                key: readiness.producer.clone(),
            },
            output: readiness.output.clone(),
        };
        let value = resolve_result_json(&self.replay, &reference, self.replay.next_sequence)?;
        let value = aos_ability_model::AbilityValue::new(value.clone()).map_err(|source| {
            invalid(
                self.replay.next_sequence,
                format!("provider readiness value is not bounded: {source}"),
            )
        })?;
        self.plan
            .validate_provider_assignment(readiness, &value)
            .map(Some)
            .map_err(|source| {
                invalid(
                    self.replay.next_sequence,
                    format!("provider readiness does not match the planned binding: {source}"),
                )
            })
    }

    pub(crate) fn check_operation_ready(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<(), TransactionError> {
        self.provider_assignment_for(operation)?;
        ensure_operation_ready(
            self.plan,
            &self.replay,
            operation,
            self.replay.next_sequence,
        )
    }

    pub(crate) fn claim_live_reservation(
        &self,
        operation: ScopedOperationKey,
        attempt: std::num::NonZeroU32,
    ) -> Result<LiveReservationGuard, TransactionError> {
        let key = (operation, attempt);
        let mut live = self
            .live_reservations
            .lock()
            .map_err(|_| TransactionError::LiveRegistryPoisoned)?;
        if !live.insert(key.clone()) {
            return Err(TransactionError::OperationAlreadyLive);
        }
        drop(live);

        Ok(LiveReservationGuard {
            key,
            registry: Arc::clone(&self.live_reservations),
            remove_on_drop: true,
        })
    }

    pub(crate) fn append(&mut self, event: ExecutionEventKind) -> Result<(), TransactionError> {
        let sequence = self.replay.next_sequence;
        self.replay.validate(self.plan, sequence, &event)?;

        let event = ExecutionEvent::new(event);
        let record = self.journal.append(&event)?;
        if record.sequence() != sequence {
            return Err(invalid(
                sequence,
                "journal sequence diverged from transaction replay",
            ));
        }
        self.replay.commit(self.plan, sequence, event.body())?;
        Ok(())
    }

    pub(crate) fn ensure_journal_capacity(
        &mut self,
        additional_records: usize,
    ) -> Result<(), TransactionError> {
        self.journal.ensure_capacity(additional_records)?;
        Ok(())
    }
}

/// Releases one process-local live-token claim when its owner is dropped.
#[derive(Debug)]
pub(crate) struct LiveReservationGuard {
    key: (ScopedOperationKey, std::num::NonZeroU32),
    registry: Arc<Mutex<BTreeSet<(ScopedOperationKey, std::num::NonZeroU32)>>>,
    remove_on_drop: bool,
}

impl LiveReservationGuard {
    pub(crate) fn retain_claim_on_drop(&mut self) {
        self.remove_on_drop = false;
    }

    pub(crate) fn release_claim(&mut self) {
        if let Ok(mut live) = self.registry.lock() {
            live.remove(&self.key);
        }
        self.remove_on_drop = false;
    }
}

impl Drop for LiveReservationGuard {
    fn drop(&mut self) {
        if self.remove_on_drop {
            self.release_claim();
        }
    }
}

#[derive(Debug)]
struct ReplayState {
    transaction: TransactionId,
    plan_bundle: Sha256Digest,
    retained_roots: Vec<Sha256Digest>,
    total_recovery_millis: u64,
    operations: BTreeMap<ScopedOperationKey, OperationHistory>,
    incoming_edges: BTreeMap<PlanNodeKey, Vec<usize>>,
    selections: BTreeMap<ScopedOperationKey, LocalKey>,
    skipped: BTreeSet<ScopedOperationKey>,
    merged: BTreeMap<ScopedOperationKey, MergeRecord>,
    elapsed_millis: u64,
    next_sequence: u64,
    planned: bool,
}

impl ReplayState {
    fn new(
        plan: &CheckedEffectPlan,
        transaction: TransactionId,
        plan_bundle: Sha256Digest,
        retained_roots: Vec<Sha256Digest>,
        total_recovery_millis: u64,
    ) -> Self {
        let operations = plan
            .operations()
            .iter()
            .map(|operation| {
                let id = OperationId {
                    plan: plan.id(),
                    operation: operation.key.clone(),
                };
                (
                    operation.key.clone(),
                    OperationHistory::new(transaction.clone(), id),
                )
            })
            .collect();
        let mut incoming_edges: BTreeMap<PlanNodeKey, Vec<usize>> = BTreeMap::new();
        for (index, edge) in plan.edges().iter().enumerate() {
            incoming_edges
                .entry(edge.to.clone())
                .or_default()
                .push(index);
        }

        Self {
            transaction,
            plan_bundle,
            retained_roots,
            total_recovery_millis,
            operations,
            incoming_edges,
            selections: BTreeMap::new(),
            skipped: BTreeSet::new(),
            merged: BTreeMap::new(),
            elapsed_millis: 0,
            next_sequence: 1,
            planned: false,
        }
    }

    fn apply(
        &mut self,
        plan: &CheckedEffectPlan,
        sequence: u64,
        event: &ExecutionEventKind,
    ) -> Result<(), TransactionError> {
        self.validate(plan, sequence, event)?;
        self.commit(plan, sequence, event)
    }

    fn validate(
        &self,
        plan: &CheckedEffectPlan,
        sequence: u64,
        event: &ExecutionEventKind,
    ) -> Result<(), TransactionError> {
        if sequence != self.next_sequence {
            return Err(invalid(sequence, "journal sequence is not contiguous"));
        }
        if event.transaction() != &self.transaction {
            return Err(invalid(sequence, "record belongs to another transaction"));
        }
        if !self.planned && !matches!(event, ExecutionEventKind::TransactionPlanned { .. }) {
            return Err(invalid(
                sequence,
                "first record is not the transaction plan root",
            ));
        }

        match event {
            ExecutionEventKind::TransactionPlanned {
                plan: recorded_plan,
                plan_bundle,
                retained_roots,
                total_recovery_millis,
                ..
            } => {
                if self.planned {
                    return Err(invalid(sequence, "transaction was planned more than once"));
                }
                if recorded_plan != &plan.id() {
                    return Err(invalid(
                        sequence,
                        "record names another checked effect plan",
                    ));
                }
                if plan_bundle != &self.plan_bundle {
                    return Err(invalid(
                        sequence,
                        "record names another protected checked-plan bundle",
                    ));
                }
                if retained_roots != &self.retained_roots {
                    return Err(invalid(
                        sequence,
                        "retained roots do not match the checked plan artifacts",
                    ));
                }
                if total_recovery_millis != &self.total_recovery_millis {
                    return Err(invalid(
                        sequence,
                        "recovery budget does not match the checked plan",
                    ));
                }
            }
            ExecutionEventKind::BranchSelected { selection, .. } => {
                let decision = plan.decision(&selection.decision).ok_or_else(|| {
                    invalid(sequence, "branch selection names an unknown decision")
                })?;
                if !branch_context_selected(&decision.branch_context, &self.selections) {
                    return Err(invalid(sequence, "decision branch context is not active"));
                }
                if self.selections.contains_key(&selection.decision) {
                    return Err(invalid(sequence, "decision was selected more than once"));
                }
                ensure_node_predecessors(
                    plan,
                    self,
                    &PlanNodeKey::Decision {
                        key: selection.decision.clone(),
                    },
                    sequence,
                )?;
                let expected = selected_alternative(plan, self, decision, sequence)?;
                if expected != selection.alternative {
                    return Err(invalid(
                        sequence,
                        "branch selection does not match its completed selector value",
                    ));
                }
                let selector = resolve_result_json(self, &decision.selector.result, sequence)?;
                if selection.selector_evidence.as_json() != selector {
                    return Err(invalid(
                        sequence,
                        "branch selector evidence does not equal the completed producer value",
                    ));
                }
            }
            ExecutionEventKind::OperationSkipped { skipped, .. } => {
                let operation = plan
                    .operation(&skipped.operation)
                    .ok_or_else(|| invalid(sequence, "skip record names an unknown operation"))?;
                let selected = self.selections.get(&skipped.decision).ok_or_else(|| {
                    invalid(
                        sequence,
                        "operation was skipped before its branch selection",
                    )
                })?;
                if selected != &skipped.selected_alternative {
                    return Err(invalid(
                        sequence,
                        "skip record disagrees with the durable branch selection",
                    ));
                }
                let excluded = operation.branch_context.iter().any(|membership| {
                    membership.decision == skipped.decision
                        && membership.alternative != skipped.selected_alternative
                });
                if !excluded {
                    return Err(invalid(
                        sequence,
                        "selected branch does not exclude the recorded operation",
                    ));
                }
                let history = self.operations.get(&skipped.operation).ok_or_else(|| {
                    invalid(sequence, "skip record has no operation replay state")
                })?;
                if !matches!(history.state(), crate::execution::OperationState::Pending) {
                    return Err(invalid(sequence, "an active operation cannot be skipped"));
                }
                if self.skipped.contains(&skipped.operation) {
                    return Err(invalid(sequence, "operation was skipped more than once"));
                }
            }
            ExecutionEventKind::MergeCompleted { merged, .. } => {
                let merge = plan
                    .merge(&merged.merge)
                    .ok_or_else(|| invalid(sequence, "merge record names an unknown merge"))?;
                if merge.decision != merged.decision {
                    return Err(invalid(sequence, "merge record names the wrong decision"));
                }
                let selected = self.selections.get(&merged.decision).ok_or_else(|| {
                    invalid(sequence, "merge completed before its branch selection")
                })?;
                if selected != &merged.alternative {
                    return Err(invalid(
                        sequence,
                        "merge record disagrees with the durable branch selection",
                    ));
                }
                if !branch_context_selected(&merge.branch_context, &self.selections) {
                    return Err(invalid(sequence, "merge branch context is not active"));
                }
                ensure_node_predecessors(
                    plan,
                    self,
                    &PlanNodeKey::Merge {
                        key: merged.merge.clone(),
                    },
                    sequence,
                )?;
                if !merge.outputs.keys().eq(merged.outputs.keys()) {
                    return Err(invalid(
                        sequence,
                        "merge record output ports do not match the checked merge",
                    ));
                }
                for (port, output) in &merge.outputs {
                    let source = output.alternatives.get(selected).ok_or_else(|| {
                        invalid(sequence, "checked merge lacks its selected input source")
                    })?;
                    let source_value = resolve_result_json(self, source, sequence)?;
                    let recorded = merged.outputs.get(port).ok_or_else(|| {
                        invalid(sequence, "merge record omits a checked output port")
                    })?;
                    if recorded.as_json() != source_value {
                        return Err(invalid(
                            sequence,
                            "merge output does not equal its selected producer value",
                        ));
                    }
                }
                if self.merged.contains_key(&merged.merge) {
                    return Err(invalid(sequence, "merge completed more than once"));
                }
            }
            _ => {
                let operation_id = event.operation().ok_or_else(|| {
                    invalid(sequence, "transaction event has no checked plan node")
                })?;
                if operation_id.plan != plan.id() {
                    return Err(invalid(sequence, "operation names another checked plan"));
                }
                if self.skipped.contains(&operation_id.operation) {
                    return Err(invalid(
                        sequence,
                        "a skipped operation cannot become active",
                    ));
                }
                validate_checked_operation_event(plan, operation_id, event, sequence)?;
                if matches!(event, ExecutionEventKind::OperationAdmitted { .. }) {
                    ensure_operation_ready(plan, self, &operation_id.operation, sequence)?;
                }
                let history = self
                    .operations
                    .get(&operation_id.operation)
                    .ok_or_else(|| invalid(sequence, "event names an unknown operation"))?;
                let mut next_history = history.clone();
                next_history.apply_event(sequence, event)?;
                if begins_new_work(event) && self.elapsed_millis >= self.total_recovery_millis {
                    return Err(invalid(
                        sequence,
                        "aggregate recovery budget is exhausted before new work",
                    ));
                }
            }
        }

        Ok(())
    }

    fn commit(
        &mut self,
        _plan: &CheckedEffectPlan,
        sequence: u64,
        event: &ExecutionEventKind,
    ) -> Result<(), TransactionError> {
        match event {
            ExecutionEventKind::TransactionPlanned { .. } => {
                for history in self.operations.values_mut() {
                    history.apply_event(sequence, event)?;
                }
                self.planned = true;
            }
            ExecutionEventKind::BranchSelected { selection, .. } => {
                self.selections
                    .insert(selection.decision.clone(), selection.alternative.clone());
            }
            ExecutionEventKind::OperationSkipped { skipped, .. } => {
                self.skipped.insert(skipped.operation.clone());
            }
            ExecutionEventKind::MergeCompleted { merged, .. } => {
                self.merged.insert(merged.merge.clone(), merged.clone());
            }
            _ => {
                let operation_id = event.operation().ok_or_else(|| {
                    invalid(sequence, "transaction event has no checked plan node")
                })?;
                let history = self
                    .operations
                    .get_mut(&operation_id.operation)
                    .ok_or_else(|| invalid(sequence, "event names an unknown operation"))?;
                let previous_elapsed = history.elapsed_millis();
                history.apply_event(sequence, event)?;
                self.elapsed_millis = self
                    .elapsed_millis
                    .saturating_sub(previous_elapsed)
                    .saturating_add(history.elapsed_millis());
            }
        }

        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid(sequence, "journal sequence number exhausted"))?;
        Ok(())
    }
}

fn validate_checked_operation_event(
    plan: &CheckedEffectPlan,
    operation_id: &OperationId,
    event: &ExecutionEventKind,
    sequence: u64,
) -> Result<(), TransactionError> {
    let operation = plan
        .operation(&operation_id.operation)
        .ok_or_else(|| invalid(sequence, "event names an unknown operation"))?;

    let maximum_attempt = match operation.recovery.retry {
        RetryPolicy::Disabled => 1,
        RetryPolicy::Bounded { max_attempts, .. } => max_attempts.get(),
    };
    let outcome = plan
        .operation_outcome_semantics(operation)
        .map_err(|source| {
            invalid(
                sequence,
                format!("operation outcome semantics are unavailable: {source}"),
            )
        })?;
    if event_attempt(event).is_some_and(|attempt| attempt.get() > maximum_attempt) {
        return Err(invalid(
            sequence,
            "operation attempt exceeds the checked retry policy",
        ));
    }

    let checked_timeout = operation.deadline.attempt_timeout_millis.get();
    match event {
        ExecutionEventKind::EffectRejectedBeforeEffect { .. }
        | ExecutionEventKind::ReconciliationObserved {
            result: crate::execution::ReconciliationResult::RejectedBeforeEffect,
            ..
        }
        | ExecutionEventKind::CancellationObserved {
            result: crate::execution::CancellationResult::RejectedBeforeEffect,
            ..
        } if !outcome.supports_rejected_before_effect => {
            return Err(invalid(
                sequence,
                "provider claimed rejection-before-effect without checked support",
            ));
        }
        ExecutionEventKind::ReconciliationIntent { .. }
        | ExecutionEventKind::ReconciliationObserved { .. }
            if outcome.indeterminate
                == aos_ability_model::IndeterminateSemantics::InterventionRequired =>
        {
            return Err(invalid(
                sequence,
                "provider contract requires intervention instead of reconciliation",
            ));
        }
        ExecutionEventKind::EffectIntent {
            attempt_timeout_millis,
            ..
        } if *attempt_timeout_millis > checked_timeout => {
            return Err(invalid(
                sequence,
                "effect timeout exceeds the checked operation deadline",
            ));
        }
        ExecutionEventKind::ReconciliationIntent {
            call_timeout_millis,
            ..
        } => {
            if operation.recovery.reconcile.is_none() {
                return Err(invalid(
                    sequence,
                    "reconciliation intent lacks a checked reconciliation method",
                ));
            }
            if *call_timeout_millis > checked_timeout {
                return Err(invalid(
                    sequence,
                    "reconciliation timeout exceeds the checked operation deadline",
                ));
            }
        }
        ExecutionEventKind::CancellationRequested {
            call_timeout_millis,
            ..
        } => {
            if operation.recovery.cancel.is_none() {
                return Err(invalid(
                    sequence,
                    "cancellation intent lacks a checked cancellation method",
                ));
            }
            if *call_timeout_millis > checked_timeout {
                return Err(invalid(
                    sequence,
                    "cancellation timeout exceeds the checked operation deadline",
                ));
            }
        }
        _ => {}
    }

    if let ExecutionEventKind::OperationAdmitted { resources, .. } = event {
        let mut expected: Vec<_> = operation
            .accesses
            .iter()
            .map(|access| access.resource.clone())
            .collect();
        expected.sort_by(compare_resource_ids);
        expected.dedup();
        if resources != &expected {
            return Err(invalid(
                sequence,
                "admitted resources do not equal the checked operation accesses",
            ));
        }
    }

    let completed = match event {
        ExecutionEventKind::EffectCompleted {
            evidence, outputs, ..
        } => Some((evidence, outputs)),
        ExecutionEventKind::ReconciliationObserved {
            result: crate::execution::ReconciliationResult::Completed,
            evidence,
            outputs,
            ..
        }
        | ExecutionEventKind::CancellationObserved {
            result: crate::execution::CancellationResult::Completed,
            evidence,
            outputs,
            ..
        } => Some((evidence, outputs)),
        _ => None,
    };
    if let Some((evidence, outputs)) = completed {
        plan.validate_completion_evidence(operation, evidence)
            .map_err(|source| {
                invalid(
                    sequence,
                    format!("completion evidence violates the checked schema: {source}"),
                )
            })?;
        plan.validate_operation_outputs(operation, outputs)
            .map_err(|source| {
                invalid(
                    sequence,
                    format!("operation output set violates the checked schema: {source}"),
                )
            })?;
    }

    let observation = match event {
        ExecutionEventKind::EffectRejectedBeforeEffect { evidence, .. }
        | ExecutionEventKind::EffectIndeterminate { evidence, .. } => Some(evidence),
        ExecutionEventKind::ReconciliationObserved {
            result, evidence, ..
        } if !matches!(result, crate::execution::ReconciliationResult::Completed) => Some(evidence),
        ExecutionEventKind::CancellationObserved {
            result, evidence, ..
        } if !matches!(result, crate::execution::CancellationResult::Completed) => Some(evidence),
        _ => None,
    };
    if let Some(evidence) = observation {
        plan.validate_observation_evidence(operation, evidence)
            .map_err(|source| {
                invalid(
                    sequence,
                    format!("observation evidence violates the checked schema: {source}"),
                )
            })?;
    }

    match event {
        ExecutionEventKind::ReconciliationObserved {
            result, outputs, ..
        } => {
            let completed = matches!(result, crate::execution::ReconciliationResult::Completed);
            if !completed && !outputs.is_empty() {
                return Err(invalid(
                    sequence,
                    "non-completing reconciliation carries successful outputs",
                ));
            }
        }
        ExecutionEventKind::CancellationObserved {
            result, outputs, ..
        } => {
            let completed = matches!(result, crate::execution::CancellationResult::Completed);
            if !completed && !outputs.is_empty() {
                return Err(invalid(
                    sequence,
                    "non-completing cancellation carries successful outputs",
                ));
            }
        }
        _ => {}
    }

    if begins_new_work(event)
        && event
            .elapsed_millis()
            .is_some_and(|elapsed| elapsed >= operation.deadline.total_recovery_millis.get())
    {
        return Err(invalid(
            sequence,
            "operation recovery budget is exhausted before new work",
        ));
    }

    Ok(())
}

fn begins_new_work(event: &ExecutionEventKind) -> bool {
    matches!(
        event,
        ExecutionEventKind::OperationAdmitted { .. }
            | ExecutionEventKind::EffectIntent { .. }
            | ExecutionEventKind::ReconciliationIntent { .. }
            | ExecutionEventKind::CancellationRequested { .. }
    )
}

fn event_attempt(event: &ExecutionEventKind) -> Option<std::num::NonZeroU32> {
    match event {
        ExecutionEventKind::OperationAdmitted { attempt, .. }
        | ExecutionEventKind::EffectIntent { attempt, .. }
        | ExecutionEventKind::EffectCompleted { attempt, .. }
        | ExecutionEventKind::EffectRejectedBeforeEffect { attempt, .. }
        | ExecutionEventKind::EffectDispatchAborted { attempt, .. }
        | ExecutionEventKind::EffectIndeterminate { attempt, .. }
        | ExecutionEventKind::ReconciliationIntent { attempt, .. }
        | ExecutionEventKind::ReconciliationObserved { attempt, .. }
        | ExecutionEventKind::CancellationRequested { attempt, .. }
        | ExecutionEventKind::CancellationObserved { attempt, .. } => Some(*attempt),
        ExecutionEventKind::OperationSettledFailure { attempt, .. } => *attempt,
        ExecutionEventKind::TransactionPlanned { .. }
        | ExecutionEventKind::BranchSelected { .. }
        | ExecutionEventKind::OperationSkipped { .. }
        | ExecutionEventKind::MergeCompleted { .. }
        | ExecutionEventKind::OwnershipTransferred { .. }
        | ExecutionEventKind::ResourcesReleased { .. } => None,
    }
}

fn ensure_operation_ready(
    plan: &CheckedEffectPlan,
    replay: &ReplayState,
    operation_key: &ScopedOperationKey,
    sequence: u64,
) -> Result<(), TransactionError> {
    let operation = plan
        .operation(operation_key)
        .ok_or_else(|| invalid(sequence, "admission names an unknown operation"))?;
    if !branch_context_selected(&operation.branch_context, &replay.selections) {
        return Err(invalid(
            sequence,
            "operation branch context is not durably selected",
        ));
    }
    // The owning transaction resolves and authenticates planned-provider
    // assignment evidence before calling this graph readiness check.
    ensure_node_predecessors(
        plan,
        replay,
        &PlanNodeKey::Operation {
            key: operation_key.clone(),
        },
        sequence,
    )
}

fn ensure_node_predecessors(
    plan: &CheckedEffectPlan,
    replay: &ReplayState,
    node: &PlanNodeKey,
    sequence: u64,
) -> Result<(), TransactionError> {
    let incoming = replay
        .incoming_edges
        .get(node)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for edge in incoming.iter().map(|index| &plan.edges()[*index]) {
        let ready = match edge.kind {
            DependencyKind::Retention | DependencyKind::Communication => true,
            DependencyKind::OrderingOnly => node_is_settled(replay, &edge.from),
            // A merge validates only the producer selected by its decision;
            // unselected BranchMerge predecessors are intentionally skipped.
            DependencyKind::BranchMerge => true,
            DependencyKind::Data
            | DependencyKind::RequiredSuccess
            | DependencyKind::Readiness
            | DependencyKind::BranchGuard => node_succeeded(replay, &edge.from),
        };
        if !ready {
            return Err(invalid(
                sequence,
                "plan node predecessor has not reached its required durable outcome",
            ));
        }
    }
    Ok(())
}

fn node_succeeded(replay: &ReplayState, node: &PlanNodeKey) -> bool {
    match node {
        PlanNodeKey::Operation { key } => replay
            .operations
            .get(key)
            .is_some_and(|history| matches!(history.state(), OperationState::Completed { .. })),
        PlanNodeKey::Decision { key } => replay.selections.contains_key(key),
        PlanNodeKey::Merge { key } => replay.merged.contains_key(key),
    }
}

fn node_is_settled(replay: &ReplayState, node: &PlanNodeKey) -> bool {
    match node {
        PlanNodeKey::Operation { key } => replay.operations.get(key).is_some_and(|history| {
            matches!(
                history.state(),
                OperationState::Completed { .. } | OperationState::SettledFailure { .. }
            )
        }),
        PlanNodeKey::Decision { key } => replay.selections.contains_key(key),
        PlanNodeKey::Merge { key } => replay.merged.contains_key(key),
    }
}

fn branch_context_selected(
    context: &[aos_ability_model::BranchMembership],
    selections: &BTreeMap<ScopedOperationKey, LocalKey>,
) -> bool {
    context
        .iter()
        .all(|membership| selections.get(&membership.decision) == Some(&membership.alternative))
}

fn selected_alternative(
    _plan: &CheckedEffectPlan,
    replay: &ReplayState,
    decision: &DecisionNode,
    sequence: u64,
) -> Result<LocalKey, TransactionError> {
    let selector = resolve_result_json(replay, &decision.selector.result, sequence)?;
    let selected_value = match &decision.selector.tag_field {
        Some(field) => selector
            .as_object()
            .and_then(|object| object.get(field.as_str()))
            .ok_or_else(|| {
                invalid(
                    sequence,
                    "tagged decision selector evidence omits its discriminator",
                )
            })?,
        None => selector,
    };

    let mut matching =
        decision
            .alternatives
            .iter()
            .filter(|alternative| match &alternative.predicate {
                DecisionPredicate::Boolean { value } => selected_value.as_bool() == Some(*value),
                DecisionPredicate::Tag { value } => selected_value.as_str() == Some(value.as_str()),
            });
    let selected = matching
        .next()
        .ok_or_else(|| invalid(sequence, "decision selector matches no checked alternative"))?;
    if matching.next().is_some() {
        return Err(invalid(
            sequence,
            "decision selector matches more than one checked alternative",
        ));
    }
    Ok(selected.key.clone())
}

fn resolve_result_json<'replay>(
    replay: &'replay ReplayState,
    reference: &aos_ability_model::OperationResultReference,
    sequence: u64,
) -> Result<&'replay serde_json::Value, TransactionError> {
    match &reference.producer {
        ResultProducerKey::Operation { key } => {
            let history = replay
                .operations
                .get(key)
                .ok_or_else(|| invalid(sequence, "result reference names an unknown operation"))?;
            let OperationState::Completed { outputs, .. } = history.state() else {
                return Err(invalid(
                    sequence,
                    "result reference producer has not completed successfully",
                ));
            };
            outputs
                .get(&reference.output)
                .map(aos_ability_model::AbilityValue::as_json)
                .ok_or_else(|| {
                    invalid(
                        sequence,
                        "operation completion evidence omits the referenced output",
                    )
                })
        }
        ResultProducerKey::Merge { key } => replay
            .merged
            .get(key)
            .and_then(|merged| merged.outputs.get(&reference.output))
            .map(aos_ability_model::AbilityValue::as_json)
            .ok_or_else(|| {
                invalid(
                    sequence,
                    "result reference names an incomplete merge output",
                )
            }),
    }
}

fn aggregate_recovery_budget(plan: &CheckedEffectPlan) -> Result<u64, TransactionError> {
    plan.operations()
        .iter()
        .try_fold(0_u64, |total, operation| {
            total
                .checked_add(operation.deadline.total_recovery_millis.get())
                .ok_or(TransactionError::RecoveryBudgetOverflow)
        })
}

fn required_runtime_artifacts(
    plan: &CheckedEffectPlan,
) -> Vec<aos_ability_model::ArtifactReference> {
    plan.required_runtime_artifacts().to_vec()
}

fn retained_roots(artifacts: &[aos_ability_model::ArtifactReference]) -> Vec<Sha256Digest> {
    let mut roots: Vec<_> = artifacts.iter().map(|artifact| artifact.closure).collect();
    roots.sort_unstable();
    roots.dedup();
    roots
}

fn invalid(sequence: u64, reason: impl Into<String>) -> TransactionError {
    TransactionError::InvalidHistory {
        sequence,
        reason: reason.into(),
    }
}
