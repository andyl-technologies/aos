//! Replay validation and next-action selection for one finite operation.

use std::num::NonZeroU32;

use std::cmp::Ordering;
use std::collections::BTreeMap;

use aos_ability_model::{
    AbilityValue, LocalKey, OperationId, ResourceId, RetryPolicy, TransactionId,
    compare_resource_ids,
};
use aos_contract::Sha256Digest;
use thiserror::Error;

use crate::execution::DispatchAbortReason;
use crate::execution::event::{CancellationResult, ExecutionEventKind, ReconciliationResult};
use crate::journal::JournalRecord;

/// Describes the durable state of one operation without discarding history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationState {
    /// The checked plan is rooted but this operation has not acquired resources.
    Pending,
    /// Current authority and resource ownership were admitted for this attempt.
    Admitted { attempt: NonZeroU32 },
    /// Effect intent is durable and the external outcome may be unknown.
    IntentDurable { attempt: NonZeroU32 },
    /// Completion evidence is durable and required-success dependents may run.
    Completed {
        attempt: NonZeroU32,
        evidence: AbilityValue,
        outputs: BTreeMap<LocalKey, AbilityValue>,
    },
    /// The provider proved that the attempt caused no external effect.
    RejectedBeforeEffect {
        attempt: NonZeroU32,
        evidence: AbilityValue,
    },
    /// The runtime proved that it never crossed the external effect boundary.
    DispatchAborted {
        attempt: NonZeroU32,
        reason: DispatchAbortReason,
    },
    /// An external effect may have occurred and cannot be retried blindly.
    Indeterminate {
        attempt: NonZeroU32,
        evidence: AbilityValue,
    },
    /// Reconciliation intent is durable for the unresolved attempt.
    ReconciliationIntentDurable { attempt: NonZeroU32 },
    /// Provider observation explicitly authorized a bounded new attempt.
    RetryAuthorized {
        attempt: NonZeroU32,
        evidence: AbilityValue,
    },
    /// Cancellation intent is durable but its actual outcome is unresolved.
    CancellationIntentDurable { attempt: NonZeroU32 },
    /// The unresolved effect requires an operator decision.
    InterventionRequired {
        attempt: NonZeroU32,
        evidence: AbilityValue,
    },
    /// The operation settled without a possible live effect or successful target.
    SettledFailure {
        attempt: Option<NonZeroU32>,
        evidence: AbilityValue,
    },
}

/// Selects the only safe next action after replaying durable history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// Acquires current authority and resource ownership for the first attempt.
    Admit,
    /// Persists and dispatches intent for an admitted attempt.
    Execute { attempt: NonZeroU32 },
    /// Observes an attempt's outcome before considering another effect.
    ReconcileBeforeRetry { attempt: NonZeroU32 },
    /// Reacquires current authority and ownership for a proven-safe new attempt.
    Retry { attempt: NonZeroU32 },
    /// Releases resources after a settled operation.
    ReleaseResources,
    /// Persists a bounded failure before releasing any admitted resources.
    SettleFailureBeforeEffect,
    /// Keeps ownership and reports that operator intervention is required.
    InterventionRequired,
    /// Performs no further work for this operation.
    None,
}

/// A semantic failure in a digest-valid execution journal prefix.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("invalid execution history at record {sequence}: {reason}")]
pub struct StateError {
    sequence: u64,
    reason: String,
}

impl StateError {
    /// Returns the record sequence that violated the state machine.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the stable diagnostic explanation.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Replays and retains the durable state needed to recover one operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationHistory {
    transaction: TransactionId,
    operation: OperationId,
    state: OperationState,
    planned: bool,
    admitted_resources: Vec<ResourceId>,
    transferred_resources: Vec<ResourceId>,
    resources_released: bool,
    elapsed_millis: u64,
    interrupted_call_budget_millis: u64,
    durable_request: Option<AbilityValue>,
    idempotency_key: Option<Sha256Digest>,
}

impl OperationHistory {
    pub(crate) fn new(transaction: TransactionId, operation: OperationId) -> Self {
        Self {
            transaction,
            operation,
            state: OperationState::Pending,
            planned: false,
            admitted_resources: Vec::new(),
            transferred_resources: Vec::new(),
            resources_released: false,
            elapsed_millis: 0,
            interrupted_call_budget_millis: 0,
            durable_request: None,
            idempotency_key: None,
        }
    }

    /// Replays one operation from a verified journal record prefix.
    ///
    /// Records for other operations in the same transaction are ignored after
    /// their transaction identity is checked. Every transition for the target
    /// operation must follow the finite state machine exactly.
    ///
    /// # Errors
    ///
    /// Returns an error for mixed transaction identities, an incorrect plan,
    /// duplicate planning, an invalid attempt transition, a completion without
    /// durable intent, or resource release before settlement.
    pub fn replay(
        transaction: TransactionId,
        operation: OperationId,
        records: &[JournalRecord<crate::execution::ExecutionEvent>],
    ) -> Result<Self, StateError> {
        let mut history = Self::new(transaction, operation);

        for record in records {
            history.apply_event(record.sequence(), record.body().body())?;
        }
        Ok(history)
    }

    /// Returns the durable operation state.
    #[must_use]
    pub const fn state(&self) -> &OperationState {
        &self.state
    }

    /// Returns the durable transaction identity checked during replay.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Returns the exact plan-qualified operation checked during replay.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation
    }

    /// Returns the greatest persisted elapsed recovery budget.
    #[must_use]
    pub const fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
            .saturating_add(self.interrupted_call_budget_millis)
    }

    /// Reports whether all recorded resources were released safely.
    #[must_use]
    pub const fn resources_released(&self) -> bool {
        self.resources_released
    }

    /// Returns the exact canonical resources admitted for the current attempt.
    #[must_use]
    pub fn admitted_resources(&self) -> &[ResourceId] {
        &self.admitted_resources
    }

    /// Returns resources whose unresolved ownership was explicitly transferred.
    #[must_use]
    pub fn transferred_resources(&self) -> &[ResourceId] {
        &self.transferred_resources
    }

    /// Returns the exact request persisted before the current or prior effect.
    #[must_use]
    pub const fn durable_request(&self) -> Option<&AbilityValue> {
        self.durable_request.as_ref()
    }

    /// Returns the logical-operation idempotency key retained across retries.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<Sha256Digest> {
        self.idempotency_key
    }

    /// Returns the attempt named by the current state, when one has begun.
    #[must_use]
    pub fn current_attempt(&self) -> Option<NonZeroU32> {
        state_attempt(&self.state)
    }

    /// Selects the only action permitted by state, retry policy, and total budget.
    #[must_use]
    pub fn recovery_action(
        &self,
        retry: &RetryPolicy,
        total_recovery_millis: u64,
    ) -> RecoveryAction {
        if !self.planned {
            return RecoveryAction::InterventionRequired;
        }
        if !self.transferred_resources.is_empty() {
            return if self.transferred_resources.len() == self.admitted_resources.len() {
                RecoveryAction::None
            } else {
                RecoveryAction::InterventionRequired
            };
        }

        match &self.state {
            OperationState::Pending => {
                if self.elapsed_millis() >= total_recovery_millis {
                    RecoveryAction::SettleFailureBeforeEffect
                } else {
                    RecoveryAction::Admit
                }
            }
            OperationState::Admitted { attempt } => {
                if self.elapsed_millis() >= total_recovery_millis {
                    RecoveryAction::SettleFailureBeforeEffect
                } else {
                    RecoveryAction::Execute { attempt: *attempt }
                }
            }
            OperationState::IntentDurable { attempt }
            | OperationState::Indeterminate { attempt, .. }
            | OperationState::ReconciliationIntentDurable { attempt }
            | OperationState::CancellationIntentDurable { attempt } => {
                if self.elapsed_millis() >= total_recovery_millis {
                    RecoveryAction::InterventionRequired
                } else {
                    RecoveryAction::ReconcileBeforeRetry { attempt: *attempt }
                }
            }
            OperationState::RetryAuthorized { attempt, .. }
            | OperationState::RejectedBeforeEffect { attempt, .. }
            | OperationState::DispatchAborted { attempt, .. } => {
                if self.resources_released {
                    self.retry_action(retry, *attempt, total_recovery_millis)
                } else {
                    RecoveryAction::ReleaseResources
                }
            }
            OperationState::Completed { .. } => {
                if self.resources_released {
                    RecoveryAction::None
                } else {
                    RecoveryAction::ReleaseResources
                }
            }
            OperationState::InterventionRequired { .. } => RecoveryAction::InterventionRequired,
            OperationState::SettledFailure { .. } => {
                if self.resources_released {
                    RecoveryAction::None
                } else {
                    RecoveryAction::ReleaseResources
                }
            }
        }
    }

    pub(crate) fn apply_event(
        &mut self,
        sequence: u64,
        event: &ExecutionEventKind,
    ) -> Result<(), StateError> {
        if event.transaction() != &self.transaction {
            return Err(invalid(sequence, "record belongs to another transaction"));
        }

        match event {
            ExecutionEventKind::TransactionPlanned { plan, .. } => {
                if self.planned {
                    return Err(invalid(sequence, "transaction was planned more than once"));
                }
                if plan != &self.operation.plan {
                    return Err(invalid(
                        sequence,
                        "transaction plan does not match operation",
                    ));
                }
                self.planned = true;
            }
            ExecutionEventKind::OperationAdmitted {
                operation,
                attempt,
                resources,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                if !self.planned {
                    return Err(invalid(
                        sequence,
                        "operation admitted before plan was rooted",
                    ));
                }
                if !resources_are_canonical(resources) {
                    return Err(invalid(
                        sequence,
                        "admitted resources are not strictly canonical and unique",
                    ));
                }
                let first_attempt =
                    matches!(self.state, OperationState::Pending) && attempt.get() == 1;
                let retry_attempt = self.resources_released
                    && matches!(
                        self.state,
                        OperationState::RetryAuthorized {
                            attempt: previous,
                            ..
                        } | OperationState::RejectedBeforeEffect {
                            attempt: previous,
                            ..
                        } if next_attempt(previous) == Some(*attempt)
                    );
                if !first_attempt && !retry_attempt {
                    return Err(invalid(
                        sequence,
                        "operation admission has an invalid attempt",
                    ));
                }
                self.admitted_resources.clone_from(resources);
                self.transferred_resources.clear();
                self.resources_released = resources.is_empty();
                self.interrupted_call_budget_millis = 0;
                self.state = OperationState::Admitted { attempt: *attempt };
                self.observe_elapsed(sequence, *elapsed_millis)?;
            }
            ExecutionEventKind::EffectIntent {
                operation,
                attempt,
                request,
                idempotency_key,
                attempt_timeout_millis,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(state, OperationState::Admitted { .. })
                })?;
                self.state = OperationState::IntentDurable { attempt: *attempt };
                if self
                    .idempotency_key
                    .is_some_and(|recorded| recorded != *idempotency_key)
                {
                    return Err(invalid(
                        sequence,
                        "logical operation idempotency key changed across attempts",
                    ));
                }
                self.durable_request = Some(request.clone());
                self.idempotency_key = Some(*idempotency_key);
                self.observe_elapsed(sequence, *elapsed_millis)?;
                self.interrupted_call_budget_millis = *attempt_timeout_millis;
            }
            ExecutionEventKind::EffectCompleted {
                operation,
                attempt,
                evidence,
                outputs,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(state, OperationState::IntentDurable { .. })
                })?;
                self.state = OperationState::Completed {
                    attempt: *attempt,
                    evidence: evidence.clone(),
                    outputs: outputs.clone(),
                };
                self.observe_elapsed(sequence, *elapsed_millis)?;
                self.interrupted_call_budget_millis = 0;
            }
            ExecutionEventKind::EffectRejectedBeforeEffect {
                operation,
                attempt,
                evidence,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(state, OperationState::IntentDurable { .. })
                })?;
                self.state = OperationState::RejectedBeforeEffect {
                    attempt: *attempt,
                    evidence: evidence.clone(),
                };
                self.observe_elapsed(sequence, *elapsed_millis)?;
                self.interrupted_call_budget_millis = 0;
            }
            ExecutionEventKind::EffectDispatchAborted {
                operation,
                attempt,
                reason,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(state, OperationState::IntentDurable { .. })
                })?;
                self.state = OperationState::DispatchAborted {
                    attempt: *attempt,
                    reason: *reason,
                };
                self.observe_elapsed(sequence, *elapsed_millis)?;
                self.interrupted_call_budget_millis = 0;
            }
            ExecutionEventKind::EffectIndeterminate {
                operation,
                attempt,
                evidence,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(state, OperationState::IntentDurable { .. })
                })?;
                self.state = OperationState::Indeterminate {
                    attempt: *attempt,
                    evidence: evidence.clone(),
                };
                self.observe_elapsed(sequence, *elapsed_millis)?;
                self.interrupted_call_budget_millis = 0;
            }
            ExecutionEventKind::ReconciliationIntent {
                operation,
                attempt,
                call_timeout_millis,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(
                        state,
                        OperationState::IntentDurable { .. }
                            | OperationState::Indeterminate { .. }
                            | OperationState::ReconciliationIntentDurable { .. }
                            | OperationState::CancellationIntentDurable { .. }
                    )
                })?;
                self.state = OperationState::ReconciliationIntentDurable { attempt: *attempt };
                self.begin_interrupted_call(sequence, *elapsed_millis, *call_timeout_millis)?;
            }
            ExecutionEventKind::ReconciliationObserved {
                operation,
                attempt,
                result,
                evidence,
                outputs,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(state, OperationState::ReconciliationIntentDurable { .. })
                })?;
                self.state = match result {
                    ReconciliationResult::Completed => OperationState::Completed {
                        attempt: *attempt,
                        evidence: evidence.clone(),
                        outputs: outputs.clone(),
                    },
                    ReconciliationResult::RejectedBeforeEffect => {
                        OperationState::RejectedBeforeEffect {
                            attempt: *attempt,
                            evidence: evidence.clone(),
                        }
                    }
                    ReconciliationResult::SafeToRetry => OperationState::RetryAuthorized {
                        attempt: *attempt,
                        evidence: evidence.clone(),
                    },
                    ReconciliationResult::StillIndeterminate => OperationState::Indeterminate {
                        attempt: *attempt,
                        evidence: evidence.clone(),
                    },
                    ReconciliationResult::InterventionRequired => {
                        OperationState::InterventionRequired {
                            attempt: *attempt,
                            evidence: evidence.clone(),
                        }
                    }
                };
                self.observe_elapsed(sequence, *elapsed_millis)?;
                self.interrupted_call_budget_millis = 0;
            }
            ExecutionEventKind::CancellationRequested {
                operation,
                attempt,
                call_timeout_millis,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(
                        state,
                        OperationState::Admitted { .. }
                            | OperationState::IntentDurable { .. }
                            | OperationState::Indeterminate { .. }
                            | OperationState::ReconciliationIntentDurable { .. }
                    )
                })?;
                self.state = OperationState::CancellationIntentDurable { attempt: *attempt };
                self.begin_interrupted_call(sequence, *elapsed_millis, *call_timeout_millis)?;
            }
            ExecutionEventKind::CancellationObserved {
                operation,
                attempt,
                result,
                evidence,
                outputs,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                self.require_attempt(sequence, *attempt, |state| {
                    matches!(state, OperationState::CancellationIntentDurable { .. })
                })?;
                self.state = match result {
                    CancellationResult::RejectedBeforeEffect => {
                        OperationState::RejectedBeforeEffect {
                            attempt: *attempt,
                            evidence: evidence.clone(),
                        }
                    }
                    CancellationResult::Completed => OperationState::Completed {
                        attempt: *attempt,
                        evidence: evidence.clone(),
                        outputs: outputs.clone(),
                    },
                    CancellationResult::Indeterminate => OperationState::Indeterminate {
                        attempt: *attempt,
                        evidence: evidence.clone(),
                    },
                };
                self.observe_elapsed(sequence, *elapsed_millis)?;
                self.interrupted_call_budget_millis = 0;
            }
            ExecutionEventKind::OperationSettledFailure {
                operation,
                attempt,
                evidence,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                let valid = match (&self.state, attempt) {
                    (OperationState::Pending, None) => true,
                    (OperationState::Admitted { attempt: current }, Some(recorded))
                    | (
                        OperationState::RejectedBeforeEffect {
                            attempt: current, ..
                        },
                        Some(recorded),
                    )
                    | (
                        OperationState::DispatchAborted {
                            attempt: current, ..
                        },
                        Some(recorded),
                    )
                    | (
                        OperationState::RetryAuthorized {
                            attempt: current, ..
                        },
                        Some(recorded),
                    ) => current == recorded,
                    _ => false,
                };
                if !valid {
                    return Err(invalid(
                        sequence,
                        "settled failure cannot hide an unresolved effect",
                    ));
                }
                self.state = OperationState::SettledFailure {
                    attempt: *attempt,
                    evidence: evidence.clone(),
                };
                self.observe_elapsed(sequence, *elapsed_millis)?;
                self.interrupted_call_budget_millis = 0;
            }
            ExecutionEventKind::OwnershipTransferred {
                operation,
                resources,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                if !matches!(
                    self.state,
                    OperationState::Indeterminate { .. }
                        | OperationState::ReconciliationIntentDurable { .. }
                        | OperationState::CancellationIntentDurable { .. }
                        | OperationState::InterventionRequired { .. }
                ) {
                    return Err(invalid(
                        sequence,
                        "ownership transfer requires an unresolved or intervention state",
                    ));
                }
                if resources.is_empty() || !resources_are_canonical(resources) {
                    return Err(invalid(
                        sequence,
                        "transferred resources must be nonempty, canonical, and unique",
                    ));
                }
                if resources.iter().any(|resource| {
                    !self.admitted_resources.contains(resource)
                        || self.transferred_resources.contains(resource)
                }) {
                    return Err(invalid(
                        sequence,
                        "ownership transfer contains an unowned or already transferred resource",
                    ));
                }
                self.transferred_resources.extend(resources.iter().cloned());
                self.observe_elapsed(sequence, *elapsed_millis)?;
            }
            ExecutionEventKind::ResourcesReleased {
                operation,
                resources,
                elapsed_millis,
                ..
            } if operation == &self.operation => {
                if self.resources_released {
                    return Err(invalid(sequence, "resources were released more than once"));
                }
                let settled = matches!(
                    self.state,
                    OperationState::Completed { .. }
                        | OperationState::RejectedBeforeEffect { .. }
                        | OperationState::DispatchAborted { .. }
                        | OperationState::RetryAuthorized { .. }
                        | OperationState::SettledFailure { .. }
                );
                let all_unsettled_resources_transferred = !self.admitted_resources.is_empty()
                    && self.transferred_resources.len() == self.admitted_resources.len();
                if !settled && !all_unsettled_resources_transferred {
                    return Err(invalid(
                        sequence,
                        "unresolved resources released without transferring all ownership",
                    ));
                }
                let expected: Vec<_> = self
                    .admitted_resources
                    .iter()
                    .filter(|resource| !self.transferred_resources.contains(resource))
                    .cloned()
                    .collect();
                if resources != &expected {
                    return Err(invalid(
                        sequence,
                        "released resources do not exactly match retained ownership",
                    ));
                }
                self.resources_released = true;
                self.observe_elapsed(sequence, *elapsed_millis)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn require_attempt(
        &self,
        sequence: u64,
        attempt: NonZeroU32,
        accepts: impl FnOnce(&OperationState) -> bool,
    ) -> Result<(), StateError> {
        if accepts(&self.state) && state_attempt(&self.state) == Some(attempt) {
            Ok(())
        } else {
            Err(invalid(
                sequence,
                "event does not follow the current attempt state",
            ))
        }
    }

    fn observe_elapsed(&mut self, sequence: u64, elapsed_millis: u64) -> Result<(), StateError> {
        if elapsed_millis < self.elapsed_millis {
            return Err(invalid(sequence, "elapsed recovery budget moved backward"));
        }
        self.elapsed_millis = elapsed_millis;
        Ok(())
    }

    fn begin_interrupted_call(
        &mut self,
        sequence: u64,
        elapsed_millis: u64,
        call_timeout_millis: u64,
    ) -> Result<(), StateError> {
        if elapsed_millis < self.elapsed_millis() {
            return Err(invalid(
                sequence,
                "new recovery call did not charge the preceding interrupted reservation",
            ));
        }

        self.elapsed_millis = elapsed_millis;
        self.interrupted_call_budget_millis = call_timeout_millis;
        Ok(())
    }

    fn retry_action(
        &self,
        retry: &RetryPolicy,
        attempt: NonZeroU32,
        total_recovery_millis: u64,
    ) -> RecoveryAction {
        if self.elapsed_millis() >= total_recovery_millis {
            return RecoveryAction::SettleFailureBeforeEffect;
        }
        let RetryPolicy::Bounded { max_attempts, .. } = retry else {
            return RecoveryAction::SettleFailureBeforeEffect;
        };
        if attempt >= *max_attempts {
            return RecoveryAction::SettleFailureBeforeEffect;
        }
        match next_attempt(attempt) {
            Some(attempt) => RecoveryAction::Retry { attempt },
            None => RecoveryAction::SettleFailureBeforeEffect,
        }
    }
}

fn resources_are_canonical(resources: &[ResourceId]) -> bool {
    resources
        .windows(2)
        .all(|pair| compare_resource_ids(&pair[0], &pair[1]) == Ordering::Less)
}

fn state_attempt(state: &OperationState) -> Option<NonZeroU32> {
    match state {
        OperationState::Pending => None,
        OperationState::Admitted { attempt }
        | OperationState::IntentDurable { attempt }
        | OperationState::Completed { attempt, .. }
        | OperationState::RejectedBeforeEffect { attempt, .. }
        | OperationState::DispatchAborted { attempt, .. }
        | OperationState::Indeterminate { attempt, .. }
        | OperationState::ReconciliationIntentDurable { attempt }
        | OperationState::RetryAuthorized { attempt, .. }
        | OperationState::CancellationIntentDurable { attempt }
        | OperationState::InterventionRequired { attempt, .. } => Some(*attempt),
        OperationState::SettledFailure { attempt, .. } => *attempt,
    }
}

fn next_attempt(attempt: NonZeroU32) -> Option<NonZeroU32> {
    attempt.get().checked_add(1).and_then(NonZeroU32::new)
}

fn invalid(sequence: u64, reason: impl Into<String>) -> StateError {
    StateError {
        sequence,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::{
        AbilityValue, EnvironmentId, ExecutionStage, InstanceId, LocalKey, PlanId, ResourceId,
        ScopePath, ScopedOperationKey, TransactionId,
    };
    use aos_contract::Sha256Digest;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::execution::{ExecutionEvent, ExecutionEventKind, ReconciliationResult};
    use crate::journal::{FileJournal, JournalLimits};

    #[test]
    fn crash_after_intent_requires_reconciliation_before_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let records = fixture.write(&[
            fixture.planned(),
            fixture.admitted(1, 2),
            fixture.intent(1, 3),
        ])?;

        let history = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )?;
        assert!(matches!(
            history.recovery_action(&bounded_retry(3), 100),
            RecoveryAction::ReconcileBeforeRetry { attempt } if attempt.get() == 1
        ));
        Ok(())
    }

    #[test]
    fn reconciliation_must_explicitly_authorize_the_next_attempt()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let evidence = fixture.evidence()?;
        let records = fixture.write(&[
            fixture.planned(),
            fixture.admitted(1, 2),
            fixture.intent(1, 3),
            fixture.indeterminate(1, 4, evidence.clone()),
            ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                attempt: attempt(1),
                call_timeout_millis: 20,
                elapsed_millis: 5,
            }),
            ExecutionEvent::new(ExecutionEventKind::ReconciliationObserved {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                attempt: attempt(1),
                result: ReconciliationResult::SafeToRetry,
                evidence,
                outputs: BTreeMap::new(),
                elapsed_millis: 6,
            }),
        ])?;

        let history = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )?;
        assert_eq!(
            history.recovery_action(&bounded_retry(3), 100),
            RecoveryAction::Retry {
                attempt: attempt(2)
            }
        );
        Ok(())
    }

    #[test]
    fn completion_without_durable_intent_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let records = fixture.write(&[
            fixture.planned(),
            fixture.admitted(1, 2),
            ExecutionEvent::new(ExecutionEventKind::EffectCompleted {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                attempt: attempt(1),
                evidence: fixture.evidence()?,
                outputs: BTreeMap::new(),
                elapsed_millis: 3,
            }),
        ])?;

        let error = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )
        .expect_err("completion cannot exist without a preceding durable intent");
        assert_eq!(error.sequence(), 3);
        Ok(())
    }

    #[test]
    fn expired_indeterminate_attempt_requires_intervention()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let evidence = fixture.evidence()?;
        let records = fixture.write(&[
            fixture.planned(),
            fixture.admitted(1, 2),
            fixture.intent(1, 3),
            fixture.indeterminate(1, 100, evidence),
        ])?;

        let history = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )?;
        assert_eq!(
            history.recovery_action(&bounded_retry(3), 100),
            RecoveryAction::InterventionRequired
        );
        Ok(())
    }

    #[test]
    fn interrupted_calls_conservatively_consume_budget_across_restarts()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let records = fixture.write(&[
            fixture.planned(),
            fixture.admitted(1, 2),
            fixture.intent(1, 3),
            ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                attempt: attempt(1),
                call_timeout_millis: 20,
                elapsed_millis: 23,
            }),
        ])?;

        let history = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )?;

        assert_eq!(history.elapsed_millis(), 43);
        assert_eq!(
            history.recovery_action(&bounded_retry(3), 40),
            RecoveryAction::InterventionRequired
        );
        Ok(())
    }

    #[test]
    fn a_new_call_cannot_erase_an_interrupted_budget_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let records = fixture.write(&[
            fixture.planned(),
            fixture.admitted(1, 0),
            fixture.intent(1, 0),
            ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                attempt: attempt(1),
                call_timeout_millis: 20,
                elapsed_millis: 0,
            }),
        ])?;

        let error = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )
        .expect_err("a new call must include the preceding interrupted reservation");

        assert_eq!(error.sequence(), 4);
        assert_eq!(
            error.reason(),
            "new recovery call did not charge the preceding interrupted reservation"
        );
        Ok(())
    }

    #[test]
    fn safe_retry_releases_reservations_before_fresh_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let owned = resource("owned")?;
        let evidence = fixture.evidence()?;
        let mut events = vec![
            fixture.planned(),
            fixture.admitted_with_resources(1, 2, vec![owned.clone()]),
            fixture.intent(1, 3),
            fixture.indeterminate(1, 4, evidence.clone()),
            ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                attempt: attempt(1),
                call_timeout_millis: 20,
                elapsed_millis: 5,
            }),
            ExecutionEvent::new(ExecutionEventKind::ReconciliationObserved {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                attempt: attempt(1),
                result: ReconciliationResult::SafeToRetry,
                evidence,
                outputs: BTreeMap::new(),
                elapsed_millis: 6,
            }),
        ];
        let records = fixture.write(&events)?;
        let history = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )?;
        assert_eq!(
            history.recovery_action(&bounded_retry(3), 100),
            RecoveryAction::ReleaseResources
        );

        events.push(ExecutionEvent::new(ExecutionEventKind::ResourcesReleased {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            resources: vec![owned],
            elapsed_millis: 7,
        }));
        let records = fixture.write_fresh(&events)?;
        let history = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )?;
        assert_eq!(
            history.recovery_action(&bounded_retry(3), 100),
            RecoveryAction::Retry {
                attempt: attempt(2)
            }
        );
        Ok(())
    }

    #[test]
    fn release_must_exactly_match_admitted_ownership() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let owned = resource("owned")?;
        let unrelated = resource("unrelated")?;
        let records = fixture.write(&[
            fixture.planned(),
            fixture.admitted_with_resources(1, 2, vec![owned]),
            fixture.intent(1, 3),
            ExecutionEvent::new(ExecutionEventKind::EffectCompleted {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                attempt: attempt(1),
                evidence: fixture.evidence()?,
                outputs: BTreeMap::new(),
                elapsed_millis: 4,
            }),
            ExecutionEvent::new(ExecutionEventKind::ResourcesReleased {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                resources: vec![unrelated],
                elapsed_millis: 5,
            }),
        ])?;

        let error = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )
        .expect_err("release of an unrelated resource must fail replay");

        assert_eq!(error.sequence(), 5);
        assert_eq!(
            error.reason(),
            "released resources do not exactly match retained ownership"
        );
        Ok(())
    }

    #[test]
    fn transferred_resource_cannot_also_be_recorded_as_released()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let owned = resource("owned")?;
        let evidence = fixture.evidence()?;
        let records = fixture.write(&[
            fixture.planned(),
            fixture.admitted_with_resources(1, 2, vec![owned.clone()]),
            fixture.intent(1, 3),
            fixture.indeterminate(1, 4, evidence.clone()),
            ExecutionEvent::new(ExecutionEventKind::OwnershipTransferred {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                resources: vec![owned.clone()],
                evidence,
                elapsed_millis: 5,
            }),
            ExecutionEvent::new(ExecutionEventKind::ResourcesReleased {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                resources: vec![owned],
                elapsed_millis: 6,
            }),
        ])?;

        let error = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )
        .expect_err("transferred ownership must not also be released locally");

        assert_eq!(error.sequence(), 6);
        Ok(())
    }

    #[test]
    fn transferred_responsibility_stops_the_old_controller()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let first = resource("alpha")?;
        let second = resource("beta")?;
        let evidence = fixture.evidence()?;
        let base = vec![
            fixture.planned(),
            fixture.admitted_with_resources(1, 2, vec![first.clone(), second.clone()]),
            fixture.intent(1, 3),
            fixture.indeterminate(1, 4, evidence.clone()),
        ];

        let mut partial = base.clone();
        partial.push(ExecutionEvent::new(
            ExecutionEventKind::OwnershipTransferred {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                resources: vec![first.clone()],
                evidence: evidence.clone(),
                elapsed_millis: 5,
            },
        ));
        let records = fixture.write(&partial)?;
        let history = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )?;
        assert_eq!(
            history.recovery_action(&bounded_retry(3), 100),
            RecoveryAction::InterventionRequired
        );

        let mut complete = base;
        complete.push(ExecutionEvent::new(
            ExecutionEventKind::OwnershipTransferred {
                transaction: fixture.transaction.clone(),
                operation: fixture.operation.clone(),
                resources: vec![first, second],
                evidence,
                elapsed_millis: 5,
            },
        ));
        let records = fixture.write_fresh(&complete)?;
        let history = OperationHistory::replay(
            fixture.transaction.clone(),
            fixture.operation.clone(),
            &records,
        )?;
        assert_eq!(
            history.recovery_action(&bounded_retry(3), 100),
            RecoveryAction::None
        );
        Ok(())
    }

    struct Fixture {
        directory: TempDir,
        transaction: TransactionId,
        operation: OperationId,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let plan = PlanId(Sha256Digest::of_bytes("plan"));
            Ok(Self {
                directory: TempDir::new()?,
                transaction: TransactionId(LocalKey::new("transaction-1")?),
                operation: OperationId {
                    plan,
                    operation: ScopedOperationKey {
                        scope: ScopePath::root(),
                        key: LocalKey::new("publish")?,
                    },
                },
            })
        }

        fn planned(&self) -> ExecutionEvent {
            ExecutionEvent::new(ExecutionEventKind::TransactionPlanned {
                transaction: self.transaction.clone(),
                plan: self.operation.plan,
                plan_bundle: Sha256Digest::of_bytes("checked-plan-bundle"),
                retained_roots: vec![Sha256Digest::of_bytes("adapter")],
                total_recovery_millis: 100,
            })
        }

        fn admitted(&self, attempt: u32, elapsed_millis: u64) -> ExecutionEvent {
            self.admitted_with_resources(attempt, elapsed_millis, Vec::new())
        }

        fn admitted_with_resources(
            &self,
            attempt: u32,
            elapsed_millis: u64,
            resources: Vec<ResourceId>,
        ) -> ExecutionEvent {
            ExecutionEvent::new(ExecutionEventKind::OperationAdmitted {
                transaction: self.transaction.clone(),
                operation: self.operation.clone(),
                attempt: super::tests::attempt(attempt),
                resources,
                elapsed_millis,
            })
        }

        fn intent(&self, attempt: u32, elapsed_millis: u64) -> ExecutionEvent {
            ExecutionEvent::new(ExecutionEventKind::EffectIntent {
                transaction: self.transaction.clone(),
                operation: self.operation.clone(),
                attempt: super::tests::attempt(attempt),
                request: AbilityValue::new(json!({"revision": 7}))
                    .expect("fixture request must be bounded"),
                idempotency_key: Sha256Digest::of_bytes("logical-operation"),
                attempt_timeout_millis: 20,
                elapsed_millis,
            })
        }

        fn indeterminate(
            &self,
            attempt: u32,
            elapsed_millis: u64,
            evidence: AbilityValue,
        ) -> ExecutionEvent {
            ExecutionEvent::new(ExecutionEventKind::EffectIndeterminate {
                transaction: self.transaction.clone(),
                operation: self.operation.clone(),
                attempt: super::tests::attempt(attempt),
                evidence,
                elapsed_millis,
            })
        }

        fn evidence(&self) -> Result<AbilityValue, Box<dyn std::error::Error>> {
            Ok(AbilityValue::new(json!({"observed": "unknown"}))?)
        }

        fn write(
            &self,
            events: &[ExecutionEvent],
        ) -> Result<Vec<JournalRecord<ExecutionEvent>>, Box<dyn std::error::Error>> {
            let path = self.directory.path().join("execution.journal");
            let opened = FileJournal::<ExecutionEvent>::open(&path, JournalLimits::default())?;
            let mut journal = opened.journal;
            for event in events {
                journal.append(event)?;
            }
            drop(journal);

            Ok(
                FileJournal::<ExecutionEvent>::open(&path, JournalLimits::default())?
                    .recovery
                    .into_records(),
            )
        }

        fn write_fresh(
            &self,
            events: &[ExecutionEvent],
        ) -> Result<Vec<JournalRecord<ExecutionEvent>>, Box<dyn std::error::Error>> {
            let directory = TempDir::new()?;
            let path = directory.path().join("execution.journal");
            let opened = FileJournal::<ExecutionEvent>::open(&path, JournalLimits::default())?;
            let mut journal = opened.journal;
            for event in events {
                journal.append(event)?;
            }
            drop(journal);

            Ok(
                FileJournal::<ExecutionEvent>::open(&path, JournalLimits::default())?
                    .recovery
                    .into_records(),
            )
        }
    }

    fn attempt(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).expect("test attempt must be nonzero")
    }

    fn resource(key: &str) -> Result<ResourceId, Box<dyn std::error::Error>> {
        Ok(ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test-authority")?,
                    key: LocalKey::new("test-environment")?,
                    stage: ExecutionStage::Host,
                },
                key: LocalKey::new("provider")?,
            },
            key: LocalKey::new(key)?,
        })
    }

    fn bounded_retry(max_attempts: u32) -> RetryPolicy {
        RetryPolicy::Bounded {
            max_attempts: NonZeroU32::new(max_attempts).expect("test retry count must be nonzero"),
            backoff_millis: 0,
        }
    }
}
