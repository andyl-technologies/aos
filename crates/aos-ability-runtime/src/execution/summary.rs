//! Read-only summaries of durable operation and transaction outcomes.

use std::num::NonZeroU32;

use aos_ability_model::{OperationId, PlanId, TransactionId};

pub use aos_ability_model::document::TerminalResult;

use crate::execution::{CompensationState, ExecutionTransaction, OperationHistory, OperationState};

/// Classifies the durable progress of one checked operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStatus {
    /// The operation has not acquired resources or crossed an effect boundary.
    Pending,
    /// The operation has durable work that can continue without reconciliation.
    Active,
    /// The operation requires release, retry, observation, or cancellation work.
    Recovering,
    /// The operation completed and released every process-scoped resource.
    Succeeded,
    /// The original success was explicitly and durably compensated.
    Compensated,
    /// The operation settled unsuccessfully and released every resource.
    SettledFailure,
    /// An unresolved effect requires an operator decision.
    InterventionRequired,
    /// A durable branch selection excluded the operation.
    Skipped,
}

impl OperationStatus {
    /// Reports whether this status needs no further work in this transaction.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Compensated
                | Self::SettledFailure
                | Self::InterventionRequired
                | Self::Skipped
        )
    }
}

/// Summarizes one operation without exposing private adapter evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSummary {
    operation: OperationId,
    status: OperationStatus,
    attempt: Option<NonZeroU32>,
    elapsed_millis: u64,
}

impl OperationSummary {
    /// Returns the plan-qualified operation identity.
    #[must_use]
    pub const fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// Returns the operation's durable progress classification.
    #[must_use]
    pub const fn status(&self) -> OperationStatus {
        self.status
    }

    /// Returns the latest attempt number when admission occurred.
    #[must_use]
    pub const fn attempt(&self) -> Option<NonZeroU32> {
        self.attempt
    }

    /// Returns the conservative persisted recovery time for the operation.
    #[must_use]
    pub const fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }
}

/// Summarizes durable transaction progress and its command-level result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionSummary {
    transaction: TransactionId,
    plan: PlanId,
    terminal: Option<TerminalResult>,
    operations: Vec<OperationSummary>,
    elapsed_millis: u64,
    total_recovery_millis: u64,
}

impl TransactionSummary {
    /// Returns the durable execution allocation identity.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Returns the exact checked plan identity.
    #[must_use]
    pub const fn plan(&self) -> PlanId {
        self.plan
    }

    /// Returns the terminal command result after every operation settles.
    ///
    /// A mixed successful and failed graph returns
    /// [`TerminalResult::SettledFailure`]. Pending cleanup or recovery keeps
    /// this value absent.
    #[must_use]
    pub const fn terminal(&self) -> Option<TerminalResult> {
        self.terminal
    }

    /// Returns operation summaries in canonical checked-plan order.
    #[must_use]
    pub fn operations(&self) -> &[OperationSummary] {
        &self.operations
    }

    /// Returns the conservative persisted transaction recovery time.
    #[must_use]
    pub const fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }

    /// Returns the aggregate finite recovery budget rooted by the journal.
    #[must_use]
    pub const fn total_recovery_millis(&self) -> u64 {
        self.total_recovery_millis
    }
}

impl ExecutionTransaction<'_> {
    /// Produces a redaction-safe view of durable operation and command progress.
    #[must_use]
    pub fn summary(&self) -> TransactionSummary {
        let operations = self
            .operation_histories()
            .map(|history| {
                let status = if self.operation_is_skipped(&history.operation_id().operation) {
                    OperationStatus::Skipped
                } else {
                    operation_status(history)
                };

                OperationSummary {
                    operation: history.operation_id().clone(),
                    status,
                    attempt: history.current_attempt(),
                    elapsed_millis: history.elapsed_millis(),
                }
            })
            .collect::<Vec<_>>();
        let terminal = transaction_result(&operations);

        TransactionSummary {
            transaction: self.transaction().clone(),
            plan: self.plan().id(),
            terminal,
            operations,
            elapsed_millis: self.elapsed_millis(),
            total_recovery_millis: self.total_recovery_millis(),
        }
    }
}

fn operation_status(history: &OperationHistory) -> OperationStatus {
    let resources_released = history.resources_released();
    if let Some(compensation) = history.compensation_state() {
        return match compensation {
            CompensationState::Completed { .. } if resources_released => {
                OperationStatus::Compensated
            }
            CompensationState::InterventionRequired { .. } => OperationStatus::InterventionRequired,
            CompensationState::RejectedBeforeEffect { .. } if resources_released => {
                OperationStatus::InterventionRequired
            }
            _ => OperationStatus::Recovering,
        };
    }
    let state = history.state();
    match state {
        OperationState::Pending => OperationStatus::Pending,
        OperationState::Admitted { .. } => OperationStatus::Active,
        OperationState::IntentDurable { .. }
        | OperationState::RejectedBeforeEffect { .. }
        | OperationState::DispatchAborted { .. }
        | OperationState::Indeterminate { .. }
        | OperationState::ReconciliationIntentDurable { .. }
        | OperationState::RetryAuthorized { .. }
        | OperationState::RetryBackoff { .. }
        | OperationState::RetryReady { .. }
        | OperationState::CancellationIntentDurable { .. } => OperationStatus::Recovering,
        OperationState::Completed { .. } if resources_released => OperationStatus::Succeeded,
        OperationState::SettledFailure { .. } if resources_released => {
            OperationStatus::SettledFailure
        }
        OperationState::Completed { .. } | OperationState::SettledFailure { .. } => {
            OperationStatus::Recovering
        }
        OperationState::InterventionRequired { .. } => OperationStatus::InterventionRequired,
    }
}

fn transaction_result(operations: &[OperationSummary]) -> Option<TerminalResult> {
    if operations
        .iter()
        .any(|operation| !operation.status.is_terminal())
    {
        return None;
    }
    if operations
        .iter()
        .any(|operation| operation.status == OperationStatus::InterventionRequired)
    {
        return Some(TerminalResult::InterventionRequired);
    }
    if operations
        .iter()
        .any(|operation| operation.status == OperationStatus::SettledFailure)
    {
        return Some(TerminalResult::SettledFailure);
    }
    if operations
        .iter()
        .any(|operation| operation.status == OperationStatus::Compensated)
    {
        return Some(TerminalResult::SettledFailure);
    }
    Some(TerminalResult::Succeeded)
}
