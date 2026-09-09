//! Closed durable journal events for one execution transaction.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use aos_ability_model::{
    AbilityValue, BranchSelection, LocalKey, MergeRecord, OperationId, PlanId, ResourceId,
    SkippedOperationRecord, TransactionId,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::journal::{JournalError, JournalLimits, JournalPayload};

/// Exact schema discriminator for runtime journal event bodies.
pub const EXECUTION_EVENT_SCHEMA: &str = "aos.ability.execution-event/v1";

/// Records the result of a provider reconciliation observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReconciliationResult {
    /// The original operation's completion was established.
    Completed,
    /// The original attempt was proven rejected before any effect.
    RejectedBeforeEffect,
    /// A new attempt was explicitly proven safe.
    SafeToRetry,
    /// The bounded observation remained inconclusive.
    StillIndeterminate,
    /// The provider requires operator intervention.
    InterventionRequired,
}

/// Records the result of requesting adapter cancellation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CancellationResult {
    /// Cancellation established that no effect occurred.
    RejectedBeforeEffect,
    /// Cancellation observed the original effect's completion.
    Completed,
    /// Cancellation left the effect indeterminate.
    Indeterminate,
}

/// Records why the runtime declined dispatch after effect intent was durable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispatchAbortReason {
    /// Cancellation was observed after the durable intent boundary.
    Cancelled,
    /// The attempt or total recovery deadline expired after intent became durable.
    DeadlineExpired,
}

/// Records why compensation stopped and now requires an operator decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompensationInterventionReason {
    /// The finite budget expired before compensation intent became durable.
    DeadlineBeforeIntent,
    /// The finite budget expired after compensation intent became durable.
    DeadlineAfterIntent,
    /// Cancellation was observed before compensation intent became durable.
    CancelledBeforeIntent,
    /// Cancellation was observed after compensation intent became durable.
    CancelledAfterIntent,
    /// The admitted adapter did not provide the required compensation call.
    AdapterUnavailable,
    /// The checked contract has no safe automatic observation after intent.
    RecoveryUnavailable,
    /// The provider's bounded observation explicitly required intervention.
    ProviderRequired,
}

/// Describes one immutable execution history event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExecutionEventKind {
    /// Roots the exact plan and required artifacts before any operation intent.
    TransactionPlanned {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact checked effect plan.
        plan: PlanId,
        /// Identifies the protected bundle containing every plan validation input.
        plan_bundle: Sha256Digest,
        /// Retains exact artifacts required for execution and recovery.
        retained_roots: Vec<Sha256Digest>,
        /// Bounds all work across attempts and reboot recovery.
        total_recovery_millis: u64,
    },
    /// Records fresh authority, assignments, and resource ownership.
    OperationAdmitted {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the current attempt.
        attempt: NonZeroU32,
        /// Lists held logical resources in canonical identity order.
        resources: Vec<ResourceId>,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Persists a restart-safe eligibility gate before a delayed retry.
    RetryBackoffScheduled {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the completed attempt preceding the delay.
        attempt: NonZeroU32,
        /// Records the trusted native timestamp observed while scheduling.
        observed_at_millis: u64,
        /// Records the earliest trusted native timestamp eligible for retry.
        eligible_at_millis: u64,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records that a persisted retry delay has elapsed under a trusted clock.
    RetryBackoffElapsed {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the completed attempt preceding the delay.
        attempt: NonZeroU32,
        /// Records the trusted native timestamp that satisfied eligibility.
        observed_at_millis: u64,
        /// Retains the recovery budget charged through this observation.
        elapsed_millis: u64,
    },
    /// Records an explicit request to compensate a completed operation.
    CompensationRequested {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the completed operation selected for compensation.
        operation: OperationId,
        /// Retains a bounded caller-supplied audit reason.
        reason: AbilityValue,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records fresh compensation authority and resource ownership.
    CompensationAdmitted {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the operation being compensated.
        operation: OperationId,
        /// Lists freshly held resources in canonical identity order.
        resources: Vec<ResourceId>,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records compensation intent before its external effect.
    CompensationIntent {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the operation being compensated.
        operation: OperationId,
        /// Retains the exact primary request accepted by the recovery contract.
        request: AbilityValue,
        /// Identifies this logical compensation consistently across recovery.
        idempotency_key: Sha256Digest,
        /// Bounds the compensation adapter call.
        attempt_timeout_millis: u64,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records a successful, separately validated compensation outcome.
    CompensationCompleted {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the compensated operation.
        operation: OperationId,
        /// Retains typed compensation completion evidence.
        evidence: AbilityValue,
        /// Retains the compensation method's exact typed output set.
        outputs: BTreeMap<LocalKey, AbilityValue>,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records proof that compensation was rejected before any effect.
    CompensationRejectedBeforeEffect {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the operation whose compensation was rejected.
        operation: OperationId,
        /// Retains typed rejection evidence.
        evidence: AbilityValue,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records an ambiguous compensation effect.
    CompensationIndeterminate {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the operation with ambiguous compensation.
        operation: OperationId,
        /// Retains typed ambiguity evidence.
        evidence: AbilityValue,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records intent to reconcile the compensation effect.
    CompensationReconciliationIntent {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the ambiguous compensation being observed.
        operation: OperationId,
        /// Conservatively reserves this budget if observation is interrupted.
        call_timeout_millis: u64,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records the authoritative disposition of compensation reconciliation.
    CompensationReconciliationObserved {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the compensation that was observed.
        operation: OperationId,
        /// States the authoritative compensation disposition.
        result: ReconciliationResult,
        /// Retains typed completion or observation evidence.
        evidence: AbilityValue,
        /// Retains outputs only when compensation completion was established.
        outputs: BTreeMap<LocalKey, AbilityValue>,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records a durable fail-closed compensation stop requiring intervention.
    CompensationInterventionRequired {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the compensation that cannot proceed automatically.
        operation: OperationId,
        /// States why automatic compensation recovery stopped.
        reason: CompensationInterventionReason,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records the one alternative chosen by a checked decision node.
    BranchSelected {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Retains the exact decision, alternative, and selector evidence.
        selection: BranchSelection,
    },
    /// Records one operation excluded by an already durable branch selection.
    OperationSkipped {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the skipped operation and excluding decision.
        skipped: SkippedOperationRecord,
    },
    /// Records the typed outputs exposed by a completed conditional merge.
    MergeCompleted {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Retains the selected alternative and its exact typed outputs.
        merged: MergeRecord,
    },
    /// Records intent durably before dispatching the external effect.
    EffectIntent {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the current attempt.
        attempt: NonZeroU32,
        /// Identifies the exact typed adapter request.
        request: AbilityValue,
        /// Identifies the logical operation consistently across retries.
        idempotency_key: Sha256Digest,
        /// Bounds this individual adapter call.
        attempt_timeout_millis: u64,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records completion evidence before required-success dependents run.
    EffectCompleted {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the completed attempt.
        attempt: NonZeroU32,
        /// Identifies typed provider completion evidence.
        evidence: AbilityValue,
        /// Retains independently typed successful method outputs.
        outputs: BTreeMap<LocalKey, AbilityValue>,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records evidence that dispatch was rejected before an effect.
    EffectRejectedBeforeEffect {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the rejected attempt.
        attempt: NonZeroU32,
        /// Identifies typed provider observation evidence.
        evidence: AbilityValue,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records that the runtime itself did not cross the external effect boundary.
    EffectDispatchAborted {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the attempt whose dispatch was aborted.
        attempt: NonZeroU32,
        /// Identifies the closed runtime-owned reason without provider evidence.
        reason: DispatchAbortReason,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records that an external effect may have occurred.
    EffectIndeterminate {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the indeterminate attempt.
        attempt: NonZeroU32,
        /// Identifies typed provider observation evidence.
        evidence: AbilityValue,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records intent to observe an indeterminate attempt before any retry.
    ReconciliationIntent {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the indeterminate attempt being observed.
        attempt: NonZeroU32,
        /// Conservatively reserves this much budget if the observation is interrupted.
        call_timeout_millis: u64,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records the authoritative disposition of one reconciliation observation.
    ReconciliationObserved {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the exact operation under the plan.
        operation: OperationId,
        /// Identifies the observed attempt.
        attempt: NonZeroU32,
        /// States whether completion, safe retry, uncertainty, or intervention was established.
        result: ReconciliationResult,
        /// Identifies typed completion or observation evidence.
        evidence: AbilityValue,
        /// Retains successful method outputs only for a completed result.
        outputs: BTreeMap<LocalKey, AbilityValue>,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records a cancellation request without implying effect rollback.
    CancellationRequested {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the operation receiving cancellation.
        operation: OperationId,
        /// Identifies the active or pending attempt.
        attempt: NonZeroU32,
        /// Conservatively reserves this much budget if cancellation is interrupted.
        call_timeout_millis: u64,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records the observed result of bounded adapter cancellation.
    CancellationObserved {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the operation receiving cancellation.
        operation: OperationId,
        /// Identifies the affected attempt.
        attempt: NonZeroU32,
        /// States what cancellation actually established.
        result: CancellationResult,
        /// Identifies typed provider completion or observation evidence.
        evidence: AbilityValue,
        /// Retains successful method outputs only for a completed result.
        outputs: BTreeMap<LocalKey, AbilityValue>,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records a settled failure only when no unresolved effect remains.
    OperationSettledFailure {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the operation that did not reach completion.
        operation: OperationId,
        /// Identifies the last admitted attempt, when admission occurred.
        attempt: Option<NonZeroU32>,
        /// Identifies a typed deadline, retry-exhaustion, or rejection diagnostic.
        evidence: AbilityValue,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records explicit transfer or fencing of unresolved resource responsibility.
    OwnershipTransferred {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the unresolved operation whose ownership moved.
        operation: OperationId,
        /// Lists fenced or transferred resources in canonical identity order.
        resources: Vec<ResourceId>,
        /// Identifies typed provider fencing or transfer evidence.
        evidence: AbilityValue,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
    /// Records safe release of all resources held for one operation.
    ResourcesReleased {
        /// Identifies this durable execution allocation.
        transaction: TransactionId,
        /// Identifies the operation whose ownership was released.
        operation: OperationId,
        /// Lists released logical resources in canonical identity order.
        resources: Vec<ResourceId>,
        /// Retains consumed operation recovery budget across reboot.
        elapsed_millis: u64,
    },
}

impl ExecutionEventKind {
    /// Returns the event's transaction identity.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        match self {
            Self::TransactionPlanned { transaction, .. }
            | Self::OperationAdmitted { transaction, .. }
            | Self::RetryBackoffScheduled { transaction, .. }
            | Self::RetryBackoffElapsed { transaction, .. }
            | Self::CompensationRequested { transaction, .. }
            | Self::CompensationAdmitted { transaction, .. }
            | Self::CompensationIntent { transaction, .. }
            | Self::CompensationCompleted { transaction, .. }
            | Self::CompensationRejectedBeforeEffect { transaction, .. }
            | Self::CompensationIndeterminate { transaction, .. }
            | Self::CompensationReconciliationIntent { transaction, .. }
            | Self::CompensationReconciliationObserved { transaction, .. }
            | Self::CompensationInterventionRequired { transaction, .. }
            | Self::BranchSelected { transaction, .. }
            | Self::OperationSkipped { transaction, .. }
            | Self::MergeCompleted { transaction, .. }
            | Self::EffectIntent { transaction, .. }
            | Self::EffectCompleted { transaction, .. }
            | Self::EffectRejectedBeforeEffect { transaction, .. }
            | Self::EffectDispatchAborted { transaction, .. }
            | Self::EffectIndeterminate { transaction, .. }
            | Self::ReconciliationIntent { transaction, .. }
            | Self::ReconciliationObserved { transaction, .. }
            | Self::CancellationRequested { transaction, .. }
            | Self::CancellationObserved { transaction, .. }
            | Self::OperationSettledFailure { transaction, .. }
            | Self::OwnershipTransferred { transaction, .. }
            | Self::ResourcesReleased { transaction, .. } => transaction,
        }
    }

    /// Returns the affected operation for an operation-scoped event.
    #[must_use]
    pub const fn operation(&self) -> Option<&OperationId> {
        match self {
            Self::OperationAdmitted { operation, .. }
            | Self::RetryBackoffScheduled { operation, .. }
            | Self::RetryBackoffElapsed { operation, .. }
            | Self::CompensationRequested { operation, .. }
            | Self::CompensationAdmitted { operation, .. }
            | Self::CompensationIntent { operation, .. }
            | Self::CompensationCompleted { operation, .. }
            | Self::CompensationRejectedBeforeEffect { operation, .. }
            | Self::CompensationIndeterminate { operation, .. }
            | Self::CompensationReconciliationIntent { operation, .. }
            | Self::CompensationReconciliationObserved { operation, .. }
            | Self::CompensationInterventionRequired { operation, .. }
            | Self::EffectIntent { operation, .. }
            | Self::EffectCompleted { operation, .. }
            | Self::EffectRejectedBeforeEffect { operation, .. }
            | Self::EffectDispatchAborted { operation, .. }
            | Self::EffectIndeterminate { operation, .. }
            | Self::ReconciliationIntent { operation, .. }
            | Self::ReconciliationObserved { operation, .. }
            | Self::CancellationRequested { operation, .. }
            | Self::CancellationObserved { operation, .. }
            | Self::OperationSettledFailure { operation, .. }
            | Self::OwnershipTransferred { operation, .. }
            | Self::ResourcesReleased { operation, .. } => Some(operation),
            Self::TransactionPlanned { .. }
            | Self::BranchSelected { .. }
            | Self::OperationSkipped { .. }
            | Self::MergeCompleted { .. } => None,
        }
    }

    /// Returns the transaction-wide elapsed budget carried by this event.
    #[must_use]
    pub const fn elapsed_millis(&self) -> Option<u64> {
        match self {
            Self::OperationAdmitted { elapsed_millis, .. }
            | Self::RetryBackoffScheduled { elapsed_millis, .. }
            | Self::RetryBackoffElapsed { elapsed_millis, .. }
            | Self::CompensationRequested { elapsed_millis, .. }
            | Self::CompensationAdmitted { elapsed_millis, .. }
            | Self::CompensationIntent { elapsed_millis, .. }
            | Self::CompensationCompleted { elapsed_millis, .. }
            | Self::CompensationRejectedBeforeEffect { elapsed_millis, .. }
            | Self::CompensationIndeterminate { elapsed_millis, .. }
            | Self::CompensationReconciliationIntent { elapsed_millis, .. }
            | Self::CompensationReconciliationObserved { elapsed_millis, .. }
            | Self::CompensationInterventionRequired { elapsed_millis, .. }
            | Self::EffectIntent { elapsed_millis, .. }
            | Self::EffectCompleted { elapsed_millis, .. }
            | Self::EffectRejectedBeforeEffect { elapsed_millis, .. }
            | Self::EffectDispatchAborted { elapsed_millis, .. }
            | Self::EffectIndeterminate { elapsed_millis, .. }
            | Self::ReconciliationIntent { elapsed_millis, .. }
            | Self::ReconciliationObserved { elapsed_millis, .. }
            | Self::CancellationRequested { elapsed_millis, .. }
            | Self::CancellationObserved { elapsed_millis, .. }
            | Self::OperationSettledFailure { elapsed_millis, .. }
            | Self::OwnershipTransferred { elapsed_millis, .. }
            | Self::ResourcesReleased { elapsed_millis, .. } => Some(*elapsed_millis),
            Self::TransactionPlanned { .. }
            | Self::BranchSelected { .. }
            | Self::OperationSkipped { .. }
            | Self::MergeCompleted { .. } => None,
        }
    }
}

/// Wraps one event in the exact version-1 journal body schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvent {
    schema: String,
    body: ExecutionEventKind,
}

impl ExecutionEvent {
    /// Constructs one exact version-1 execution journal event.
    #[must_use]
    pub fn new(body: ExecutionEventKind) -> Self {
        Self {
            schema: EXECUTION_EVENT_SCHEMA.to_string(),
            body,
        }
    }

    /// Returns the immutable execution event body.
    #[must_use]
    pub const fn body(&self) -> &ExecutionEventKind {
        &self.body
    }
}

impl JournalPayload for ExecutionEvent {
    fn validate_for_journal(&self, limits: JournalLimits) -> Result<(), JournalError> {
        if self.schema != EXECUTION_EVENT_SCHEMA {
            return Err(JournalError::Limit(
                "execution event has an unsupported schema discriminator".to_string(),
            ));
        }

        let collection_length = match &self.body {
            ExecutionEventKind::TransactionPlanned { retained_roots, .. } => retained_roots.len(),
            ExecutionEventKind::OperationAdmitted { resources, .. }
            | ExecutionEventKind::CompensationAdmitted { resources, .. }
            | ExecutionEventKind::OwnershipTransferred { resources, .. }
            | ExecutionEventKind::ResourcesReleased { resources, .. } => resources.len(),
            ExecutionEventKind::EffectCompleted { outputs, .. }
            | ExecutionEventKind::CompensationCompleted { outputs, .. }
            | ExecutionEventKind::CompensationReconciliationObserved { outputs, .. }
            | ExecutionEventKind::ReconciliationObserved { outputs, .. }
            | ExecutionEventKind::CancellationObserved { outputs, .. } => outputs.len(),
            ExecutionEventKind::MergeCompleted { merged, .. } => merged.outputs.len(),
            _ => 0,
        };
        if collection_length > limits.max_items {
            return Err(JournalError::Limit(format!(
                "execution event collection has {collection_length} items, limit is {}",
                limits.max_items
            )));
        }

        match &self.body {
            ExecutionEventKind::TransactionPlanned {
                total_recovery_millis,
                ..
            } if *total_recovery_millis == 0 => Err(JournalError::Limit(
                "transaction recovery budget must be nonzero".to_string(),
            )),
            ExecutionEventKind::EffectIntent {
                attempt_timeout_millis,
                ..
            } if *attempt_timeout_millis == 0 => Err(JournalError::Limit(
                "effect attempt timeout must be nonzero".to_string(),
            )),
            ExecutionEventKind::CompensationIntent {
                attempt_timeout_millis,
                ..
            } if *attempt_timeout_millis == 0 => Err(JournalError::Limit(
                "compensation attempt timeout must be nonzero".to_string(),
            )),
            ExecutionEventKind::ReconciliationIntent {
                call_timeout_millis,
                ..
            }
            | ExecutionEventKind::CancellationRequested {
                call_timeout_millis,
                ..
            }
            | ExecutionEventKind::CompensationReconciliationIntent {
                call_timeout_millis,
                ..
            } if *call_timeout_millis == 0 => Err(JournalError::Limit(
                "recovery call timeout must be nonzero".to_string(),
            )),
            _ => Ok(()),
        }
    }
}
