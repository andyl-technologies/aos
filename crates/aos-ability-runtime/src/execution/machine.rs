//! Live transitions that preserve intent-before-effect journal ordering.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use aos_ability_model::{OperationId, TransactionId};
use thiserror::Error;

use crate::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CancellationToken,
    EffectDisposition, InvocationPurpose, MonotonicClock, PreparedRequest, ReconcileDisposition,
    RuntimeControl, TrustedAdapter,
};
use crate::execution::event::{
    CancellationResult, CompensationInterventionReason, DispatchAbortReason, ExecutionEventKind,
    ReconciliationResult,
};
use crate::execution::{ExecutionTransaction, TransactionError};
use crate::journal::{FileJournal, JournalError};

pub(crate) trait ExecutionEventSink {
    fn ensure_capacity(&mut self, additional_records: usize) -> Result<(), ExecutionError>;

    fn append_event(&mut self, event: ExecutionEventKind) -> Result<(), ExecutionError>;
}

impl ExecutionEventSink for FileJournal<crate::execution::ExecutionEvent> {
    fn ensure_capacity(&mut self, additional_records: usize) -> Result<(), ExecutionError> {
        FileJournal::ensure_capacity(self, additional_records).map_err(ExecutionError::Journal)
    }

    fn append_event(&mut self, event: ExecutionEventKind) -> Result<(), ExecutionError> {
        self.append(&crate::execution::ExecutionEvent::new(event))?;
        Ok(())
    }
}

impl ExecutionEventSink for ExecutionTransaction<'_> {
    fn ensure_capacity(&mut self, additional_records: usize) -> Result<(), ExecutionError> {
        self.ensure_journal_capacity(additional_records)
            .map_err(ExecutionError::Transaction)
    }

    fn append_event(&mut self, event: ExecutionEventKind) -> Result<(), ExecutionError> {
        self.append(event).map_err(ExecutionError::Transaction)
    }
}

/// Names a durable boundary available to tests and external observation hooks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Boundary {
    /// Effect intent is durable and no adapter call has begun yet.
    EffectIntentDurable,
    /// The adapter returned but its outcome is not yet durable.
    EffectReturned,
    /// The adapter outcome is durable.
    EffectOutcomeDurable,
    /// Reconciliation intent is durable and no observation call has begun yet.
    ReconciliationIntentDurable,
    /// Reconciliation returned but its observation is not yet durable.
    ReconciliationReturned,
    /// The reconciliation observation is durable.
    ReconciliationOutcomeDurable,
    /// Cancellation intent is durable and no cancellation call has begun yet.
    CancellationIntentDurable,
    /// Cancellation returned but its observation is not yet durable.
    CancellationReturned,
    /// The cancellation observation is durable.
    CancellationOutcomeDurable,
}

/// Selects whether execution may advance beyond an observed durable boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionBoundaryControl {
    /// Allows execution to advance normally.
    Continue,
    /// Stops execution at the observed boundary without recording a later outcome.
    Halt,
}

/// Identifies one exact boundary in an admitted operation attempt.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionBoundaryObservation<'a> {
    transaction: &'a TransactionId,
    operation: &'a OperationId,
    attempt: NonZeroU32,
    purpose: InvocationPurpose,
    boundary: Boundary,
}

impl<'a> ExecutionBoundaryObservation<'a> {
    pub(crate) const fn new(
        transaction: &'a TransactionId,
        operation: &'a OperationId,
        attempt: NonZeroU32,
        purpose: InvocationPurpose,
        boundary: Boundary,
    ) -> Self {
        Self {
            transaction,
            operation,
            attempt,
            purpose,
            boundary,
        }
    }

    /// Returns the exact durable transaction identity.
    #[must_use]
    pub const fn transaction(&self) -> &'a TransactionId {
        self.transaction
    }

    /// Returns the plan-qualified operation identity.
    #[must_use]
    pub const fn operation(&self) -> &'a OperationId {
        self.operation
    }

    /// Returns the attempt number within the logical operation.
    #[must_use]
    pub const fn attempt(&self) -> NonZeroU32 {
        self.attempt
    }

    /// Returns the independently admitted invocation purpose.
    #[must_use]
    pub const fn purpose(&self) -> InvocationPurpose {
        self.purpose
    }

    /// Returns the exact journal or adapter boundary being observed.
    #[must_use]
    pub const fn boundary(&self) -> Boundary {
        self.boundary
    }
}

/// Observes exact admitted-operation boundaries without access to effect data.
pub trait ExecutionBoundaryObserver {
    /// Observes one boundary and decides whether execution may continue.
    ///
    /// The observer receives only stable execution identity and the live time
    /// and cancellation budget. It cannot replace adapter evidence or choose an
    /// execution result.
    ///
    /// # Errors
    ///
    /// Returns an error when configured observation cannot complete. Execution
    /// fails closed at the named boundary and does not append a later outcome.
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl>;
}

/// Observes execution boundaries and may halt deterministic fault-injection runs.
///
/// Returning `false` models process loss immediately after the named boundary.
/// The hook supplies the generic seam used by production observers, modeled
/// clocks, and fault campaigns without importing a particular platform into
/// the runtime.
pub(crate) trait BoundaryHook {
    /// Returns whether execution should continue beyond this boundary.
    fn observe(
        &mut self,
        boundary: Boundary,
        control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl>;
}

/// Reports the newly durable result of one live state-machine step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStep {
    /// Completion evidence is durable and dependents may now observe success.
    Completed,
    /// Rejection-before-effect evidence is durable.
    RejectedBeforeEffect,
    /// The operation remains indeterminate and must reconcile before retrying.
    Indeterminate,
    /// Reconciliation explicitly authorized a new attempt.
    SafeToRetry,
    /// The provider requires operator intervention.
    InterventionRequired,
}

/// A failure to make a requested execution transition durable.
#[derive(Debug, Error)]
pub enum ExecutionError {
    /// A durable journal operation failed.
    #[error("execution journal failed: {0}")]
    Journal(#[from] JournalError),
    /// The owning transaction rejected the attempted durable transition.
    #[error("execution transaction failed: {0}")]
    Transaction(#[from] TransactionError),
    /// A fault-injection or observation hook halted at a precise boundary.
    #[error("execution halted after {0:?}")]
    BoundaryHalt(Boundary),
    /// An explicitly configured boundary observer failed closed.
    #[error("execution boundary observation failed: {0}")]
    BoundaryObservation(#[source] anyhow::Error),
    /// Cancellation was already requested before intent could be admitted.
    #[error("operation was cancelled before effect intent")]
    CancelledBeforeIntent,
    /// A finite deadline expired before intent could be admitted.
    #[error("operation deadline expired before effect intent")]
    DeadlineBeforeIntent,
    /// A recovery deadline expired before the trusted adapter could be called.
    #[error("operation deadline expired before the recovery adapter call")]
    RecoveryDeadlineExpired,
    /// A fixed runtime observation could not satisfy the value contract.
    #[error("runtime observation could not be encoded: {0}")]
    Observation(#[from] aos_ability_model::ValueError),
    /// The admitted token no longer matches the transaction's durable state.
    #[error("admitted operation does not match current durable state")]
    StaleAdmission,
    /// Current policy rejected a token immediately before adapter dispatch.
    #[error("fresh dispatch authorization failed: {0}")]
    DispatchAuthorization(#[source] anyhow::Error),
    /// Fresh dispatch validation rejected the token's invocation.
    #[error("fresh dispatch admission failed: {0}")]
    DispatchAdmission(#[source] crate::execution::AdmissionError),
    /// A stable logical-operation identity could not be encoded.
    #[error("operation identity could not be encoded: {0}")]
    Identity(#[source] anyhow::Error),
}

/// Advances admitted operations through effect, reconciliation, and cancellation.
pub(crate) struct OperationExecutor<'a, Adapter, Clock, Hook> {
    adapter: &'a mut Adapter,
    clock: &'a Clock,
    cancellation: &'a CancellationToken,
    hook: &'a mut Hook,
}

impl<'a, Adapter, Clock, Hook> OperationExecutor<'a, Adapter, Clock, Hook>
where
    Adapter: TrustedAdapter,
    Clock: MonotonicClock,
    Hook: BoundaryHook,
{
    /// Constructs an executor over one trusted adapter and monotonic clock.
    #[must_use]
    pub(crate) fn new(
        adapter: &'a mut Adapter,
        clock: &'a Clock,
        cancellation: &'a CancellationToken,
        hook: &'a mut Hook,
    ) -> Self {
        Self {
            adapter,
            clock,
            cancellation,
            hook,
        }
    }

    /// Persists intent, invokes one effect, and persists its typed outcome.
    ///
    /// Returning `Completed` occurs only after completion evidence has been
    /// synchronized by the journal. If persistence fails after adapter dispatch,
    /// reopening the journal exposes the retained intent as indeterminate.
    ///
    /// # Errors
    ///
    /// Returns an error when a journal boundary fails or a configured boundary
    /// hook stops execution. A halt after intent deliberately leaves recovery to
    /// reconcile even when the test hook stopped before adapter dispatch.
    pub(crate) fn execute(
        &mut self,
        journal: &mut impl ExecutionEventSink,
        context: AttemptContext<'_>,
        request: &PreparedRequest<Adapter::Request>,
    ) -> Result<ExecutionStep, ExecutionError> {
        // Keep configured room for intent, outcome, and one complete
        // reconciliation round before any external effect can begin.
        journal.ensure_capacity(4)?;
        let control = LiveControl::new(
            self.clock,
            self.cancellation,
            context.elapsed_millis,
            context.attempt_timeout_millis,
            context.total_recovery_millis,
        );
        if control.is_cancelled() {
            return Err(ExecutionError::CancelledBeforeIntent);
        }
        if control.attempt_remaining_millis() == 0 || control.recovery_remaining_millis() == 0 {
            return Err(ExecutionError::DeadlineBeforeIntent);
        }
        journal.append_event(ExecutionEventKind::EffectIntent {
            transaction: context.transaction.clone(),
            operation: context.operation.clone(),
            attempt: context.attempt,
            request: request.durable().clone(),
            idempotency_key: context.idempotency_key,
            attempt_timeout_millis: context.attempt_timeout_millis,
            elapsed_millis: control.elapsed_millis(),
        })?;
        self.observe(Boundary::EffectIntentDurable, &control)?;

        if control.is_cancelled()
            || control.attempt_remaining_millis() == 0
            || control.recovery_remaining_millis() == 0
        {
            let reason = if control.is_cancelled() {
                DispatchAbortReason::Cancelled
            } else {
                DispatchAbortReason::DeadlineExpired
            };
            journal.append_event(ExecutionEventKind::EffectDispatchAborted {
                transaction: context.transaction.clone(),
                operation: context.operation.clone(),
                attempt: context.attempt,
                reason,
                elapsed_millis: control.elapsed_millis(),
            })?;
            self.observe(Boundary::EffectOutcomeDurable, &control)?;
            return Ok(ExecutionStep::RejectedBeforeEffect);
        }

        let disposition = self.adapter.execute(request.request(), &control);
        self.observe(Boundary::EffectReturned, &control)?;
        let (event, step) = match disposition {
            EffectDisposition::Completed(evidence) => (
                ExecutionEventKind::EffectCompleted {
                    transaction: context.transaction.clone(),
                    operation: context.operation.clone(),
                    attempt: context.attempt,
                    evidence: evidence.durable().clone(),
                    outputs: evidence.outputs().clone(),
                    elapsed_millis: control.elapsed_millis(),
                },
                ExecutionStep::Completed,
            ),
            EffectDisposition::RejectedBeforeEffect(evidence) => (
                ExecutionEventKind::EffectRejectedBeforeEffect {
                    transaction: context.transaction.clone(),
                    operation: context.operation.clone(),
                    attempt: context.attempt,
                    evidence: evidence.durable().clone(),
                    elapsed_millis: control.elapsed_millis(),
                },
                ExecutionStep::RejectedBeforeEffect,
            ),
            EffectDisposition::Indeterminate(evidence) => (
                ExecutionEventKind::EffectIndeterminate {
                    transaction: context.transaction.clone(),
                    operation: context.operation.clone(),
                    attempt: context.attempt,
                    evidence: evidence.durable().clone(),
                    elapsed_millis: control.elapsed_millis(),
                },
                ExecutionStep::Indeterminate,
            ),
        };
        journal.append_event(event)?;
        self.observe(Boundary::EffectOutcomeDurable, &control)?;
        Ok(step)
    }

    /// Reconciles one unresolved attempt without dispatching the effect again.
    ///
    /// # Errors
    ///
    /// Returns an error when a journal boundary fails or a configured boundary
    /// hook halts execution. `SafeToRetry` is returned only after the provider's
    /// observation and its evidence are durable.
    pub(crate) fn reconcile(
        &mut self,
        journal: &mut impl ExecutionEventSink,
        context: AttemptContext<'_>,
        request: &Adapter::Request,
    ) -> Result<ExecutionStep, ExecutionError> {
        journal.ensure_capacity(2)?;
        let control = LiveControl::new(
            self.clock,
            self.cancellation,
            context.elapsed_millis,
            context.attempt_timeout_millis,
            context.total_recovery_millis,
        );
        if deadline_expired(&control) {
            return Err(ExecutionError::RecoveryDeadlineExpired);
        }
        journal.append_event(ExecutionEventKind::ReconciliationIntent {
            transaction: context.transaction.clone(),
            operation: context.operation.clone(),
            attempt: context.attempt,
            call_timeout_millis: context.attempt_timeout_millis,
            elapsed_millis: control.elapsed_millis(),
        })?;
        self.observe(Boundary::ReconciliationIntentDurable, &control)?;
        if deadline_expired(&control) {
            return Err(ExecutionError::RecoveryDeadlineExpired);
        }

        let disposition = self.adapter.reconcile(request, &control);
        self.observe(Boundary::ReconciliationReturned, &control)?;
        let (result, evidence, outputs, step) = match disposition {
            ReconcileDisposition::Completed(evidence) => (
                ReconciliationResult::Completed,
                evidence.durable().clone(),
                evidence.outputs().clone(),
                ExecutionStep::Completed,
            ),
            ReconcileDisposition::RejectedBeforeEffect(evidence) => (
                ReconciliationResult::RejectedBeforeEffect,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::RejectedBeforeEffect,
            ),
            ReconcileDisposition::SafeToRetry(evidence) => (
                ReconciliationResult::SafeToRetry,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::SafeToRetry,
            ),
            ReconcileDisposition::StillIndeterminate(evidence) => (
                ReconciliationResult::StillIndeterminate,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::Indeterminate,
            ),
            ReconcileDisposition::InterventionRequired(evidence) => (
                ReconciliationResult::InterventionRequired,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::InterventionRequired,
            ),
        };
        journal.append_event(ExecutionEventKind::ReconciliationObserved {
            transaction: context.transaction.clone(),
            operation: context.operation.clone(),
            attempt: context.attempt,
            result,
            evidence,
            outputs,
            elapsed_millis: control.elapsed_millis(),
        })?;
        self.observe(Boundary::ReconciliationOutcomeDurable, &control)?;
        Ok(step)
    }

    /// Persists and dispatches an explicitly requested compensation effect.
    pub(crate) fn compensate(
        &mut self,
        journal: &mut impl ExecutionEventSink,
        context: AttemptContext<'_>,
        request: &PreparedRequest<Adapter::Request>,
    ) -> Result<ExecutionStep, ExecutionError> {
        journal.ensure_capacity(4)?;
        let control = LiveControl::new(
            self.clock,
            self.cancellation,
            context.elapsed_millis,
            context.attempt_timeout_millis,
            context.total_recovery_millis,
        );
        if control.is_cancelled() || deadline_expired(&control) {
            let reason = if control.is_cancelled() {
                CompensationInterventionReason::CancelledBeforeIntent
            } else {
                CompensationInterventionReason::DeadlineBeforeIntent
            };
            journal.append_event(ExecutionEventKind::CompensationInterventionRequired {
                transaction: context.transaction.clone(),
                operation: context.operation.clone(),
                reason,
                elapsed_millis: control.elapsed_millis(),
            })?;
            return Ok(ExecutionStep::InterventionRequired);
        }
        journal.append_event(ExecutionEventKind::CompensationIntent {
            transaction: context.transaction.clone(),
            operation: context.operation.clone(),
            request: request.durable().clone(),
            idempotency_key: context.idempotency_key,
            attempt_timeout_millis: context.attempt_timeout_millis,
            elapsed_millis: control.elapsed_millis(),
        })?;
        self.observe(Boundary::EffectIntentDurable, &control)?;
        if control.is_cancelled() || deadline_expired(&control) {
            let reason = if control.is_cancelled() {
                CompensationInterventionReason::CancelledAfterIntent
            } else {
                CompensationInterventionReason::DeadlineAfterIntent
            };
            journal.append_event(ExecutionEventKind::CompensationInterventionRequired {
                transaction: context.transaction.clone(),
                operation: context.operation.clone(),
                reason,
                elapsed_millis: control.elapsed_millis(),
            })?;
            self.observe(Boundary::EffectOutcomeDurable, &control)?;
            return Ok(ExecutionStep::InterventionRequired);
        }

        let Some(disposition) = self.adapter.compensate(request.request(), &control) else {
            journal.append_event(ExecutionEventKind::CompensationInterventionRequired {
                transaction: context.transaction.clone(),
                operation: context.operation.clone(),
                reason: CompensationInterventionReason::AdapterUnavailable,
                elapsed_millis: control.elapsed_millis(),
            })?;
            self.observe(Boundary::EffectOutcomeDurable, &control)?;
            return Ok(ExecutionStep::InterventionRequired);
        };
        self.observe(Boundary::EffectReturned, &control)?;
        let (event, step) = match disposition {
            EffectDisposition::Completed(evidence) => (
                ExecutionEventKind::CompensationCompleted {
                    transaction: context.transaction.clone(),
                    operation: context.operation.clone(),
                    evidence: evidence.durable().clone(),
                    outputs: evidence.outputs().clone(),
                    elapsed_millis: control.elapsed_millis(),
                },
                ExecutionStep::Completed,
            ),
            EffectDisposition::RejectedBeforeEffect(evidence) => (
                ExecutionEventKind::CompensationRejectedBeforeEffect {
                    transaction: context.transaction.clone(),
                    operation: context.operation.clone(),
                    evidence: evidence.durable().clone(),
                    elapsed_millis: control.elapsed_millis(),
                },
                ExecutionStep::RejectedBeforeEffect,
            ),
            EffectDisposition::Indeterminate(evidence) => (
                ExecutionEventKind::CompensationIndeterminate {
                    transaction: context.transaction.clone(),
                    operation: context.operation.clone(),
                    evidence: evidence.durable().clone(),
                    elapsed_millis: control.elapsed_millis(),
                },
                ExecutionStep::Indeterminate,
            ),
        };
        journal.append_event(event)?;
        self.observe(Boundary::EffectOutcomeDurable, &control)?;
        Ok(step)
    }

    /// Reconciles the compensation effect without observing the primary effect.
    pub(crate) fn reconcile_compensation(
        &mut self,
        journal: &mut impl ExecutionEventSink,
        context: AttemptContext<'_>,
        request: &Adapter::Request,
    ) -> Result<ExecutionStep, ExecutionError> {
        journal.ensure_capacity(2)?;
        let control = LiveControl::new(
            self.clock,
            self.cancellation,
            context.elapsed_millis,
            context.attempt_timeout_millis,
            context.total_recovery_millis,
        );
        if deadline_expired(&control) {
            journal.append_event(ExecutionEventKind::CompensationInterventionRequired {
                transaction: context.transaction.clone(),
                operation: context.operation.clone(),
                reason: CompensationInterventionReason::DeadlineAfterIntent,
                elapsed_millis: control.elapsed_millis(),
            })?;
            return Ok(ExecutionStep::InterventionRequired);
        }
        journal.append_event(ExecutionEventKind::CompensationReconciliationIntent {
            transaction: context.transaction.clone(),
            operation: context.operation.clone(),
            call_timeout_millis: context.attempt_timeout_millis,
            elapsed_millis: control.elapsed_millis(),
        })?;
        self.observe(Boundary::ReconciliationIntentDurable, &control)?;
        if deadline_expired(&control) {
            journal.append_event(ExecutionEventKind::CompensationInterventionRequired {
                transaction: context.transaction.clone(),
                operation: context.operation.clone(),
                reason: CompensationInterventionReason::DeadlineAfterIntent,
                elapsed_millis: control.elapsed_millis(),
            })?;
            self.observe(Boundary::ReconciliationOutcomeDurable, &control)?;
            return Ok(ExecutionStep::InterventionRequired);
        }

        let Some(disposition) = self.adapter.reconcile_compensation(request, &control) else {
            journal.append_event(ExecutionEventKind::CompensationInterventionRequired {
                transaction: context.transaction.clone(),
                operation: context.operation.clone(),
                reason: CompensationInterventionReason::AdapterUnavailable,
                elapsed_millis: control.elapsed_millis(),
            })?;
            self.observe(Boundary::ReconciliationOutcomeDurable, &control)?;
            return Ok(ExecutionStep::InterventionRequired);
        };
        self.observe(Boundary::ReconciliationReturned, &control)?;
        let (result, evidence, outputs, step) = match disposition {
            ReconcileDisposition::Completed(evidence) => (
                ReconciliationResult::Completed,
                evidence.durable().clone(),
                evidence.outputs().clone(),
                ExecutionStep::Completed,
            ),
            ReconcileDisposition::RejectedBeforeEffect(evidence) => (
                ReconciliationResult::RejectedBeforeEffect,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::RejectedBeforeEffect,
            ),
            ReconcileDisposition::StillIndeterminate(evidence) => (
                ReconciliationResult::StillIndeterminate,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::Indeterminate,
            ),
            ReconcileDisposition::SafeToRetry(evidence)
            | ReconcileDisposition::InterventionRequired(evidence) => (
                ReconciliationResult::InterventionRequired,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::InterventionRequired,
            ),
        };
        journal.append_event(ExecutionEventKind::CompensationReconciliationObserved {
            transaction: context.transaction.clone(),
            operation: context.operation.clone(),
            result,
            evidence,
            outputs,
            elapsed_millis: control.elapsed_millis(),
        })?;
        self.observe(Boundary::ReconciliationOutcomeDurable, &control)?;
        Ok(step)
    }

    /// Requests cancellation and records what the adapter actually established.
    ///
    /// # Errors
    ///
    /// Returns an error when a journal boundary fails or a configured boundary
    /// hook halts execution. An indeterminate cancellation remains subject to
    /// reconciliation and retains resource ownership.
    pub(crate) fn cancel(
        &mut self,
        journal: &mut impl ExecutionEventSink,
        context: AttemptContext<'_>,
        request: &Adapter::Request,
    ) -> Result<ExecutionStep, ExecutionError> {
        journal.ensure_capacity(2)?;
        let control = LiveControl::new(
            self.clock,
            self.cancellation,
            context.elapsed_millis,
            context.attempt_timeout_millis,
            context.total_recovery_millis,
        );
        if deadline_expired(&control) {
            return Err(ExecutionError::RecoveryDeadlineExpired);
        }
        journal.append_event(ExecutionEventKind::CancellationRequested {
            transaction: context.transaction.clone(),
            operation: context.operation.clone(),
            attempt: context.attempt,
            call_timeout_millis: context.attempt_timeout_millis,
            elapsed_millis: control.elapsed_millis(),
        })?;
        self.observe(Boundary::CancellationIntentDurable, &control)?;
        if deadline_expired(&control) {
            return Err(ExecutionError::RecoveryDeadlineExpired);
        }

        let cancellation_control = CancellationCallControl::new(&control);
        let disposition = self.adapter.cancel(request, &cancellation_control);
        self.observe(Boundary::CancellationReturned, &control)?;
        let (result, evidence, outputs, step) = match disposition {
            CancellationDisposition::RejectedBeforeEffect(evidence) => (
                CancellationResult::RejectedBeforeEffect,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::RejectedBeforeEffect,
            ),
            CancellationDisposition::Completed(evidence) => (
                CancellationResult::Completed,
                evidence.durable().clone(),
                evidence.outputs().clone(),
                ExecutionStep::Completed,
            ),
            CancellationDisposition::Indeterminate(evidence) => (
                CancellationResult::Indeterminate,
                evidence.durable().clone(),
                BTreeMap::new(),
                ExecutionStep::Indeterminate,
            ),
        };
        journal.append_event(ExecutionEventKind::CancellationObserved {
            transaction: context.transaction.clone(),
            operation: context.operation.clone(),
            attempt: context.attempt,
            result,
            evidence,
            outputs,
            elapsed_millis: control.elapsed_millis(),
        })?;
        self.observe(Boundary::CancellationOutcomeDurable, &control)?;
        Ok(step)
    }

    fn observe(
        &mut self,
        boundary: Boundary,
        control: &dyn RuntimeControl,
    ) -> Result<(), ExecutionError> {
        match self
            .hook
            .observe(boundary, control)
            .map_err(ExecutionError::BoundaryObservation)?
        {
            ExecutionBoundaryControl::Continue => Ok(()),
            ExecutionBoundaryControl::Halt => Err(ExecutionError::BoundaryHalt(boundary)),
        }
    }
}

fn deadline_expired(control: &dyn RuntimeControl) -> bool {
    control.attempt_remaining_millis() == 0 || control.recovery_remaining_millis() == 0
}

/// Supplies stable identifiers and bounded time policy for one operation attempt.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AttemptContext<'a> {
    /// Identifies the durable transaction.
    pub transaction: &'a TransactionId,
    /// Identifies the exact operation.
    pub operation: &'a OperationId,
    /// Identifies this attempt under the stable operation identity.
    pub attempt: NonZeroU32,
    /// Identifies the logical operation consistently across retries.
    pub idempotency_key: aos_contract::Sha256Digest,
    /// Retains elapsed budget from previous live processes.
    pub elapsed_millis: u64,
    /// Bounds this adapter call.
    pub attempt_timeout_millis: u64,
    /// Bounds all attempts and recovery across restarts.
    pub total_recovery_millis: u64,
}

struct LiveControl<'a, Clock> {
    clock: &'a Clock,
    cancellation: &'a CancellationToken,
    started_at: u64,
    prior_elapsed: u64,
    attempt_timeout: u64,
    total_recovery: u64,
}

impl<'a, Clock> LiveControl<'a, Clock>
where
    Clock: MonotonicClock,
{
    fn new(
        clock: &'a Clock,
        cancellation: &'a CancellationToken,
        prior_elapsed: u64,
        attempt_timeout: u64,
        total_recovery: u64,
    ) -> Self {
        Self {
            clock,
            cancellation,
            started_at: clock.now_millis(),
            prior_elapsed,
            attempt_timeout,
            total_recovery,
        }
    }

    fn live_elapsed(&self) -> u64 {
        self.clock.now_millis().saturating_sub(self.started_at)
    }
}

impl<Clock> RuntimeControl for LiveControl<'_, Clock>
where
    Clock: MonotonicClock,
{
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn elapsed_millis(&self) -> u64 {
        self.prior_elapsed.saturating_add(self.live_elapsed())
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.attempt_timeout.saturating_sub(self.live_elapsed())
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.total_recovery.saturating_sub(self.elapsed_millis())
    }
}

/// Keeps a cancellation adapter's postcondition work usable after cancellation.
///
/// The live cancellation signal selects the durable cancellation path. Once
/// that intent is recorded, the adapter must still be able to run bounded
/// helpers that establish or observe the requested postcondition.
struct CancellationCallControl<'a> {
    live: &'a dyn RuntimeControl,
}

impl<'a> CancellationCallControl<'a> {
    fn new(live: &'a dyn RuntimeControl) -> Self {
        Self { live }
    }
}

impl RuntimeControl for CancellationCallControl<'_> {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn elapsed_millis(&self) -> u64 {
        self.live.elapsed_millis()
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.live.attempt_remaining_millis()
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.live.recovery_remaining_millis()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io;
    use std::num::NonZeroU32;
    use std::rc::Rc;

    use aos_ability_model::{
        AbilityValue, LocalKey, Operation, OperationId, PlanId, ScopePath, ScopedOperationKey,
        TransactionId,
    };
    use aos_contract::Sha256Digest;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::adapter::{AdapterRecord, ResourceHandle};
    use crate::execution::{CompensationState, ExecutionEvent, OperationHistory, RecoveryAction};
    use crate::journal::{FileJournal, JournalLimits};

    #[test]
    fn halt_after_intent_never_dispatches_and_recovers_by_reconciliation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut journal = fixture.journal_with_admission()?;
        let clock = TestClock::default();
        let cancellation = CancellationToken::default();
        let mut hook = StopAt::new(Boundary::EffectIntentDurable, clock.now.clone(), None);
        let mut adapter = TestAdapter::completed(fixture.evidence()?);
        let request_value = AbilityValue::new(json!({"revision": 2}))?;
        let request = PreparedRequest::new(request_value.clone(), request_value);

        let error = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
            .execute(&mut journal, fixture.context(), &request)
            .expect_err("fault injection must halt immediately after durable intent");
        assert!(matches!(
            error,
            ExecutionError::BoundaryHalt(Boundary::EffectIntentDurable)
        ));
        assert_eq!(adapter.execute_calls, 0);
        drop(journal);

        let recovered = fixture.recover_history()?;
        assert!(matches!(
            recovered.recovery_action(&aos_ability_model::RetryPolicy::Disabled, 100),
            RecoveryAction::ReconcileBeforeRetry { .. }
        ));
        Ok(())
    }

    #[test]
    fn deadline_expiring_while_syncing_intent_prevents_adapter_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut journal = fixture.journal_with_admission()?;
        let clock = TestClock::default();
        let cancellation = CancellationToken::default();
        let mut hook = StopAt::new(
            Boundary::ReconciliationOutcomeDurable,
            clock.now.clone(),
            Some(20),
        );
        let mut adapter = TestAdapter::completed(fixture.evidence()?);
        let request_value = AbilityValue::new(json!({"revision": 2}))?;
        let request = PreparedRequest::new(request_value.clone(), request_value);

        let step = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook).execute(
            &mut journal,
            fixture.context(),
            &request,
        )?;
        assert_eq!(step, ExecutionStep::RejectedBeforeEffect);
        assert_eq!(adapter.execute_calls, 0);
        drop(journal);

        let recovered = fixture.recover_history()?;
        assert!(matches!(
            recovered.state(),
            crate::execution::OperationState::DispatchAborted {
                reason: DispatchAbortReason::DeadlineExpired,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn cancellation_after_intent_records_runtime_abort_without_adapter_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut journal = fixture.journal_with_admission()?;
        let clock = TestClock::default();
        let cancellation = CancellationToken::default();
        let mut hook = CancelAtEffectIntent(cancellation.clone());
        let mut adapter = TestAdapter::completed(AbilityValue::new(json!(true))?);
        let request_value = AbilityValue::new(json!(2))?;
        let request = PreparedRequest::new(request_value.clone(), request_value);

        let step = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook).execute(
            &mut journal,
            fixture.context(),
            &request,
        )?;

        assert_eq!(step, ExecutionStep::RejectedBeforeEffect);
        assert_eq!(adapter.execute_calls, 0);
        drop(journal);

        let recovered = fixture.recover_history()?;
        assert!(matches!(
            recovered.state(),
            crate::execution::OperationState::DispatchAborted {
                reason: DispatchAbortReason::Cancelled,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn crash_after_external_return_cannot_publish_completion_to_dependents()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut journal = fixture.journal_with_admission()?;
        let clock = TestClock::default();
        let cancellation = CancellationToken::default();
        let mut hook = StopAt::new(Boundary::EffectReturned, clock.now.clone(), None);
        let mut adapter = TestAdapter::completed(fixture.evidence()?);
        let request_value = AbilityValue::new(json!({"revision": 2}))?;
        let request = PreparedRequest::new(request_value.clone(), request_value);

        let error = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
            .execute(&mut journal, fixture.context(), &request)
            .expect_err("fault injection must halt before completion persistence");
        assert!(matches!(
            error,
            ExecutionError::BoundaryHalt(Boundary::EffectReturned)
        ));
        assert_eq!(adapter.execute_calls, 1);
        drop(journal);

        let recovered = fixture.recover_history()?;
        assert!(matches!(
            recovered.recovery_action(&aos_ability_model::RetryPolicy::Disabled, 100),
            RecoveryAction::ReconcileBeforeRetry { .. }
        ));
        Ok(())
    }

    #[test]
    fn deadline_expiring_while_syncing_reconciliation_intent_prevents_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut journal = fixture.journal_with_intent()?;
        let clock = TestClock::default();
        let cancellation = CancellationToken::default();
        let mut hook = StopAt::new(Boundary::EffectOutcomeDurable, clock.now.clone(), Some(20));
        let mut adapter = TestAdapter::completed(fixture.evidence()?);
        let request = AbilityValue::new(json!({"revision": 2}))?;

        let error = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
            .reconcile(&mut journal, fixture.context(), &request)
            .expect_err("expired recovery budget must stop reconciliation dispatch");

        assert!(matches!(error, ExecutionError::RecoveryDeadlineExpired));
        assert_eq!(adapter.reconcile_calls, 0);
        Ok(())
    }

    #[test]
    fn deadline_expiring_while_syncing_cancellation_intent_prevents_adapter_call()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut journal = fixture.journal_with_intent()?;
        let clock = TestClock::default();
        let cancellation = CancellationToken::default();
        let mut hook = StopAt::new(Boundary::EffectOutcomeDurable, clock.now.clone(), Some(20));
        let mut adapter = TestAdapter::completed(fixture.evidence()?);
        let request = AbilityValue::new(json!({"revision": 2}))?;

        let error = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
            .cancel(&mut journal, fixture.context(), &request)
            .expect_err("expired recovery budget must stop cancellation dispatch");

        assert!(matches!(error, ExecutionError::RecoveryDeadlineExpired));
        assert_eq!(adapter.cancel_calls, 0);
        Ok(())
    }

    #[test]
    fn cancellation_adapter_receives_usable_control_with_live_budgets()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut journal = fixture.journal_with_intent()?;
        let clock = TestClock::default();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let mut hook = RecordingControlHook::default();
        let mut adapter = TestAdapter::completed(fixture.evidence()?);
        let request = AbilityValue::new(json!({"revision": 2}))?;
        let context = AttemptContext {
            elapsed_millis: 7,
            attempt_timeout_millis: 40,
            total_recovery_millis: 90,
            ..fixture.context()
        };

        let step = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook).cancel(
            &mut journal,
            context,
            &request,
        )?;

        assert_eq!(step, ExecutionStep::Indeterminate);
        assert_eq!(adapter.cancel_control, Some((false, 7, 40, 83)));
        assert_eq!(
            hook.observations,
            [
                (Boundary::CancellationIntentDurable, true),
                (Boundary::CancellationReturned, true),
                (Boundary::CancellationOutcomeDurable, true),
            ]
        );
        Ok(())
    }

    #[test]
    fn compensation_deadline_after_intent_records_durable_intervention()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut journal = fixture.journal_with_compensation_admission()?;
        let clock = TestClock::default();
        let cancellation = CancellationToken::default();
        let mut hook = AdvanceAtEffectIntent {
            clock: clock.now.clone(),
            now: 100,
        };
        let mut adapter = TestAdapter::completed(fixture.evidence()?);
        let request_value = AbilityValue::new(json!({"revision": 2}))?;
        let request = PreparedRequest::new(request_value.clone(), request_value);

        let step = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
            .compensate(&mut journal, fixture.context(), &request)?;
        assert_eq!(step, ExecutionStep::InterventionRequired);
        assert_eq!(adapter.execute_calls, 0);
        drop(journal);

        let recovered = fixture.recover_history()?;
        assert!(matches!(
            recovered.compensation_state(),
            Some(CompensationState::InterventionRequired {
                reason: CompensationInterventionReason::DeadlineAfterIntent,
                evidence: None,
            })
        ));
        assert_eq!(
            recovered.recovery_action(&aos_ability_model::RetryPolicy::Disabled, 100),
            RecoveryAction::CompensationInterventionRequired
        );
        Ok(())
    }

    #[derive(Default)]
    struct TestClock {
        now: Rc<Cell<u64>>,
    }

    impl MonotonicClock for TestClock {
        fn now_millis(&self) -> u64 {
            self.now.get()
        }

        fn restart_stable_millis(&self) -> u64 {
            self.now.get()
        }
    }

    struct StopAt {
        boundary: Boundary,
        clock: Rc<Cell<u64>>,
        advance_at_intent: Option<u64>,
    }

    impl StopAt {
        fn new(boundary: Boundary, clock: Rc<Cell<u64>>, advance_at_intent: Option<u64>) -> Self {
            Self {
                boundary,
                clock,
                advance_at_intent,
            }
        }
    }

    impl BoundaryHook for StopAt {
        fn observe(
            &mut self,
            boundary: Boundary,
            _control: &dyn RuntimeControl,
        ) -> anyhow::Result<ExecutionBoundaryControl> {
            if matches!(
                boundary,
                Boundary::EffectIntentDurable
                    | Boundary::ReconciliationIntentDurable
                    | Boundary::CancellationIntentDurable
            ) {
                if let Some(now) = self.advance_at_intent {
                    self.clock.set(now);
                }
            }
            Ok(if boundary == self.boundary {
                ExecutionBoundaryControl::Halt
            } else {
                ExecutionBoundaryControl::Continue
            })
        }
    }

    struct CancelAtEffectIntent(CancellationToken);

    impl BoundaryHook for CancelAtEffectIntent {
        fn observe(
            &mut self,
            boundary: Boundary,
            _control: &dyn RuntimeControl,
        ) -> anyhow::Result<ExecutionBoundaryControl> {
            if boundary == Boundary::EffectIntentDurable {
                self.0.cancel();
            }
            Ok(ExecutionBoundaryControl::Continue)
        }
    }

    #[derive(Default)]
    struct RecordingControlHook {
        observations: Vec<(Boundary, bool)>,
    }

    impl BoundaryHook for RecordingControlHook {
        fn observe(
            &mut self,
            boundary: Boundary,
            control: &dyn RuntimeControl,
        ) -> anyhow::Result<ExecutionBoundaryControl> {
            self.observations.push((boundary, control.is_cancelled()));
            Ok(ExecutionBoundaryControl::Continue)
        }
    }

    struct AdvanceAtEffectIntent {
        clock: Rc<Cell<u64>>,
        now: u64,
    }

    impl BoundaryHook for AdvanceAtEffectIntent {
        fn observe(
            &mut self,
            boundary: Boundary,
            _control: &dyn RuntimeControl,
        ) -> anyhow::Result<ExecutionBoundaryControl> {
            if boundary == Boundary::EffectIntentDurable {
                self.clock.set(self.now);
            }
            Ok(ExecutionBoundaryControl::Continue)
        }
    }

    struct TestRecord {
        durable: AbilityValue,
        outputs: BTreeMap<aos_ability_model::LocalKey, AbilityValue>,
    }

    fn test_record(durable: AbilityValue) -> TestRecord {
        TestRecord {
            durable,
            outputs: BTreeMap::new(),
        }
    }

    impl AdapterRecord for TestRecord {
        fn durable(&self) -> &AbilityValue {
            &self.durable
        }
    }

    impl AdapterCompletion for TestRecord {
        fn outputs(&self) -> &BTreeMap<aos_ability_model::LocalKey, AbilityValue> {
            &self.outputs
        }
    }

    struct TestAdapter {
        completion: Option<TestRecord>,
        execute_calls: usize,
        reconcile_calls: usize,
        cancel_calls: usize,
        cancel_control: Option<(bool, u64, u64, u64)>,
    }

    impl TestAdapter {
        fn completed(value: AbilityValue) -> Self {
            Self {
                completion: Some(test_record(value)),
                execute_calls: 0,
                reconcile_calls: 0,
                cancel_calls: 0,
                cancel_control: None,
            }
        }
    }

    impl TrustedAdapter for TestAdapter {
        type Request = AbilityValue;
        type Completion = TestRecord;
        type Observation = TestRecord;
        type Handle = ();
        type PrepareError = io::Error;

        fn prepare_durable(
            &self,
            _operation: &Operation,
            _inputs: &AbilityValue,
            _resources: &[ResourceHandle<Self::Handle>],
        ) -> Result<AbilityValue, Self::PrepareError> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not used by this operation-machine test",
            ))
        }

        fn recover_request(
            &self,
            durable: &AbilityValue,
            _resources: &[ResourceHandle<Self::Handle>],
        ) -> Result<Self::Request, Self::PrepareError> {
            Ok(durable.clone())
        }

        fn execute(
            &mut self,
            _request: &Self::Request,
            _control: &dyn RuntimeControl,
        ) -> EffectDisposition<Self::Completion, Self::Observation> {
            self.execute_calls += 1;
            match self.completion.take() {
                Some(completion) => EffectDisposition::Completed(completion),
                None => EffectDisposition::Indeterminate(test_record(
                    AbilityValue::new(json!({"reason": "duplicate-dispatch"}))
                        .expect("test observation must be bounded"),
                )),
            }
        }

        fn reconcile(
            &mut self,
            _request: &Self::Request,
            _control: &dyn RuntimeControl,
        ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
            self.reconcile_calls += 1;
            ReconcileDisposition::InterventionRequired(test_record(
                AbilityValue::new(json!({"reason": "test-only"}))
                    .expect("test observation must be bounded"),
            ))
        }

        fn cancel(
            &mut self,
            _request: &Self::Request,
            control: &dyn RuntimeControl,
        ) -> CancellationDisposition<Self::Completion, Self::Observation> {
            self.cancel_calls += 1;
            self.cancel_control = Some((
                control.is_cancelled(),
                control.elapsed_millis(),
                control.attempt_remaining_millis(),
                control.recovery_remaining_millis(),
            ));
            CancellationDisposition::Indeterminate(test_record(
                AbilityValue::new(json!({"reason": "test-only"}))
                    .expect("test observation must be bounded"),
            ))
        }
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

        fn journal_with_admission(
            &self,
        ) -> Result<FileJournal<ExecutionEvent>, Box<dyn std::error::Error>> {
            let opened = FileJournal::open(self.path(), JournalLimits::default())?;
            let mut journal = opened.journal;
            journal.append(&ExecutionEvent::new(
                ExecutionEventKind::TransactionPlanned {
                    transaction: self.transaction.clone(),
                    plan: self.operation.plan,
                    plan_bundle: Sha256Digest::of_bytes("checked-plan-bundle"),
                    retained_roots: Vec::new(),
                    total_recovery_millis: 100,
                },
            ))?;
            journal.append(&ExecutionEvent::new(
                ExecutionEventKind::OperationAdmitted {
                    transaction: self.transaction.clone(),
                    operation: self.operation.clone(),
                    attempt: NonZeroU32::new(1).expect("test attempt must be nonzero"),
                    resources: Vec::new(),
                    elapsed_millis: 0,
                },
            ))?;
            Ok(journal)
        }

        fn context(&self) -> AttemptContext<'_> {
            AttemptContext {
                transaction: &self.transaction,
                operation: &self.operation,
                attempt: NonZeroU32::new(1).expect("test attempt must be nonzero"),
                idempotency_key: Sha256Digest::of_bytes("logical-operation"),
                elapsed_millis: 0,
                attempt_timeout_millis: 10,
                total_recovery_millis: 100,
            }
        }

        fn journal_with_intent(
            &self,
        ) -> Result<FileJournal<ExecutionEvent>, Box<dyn std::error::Error>> {
            let mut journal = self.journal_with_admission()?;
            let request = AbilityValue::new(json!({"revision": 2}))?;
            journal.append(&ExecutionEvent::new(ExecutionEventKind::EffectIntent {
                transaction: self.transaction.clone(),
                operation: self.operation.clone(),
                attempt: NonZeroU32::new(1).expect("test attempt must be nonzero"),
                request,
                idempotency_key: Sha256Digest::of_bytes("logical-operation"),
                attempt_timeout_millis: 10,
                elapsed_millis: 0,
            }))?;
            Ok(journal)
        }

        fn journal_with_compensation_admission(
            &self,
        ) -> Result<FileJournal<ExecutionEvent>, Box<dyn std::error::Error>> {
            let mut journal = self.journal_with_intent()?;
            journal.append(&ExecutionEvent::new(ExecutionEventKind::EffectCompleted {
                transaction: self.transaction.clone(),
                operation: self.operation.clone(),
                attempt: NonZeroU32::MIN,
                evidence: self.evidence()?,
                outputs: BTreeMap::new(),
                elapsed_millis: 0,
            }))?;
            journal.append(&ExecutionEvent::new(
                ExecutionEventKind::CompensationRequested {
                    transaction: self.transaction.clone(),
                    operation: self.operation.clone(),
                    reason: AbilityValue::new(json!("test rollback"))?,
                    elapsed_millis: 0,
                },
            ))?;
            journal.append(&ExecutionEvent::new(
                ExecutionEventKind::CompensationAdmitted {
                    transaction: self.transaction.clone(),
                    operation: self.operation.clone(),
                    resources: Vec::new(),
                    elapsed_millis: 0,
                },
            ))?;
            Ok(journal)
        }

        fn evidence(&self) -> Result<AbilityValue, Box<dyn std::error::Error>> {
            Ok(AbilityValue::new(
                json!({"revision": 2, "status": "ready"}),
            )?)
        }

        fn recover_history(&self) -> Result<OperationHistory, Box<dyn std::error::Error>> {
            let records =
                FileJournal::<ExecutionEvent>::open(self.path(), JournalLimits::default())?
                    .recovery
                    .into_records();
            Ok(OperationHistory::replay(
                self.transaction.clone(),
                self.operation.clone(),
                &records,
            )?)
        }

        fn path(&self) -> std::path::PathBuf {
            self.directory.path().join("execution.journal")
        }
    }
}
