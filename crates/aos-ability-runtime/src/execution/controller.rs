//! Public admitted-token driver for effect and recovery transitions.

use std::num::NonZeroU32;

use aos_ability_model::MethodReference;
use aos_contract::Sha256Digest;

use crate::adapter::{CancellationToken, InvocationPurpose, MonotonicClock, TrustedAdapter};
use crate::execution::admission::check_invocation;
use crate::execution::machine::{AttemptContext, NoopBoundaryHook, OperationExecutor};
use crate::execution::{
    AdmittedOperation, CompensationInterventionReason, ExecutionError, ExecutionStep,
    ExecutionTransaction, RecoveryAction, TrustedAdmissionPolicy,
};

impl<'plan> ExecutionTransaction<'plan> {
    /// Advances one freshly authorized token through effect or reconciliation.
    ///
    /// The current durable state selects effect dispatch versus reconciliation.
    /// The driver rechecks policy and held-resource evidence immediately before
    /// persisting intent. A stale token can never dispatch a second effect.
    ///
    /// # Errors
    ///
    /// Returns an error when the token does not match current replay state,
    /// current policy has changed, the finite deadline is exhausted, a journal
    /// boundary fails, or the trusted adapter outcome violates checked runtime
    /// schemas.
    pub fn drive_admitted<Adapter, Policy, Clock>(
        &mut self,
        admitted: &AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        adapter: &mut Adapter,
        policy: &mut Policy,
        clock: &Clock,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionStep, ExecutionError>
    where
        Adapter: TrustedAdapter,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
    {
        let (action, context) = match self.dispatch_context::<Adapter, Clock>(admitted, clock) {
            Ok(dispatch) => dispatch,
            Err(error @ ExecutionError::DeadlineBeforeIntent)
                if is_compensation_purpose(admitted.invocation_purpose()) =>
            {
                let elapsed_millis = observed_operation_elapsed(admitted, clock);
                self.record_admitted_compensation_deadline(admitted, elapsed_millis)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let (method, purpose) = match action {
            RecoveryAction::Execute { .. } => (
                MethodReference {
                    interface: admitted.operation().interface.clone(),
                    method: admitted.operation().method.clone(),
                },
                InvocationPurpose::Effect,
            ),
            RecoveryAction::ReconcileBeforeRetry { .. } => (
                admitted
                    .operation()
                    .recovery
                    .reconcile
                    .clone()
                    .ok_or(ExecutionError::StaleAdmission)?,
                InvocationPurpose::Reconcile,
            ),
            RecoveryAction::ExecuteCompensation => (
                admitted
                    .operation()
                    .recovery
                    .compensate
                    .clone()
                    .ok_or(ExecutionError::StaleAdmission)?,
                InvocationPurpose::Compensate,
            ),
            RecoveryAction::ReconcileCompensation => (
                admitted
                    .operation()
                    .recovery
                    .reconcile
                    .clone()
                    .ok_or(ExecutionError::StaleAdmission)?,
                InvocationPurpose::ReconcileCompensation,
            ),
            _ => return Err(ExecutionError::StaleAdmission),
        };

        authorize_dispatch(admitted, adapter, policy, &method, purpose)?;
        let persisted_elapsed = self
            .history(&admitted.operation().key)
            .map_err(ExecutionError::Transaction)?
            .elapsed_millis();
        let elapsed_after_policy =
            observed_operation_elapsed(admitted, clock).max(persisted_elapsed);
        if let Err(error @ ExecutionError::DeadlineBeforeIntent) =
            ensure_dispatch_budget(self, admitted, persisted_elapsed, elapsed_after_policy)
        {
            if is_compensation_purpose(admitted.invocation_purpose()) {
                self.record_admitted_compensation_deadline(admitted, elapsed_after_policy)?;
            }
            return Err(error);
        }
        let context = AttemptContext {
            elapsed_millis: elapsed_after_policy,
            ..context
        };

        let mut hook = NoopBoundaryHook;
        let mut executor = OperationExecutor::new(adapter, clock, cancellation, &mut hook);
        match action {
            RecoveryAction::Execute { .. } => {
                executor.execute(self, context, admitted.prepared_request())
            }
            RecoveryAction::ReconcileBeforeRetry { .. } => {
                executor.reconcile(self, context, admitted.prepared_request().request())
            }
            RecoveryAction::ExecuteCompensation => {
                executor.compensate(self, context, admitted.prepared_request())
            }
            RecoveryAction::ReconcileCompensation => executor.reconcile_compensation(
                self,
                context,
                admitted.prepared_request().request(),
            ),
            _ => Err(ExecutionError::StaleAdmission),
        }
    }

    /// Requests checked cancellation for one current admitted attempt.
    ///
    /// # Errors
    ///
    /// Returns an error when cancellation is absent from the checked contract,
    /// the token is stale, fresh policy rejects it, its deadline is exhausted,
    /// or the cancellation intent/outcome cannot be made durable.
    pub fn cancel_admitted<Adapter, Policy, Clock>(
        &mut self,
        admitted: &AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        adapter: &mut Adapter,
        policy: &mut Policy,
        clock: &Clock,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionStep, ExecutionError>
    where
        Adapter: TrustedAdapter,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
    {
        if !matches!(
            admitted.invocation_purpose(),
            InvocationPurpose::Effect | InvocationPurpose::Reconcile
        ) {
            return Err(ExecutionError::StaleAdmission);
        }
        let (_, mut context) = self.dispatch_context::<Adapter, Clock>(admitted, clock)?;
        let method = admitted
            .operation()
            .recovery
            .cancel
            .clone()
            .ok_or(ExecutionError::StaleAdmission)?;
        authorize_dispatch(
            admitted,
            adapter,
            policy,
            &method,
            InvocationPurpose::Cancel,
        )?;
        let persisted_elapsed = self
            .history(&admitted.operation().key)
            .map_err(ExecutionError::Transaction)?
            .elapsed_millis();
        context.elapsed_millis = observed_operation_elapsed(admitted, clock).max(persisted_elapsed);
        ensure_dispatch_budget(self, admitted, persisted_elapsed, context.elapsed_millis)?;

        let mut hook = NoopBoundaryHook;
        let mut executor = OperationExecutor::new(adapter, clock, cancellation, &mut hook);
        executor.cancel(self, context, admitted.prepared_request().request())
    }

    fn dispatch_context<'token, Adapter, Clock>(
        &self,
        admitted: &'token AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        clock: &Clock,
    ) -> Result<(RecoveryAction, AttemptContext<'token>), ExecutionError>
    where
        Adapter: TrustedAdapter,
        Clock: MonotonicClock,
    {
        if !admitted.belongs_to_session(self.session())
            || admitted.plan().id() != self.plan().id()
            || admitted.transaction() != self.transaction()
            || admitted.operation_id().operation != admitted.operation().key
        {
            return Err(ExecutionError::StaleAdmission);
        }
        let history = self
            .history(&admitted.operation().key)
            .map_err(ExecutionError::Transaction)?;
        let action = self
            .next_action(&admitted.operation().key)
            .map_err(ExecutionError::Transaction)?;
        if matches!(action, RecoveryAction::Execute { .. }) {
            self.check_operation_ready(&admitted.operation().key)
                .map_err(ExecutionError::Transaction)?;
        }
        let (expected_attempt, expected_purpose) = match action {
            RecoveryAction::Execute { attempt } => (attempt, InvocationPurpose::Effect),
            RecoveryAction::ReconcileBeforeRetry { attempt } => {
                (attempt, InvocationPurpose::Reconcile)
            }
            RecoveryAction::ExecuteCompensation => (NonZeroU32::MIN, InvocationPurpose::Compensate),
            RecoveryAction::ReconcileCompensation => {
                (NonZeroU32::MIN, InvocationPurpose::ReconcileCompensation)
            }
            _ => return Err(ExecutionError::StaleAdmission),
        };
        let resources_match = admitted.resources().eq(history.admitted_resources().iter());
        let released_nonempty_resources =
            !history.admitted_resources().is_empty() && history.resources_released();
        if expected_attempt != admitted.attempt()
            || expected_purpose != admitted.invocation_purpose()
            || admitted.operation_sequence() != history.last_sequence()
            || !resources_match
            || released_nonempty_resources
        {
            return Err(ExecutionError::StaleAdmission);
        }

        let elapsed_millis =
            observed_operation_elapsed(admitted, clock).max(history.elapsed_millis());
        ensure_dispatch_budget(self, admitted, history.elapsed_millis(), elapsed_millis)?;
        let compensation = matches!(
            action,
            RecoveryAction::ExecuteCompensation | RecoveryAction::ReconcileCompensation
        );
        let idempotency_key = match if compensation {
            history.compensation_idempotency_key()
        } else {
            history.idempotency_key()
        } {
            Some(key) => key,
            None if compensation => compensation_idempotency_key(admitted)?,
            None => logical_idempotency_key(admitted)?,
        };
        Ok((
            action,
            AttemptContext {
                transaction: admitted.transaction(),
                operation: admitted.operation_id(),
                attempt: admitted.attempt(),
                idempotency_key,
                elapsed_millis,
                attempt_timeout_millis: admitted.operation().deadline.attempt_timeout_millis.get(),
                total_recovery_millis: admitted.operation().deadline.total_recovery_millis.get(),
            },
        ))
    }

    fn record_admitted_compensation_deadline<Request, Handle>(
        &mut self,
        admitted: &AdmittedOperation<'_, Request, Handle>,
        elapsed_millis: u64,
    ) -> Result<(), ExecutionError> {
        let reason = match admitted.invocation_purpose() {
            InvocationPurpose::Compensate => CompensationInterventionReason::DeadlineBeforeIntent,
            InvocationPurpose::ReconcileCompensation => {
                CompensationInterventionReason::DeadlineAfterIntent
            }
            _ => return Ok(()),
        };
        self.record_compensation_intervention(&admitted.operation().key, reason, elapsed_millis)
            .map_err(ExecutionError::Transaction)
    }
}

fn is_compensation_purpose(purpose: InvocationPurpose) -> bool {
    matches!(
        purpose,
        InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation
    )
}

fn authorize_dispatch<Adapter, Policy>(
    admitted: &AdmittedOperation<'_, Adapter::Request, Adapter::Handle>,
    adapter: &Adapter,
    policy: &mut Policy,
    method: &MethodReference,
    purpose: InvocationPurpose,
) -> Result<(), ExecutionError>
where
    Adapter: TrustedAdapter,
    Policy: TrustedAdmissionPolicy,
{
    check_invocation(
        admitted.plan(),
        admitted.operation(),
        admitted.binding(),
        method,
        purpose,
        adapter,
        policy,
    )
    .map_err(ExecutionError::DispatchAdmission)?;
    let evidence = admitted.resource_evidence();
    policy
        .authorize_resources(
            admitted.plan(),
            admitted.binding(),
            admitted.operation(),
            admitted.expected_provider(),
            &evidence,
        )
        .map_err(|source| ExecutionError::DispatchAuthorization(anyhow::Error::new(source)))
}

fn observed_operation_elapsed<Request, Handle, Clock>(
    admitted: &AdmittedOperation<'_, Request, Handle>,
    clock: &Clock,
) -> u64
where
    Clock: MonotonicClock,
{
    admitted.elapsed_millis().saturating_add(
        clock
            .now_millis()
            .saturating_sub(admitted.clock_observed_at()),
    )
}

fn ensure_dispatch_budget<Request, Handle>(
    transaction: &ExecutionTransaction<'_>,
    admitted: &AdmittedOperation<'_, Request, Handle>,
    persisted_operation_elapsed: u64,
    operation_elapsed: u64,
) -> Result<(), ExecutionError> {
    if admitted.deadline_expired()
        || operation_elapsed >= admitted.operation().deadline.total_recovery_millis.get()
    {
        return Err(ExecutionError::DeadlineBeforeIntent);
    }
    let candidate_transaction_elapsed = transaction
        .elapsed_millis()
        .saturating_sub(persisted_operation_elapsed)
        .saturating_add(operation_elapsed);
    if candidate_transaction_elapsed >= transaction.total_recovery_millis() {
        return Err(ExecutionError::DeadlineBeforeIntent);
    }
    Ok(())
}

fn logical_idempotency_key<Request, Handle>(
    admitted: &AdmittedOperation<'_, Request, Handle>,
) -> Result<Sha256Digest, ExecutionError> {
    Sha256Digest::of_canonical(
        "aos.ability.operation-idempotency-key/v1",
        &(admitted.transaction(), admitted.operation_id()),
    )
    .map_err(ExecutionError::Identity)
}

fn compensation_idempotency_key<Request, Handle>(
    admitted: &AdmittedOperation<'_, Request, Handle>,
) -> Result<Sha256Digest, ExecutionError> {
    Sha256Digest::of_canonical(
        "aos.ability.compensation-idempotency-key/v1",
        &(admitted.transaction(), admitted.operation_id()),
    )
    .map_err(ExecutionError::Identity)
}
