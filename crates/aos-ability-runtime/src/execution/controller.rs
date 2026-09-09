//! Public admitted-token driver for effect and recovery transitions.

use aos_ability_model::MethodReference;
use aos_contract::Sha256Digest;

use crate::adapter::{CancellationToken, InvocationPurpose, MonotonicClock, TrustedAdapter};
use crate::execution::admission::check_invocation;
use crate::execution::machine::{AttemptContext, NoopBoundaryHook, OperationExecutor};
use crate::execution::{
    AdmittedOperation, ExecutionError, ExecutionStep, ExecutionTransaction, RecoveryAction,
    TrustedAdmissionPolicy,
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
        let (action, context) = self.dispatch_context::<Adapter, Clock>(admitted, clock)?;
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
            _ => return Err(ExecutionError::StaleAdmission),
        };

        authorize_dispatch(admitted, adapter, policy, &method, purpose)?;
        let persisted_elapsed = self
            .history(&admitted.operation().key)
            .map_err(ExecutionError::Transaction)?
            .elapsed_millis();
        let elapsed_after_policy =
            observed_operation_elapsed(admitted, clock).max(persisted_elapsed);
        ensure_dispatch_budget(self, admitted, persisted_elapsed, elapsed_after_policy)?;
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
        let expected_attempt = match action {
            RecoveryAction::Execute { attempt }
            | RecoveryAction::ReconcileBeforeRetry { attempt } => attempt,
            _ => return Err(ExecutionError::StaleAdmission),
        };
        if expected_attempt != admitted.attempt() {
            return Err(ExecutionError::StaleAdmission);
        }

        let elapsed_millis =
            observed_operation_elapsed(admitted, clock).max(history.elapsed_millis());
        ensure_dispatch_budget(self, admitted, history.elapsed_millis(), elapsed_millis)?;
        let idempotency_key = match history.idempotency_key() {
            Some(key) => key,
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
