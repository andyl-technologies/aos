//! Fresh runtime admission for semantically checked effect-plan operations.

use std::num::NonZeroU32;
use std::sync::Arc;

use aos_ability_model::{
    Binding, MethodReference, Operation, OperationId, ResourceId, ScopedOperationKey,
    TransactionId, compare_resource_ids,
};
use aos_ability_validate::{CheckedEffectPlan, InvocationAuthorizationError};
use thiserror::Error;

use crate::adapter::{
    InvocationPurpose, MonotonicClock, PreparedRequest, ReservationContext,
    ResourceAdmissionEvidence, ResourceHandle, TrustedAdapter, TrustedResourceCatalog,
};
use crate::execution::{
    ExecutionEventKind, ExecutionTransaction, OperationHistory, RecoveryAction, TransactionError,
    transaction::LiveReservationGuard,
};

/// Revalidates current policy and provider assignment at every admission.
pub trait TrustedAdmissionPolicy {
    /// Structured current-policy failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Authorizes one exact implementation method under current assignments.
    ///
    /// # Errors
    ///
    /// Returns an error when current policy, assignment, principal, artifact,
    /// or provider state no longer authorizes the exact invocation.
    fn authorize(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> Result<(), Self::Error>;

    /// Authorizes current assignments and observations under held reservations.
    ///
    /// # Errors
    ///
    /// Returns an error when current policy no longer accepts the exact
    /// provider assignments, revisions, or precondition observations.
    fn authorize_resources(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        expected_provider: Option<&aos_ability_model::ProviderAssignment>,
        resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error>;
}

/// Reports why fresh operation admission did not complete.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// The checked graph still carries unresolved deployment obligations.
    #[error("checked effect plan is not executable")]
    PlanNotExecutable,
    /// Durable history names another plan or an operation absent from this plan.
    #[error("durable operation does not belong to the checked effect plan")]
    OperationNotInPlan,
    /// Durable state does not currently permit fresh admission.
    #[error("durable operation state does not permit fresh admission")]
    StateDoesNotPermitAdmission,
    /// Durable admission names resources different from the checked operation.
    #[error("durable admitted resources do not match the checked operation")]
    DurableAdmissionMismatch,
    /// Durable recovery state omitted its exact original effect request.
    #[error("durable effect intent is missing its exact request")]
    RecoveryRequestMissing,
    /// The operation's exact checked binding could not be resolved.
    #[error("operation binding is absent from the checked binding plan")]
    BindingMissing,
    /// Version 1 does not execute an advertised compensation contract.
    #[error("operation declares compensation, which this runtime does not implement")]
    CompensationUnsupported,
    /// The checked plan does not authorize the exact invocation semantics.
    #[error("checked plan does not authorize {purpose:?}: {source}")]
    CheckedAuthority {
        /// Names the independently checked invocation.
        purpose: InvocationPurpose,
        /// Retains the shared validator's exact semantic failure.
        #[source]
        source: InvocationAuthorizationError,
    },
    /// The selected trusted adapter did not authenticate the exact entry point.
    #[error("trusted adapter does not authenticate {0:?}")]
    AdapterMismatch(InvocationPurpose),
    /// Current trusted policy rejected an exact entry point.
    #[error("fresh policy rejected {purpose:?}: {source}")]
    FreshAuthorization {
        /// Names the independently checked invocation.
        purpose: InvocationPurpose,
        /// Retains the current-policy failure.
        #[source]
        source: anyhow::Error,
    },
    /// The trusted resource catalog rejected one exact reservation.
    #[error("resource acquisition failed for {resource:?}: {source}")]
    ResourceAcquisition {
        /// Names the logical resource that could not be reserved.
        resource: ResourceId,
        /// Retains the trusted-catalog failure.
        #[source]
        source: anyhow::Error,
    },
    /// Catalog evidence did not describe the reserved logical resource.
    #[error("resource catalog returned mismatched evidence for {0:?}")]
    CatalogEvidenceMismatch(ResourceId),
    /// A checked operation precondition no longer holds under reservation.
    #[error("fresh precondition failed for {0:?}")]
    StalePrecondition(ResourceId),
    /// Current policy rejected held resource assignments or observations.
    #[error("fresh policy rejected resource evidence: {0}")]
    FreshResourceAuthorization(#[source] anyhow::Error),
    /// The adapter rejected checked inputs or freshly acquired handles.
    #[error("adapter request preparation failed: {0}")]
    RequestPreparation(#[source] anyhow::Error),
    /// A checked symbolic input was not durably available for this operation.
    #[error("operation inputs could not be resolved: {0}")]
    InputResolution(#[source] crate::execution::InputResolutionError),
    /// Fresh admission exhausted the finite transaction recovery budget.
    #[error("fresh admission exceeded the transaction recovery deadline")]
    DeadlineExceeded,
    /// The owning transaction rejected or could not persist admission.
    #[error("execution transaction could not record admission: {0}")]
    Transaction(#[source] TransactionError),
}

/// Retains ownership tokens whose cleanup also failed during admission.
#[derive(Debug)]
pub struct AdmissionFailure<H> {
    error: AdmissionError,
    retained_resources: Vec<ResourceHandle<H>>,
    cleanup_errors: Vec<anyhow::Error>,
    live_reservation: Option<LiveReservationGuard>,
}

impl<H> AdmissionFailure<H> {
    /// Returns the primary reason admission failed.
    #[must_use]
    pub const fn error(&self) -> &AdmissionError {
        &self.error
    }

    /// Returns resources still owned because their cleanup failed.
    #[must_use]
    pub fn retained_resources(&self) -> impl Iterator<Item = &ResourceId> {
        self.retained_resources.iter().map(ResourceHandle::resource)
    }

    /// Returns failures reported while releasing incomplete reservations.
    #[must_use]
    pub fn cleanup_errors(&self) -> &[anyhow::Error] {
        &self.cleanup_errors
    }

    /// Retries release of every retained reservation.
    ///
    /// # Errors
    ///
    /// Returns this failure with remaining handles when a release still fails.
    pub fn retry_cleanup<Catalog>(mut self, catalog: &mut Catalog) -> Result<(), Self>
    where
        Catalog: TrustedResourceCatalog<Handle = H>,
    {
        self.cleanup_errors.clear();
        release_incomplete(
            &mut self.retained_resources,
            &mut self.cleanup_errors,
            catalog,
        );
        if self.retained_resources.is_empty() {
            if let Some(live_reservation) = &mut self.live_reservation {
                live_reservation.release_claim();
            }
            Ok(())
        } else {
            Err(self)
        }
    }
}

/// Proves that one checked operation passed fresh authority and ownership checks.
#[derive(Debug)]
pub struct AdmittedOperation<'plan, Request, H> {
    plan: &'plan CheckedEffectPlan,
    operation: &'plan Operation,
    binding: &'plan Binding,
    session: Arc<()>,
    expected_provider: Option<aos_ability_model::ProviderAssignment>,
    transaction: TransactionId,
    operation_id: OperationId,
    attempt: NonZeroU32,
    elapsed_millis: u64,
    clock_observed_at: u64,
    deadline_expired: bool,
    request: PreparedRequest<Request>,
    resources: Vec<ResourceHandle<H>>,
    _live_reservation: LiveReservationGuard,
}

impl<Request, H> AdmittedOperation<'_, Request, H> {
    /// Returns the exact checked plan that authorized this token.
    #[must_use]
    pub const fn plan(&self) -> &CheckedEffectPlan {
        self.plan
    }

    /// Returns the exact checked operation.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        self.operation
    }

    /// Returns the exact checked binding selected for the operation.
    #[must_use]
    pub const fn binding(&self) -> &Binding {
        self.binding
    }

    /// Returns the durable transaction identity.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Returns the stable plan-qualified operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the positive attempt selected by durable replay.
    #[must_use]
    pub const fn attempt(&self) -> NonZeroU32 {
        self.attempt
    }

    /// Returns charged recovery time for this operation across restarts.
    #[must_use]
    pub const fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }

    /// Reports whether admission consumed the last available recovery budget.
    #[must_use]
    pub const fn deadline_expired(&self) -> bool {
        self.deadline_expired
    }

    pub(crate) const fn clock_observed_at(&self) -> u64 {
        self.clock_observed_at
    }

    pub(crate) fn belongs_to_session(&self, session: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.session, session)
    }

    pub(crate) const fn expected_provider(&self) -> Option<&aos_ability_model::ProviderAssignment> {
        self.expected_provider.as_ref()
    }

    /// Returns the exact bounded request persisted before any effect.
    #[must_use]
    pub fn durable_request(&self) -> &aos_ability_model::AbilityValue {
        self.request.durable()
    }

    /// Returns reserved logical resources in canonical identity order.
    #[must_use]
    pub fn resources(&self) -> impl Iterator<Item = &ResourceId> {
        self.resources.iter().map(ResourceHandle::resource)
    }

    pub(crate) const fn prepared_request(&self) -> &PreparedRequest<Request> {
        &self.request
    }

    pub(crate) fn resource_evidence(&self) -> Vec<ResourceAdmissionEvidence> {
        self.resources
            .iter()
            .map(|resource| resource.evidence().clone())
            .collect()
    }

    pub(crate) fn resource_handles_mut(&mut self) -> &mut [ResourceHandle<H>] {
        &mut self.resources
    }

    pub(crate) fn release_live_reservation(&mut self) {
        self._live_reservation.release_claim();
    }
}

impl<'plan> ExecutionTransaction<'plan> {
    /// Performs fresh method authorization, resource acquisition, and journaling.
    ///
    /// # Errors
    ///
    /// Returns a failure for an unexecutable plan, inadmissible state, authority
    /// mismatch, current-policy rejection, resource failure, adapter request
    /// failure, or journal failure. Failed cleanup retains ownership tokens.
    pub fn admit<Adapter, Catalog, Policy, Clock>(
        &mut self,
        operation_key: &ScopedOperationKey,
        adapter: &Adapter,
        catalog: &mut Catalog,
        policy: &mut Policy,
        clock: &Clock,
    ) -> Result<
        AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        AdmissionFailure<Adapter::Handle>,
    >
    where
        Adapter: TrustedAdapter,
        Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
    {
        let plan = self.plan();
        let session = Arc::clone(self.session());
        let transaction = self.transaction().clone();
        let transaction_elapsed = self.elapsed_millis();
        let transaction_limit = self.total_recovery_millis();
        self.check_operation_ready(operation_key)
            .map_err(transaction_failure)?;
        let expected_provider = self
            .provider_assignment_for(operation_key)
            .map_err(transaction_failure)?;
        let recovery_action = self
            .next_action(operation_key)
            .map_err(transaction_failure)?;
        let history = self.history(operation_key).map_err(transaction_failure)?;
        let admission = check_admission(plan, history, recovery_action).map_err(failure)?;
        let live_reservation = self
            .claim_live_reservation(operation_key.clone(), admission.attempt)
            .map_err(transaction_failure)?;
        let timer = AdmissionTimer::new(
            clock,
            admission.elapsed_millis,
            transaction_elapsed,
            admission.operation.deadline.total_recovery_millis.get(),
            transaction_limit,
        );

        check_deadline(&timer).map_err(failure)?;
        if admission.invocation_purpose == InvocationPurpose::Reconcile {
            let method = admission
                .operation
                .recovery
                .reconcile
                .as_ref()
                .ok_or_else(|| failure(AdmissionError::StateDoesNotPermitAdmission))?;
            check_invocation(
                plan,
                admission.operation,
                admission.binding,
                method,
                InvocationPurpose::Reconcile,
                adapter,
                policy,
            )
            .map_err(failure)?;
            check_deadline(&timer).map_err(failure)?;
        } else {
            check_invocation(
                plan,
                admission.operation,
                admission.binding,
                &effect_method(admission.operation),
                InvocationPurpose::Effect,
                adapter,
                policy,
            )
            .map_err(failure)?;
            check_deadline(&timer).map_err(failure)?;
            if let Some(method) = &admission.operation.recovery.reconcile {
                check_invocation(
                    plan,
                    admission.operation,
                    admission.binding,
                    method,
                    InvocationPurpose::Reconcile,
                    adapter,
                    policy,
                )
                .map_err(failure)?;
                check_deadline(&timer).map_err(failure)?;
            }
            if let Some(method) = &admission.operation.recovery.cancel {
                check_invocation(
                    plan,
                    admission.operation,
                    admission.binding,
                    method,
                    InvocationPurpose::Cancel,
                    adapter,
                    policy,
                )
                .map_err(failure)?;
                check_deadline(&timer).map_err(failure)?;
            }
        }

        let mut resources = Vec::with_capacity(admission.operation.accesses.len());
        let mut accesses = admission.operation.accesses.clone();
        accesses.sort_by(|left, right| compare_resource_ids(&left.resource, &right.resource));

        let resource_ids: Vec<_> = accesses
            .iter()
            .map(|access| access.resource.clone())
            .collect();
        if admission.already_durable && history.admitted_resources() != resource_ids {
            return Err(failure(AdmissionError::DurableAdmissionMismatch));
        }

        for access in accesses {
            if let Err(error) = check_deadline(&timer) {
                return Err(cleanup_failure(error, resources, catalog, live_reservation));
            }
            let reservation = match catalog.acquire(
                ReservationContext {
                    transaction: &transaction,
                    operation: &admission.operation_id,
                    attempt: admission.attempt,
                    expected_provider: expected_provider.as_ref(),
                    recovery_remaining_millis: timer.remaining_millis(),
                },
                admission.operation,
                &access,
            ) {
                Ok(reservation) => reservation,
                Err(source) => {
                    let error = AdmissionError::ResourceAcquisition {
                        resource: access.resource,
                        source: anyhow::Error::new(source),
                    };
                    return Err(cleanup_failure(error, resources, catalog, live_reservation));
                }
            };
            let resource = ResourceHandle::new(access.resource.clone(), access, reservation);
            if resource.evidence().resource() != resource.resource() {
                let error = AdmissionError::CatalogEvidenceMismatch(resource.resource().clone());
                resources.push(resource);
                return Err(cleanup_failure(error, resources, catalog, live_reservation));
            }
            resources.push(resource);
            if expected_provider.as_ref().is_some_and(|assignment| {
                resources.last().is_none_or(|resource| {
                    resource.evidence().provider_incarnation() != Some(&assignment.incarnation)
                })
            }) {
                let error = AdmissionError::CatalogEvidenceMismatch(
                    resources
                        .last()
                        .map(|resource| resource.resource().clone())
                        .unwrap_or_else(|| admission.operation.target.resource.clone()),
                );
                return Err(cleanup_failure(error, resources, catalog, live_reservation));
            }
            if let Err(error) = check_deadline(&timer) {
                return Err(cleanup_failure(error, resources, catalog, live_reservation));
            }
        }

        for precondition in &admission.operation.preconditions {
            let evidence = resources
                .iter()
                .find(|resource| resource.resource() == &precondition.resource)
                .map(ResourceHandle::evidence)
                .cloned();
            let Some(evidence) = evidence else {
                return Err(cleanup_failure(
                    AdmissionError::StalePrecondition(precondition.resource.clone()),
                    resources,
                    catalog,
                    live_reservation,
                ));
            };
            let revision_matches = precondition
                .expected_revision
                .is_none_or(|expected| evidence.revision() == Some(expected));
            let incarnation_matches = precondition
                .expected_incarnation
                .as_ref()
                .is_none_or(|expected| evidence.provider_incarnation() == Some(expected));
            if !revision_matches || !incarnation_matches {
                return Err(cleanup_failure(
                    AdmissionError::StalePrecondition(precondition.resource.clone()),
                    resources,
                    catalog,
                    live_reservation,
                ));
            }
        }
        let resource_evidence: Vec<_> = resources
            .iter()
            .map(|resource| resource.evidence().clone())
            .collect();
        if let Err(source) = policy.authorize_resources(
            plan,
            admission.binding,
            admission.operation,
            expected_provider.as_ref(),
            &resource_evidence,
        ) {
            return Err(cleanup_failure(
                AdmissionError::FreshResourceAuthorization(anyhow::Error::new(source)),
                resources,
                catalog,
                live_reservation,
            ));
        }
        if let Err(error) = check_deadline(&timer) {
            return Err(cleanup_failure(error, resources, catalog, live_reservation));
        }
        let durable = match admission.durable_request.clone() {
            Some(durable) => durable,
            None => {
                let inputs = match self.resolve_operation_inputs(operation_key) {
                    Ok(inputs) => inputs,
                    Err(source) => {
                        return Err(cleanup_failure(
                            AdmissionError::InputResolution(source),
                            resources,
                            catalog,
                            live_reservation,
                        ));
                    }
                };
                match adapter.prepare_durable(admission.operation, &inputs, &resources) {
                    Ok(durable) => durable,
                    Err(source) => {
                        return Err(cleanup_failure(
                            AdmissionError::RequestPreparation(anyhow::Error::new(source)),
                            resources,
                            catalog,
                            live_reservation,
                        ));
                    }
                }
            }
        };
        if let Err(error) = check_deadline(&timer) {
            return Err(cleanup_failure(error, resources, catalog, live_reservation));
        }
        let request = match adapter.recover_request(&durable, &resources) {
            Ok(request) => PreparedRequest::new(request, durable),
            Err(source) => {
                return Err(cleanup_failure(
                    AdmissionError::RequestPreparation(anyhow::Error::new(source)),
                    resources,
                    catalog,
                    live_reservation,
                ));
            }
        };
        if let Err(error) = check_deadline(&timer) {
            return Err(cleanup_failure(error, resources, catalog, live_reservation));
        }

        if !admission.already_durable {
            let event = ExecutionEventKind::OperationAdmitted {
                transaction: transaction.clone(),
                operation: admission.operation_id.clone(),
                attempt: admission.attempt,
                resources: resource_ids,
                elapsed_millis: timer.operation_elapsed_millis(),
            };
            if let Err(source) = self.append(event) {
                return Err(cleanup_failure(
                    AdmissionError::Transaction(source),
                    resources,
                    catalog,
                    live_reservation,
                ));
            }
        }

        let deadline_expired = timer.remaining_millis() == 0;
        let elapsed_millis = timer.operation_elapsed_millis();
        let clock_observed_at = clock.now_millis();
        let mut live_reservation = live_reservation;
        if !resources.is_empty() {
            live_reservation.retain_claim_on_drop();
        }
        Ok(AdmittedOperation {
            plan,
            operation: admission.operation,
            binding: admission.binding,
            session,
            expected_provider,
            transaction,
            operation_id: admission.operation_id,
            attempt: admission.attempt,
            elapsed_millis,
            clock_observed_at,
            deadline_expired,
            request,
            resources,
            _live_reservation: live_reservation,
        })
    }
}

fn check_admission<'plan>(
    plan: &'plan CheckedEffectPlan,
    history: &OperationHistory,
    action: RecoveryAction,
) -> Result<CheckedAdmission<'plan>, AdmissionError> {
    if !plan.is_executable() {
        return Err(AdmissionError::PlanNotExecutable);
    }
    let operation_id = history.operation_id();
    if operation_id.plan != plan.id() {
        return Err(AdmissionError::OperationNotInPlan);
    }
    let operation = plan
        .operation(&operation_id.operation)
        .ok_or(AdmissionError::OperationNotInPlan)?;
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or(AdmissionError::BindingMissing)?;
    if operation.recovery.compensate.is_some() {
        return Err(AdmissionError::CompensationUnsupported);
    }

    let (attempt, already_durable, durable_request, invocation_purpose) = match action {
        RecoveryAction::Admit => (NonZeroU32::MIN, false, None, InvocationPurpose::Effect),
        RecoveryAction::Retry { attempt } => (attempt, false, None, InvocationPurpose::Effect),
        RecoveryAction::Execute { attempt } => (attempt, true, None, InvocationPurpose::Effect),
        RecoveryAction::ReconcileBeforeRetry { attempt } => (
            attempt,
            true,
            Some(
                history
                    .durable_request()
                    .cloned()
                    .ok_or(AdmissionError::RecoveryRequestMissing)?,
            ),
            InvocationPurpose::Reconcile,
        ),
        _ => return Err(AdmissionError::StateDoesNotPermitAdmission),
    };

    Ok(CheckedAdmission {
        operation,
        binding,
        operation_id: operation_id.clone(),
        attempt,
        elapsed_millis: history.elapsed_millis(),
        already_durable,
        durable_request,
        invocation_purpose,
    })
}

struct CheckedAdmission<'plan> {
    operation: &'plan Operation,
    binding: &'plan Binding,
    operation_id: OperationId,
    attempt: NonZeroU32,
    elapsed_millis: u64,
    already_durable: bool,
    durable_request: Option<aos_ability_model::AbilityValue>,
    invocation_purpose: InvocationPurpose,
}

pub(crate) fn check_invocation<Adapter, Policy>(
    plan: &CheckedEffectPlan,
    operation: &Operation,
    binding: &Binding,
    method: &MethodReference,
    purpose: InvocationPurpose,
    adapter: &Adapter,
    policy: &mut Policy,
) -> Result<(), AdmissionError>
where
    Adapter: TrustedAdapter,
    Policy: TrustedAdmissionPolicy,
{
    plan.authorize_invocation(operation, method)
        .map_err(|source| AdmissionError::CheckedAuthority { purpose, source })?;
    if !adapter.authenticates(&binding.implementation, method, purpose) {
        return Err(AdmissionError::AdapterMismatch(purpose));
    }
    policy
        .authorize(plan, binding, operation, method, purpose)
        .map_err(|source| AdmissionError::FreshAuthorization {
            purpose,
            source: anyhow::Error::new(source),
        })
}

fn effect_method(operation: &Operation) -> MethodReference {
    MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    }
}

struct AdmissionTimer<'clock, Clock> {
    clock: &'clock Clock,
    started_at: u64,
    prior_operation_elapsed: u64,
    prior_transaction_elapsed: u64,
    operation_limit: u64,
    transaction_limit: u64,
}

impl<'clock, Clock> AdmissionTimer<'clock, Clock>
where
    Clock: MonotonicClock,
{
    fn new(
        clock: &'clock Clock,
        prior_operation_elapsed: u64,
        prior_transaction_elapsed: u64,
        operation_limit: u64,
        transaction_limit: u64,
    ) -> Self {
        Self {
            clock,
            started_at: clock.now_millis(),
            prior_operation_elapsed,
            prior_transaction_elapsed,
            operation_limit,
            transaction_limit,
        }
    }

    fn live_elapsed_millis(&self) -> u64 {
        self.clock.now_millis().saturating_sub(self.started_at)
    }

    fn operation_elapsed_millis(&self) -> u64 {
        self.prior_operation_elapsed
            .saturating_add(self.live_elapsed_millis())
    }

    fn transaction_elapsed_millis(&self) -> u64 {
        self.prior_transaction_elapsed
            .saturating_add(self.live_elapsed_millis())
    }

    fn remaining_millis(&self) -> u64 {
        self.operation_limit
            .saturating_sub(self.operation_elapsed_millis())
            .min(
                self.transaction_limit
                    .saturating_sub(self.transaction_elapsed_millis()),
            )
    }
}

fn check_deadline<Clock>(timer: &AdmissionTimer<'_, Clock>) -> Result<(), AdmissionError>
where
    Clock: MonotonicClock,
{
    if timer.remaining_millis() == 0 {
        Err(AdmissionError::DeadlineExceeded)
    } else {
        Ok(())
    }
}

fn cleanup_failure<H, Catalog>(
    error: AdmissionError,
    mut resources: Vec<ResourceHandle<H>>,
    catalog: &mut Catalog,
    mut live_reservation: LiveReservationGuard,
) -> AdmissionFailure<H>
where
    Catalog: TrustedResourceCatalog<Handle = H>,
{
    let mut cleanup_errors = Vec::new();
    release_incomplete(&mut resources, &mut cleanup_errors, catalog);
    let live_reservation = if resources.is_empty() {
        None
    } else {
        live_reservation.retain_claim_on_drop();
        Some(live_reservation)
    };
    AdmissionFailure {
        error,
        retained_resources: resources,
        cleanup_errors,
        live_reservation,
    }
}

fn release_incomplete<H, Catalog>(
    resources: &mut Vec<ResourceHandle<H>>,
    cleanup_errors: &mut Vec<anyhow::Error>,
    catalog: &mut Catalog,
) where
    Catalog: TrustedResourceCatalog<Handle = H>,
{
    let mut retained = Vec::new();
    while let Some(mut resource) = resources.pop() {
        let id = resource.resource().clone();
        match catalog.release(&id, resource.native_mut()) {
            Ok(()) => {}
            Err(source) => {
                cleanup_errors.push(anyhow::Error::new(source));
                retained.push(resource);
            }
        }
    }
    retained.reverse();
    *resources = retained;
}

fn failure<H>(error: AdmissionError) -> AdmissionFailure<H> {
    AdmissionFailure {
        error,
        retained_resources: Vec::new(),
        cleanup_errors: Vec::new(),
        live_reservation: None,
    }
}

fn transaction_failure<H>(error: TransactionError) -> AdmissionFailure<H> {
    failure(AdmissionError::Transaction(error))
}

#[cfg(test)]
mod tests {
    use std::io;

    use aos_ability_model::{
        AccessMode, EnvironmentId, ExecutionStage, InstanceId, LocalKey, ResourceAccess,
    };

    use super::*;
    use crate::adapter::CatalogReservation;

    #[test]
    fn incomplete_acquisition_releases_in_reverse_and_retains_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut resources = vec![handle("alpha")?, handle("beta")?, handle("gamma")?];
        let mut errors = Vec::new();
        let mut catalog = TestCatalog::failing("beta");

        release_incomplete(&mut resources, &mut errors, &mut catalog);

        assert_eq!(catalog.release_order, ["gamma", "beta", "alpha"]);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            resources
                .iter()
                .map(|resource| resource.resource().key.as_str())
                .collect::<Vec<_>>(),
            ["beta"]
        );
        Ok(())
    }

    #[test]
    fn retry_cleanup_preserves_the_token_until_release_succeeds()
    -> Result<(), Box<dyn std::error::Error>> {
        let failure = AdmissionFailure {
            error: AdmissionError::PlanNotExecutable,
            retained_resources: vec![handle("alpha")?],
            cleanup_errors: Vec::new(),
            live_reservation: None,
        };
        let mut catalog = TestCatalog::failing("alpha");

        let failure = failure
            .retry_cleanup(&mut catalog)
            .expect_err("the failed release must retain its ownership token");
        assert_eq!(failure.retained_resources().count(), 1);

        catalog.fail_resource = None;
        failure.retry_cleanup(&mut catalog).map_err(|failure| {
            io::Error::other(format!("cleanup remained failed: {}", failure.error()))
        })?;
        Ok(())
    }

    fn handle(key: &str) -> Result<ResourceHandle<String>, Box<dyn std::error::Error>> {
        let resource = resource(key)?;
        let observation = aos_ability_model::AbilityValue::new(serde_json::json!({}))?;
        Ok(ResourceHandle::new(
            resource.clone(),
            ResourceAccess {
                resource: resource.clone(),
                mode: AccessMode::ExclusiveWrite,
            },
            CatalogReservation::new(
                key.to_string(),
                ResourceAdmissionEvidence::new(resource, None, None, observation),
            ),
        ))
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

    struct TestCatalog {
        fail_resource: Option<String>,
        release_order: Vec<String>,
    }

    impl TestCatalog {
        fn failing(resource: &str) -> Self {
            Self {
                fail_resource: Some(resource.to_string()),
                release_order: Vec::new(),
            }
        }
    }

    impl TrustedResourceCatalog for TestCatalog {
        type Handle = String;
        type Error = io::Error;

        fn acquire(
            &mut self,
            _context: ReservationContext<'_>,
            _operation: &Operation,
            _access: &ResourceAccess,
        ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
            Err(io::Error::other("acquire is not used by this test"))
        }

        fn release(
            &mut self,
            resource: &ResourceId,
            _handle: &mut Self::Handle,
        ) -> Result<(), Self::Error> {
            self.release_order.push(resource.key.as_str().to_string());
            if self.fail_resource.as_deref() == Some(resource.key.as_str()) {
                Err(io::Error::other("injected release failure"))
            } else {
                Ok(())
            }
        }
    }
}
