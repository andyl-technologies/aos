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
    ResourceAdmissionEvidence, ResourceHandle, RuntimeControl, TrustedAdapter,
    TrustedResourceCatalog,
};
use crate::execution::invocation;
use crate::execution::{
    AuthorityCheckBoundary, Boundary, CompensationInterventionReason, CompensationState,
    ExecutionBoundaryControl, ExecutionBoundaryObservation, ExecutionBoundaryObserver,
    ExecutionEventKind, ExecutionTransaction, OperationHistory, RecoveryAction,
    RuntimeAuthorityRole, TransactionError, TrustedAdmissionPolicy, TrustedAuthoritySnapshot,
    transaction::LiveReservationGuard,
};

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
    /// A trusted restart-stable clock moved behind its persisted observation.
    #[error("trusted retry clock moved backward")]
    RetryClockMovedBackward,
    /// A retry remains ineligible under its persisted delay.
    #[error("retry backoff has {remaining_millis} milliseconds remaining")]
    RetryBackoffPending {
        /// Reports the minimum remaining delay.
        remaining_millis: u64,
    },
    /// A durable retry timestamp or elapsed budget was not representable.
    #[error("retry backoff timestamp or elapsed budget overflowed")]
    RetryBackoffOverflow,
    /// A qualification observer halted at one exact admission boundary.
    #[error("admission halted at {0:?}")]
    BoundaryHalt(Boundary),
    /// A qualification observer failed closed at an admission boundary.
    #[error("admission boundary observation failed: {0}")]
    BoundaryObservation(#[source] anyhow::Error),
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
    #[error("fresh policy rejected {role:?} for {purpose:?} at {boundary:?}: {source}")]
    FreshAuthorization {
        /// Names the independently checked invocation.
        purpose: InvocationPurpose,
        /// Names the independently revocable authority that was rejected.
        role: RuntimeAuthorityRole,
        /// Names the exact runtime boundary where rejection was observed.
        boundary: AuthorityCheckBoundary,
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
    state: Box<AdmissionFailureState<H>>,
}

#[derive(Debug)]
struct AdmissionFailureState<H> {
    error: AdmissionError,
    retained_resources: Vec<ResourceHandle<H>>,
    cleanup_errors: Vec<anyhow::Error>,
    live_reservation: Option<LiveReservationGuard>,
}

impl<H> AdmissionFailure<H> {
    /// Returns the primary reason admission failed.
    #[must_use]
    pub const fn error(&self) -> &AdmissionError {
        &self.state.error
    }

    /// Returns resources still owned because their cleanup failed.
    pub fn retained_resources(&self) -> impl Iterator<Item = &ResourceId> {
        self.state
            .retained_resources
            .iter()
            .map(ResourceHandle::resource)
    }

    /// Returns failures reported while releasing incomplete reservations.
    #[must_use]
    pub fn cleanup_errors(&self) -> &[anyhow::Error] {
        &self.state.cleanup_errors
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
        self.state.cleanup_errors.clear();
        release_incomplete(
            &mut self.state.retained_resources,
            &mut self.state.cleanup_errors,
            catalog,
        );
        if self.state.retained_resources.is_empty() {
            if let Some(live_reservation) = &mut self.state.live_reservation {
                live_reservation.release_claim();
            }
            Ok(())
        } else {
            Err(self)
        }
    }
}

/// Returns either a freshly admitted operation or a failure retaining cleanup ownership.
pub type AdmissionResult<'plan, Request, Handle> =
    Result<AdmittedOperation<'plan, Request, Handle>, AdmissionFailure<Handle>>;

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
    invocation_purpose: InvocationPurpose,
    operation_sequence: u64,
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

    /// Returns the exact effect or recovery purpose admitted by this token.
    #[must_use]
    pub const fn invocation_purpose(&self) -> InvocationPurpose {
        self.invocation_purpose
    }

    pub(crate) const fn operation_sequence(&self) -> u64 {
        self.operation_sequence
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
    /// A settled operation whose durable ownership was not released before a
    /// process loss follows a narrower path: it reacquires matching catalog
    /// handles solely for [`ExecutionTransaction::release_admitted`]. That path
    /// does not reauthorize or redispatch the completed effect, recheck its old
    /// preconditions, or enforce its expired execution deadline.
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
    ) -> AdmissionResult<'plan, Adapter::Request, Adapter::Handle>
    where
        Adapter: TrustedAdapter,
        Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
    {
        let mut observer = ContinueAdmissionObserver;
        self.admit_with_observer(
            operation_key,
            adapter,
            catalog,
            policy,
            clock,
            &mut observer,
        )
    }

    /// Performs fresh admission while exposing deterministic qualification boundaries.
    ///
    /// The observer runs before resource acquisition and again after all
    /// reservations are held. It receives only stable execution identity and
    /// timing state, and cannot manufacture authority or resource evidence.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::admit`], plus a fail-closed observer
    /// halt or observer error at an exact qualification boundary.
    pub fn admit_with_observer<Adapter, Catalog, Policy, Clock, Observer>(
        &mut self,
        operation_key: &ScopedOperationKey,
        adapter: &Adapter,
        catalog: &mut Catalog,
        policy: &mut Policy,
        clock: &Clock,
        observer: &mut Observer,
    ) -> AdmissionResult<'plan, Adapter::Request, Adapter::Handle>
    where
        Adapter: TrustedAdapter,
        Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
        Observer: ExecutionBoundaryObserver,
    {
        let plan = self.plan();
        let session = Arc::clone(self.session());
        let transaction = self.transaction().clone();
        let transaction_limit = self.total_recovery_millis();
        self.check_operation_ready(operation_key)
            .map_err(transaction_failure)?;
        let expected_provider = self
            .provider_assignment_for(operation_key)
            .map_err(transaction_failure)?;
        let mut recovery_action = self
            .next_action(operation_key)
            .map_err(transaction_failure)?;
        if let RecoveryAction::ScheduleRetryBackoff {
            attempt,
            backoff_millis,
        } = recovery_action
        {
            let observed_at_millis = clock.restart_stable_millis();
            let eligible_at_millis = observed_at_millis
                .checked_add(backoff_millis)
                .ok_or_else(|| failure(AdmissionError::RetryBackoffOverflow))?;
            let history = self.history(operation_key).map_err(transaction_failure)?;
            self.append(ExecutionEventKind::RetryBackoffScheduled {
                transaction: transaction.clone(),
                operation: history.operation_id().clone(),
                attempt,
                observed_at_millis,
                eligible_at_millis,
                elapsed_millis: history.elapsed_millis(),
            })
            .map_err(transaction_failure)?;
            recovery_action = self
                .next_action(operation_key)
                .map_err(transaction_failure)?;
        }
        if let RecoveryAction::AwaitRetryBackoff {
            attempt,
            observed_at_millis,
            eligible_at_millis,
        } = recovery_action
        {
            let now = clock.restart_stable_millis();
            if now < observed_at_millis {
                return Err(failure(AdmissionError::RetryClockMovedBackward));
            }
            if now < eligible_at_millis {
                return Err(failure(AdmissionError::RetryBackoffPending {
                    remaining_millis: eligible_at_millis - now,
                }));
            }
            let history = self.history(operation_key).map_err(transaction_failure)?;
            let elapsed_millis = history
                .elapsed_millis()
                .checked_add(now - observed_at_millis)
                .ok_or_else(|| failure(AdmissionError::RetryBackoffOverflow))?;
            self.append(ExecutionEventKind::RetryBackoffElapsed {
                transaction: transaction.clone(),
                operation: history.operation_id().clone(),
                attempt,
                observed_at_millis: now,
                elapsed_millis,
            })
            .map_err(transaction_failure)?;
            recovery_action = self
                .next_action(operation_key)
                .map_err(transaction_failure)?;
            if matches!(recovery_action, RecoveryAction::SettleFailureBeforeEffect) {
                return Err(failure(AdmissionError::DeadlineExceeded));
            }
        }
        let history = self
            .history(operation_key)
            .map_err(transaction_failure)?
            .clone();
        let admission = check_admission(plan, &history, recovery_action).map_err(failure)?;
        let transaction_elapsed = self.elapsed_millis();
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

        observe_admission_boundary(
            observer,
            &transaction,
            &admission.operation_id,
            admission.attempt,
            admission.invocation_purpose,
            Boundary::BeforeResourceAcquisition,
            &timer,
        )
        .map_err(failure)?;

        check_admission_deadline(
            self,
            operation_key,
            admission.invocation_purpose,
            &timer,
            admission.release_only,
        )
        .map_err(failure)?;
        if !admission.release_only {
            let method = invocation::method(admission.operation, admission.invocation_purpose)
                .ok_or_else(|| failure(AdmissionError::StateDoesNotPermitAdmission))?;
            if let Err(error) = check_invocation(
                plan,
                admission.operation,
                admission.binding,
                &method,
                admission.invocation_purpose,
                adapter,
                policy,
                AuthorityCheckBoundary::BeforeResourceAcquisition,
            ) {
                if let Err(source) = record_authority_rejection(
                    self,
                    &transaction,
                    &admission.operation_id,
                    admission.attempt,
                    &error,
                    timer.operation_elapsed_millis(),
                ) {
                    return Err(failure(AdmissionError::Transaction(source)));
                }
                return Err(failure(error));
            }

            // Recovery after a crash may reacquire process-scoped catalog
            // handles solely to release durable ownership. That path must not
            // reauthorize or redispatch the already settled effect.
            if matches!(
                admission.invocation_purpose,
                InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation
            ) && !adapter.supports_compensation()
            {
                return Err(failure(AdmissionError::AdapterMismatch(
                    admission.invocation_purpose,
                )));
            }
            if matches!(
                admission.invocation_purpose,
                InvocationPurpose::Reconcile | InvocationPurpose::ReconcileCompensation
            ) {
                check_deadline_or_record_compensation(
                    self,
                    operation_key,
                    admission.invocation_purpose,
                    &timer,
                )
                .map_err(failure)?;
            } else if admission.invocation_purpose == InvocationPurpose::Compensate {
                check_deadline_or_record_compensation(
                    self,
                    operation_key,
                    admission.invocation_purpose,
                    &timer,
                )
                .map_err(failure)?;
                if let Some(reconcile) = &admission.operation.recovery.reconcile {
                    check_invocation(
                        plan,
                        admission.operation,
                        admission.binding,
                        reconcile,
                        InvocationPurpose::ReconcileCompensation,
                        adapter,
                        policy,
                        AuthorityCheckBoundary::BeforeResourceAcquisition,
                    )
                    .map_err(failure)?;
                    check_deadline_or_record_compensation(
                        self,
                        operation_key,
                        admission.invocation_purpose,
                        &timer,
                    )
                    .map_err(failure)?;
                }
            } else {
                if admission.operation.recovery.compensate.is_some()
                    && !adapter.supports_compensation()
                {
                    return Err(failure(AdmissionError::AdapterMismatch(
                        InvocationPurpose::Compensate,
                    )));
                }
                check_deadline_or_record_compensation(
                    self,
                    operation_key,
                    admission.invocation_purpose,
                    &timer,
                )
                .map_err(failure)?;
                if let Some(method) = &admission.operation.recovery.reconcile {
                    check_invocation(
                        plan,
                        admission.operation,
                        admission.binding,
                        method,
                        InvocationPurpose::Reconcile,
                        adapter,
                        policy,
                        AuthorityCheckBoundary::BeforeResourceAcquisition,
                    )
                    .map_err(failure)?;
                    check_deadline_or_record_compensation(
                        self,
                        operation_key,
                        admission.invocation_purpose,
                        &timer,
                    )
                    .map_err(failure)?;
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
                        AuthorityCheckBoundary::BeforeResourceAcquisition,
                    )
                    .map_err(failure)?;
                    check_deadline_or_record_compensation(
                        self,
                        operation_key,
                        admission.invocation_purpose,
                        &timer,
                    )
                    .map_err(failure)?;
                }
                if let Some(method) = &admission.operation.recovery.compensate {
                    check_invocation(
                        plan,
                        admission.operation,
                        admission.binding,
                        method,
                        InvocationPurpose::Compensate,
                        adapter,
                        policy,
                        AuthorityCheckBoundary::BeforeResourceAcquisition,
                    )
                    .map_err(failure)?;
                    check_deadline_or_record_compensation(
                        self,
                        operation_key,
                        admission.invocation_purpose,
                        &timer,
                    )
                    .map_err(failure)?;
                    if let Some(reconcile) = &admission.operation.recovery.reconcile {
                        check_invocation(
                            plan,
                            admission.operation,
                            admission.binding,
                            reconcile,
                            InvocationPurpose::ReconcileCompensation,
                            adapter,
                            policy,
                            AuthorityCheckBoundary::BeforeResourceAcquisition,
                        )
                        .map_err(failure)?;
                        check_deadline_or_record_compensation(
                            self,
                            operation_key,
                            admission.invocation_purpose,
                            &timer,
                        )
                        .map_err(failure)?;
                    }
                }
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
            let expected_resource_provider = (access.resource
                == admission.operation.target.resource)
                .then_some(expected_provider.as_ref())
                .flatten();
            if let Err(error) = check_admission_deadline(
                self,
                operation_key,
                admission.invocation_purpose,
                &timer,
                admission.release_only,
            ) {
                return Err(cleanup_failure(error, resources, catalog, live_reservation));
            }
            let reservation = match catalog.acquire(
                ReservationContext {
                    transaction: &transaction,
                    operation: &admission.operation_id,
                    attempt: admission.attempt,
                    expected_provider: expected_resource_provider,
                    recovery_remaining_millis: if admission.release_only {
                        admission.operation.deadline.attempt_timeout_millis.get()
                    } else {
                        timer.remaining_millis()
                    },
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
            if expected_resource_provider.is_some_and(|assignment| {
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
            if let Err(error) = check_admission_deadline(
                self,
                operation_key,
                admission.invocation_purpose,
                &timer,
                admission.release_only,
            ) {
                return Err(cleanup_failure(error, resources, catalog, live_reservation));
            }
        }

        if let Err(error) = observe_admission_boundary(
            observer,
            &transaction,
            &admission.operation_id,
            admission.attempt,
            admission.invocation_purpose,
            Boundary::ResourcesAcquired,
            &timer,
        ) {
            return Err(cleanup_failure(error, resources, catalog, live_reservation));
        }
        if !admission.release_only {
            let Some(method) =
                invocation::method(admission.operation, admission.invocation_purpose)
            else {
                return Err(cleanup_failure(
                    AdmissionError::StateDoesNotPermitAdmission,
                    resources,
                    catalog,
                    live_reservation,
                ));
            };
            if let Err(error) = check_invocation(
                plan,
                admission.operation,
                admission.binding,
                &method,
                admission.invocation_purpose,
                adapter,
                policy,
                AuthorityCheckBoundary::AfterResourceAcquisition,
            ) {
                if let Err(source) = record_authority_rejection(
                    self,
                    &transaction,
                    &admission.operation_id,
                    admission.attempt,
                    &error,
                    timer.operation_elapsed_millis(),
                ) {
                    return Err(cleanup_failure(
                        AdmissionError::Transaction(source),
                        resources,
                        catalog,
                        live_reservation,
                    ));
                }
                return Err(cleanup_failure(error, resources, catalog, live_reservation));
            }
        }

        for precondition in admission
            .operation
            .preconditions
            .iter()
            .filter(|_| !admission.release_only)
        {
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
        if !admission.release_only {
            let resource_evidence: Vec<_> = resources
                .iter()
                .map(|resource| resource.evidence().clone())
                .collect();
            if let Err(error) = check_resources(
                policy,
                plan,
                admission.binding,
                admission.operation,
                expected_provider.as_ref(),
                &resource_evidence,
                admission.invocation_purpose,
                AuthorityCheckBoundary::AfterResourceAcquisition,
            ) {
                if let Err(source) = record_authority_rejection(
                    self,
                    &transaction,
                    &admission.operation_id,
                    admission.attempt,
                    &error,
                    timer.operation_elapsed_millis(),
                ) {
                    return Err(cleanup_failure(
                        AdmissionError::Transaction(source),
                        resources,
                        catalog,
                        live_reservation,
                    ));
                }
                return Err(cleanup_failure(error, resources, catalog, live_reservation));
            }
        }
        if let Err(error) = check_admission_deadline(
            self,
            operation_key,
            admission.invocation_purpose,
            &timer,
            admission.release_only,
        ) {
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
                let prepared = adapter
                    .prepare_durable(admission.operation, &inputs, &resources)
                    .map_err(anyhow::Error::new);
                match prepared {
                    Ok(durable) => durable,
                    Err(source) => {
                        return Err(cleanup_failure(
                            AdmissionError::RequestPreparation(source),
                            resources,
                            catalog,
                            live_reservation,
                        ));
                    }
                }
            }
        };
        if let Err(error) = check_admission_deadline(
            self,
            operation_key,
            admission.invocation_purpose,
            &timer,
            admission.release_only,
        ) {
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
        if let Err(error) = check_admission_deadline(
            self,
            operation_key,
            admission.invocation_purpose,
            &timer,
            admission.release_only,
        ) {
            return Err(cleanup_failure(error, resources, catalog, live_reservation));
        }

        if !admission.already_durable {
            let event = if admission.invocation_purpose == InvocationPurpose::Compensate {
                ExecutionEventKind::CompensationAdmitted {
                    transaction: transaction.clone(),
                    operation: admission.operation_id.clone(),
                    resources: resource_ids,
                    elapsed_millis: timer.operation_elapsed_millis(),
                }
            } else {
                ExecutionEventKind::OperationAdmitted {
                    transaction: transaction.clone(),
                    operation: admission.operation_id.clone(),
                    attempt: admission.attempt,
                    resources: resource_ids,
                    elapsed_millis: timer.operation_elapsed_millis(),
                }
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
        let operation_sequence = match self.history(operation_key) {
            Ok(history) => history.last_sequence(),
            Err(source) => {
                return Err(cleanup_failure(
                    AdmissionError::Transaction(source),
                    resources,
                    catalog,
                    live_reservation,
                ));
            }
        };
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
            invocation_purpose: admission.invocation_purpose,
            operation_sequence,
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
    let release_only = matches!(
        action,
        RecoveryAction::ReleaseResources | RecoveryAction::ReleaseCompensationResources
    );
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
        RecoveryAction::AdmitCompensation => (
            NonZeroU32::MIN,
            false,
            Some(
                history
                    .durable_request()
                    .cloned()
                    .ok_or(AdmissionError::RecoveryRequestMissing)?,
            ),
            InvocationPurpose::Compensate,
        ),
        RecoveryAction::ExecuteCompensation => (
            NonZeroU32::MIN,
            true,
            Some(
                history
                    .durable_request()
                    .cloned()
                    .ok_or(AdmissionError::RecoveryRequestMissing)?,
            ),
            InvocationPurpose::Compensate,
        ),
        RecoveryAction::ReconcileCompensation => (
            NonZeroU32::MIN,
            true,
            Some(
                history
                    .compensation_request()
                    .cloned()
                    .ok_or(AdmissionError::RecoveryRequestMissing)?,
            ),
            InvocationPurpose::ReconcileCompensation,
        ),
        RecoveryAction::ReleaseResources => (
            history
                .current_attempt()
                .ok_or(AdmissionError::StateDoesNotPermitAdmission)?,
            true,
            Some(
                history
                    .durable_request()
                    .cloned()
                    .ok_or(AdmissionError::RecoveryRequestMissing)?,
            ),
            InvocationPurpose::Effect,
        ),
        RecoveryAction::ReleaseCompensationResources => (
            NonZeroU32::MIN,
            true,
            Some(
                history
                    .compensation_request()
                    .cloned()
                    .ok_or(AdmissionError::RecoveryRequestMissing)?,
            ),
            InvocationPurpose::Compensate,
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
        release_only,
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
    release_only: bool,
}

pub(crate) fn check_invocation<Adapter, Authority>(
    plan: &CheckedEffectPlan,
    operation: &Operation,
    binding: &Binding,
    method: &MethodReference,
    purpose: InvocationPurpose,
    adapter: &Adapter,
    authority: &mut Authority,
    boundary: AuthorityCheckBoundary,
) -> Result<(), AdmissionError>
where
    Adapter: TrustedAdapter,
    Authority: TrustedAuthoritySnapshot,
{
    plan.authorize_invocation(operation, method)
        .map_err(|source| AdmissionError::CheckedAuthority { purpose, source })?;
    if !adapter.authenticates(&binding.implementation, method, purpose) {
        return Err(AdmissionError::AdapterMismatch(purpose));
    }

    for role in [
        RuntimeAuthorityRole::CallerBindingGrant,
        RuntimeAuthorityRole::ProviderMethodImplementation,
        RuntimeAuthorityRole::EnforcementPlatformGuarantee,
        RuntimeAuthorityRole::AssignmentIncarnation,
    ] {
        authority
            .authorize_role(plan, binding, operation, method, purpose, role)
            .map_err(|source| AdmissionError::FreshAuthorization {
                purpose,
                role,
                boundary,
                source: anyhow::Error::new(source),
            })?;
    }
    Ok(())
}

pub(crate) fn check_resources<Authority>(
    authority: &mut Authority,
    plan: &CheckedEffectPlan,
    binding: &Binding,
    operation: &Operation,
    expected_provider: Option<&aos_ability_model::ProviderAssignment>,
    resources: &[ResourceAdmissionEvidence],
    purpose: InvocationPurpose,
    boundary: AuthorityCheckBoundary,
) -> Result<(), AdmissionError>
where
    Authority: TrustedAuthoritySnapshot,
{
    authority
        .authorize_resources(plan, binding, operation, expected_provider, resources)
        .map_err(|source| AdmissionError::FreshAuthorization {
            purpose,
            role: RuntimeAuthorityRole::AssignmentIncarnation,
            boundary,
            source: anyhow::Error::new(source),
        })
}

struct AdmissionTimer<'clock, Clock> {
    clock: &'clock Clock,
    started_at: u64,
    prior_operation_elapsed: u64,
    prior_transaction_elapsed: u64,
    operation_limit: u64,
    transaction_limit: u64,
}

impl<Clock> RuntimeControl for AdmissionTimer<'_, Clock>
where
    Clock: MonotonicClock,
{
    fn is_cancelled(&self) -> bool {
        false
    }

    fn elapsed_millis(&self) -> u64 {
        self.operation_elapsed_millis()
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.remaining_millis()
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.remaining_millis()
    }
}

struct ContinueAdmissionObserver;

impl ExecutionBoundaryObserver for ContinueAdmissionObserver {
    fn observe(
        &mut self,
        _observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        Ok(ExecutionBoundaryControl::Continue)
    }
}

fn observe_admission_boundary(
    observer: &mut impl ExecutionBoundaryObserver,
    transaction: &TransactionId,
    operation: &OperationId,
    attempt: NonZeroU32,
    purpose: InvocationPurpose,
    boundary: Boundary,
    control: &dyn RuntimeControl,
) -> Result<(), AdmissionError> {
    let observation =
        ExecutionBoundaryObservation::new(transaction, operation, attempt, purpose, boundary);
    match observer
        .observe(observation, control)
        .map_err(AdmissionError::BoundaryObservation)?
    {
        ExecutionBoundaryControl::Continue => Ok(()),
        ExecutionBoundaryControl::Halt => Err(AdmissionError::BoundaryHalt(boundary)),
    }
}

fn record_authority_rejection(
    transaction: &mut ExecutionTransaction<'_>,
    transaction_id: &TransactionId,
    operation: &OperationId,
    attempt: NonZeroU32,
    error: &AdmissionError,
    elapsed_millis: u64,
) -> Result<(), TransactionError> {
    let AdmissionError::FreshAuthorization {
        purpose,
        role,
        boundary,
        ..
    } = error
    else {
        return Ok(());
    };
    transaction.append(ExecutionEventKind::AuthorityRejected {
        transaction: transaction_id.clone(),
        operation: operation.clone(),
        attempt,
        purpose: *purpose,
        role: *role,
        boundary: *boundary,
        elapsed_millis,
    })
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

fn check_deadline_or_record_compensation<Clock>(
    transaction: &mut ExecutionTransaction<'_>,
    operation: &ScopedOperationKey,
    purpose: InvocationPurpose,
    timer: &AdmissionTimer<'_, Clock>,
) -> Result<(), AdmissionError>
where
    Clock: MonotonicClock,
{
    let Err(deadline_error) = check_deadline(timer) else {
        return Ok(());
    };

    if !matches!(
        purpose,
        InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation
    ) {
        return Err(deadline_error);
    }
    let history = transaction
        .history(operation)
        .map_err(AdmissionError::Transaction)?;
    let reason = match history.compensation_state() {
        Some(CompensationState::Requested { .. } | CompensationState::Admitted) => {
            CompensationInterventionReason::DeadlineBeforeIntent
        }
        Some(
            CompensationState::IntentDurable
            | CompensationState::Indeterminate { .. }
            | CompensationState::ReconciliationIntentDurable,
        ) => CompensationInterventionReason::DeadlineAfterIntent,
        _ => return Err(deadline_error),
    };
    transaction
        .record_compensation_intervention(operation, reason, timer.operation_elapsed_millis())
        .map_err(AdmissionError::Transaction)?;
    Err(deadline_error)
}

fn check_admission_deadline<Clock>(
    transaction: &mut ExecutionTransaction<'_>,
    operation: &ScopedOperationKey,
    purpose: InvocationPurpose,
    timer: &AdmissionTimer<'_, Clock>,
    release_only: bool,
) -> Result<(), AdmissionError>
where
    Clock: MonotonicClock,
{
    if release_only {
        Ok(())
    } else {
        check_deadline_or_record_compensation(transaction, operation, purpose, timer)
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
        state: Box::new(AdmissionFailureState {
            error,
            retained_resources: resources,
            cleanup_errors,
            live_reservation,
        }),
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
        state: Box::new(AdmissionFailureState {
            error,
            retained_resources: Vec::new(),
            cleanup_errors: Vec::new(),
            live_reservation: None,
        }),
    }
}

fn transaction_failure<H>(error: TransactionError) -> AdmissionFailure<H> {
    failure(AdmissionError::Transaction(error))
}

#[cfg(test)]
#[path = "admission/tests.rs"]
mod tests;
