//! Data-driven execution of checked package handler routes.
//!
//! The dispatcher resolves each operation through its checked binding and the
//! authenticated package document. It contains no package, interface, method,
//! or executable-path catalog.

use std::fmt;
use std::num::NonZeroUsize;

use anyhow::{Context as _, Result, anyhow, ensure};
use aos_ability_model::document::ProviderState;
use aos_ability_model::{AbilityValue, Binding, MethodReference, Operation, ProviderAssignment};
use aos_ability_plan::{RuntimeResourceHealth, RuntimeResourceState};
use aos_ability_runtime::adapter::{
    CancellationToken, InvocationPurpose, MonotonicClock, SystemMonotonicClock, TrustedAdapter,
    TrustedResourceCatalog,
};
use aos_ability_runtime::execution::{
    AdmittedOperation, AuthorityRejection, ExecutionBoundaryObserver, ExecutionError,
    ExecutionStep, RecoveryAction, RuntimeAuthorityRole, TerminalResult, TrustedAdmissionPolicy,
    TrustedAuthoritySnapshot,
};
use aos_ability_validate::CheckedEffectPlan;

use super::ability_activation::SpecializedAbilityActivation;
use super::ability_policy::{
    CurrentResourceObservation, CurrentResourceState, PublishingNativeAdmissionPolicy,
};
use super::ability_policy_authority::{
    OperatorPolicyAuthorityRecord, OperatorPolicyAuthorityStore,
};
use super::transaction_store::AbilityTransactionSession;
use super::command_handler::{
    CommandHandlerAdapter, CommandHandlerResourceCatalog, preflight_selected_handler,
};
use crate::ability_package::{VerifiedAbilityPackage, VerifiedAbilityPackageSet};

/// Resolves and executes only handlers selected by a checked effect plan.
pub(crate) struct HandlerDispatcher<'a> {
    activation: &'a SpecializedAbilityActivation,
    packages: &'a VerifiedAbilityPackageSet,
}

impl<'a> HandlerDispatcher<'a> {
    /// Authenticates every possible checked operation route without executing it.
    ///
    /// # Errors
    ///
    /// Returns an error when any operation lacks an exact package-owned handler.
    pub(crate) fn preflight(
        activation: &'a SpecializedAbilityActivation,
        packages: &'a VerifiedAbilityPackageSet,
    ) -> Result<()> {
        for operation in activation.plan().operations() {
            let (binding, package, _) = selected_route(activation.plan(), packages, operation)?;
            preflight_selected_handler(package, &binding.interface, &binding.implementation)
                .with_context(|| format!("authenticating handler for {:?}", operation.key))?;
        }
        Ok(())
    }

    /// Constructs a dispatcher after authenticating every possible route.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::preflight`].
    pub(crate) fn new(
        activation: &'a SpecializedAbilityActivation,
        packages: &'a VerifiedAbilityPackageSet,
    ) -> Result<Self> {
        Self::preflight(activation, packages)?;
        Ok(Self {
            activation,
            packages,
        })
    }

    /// Drives the checked transaction through package-owned handlers.
    ///
    /// # Errors
    ///
    /// Returns an error when scheduling, assignment recovery, admission,
    /// handler execution, resource release, or authority validation fails.
    pub(crate) fn run_to_terminal<Observer>(
        &self,
        session: &mut AbilityTransactionSession<'a>,
        operator_authority: &'a OperatorPolicyAuthorityStore,
        current_policy: PublishingNativeAdmissionPolicy,
        cancellation: &CancellationToken,
        observer: &mut Observer,
    ) -> Result<TerminalResult>
    where
        Observer: ExecutionBoundaryObserver,
    {
        let mut policy =
            OperatorAuthorizedPolicy::new(self.activation, operator_authority, current_policy);
        let clock = SystemMonotonicClock::new();

        loop {
            if let Some(terminal) = session.transaction().summary().terminal() {
                self.activation.reauthorize(operator_authority)?;
                ensure!(
                    !self.activation.plan().operations().is_empty(),
                    "empty checked transactions require explicit retained-resource observation"
                );
                session
                    .finalize_terminal_outcome()
                    .map_err(anyhow::Error::new)?;
                return Ok(terminal);
            }
            ensure!(
                !cancellation.is_cancelled(),
                "ability activation was cancelled before another operation could be admitted"
            );
            let ready = session
                .schedule_ready(NonZeroUsize::MIN)
                .map_err(anyhow::Error::new)?;
            let item = ready
                .first()
                .context("ability transaction is nonterminal but has no schedulable operation")?;
            let operation = session
                .transaction()
                .plan()
                .operation(item.operation())
                .context("ability scheduler returned an operation outside its plan")?;

            match item.action() {
                RecoveryAction::SettleFailureBeforeEffect => {
                    let evidence = AbilityValue::new(serde_json::Value::Bool(false))
                        .context("constructing failure-before-effect evidence")?;
                    session
                        .settle_failure_before_effect(item.operation(), evidence)
                        .map_err(anyhow::Error::new)?;
                    continue;
                }
                RecoveryAction::AwaitRetryBackoff {
                    eligible_at_millis, ..
                } => {
                    wait_for_retry_eligibility(&clock, cancellation, *eligible_at_millis)?;
                }
                RecoveryAction::InterventionRequired
                | RecoveryAction::CompensationInterventionRequired => {
                    return Err(anyhow!(
                        "ability operation {:?} requires operator intervention",
                        item.operation()
                    ));
                }
                _ => {}
            }

            let assignment = assignment_for_operation(session, operation)?;
            let (_, package, interface) =
                selected_route(self.activation.plan(), self.packages, operation)?;
            let mut catalog = CommandHandlerResourceCatalog::for_operation(
                self.activation.plan(),
                self.packages,
                operation,
                |owner| assignment_for_operation(session, owner),
            )?;
            let assignments = catalog.assignments();
            let mut resources = Vec::with_capacity(operation.accesses.len());
            for access in &operation.accesses {
                let state = catalog.classify(operation, &access.resource)?;
                resources.push(CurrentResourceObservation {
                    resource: access.resource.clone(),
                    state: current_resource_state(state),
                });
            }
            policy.current_mut().publish_authority(
                self.activation.plan(),
                &assignments,
                resources,
            )?;
            let mut adapter = CommandHandlerAdapter::new(package, assignment, interface.clone())?;
            drive_with_adapter(
                session,
                item.operation(),
                &mut adapter,
                &mut catalog,
                &mut policy,
                &clock,
                cancellation,
                observer,
            )?;
        }
    }
}

fn selected_route<'a>(
    plan: &'a CheckedEffectPlan,
    packages: &'a VerifiedAbilityPackageSet,
    operation: &Operation,
) -> Result<(
    &'a Binding,
    &'a VerifiedAbilityPackage,
    &'a aos_ability_model::InterfaceDocument,
)> {
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .context("operation binding disappeared from checked plan")?;
    let package_digest = binding
        .provider_package
        .context("selected handler binding has no authenticated package")?;
    let package = packages
        .iter()
        .find(|package| package.package_digest() == package_digest)
        .context("selected handler package is absent from authenticated package set")?;
    let interface = plan
        .interfaces()
        .get(&binding.interface)
        .context("selected handler interface disappeared from checked plan")?;
    ensure!(
        operation.interface == binding.interface,
        "operation interface differs from its selected handler binding"
    );
    Ok((binding, package, interface))
}

fn assignment_for_operation(
    session: &AbilityTransactionSession<'_>,
    operation: &Operation,
) -> Result<ProviderAssignment, std::io::Error> {
    if let Some(assignment) = session
        .transaction()
        .provider_assignment_for(&operation.key)
        .map_err(invalid)?
    {
        return Ok(assignment);
    }

    let plan = session.transaction().plan();
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or_else(|| invalid("operation binding disappeared from checked plan"))?;
    let mut candidates = plan
        .binding_plan()
        .environment()
        .providers
        .iter()
        .filter(|provider| {
            provider.provider == binding.provider
                && provider.interface == binding.interface
                && provider.implementation == binding.implementation
                && provider.state == ProviderState::Available
                && provider.incarnation.is_some()
        });
    let provider = candidates
        .next()
        .ok_or_else(|| invalid("checked provider assignment is absent from live inventory"))?;
    if candidates.next().is_some() {
        return Err(invalid(
            "live inventory repeats the checked provider assignment",
        ));
    }
    Ok(ProviderAssignment {
        provider: provider.provider.clone(),
        interface: provider.interface.clone(),
        implementation: provider.implementation.clone(),
        incarnation: provider
            .incarnation
            .clone()
            .ok_or_else(|| invalid("available provider has no incarnation"))?,
    })
}

const fn current_resource_state(state: RuntimeResourceState) -> CurrentResourceState {
    match state {
        RuntimeResourceState::Absent => CurrentResourceState::Absent,
        RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Healthy,
        } => CurrentResourceState::Present { revision },
        RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Stopped,
        } => CurrentResourceState::Stopped { revision },
        RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Divergent,
        } => CurrentResourceState::Divergent { revision },
    }
}

fn drive_with_adapter<'plan, Adapter, Catalog, Policy, Observer>(
    session: &mut AbilityTransactionSession<'plan>,
    operation: &aos_ability_model::ScopedOperationKey,
    adapter: &mut Adapter,
    catalog: &mut Catalog,
    policy: &mut Policy,
    clock: &SystemMonotonicClock,
    cancellation: &CancellationToken,
    observer: &mut Observer,
) -> Result<()>
where
    Adapter: TrustedAdapter,
    Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
    Policy: TrustedAdmissionPolicy,
    Observer: ExecutionBoundaryObserver,
{
    let admission = session
        .admit(operation, adapter, catalog, policy, clock)
        .map_err(|failure| failure.into_parts().1)?;
    let admitted = match admission {
        Ok(admitted) => admitted,
        Err(failure) => {
            let reason = failure.error().to_string();
            let cleanup_failed = session.retry_admission_cleanup(failure, catalog).is_err();
            return Err(anyhow!(
                "handler admission failed: {reason}; cleanup_failed={cleanup_failed}"
            ));
        }
    };

    drive_admitted_to_release(
        session,
        admitted,
        adapter,
        catalog,
        policy,
        clock,
        cancellation,
        observer,
    )
}

fn drive_admitted_to_release<'plan, Adapter, Catalog, Policy, Observer>(
    session: &mut AbilityTransactionSession<'plan>,
    admitted: AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
    adapter: &mut Adapter,
    catalog: &mut Catalog,
    policy: &mut Policy,
    clock: &SystemMonotonicClock,
    cancellation: &CancellationToken,
    observer: &mut Observer,
) -> Result<()>
where
    Adapter: TrustedAdapter,
    Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
    Policy: TrustedAdmissionPolicy,
    Observer: ExecutionBoundaryObserver,
{
    loop {
        let action = session
            .transaction()
            .next_action(&admitted.operation().key)
            .map_err(anyhow::Error::new)?;
        if cancellation.is_cancelled()
            && matches!(
                action,
                RecoveryAction::Execute { .. } | RecoveryAction::ReconcileBeforeRetry { .. }
            )
        {
            if admitted.operation().recovery.cancel.is_none() {
                session
                    .record_unsupported_cancellation(&admitted, clock)
                    .map_err(anyhow::Error::new)?
                    .map_err(anyhow::Error::new)?;
                return Err(anyhow!(
                    "operation {:?} was cancelled without a checked cancellation method",
                    admitted.operation().key
                ));
            }
            let step = session
                .cancel_admitted_with_observer(
                    &admitted,
                    adapter,
                    policy,
                    clock,
                    cancellation,
                    observer,
                )
                .map_err(anyhow::Error::new)?
                .map_err(anyhow::Error::new)?;
            if step == ExecutionStep::Indeterminate {
                return Err(anyhow!(
                    "cancellation of operation {:?} remained indeterminate",
                    admitted.operation().key
                ));
            }
            continue;
        }

        match action {
            RecoveryAction::Execute { .. }
            | RecoveryAction::ReconcileBeforeRetry { .. }
            | RecoveryAction::ExecuteCompensation
            | RecoveryAction::ReconcileCompensation => {
                let result = session
                    .drive_admitted_with_observer(
                        &admitted,
                        adapter,
                        policy,
                        clock,
                        cancellation,
                        observer,
                    )
                    .map_err(anyhow::Error::new)?;
                match result {
                    Ok(_) => {}
                    Err(ExecutionError::CancelledBeforeIntent) if cancellation.is_cancelled() => {
                        continue;
                    }
                    Err(error) => return Err(anyhow::Error::new(error)),
                }
            }
            RecoveryAction::ReleaseResources | RecoveryAction::ReleaseCompensationResources => {
                let release = session
                    .release_admitted::<Adapter, _, _>(admitted, catalog, clock)
                    .map_err(|failure| failure.into_parts().1)?;
                return match release {
                    Ok(()) => Ok(()),
                    Err(failure) => {
                        let reason = failure.error().to_string();
                        match session.retry_release(failure, catalog, clock) {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(_)) => Err(anyhow!(
                                "resource release remained incomplete after retry: {reason}"
                            )),
                            Err(marker) => Err(anyhow::Error::new(marker.into_parts().1)),
                        }
                    }
                };
            }
            RecoveryAction::InterventionRequired
                if admitted.operation().recovery.reconcile.is_none() =>
            {
                session
                    .record_unsupported_reconciliation(&admitted, clock)
                    .map_err(anyhow::Error::new)?
                    .map_err(anyhow::Error::new)?;
                return Err(anyhow!(
                    "operation {:?} requires intervention without a checked reconciliation method",
                    admitted.operation().key
                ));
            }
            RecoveryAction::InterventionRequired
            | RecoveryAction::CompensationInterventionRequired => {
                return Err(anyhow!(
                    "operation {:?} requires operator intervention",
                    admitted.operation().key
                ));
            }
            other => {
                return Err(anyhow!(
                    "admitted operation selected incompatible action {other:?}"
                ));
            }
        }
    }
}

fn wait_for_retry_eligibility(
    clock: &SystemMonotonicClock,
    cancellation: &CancellationToken,
    eligible_at_millis: u64,
) -> Result<()> {
    while clock.restart_stable_millis() < eligible_at_millis {
        ensure!(
            !cancellation.is_cancelled(),
            "ability activation was cancelled"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    Ok(())
}

/// Rechecks operator authority around the current-authority dispatch fence.
struct OperatorAuthorizedPolicy<'a, Policy> {
    activation: &'a SpecializedAbilityActivation,
    operator_authority: &'a OperatorPolicyAuthorityStore,
    current: Policy,
}

impl<'a, Policy> OperatorAuthorizedPolicy<'a, Policy> {
    const fn new(
        activation: &'a SpecializedAbilityActivation,
        operator_authority: &'a OperatorPolicyAuthorityStore,
        current: Policy,
    ) -> Self {
        Self {
            activation,
            operator_authority,
            current,
        }
    }

    fn current_mut(&mut self) -> &mut Policy {
        &mut self.current
    }
}

struct OperatorDispatchFence<Fence> {
    current: Fence,
    _operator_grants: Vec<OperatorPolicyAuthorityRecord>,
}

impl<Fence> TrustedAuthoritySnapshot for OperatorDispatchFence<Fence>
where
    Fence: TrustedAuthoritySnapshot,
{
    type Error = OperatorAuthorizedPolicyError;

    fn authorize_role(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> std::result::Result<(), Self::Error> {
        self.current
            .authorize_role(plan, binding, operation, method, purpose, role)
            .map_err(|error| OperatorAuthorizedPolicyError::Current(anyhow!(error)))
    }

    fn authorize_resources(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        expected_provider: Option<&ProviderAssignment>,
        resources: &[aos_ability_runtime::adapter::ResourceAdmissionEvidence],
    ) -> std::result::Result<(), Self::Error> {
        self.current
            .authorize_resources(plan, binding, operation, expected_provider, resources)
            .map_err(|error| OperatorAuthorizedPolicyError::Current(anyhow!(error)))
    }
}

impl<Policy> TrustedAuthoritySnapshot for OperatorAuthorizedPolicy<'_, Policy>
where
    Policy: TrustedAdmissionPolicy,
{
    type Error = OperatorAuthorizedPolicyError;

    fn authorize_role(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> std::result::Result<(), Self::Error> {
        self.activation
            .reauthorize(self.operator_authority)
            .map_err(OperatorAuthorizedPolicyError::Operator)?;
        self.current
            .authorize_role(plan, binding, operation, method, purpose, role)
            .map_err(|error| OperatorAuthorizedPolicyError::Current(anyhow!(error)))
    }

    fn authorize_resources(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        expected_provider: Option<&ProviderAssignment>,
        resources: &[aos_ability_runtime::adapter::ResourceAdmissionEvidence],
    ) -> std::result::Result<(), Self::Error> {
        self.activation
            .reauthorize(self.operator_authority)
            .map_err(OperatorAuthorizedPolicyError::Operator)?;
        self.current
            .authorize_resources(plan, binding, operation, expected_provider, resources)
            .map_err(|error| OperatorAuthorizedPolicyError::Current(anyhow!(error)))
    }
}

impl<Policy> TrustedAdmissionPolicy for OperatorAuthorizedPolicy<'_, Policy>
where
    Policy: TrustedAdmissionPolicy,
{
    type DispatchFence = OperatorDispatchFence<Policy::DispatchFence>;

    fn acquire_dispatch_fence(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> std::result::Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        let operator_grants = self
            .activation
            .acquire_authority_fence(self.operator_authority)
            .map_err(|error| {
                AuthorityRejection::new(
                    RuntimeAuthorityRole::CallerBindingGrant,
                    OperatorAuthorizedPolicyError::Operator(error),
                )
            })?;
        let current = self
            .current
            .acquire_dispatch_fence(plan, binding, operation, method, purpose)
            .map_err(|rejection| {
                AuthorityRejection::new(
                    rejection.role(),
                    OperatorAuthorizedPolicyError::Current(anyhow!(rejection)),
                )
            })?;
        Ok(OperatorDispatchFence {
            current,
            _operator_grants: operator_grants,
        })
    }
}

#[derive(Debug)]
enum OperatorAuthorizedPolicyError {
    Operator(anyhow::Error),
    Current(anyhow::Error),
}

impl fmt::Display for OperatorAuthorizedPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operator(error) => {
                write!(formatter, "operator authority rejected dispatch: {error}")
            }
            Self::Current(error) => {
                write!(formatter, "current authority rejected dispatch: {error}")
            }
        }
    }
}

impl std::error::Error for OperatorAuthorizedPolicyError {}

fn invalid(error: impl fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}
