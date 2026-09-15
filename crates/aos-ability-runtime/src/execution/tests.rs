//! Checked-plan integration tests for the public runtime controller boundary.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::rc::Rc;

use aos_ability_model::{
    AbilityValue, AccessMode, ArtifactReference, BindingId, BranchMembership, DecisionAlternative,
    DecisionNode, DecisionPredicate, DecisionSelector, DependencyEdge, DependencyKind,
    IncarnationId, IndeterminateSemantics, LocalKey, MergeNode, MergedOutput, MethodReference,
    Operation, OperationId, OperationResultReference, PlanNodeKey, ProviderAssignment,
    ResourceAccess, ResourceId, ResourcePermission, ResultProducerKey, RetryPolicy, RevisionId,
    ScopedOperationKey, TransactionId, ValueExpression, compare_edges, compare_operation_keys,
};
use aos_ability_plan::test_support::verified_planning_effect_plan;
use aos_ability_validate::test_support::{
    checked_effect_plan, checked_lifecycle_effect_plan, checked_planned_provider_chain,
    plan_fixture,
};
use aos_contract::Sha256Digest;
use tempfile::TempDir;

use crate::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CancellationToken,
    CatalogReservation, EffectDisposition, InvocationPurpose, MonotonicClock, PlanRetentionReceipt,
    ReconcileDisposition, ReservationContext, ResourceAdmissionEvidence, ResourceHandle,
    RootRetentionReceipt, RuntimeControl, TrustedAdapter, TrustedPlanStore, TrustedResourceCatalog,
    TrustedRootStore,
};
use crate::execution::{
    AdmissionError, AuthorityCheckBoundary, AuthorityRejection, CheckedExecutionJournalSnapshot,
    ExecutionBoundaryControl, ExecutionBoundaryObservation, ExecutionBoundaryObserver,
    ExecutionError, ExecutionEvent, ExecutionEventKind, ExecutionStep, ExecutionTransaction,
    OperationInterventionReason, OperationState, OperationStatus, RecoveryAction,
    ResourceReleaseError, RuntimeAuthorityRole, TerminalResult, TrustedAdmissionPolicy,
    TrustedAuthoritySnapshot,
};
use crate::journal::{FileJournal, JournalLimits};

mod compensation;
mod recovery;
mod retry;
mod scheduling;
mod transaction;
fn complete_with_expected_provider(
    transaction: &mut ExecutionTransaction<'_>,
    operation: &ScopedOperationKey,
    expected_provider: &ProviderAssignment,
    output: AbilityValue,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = TestCatalog::default();
    complete_with_catalog(transaction, operation, output, &mut catalog)?;
    assert_eq!(
        catalog.expected_providers,
        [Some(expected_provider.clone())]
    );
    Ok(())
}

fn complete_with_output(
    transaction: &mut ExecutionTransaction<'_>,
    operation: &ScopedOperationKey,
    output: AbilityValue,
) -> Result<(), Box<dyn std::error::Error>> {
    complete_with_catalog(transaction, operation, output, &mut TestCatalog::default())
}

fn complete_with_catalog(
    transaction: &mut ExecutionTransaction<'_>,
    operation: &ScopedOperationKey,
    output: AbilityValue,
    catalog: &mut TestCatalog,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::with_output(output);
    let clock = TestClock;
    let admitted = transaction
        .admit(operation, &adapter, catalog, &mut policy, &clock)
        .map_err(admission_error)?;
    transaction.drive_admitted(
        &admitted,
        &mut adapter,
        &mut policy,
        &clock,
        &CancellationToken::default(),
    )?;
    transaction
        .release_admitted::<TestAdapter, _, _>(admitted, catalog, &clock)
        .map_err(release_error)?;
    Ok(())
}

fn provider_assignment(
    plan: &aos_ability_validate::CheckedEffectPlan,
    binding: &str,
    incarnation: &str,
) -> Result<ProviderAssignment, Box<dyn std::error::Error>> {
    let binding = plan
        .binding_plan()
        .binding(&BindingId(key(binding)))
        .ok_or("planned binding missing")?;
    Ok(ProviderAssignment {
        provider: binding.provider.clone(),
        interface: binding.interface.clone(),
        implementation: binding.implementation.clone(),
        incarnation: IncarnationId::new(incarnation)?,
    })
}

fn assignment_value(
    assignment: &ProviderAssignment,
) -> Result<AbilityValue, Box<dyn std::error::Error>> {
    Ok(AbilityValue::new(serde_json::to_value(assignment)?)?)
}

fn complete(
    transaction: &mut ExecutionTransaction<'_>,
    operation: &ScopedOperationKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let clock = TestClock;
    let admitted = transaction
        .admit(operation, &adapter, &mut catalog, &mut policy, &clock)
        .map_err(admission_error)?;
    transaction.drive_admitted(
        &admitted,
        &mut adapter,
        &mut policy,
        &clock,
        &CancellationToken::default(),
    )?;
    transaction
        .release_admitted::<TestAdapter, _, _>(admitted, &mut catalog, &clock)
        .map_err(release_error)?;
    Ok(())
}

fn reject_and_settle(
    transaction: &mut ExecutionTransaction<'_>,
    operation: &ScopedOperationKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::rejected_before_effect();
    let clock = TestClock;
    let admitted = transaction
        .admit(operation, &adapter, &mut catalog, &mut policy, &clock)
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &clock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::RejectedBeforeEffect
    );
    transaction
        .release_admitted::<TestAdapter, _, _>(admitted, &mut catalog, &clock)
        .map_err(release_error)?;
    transaction.settle_failure_before_effect(operation, ability(false))?;
    Ok(())
}

mod plans;

use plans::*;
struct RuntimeFixture {
    directory: TempDir,
    plan: aos_ability_validate::CheckedEffectPlan,
    transaction: TransactionId,
}

impl RuntimeFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_plan(checked_effect_plan())
    }

    fn with_plan(
        plan: aos_ability_validate::CheckedEffectPlan,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            directory: TempDir::new()?,
            plan,
            transaction: TransactionId(LocalKey::new("runtime-test")?),
        })
    }

    fn operation(&self) -> &aos_ability_model::ScopedOperationKey {
        &self.plan.operations()[0].key
    }

    fn open<'plan>(
        &'plan self,
        store: &mut TestStore,
    ) -> Result<ExecutionTransaction<'plan>, crate::execution::TransactionError> {
        ExecutionTransaction::open(
            &self.plan,
            self.transaction.clone(),
            self.journal_path(),
            JournalLimits::default(),
            store,
        )
    }

    fn journal_path(&self) -> std::path::PathBuf {
        self.directory.path().join("execution.journal")
    }
}

struct TestStore;

impl TrustedRootStore for TestStore {
    type Error = io::Error;

    fn retain(
        &mut self,
        transaction: &TransactionId,
        artifacts: &[ArtifactReference],
    ) -> Result<RootRetentionReceipt, Self::Error> {
        let mut roots: Vec<_> = artifacts.iter().map(|artifact| artifact.closure).collect();
        roots.sort_unstable();
        roots.dedup();
        Ok(RootRetentionReceipt::new(
            transaction.clone(),
            roots,
            ability(true),
        ))
    }
}

impl TrustedPlanStore for TestStore {
    type Error = io::Error;

    fn retain_plan(
        &mut self,
        transaction: &TransactionId,
        plan: &aos_ability_validate::CheckedEffectPlan,
    ) -> Result<PlanRetentionReceipt, Self::Error> {
        Ok(PlanRetentionReceipt::new(
            transaction.clone(),
            plan.id(),
            Sha256Digest::of_bytes("test-plan-bundle"),
            ability(true),
        ))
    }
}

#[derive(Default)]
struct TestCatalog {
    fail_release: bool,
    fail_release_once_for: Option<ResourceId>,
    omit_expected_incarnation: bool,
    acquire_calls: usize,
    release_calls: usize,
    release_order: Vec<ResourceId>,
    expected_providers: Vec<Option<ProviderAssignment>>,
}

impl TrustedResourceCatalog for TestCatalog {
    type Handle = String;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        _operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        self.acquire_calls += 1;
        self.expected_providers
            .push(context.expected_provider.cloned());
        Ok(CatalogReservation::new(
            access.resource.key.as_str().to_string(),
            ResourceAdmissionEvidence::new(
                access.resource.clone(),
                if self.omit_expected_incarnation {
                    None
                } else {
                    context
                        .expected_provider
                        .map(|assignment| assignment.incarnation.clone())
                },
                None,
                ability(true),
            ),
        ))
    }

    fn release(
        &mut self,
        resource: &ResourceId,
        _handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        self.release_calls += 1;
        self.release_order.push(resource.clone());
        if self.fail_release {
            Err(io::Error::other("injected release failure"))
        } else if self.fail_release_once_for.as_ref() == Some(resource) {
            self.fail_release_once_for = None;
            Err(io::Error::other("injected one-shot release failure"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
struct AllowPolicy;

impl TrustedAuthoritySnapshot for AllowPolicy {
    type Error = io::Error;

    fn authorize_role(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &aos_ability_model::MethodReference,
        _purpose: InvocationPurpose,
        _role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn authorize_resources(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _expected_provider: Option<&ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl TrustedAdmissionPolicy for AllowPolicy {
    type DispatchFence = Self;

    fn acquire_dispatch_fence(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &aos_ability_model::MethodReference,
        _purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        Ok(*self)
    }
}

struct RevocablePolicy {
    revoked: Rc<Cell<bool>>,
}

impl RevocablePolicy {
    fn new(revoked: Rc<Cell<bool>>) -> Self {
        Self { revoked }
    }

    fn authorize_current(&self) -> Result<(), io::Error> {
        if self.revoked.get() {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected authority revocation",
            ))
        } else {
            Ok(())
        }
    }
}

impl TrustedAuthoritySnapshot for RevocablePolicy {
    type Error = io::Error;

    fn authorize_role(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
        _role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        self.authorize_current()
    }

    fn authorize_resources(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _expected_provider: Option<&ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        self.authorize_current()
    }
}

impl TrustedAdmissionPolicy for RevocablePolicy {
    type DispatchFence = AllowPolicy;

    fn acquire_dispatch_fence(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        self.authorize_current().map_err(|source| {
            AuthorityRejection::new(RuntimeAuthorityRole::CallerBindingGrant, source)
        })?;
        Ok(AllowPolicy)
    }
}

struct RoleRevocablePolicy {
    revoked: Rc<Cell<Option<RuntimeAuthorityRole>>>,
}

#[derive(Clone, Copy)]
struct RoleAuthorityFence {
    revoked: Option<RuntimeAuthorityRole>,
}

fn authorize_test_role(
    revoked: Option<RuntimeAuthorityRole>,
    role: RuntimeAuthorityRole,
) -> Result<(), io::Error> {
    if revoked == Some(role) {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected role-specific authority revocation",
        ))
    } else {
        Ok(())
    }
}

impl TrustedAuthoritySnapshot for RoleAuthorityFence {
    type Error = io::Error;

    fn authorize_role(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        authorize_test_role(self.revoked, role)
    }

    fn authorize_resources(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _expected_provider: Option<&ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        authorize_test_role(self.revoked, RuntimeAuthorityRole::AssignmentIncarnation)
    }
}

impl TrustedAuthoritySnapshot for RoleRevocablePolicy {
    type Error = io::Error;

    fn authorize_role(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        authorize_test_role(self.revoked.get(), role)
    }

    fn authorize_resources(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _expected_provider: Option<&ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        authorize_test_role(
            self.revoked.get(),
            RuntimeAuthorityRole::AssignmentIncarnation,
        )
    }
}

impl TrustedAdmissionPolicy for RoleRevocablePolicy {
    type DispatchFence = RoleAuthorityFence;

    fn acquire_dispatch_fence(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        Ok(RoleAuthorityFence {
            revoked: self.revoked.get(),
        })
    }
}

#[derive(Clone)]
struct TestRecord {
    evidence: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for TestRecord {
    fn durable(&self) -> &AbilityValue {
        &self.evidence
    }
}

impl AdapterCompletion for TestRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

#[derive(Default)]
struct HaltAfterEffectReturn {
    effect_returned: Option<(TransactionId, OperationId)>,
}

#[derive(Default)]
struct RecordingBoundaryObserver {
    observations: Vec<(
        TransactionId,
        OperationId,
        NonZeroU32,
        InvocationPurpose,
        crate::execution::Boundary,
    )>,
}

struct RevokeAtBoundary {
    revoked: Rc<Cell<bool>>,
    boundary: crate::execution::Boundary,
}

struct RevokeRoleAtBoundary {
    revoked: Rc<Cell<Option<RuntimeAuthorityRole>>>,
    role: RuntimeAuthorityRole,
    boundary: crate::execution::Boundary,
}

impl ExecutionBoundaryObserver for RevokeRoleAtBoundary {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() == self.boundary {
            self.revoked.set(Some(self.role));
        }
        Ok(ExecutionBoundaryControl::Continue)
    }
}

impl RevokeAtBoundary {
    fn new(revoked: Rc<Cell<bool>>, boundary: crate::execution::Boundary) -> Self {
        Self { revoked, boundary }
    }
}

impl ExecutionBoundaryObserver for RevokeAtBoundary {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() == self.boundary {
            self.revoked.set(true);
        }
        Ok(ExecutionBoundaryControl::Continue)
    }
}

impl ExecutionBoundaryObserver for RecordingBoundaryObserver {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        self.observations.push((
            observation.transaction().clone(),
            observation.operation().clone(),
            observation.attempt(),
            observation.purpose(),
            observation.boundary(),
        ));
        Ok(ExecutionBoundaryControl::Continue)
    }
}

impl ExecutionBoundaryObserver for HaltAfterEffectReturn {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() == crate::execution::Boundary::EffectReturned {
            self.effect_returned = Some((
                observation.transaction().clone(),
                observation.operation().clone(),
            ));
            Ok(ExecutionBoundaryControl::Halt)
        } else {
            Ok(ExecutionBoundaryControl::Continue)
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("injected execution boundary observer failure")]
struct InjectedBoundaryError;

struct ErrorAfterEffectReturn;

impl ExecutionBoundaryObserver for ErrorAfterEffectReturn {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() == crate::execution::Boundary::EffectReturned {
            Err(anyhow::Error::new(InjectedBoundaryError))
        } else {
            Ok(ExecutionBoundaryControl::Continue)
        }
    }
}

struct PublishingAdapter {
    publication: std::path::PathBuf,
    execute_calls: usize,
    reconcile_calls: usize,
}

impl PublishingAdapter {
    fn new(publication: std::path::PathBuf) -> Self {
        Self {
            publication,
            execute_calls: 0,
            reconcile_calls: 0,
        }
    }
}

impl TrustedAdapter for PublishingAdapter {
    type Request = AbilityValue;
    type Completion = TestRecord;
    type Observation = TestRecord;
    type Handle = String;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        _implementation: &aos_ability_model::ProviderImplementationReference,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> bool {
        true
    }

    fn supports_compensation(&self) -> bool {
        false
    }

    fn prepare_durable(
        &self,
        _operation: &Operation,
        inputs: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        Ok(inputs.clone())
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
        request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        self.execute_calls += 1;
        let Ok(bytes) = aos_contract::canonical::to_vec(request.as_json()) else {
            return EffectDisposition::Indeterminate(TestRecord {
                evidence: ability(false),
                outputs: BTreeMap::new(),
            });
        };
        if std::fs::write(&self.publication, bytes).is_err() {
            return EffectDisposition::Indeterminate(TestRecord {
                evidence: ability(false),
                outputs: BTreeMap::new(),
            });
        }
        EffectDisposition::Completed(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::from([(key("ready"), ability(true))]),
        })
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        self.reconcile_calls += 1;
        let expected = aos_contract::canonical::to_vec(request.as_json());
        let publication_matches = expected.ok().is_some_and(|expected| {
            std::fs::read(&self.publication).is_ok_and(|published| published == expected)
        });
        if publication_matches {
            ReconcileDisposition::Completed(TestRecord {
                evidence: ability(true),
                outputs: BTreeMap::from([(key("ready"), ability(true))]),
            })
        } else {
            ReconcileDisposition::SafeToRetry(TestRecord {
                evidence: ability(false),
                outputs: BTreeMap::new(),
            })
        }
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        CancellationDisposition::Indeterminate(TestRecord {
            evidence: ability(false),
            outputs: BTreeMap::new(),
        })
    }
}

struct TestAdapter {
    outputs: BTreeMap<LocalKey, AbilityValue>,
    fail_preparation: bool,
    reject_before_effect: bool,
    indeterminate: bool,
    supports_compensation: bool,
    execute_calls: usize,
    reconciliation_elapsed: Vec<u64>,
    cancel_calls: usize,
    compensate_calls: usize,
    compensation_reconciliation_calls: usize,
}

impl TestAdapter {
    fn with_output(output: AbilityValue) -> Self {
        Self {
            outputs: BTreeMap::from([(key("ready"), output)]),
            fail_preparation: false,
            reject_before_effect: false,
            indeterminate: false,
            supports_compensation: true,
            execute_calls: 0,
            reconciliation_elapsed: Vec::new(),
            cancel_calls: 0,
            compensate_calls: 0,
            compensation_reconciliation_calls: 0,
        }
    }

    fn valid() -> Self {
        Self::with_output(ability(true))
    }

    fn missing_outputs() -> Self {
        Self {
            outputs: BTreeMap::new(),
            fail_preparation: false,
            reject_before_effect: false,
            indeterminate: false,
            supports_compensation: true,
            execute_calls: 0,
            reconciliation_elapsed: Vec::new(),
            cancel_calls: 0,
            compensate_calls: 0,
            compensation_reconciliation_calls: 0,
        }
    }

    fn preparation_failure() -> Self {
        Self {
            outputs: BTreeMap::new(),
            fail_preparation: true,
            reject_before_effect: false,
            indeterminate: false,
            supports_compensation: true,
            execute_calls: 0,
            reconciliation_elapsed: Vec::new(),
            cancel_calls: 0,
            compensate_calls: 0,
            compensation_reconciliation_calls: 0,
        }
    }

    fn rejected_before_effect() -> Self {
        Self {
            outputs: BTreeMap::new(),
            fail_preparation: false,
            reject_before_effect: true,
            indeterminate: false,
            supports_compensation: true,
            execute_calls: 0,
            reconciliation_elapsed: Vec::new(),
            cancel_calls: 0,
            compensate_calls: 0,
            compensation_reconciliation_calls: 0,
        }
    }

    fn without_compensation_support() -> Self {
        Self {
            supports_compensation: false,
            ..Self::valid()
        }
    }

    fn recovery() -> Self {
        Self {
            outputs: BTreeMap::new(),
            indeterminate: true,
            ..Self::valid()
        }
    }
}

impl TrustedAdapter for TestAdapter {
    type Request = AbilityValue;
    type Completion = TestRecord;
    type Observation = TestRecord;
    type Handle = String;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        _implementation: &aos_ability_model::ProviderImplementationReference,
        _method: &aos_ability_model::MethodReference,
        _purpose: InvocationPurpose,
    ) -> bool {
        true
    }

    fn supports_compensation(&self) -> bool {
        self.supports_compensation
    }

    fn prepare_durable(
        &self,
        _operation: &Operation,
        inputs: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        if self.fail_preparation {
            Err(io::Error::other("injected preparation failure"))
        } else {
            Ok(inputs.clone())
        }
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
        let record = TestRecord {
            evidence: ability(true),
            outputs: self.outputs.clone(),
        };
        if self.reject_before_effect {
            EffectDisposition::RejectedBeforeEffect(record)
        } else if self.indeterminate {
            EffectDisposition::Indeterminate(record)
        } else {
            EffectDisposition::Completed(record)
        }
    }

    fn reconcile(
        &mut self,
        _request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        let record = TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::new(),
        };
        if self.indeterminate {
            self.reconciliation_elapsed.push(control.elapsed_millis());
            ReconcileDisposition::SafeToRetry(record)
        } else {
            ReconcileDisposition::InterventionRequired(record)
        }
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        self.cancel_calls += 1;
        CancellationDisposition::Indeterminate(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::new(),
        })
    }

    fn compensate(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> Option<EffectDisposition<Self::Completion, Self::Observation>> {
        self.compensate_calls += 1;
        let record = TestRecord {
            evidence: ability(true),
            outputs: self.outputs.clone(),
        };
        if self.indeterminate {
            Some(EffectDisposition::Indeterminate(record))
        } else {
            Some(EffectDisposition::Completed(record))
        }
    }

    fn reconcile_compensation(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> Option<ReconcileDisposition<Self::Completion, Self::Observation>> {
        self.compensation_reconciliation_calls += 1;
        let outputs = if self.indeterminate {
            BTreeMap::from([(key("ready"), ability(true))])
        } else {
            self.outputs.clone()
        };
        Some(ReconcileDisposition::Completed(TestRecord {
            evidence: ability(true),
            outputs,
        }))
    }
}

struct TestClock;

impl MonotonicClock for TestClock {
    fn now_millis(&self) -> u64 {
        0
    }

    fn restart_stable_millis(&self) -> u64 {
        0
    }
}

#[derive(Default)]
struct SettableClock(Cell<u64>);

impl SettableClock {
    fn set(&self, millis: u64) {
        self.0.set(millis);
    }
}

impl MonotonicClock for SettableClock {
    fn now_millis(&self) -> u64 {
        self.0.get()
    }

    fn restart_stable_millis(&self) -> u64 {
        self.0.get()
    }
}

#[derive(Default)]
struct RecordingPolicy {
    purposes: Vec<InvocationPurpose>,
}

impl TrustedAuthoritySnapshot for RecordingPolicy {
    type Error = io::Error;

    fn authorize_role(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        if role == RuntimeAuthorityRole::CallerBindingGrant {
            self.purposes.push(purpose);
        }
        Ok(())
    }

    fn authorize_resources(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _expected_provider: Option<&ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl TrustedAdmissionPolicy for RecordingPolicy {
    type DispatchFence = AllowPolicy;

    fn acquire_dispatch_fence(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        self.purposes.push(purpose);
        Ok(AllowPolicy)
    }
}

fn assert_revoked_dispatch(
    error: ExecutionError,
    expected_purpose: InvocationPurpose,
) -> Result<(), Box<dyn std::error::Error>> {
    match error {
        ExecutionError::DispatchAdmission(AdmissionError::FreshAuthorization {
            purpose, ..
        }) if purpose == expected_purpose => Ok(()),
        other => {
            Err(format!("expected {expected_purpose:?} dispatch revocation, got {other:?}").into())
        }
    }
}

fn runtime_authority_roles() -> [RuntimeAuthorityRole; 4] {
    [
        RuntimeAuthorityRole::CallerBindingGrant,
        RuntimeAuthorityRole::ProviderMethodImplementation,
        RuntimeAuthorityRole::EnforcementPlatformGuarantee,
        RuntimeAuthorityRole::AssignmentIncarnation,
    ]
}

fn assert_authority_rejection(
    error: &AdmissionError,
    expected_role: RuntimeAuthorityRole,
    expected_boundary: AuthorityCheckBoundary,
) -> Result<(), Box<dyn std::error::Error>> {
    match error {
        AdmissionError::FreshAuthorization { role, boundary, .. }
            if *role == expected_role && *boundary == expected_boundary =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected {expected_role:?} rejection at {expected_boundary:?}, got {other:?}"
        )
        .into()),
    }
}

fn assert_durable_authority_rejection(
    fixture: &RuntimeFixture,
    expected_role: RuntimeAuthorityRole,
    expected_boundary: AuthorityCheckBoundary,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = CheckedExecutionJournalSnapshot::read(
        &fixture.plan,
        fixture.journal_path(),
        JournalLimits::default(),
    )?;
    if snapshot.records().iter().any(|record| {
        matches!(
            record.body().body(),
            ExecutionEventKind::AuthorityRejected {
                purpose: InvocationPurpose::Effect,
                role,
                boundary,
                ..
            } if *role == expected_role && *boundary == expected_boundary
        )
    }) {
        Ok(())
    } else {
        Err(format!("journal lacks {expected_role:?} rejection at {expected_boundary:?}").into())
    }
}

fn admission_error<H>(failure: crate::execution::AdmissionFailure<H>) -> io::Error {
    io::Error::other(failure.error().to_string())
}

fn release_error<Request, Handle>(
    failure: crate::execution::ResourceReleaseFailure<'_, Request, Handle>,
) -> io::Error {
    io::Error::other(failure.error().to_string())
}

fn ability(value: bool) -> AbilityValue {
    AbilityValue::new(serde_json::Value::Bool(value)).expect("Boolean is a bounded ability value")
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("test key is valid")
}
