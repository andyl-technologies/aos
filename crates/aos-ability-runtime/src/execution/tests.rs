//! Checked-plan integration tests for the public runtime controller boundary.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io;
use std::num::{NonZeroU32, NonZeroUsize};

use aos_ability_model::{
    compare_edges, compare_operation_keys, AbilityValue, AccessMode, ArtifactReference, BindingId,
    BranchMembership, DecisionAlternative, DecisionNode, DecisionPredicate, DecisionSelector,
    DependencyEdge, DependencyKind, IncarnationId, IndeterminateSemantics, LocalKey, MergeNode,
    MergedOutput, MethodReference, Operation, OperationResultReference, PlanNodeKey,
    ProviderAssignment, ResourceAccess, ResourceId, ResourcePermission, ResultProducerKey,
    RetryPolicy, RevisionId, ScopedOperationKey, TransactionId, ValueExpression,
};
use aos_ability_validate::test_support::{
    checked_effect_plan, checked_planned_provider_chain, plan_fixture,
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
    AdmissionError, ExecutionError, ExecutionStep, ExecutionTransaction, OperationState,
    RecoveryAction, ResourceReleaseError, TrustedAdmissionPolicy,
};
use crate::journal::JournalLimits;

#[test]
fn public_controller_completes_and_releases_a_checked_operation(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let ready = transaction.schedule_ready(NonZeroUsize::MIN)?;
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].action(), &RecoveryAction::Admit);

    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let clock = TestClock;
    let admitted = transaction
        .admit(
            ready[0].operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    let step = transaction.drive_admitted(
        &admitted,
        &mut adapter,
        &mut policy,
        &clock,
        &CancellationToken::default(),
    )?;
    assert_eq!(step, ExecutionStep::Completed);

    transaction
        .release_admitted::<TestAdapter, _, _>(admitted, &mut catalog, &clock)
        .map_err(release_error)?;
    assert!(transaction
        .history(fixture.operation())?
        .resources_released());
    assert_eq!(
        transaction.next_action(fixture.operation())?,
        RecoveryAction::None
    );
    assert_eq!(catalog.release_calls, 1);
    Ok(())
}

#[test]
fn schema_invalid_completion_stays_at_durable_intent() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::missing_outputs();
    let clock = TestClock;
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;

    let error = transaction
        .drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &clock,
            &CancellationToken::default(),
        )
        .expect_err("missing checked output port must reject completion");

    assert!(matches!(error, ExecutionError::Transaction(_)));
    assert!(matches!(
        transaction.history(fixture.operation())?.state(),
        OperationState::IntentDurable { .. }
    ));
    assert_eq!(adapter.execute_calls, 1);
    assert_eq!(
        transaction.next_action(fixture.operation())?,
        RecoveryAction::InterventionRequired
    );
    Ok(())
}

#[test]
fn token_from_closed_controller_cannot_drive_or_release_reopened_transaction(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let mut first = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let clock = TestClock;
    let admitted = first
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    drop(first);

    let mut reopened = fixture.open(&mut store)?;
    let drive_error = reopened
        .drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &clock,
            &CancellationToken::default(),
        )
        .expect_err("old controller token must be stale");
    assert!(matches!(drive_error, ExecutionError::StaleAdmission));
    assert_eq!(adapter.execute_calls, 0);

    let release = reopened
        .release_admitted::<TestAdapter, _, _>(admitted, &mut catalog, &clock)
        .expect_err("old controller token must not release reopened ownership");
    assert!(matches!(
        release.error(),
        ResourceReleaseError::StaleAdmission
    ));
    assert_eq!(catalog.release_calls, 0);
    Ok(())
}

#[test]
fn dropped_failed_cleanup_keeps_duplicate_admission_blocked(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog {
        fail_release: true,
        ..TestCatalog::default()
    };
    let mut policy = AllowPolicy;
    let adapter = TestAdapter::preparation_failure();
    let clock = TestClock;

    let failure = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .expect_err("request preparation must fail after acquisition");
    assert_eq!(failure.retained_resources().count(), 1);
    drop(failure);

    let duplicate = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .expect_err("dropped unresolved cleanup must retain its live claim");
    assert!(matches!(
        duplicate.error(),
        AdmissionError::Transaction(source)
            if matches!(source, crate::execution::TransactionError::OperationAlreadyLive)
    ));
    assert_eq!(catalog.acquire_calls, 1);
    Ok(())
}

#[test]
fn failed_release_retries_without_publishing_early() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let clock = TestClock;
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    transaction.drive_admitted(
        &admitted,
        &mut adapter,
        &mut policy,
        &clock,
        &CancellationToken::default(),
    )?;
    catalog.fail_release = true;

    let failure = transaction
        .release_admitted::<TestAdapter, _, _>(admitted, &mut catalog, &clock)
        .expect_err("catalog release failure must retain the token");
    assert!(!transaction
        .history(fixture.operation())?
        .resources_released());
    assert_eq!(failure.retained_resources().count(), 1);

    catalog.fail_release = false;
    failure
        .retry(&mut transaction, &mut catalog, &clock)
        .map_err(release_error)?;
    assert!(transaction
        .history(fixture.operation())?
        .resources_released());
    assert_eq!(catalog.release_calls, 2);
    Ok(())
}

#[test]
fn partial_release_retries_only_the_handles_still_owned() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = RuntimeFixture::with_plan(checked_two_resource_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let clock = TestClock;
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    transaction.drive_admitted(
        &admitted,
        &mut adapter,
        &mut policy,
        &clock,
        &CancellationToken::default(),
    )?;
    let lower_resource = fixture.plan.operations()[0].accesses[0].resource.clone();
    let higher_resource = fixture.plan.operations()[0].accesses[1].resource.clone();
    catalog.fail_release_once_for = Some(lower_resource.clone());

    let failure = transaction
        .release_admitted::<TestAdapter, _, _>(admitted, &mut catalog, &clock)
        .expect_err("the second reverse-order release must fail once");
    assert_eq!(
        failure.retained_resources().collect::<Vec<_>>(),
        [&lower_resource]
    );
    assert!(!transaction
        .history(fixture.operation())?
        .resources_released());
    assert_eq!(
        catalog.release_order,
        [higher_resource.clone(), lower_resource.clone()]
    );

    failure
        .retry(&mut transaction, &mut catalog, &clock)
        .map_err(release_error)?;
    assert_eq!(
        catalog.release_order,
        [higher_resource, lower_resource.clone(), lower_resource]
    );
    assert!(transaction
        .history(fixture.operation())?
        .resources_released());
    Ok(())
}

#[test]
fn scheduler_waits_for_data_and_resolves_the_durable_output(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_dependent_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let first = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].operation().key.as_str(), "observe");

    complete(&mut transaction, first[0].operation())?;

    let second = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].operation().key.as_str(), "consume");
    assert_eq!(
        transaction
            .resolve_operation_inputs(second[0].operation())?
            .as_json(),
        &serde_json::Value::Bool(true)
    );
    Ok(())
}

#[test]
fn scheduler_persists_selection_and_excludes_the_unselected_operation(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_branch_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let first = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].operation().key.as_str(), "observe");

    complete(&mut transaction, first[0].operation())?;

    let selected = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].operation().key.as_str(), "true-step");
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    let replayed = reopened.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].operation().key.as_str(), "true-step");
    Ok(())
}

#[test]
fn scheduler_persists_selected_merge_output_for_downstream_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_merge_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let first = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].operation().key.as_str(), "observe");
    complete(&mut transaction, first[0].operation())?;

    let branch = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(branch.len(), 1);
    assert_eq!(branch[0].operation().key.as_str(), "true-step");
    complete(&mut transaction, branch[0].operation())?;

    let downstream = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(downstream.len(), 1);
    assert_eq!(downstream[0].operation().key.as_str(), "consume");
    assert_eq!(
        transaction
            .resolve_operation_inputs(downstream[0].operation())?
            .as_json(),
        &serde_json::Value::Bool(true)
    );
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    let replayed = reopened.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].operation().key.as_str(), "consume");
    assert_eq!(
        reopened
            .resolve_operation_inputs(replayed[0].operation())?
            .as_json(),
        &serde_json::Value::Bool(true)
    );
    Ok(())
}

#[test]
fn planned_provider_chain_requires_each_durable_assignment_before_use(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_planned_provider_chain())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let first = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].operation().key.as_str(), "ready-b");

    let assignment_b = provider_assignment(&fixture.plan, "b", "planned-b-live")?;
    complete_with_output(
        &mut transaction,
        first[0].operation(),
        assignment_value(&assignment_b)?,
    )?;
    let second = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].operation().key.as_str(), "ready-c");

    let assignment_c = provider_assignment(&fixture.plan, "c", "planned-c-live")?;
    complete_with_expected_provider(
        &mut transaction,
        second[0].operation(),
        &assignment_b,
        assignment_value(&assignment_c)?,
    )?;
    let third = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].operation().key.as_str(), "use-c");

    complete_with_expected_provider(
        &mut transaction,
        third[0].operation(),
        &assignment_c,
        assignment_value(&assignment_c)?,
    )?;
    assert!(transaction
        .schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?
        .is_empty());
    Ok(())
}

#[test]
fn planned_provider_admission_rejects_missing_live_incarnation_before_effect(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_planned_provider_chain())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let first = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    let assignment_b = provider_assignment(&fixture.plan, "b", "planned-b-live")?;
    complete_with_output(
        &mut transaction,
        first[0].operation(),
        assignment_value(&assignment_b)?,
    )?;
    let second = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    let mut catalog = TestCatalog {
        omit_expected_incarnation: true,
        ..TestCatalog::default()
    };
    let mut policy = AllowPolicy;
    let adapter = TestAdapter::valid();

    let failure = transaction
        .admit(
            second[0].operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &TestClock,
        )
        .expect_err("missing live incarnation must reject a durable planned assignment");

    assert!(matches!(
        failure.error(),
        AdmissionError::CatalogEvidenceMismatch(_)
    ));
    assert_eq!(adapter.execute_calls, 0);
    assert_eq!(catalog.acquire_calls, 1);
    assert_eq!(catalog.release_calls, 1);
    Ok(())
}

#[test]
fn reopened_indeterminate_effect_authorizes_only_reconciliation_and_preserves_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
    let mut store = TestStore;
    let clock = SettableClock::default();
    let mut catalog = TestCatalog::default();
    let mut initial_policy = RecordingPolicy::default();
    let mut adapter = RecoveryAdapter::default();
    let mut transaction = fixture.open(&mut store)?;
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut initial_policy,
            &clock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        initial_policy.purposes,
        [InvocationPurpose::Effect, InvocationPurpose::Reconcile]
    );

    clock.set(100);
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut initial_policy,
            &clock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Indeterminate
    );
    drop(admitted);
    drop(transaction);

    let mut recovered = fixture.open(&mut store)?;
    let mut recovery_policy = RecordingPolicy::default();
    let recovered_token = recovered
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut recovery_policy,
            &clock,
        )
        .map_err(admission_error)?;
    assert_eq!(recovered_token.elapsed_millis(), 100);
    assert_eq!(recovery_policy.purposes, [InvocationPurpose::Reconcile]);

    clock.set(150);
    assert_eq!(
        recovered.drive_admitted(
            &recovered_token,
            &mut adapter,
            &mut recovery_policy,
            &clock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::SafeToRetry
    );
    assert_eq!(
        recovery_policy.purposes,
        [InvocationPurpose::Reconcile, InvocationPurpose::Reconcile]
    );
    assert_eq!(adapter.reconciliation_elapsed, [150]);
    assert_eq!(recovered.elapsed_millis(), 150);

    recovered
        .release_admitted::<RecoveryAdapter, _, _>(recovered_token, &mut catalog, &clock)
        .map_err(release_error)?;
    assert_eq!(
        recovered.next_action(fixture.operation())?,
        RecoveryAction::Retry {
            attempt: NonZeroU32::new(2).ok_or("positive retry attempt")?,
        }
    );
    Ok(())
}

#[test]
fn transaction_rejects_unenforced_nonzero_retry_backoff() -> Result<(), Box<dyn std::error::Error>>
{
    let plan = recovery_plan_fixture(1)
        .validate()
        .expect("nonzero backoff is a valid checked plan contract");
    let fixture = RuntimeFixture::with_plan(plan)?;
    let mut store = TestStore;

    let error = fixture
        .open(&mut store)
        .expect_err("runtime must not silently ignore declared retry backoff");

    assert!(matches!(
        error,
        crate::execution::TransactionError::UnsupportedRetryBackoff
    ));
    Ok(())
}

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

fn checked_dependent_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = plan_fixture();
    let producer = fixture.effect_plan.operations[0].clone();
    let mut consumer = producer.clone();
    consumer.key = scoped("consume");
    consumer.inputs = ValueExpression::OperationResult {
        reference: result_reference(&producer.key),
    };
    fixture.effect_plan.operations = vec![consumer, producer.clone()];
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.edges = vec![DependencyEdge {
        from: PlanNodeKey::Operation { key: producer.key },
        to: PlanNodeKey::Operation {
            key: scoped("consume"),
        },
        kind: DependencyKind::Data,
    }];
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("dependent runtime fixture must pass production validation")
}

fn checked_two_resource_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = plan_fixture();
    let mut extra_revision = fixture.effect_plan.current_revisions[0].clone();
    extra_revision.resource.key = key("secondary");
    extra_revision.revision = RevisionId(Sha256Digest::of_bytes("secondary-resource"));
    let extra_resource = extra_revision.resource.clone();
    fixture
        .binding_inputs
        .environment
        .resources
        .push(extra_revision.clone());
    fixture
        .binding_inputs
        .environment
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture
        .binding_inputs
        .desired_state
        .resources
        .push(extra_revision.clone());
    fixture
        .binding_inputs
        .desired_state
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.binding_plan.resources.push(extra_revision.clone());
    fixture
        .binding_plan
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.binding_plan.bindings[0]
        .caller_grant
        .resources
        .push(ResourcePermission {
            resource: extra_resource.clone(),
            access: AccessMode::Read,
            operations: vec![key("observe")],
        });
    fixture.binding_plan.bindings[0]
        .caller_grant
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.effect_plan.operations[0]
        .accesses
        .push(ResourceAccess {
            resource: extra_resource,
            mode: AccessMode::Read,
        });
    fixture.effect_plan.operations[0]
        .accesses
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture
        .effect_plan
        .current_revisions
        .push(extra_revision.clone());
    fixture
        .effect_plan
        .current_revisions
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.effect_plan.desired_revisions.push(extra_revision);
    fixture
        .effect_plan
        .desired_revisions
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("multi-resource runtime fixture must pass production validation")
}

fn recovery_plan_fixture(backoff_millis: u64) -> aos_ability_validate::test_support::PlanFixture {
    let mut fixture = plan_fixture();
    fixture.interfaces[0]
        .interface
        .methods
        .get_mut(&key("observe"))
        .expect("fixture observe method")
        .outcome
        .indeterminate = IndeterminateSemantics::Reconcile;
    let operation = &mut fixture.effect_plan.operations[0];
    operation.recovery.retry = RetryPolicy::Bounded {
        max_attempts: NonZeroU32::new(2).expect("positive test retry count"),
        backoff_millis,
    };
    operation.recovery.reconcile = Some(MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    });
    fixture.refresh_interface();
    fixture
}

fn checked_recovery_plan() -> aos_ability_validate::CheckedEffectPlan {
    recovery_plan_fixture(0)
        .validate()
        .expect("reconcilable runtime fixture must pass production validation")
}

fn branch_plan_fixture() -> aos_ability_validate::test_support::PlanFixture {
    let mut fixture = plan_fixture();
    let producer = fixture.effect_plan.operations[0].clone();
    let decision_key = scoped("choose");
    let false_key = key("false");
    let true_key = key("true");
    let mut false_operation = producer.clone();
    false_operation.key = scoped("false-step");
    false_operation.branch_context = vec![BranchMembership {
        decision: decision_key.clone(),
        alternative: false_key.clone(),
    }];
    let mut true_operation = producer.clone();
    true_operation.key = scoped("true-step");
    true_operation.branch_context = vec![BranchMembership {
        decision: decision_key.clone(),
        alternative: true_key.clone(),
    }];
    fixture.effect_plan.operations = vec![false_operation, producer.clone(), true_operation];
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.decisions = vec![DecisionNode {
        key: decision_key.clone(),
        branch_context: Vec::new(),
        selector: DecisionSelector {
            result: result_reference(&producer.key),
            tag_field: None,
        },
        alternatives: vec![
            DecisionAlternative {
                key: false_key,
                predicate: DecisionPredicate::Boolean { value: false },
            },
            DecisionAlternative {
                key: true_key,
                predicate: DecisionPredicate::Boolean { value: true },
            },
        ],
    }];
    fixture.effect_plan.edges = vec![
        DependencyEdge {
            from: PlanNodeKey::Decision {
                key: decision_key.clone(),
            },
            to: PlanNodeKey::Operation {
                key: scoped("false-step"),
            },
            kind: DependencyKind::BranchGuard,
        },
        DependencyEdge {
            from: PlanNodeKey::Decision {
                key: decision_key.clone(),
            },
            to: PlanNodeKey::Operation {
                key: scoped("true-step"),
            },
            kind: DependencyKind::BranchGuard,
        },
        DependencyEdge {
            from: PlanNodeKey::Operation { key: producer.key },
            to: PlanNodeKey::Decision { key: decision_key },
            kind: DependencyKind::Data,
        },
    ];
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
}

fn checked_branch_plan() -> aos_ability_validate::CheckedEffectPlan {
    branch_plan_fixture()
        .validate()
        .expect("conditional runtime fixture must pass production validation")
}

fn checked_merge_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = branch_plan_fixture();
    let template = fixture.effect_plan.operations[0].clone();
    let mut consumer = template;
    consumer.key = scoped("consume");
    consumer.branch_context.clear();
    consumer.inputs = ValueExpression::OperationResult {
        reference: OperationResultReference {
            producer: ResultProducerKey::Merge {
                key: scoped("selected"),
            },
            output: key("ready"),
        },
    };
    fixture.effect_plan.operations.push(consumer);
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    let descriptor = fixture.interfaces[0]
        .interface
        .methods
        .get(&key("observe"))
        .and_then(|method| method.outputs.get(&key("ready")))
        .cloned()
        .expect("fixture readiness output");
    fixture.effect_plan.merges = vec![MergeNode {
        key: scoped("selected"),
        decision: scoped("choose"),
        branch_context: Vec::new(),
        outputs: BTreeMap::from([(
            key("ready"),
            MergedOutput {
                descriptor,
                alternatives: BTreeMap::from([
                    (key("false"), result_reference(&scoped("false-step"))),
                    (key("true"), result_reference(&scoped("true-step"))),
                ]),
            },
        )]),
    }];
    fixture.effect_plan.edges.extend([
        DependencyEdge {
            from: PlanNodeKey::Operation {
                key: scoped("false-step"),
            },
            to: PlanNodeKey::Merge {
                key: scoped("selected"),
            },
            kind: DependencyKind::BranchMerge,
        },
        DependencyEdge {
            from: PlanNodeKey::Operation {
                key: scoped("true-step"),
            },
            to: PlanNodeKey::Merge {
                key: scoped("selected"),
            },
            kind: DependencyKind::BranchMerge,
        },
        DependencyEdge {
            from: PlanNodeKey::Merge {
                key: scoped("selected"),
            },
            to: PlanNodeKey::Operation {
                key: scoped("consume"),
            },
            kind: DependencyKind::Data,
        },
    ]);
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("merged runtime fixture must pass production validation")
}

fn result_reference(producer: &ScopedOperationKey) -> OperationResultReference {
    OperationResultReference {
        producer: ResultProducerKey::Operation {
            key: producer.clone(),
        },
        output: key("ready"),
    }
}

fn scoped(value: &str) -> ScopedOperationKey {
    ScopedOperationKey {
        scope: aos_ability_model::ScopePath::root(),
        key: key(value),
    }
}

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
            self.directory.path().join("execution.journal"),
            JournalLimits::default(),
            store,
        )
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

struct AllowPolicy;

impl TrustedAdmissionPolicy for AllowPolicy {
    type Error = io::Error;

    fn authorize(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &aos_ability_model::MethodReference,
        _purpose: InvocationPurpose,
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

struct TestAdapter {
    outputs: BTreeMap<LocalKey, AbilityValue>,
    fail_preparation: bool,
    execute_calls: usize,
}

impl TestAdapter {
    fn with_output(output: AbilityValue) -> Self {
        Self {
            outputs: BTreeMap::from([(key("ready"), output)]),
            fail_preparation: false,
            execute_calls: 0,
        }
    }

    fn valid() -> Self {
        Self::with_output(ability(true))
    }

    fn missing_outputs() -> Self {
        Self {
            outputs: BTreeMap::new(),
            fail_preparation: false,
            execute_calls: 0,
        }
    }

    fn preparation_failure() -> Self {
        Self {
            outputs: BTreeMap::new(),
            fail_preparation: true,
            execute_calls: 0,
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
        EffectDisposition::Completed(TestRecord {
            evidence: ability(true),
            outputs: self.outputs.clone(),
        })
    }

    fn reconcile(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        ReconcileDisposition::InterventionRequired(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::new(),
        })
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        CancellationDisposition::Indeterminate(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::new(),
        })
    }
}

struct TestClock;

impl MonotonicClock for TestClock {
    fn now_millis(&self) -> u64 {
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
}

#[derive(Default)]
struct RecordingPolicy {
    purposes: Vec<InvocationPurpose>,
}

impl TrustedAdmissionPolicy for RecordingPolicy {
    type Error = io::Error;

    fn authorize(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> Result<(), Self::Error> {
        self.purposes.push(purpose);
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

#[derive(Default)]
struct RecoveryAdapter {
    reconciliation_elapsed: Vec<u64>,
}

impl TrustedAdapter for RecoveryAdapter {
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
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        EffectDisposition::Indeterminate(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::new(),
        })
    }

    fn reconcile(
        &mut self,
        _request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        self.reconciliation_elapsed.push(control.elapsed_millis());
        ReconcileDisposition::SafeToRetry(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::new(),
        })
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        CancellationDisposition::Indeterminate(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::new(),
        })
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
