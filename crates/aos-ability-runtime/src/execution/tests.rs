//! Checked-plan integration tests for the public runtime controller boundary.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};

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
    checked_effect_plan, checked_planned_provider_chain, checked_systemd_manager_effect_plan,
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
    AdmissionError, CheckedExecutionJournalSnapshot, ExecutionError, ExecutionEvent,
    ExecutionEventKind, ExecutionStep, ExecutionTransaction, OperationState, OperationStatus,
    RecoveryAction, ResourceReleaseError, TerminalResult, TrustedAdmissionPolicy,
};
use crate::journal::{FileJournal, JournalLimits};

#[test]
fn executable_no_op_transaction_creates_and_replays_a_zero_budget_journal()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, plan) = verified_planning_effect_plan();
    assert!(plan.is_executable());
    assert!(plan.operations().is_empty());
    let fixture = RuntimeFixture::with_plan(plan)?;
    let mut store = TestStore;

    let transaction = fixture.open(&mut store)?;
    assert_eq!(transaction.total_recovery_millis(), 0);
    drop(transaction);

    let snapshot = CheckedExecutionJournalSnapshot::read(
        &fixture.plan,
        fixture.journal_path(),
        JournalLimits::default(),
    )?;
    assert_eq!(snapshot.records().len(), 1);
    assert!(matches!(
        snapshot.records()[0].body().body(),
        ExecutionEventKind::TransactionPlanned {
            total_recovery_millis: 0,
            ..
        }
    ));
    Ok(())
}

#[test]
fn zero_budget_journal_is_rejected_for_a_nonempty_checked_plan()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let retained_roots = fixture
        .plan
        .required_runtime_artifacts()
        .iter()
        .map(|artifact| artifact.closure)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut journal =
        FileJournal::<ExecutionEvent>::open(fixture.journal_path(), JournalLimits::default())?
            .journal;
    journal.append(&ExecutionEvent::new(
        ExecutionEventKind::TransactionPlanned {
            transaction: fixture.transaction.clone(),
            plan: fixture.plan.id(),
            plan_bundle: Sha256Digest::of_bytes("test-plan-bundle"),
            retained_roots,
            total_recovery_millis: 0,
        },
    ))?;
    drop(journal);

    let error = CheckedExecutionJournalSnapshot::read(
        &fixture.plan,
        fixture.journal_path(),
        JournalLimits::default(),
    )
    .expect_err("zero recovery budget must not match a plan with work");
    assert!(matches!(
        error,
        crate::execution::TransactionError::InvalidHistory { .. }
    ));
    Ok(())
}

#[test]
fn read_only_execution_snapshot_replays_exact_plan_membership_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let transaction = fixture.open(&mut store)?;
    drop(transaction);
    let length_before = std::fs::metadata(fixture.journal_path())?.len();

    let snapshot = CheckedExecutionJournalSnapshot::read(
        &fixture.plan,
        fixture.journal_path(),
        JournalLimits::default(),
    )?;

    assert_eq!(snapshot.transaction(), &fixture.transaction);
    assert_eq!(snapshot.records().len(), 1);
    assert_eq!(snapshot.head_digest(), snapshot.records()[0].digest());
    assert_eq!(snapshot.incomplete_tail_bytes(), 0);
    assert_eq!(
        std::fs::metadata(fixture.journal_path())?.len(),
        length_before
    );

    let wrong_plan = checked_systemd_manager_effect_plan();
    let mismatch = CheckedExecutionJournalSnapshot::read(
        &wrong_plan,
        fixture.journal_path(),
        JournalLimits::default(),
    );
    assert!(matches!(
        mismatch,
        Err(crate::execution::TransactionError::InvalidHistory { .. })
    ));
    Ok(())
}

#[test]
fn public_controller_completes_and_releases_a_checked_operation()
-> Result<(), Box<dyn std::error::Error>> {
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
    assert!(
        transaction
            .history(fixture.operation())?
            .resources_released()
    );
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
fn token_from_closed_controller_cannot_drive_or_release_reopened_transaction()
-> Result<(), Box<dyn std::error::Error>> {
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
fn dropped_failed_cleanup_keeps_duplicate_admission_blocked()
-> Result<(), Box<dyn std::error::Error>> {
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
    assert!(
        !transaction
            .history(fixture.operation())?
            .resources_released()
    );
    assert_eq!(failure.retained_resources().count(), 1);

    catalog.fail_release = false;
    failure
        .retry(&mut transaction, &mut catalog, &clock)
        .map_err(release_error)?;
    assert!(
        transaction
            .history(fixture.operation())?
            .resources_released()
    );
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
    assert!(
        !transaction
            .history(fixture.operation())?
            .resources_released()
    );
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
    assert!(
        transaction
            .history(fixture.operation())?
            .resources_released()
    );
    Ok(())
}

#[test]
fn scheduler_waits_for_data_and_resolves_the_durable_output()
-> Result<(), Box<dyn std::error::Error>> {
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
fn settled_failure_propagates_to_a_required_dependent_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_dependent_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let producer = scoped("observe");

    reject_and_settle(&mut transaction, &producer)?;
    let ready = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].operation().key.as_str(), "consume");
    assert_eq!(
        ready[0].action(),
        &RecoveryAction::SettleFailureBeforeEffect
    );
    transaction.settle_failure_before_effect(ready[0].operation(), ability(false))?;

    let summary = transaction.summary();
    assert_eq!(summary.terminal(), Some(TerminalResult::SettledFailure));
    assert!(
        summary
            .operations()
            .iter()
            .all(|operation| operation.status() == OperationStatus::SettledFailure)
    );
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    assert_eq!(
        reopened.summary().terminal(),
        Some(TerminalResult::SettledFailure)
    );
    assert!(
        reopened
            .schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn ordering_only_waits_for_propagated_failure_to_settle_then_runs()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_failure_then_ordering_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;

    reject_and_settle(&mut transaction, &scoped("first"))?;
    let blocked = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].operation().key.as_str(), "blocked");
    assert_eq!(
        blocked[0].action(),
        &RecoveryAction::SettleFailureBeforeEffect
    );
    transaction.settle_failure_before_effect(blocked[0].operation(), ability(false))?;

    let ordered = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(ordered.len(), 1);
    assert_eq!(ordered[0].operation().key.as_str(), "after");
    assert_eq!(ordered[0].action(), &RecoveryAction::Admit);
    Ok(())
}

#[test]
fn scheduler_persists_selection_and_excludes_the_unselected_operation()
-> Result<(), Box<dyn std::error::Error>> {
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
fn transaction_summary_preserves_mixed_terminal_outcomes() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = RuntimeFixture::with_plan(checked_branch_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let producer = scoped("observe");

    complete(&mut transaction, &producer)?;
    let branch = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(branch.len(), 1);
    assert_eq!(branch[0].operation().key.as_str(), "true-step");
    reject_and_settle(&mut transaction, branch[0].operation())?;

    let summary = transaction.summary();
    assert_eq!(summary.terminal(), Some(TerminalResult::SettledFailure));
    assert_eq!(
        summary
            .operations()
            .iter()
            .map(|operation| operation.status())
            .collect::<Vec<_>>(),
        [
            OperationStatus::Skipped,
            OperationStatus::Succeeded,
            OperationStatus::SettledFailure,
        ]
    );
    Ok(())
}

#[test]
fn failed_selector_settles_both_unselected_branch_arms() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_failed_decision_ordering_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;

    reject_and_settle(&mut transaction, &scoped("observe"))?;
    let blocked = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(blocked.len(), 3);
    assert!(
        blocked
            .iter()
            .any(|operation| operation.operation().key.as_str() == "after-decision")
    );
    assert!(
        blocked
            .iter()
            .all(|operation| operation.action() == &RecoveryAction::SettleFailureBeforeEffect)
    );
    for operation in blocked {
        transaction.settle_failure_before_effect(operation.operation(), ability(false))?;
    }

    assert_eq!(
        transaction.summary().terminal(),
        Some(TerminalResult::SettledFailure)
    );
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    assert!(
        reopened
            .schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn deep_failure_propagation_is_iterative_and_work_bounded() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = RuntimeFixture::with_plan(checked_deep_dependent_plan(4_096))?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;

    reject_and_settle(&mut transaction, &scoped("step-00000"))?;
    let maximum_work = NonZeroUsize::new(7).ok_or("positive batch")?;
    let blocked = transaction.schedule_ready(maximum_work)?;

    assert_eq!(blocked.len(), maximum_work.get());
    assert_eq!(blocked[0].operation().key.as_str(), "step-00001");
    assert_eq!(blocked[6].operation().key.as_str(), "step-00007");
    assert!(
        blocked
            .iter()
            .all(|operation| operation.action() == &RecoveryAction::SettleFailureBeforeEffect)
    );
    Ok(())
}

#[test]
fn scheduler_persists_selected_merge_output_for_downstream_inputs()
-> Result<(), Box<dyn std::error::Error>> {
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
fn planned_provider_chain_requires_each_durable_assignment_before_use()
-> Result<(), Box<dyn std::error::Error>> {
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
    assert!(
        transaction
            .schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn planned_provider_admission_rejects_missing_live_incarnation_before_effect()
-> Result<(), Box<dyn std::error::Error>> {
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
fn reopened_indeterminate_effect_authorizes_only_reconciliation_and_preserves_budget()
-> Result<(), Box<dyn std::error::Error>> {
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
fn transaction_accepts_durably_enforced_nonzero_retry_backoff()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = recovery_plan_fixture(1)
        .validate()
        .expect("nonzero backoff is a valid checked plan contract");
    let fixture = RuntimeFixture::with_plan(plan)?;
    let mut store = TestStore;

    let transaction = fixture.open(&mut store)?;

    assert_eq!(
        transaction.next_action(fixture.operation())?,
        RecoveryAction::Admit
    );
    Ok(())
}

#[test]
fn retry_backoff_survives_reopen_and_charges_waited_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = recovery_plan_fixture(50)
        .validate()
        .expect("delayed recovery plan must validate");
    let fixture = RuntimeFixture::with_plan(plan)?;
    let mut store = TestStore;
    let clock = SettableClock::default();
    let mut catalog = TestCatalog::default();
    let mut policy = RecordingPolicy::default();
    let mut adapter = RecoveryAdapter::default();
    let mut transaction = fixture.open(&mut store)?;
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &clock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Indeterminate
    );
    drop(admitted);
    drop(transaction);
    let mut transaction = fixture.open(&mut store)?;
    let recovery = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &recovery,
            &mut adapter,
            &mut policy,
            &clock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::SafeToRetry
    );
    transaction
        .release_admitted::<RecoveryAdapter, _, _>(recovery, &mut catalog, &clock)
        .map_err(release_error)?;

    clock.set(u64::MAX);
    let overflow = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .expect_err("an unrepresentable eligibility point must fail closed");
    assert!(matches!(
        overflow.error(),
        AdmissionError::RetryBackoffOverflow
    ));
    clock.set(100);
    let pending = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .expect_err("the persisted delay must reject an early retry");
    assert!(matches!(
        pending.error(),
        AdmissionError::RetryBackoffPending {
            remaining_millis: 50
        }
    ));
    drop(transaction);

    clock.set(99);
    let mut reopened = fixture.open(&mut store)?;
    let backward = reopened
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .expect_err("a backward trusted clock must fail closed");
    assert!(matches!(
        backward.error(),
        AdmissionError::RetryClockMovedBackward
    ));
    clock.set(149);
    let pending = reopened
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .expect_err("reopen must preserve remaining delay");
    assert!(matches!(
        pending.error(),
        AdmissionError::RetryBackoffPending {
            remaining_millis: 1
        }
    ));
    clock.set(150);
    let retry = reopened
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    assert_eq!(retry.attempt().get(), 2);
    assert_eq!(retry.elapsed_millis(), 50);
    Ok(())
}

#[test]
fn retry_backoff_exhaustion_settles_before_another_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let mut plan_fixture = recovery_plan_fixture(50);
    plan_fixture.effect_plan.operations[0]
        .deadline
        .attempt_timeout_millis = NonZeroU64::new(10).ok_or("positive attempt timeout")?;
    plan_fixture.effect_plan.operations[0]
        .deadline
        .total_recovery_millis = NonZeroU64::new(40).ok_or("positive recovery timeout")?;
    plan_fixture.refresh_commitments();
    let plan = plan_fixture
        .validate()
        .expect("bounded delayed recovery plan must validate");
    let fixture = RuntimeFixture::with_plan(plan)?;
    let mut store = TestStore;
    let clock = SettableClock::default();
    let mut catalog = TestCatalog::default();
    let mut policy = RecordingPolicy::default();
    let mut adapter = RecoveryAdapter::default();
    let mut transaction = fixture.open(&mut store)?;
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
    drop(admitted);
    drop(transaction);

    let mut transaction = fixture.open(&mut store)?;
    let recovery = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    transaction.drive_admitted(
        &recovery,
        &mut adapter,
        &mut policy,
        &clock,
        &CancellationToken::default(),
    )?;
    transaction
        .release_admitted::<RecoveryAdapter, _, _>(recovery, &mut catalog, &clock)
        .map_err(release_error)?;
    let pending = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .expect_err("the delay must be persisted before eligibility");
    assert!(matches!(
        pending.error(),
        AdmissionError::RetryBackoffPending { .. }
    ));

    clock.set(50);
    let exhausted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .expect_err("elapsed backoff must exhaust the recovery budget");
    assert!(matches!(
        exhausted.error(),
        AdmissionError::DeadlineExceeded
    ));
    assert_eq!(
        transaction.next_action(fixture.operation())?,
        RecoveryAction::SettleFailureBeforeEffect
    );
    Ok(())
}

#[test]
fn declared_compensation_is_preflighted_before_primary_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let adapter = TestAdapter::without_compensation_support();

    let failure = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .expect_err("primary admission must require its declared compensation capability");
    assert!(matches!(
        failure.error(),
        AdmissionError::AdapterMismatch(InvocationPurpose::Compensate)
    ));
    assert_eq!(catalog.acquire_calls, 0);
    assert!(matches!(
        transaction.history(&operation)?.state(),
        OperationState::Pending
    ));
    Ok(())
}

#[test]
fn explicit_compensation_preserves_original_evidence_and_has_a_separate_outcome()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    complete(&mut transaction, &operation)?;

    transaction.request_compensation(&operation, ability(true))?;
    let history = transaction.history(&operation)?;
    assert!(history.original_completion().is_some());
    assert!(history.compensation_state().is_some());

    let mut catalog = TestCatalog::default();
    let mut policy = RecordingPolicy::default();
    let mut adapter = TestAdapter::valid();
    let admitted = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    assert_eq!(admitted.invocation_purpose(), InvocationPurpose::Compensate);
    assert!(policy.purposes.contains(&InvocationPurpose::Compensate));
    assert!(
        policy
            .purposes
            .contains(&InvocationPurpose::ReconcileCompensation)
    );
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );
    transaction
        .release_admitted::<TestAdapter, _, _>(admitted, &mut catalog, &TestClock)
        .map_err(release_error)?;

    let history = transaction.history(&operation)?;
    assert!(history.original_completion().is_some());
    assert!(matches!(
        history.compensation_state(),
        Some(crate::execution::CompensationState::Completed { .. })
    ));
    let summary = transaction.summary();
    let compensated = summary
        .operations()
        .iter()
        .find(|item| &item.operation().operation == &operation)
        .ok_or("compensated operation summary missing")?;
    assert_eq!(compensated.status(), OperationStatus::Compensated);
    Ok(())
}

#[test]
fn primary_token_is_stale_after_compensation_admission() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let mut primary = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &primary,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );

    let resources = primary.resources().cloned().collect();
    transaction.append(ExecutionEventKind::ResourcesReleased {
        transaction: transaction.transaction().clone(),
        operation: primary.operation_id().clone(),
        resources,
        elapsed_millis: transaction.history(&operation)?.elapsed_millis(),
    })?;
    primary.release_live_reservation();
    transaction.request_compensation(&operation, ability(true))?;
    let _compensation = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;

    let error = transaction
        .drive_admitted(
            &primary,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )
        .expect_err("a primary token must not dispatch compensation");
    assert!(matches!(error, ExecutionError::StaleAdmission));
    assert_eq!(adapter.compensate_calls, 0);
    Ok(())
}

#[test]
fn compensation_token_is_stale_after_reconciliation_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    complete(&mut transaction, &operation)?;
    transaction.request_compensation(&operation, ability(true))?;

    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = RecoveryAdapter::default();
    let mut compensation = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &compensation,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Indeterminate
    );
    compensation.release_live_reservation();
    let reconciliation = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;

    let error = transaction
        .drive_admitted(
            &compensation,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )
        .expect_err("a compensation token must not dispatch reconciliation");
    assert!(matches!(error, ExecutionError::StaleAdmission));
    assert_eq!(adapter.compensate_calls, 1);
    assert_eq!(adapter.compensation_reconciliation_calls, 0);

    assert_eq!(
        transaction.drive_admitted(
            &reconciliation,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );
    assert_eq!(adapter.compensation_reconciliation_calls, 1);
    Ok(())
}

#[test]
fn ambiguous_compensation_reopens_into_compensation_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    complete(&mut transaction, &operation)?;
    transaction.request_compensation(&operation, ability(true))?;

    let mut catalog = TestCatalog::default();
    let mut policy = RecordingPolicy::default();
    let mut adapter = RecoveryAdapter::default();
    let admitted = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Indeterminate
    );
    drop(admitted);
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    let reconciliation = reopened
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    assert_eq!(
        reconciliation.invocation_purpose(),
        InvocationPurpose::ReconcileCompensation
    );
    assert_eq!(
        reopened.drive_admitted(
            &reconciliation,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );
    assert_eq!(adapter.compensation_reconciliation_calls, 1);
    reopened
        .release_admitted::<RecoveryAdapter, _, _>(reconciliation, &mut catalog, &TestClock)
        .map_err(release_error)?;
    assert_eq!(reopened.next_action(&operation)?, RecoveryAction::None);
    Ok(())
}

#[test]
fn compensation_deadline_before_intent_is_durable_and_retains_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    complete(&mut transaction, &operation)?;
    transaction.request_compensation(&operation, ability(true))?;

    let clock = SettableClock::default();
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let admitted = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &clock)
        .map_err(admission_error)?;
    assert!(admitted.resources().next().is_some());
    clock.set(
        fixture
            .plan
            .operation(&operation)
            .ok_or("compensation operation missing")?
            .deadline
            .total_recovery_millis
            .get(),
    );

    let error = transaction
        .drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &clock,
            &CancellationToken::default(),
        )
        .expect_err("deadline exhaustion before compensation intent must be reported");
    assert!(
        matches!(error, ExecutionError::DeadlineBeforeIntent),
        "unexpected compensation deadline error: {error:?}"
    );
    let history = transaction.history(&operation)?;
    assert!(matches!(
        history.compensation_state(),
        Some(crate::execution::CompensationState::InterventionRequired {
            reason: crate::execution::CompensationInterventionReason::DeadlineBeforeIntent,
            evidence: None,
        })
    ));
    assert!(!history.resources_released());
    assert_eq!(catalog.release_calls, 0);
    let summary = transaction.summary();
    let operation = summary
        .operations()
        .iter()
        .find(|item| item.operation() == history.operation_id())
        .ok_or("intervention operation summary missing")?;
    assert_eq!(operation.status(), OperationStatus::InterventionRequired);
    Ok(())
}

#[test]
fn scheduler_durably_classifies_an_exhausted_compensation_request()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    complete(&mut transaction, &operation)?;
    let operation_id = transaction.history(&operation)?.operation_id().clone();
    let deadline = fixture
        .plan
        .operation(&operation)
        .ok_or("compensation operation missing")?
        .deadline
        .total_recovery_millis
        .get();
    transaction.append(ExecutionEventKind::CompensationRequested {
        transaction: fixture.transaction.clone(),
        operation: operation_id,
        reason: ability(true),
        elapsed_millis: deadline,
    })?;

    let ready = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert!(ready.iter().any(|item| {
        item.operation() == &operation
            && item.action() == &RecoveryAction::CompensationInterventionRequired
    }));
    assert!(matches!(
        transaction.history(&operation)?.compensation_state(),
        Some(crate::execution::CompensationState::InterventionRequired {
            reason: crate::execution::CompensationInterventionReason::DeadlineBeforeIntent,
            evidence: None,
        })
    ));
    let summary = transaction.summary();
    let operation = summary
        .operations()
        .iter()
        .find(|item| item.operation().operation == scoped("observe"))
        .ok_or("intervention operation summary missing")?;
    assert_eq!(operation.status(), OperationStatus::InterventionRequired);
    Ok(())
}

#[test]
fn compensation_request_rejects_a_previously_admitted_downstream_consumer()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let producer = scoped("observe");
    let consumer = scoped("consume");
    complete(&mut transaction, &producer)?;

    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let admitted = transaction
        .admit(&consumer, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    let error = transaction
        .request_compensation(&producer, ability(true))
        .expect_err("a live success-consuming dependent must block compensation");
    assert!(matches!(
        error,
        crate::execution::TransactionError::CompensationDependentProgressed
    ));

    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );
    assert_eq!(adapter.execute_calls, 1);
    Ok(())
}

#[test]
fn replay_rejects_compensation_after_a_dependent_consumed_success()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let producer = scoped("observe");
    let consumer = scoped("consume");
    complete(&mut transaction, &producer)?;

    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let adapter = TestAdapter::valid();
    let admitted = transaction
        .admit(&consumer, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    drop(admitted);
    drop(transaction);

    let mut journal =
        FileJournal::<ExecutionEvent>::open(fixture.journal_path(), JournalLimits::default())?
            .journal;
    journal.append(&ExecutionEvent::new(
        ExecutionEventKind::CompensationRequested {
            transaction: fixture.transaction.clone(),
            operation: OperationId {
                plan: fixture.plan.id(),
                operation: producer,
            },
            reason: ability(true),
            elapsed_millis: 0,
        },
    ))?;
    drop(journal);

    let error = fixture
        .open(&mut store)
        .expect_err("replay must reject a late compensation request");
    assert!(matches!(
        error,
        crate::execution::TransactionError::InvalidHistory { .. }
    ));
    Ok(())
}

#[test]
fn terminal_transaction_requires_a_separately_rooted_compensation_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_terminal_compensation_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    complete(&mut transaction, fixture.operation())?;

    let error = transaction
        .request_compensation(fixture.operation(), ability(true))
        .expect_err("terminal journals must not be amended behind their terminal marker");
    assert!(matches!(
        error,
        crate::execution::TransactionError::CompensationAfterTerminal
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

fn checked_compensatable_dependent_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = recovery_plan_fixture(0);
    let mut producer = fixture.effect_plan.operations[0].clone();
    producer.recovery.retry = RetryPolicy::Disabled;
    producer.recovery.compensate = Some(MethodReference {
        interface: producer.interface.clone(),
        method: producer.method.clone(),
    });
    let mut consumer = producer.clone();
    consumer.key = scoped("consume");
    consumer.recovery.compensate = None;
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
        .expect("compensatable dependent fixture must pass production validation")
}

fn checked_failure_then_ordering_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = plan_fixture();
    let template = fixture.effect_plan.operations[0].clone();
    fixture.effect_plan.operations = ["after", "blocked", "first"]
        .map(|name| {
            let mut operation = template.clone();
            operation.key = scoped(name);
            operation
        })
        .into();
    fixture.effect_plan.edges = vec![
        DependencyEdge {
            from: PlanNodeKey::Operation {
                key: scoped("first"),
            },
            to: PlanNodeKey::Operation {
                key: scoped("blocked"),
            },
            kind: DependencyKind::RequiredSuccess,
        },
        DependencyEdge {
            from: PlanNodeKey::Operation {
                key: scoped("blocked"),
            },
            to: PlanNodeKey::Operation {
                key: scoped("after"),
            },
            kind: DependencyKind::OrderingOnly,
        },
    ];
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("failure-ordering runtime fixture must pass production validation")
}

fn checked_deep_dependent_plan(length: usize) -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = plan_fixture();
    let template = fixture.effect_plan.operations[0].clone();
    let keys = (0..length)
        .map(|index| scoped(&format!("step-{index:05}")))
        .collect::<Vec<_>>();

    fixture.effect_plan.operations = keys
        .iter()
        .map(|key| {
            let mut operation = template.clone();
            operation.key = key.clone();
            operation
        })
        .collect();
    fixture.effect_plan.edges = keys
        .windows(2)
        .map(|pair| DependencyEdge {
            from: PlanNodeKey::Operation {
                key: pair[0].clone(),
            },
            to: PlanNodeKey::Operation {
                key: pair[1].clone(),
            },
            kind: DependencyKind::RequiredSuccess,
        })
        .collect();
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("deep runtime fixture must pass production validation")
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

fn checked_terminal_compensation_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = recovery_plan_fixture(0);
    let operation = &mut fixture.effect_plan.operations[0];
    operation.recovery.retry = RetryPolicy::Disabled;
    operation.recovery.compensate = Some(MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    });
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("terminal compensation fixture must pass production validation")
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

fn checked_failed_decision_ordering_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = branch_plan_fixture();
    let mut after_decision = fixture.effect_plan.operations[0].clone();
    after_decision.key = scoped("after-decision");
    after_decision.branch_context.clear();
    fixture.effect_plan.operations.push(after_decision);
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.edges.push(DependencyEdge {
        from: PlanNodeKey::Decision {
            key: scoped("choose"),
        },
        to: PlanNodeKey::Operation {
            key: scoped("after-decision"),
        },
        kind: DependencyKind::OrderingOnly,
    });
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("failed-decision ordering fixture must pass production validation")
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
    reject_before_effect: bool,
    supports_compensation: bool,
    execute_calls: usize,
    compensate_calls: usize,
}

impl TestAdapter {
    fn with_output(output: AbilityValue) -> Self {
        Self {
            outputs: BTreeMap::from([(key("ready"), output)]),
            fail_preparation: false,
            reject_before_effect: false,
            supports_compensation: true,
            execute_calls: 0,
            compensate_calls: 0,
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
            supports_compensation: true,
            execute_calls: 0,
            compensate_calls: 0,
        }
    }

    fn preparation_failure() -> Self {
        Self {
            outputs: BTreeMap::new(),
            fail_preparation: true,
            reject_before_effect: false,
            supports_compensation: true,
            execute_calls: 0,
            compensate_calls: 0,
        }
    }

    fn rejected_before_effect() -> Self {
        Self {
            outputs: BTreeMap::new(),
            fail_preparation: false,
            reject_before_effect: true,
            supports_compensation: true,
            execute_calls: 0,
            compensate_calls: 0,
        }
    }

    fn without_compensation_support() -> Self {
        Self {
            supports_compensation: false,
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
        } else {
            EffectDisposition::Completed(record)
        }
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

    fn compensate(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> Option<EffectDisposition<Self::Completion, Self::Observation>> {
        self.compensate_calls += 1;
        Some(EffectDisposition::Completed(TestRecord {
            evidence: ability(true),
            outputs: self.outputs.clone(),
        }))
    }

    fn reconcile_compensation(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> Option<ReconcileDisposition<Self::Completion, Self::Observation>> {
        Some(ReconcileDisposition::Completed(TestRecord {
            evidence: ability(true),
            outputs: self.outputs.clone(),
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
    compensate_calls: usize,
    compensation_reconciliation_calls: usize,
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

    fn supports_compensation(&self) -> bool {
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

    fn compensate(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> Option<EffectDisposition<Self::Completion, Self::Observation>> {
        self.compensate_calls += 1;
        Some(EffectDisposition::Indeterminate(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::new(),
        }))
    }

    fn reconcile_compensation(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> Option<ReconcileDisposition<Self::Completion, Self::Observation>> {
        self.compensation_reconciliation_calls += 1;
        Some(ReconcileDisposition::Completed(TestRecord {
            evidence: ability(true),
            outputs: BTreeMap::from([(key("ready"), ability(true))]),
        }))
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
