//! Dependency, branch, merge, and provider scheduling integration tests.

use super::*;

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

    let snapshot = CheckedExecutionJournalSnapshot::read(
        &fixture.plan,
        fixture.journal_path(),
        JournalLimits::default(),
    )?;
    assert_eq!(snapshot.terminal(), Some(TerminalResult::SettledFailure));

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
fn effect_intent_replay_excludes_a_dependent_settled_before_effect()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_dependent_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let producer = scoped("observe");
    let dependent = scoped("consume");

    reject_and_settle(&mut transaction, &producer)?;
    let ready = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].operation(), &dependent);
    transaction.settle_failure_before_effect(&dependent, ability(false))?;

    assert_eq!(
        transaction
            .operations_reaching_effect_intent()
            .cloned()
            .collect::<Vec<_>>(),
        [OperationId {
            plan: fixture.plan.id(),
            operation: producer,
        }]
    );
    assert_eq!(
        transaction
            .summary()
            .operations()
            .iter()
            .find(|summary| summary.operation().operation == dependent)
            .map(|summary| summary.status()),
        Some(OperationStatus::SettledFailure)
    );
    Ok(())
}

#[test]
fn effect_intent_replay_excludes_an_operation_skipped_before_effect()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_branch_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let selector = scoped("observe");
    let skipped = scoped("false-step");

    complete(&mut transaction, &selector)?;
    let selected = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].operation().key.as_str(), "true-step");

    assert_eq!(
        transaction
            .operations_reaching_effect_intent()
            .cloned()
            .collect::<Vec<_>>(),
        [OperationId {
            plan: fixture.plan.id(),
            operation: selector,
        }]
    );
    assert_eq!(
        transaction
            .summary()
            .operations()
            .iter()
            .find(|summary| summary.operation().operation == skipped)
            .map(|summary| summary.status()),
        Some(OperationStatus::Skipped)
    );
    Ok(())
}

#[test]
fn effect_intent_replay_remains_monotonic_through_failure_settlement_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let expected = OperationId {
        plan: fixture.plan.id(),
        operation: fixture.operation().clone(),
    };
    let mut transaction = fixture.open(&mut store)?;

    reject_and_settle(&mut transaction, fixture.operation())?;
    assert_eq!(
        transaction
            .operations_reaching_effect_intent()
            .cloned()
            .collect::<Vec<_>>(),
        [expected.clone()]
    );
    drop(transaction);

    let snapshot = CheckedExecutionJournalSnapshot::read(
        &fixture.plan,
        fixture.journal_path(),
        JournalLimits::default(),
    )?;
    let intent_sequence = snapshot
        .records()
        .iter()
        .position(|record| {
            matches!(
                record.body().body(),
                ExecutionEventKind::EffectIntent { .. }
            )
        })
        .ok_or("effect intent record missing")?;
    let settlement_sequence = snapshot
        .records()
        .iter()
        .position(|record| {
            matches!(
                record.body().body(),
                ExecutionEventKind::OperationSettledFailure { .. }
            )
        })
        .ok_or("failure settlement record missing")?;
    assert!(intent_sequence < settlement_sequence);

    let reopened = fixture.open(&mut store)?;
    assert_eq!(
        reopened
            .operations_reaching_effect_intent()
            .cloned()
            .collect::<Vec<_>>(),
        [expected]
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
fn reopened_release_rejects_a_reassigned_provider_incarnation()
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
    let assignment_c = provider_assignment(&fixture.plan, "c", "planned-c-live")?;
    complete_with_expected_provider(
        &mut transaction,
        second[0].operation(),
        &assignment_b,
        assignment_value(&assignment_c)?,
    )?;
    let third = transaction.schedule_ready(NonZeroUsize::new(8).ok_or("positive batch")?)?;
    let operation = third[0].operation().clone();
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::with_output(assignment_value(&assignment_c)?);
    let admitted = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    transaction.drive_admitted(
        &admitted,
        &mut adapter,
        &mut policy,
        &TestClock,
        &CancellationToken::default(),
    )?;
    drop(admitted);
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    let mut reassigned = TestCatalog {
        omit_expected_incarnation: true,
        ..TestCatalog::default()
    };
    let mut release_policy = RecordingPolicy::default();
    let failure = reopened
        .admit(
            &operation,
            &adapter,
            &mut reassigned,
            &mut release_policy,
            &TestClock,
        )
        .expect_err("reopened cleanup must not acquire a reassigned resource");

    assert!(matches!(
        failure.error(),
        AdmissionError::CatalogEvidenceMismatch(_)
    ));
    assert!(release_policy.purposes.is_empty());
    assert_eq!(reassigned.acquire_calls, 1);
    assert_eq!(reassigned.release_calls, 1);
    assert_eq!(
        reopened.next_action(&operation)?,
        RecoveryAction::ReleaseResources
    );
    Ok(())
}
