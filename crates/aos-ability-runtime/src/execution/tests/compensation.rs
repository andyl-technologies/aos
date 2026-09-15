//! Explicit compensation and compensation-recovery integration tests.

use super::*;

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
    let mut adapter = TestAdapter::recovery();
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
    let mut adapter = TestAdapter::recovery();
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
        .release_admitted::<TestAdapter, _, _>(reconciliation, &mut catalog, &TestClock)
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
