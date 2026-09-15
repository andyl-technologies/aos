//! Transaction opening, ownership, and resource-lifecycle integration tests.

use super::*;

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
    assert_eq!(snapshot.terminal(), Some(TerminalResult::Succeeded));
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
    assert_eq!(snapshot.terminal(), None);
    assert_eq!(
        std::fs::metadata(fixture.journal_path())?.len(),
        length_before
    );

    let wrong_plan = checked_lifecycle_effect_plan();
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
fn reopened_settled_operation_reacquires_handles_only_for_release()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::valid();
    let clock = TestClock;
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
        ExecutionStep::Completed
    );
    drop(admitted);
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    assert_eq!(
        reopened.next_action(fixture.operation())?,
        RecoveryAction::ReleaseResources
    );
    let mut release_policy = RecordingPolicy::default();
    let release = reopened
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut release_policy,
            &clock,
        )
        .map_err(admission_error)?;

    assert!(release_policy.purposes.is_empty());
    reopened
        .release_admitted::<TestAdapter, _, _>(release, &mut catalog, &clock)
        .map_err(release_error)?;
    assert_eq!(
        reopened.next_action(fixture.operation())?,
        RecoveryAction::None
    );
    assert_eq!(catalog.acquire_calls, 2);
    assert_eq!(catalog.release_calls, 1);
    Ok(())
}

#[test]
fn scheduler_durably_stops_when_reconciliation_is_unsupported()
-> Result<(), Box<dyn std::error::Error>> {
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

    let ready = transaction.schedule_ready(NonZeroUsize::MIN)?;
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].action(), &RecoveryAction::InterventionRequired);
    assert!(matches!(
        transaction.history(fixture.operation())?.state(),
        OperationState::RuntimeInterventionRequired {
            attempt: NonZeroU32::MIN,
            reason: OperationInterventionReason::ReconciliationUnsupported,
        }
    ));
    assert!(
        !transaction
            .history(fixture.operation())?
            .resources_released()
    );
    assert_eq!(
        transaction.summary().terminal(),
        Some(TerminalResult::InterventionRequired)
    );

    let journal_length_before = std::fs::metadata(fixture.journal_path())?.len();
    transaction.record_unsupported_reconciliation(&admitted, &TestClock)?;
    assert_eq!(
        std::fs::metadata(fixture.journal_path())?.len(),
        journal_length_before
    );

    drop(admitted);
    drop(transaction);
    let mut reopened = fixture.open(&mut store)?;
    let journal_length_before = std::fs::metadata(fixture.journal_path())?.len();
    assert!(matches!(
        reopened.history(fixture.operation())?.state(),
        OperationState::RuntimeInterventionRequired {
            reason: OperationInterventionReason::ReconciliationUnsupported,
            ..
        }
    ));
    let ready = reopened.schedule_ready(NonZeroUsize::MIN)?;
    assert_eq!(ready[0].action(), &RecoveryAction::InterventionRequired);
    assert_eq!(
        std::fs::metadata(fixture.journal_path())?.len(),
        journal_length_before
    );
    Ok(())
}

#[test]
fn unsupported_cancellation_is_durable_and_retains_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::new()?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let adapter = TestAdapter::valid();
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &TestClock,
        )
        .map_err(admission_error)?;

    transaction.record_unsupported_cancellation(&admitted, &TestClock)?;

    let journal_length = std::fs::metadata(fixture.journal_path())?.len();
    transaction.record_unsupported_cancellation(&admitted, &TestClock)?;
    assert_eq!(
        std::fs::metadata(fixture.journal_path())?.len(),
        journal_length
    );

    let history = transaction.history(fixture.operation())?;
    assert!(matches!(
        history.state(),
        OperationState::RuntimeInterventionRequired {
            attempt: NonZeroU32::MIN,
            reason: OperationInterventionReason::CancellationUnsupported,
        }
    ));
    assert!(!history.resources_released());
    assert_eq!(catalog.release_calls, 0);
    assert_eq!(
        transaction.summary().terminal(),
        Some(TerminalResult::InterventionRequired)
    );
    drop(admitted);
    drop(transaction);
    let reopened = fixture.open(&mut store)?;
    assert!(matches!(
        reopened.history(fixture.operation())?.state(),
        OperationState::RuntimeInterventionRequired {
            reason: OperationInterventionReason::CancellationUnsupported,
            ..
        }
    ));
    assert_eq!(
        reopened.summary().terminal(),
        Some(TerminalResult::InterventionRequired)
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
