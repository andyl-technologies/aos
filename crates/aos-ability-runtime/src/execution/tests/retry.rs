//! Durable retry timing and budget integration tests.

use super::*;

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
    let mut adapter = TestAdapter::recovery();
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
        .release_admitted::<TestAdapter, _, _>(recovery, &mut catalog, &clock)
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
    let mut adapter = TestAdapter::recovery();
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
        .release_admitted::<TestAdapter, _, _>(recovery, &mut catalog, &clock)
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
