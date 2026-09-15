//! Crash recovery and current-authority integration tests.

use super::*;

#[test]
fn reopened_indeterminate_effect_authorizes_only_reconciliation_and_preserves_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
    let mut store = TestStore;
    let clock = SettableClock::default();
    let mut catalog = TestCatalog::default();
    let mut initial_policy = RecordingPolicy::default();
    let mut adapter = TestAdapter::recovery();
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
        [
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Effect,
        ]
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

    let snapshot = CheckedExecutionJournalSnapshot::read(
        &fixture.plan,
        fixture.journal_path(),
        JournalLimits::default(),
    )?;
    assert_eq!(snapshot.terminal(), None);

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
    assert_eq!(
        recovery_policy.purposes,
        [InvocationPurpose::Reconcile, InvocationPurpose::Reconcile]
    );

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
        [
            InvocationPurpose::Reconcile,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Reconcile,
        ]
    );
    assert_eq!(adapter.reconciliation_elapsed, [150]);
    assert_eq!(recovered.elapsed_millis(), 150);

    recovered
        .release_admitted::<TestAdapter, _, _>(recovered_token, &mut catalog, &clock)
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
fn boundary_halt_after_real_effect_reopens_into_fresh_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
    let mut store = TestStore;
    let mut catalog = TestCatalog::default();
    let mut policy = RecordingPolicy::default();
    let publication = fixture.directory.path().join("published.json");
    let mut adapter = PublishingAdapter::new(publication.clone());
    let mut transaction = fixture.open(&mut store)?;
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &TestClock,
        )
        .map_err(admission_error)?;
    let transaction_id = admitted.transaction().clone();
    let operation_id = admitted.operation_id().clone();
    let mut observer = HaltAfterEffectReturn::default();

    let error = transaction
        .drive_admitted_with_observer(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
            &mut observer,
        )
        .expect_err("the boundary observer must halt before outcome persistence");
    assert!(matches!(
        error,
        ExecutionError::BoundaryHalt(crate::execution::Boundary::EffectReturned)
    ));
    assert!(publication.is_file());
    assert_eq!(adapter.execute_calls, 1);
    assert_eq!(
        observer.effect_returned,
        Some((transaction_id, operation_id))
    );
    drop(admitted);
    drop(transaction);

    let recovered_adapter =
        reconcile_published_effect(&fixture, &mut store, &mut catalog, &mut policy, publication)?;
    assert_eq!(adapter.execute_calls, 1);
    assert_eq!(recovered_adapter.execute_calls, 0);
    assert_eq!(recovered_adapter.reconcile_calls, 1);
    Ok(())
}

#[test]
fn boundary_source_error_survives_and_reopens_into_fresh_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
    let mut store = TestStore;
    let mut catalog = TestCatalog::default();
    let mut policy = RecordingPolicy::default();
    let publication = fixture.directory.path().join("published.json");
    let mut adapter = PublishingAdapter::new(publication.clone());
    let mut transaction = fixture.open(&mut store)?;
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &TestClock,
        )
        .map_err(admission_error)?;
    let mut observer = ErrorAfterEffectReturn;

    let error = transaction
        .drive_admitted_with_observer(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
            &mut observer,
        )
        .expect_err("the injected observer error must fail closed");
    let ExecutionError::BoundaryObservation(source) = error else {
        return Err("observer source error lost its execution classification".into());
    };
    assert!(source.downcast_ref::<InjectedBoundaryError>().is_some());
    assert!(publication.is_file());
    assert_eq!(adapter.execute_calls, 1);
    drop(admitted);
    drop(transaction);

    let recovered_adapter =
        reconcile_published_effect(&fixture, &mut store, &mut catalog, &mut policy, publication)?;
    assert_eq!(adapter.execute_calls, 1);
    assert_eq!(recovered_adapter.execute_calls, 0);
    assert_eq!(recovered_adapter.reconcile_calls, 1);
    Ok(())
}

#[test]
fn role_revocation_before_acquisition_is_typed_and_never_dispatches()
-> Result<(), Box<dyn std::error::Error>> {
    for role in runtime_authority_roles() {
        let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
        let mut store = TestStore;
        let mut transaction = fixture.open(&mut store)?;
        let mut catalog = TestCatalog::default();
        let revoked = Rc::new(Cell::new(None));
        let mut policy = RoleRevocablePolicy {
            revoked: Rc::clone(&revoked),
        };
        let adapter = TestAdapter::recovery();
        let mut observer = RevokeRoleAtBoundary {
            revoked,
            role,
            boundary: crate::execution::Boundary::BeforeResourceAcquisition,
        };

        let failure = transaction
            .admit_with_observer(
                fixture.operation(),
                &adapter,
                &mut catalog,
                &mut policy,
                &TestClock,
                &mut observer,
            )
            .expect_err("role revocation must reject admission");
        assert_authority_rejection(
            failure.error(),
            role,
            AuthorityCheckBoundary::BeforeResourceAcquisition,
        )?;
        assert_eq!(adapter.execute_calls, 0);
        assert_eq!(catalog.acquire_calls, 0);
        assert_eq!(catalog.release_calls, 0);
        drop(failure);
        drop(transaction);

        assert_durable_authority_rejection(
            &fixture,
            role,
            AuthorityCheckBoundary::BeforeResourceAcquisition,
        )?;
    }
    Ok(())
}

#[test]
fn role_revocation_after_acquisition_releases_resources_without_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    for role in runtime_authority_roles() {
        let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
        let mut store = TestStore;
        let mut transaction = fixture.open(&mut store)?;
        let mut catalog = TestCatalog::default();
        let revoked = Rc::new(Cell::new(None));
        let mut policy = RoleRevocablePolicy {
            revoked: Rc::clone(&revoked),
        };
        let adapter = TestAdapter::recovery();
        let mut observer = RevokeRoleAtBoundary {
            revoked,
            role,
            boundary: crate::execution::Boundary::ResourcesAcquired,
        };

        let failure = transaction
            .admit_with_observer(
                fixture.operation(),
                &adapter,
                &mut catalog,
                &mut policy,
                &TestClock,
                &mut observer,
            )
            .expect_err("post-acquisition revocation must reject admission");
        assert_authority_rejection(
            failure.error(),
            role,
            AuthorityCheckBoundary::AfterResourceAcquisition,
        )?;
        assert_eq!(adapter.execute_calls, 0);
        assert_eq!(catalog.acquire_calls, 1);
        assert_eq!(catalog.release_calls, 1);
        drop(failure);
        drop(transaction);

        assert_durable_authority_rejection(
            &fixture,
            role,
            AuthorityCheckBoundary::AfterResourceAcquisition,
        )?;
    }
    Ok(())
}

#[test]
fn role_revocation_at_final_dispatch_is_durable_and_never_invokes_primary()
-> Result<(), Box<dyn std::error::Error>> {
    for role in runtime_authority_roles() {
        let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
        let mut store = TestStore;
        let mut transaction = fixture.open(&mut store)?;
        let mut catalog = TestCatalog::default();
        let revoked = Rc::new(Cell::new(None));
        let mut policy = RoleRevocablePolicy {
            revoked: Rc::clone(&revoked),
        };
        let mut adapter = TestAdapter::recovery();
        let admitted = transaction
            .admit(
                fixture.operation(),
                &adapter,
                &mut catalog,
                &mut policy,
                &TestClock,
            )
            .map_err(admission_error)?;
        let mut observer = RevokeRoleAtBoundary {
            revoked,
            role,
            boundary: crate::execution::Boundary::FinalDispatch,
        };

        let error = transaction
            .drive_admitted_with_observer(
                &admitted,
                &mut adapter,
                &mut policy,
                &TestClock,
                &CancellationToken::default(),
                &mut observer,
            )
            .expect_err("final dispatch revocation must fail closed");
        let ExecutionError::DispatchAdmission(error) = error else {
            return Err("final dispatch rejection lost its admission classification".into());
        };
        assert_authority_rejection(&error, role, AuthorityCheckBoundary::FinalDispatch)?;
        assert_eq!(adapter.execute_calls, 0);
        assert!(matches!(
            transaction.next_action(fixture.operation())?,
            RecoveryAction::ReleaseResources
        ));
        drop(admitted);
        drop(transaction);

        assert_durable_authority_rejection(&fixture, role, AuthorityCheckBoundary::FinalDispatch)?;
        let snapshot = CheckedExecutionJournalSnapshot::read(
            &fixture.plan,
            fixture.journal_path(),
            JournalLimits::default(),
        )?;
        assert!(snapshot.records().iter().any(|record| matches!(
            record.body().body(),
            ExecutionEventKind::EffectDispatchAborted {
                reason: crate::execution::DispatchAbortReason::AuthorityRejected,
                ..
            }
        )));
    }
    Ok(())
}

#[test]
fn revocation_after_effect_intent_prevents_external_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let revoked = Rc::new(Cell::new(false));
    let mut policy = RevocablePolicy::new(Rc::clone(&revoked));
    let mut adapter = TestAdapter::recovery();
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &TestClock,
        )
        .map_err(admission_error)?;
    let mut observer = RevokeAtBoundary::new(
        Rc::clone(&revoked),
        crate::execution::Boundary::EffectIntentDurable,
    );

    let error = transaction
        .drive_admitted_with_observer(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
            &mut observer,
        )
        .expect_err("revocation after durable intent must fail closed");

    assert_revoked_dispatch(error, InvocationPurpose::Effect)?;
    assert_eq!(adapter.execute_calls, 0);
    assert!(matches!(
        transaction.next_action(fixture.operation())?,
        RecoveryAction::ReleaseResources
    ));
    Ok(())
}

#[test]
fn revocation_after_reconciliation_intent_prevents_replay_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_recovery_plan())?;
    let mut store = TestStore;
    let mut catalog = TestCatalog::default();
    let mut adapter = TestAdapter::recovery();
    let mut transaction = fixture.open(&mut store)?;
    let mut initial_policy = AllowPolicy;
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut initial_policy,
            &TestClock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut initial_policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Indeterminate
    );
    drop(admitted);
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    let revoked = Rc::new(Cell::new(false));
    let mut policy = RevocablePolicy::new(Rc::clone(&revoked));
    let replay = reopened
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &TestClock,
        )
        .map_err(admission_error)?;
    assert_eq!(replay.invocation_purpose(), InvocationPurpose::Reconcile);
    let mut observer = RevokeAtBoundary::new(
        Rc::clone(&revoked),
        crate::execution::Boundary::ReconciliationIntentDurable,
    );

    let error = reopened
        .drive_admitted_with_observer(
            &replay,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
            &mut observer,
        )
        .expect_err("revocation after durable reconciliation intent must fail closed");

    assert_revoked_dispatch(error, InvocationPurpose::Reconcile)?;
    assert_eq!(adapter.execute_calls, 1);
    assert!(adapter.reconciliation_elapsed.is_empty());
    assert!(matches!(
        reopened.next_action(fixture.operation())?,
        RecoveryAction::ReconcileBeforeRetry { .. }
    ));
    Ok(())
}

#[test]
fn revocation_after_compensation_intent_prevents_external_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    complete(&mut transaction, &operation)?;
    transaction.request_compensation(&operation, ability(true))?;

    let mut catalog = TestCatalog::default();
    let revoked = Rc::new(Cell::new(false));
    let mut policy = RevocablePolicy::new(Rc::clone(&revoked));
    let mut adapter = TestAdapter::recovery();
    let admitted = transaction
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    assert_eq!(admitted.invocation_purpose(), InvocationPurpose::Compensate);
    let mut observer = RevokeAtBoundary::new(
        Rc::clone(&revoked),
        crate::execution::Boundary::EffectIntentDurable,
    );

    let error = transaction
        .drive_admitted_with_observer(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
            &mut observer,
        )
        .expect_err("revocation after durable compensation intent must fail closed");

    assert_revoked_dispatch(error, InvocationPurpose::Compensate)?;
    assert_eq!(adapter.compensate_calls, 0);
    assert_eq!(
        transaction.next_action(&operation)?,
        RecoveryAction::ReconcileCompensation
    );
    Ok(())
}

#[test]
fn revocation_after_compensation_reconciliation_intent_prevents_replay_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_compensatable_dependent_plan())?;
    let operation = scoped("observe");
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    complete(&mut transaction, &operation)?;
    transaction.request_compensation(&operation, ability(true))?;

    let mut catalog = TestCatalog::default();
    let mut adapter = TestAdapter::recovery();
    let mut initial_policy = AllowPolicy;
    let compensation = transaction
        .admit(
            &operation,
            &adapter,
            &mut catalog,
            &mut initial_policy,
            &TestClock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &compensation,
            &mut adapter,
            &mut initial_policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Indeterminate
    );
    drop(compensation);
    drop(transaction);

    let mut reopened = fixture.open(&mut store)?;
    let revoked = Rc::new(Cell::new(false));
    let mut policy = RevocablePolicy::new(Rc::clone(&revoked));
    let replay = reopened
        .admit(&operation, &adapter, &mut catalog, &mut policy, &TestClock)
        .map_err(admission_error)?;
    assert_eq!(
        replay.invocation_purpose(),
        InvocationPurpose::ReconcileCompensation
    );
    let mut observer = RevokeAtBoundary::new(
        Rc::clone(&revoked),
        crate::execution::Boundary::ReconciliationIntentDurable,
    );

    let error = reopened
        .drive_admitted_with_observer(
            &replay,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
            &mut observer,
        )
        .expect_err("revocation after durable compensation reconciliation must fail closed");

    assert_revoked_dispatch(error, InvocationPurpose::ReconcileCompensation)?;
    assert_eq!(adapter.compensate_calls, 1);
    assert_eq!(adapter.compensation_reconciliation_calls, 0);
    assert_eq!(
        reopened.next_action(&operation)?,
        RecoveryAction::ReconcileCompensation
    );
    Ok(())
}

#[test]
fn revocation_after_cancellation_intent_prevents_external_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RuntimeFixture::with_plan(checked_cancellation_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let revoked = Rc::new(Cell::new(false));
    let mut policy = RevocablePolicy::new(Rc::clone(&revoked));
    let mut adapter = TestAdapter::recovery();
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &TestClock,
        )
        .map_err(admission_error)?;
    let mut observer = RevokeAtBoundary::new(
        Rc::clone(&revoked),
        crate::execution::Boundary::CancellationIntentDurable,
    );

    let error = transaction
        .cancel_admitted_with_observer(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &CancellationToken::default(),
            &mut observer,
        )
        .expect_err("revocation after durable cancellation intent must fail closed");

    assert_revoked_dispatch(error, InvocationPurpose::Cancel)?;
    assert_eq!(adapter.cancel_calls, 0);
    Ok(())
}

#[test]
fn checked_cancellation_reports_exact_admitted_boundaries() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = RuntimeFixture::with_plan(checked_cancellation_plan())?;
    let mut store = TestStore;
    let mut transaction = fixture.open(&mut store)?;
    let mut catalog = TestCatalog::default();
    let mut policy = AllowPolicy;
    let mut adapter = TestAdapter::recovery();
    let cancellation = CancellationToken::default();
    let admitted = transaction
        .admit(
            fixture.operation(),
            &adapter,
            &mut catalog,
            &mut policy,
            &TestClock,
        )
        .map_err(admission_error)?;
    let expected_transaction = admitted.transaction().clone();
    let expected_operation = admitted.operation_id().clone();
    let expected_attempt = admitted.attempt();
    let mut observer = RecordingBoundaryObserver::default();
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &TestClock,
            &cancellation,
        )?,
        ExecutionStep::Indeterminate
    );
    cancellation.cancel();

    let step = transaction.cancel_admitted_with_observer(
        &admitted,
        &mut adapter,
        &mut policy,
        &TestClock,
        &cancellation,
        &mut observer,
    )?;

    assert_eq!(step, ExecutionStep::Indeterminate);
    assert_eq!(
        observer.observations,
        [
            (
                expected_transaction.clone(),
                expected_operation.clone(),
                expected_attempt,
                InvocationPurpose::Cancel,
                crate::execution::Boundary::CancellationIntentDurable,
            ),
            (
                expected_transaction.clone(),
                expected_operation.clone(),
                expected_attempt,
                InvocationPurpose::Cancel,
                crate::execution::Boundary::FinalDispatch,
            ),
            (
                expected_transaction.clone(),
                expected_operation.clone(),
                expected_attempt,
                InvocationPurpose::Cancel,
                crate::execution::Boundary::CancellationReturned,
            ),
            (
                expected_transaction,
                expected_operation,
                expected_attempt,
                InvocationPurpose::Cancel,
                crate::execution::Boundary::CancellationOutcomeDurable,
            ),
        ]
    );
    assert!(matches!(
        transaction.history(fixture.operation())?.state(),
        OperationState::Indeterminate { attempt, .. } if *attempt == expected_attempt
    ));
    Ok(())
}

fn reconcile_published_effect(
    fixture: &RuntimeFixture,
    store: &mut TestStore,
    catalog: &mut TestCatalog,
    policy: &mut RecordingPolicy,
    publication: std::path::PathBuf,
) -> Result<PublishingAdapter, Box<dyn std::error::Error>> {
    let mut adapter = PublishingAdapter::new(publication);
    let mut recovered = fixture.open(store)?;
    let admitted = recovered
        .admit(fixture.operation(), &adapter, catalog, policy, &TestClock)
        .map_err(admission_error)?;
    assert_eq!(admitted.invocation_purpose(), InvocationPurpose::Reconcile);
    assert_eq!(
        recovered.drive_admitted(
            &admitted,
            &mut adapter,
            policy,
            &TestClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );
    recovered
        .release_admitted::<PublishingAdapter, _, _>(admitted, catalog, &TestClock)
        .map_err(release_error)?;
    Ok(adapter)
}
