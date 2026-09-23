//! Adoption, publication, preflight, and routing regressions.

use super::*;

#[test]
fn second_adoption_failure_retains_first_adoption_and_complete_world() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let first_source_process = first.process_id();
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let second_source_process = second.process_id();
    let (nodes, mut source_world) =
        prepared_test_source_world(vec![first, second]).expect("prepared source world");
    source_world
        .replace_immutable_root_for_test(&nodes[1].0, ContentHash::from_bytes(b"mismatched-root"))
        .expect("replace second immutable root");
    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        input.lineage(),
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    reset_hot_fork_adoption_count_for_test();
    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(_)
        ))
    ));
    assert_eq!(hot_fork_adoption_count_for_test(), 1);
    assert!(!factory.sources.available());
    assert!(linux_process_identity(first_source_process).is_ok_and(|identity| identity.is_some()));
    assert!(linux_process_identity(second_source_process).is_ok_and(|identity| identity.is_some()));
    let retained_children = observations
        .retained_child_processes
        .lock()
        .expect("retained child registry");
    assert_eq!(retained_children.len(), 2);
    assert!(
        retained_children
            .iter()
            .all(|process| PathBuf::from("/proc").join(process.to_string()).exists())
    );
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_some());
}

#[test]
fn poisoned_source_owner_cannot_be_recovered_on_retry() {
    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source");
    let (_nodes, source_world) =
        prepared_test_source_world(vec![source]).expect("prepared source world");
    let input = execution_input();
    let context = execution_context(&input, 0x79);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        input.lineage(),
        run_state.path().to_path_buf(),
        observations,
    );
    let mut lifecycle = match factory.try_start(&input, &context).expect("start world") {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("exact source world declined"),
    };
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown adopted world");
    reconcile_canceled_world(&mut lifecycle);

    let source_owner = lifecycle.source_world_owner_for_test();
    let poisoner = std::thread::spawn(move || {
        let _source = source_owner.lock().expect("lock source owner");
        panic!("poison source owner");
    });
    assert!(poisoner.join().is_err());

    let lifecycle = factory
        .recover(lifecycle)
        .expect_err("poisoned source owner must fail recovery");
    let lifecycle = factory
        .recover(lifecycle)
        .expect_err("recovery retry must preserve source poison");
    assert!(!factory.sources.available());
    factory.quarantine(lifecycle);
}

#[test]
fn published_observation_reconciliation_makes_the_exact_source_world_reusable() {
    let (repository, store, lineage, attempt, _result, scenario) = repository_execution_fixture();
    let (selectable_plan, pending_request) = pending_guest_selectable_plan();
    let expected_discovery = crate::guest_selectable::resolve_guest_selectable(
        lineage.scenario(),
        &scenario,
        &crucible::NodeId {
            name: String::from("db-0"),
        },
        &pending_request,
    )
    .expect("resolve expected typed guest opportunity");
    let expected_opportunity = expected_discovery.opportunity().clone();
    let first = scripted_hot_fork_source_with_state_for_test(
        QemuTestHotForkOutcome::Forked,
        Vec::new(),
        Some((selectable_plan, pending_request)),
    )
    .expect("first source");
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_nodes, source_world) = prepared_multi_node_hot_fork_source_world_for_scenario_for_test(
        &scenario,
        vec![first, second],
    )
    .expect("prepared source world");
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let hot_fork = QemuHotForkWorldExecutionRunner::new(
        factory(
            source_world,
            &lineage,
            run_state.path().to_path_buf(),
            observations.clone(),
        ),
        QemuFreshModeledDriver::new(),
    );
    let router = QemuHotFirstExecutionRouter::new(
        hot_fork,
        NeverFallbackRunner {
            calls: Arc::clone(&fallback_calls),
        },
    );
    let model = CrucibleExecutionModel::new(store.clone(), router);
    let mut worker = RepositoryAttemptWorker::new(store.clone(), model);

    let profile = ExecutorCompatibilityProfile::new(
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        lineage.scenario_schema(),
        1,
    )
    .expect("compatibility profile");
    let epoch = DaemonEpoch::from_bytes([0x72; 16]).expect("daemon epoch");
    let resources = AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 64).expect("attempt resources");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x73; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        attempt,
        resources,
        ExecutionRetentionIntent::Discard,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("submit request");
    let admission = RepositoryAttemptAdmission::new(Arc::clone(&repository), profile);
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        admission,
        epoch,
        ExecutorCapacity::new(1, 8, 8 << 30, 8 << 30, 64).expect("executor capacity"),
    );
    let submitted =
        ExecutorService::submit_attempt(&mut supervisor, &request).expect("submit exact discovery");
    assert!(matches!(
        submitted.disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    let queued = supervisor.next_queued().expect("queued execution");

    let work = worker.execute(queued);
    let checkpoints = ExactCheckpointStore::new(
        Arc::new(TestDurableCheckpointBackend::new()),
        8 * 1024 * 1024,
    )
    .expect("checkpoint store");
    let prepared = prepare_attempt_result(&store, &checkpoints, work).expect("prepare result");
    let PreparedAttemptWorkResult::Observation(prepared) = prepared else {
        panic!("driver returned an unexpected checkpoint")
    };
    let observation = prepared.observation();

    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        worker.model().last_materialization(),
        Some(CrucibleMaterializationTier::HotFork)
    );
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);

    let staged = stage_prepared_attempt_result(&mut supervisor, *prepared).expect("stage result");
    let AttemptResultStageOutcome::Publish(staged) = staged else {
        panic!("current execution must publish")
    };
    let exact_authenticator =
        crate::exact_checkpoint_store::ExactFindingCheckpointAuthenticator::new(
            &store,
            &checkpoints,
        );
    let published = publish_prepared_attempt_result(&store, &exact_authenticator, staged)
        .expect("publish result");
    let published_observation = repository
        .load_observation(observation)
        .expect("published observation");
    assert_eq!(
        published_observation
            .id()
            .expect("published observation id"),
        observation
    );
    let expected_opportunity_id = expected_opportunity.id().expect("expected opportunity id");
    assert_eq!(
        published_observation.discovered_choices(),
        &BTreeSet::from([expected_opportunity_id])
    );
    assert_eq!(
        repository
            .load_choice_opportunity(expected_opportunity_id)
            .expect("published typed opportunity"),
        expected_opportunity
    );
    let child_artifact = repository
        .load_configuration_artifact(published_observation.child_content())
        .expect("published child configuration artifact");
    let scenario_artifact = repository
        .load_scenario_artifact(lineage.scenario_content())
        .expect("published scenario artifact");
    let child_configuration = decode_crucible_configuration_artifact_with_selections(
        &scenario,
        &scenario_artifact,
        &child_artifact,
        &store,
    )
    .expect("decode published child configuration");
    assert_eq!(
        ConfigurationId::from_hash(CampaignHash::from_bytes(child_configuration.id().bytes)),
        published_observation.child()
    );
    assert_eq!(child_configuration.def.id(), scenario.scenario_def().id());
    assert_eq!(expected_opportunity.instance(), "publication");
    assert_eq!(
        expected_opportunity.source(),
        &ChoiceSource::Guest {
            node: String::from("db-0"),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        }
    );
    let reconciled = reconcile_published_attempt_result::<_, _, ()>(&mut supervisor, published)
        .expect("reconcile published result");
    assert_eq!(
        reconciled,
        AttemptWorkerReconcileOutcome::Reconciled {
            observation,
            completion: CompletionOutcome::Completed,
        }
    );

    let mut cleanup_complete = false;
    for _ in 0..64 {
        if LocalAttemptWorker::reconcile_execution(
            &mut worker,
            AttemptExecutionDisposition::Observation(observation),
        )
        .expect("reconcile hot-fork execution")
            == AttemptExecutionReconciliationStep::Complete
        {
            cleanup_complete = true;
            break;
        }
    }
    assert!(cleanup_complete);
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn target_world_resource_preflight_rejects_before_source_checkout_or_guard_installation() {
    let input = execution_input();
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_nodes, source_world) =
        prepared_test_source_world(vec![first, second]).expect("prepared source world");
    let observations = ScriptedWorldObservations::new();
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = factory(
        source_world,
        input.lineage(),
        run_state.path().to_path_buf(),
        observations.clone(),
    );
    let resources = AttemptResourceLimits::new(1, 64 << 20, 64 << 20, 64)
        .expect("undersized attempt resources");
    let context = AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .with_runtime_basis(execution_basis(&input, 0x80));

    let failure = match factory.try_start(&input, &context) {
        Err(failure) => failure,
        Ok(_) => panic!("aggregate World baseline must exceed the attempt ceiling"),
    };
    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(
            QemuProductionHotForkWorldLifecycleFactoryError::ScenarioResources(_)
        )
    ));
    assert!(factory.sources.available());
    assert!(
        observations
            .guard_liveness
            .lock()
            .expect("guard liveness")
            .is_none()
    );
    assert!(
        observations
            .retained_child_processes
            .lock()
            .expect("child process observations")
            .is_empty()
    );
}

#[test]
fn hot_first_router_falls_back_only_after_decline_and_bypasses_hot_fork_for_resume_and_capture() {
    let (_repository, _store, _lineage, _attempt, result, _scenario) =
        repository_execution_fixture();
    let input = execution_input();
    let checkouts = Arc::new(AtomicUsize::new(0));
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let reconciliations = Arc::new(AtomicUsize::new(0));
    let observations = ScriptedWorldObservations::new();
    let run_state = tempfile::tempdir().expect("run state");
    let factory = QemuProductionHotForkWorldLifecycleFactory::new(
        RecordingUnavailableSourceWorldProvider {
            checkouts: Arc::clone(&checkouts),
        },
        ScriptedWorldGuardFactory { observations },
        run_state.path(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    );
    let unused_driver_calls = Arc::new(AtomicUsize::new(0));
    let unused_seals = Arc::new(AtomicUsize::new(0));
    let hot_fork = QemuHotForkWorldExecutionRunner::new(
        factory,
        ScriptedPublishedObservationDriver {
            result: result.clone(),
            drives: Arc::clone(&unused_driver_calls),
            seals: Arc::clone(&unused_seals),
        },
    );
    let fallback = RecordingFallbackRunner {
        result,
        calls: Arc::clone(&fallback_calls),
        reconciliations: Arc::clone(&reconciliations),
    };
    let mut router = QemuHotFirstExecutionRouter::new(hot_fork, fallback);

    let fresh = router
        .execute(&input, &execution_context(&input, 0x81))
        .expect("declined hot fork falls back");
    assert_eq!(
        fresh.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
    assert_eq!(checkouts.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    assert_eq!(unused_driver_calls.load(Ordering::SeqCst), 0);
    assert_eq!(unused_seals.load(Ordering::SeqCst), 0);
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::Canceled)
            .expect("reconcile fallback"),
        AttemptExecutionReconciliationStep::Complete
    );

    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"hot-first-resume",
    ))
    .expect("checkpoint id");
    let resume_context = execution_context(&input, 0x82).with_resume_checkpoint(Some(checkpoint));
    let resumed = router
        .execute(&input, &resume_context)
        .expect("resume uses fallback directly");
    assert_eq!(
        resumed.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
    assert_eq!(checkouts.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::ExactCheckpoint(checkpoint))
            .expect("reconcile resumed fallback"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(reconciliations.load(Ordering::SeqCst), 2);

    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("router fixture must be a discovery attempt")
    };
    let capture_context = execution_context(&input, 0x83)
        .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration });
    let captured = router
        .execute(&input, &capture_context)
        .expect("materialized-start capture uses fallback directly");
    assert_eq!(
        captured.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
    assert_eq!(checkouts.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::Canceled)
            .expect("reconcile capture fallback"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(reconciliations.load(Ordering::SeqCst), 3);
}
