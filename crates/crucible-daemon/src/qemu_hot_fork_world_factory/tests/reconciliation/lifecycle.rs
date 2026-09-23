//! Source checkout, child launch, and failure-recovery regressions.

use super::*;

fn assert_scripted_child_owned_or_reaped(expected: &QemuProcessIdentity) {
    let process = expected.process_id;
    let stat_path = PathBuf::from("/proc")
        .join(process.to_string())
        .join("stat");
    let stat = match std::fs::read_to_string(stat_path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("inspect retained child {process}: {error}"),
    };
    let mut fields = stat
        .rsplit_once(") ")
        .map(|(_identity, fields)| fields.split_ascii_whitespace())
        .expect("retained child process status");
    let _state = fields.next().expect("retained child process state");
    let parent = fields
        .next()
        .expect("retained child parent process")
        .parse::<u32>()
        .expect("retained child parent process ID");
    let start_time_ticks = fields
        .nth(17)
        .expect("retained child process start time")
        .parse::<u64>()
        .expect("retained child process start-time ticks");

    // Retention authenticated the identity before recording it. One stat
    // snapshot now proves that any extant generation remains parented to the
    // scripted source owner; an absent entry above proves completed reap.
    assert_eq!(parent, std::process::id());
    assert_eq!(start_time_ticks, expected.start_time_ticks);
}

#[test]
fn two_running_nodes_install_shutdown_reconcile_and_reuse_one_source_world() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (nodes, source_world) =
        prepared_test_source_world(vec![first, second]).expect("prepared source world");
    assert_eq!(nodes.len(), 2);
    assert!(source_world.continuation().nodes().iter().any(|boundary| {
        boundary.service_state() == ProductionVmHotForkNodeServiceState::PermanentlyFailed
            && boundary.process().is_none()
    }));

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

    let mut lifecycle = match factory.try_start(&input, &context).expect("start world") {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("exact source world declined"),
    };
    assert!(!factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    assert!(lifecycle.start_materialization().is_ok());
    let first_directories = observations
        .prepared_run_directories
        .lock()
        .expect("first branch directory registry")
        .clone();
    let first_children = observations
        .retained_child_processes
        .lock()
        .expect("first branch child registry")
        .clone();
    assert_eq!(first_directories.len(), 2);
    assert_eq!(first_children.len(), 2);
    assert_eq!(
        first_directories.iter().collect::<BTreeSet<_>>().len(),
        first_directories.len()
    );
    assert_eq!(
        first_children
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        first_children.len()
    );
    assert!(first_directories.iter().all(|directory| directory.is_dir()));
    assert!(first_children.iter().all(|process| {
        linux_process_identity(*process)
            .expect("inspect first branch child")
            .is_some()
    }));
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown adopted world");
    assert!(!factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    reconcile_canceled_world(&mut lifecycle);

    assert!(factory.recover(lifecycle).is_ok());

    assert!(factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);

    let second_context = execution_context(&input, 0x7a);
    let mut second_lifecycle = match factory
        .try_start(&input, &second_context)
        .expect("reuse source world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("reprepared source world declined"),
    };
    assert!(second_lifecycle.start_materialization().is_ok());
    let all_directories = observations
        .prepared_run_directories
        .lock()
        .expect("branch directory registry")
        .clone();
    let all_children = observations
        .retained_child_processes
        .lock()
        .expect("branch child registry")
        .clone();
    assert_eq!(all_directories.len(), 4);
    assert_eq!(all_children.len(), 4);
    assert_eq!(
        all_directories.iter().collect::<BTreeSet<_>>().len(),
        all_directories.len()
    );
    assert_eq!(
        all_children.iter().copied().collect::<BTreeSet<_>>().len(),
        all_children.len()
    );
    assert!(
        all_directories[2..]
            .iter()
            .all(|directory| directory.is_dir())
    );
    assert!(all_children[2..].iter().all(|process| {
        linux_process_identity(*process)
            .expect("inspect second branch child")
            .is_some()
    }));
    assert!(
        first_directories
            .iter()
            .all(|directory| !directory.exists())
    );
    assert!(first_children.iter().all(|process| {
        linux_process_identity(*process)
            .expect("inspect reconciled first branch child")
            .is_none()
    }));
    QemuFreshAttemptLifecycleOwner::shutdown(&mut second_lifecycle)
        .expect("shutdown second adopted world");
    reconcile_canceled_world(&mut second_lifecycle);
    assert!(factory.recover(second_lifecycle).is_ok());

    assert!(factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 2);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
    assert!(all_directories.iter().all(|directory| !directory.exists()));
    assert!(all_children.iter().all(|process| {
        linux_process_identity(*process)
            .expect("inspect reconciled branch child")
            .is_none()
    }));
}

#[test]
fn powered_off_node_forks_with_the_complete_world_and_releases_on_shutdown() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let scenario = test_execution_scenario();
    let powered_off = scenario
        .world()
        .vm_nodes()
        .iter()
        .next()
        .expect("scenario VM")
        .id
        .clone();
    let (_nodes, source_world) =
        prepared_multi_node_hot_fork_source_world_with_powered_off_for_scenario_for_test(
            &scenario,
            vec![first, second],
            &BTreeSet::from([powered_off.clone()]),
        )
        .expect("prepared world with powered-off source");
    let boundary = source_world
        .continuation()
        .nodes()
        .iter()
        .find(|boundary| boundary.node() == &powered_off)
        .expect("powered-off boundary");
    assert_eq!(
        boundary.service_state(),
        ProductionVmHotForkNodeServiceState::PoweredOff
    );
    assert!(boundary.process().is_some());
    assert!(boundary.physical_time().is_some());

    let input = execution_input_for_scenario(scenario);
    let context = execution_context(&input, 0xc7);
    let run_state = tempfile::tempdir().expect("run state");
    let observations = ScriptedWorldObservations::new();
    let mut factory = factory(
        source_world,
        input.lineage(),
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    let mut lifecycle = match factory
        .try_start(&input, &context)
        .expect("start child world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("powered-off source declined"),
    };
    assert!(lifecycle.start_materialization().is_ok());
    let before_boot = lifecycle
        .fault_evidence_snapshot()
        .expect("adopted powered-off evidence");
    let powered_off_evidence = before_boot
        .nodes
        .iter()
        .find(|node| node.node == powered_off)
        .expect("adopted powered-off node evidence");
    assert_eq!(powered_off_evidence.service_state, "powered_off");
    assert_eq!(
        powered_off_evidence.scheduler_activity,
        SchedulerNodeActivity::Halted
    );
    assert!(powered_off_evidence.backend_owned);
    assert_eq!(powered_off_evidence.process_ownership, "exact");

    lifecycle
        .commit_modeled_boot_for_test(&powered_off)
        .expect("commit later modeled Boot");
    let after_boot = lifecycle
        .fault_evidence_snapshot()
        .expect("reactivated child evidence");
    let booted_evidence = after_boot
        .nodes
        .iter()
        .find(|node| node.node == powered_off)
        .expect("booted node evidence");
    assert_eq!(booted_evidence.service_state, "running");
    assert_eq!(
        booted_evidence.scheduler_activity,
        SchedulerNodeActivity::Runnable
    );
    assert!(booted_evidence.backend_owned);
    assert_eq!(booted_evidence.process_ownership, "exact");
    assert_eq!(
        observations
            .retained_child_processes
            .lock()
            .expect("child registry")
            .len(),
        2
    );
    assert!(!factory.sources.available());

    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown child world");
    reconcile_canceled_world(&mut lifecycle);
    assert!(factory.recover(lifecycle).is_ok());
    assert!(factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn two_factories_keep_independent_live_children_from_one_managed_source() {
    let source_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source node");
    let (_nodes, mut source_world) =
        prepared_test_source_world(vec![source_node]).expect("prepared source world");
    let input = execution_input();
    let source_key = QemuHotForkSourceWorldKey::new(
        input.lineage().id().expect("lineage id"),
        source_world.continuation().configuration().def.id(),
        source_world.continuation().configuration().id(),
        ExecutorCompatibilityProfile::from_lineage(input.lineage()),
    );
    let usage = source_world
        .measure_retained_resources()
        .expect("measure source resources");
    let source_resources = HotCheckpointResourceProfile::new(
        usage.template_bytes(),
        usage.expected_private_dirty_bytes(),
        usage.process_count(),
        usage.virtual_cpu_count(),
        usage.descriptor_count(),
        usage.overlay_count(),
    )
    .expect("source resource profile");
    let parent_and_two_children = HotCheckpointResourceProfile::new(
        source_resources.template_bytes() * 3,
        source_resources.expected_private_dirty_bytes() * 3,
        source_resources.process_count() * 3,
        source_resources.virtual_cpu_count() * 3,
        source_resources.descriptor_count() * 3,
        source_resources.overlay_count() * 3,
    )
    .expect("parent-and-two-child resource ceiling");
    let limits = HotCheckpointLimits::new(1, parent_and_two_children, 3, 1_000_000_000)
        .expect("two-child managed limits");
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        FactoryReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("managed source pool");
    let fallback = ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.4.{}",
        "d1".repeat(32)
    ))
    .expect("fallback checkpoint");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(source_key, source_world),
        HotCheckpointHotnessSignals::new(),
        HotCheckpointFallback::Exact(fallback),
    )
    .expect("admit managed source");

    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let first_observations = ScriptedWorldObservations::new();
    let second_observations = ScriptedWorldObservations::new();
    let first_run_state = tempfile::tempdir().expect("first run state");
    let second_run_state = tempfile::tempdir().expect("second run state");
    let mut first_factory = QemuProductionHotForkWorldLifecycleFactory::new(
        shared.provider().expect("first source provider"),
        ScriptedWorldGuardFactory {
            observations: first_observations.clone(),
        },
        first_run_state.path(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    );
    let mut second_factory = QemuProductionHotForkWorldLifecycleFactory::new(
        shared.provider().expect("second source provider"),
        ScriptedWorldGuardFactory {
            observations: second_observations.clone(),
        },
        second_run_state.path(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    );

    let mut first = match first_factory
        .try_start(&input, &execution_context(&input, 0xd2))
        .expect("start first child world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("first managed lease declined"),
    };
    let mut second = match second_factory
        .try_start(&input, &execution_context(&input, 0xd3))
        .expect("start second child world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("second managed lease declined"),
    };

    let first_source = first.source_world_owner_for_test();
    let second_source = second.source_world_owner_for_test();
    assert!(Arc::ptr_eq(&first_source, &second_source));
    drop((first_source, second_source));
    assert!(first.start_materialization().is_ok());
    assert!(second.start_materialization().is_ok());
    let first_children = first_observations
        .retained_child_processes
        .lock()
        .expect("first child registry")
        .clone();
    let second_children = second_observations
        .retained_child_processes
        .lock()
        .expect("second child registry")
        .clone();
    assert_eq!(first_children.len(), 1);
    assert_eq!(second_children.len(), 1);
    assert_ne!(first_children, second_children);
    let first_request = first_observations
        .retained_child_requests
        .lock()
        .expect("first child request registry")[0];
    let second_request = second_observations
        .retained_child_requests
        .lock()
        .expect("second child request registry")[0];
    assert_ne!(
        first_request.child_process_contract_generation(),
        second_request.child_process_contract_generation()
    );
    assert_ne!(
        first_request.child_files_generation(),
        second_request.child_files_generation()
    );

    QemuFreshAttemptLifecycleOwner::shutdown(&mut first).expect("shutdown first child world");
    reconcile_canceled_world(&mut first);
    assert!(first_factory.recover(first).is_ok());
    assert!(shared.orderly_shutdown().is_err());
    assert_eq!(first_observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(second_observations.finishes.load(Ordering::SeqCst), 0);

    QemuFreshAttemptLifecycleOwner::shutdown(&mut second).expect("shutdown second child world");
    reconcile_canceled_world(&mut second);
    assert!(second_factory.recover(second).is_ok());
    assert_eq!(second_observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(first_observations.quarantines.load(Ordering::SeqCst), 0);
    assert_eq!(second_observations.quarantines.load(Ordering::SeqCst), 0);
    assert_eq!(
        shared
            .orderly_shutdown()
            .expect("retire source after both children")
            .len(),
        1
    );
}

#[test]
fn proven_first_child_rejection_restores_the_exact_source_world_for_retry() {
    let source =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::RejectedOnce).expect("source");
    let source_process = source.process_id();
    let (_nodes, source_world) =
        prepared_test_source_world(vec![source]).expect("prepared source world");
    let checkout_nodes = source_world.continuation().nodes().to_vec();
    let input = execution_input();
    let observations = ScriptedWorldObservations::new();
    let source_key = QemuHotForkSourceWorldKey::new(
        input.lineage().id().expect("lineage id"),
        source_world.continuation().configuration().def.id(),
        source_world.continuation().configuration().id(),
        ExecutorCompatibilityProfile::from_lineage(input.lineage()),
    );
    let finish_count_at_restore = Arc::new(AtomicUsize::new(usize::MAX));
    let provider = CleanupOrderedSourceWorldProvider {
        inner: QemuSingleHotForkSourceWorldProvider::new(source_key, source_world),
        finishes: Arc::clone(&observations.finishes),
        finish_count_at_restore: Arc::clone(&finish_count_at_restore),
    };
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ScriptedWorldGuardFactory {
            observations: observations.clone(),
        },
        run_state.path(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    );

    let first_context = execution_context(&input, 0x79);
    assert!(matches!(
        factory.try_start(&input, &first_context),
        Err(AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
        ))
    ));
    assert!(factory.sources.available());
    assert_eq!(finish_count_at_restore.load(Ordering::SeqCst), 1);
    assert_eq!(
        factory
            .sources
            .inner
            .source
            .as_ref()
            .expect("restored source world")
            .continuation()
            .nodes(),
        checkout_nodes
    );
    assert!(linux_process_identity(source_process).is_ok_and(|identity| identity.is_some()));
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
    let prepared_directories = observations
        .prepared_run_directories
        .lock()
        .expect("prepared directory registry");
    assert_eq!(prepared_directories.len(), 1);
    assert!(!prepared_directories[0].exists());
    drop(prepared_directories);
    assert!(
        observations
            .retained_child_processes
            .lock()
            .expect("retained child registry")
            .is_empty()
    );

    let second_context = execution_context(&input, 0x7a);
    let mut lifecycle = match factory
        .try_start(&input, &second_context)
        .expect("retry exact source world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("restored source world declined"),
    };
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown retried world");
    reconcile_canceled_world(&mut lifecycle);
    assert!(factory.recover(lifecycle).is_ok());

    assert!(factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 2);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn target_directory_rejection_restores_the_source_without_invoking_qemu() {
    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source");
    let (_nodes, source_world) =
        prepared_test_source_world(vec![source]).expect("prepared source world");
    let input = execution_input();
    let observations = ScriptedWorldObservations::new();
    observations
        .prepare_rejections_remaining
        .store(1, Ordering::SeqCst);
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = factory(
        source_world,
        input.lineage(),
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    assert!(matches!(
        factory.try_start(&input, &execution_context(&input, 0x79)),
        Err(AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
        ))
    ));
    assert!(factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
    assert!(
        observations
            .prepared_run_directories
            .lock()
            .expect("prepared directory registry")
            .is_empty()
    );
    assert!(
        observations
            .retained_child_processes
            .lock()
            .expect("retained child registry")
            .is_empty()
    );
}

#[test]
fn failed_target_cleanup_after_first_child_rejection_keeps_the_source_unavailable() {
    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source");
    let source_process = source.process_id();
    let (_nodes, source_world) =
        prepared_test_source_world(vec![source]).expect("prepared source world");
    let input = execution_input();
    let observations = ScriptedWorldObservations::new();
    observations
        .prepare_rejections_remaining
        .store(1, Ordering::SeqCst);
    observations
        .finish_failures_remaining
        .store(1, Ordering::SeqCst);
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = factory(
        source_world,
        input.lineage(),
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    assert!(matches!(
        factory.try_start(&input, &execution_context(&input, 0x79)),
        Err(AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
        ))
    ));
    assert!(!factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert!(linux_process_identity(source_process).is_ok_and(|identity| identity.is_some()));
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_some());
}

#[test]
fn indeterminate_child_failure_quarantines_complete_world_during_sibling_launch() {
    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let first_source_process = first.process_id();
    let second = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Indeterminate)
        .expect("second source");
    let second_source_process = second.process_id();
    let (_nodes, source_world) =
        prepared_test_source_world(vec![first, second]).expect("prepared source world");
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

    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
        ))
    ));
    assert!(!factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
    assert!(linux_process_identity(first_source_process).is_ok_and(|identity| identity.is_some()));
    assert!(linux_process_identity(second_source_process).is_ok_and(|identity| identity.is_some()));
    let retained_children = observations
        .retained_child_processes
        .lock()
        .expect("retained child registry");
    // Concurrent quarantine can win before sibling retention or after it
    // begins. The sibling therefore records at most one retention attempt;
    // the complete World owns either its live child or its finished cleanup.
    assert!(retained_children.len() <= 1);
    let retained_identities = observations
        .retained_child_identities
        .lock()
        .expect("retained child identity registry");
    assert_eq!(retained_identities.len(), retained_children.len());
    assert!(
        retained_identities
            .iter()
            .zip(retained_children.iter())
            .all(|(identity, process)| identity.process_id == *process)
    );
    retained_identities
        .iter()
        .for_each(assert_scripted_child_owned_or_reaped);
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_some());
}

#[cfg(feature = "destructive-recovery-faults")]
#[test]
fn child_resource_alias_rejects_before_fork_and_restores_source_world() {
    if std::env::var_os(CHILD_RESOURCE_ALIAS_CHILD_ENVIRONMENT).is_none() {
        let child =
            std::process::Command::new(std::env::current_exe().expect("current test binary"))
                .arg("--exact")
                .arg(CHILD_RESOURCE_ALIAS_TEST_NAME)
                .arg("--nocapture")
                .env(CHILD_RESOURCE_ALIAS_CHILD_ENVIRONMENT, "1")
                .env(
                    DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT,
                    CHILD_RESOURCE_ALIAS_TRIGGER,
                )
                .output()
                .expect("run child-resource alias child");
        assert!(
            child.status.success(),
            "child-resource alias child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr),
        );
        return;
    }

    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source");
    let source_process = source.process_id();
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
        observations.clone(),
    );

    reset_hot_fork_adoption_count_for_test();
    let failure = match factory.try_start(&input, &context) {
        Err(failure) => failure,
        Ok(_) => panic!("fault build must reject aliased child resources"),
    };
    let AttemptWorkerFailure::Retryable(QemuProductionHotForkWorldLifecycleFactoryError::Assembly(
        message,
    )) = failure
    else {
        panic!("child-resource alias must be a retryable assembly failure")
    };
    assert!(message.contains("child file destinations must name distinct roots and files"));
    assert_eq!(hot_fork_adoption_count_for_test(), 0);
    assert!(factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
    assert!(linux_process_identity(source_process).is_ok_and(|identity| identity.is_some()));
    let prepared_directories = observations
        .prepared_run_directories
        .lock()
        .expect("prepared directory registry");
    assert_eq!(prepared_directories.len(), 1);
    assert!(!prepared_directories[0].exists());
    drop(prepared_directories);
    assert!(
        observations
            .retained_child_processes
            .lock()
            .expect("retained child registry")
            .is_empty()
    );
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_none());
}

#[cfg(feature = "destructive-recovery-faults")]
#[test]
fn world_fork_preflight_failure_restores_source_world() {
    if std::env::var_os(WORLD_FORK_PREFLIGHT_FAILURE_CHILD_ENVIRONMENT).is_none() {
        let child =
            std::process::Command::new(std::env::current_exe().expect("current test binary"))
                .arg("--exact")
                .arg(WORLD_FORK_PREFLIGHT_FAILURE_TEST_NAME)
                .arg("--nocapture")
                .env(WORLD_FORK_PREFLIGHT_FAILURE_CHILD_ENVIRONMENT, "1")
                .env(
                    DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT,
                    WORLD_FORK_PREFLIGHT_FAILURE_TRIGGER,
                )
                .output()
                .expect("run world-fork one-VM failure child");
        assert!(
            child.status.success(),
            "world-fork child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr),
        );
        return;
    }

    let first =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let first_source_process = first.process_id();
    let second =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let second_source_process = second.process_id();
    let (_nodes, source_world) =
        prepared_test_source_world(vec![first, second]).expect("prepared source world");
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
    let failure = match factory.try_start(&input, &context) {
        Err(failure) => failure,
        Ok(_) => panic!("fault build must reject the second world VM"),
    };
    let AttemptWorkerFailure::Retryable(QemuProductionHotForkWorldLifecycleFactoryError::Assembly(
        message,
    )) = failure
    else {
        panic!("world-fork fault must be a retryable assembly failure: {failure:?}")
    };
    assert!(message.contains("fault-injected failure while reserving the next hot-fork world VM"));
    assert_eq!(hot_fork_adoption_count_for_test(), 0);
    // All node reservations precede every launch, so this fault is provably
    // childless and the authenticated source remains reusable.
    assert!(factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
    assert!(linux_process_identity(first_source_process).is_ok_and(|identity| identity.is_some()));
    assert!(linux_process_identity(second_source_process).is_ok_and(|identity| identity.is_some()));
    let prepared_directories = observations
        .prepared_run_directories
        .lock()
        .expect("prepared directory registry");
    assert_eq!(prepared_directories.len(), 1);
    drop(prepared_directories);
    let retained_children = observations
        .retained_child_processes
        .lock()
        .expect("retained child registry");
    assert!(retained_children.is_empty());
    drop(retained_children);
    let guard = observations
        .guard_liveness
        .lock()
        .expect("guard liveness registry")
        .as_ref()
        .and_then(Weak::upgrade);
    assert!(guard.is_none());
}
