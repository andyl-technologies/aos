//! Focused model-tier proof of production whole-world hot-fork atomicity.

use super::*;

#[derive(Clone, Copy)]
enum RollbackFailureMode {
    None,
    Termination,
    ReapForever,
    ResourceProgressForever,
    PrivateRelease,
    CancellationForever,
}

struct ScriptedRollbackChild {
    mode: RollbackFailureMode,
    terminations: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
}

impl HotForkRollbackChild for ScriptedRollbackChild {
    fn request_rollback_termination(&mut self) -> Result<(), String> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        if matches!(self.mode, RollbackFailureMode::Termination) {
            Err(String::from("injected termination failure"))
        } else {
            Ok(())
        }
    }

    fn rollback_step(&mut self) -> Result<QemuHotForkReconciliationStep, String> {
        match self.mode {
            RollbackFailureMode::ReapForever => Ok(QemuHotForkReconciliationStep::ChildRunning),
            RollbackFailureMode::ResourceProgressForever => {
                Ok(QemuHotForkReconciliationStep::Advanced(
                    crate::QemuHotForkReconciliationPhase::ParentReaped,
                ))
            }
            RollbackFailureMode::PrivateRelease => {
                Err(String::from("injected private-resource release failure"))
            }
            RollbackFailureMode::None
            | RollbackFailureMode::Termination
            | RollbackFailureMode::CancellationForever => {
                Ok(QemuHotForkReconciliationStep::AwaitingPublication)
            }
        }
    }

    fn reconcile_rollback_cancellation(
        &mut self,
    ) -> Result<AttemptExecutionReconciliationStep, String> {
        if matches!(self.mode, RollbackFailureMode::CancellationForever) {
            Ok(AttemptExecutionReconciliationStep::Progressed)
        } else {
            Ok(AttemptExecutionReconciliationStep::Complete)
        }
    }

    fn quarantine_rollback(&mut self) {
        self.quarantines.fetch_add(1, Ordering::SeqCst);
    }
}

fn rollback_child(
    mode: RollbackFailureMode,
    terminations: &Arc<AtomicUsize>,
    quarantines: &Arc<AtomicUsize>,
) -> ScriptedRollbackChild {
    ScriptedRollbackChild {
        mode,
        terminations: Arc::clone(terminations),
        quarantines: Arc::clone(quarantines),
    }
}

fn rollback_policy() -> QemuShutdownPolicy {
    let mut policy = QemuShutdownPolicy::fast_test();
    policy.sigkill_wait = Duration::from_millis(2);
    policy.reap_wait = Duration::from_millis(2);
    policy
}

#[test]
fn rollback_retains_every_unfinished_owner_on_termination_failure() {
    let terminations = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let children = BTreeMap::from([
        (
            NodeId {
                name: String::from("node-0"),
            },
            rollback_child(
                RollbackFailureMode::Termination,
                &terminations,
                &quarantines,
            ),
        ),
        (
            NodeId {
                name: String::from("node-1"),
            },
            rollback_child(RollbackFailureMode::None, &terminations, &quarantines),
        ),
        (
            NodeId {
                name: String::from("node-2"),
            },
            rollback_child(RollbackFailureMode::None, &terminations, &quarantines),
        ),
    ]);

    let (mut retained, failure) = rollback_hot_fork_children(children, rollback_policy())
        .expect_err("termination failure must retain the rollback map");

    assert_eq!(retained.len(), 3);
    assert_eq!(terminations.load(Ordering::SeqCst), 3);
    assert!(failure.contains("request termination for `node-0`"));
    for child in retained.values_mut() {
        child.quarantine_rollback();
    }
    assert_eq!(quarantines.load(Ordering::SeqCst), 3);
}

#[test]
fn rollback_deadline_covers_reap_private_release_and_cancellation_progress() {
    for (mode, expected) in [
        (RollbackFailureMode::ReapForever, "reconcile `node-0`"),
        (
            RollbackFailureMode::ResourceProgressForever,
            "reconcile `node-0`",
        ),
        (
            RollbackFailureMode::PrivateRelease,
            "injected private-resource release failure",
        ),
        (
            RollbackFailureMode::CancellationForever,
            "reconcile cancellation for `node-0` within",
        ),
    ] {
        let terminations = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let children = BTreeMap::from([(
            NodeId {
                name: String::from("node-0"),
            },
            rollback_child(mode, &terminations, &quarantines),
        )]);

        let (mut retained, failure) = rollback_hot_fork_children(children, rollback_policy())
            .expect_err("incomplete reconciliation must retain the child owner");

        assert_eq!(retained.len(), 1);
        assert!(failure.contains(expected), "unexpected failure: {failure}");
        retained
            .get_mut(&NodeId {
                name: String::from("node-0"),
            })
            .expect("retained child")
            .quarantine_rollback();
        assert_eq!(quarantines.load(Ordering::SeqCst), 1);
    }
}

fn three_source_world(
    failure_index: usize,
    failure: QemuTestHotForkOutcome,
) -> (
    Vec<u32>,
    Vec<ProductionVmHotForkNodeBoundary>,
    ProductionVmHotForkSourceWorld,
) {
    let mut source_processes = Vec::new();
    let mut sources = Vec::new();
    for index in 0..3 {
        let outcome = if index == failure_index {
            failure
        } else {
            QemuTestHotForkOutcome::Forked
        };
        let source = scripted_hot_fork_source_for_test(outcome).expect("scripted source");
        source_processes.push(source.process_id());
        sources.push(source);
    }
    let (_nodes, source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(sources).expect("prepared source world");
    let roster = source_world.continuation().nodes().to_vec();
    (source_processes, roster, source_world)
}

fn assert_process_alive(process: u32) {
    assert!(linux_process_identity(process).is_ok_and(|identity| identity.is_some()));
}

fn assert_process_absent(process: u32) {
    assert!(!PathBuf::from("/proc").join(process.to_string()).exists());
}

#[test]
fn production_three_node_clean_rejection_is_atomic_at_every_launch_index() {
    for failure_index in 0..3 {
        let (source_processes, original_roster, source_world) =
            three_source_world(failure_index, QemuTestHotForkOutcome::RejectedOnce);
        let input = execution_input();
        let observations = ScriptedWorldObservations::new();
        let run_state = tempfile::tempdir().expect("run state");
        let mut factory = factory(
            source_world,
            input.lineage(),
            run_state.path().to_path_buf(),
            observations.clone(),
        );

        let failure = factory
            .try_start(
                &input,
                &execution_context(&input, 0x80 + failure_index as u8),
            )
            .err()
            .expect("clean rejection must fail this launch transaction");
        let AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
        ) = failure
        else {
            panic!("unexpected clean-rejection disposition at index {failure_index}")
        };
        assert!(
            factory.sources().available(),
            "clean rejection at index {failure_index} did not restore the source: {message}"
        );
        assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
        assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
        assert!(source_processes.iter().copied().all(|process| {
            linux_process_identity(process).is_ok_and(|identity| identity.is_some())
        }));

        let retained_children = observations
            .retained_child_processes
            .lock()
            .expect("retained child registry");
        assert_eq!(retained_children.len(), failure_index);
        for process in retained_children.iter().copied() {
            assert_process_absent(process);
        }
        drop(retained_children);
        let directories = observations
            .prepared_run_directories
            .lock()
            .expect("prepared directory registry");
        assert_eq!(directories.len(), failure_index + 1);
        assert!(directories.iter().all(|directory| !directory.exists()));
        drop(directories);
        assert_eq!(
            factory
                .sources()
                .source
                .as_ref()
                .expect("restored source")
                .continuation()
                .nodes(),
            original_roster
        );

        let mut lifecycle = match factory
            .try_start(
                &input,
                &execution_context(&input, 0x90 + failure_index as u8),
            )
            .expect("restored source retry")
        {
            QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
            QemuHotForkWorldLifecycleStart::Declined => panic!("restored source declined"),
        };
        QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown retry world");
        reconcile_canceled_world(&mut lifecycle);
        assert!(factory.recover(lifecycle).is_ok());
        assert!(factory.sources().available());
    }
}

#[test]
fn production_three_node_ambiguous_launch_is_fail_closed_at_every_index() {
    for failure_index in 0..3 {
        let (source_processes, _roster, source_world) =
            three_source_world(failure_index, QemuTestHotForkOutcome::Indeterminate);
        let input = execution_input();
        let observations = ScriptedWorldObservations::new();
        let run_state = tempfile::tempdir().expect("run state");
        let mut factory = factory(
            source_world,
            input.lineage(),
            run_state.path().to_path_buf(),
            observations.clone(),
        );

        assert!(matches!(
            factory.try_start(
                &input,
                &execution_context(&input, 0xa0 + failure_index as u8)
            ),
            Err(AttemptWorkerFailure::Retryable(
                QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
            ))
        ));
        assert!(!factory.sources().available());
        assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
        assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
        for process in source_processes {
            assert_process_alive(process);
        }
        let children = observations
            .retained_child_processes
            .lock()
            .expect("retained child registry");
        assert_eq!(children.len(), failure_index);
        assert!(
            children
                .iter()
                .copied()
                .all(|process| { PathBuf::from("/proc").join(process.to_string()).exists() })
        );
        assert!(
            observations
                .guard_liveness
                .lock()
                .expect("guard liveness registry")
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some()
        );
    }
}

#[test]
fn production_three_node_adoption_failure_retains_the_complete_world() {
    for failure_index in 0..3 {
        let (source_processes, _roster, mut source_world) =
            three_source_world(usize::MAX, QemuTestHotForkOutcome::Forked);
        let node = source_world.continuation().nodes()[failure_index]
            .node()
            .clone();
        source_world
            .replace_immutable_root_for_test(
                &node,
                ContentHash::from_bytes(format!("mismatch-{failure_index}").as_bytes()),
            )
            .expect("replace immutable root");
        let input = execution_input();
        let observations = ScriptedWorldObservations::new();
        let run_state = tempfile::tempdir().expect("run state");
        let mut factory = factory(
            source_world,
            input.lineage(),
            run_state.path().to_path_buf(),
            observations.clone(),
        );

        assert!(matches!(
            factory.try_start(
                &input,
                &execution_context(&input, 0xb0 + failure_index as u8)
            ),
            Err(AttemptWorkerFailure::Terminal(
                QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(_)
            ))
        ));
        assert!(!factory.sources().available());
        for process in source_processes {
            assert_process_alive(process);
        }
        let children = observations
            .retained_child_processes
            .lock()
            .expect("retained child registry");
        assert_eq!(children.len(), 3);
        assert!(
            children
                .iter()
                .copied()
                .all(|process| { PathBuf::from("/proc").join(process.to_string()).exists() })
        );
        assert!(
            observations
                .guard_liveness
                .lock()
                .expect("guard liveness registry")
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some()
        );
    }
}

#[test]
fn production_aggregate_release_failure_blocks_source_restore() {
    let (_source_processes, _roster, source_world) =
        three_source_world(1, QemuTestHotForkOutcome::RejectedOnce);
    let input = execution_input();
    let observations = ScriptedWorldObservations::new();
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

    let failure = factory
        .try_start(&input, &execution_context(&input, 0xc0))
        .err()
        .expect("aggregate release failure must reject restore");
    let AttemptWorkerFailure::Retryable(QemuProductionHotForkWorldLifecycleFactoryError::Assembly(
        message,
    )) = failure
    else {
        panic!("unexpected aggregate release disposition")
    };
    assert!(message.contains("aggregate target release failed after rollback"));
    assert!(!factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert!(
        observations
            .guard_liveness
            .lock()
            .expect("guard liveness registry")
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some()
    );
}

#[test]
fn production_source_identity_drift_blocks_restore_after_complete_rollback() {
    let (source_processes, _roster, source_world) =
        three_source_world(1, QemuTestHotForkOutcome::RejectedAfterSourceExit);
    let input = execution_input();
    let observations = ScriptedWorldObservations::new();
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = factory(
        source_world,
        input.lineage(),
        run_state.path().to_path_buf(),
        observations.clone(),
    );

    let failure = factory
        .try_start(&input, &execution_context(&input, 0xc1))
        .err()
        .expect("source identity drift must reject restore");
    let AttemptWorkerFailure::Retryable(QemuProductionHotForkWorldLifecycleFactoryError::Assembly(
        message,
    )) = failure
    else {
        panic!("unexpected source identity disposition")
    };
    assert!(message.contains("exact source-world reauthentication failed after rollback"));
    assert!(!factory.sources().available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
    assert_process_alive(source_processes[0]);
    assert_process_alive(source_processes[2]);
    assert!(
        observations
            .guard_liveness
            .lock()
            .expect("guard liveness registry")
            .as_ref()
            .and_then(Weak::upgrade)
            .is_none()
    );
}
