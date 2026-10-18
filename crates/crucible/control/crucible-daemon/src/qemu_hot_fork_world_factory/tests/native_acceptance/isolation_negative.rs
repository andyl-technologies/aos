//! Native production-factory rejection matrix for corrupted child isolation.

// crucible-lint: allow panic-shortcut -- native gate assertions use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;

const ISOLATION_FAULTS: [QemuTestHotForkIsolationFault; 7] = [
    QemuTestHotForkIsolationFault::PrivateRingOmitted,
    QemuTestHotForkIsolationFault::ControlAliased,
    QemuTestHotForkIsolationFault::ConsoleDiagnosticsAliased,
    QemuTestHotForkIsolationFault::WritableDiskBackingAliased,
    QemuTestHotForkIsolationFault::NetworkOmitted,
    QemuTestHotForkIsolationFault::NinepAliased,
    QemuTestHotForkIsolationFault::HostContinuationIdentityAliased,
];

#[test]
#[ignore = "run by the native hot-fork isolation gate"]
fn production_factory_rejects_the_complete_isolation_negative_matrix_before_readiness() {
    for (index, fault) in ISOLATION_FAULTS.into_iter().enumerate() {
        let source =
            scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::IsolationRejected(fault))
                .expect("scripted production source");
        let source_process = source.process_id();
        let source_identity = linux_process_identity(source_process)
            .expect("inspect source identity before rejection")
            .expect("source process before rejection");
        let (_nodes, source_world) =
            prepared_test_source_world(vec![source]).expect("prepared production source world");
        let input = execution_input();
        let context =
            native_execution_context(&input, 0x90 + u8::try_from(index).expect("matrix index"));
        let observations = ScriptedWorldObservations::new();
        let run_state = tempfile::tempdir().expect("isolation run state");
        let mut factory = super::super::reconciliation::factory(
            source_world,
            input.lineage(),
            run_state.path().to_path_buf(),
            observations.clone(),
        );

        reset_hot_fork_adoption_count_for_test();
        let failure = match factory.try_start(&input, &context) {
            Err(failure) => failure,
            Ok(_) => panic!("{} unexpectedly exposed a world", fault.label()),
        };

        let AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message),
        ) = failure
        else {
            panic!("{} produced the wrong failure class", fault.label());
        };
        assert!(
            message.contains(fault.label()),
            "missing fault label: {message}"
        );
        assert_eq!(hot_fork_adoption_count_for_test(), 0);
        assert!(
            factory.sources.available(),
            "source lost for {}",
            fault.label()
        );
        assert_eq!(observations.finishes.load(Ordering::SeqCst), 1);
        assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
        assert!(
            observations
                .retained_child_processes
                .lock()
                .expect("retained child registry")
                .is_empty(),
            "{} reached child process retention",
            fault.label(),
        );
        assert_eq!(
            linux_process_identity(source_process)
                .expect("inspect source identity after rejection")
                .expect("source process after rejection"),
            source_identity,
            "{} changed the source process incarnation",
            fault.label(),
        );
        let prepared = observations
            .prepared_run_directories
            .lock()
            .expect("prepared run-directory registry");
        assert_eq!(prepared.len(), 1);
        assert!(
            !prepared[0].exists(),
            "{} leaked target storage",
            fault.label()
        );
        drop(prepared);
        assert!(
            observations
                .guard_liveness
                .lock()
                .expect("guard liveness registry")
                .as_ref()
                .and_then(Weak::upgrade)
                .is_none(),
            "{} retained a partial target world",
            fault.label(),
        );
    }

    println!(
        "native_negative_isolation_matrix=private-ring-omitted,qmp-control-aliased,console-diagnostics-aliased,writable-disk-backing-aliased,network-omitted,ninep-aliased,host-continuation-identity-aliased"
    );
    println!("native_negative_isolation_rejected_before=child-readiness,resume,world-publication");
    println!("native_negative_isolation_source_unchanged=true");
}
