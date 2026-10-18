//! Actual root/checkpoint dirty-consumer overlap and unpublished candidate abort.
//!
//! This separate ignored profile reuses the existing production paging guest,
//! 64 MiB/one-CPU machine and actual scheduler continuation. It adds no operation
//! budget, checkpoint fiction or direct monitor capture bypass.

use super::super::super::hot_fork_native::native_repository;
use super::super::*;

#[test]
#[ignore = "requires paired native Source/W, actual quota and coherent paged checkpoint admission"]
fn root_ack_and_failed_capture_preserve_independent_checkpoint_obligations() {
    let source = paging_scenario();
    environment::with_native_repository_environment(
        "write-oracle-consumers",
        37_200,
        |root, storage| native_repository(&source, root, storage),
        |config| config,
        |prepared, config, _repository| {
            let available = prepared
                .actor
                .with_supervisor(|actor| Ok(actor.host_resource_availability()))
                .expect("original actor")
                .expect("original full vector");
            run_capture(prepared, config, &source, |context| {
                let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
                    .expect("actual original physical namespace");
                let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
                    config.lifecycle.clone(),
                    ComposedQemuAttemptResourceGuardFactory::new(host),
                );
                let mut lifecycle = factory
                    .begin_fresh(&source.scenario_def(), &source, context)
                    .expect("actual admitted production guest and scheduler");
                let node = NodeId {
                    name: String::from("memory"),
                };
                let parent = lifecycle
                    .capture_portable_exact_checkpoint_with_boundary(&mut || Ok(()))
                    .expect("real durable parent capture");
                let parent_epoch = lifecycle
                    .checkpoint_consumer_epoch_for_test(&node)
                    .expect("actual committed checkpoint consumer");
                assert!(parent_epoch.committed().is_some());
                assert!(parent_epoch.candidate().is_none());
                let parent_ram = parent.ram_sources()[0].root().record().encode();
                drop(parent);

                let configuration = lifecycle
                    .resume_state()
                    .expect("genuine scheduler")
                    .into_parts()
                    .0;
                let outcome = QemuFreshAttemptLifecycleOwner::drive_quantum(
                    &mut lifecycle,
                    QuantumRequest {
                        configuration,
                        control: Vec::new(),
                    },
                )
                .expect("actual guest writes under unchanged quantum limits");
                let root = QemuFreshAttemptLifecycleOwner::sample_fingerprint(
                    &mut lifecycle,
                    node.clone(),
                )
                .expect("actual root-consumer acknowledgement");
                let after_root = lifecycle
                    .checkpoint_consumer_epoch_for_test(&node)
                    .expect("independent checkpoint epoch after root ACK");
                assert_eq!(after_root.committed(), parent_epoch.committed());
                assert_eq!(
                    after_root.committed_capture_generation(),
                    parent_epoch.committed_capture_generation()
                );
                assert!(after_root.candidate().is_none());

                let refused =
                    lifecycle.refuse_completed_capture_publication_for_test(&mut || Ok(()));
                assert!(
                    matches!(&refused, Err(SchedulerError::BoundaryViolation { message })
                    if message == "CPU oracle refused completed capture publication"),
                    "must reach completed native capture, not a pre-capture refusal: {refused:?}"
                );
                let aborted = lifecycle
                    .checkpoint_consumer_epoch_for_test(&node)
                    .expect("actual abort cleanup and retained parent");
                assert_eq!(aborted.committed(), parent_epoch.committed());
                assert_eq!(
                    aborted.committed_capture_generation(),
                    parent_epoch.committed_capture_generation()
                );
                assert!(aborted.candidate().is_none());
                assert_eq!(
                    lifecycle
                        .resume_state()
                        .expect("same scheduler after failed publication")
                        .into_parts()
                        .0,
                    outcome.configuration
                );

                let successor = lifecycle
                    .capture_portable_exact_checkpoint_with_boundary(&mut || Ok(()))
                    .expect("same boundary completes genuine capture after aborted publication");
                assert_ne!(
                    successor.ram_sources()[0].root().record().encode(),
                    parent_ram,
                    "the real guest boundary must carry changed RAM, not only a CPU coordinate"
                );
                let committed = lifecycle
                    .checkpoint_consumer_epoch_for_test(&node)
                    .expect("actual next durable checkpoint epoch");
                assert_ne!(committed.committed(), parent_epoch.committed());
                assert!(
                    committed.committed_capture_generation()
                        > parent_epoch.committed_capture_generation()
                );
                assert!(committed.candidate().is_none());
                let successor_root =
                    QemuFreshAttemptLifecycleOwner::sample_fingerprint(&mut lifecycle, node)
                        .expect("root consumer after checkpoint commit");
                assert_eq!(
                    successor_root.fingerprint, root.fingerprint,
                    "captures/abort/commit cannot change logical RAM at the same guest boundary"
                );
                drop(successor);
                QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
                    .expect("actual child and original source cleanup");
                Ok(())
            })
            .expect("same original capture service physically closes");
            let restored = prepared
                .actor
                .with_supervisor(|actor| Ok(actor.host_resource_availability()))
                .expect("same actor after cleanup")
                .expect("same full vector");
            assert_eq!(available, restored);
        },
    );
}
