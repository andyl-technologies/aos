//! Seven genuine source-object refusals before any native child is exposed.
//!
//! Every duplicate comes from the authenticated live source and borrows its
//! original allocator. Uncertain monitor custody survives until physical source
//! reap; failed reap retains the complete actual source and Service reservation.

use super::*;
use crate::packaged_qemu_executor::hot_fork::retained_service::RetainedTemplateService;
use crucible_qemu::{QemuTestNativeAliasKind, QemuTestNativeAliasProbeError};

const CASES: [(QemuTestNativeAliasKind, &str); 7] = [
    (QemuTestNativeAliasKind::Ring, "private-ring-source-aliased"),
    (
        QemuTestNativeAliasKind::Control,
        "plugin-control-source-aliased",
    ),
    (QemuTestNativeAliasKind::Wake, "plugin-wake-source-aliased"),
    (
        QemuTestNativeAliasKind::ConsoleDiagnostics,
        "console-diagnostic-source-aliased",
    ),
    (
        QemuTestNativeAliasKind::WritableDisk,
        "writable-vmstate-source-aliased",
    ),
    (
        QemuTestNativeAliasKind::NetworkScope,
        "network-reader-ring-scope-aliased",
    ),
    (
        QemuTestNativeAliasKind::NinepScope,
        "ninep-reader-ring-scope-aliased",
    ),
];

pub(super) fn run(
    model: &mut MixedResume<'_>,
    mut world: ProductionVmHotForkSourceWorld,
    service: Arc<RetainedTemplateService>,
    before_source: HostResourceVector,
    source_processes: &[crucible_qemu::QemuProcessIdentity],
) {
    let owner = world
        .continuation()
        .io_nodes()
        .iter()
        .find(|node| node.kind() == ProductionVmHotForkIoNodeKind::NineP)
        .expect("reviewed traffic world has a live 9p reader owner")
        .owner()
        .clone();
    let expected_process = world
        .prepared_source(&owner)
        .expect("actual retained reader source")
        .process_identity()
        .clone();
    assert!(source_processes.contains(&expected_process));
    reset_hot_fork_adoption_count_for_test();
    let mut expected_template = None;
    let mut failure: Option<QemuTestNativeAliasProbeError> = None;
    let mut completed = Vec::new();

    for (kind, label) in CASES {
        let mut prepared = world
            .prepared_source(&owner)
            .expect("original native source and template remain authenticated");
        let allocator = prepared
            .host_service_allocator_for_test()
            .expect("share actual node-local charged descriptor allocator");
        match prepared.probe_native_source_isolation_for_test(kind, &allocator) {
            Ok(report) => {
                assert_eq!(report.kind, kind);
                assert_eq!(report.source, expected_process);
                assert!(report.template_generation > 0);
                if let Some(template) = expected_template {
                    assert_eq!(report.template_generation, template);
                } else {
                    expected_template = Some(report.template_generation);
                }
                assert_eq!(hot_fork_adoption_count_for_test(), 0);
                completed.push((label, report.rejection.to_string()));
            }
            Err(error) => {
                // The error can own an imported FD and its actual permit. Keep
                // it until source reap makes an uncertain native alias terminal.
                failure = Some(error);
                break;
            }
        }
    }

    if let Some(error) = failure {
        let message = error.to_string();
        let mut parent = match world.recover() {
            Ok(parent) => parent,
            Err(rollback) => {
                let _retained_actual_custody = Box::leak(Box::new((rollback, service, error)));
                panic!("actual isolation probe failed and rollback remains held: {message}");
            }
        };
        if let Err(cleanup) = parent.shutdown() {
            let _retained_actual_custody = Box::leak(Box::new((parent, service, error)));
            panic!(
                "actual isolation probe failed and physical cleanup remains held: {cleanup}; {message}"
            );
        }
        // Reap proves every native alias terminal. Close the retained host FD
        // and original permit before the Service can discharge its real actor.
        drop(error);
        service
            .release_after_world_cleanup()
            .expect("failed qualification still closes actual source borrowers and watchdog");
        assert_eq!(available_resources(model.prepared), before_source);
        panic!("actual native isolation qualification failed: {message}");
    }

    for process in source_processes {
        assert_eq!(
            linux_process_identity(process.process_id)
                .expect("actual source identity lookup")
                .expect("source survives isolation refusal"),
            *process,
        );
    }
    let mut parent = world
        .recover()
        .expect("retained native source world recovery");
    let after = mixed_boundary(&mut parent, model.boundary.configuration.clone());
    assert_eq!(after.fingerprints, model.boundary.fingerprints);
    assert_eq!(after.faults, model.boundary.faults);
    assert_eq!(hot_fork_adoption_count_for_test(), 0);
    if let Err(error) = parent.shutdown() {
        let _retained_actual_custody = Box::leak(Box::new((parent, service)));
        panic!("isolation probe cannot discharge source cleanup: {error}");
    }
    service
        .release_after_world_cleanup()
        .expect("source FD borrowers and original watcher fully closed");
    assert_eq!(available_resources(model.prepared), before_source);

    assert_eq!(completed.len(), 7);
    for (label, rejection) in &completed {
        println!("native_negative_isolation_case={label}");
        println!("native_negative_isolation_lower_rejection[{label}]={rejection}");
    }
    let labels = completed
        .iter()
        .map(|(label, _)| *label)
        .collect::<Vec<_>>();
    println!("native_negative_isolation_matrix={}", labels.join(","));
    println!(
        "native_negative_isolation_rejected_before=native-fork,child-readiness,resume,world-publication"
    );
    println!("native_negative_isolation_source_unchanged=true");
    println!(
        "native_negative_isolation_mechanisms=authenticated-pidfd-getfd,native-stage-query,monitor-closefd,host-reader-guard"
    );
    model.completed = true;
}
