//! Exercises consuming retirement against actual initial and restored Root custody.

// crucible-lint: allow panic-shortcut -- Actual native lifecycle failures retain the owning supervisor and stop the original witness.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    os::unix::fs::PermissionsExt,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible::node_state::{
    NativeArchive, NativeArchiveLimits, RestorePublication, StateLimits, StateRequirements,
    StateRestoreMode, stage_restore,
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::{Id, Phase, Position, U64};

use super::super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, measure_executable,
};
use crate::node_observed_executor::StoredWorldActivationPublisher;

use super::{
    InstalledRootRetirement, installed::RootInstalledEngine, tests::FailedWitnessSupervision,
};

#[test]
#[ignore = "requires the actual installed Root model, complete public preparation and independent native restore audit"]
fn actual_initial_and_restored_retirement_preserve_custody_until_namespace_release() {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = directory.canonicalize().unwrap();
    let companion = std::path::PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE")
            .expect("actual installed companion is required"),
    );
    let mut catalog = InstalledNodeCatalog::new(
        companion.clone(),
        measure_executable(&companion).unwrap(),
        directory.clone(),
        Duration::from_secs(30),
        8,
    )
    .unwrap();
    let engine =
        RootInstalledEngine::with_runtime(directory.clone(), catalog.custody().clone()).unwrap();
    let _supervision = FailedWitnessSupervision(&engine);
    let selections = selections();
    let scenario = catalog.scenario(&selections).unwrap();
    let prepared = catalog
        .prepare_root_native_world(
            &selections,
            scenario,
            crucible_campaign::ExecutionId::from_bytes([95; 16]).unwrap(),
        )
        .unwrap();
    let source_namespace = prepared.preservation.namespace.clone();
    let target = prepared.world.realization.activation_record().clone();
    let graph = Rc::new(prepared.world.graph);
    let mut runtime = prepared
        .world
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let preparations = runtime.prepared_node_records().unwrap().to_vec();
    let coordinator = runtime
        .initial_coordinator_snapshot(&graph, 16 * 1024 * 1024)
        .unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "root-retirement",
        directory.join("cas"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let stored = publisher(&blobs, &refs, "initial")
        .with_prepared_coordinator(target, preparations, coordinator)
        .unwrap();
    let mut initial_publisher = prepared.preservation.publisher(stored).unwrap();
    let activation = runtime.activate(initial_publisher.as_mut()).unwrap();
    assert_eq!(activation.prepared_owners().unwrap().len(), 2);
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }

    let archive = NativeArchive::open(directory.join("archive"), limits()).unwrap();
    let factory = prepared.preservation.factory();
    let immutable = prepared.preservation.immutable();
    let record = archive
        .capture_world_typed(
            &graph,
            &mut runtime,
            &activation,
            Position::new(0.into(), 0.into(), Phase::BoundaryControl),
            U64::new(2),
            id("retirement/source"),
            requirements(),
            immutable.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let artifact = record.artifact().clone();
    drop(immutable);
    drop(factory);
    let retirement = prepared
        .preservation
        .begin_retirement(runtime, &graph, &activation)
        .unwrap();
    assert!(source_namespace.is_dir());
    finish_retirement(retirement, &source_namespace);
    assert!(!source_namespace.exists());
    drop(initial_publisher);
    drop(activation);
    drop(graph);
    drop(record);

    let record = archive.load(&artifact).unwrap();
    let mut unused = catalog
        .prepare_root_native_restore(&selections, record.clone())
        .unwrap();
    let unused_namespace = unused.namespace.clone();
    let original_target = unused.target.clone();
    let original_factory = unused.factory.clone();
    unused.target.activation_id = id("retirement/foreign-target");

    let failure = unused.begin_unstarted_retirement().unwrap_err();
    assert!(unused_namespace.is_dir());
    assert!(Rc::ptr_eq(&failure.restore.factory, &original_factory));
    let mut unused = failure.restore;
    unused.target = original_target;
    let retirement = unused.begin_unstarted_retirement().unwrap();
    finish_retirement(retirement, &unused_namespace);
    assert!(!unused_namespace.exists());
    drop(original_factory);

    let plan = catalog
        .prepare_root_native_restore(&selections, record.clone())
        .unwrap();
    let restored_namespace = plan.namespace.clone();
    let factory = plan.factory();
    let verified = record
        .admit(&plan.graph, requirements(), factory.as_ref())
        .unwrap();
    let mut driver = plan.driver().unwrap();
    let prepared = stage_restore(
        &plan.graph,
        verified,
        plan.target.clone(),
        &mut driver,
        limits().state,
    )
    .unwrap_or_else(|failure| panic!("{}", failure.error));
    let mut publisher = plan
        .publisher(publisher(&blobs, &refs, "restored"))
        .unwrap();
    let RestorePublication::Committed(restored) = prepared.publish(publisher.as_mut()) else {
        panic!("actual complete restored publication did not commit");
    };
    assert_eq!(restored.activation().prepared_owners().unwrap().len(), 2);
    drop(driver);
    drop(factory);
    drop(publisher);
    // The actual factory consumed its lease during staging. A missing cold
    // plan cannot be relabeled as unused, even while the real world is retained.
    let original_factory = plan.factory.clone();
    let failure = plan.begin_unstarted_retirement().unwrap_err();
    assert!(
        failure
            .error
            .to_string()
            .contains("already entered staging")
    );
    assert!(Rc::ptr_eq(&failure.restore.factory, &original_factory));
    assert!(restored_namespace.is_dir());
    drop(original_factory);
    let retirement = failure.restore.begin_retirement(*restored).unwrap();
    assert!(restored_namespace.is_dir());
    finish_retirement(retirement, &restored_namespace);
    assert!(!restored_namespace.exists());
    assert!(directory.join("archive").is_dir());
    assert!(directory.join("cas").is_dir());
}

fn finish_retirement(retirement: InstalledRootRetirement, namespace: &std::path::Path) {
    // A returned retirement handle is not a cleanup proof. The failed release
    // returns that exact owner, which remains usable for original queue polling.
    let failure = retirement.release_namespace().unwrap_err();
    assert!(namespace.is_dir());
    let mut retirement = failure.retirement;
    let mut context = Context::from_waker(Waker::noop());
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(180)).unwrap();
    loop {
        match retirement.poll_reclamation(&mut context) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(error)) => panic!("{error}"),
            Poll::Pending => {}
        }
        assert!(!deadline.expired(), "original retirement did not reclaim");
        deadline.pause(Duration::from_millis(10));
    }
    assert!(namespace.is_dir());
    retirement.release_namespace().unwrap();
}

fn selections() -> Vec<InstalledNodeSelection> {
    vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("root"),
            owner: id("owner/root"),
            kind: InstalledNodeKind::Gem5ArmRoot,
        },
    ]
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn publisher(
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
) -> StoredWorldActivationPublisher {
    StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new(format!("node-world-activations/root-retirement-{name}")).unwrap(),
    )
    .unwrap()
}

fn requirements() -> StateRequirements {
    StateRequirements {
        preservation_contract: id("arm-root/native-preservation-v2"),
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    }
}

fn limits() -> NativeArchiveLimits {
    NativeArchiveLimits {
        state: StateLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_native_processes: 8192,
            ..StateLimits::default()
        },
        native: crucible::node_contract::NativeCaptureLimits {
            maximum_objects: 20_000,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_total_record_bytes: 64 * 1024 * 1024,
            maximum_artifact_bytes: 2 * 1024 * 1024 * 1024,
            maximum_total_artifact_bytes: 8 * 1024 * 1024 * 1024,
        },
    }
}
