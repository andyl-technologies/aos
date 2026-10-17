//! Exercises signed Root/Clock reconstruction with actual public preparations.

// crucible-lint: allow panic-shortcut -- Genuine native witness failures must retain the original owning supervisors while reporting the violated invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    os::unix::fs::PermissionsExt,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{BeginResult, NodeRuntime, OperationOutcome, OperationToken},
    node_state::{
        NativeArchive, NativeArchiveLimits, NativeArchiveRecord, NativeWorldRestoreDriver,
        RestorePublication, RestoredWorld, StateLimits, StateRequirements, StateRestoreMode,
        stage_restore,
    },
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::{Id, Phase, Position, U64};

use super::{
    factory::RootNativeFactory, installed::RootInstalledEngine, publication::RootPublisher,
    tests::FailedWitnessSupervision,
};
use crate::node_observed_executor::StoredWorldActivationPublisher;

#[test]
#[ignore = "requires the actual installed Root model, opaque native audit and three supervised peers"]
fn actual_root_clock_original_permission_survives_restored_recapture_and_namespace_death() {
    run_root_ancestry(false);
}

#[test]
#[ignore = "requires the ordinary installed catalog, actual Root model and independently measured companion"]
fn actual_ordinary_root_catalog_preserves_original_permission_through_three_generations() {
    run_root_ancestry(true);
}

fn run_root_ancestry(public: bool) {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = directory.canonicalize().unwrap();
    let mut catalog = public.then(|| {
        let companion = std::path::PathBuf::from(
            std::env::var_os("CRUCIBLE_REFERENCE_DEVICE")
                .expect("actual independently installed companion is required"),
        );
        super::super::InstalledNodeCatalog::new(
            companion.clone(),
            super::super::measure_executable(&companion).unwrap(),
            directory.clone(),
            Duration::from_secs(30),
            8,
        )
        .unwrap()
    });
    let engine = match &catalog {
        Some(catalog) => {
            RootInstalledEngine::with_runtime(directory.clone(), catalog.custody().clone()).unwrap()
        }
        None => RootInstalledEngine::new(directory.clone()).unwrap(),
    };
    let _supervision = FailedWitnessSupervision(&engine);
    let (graph, target, namespace, realization, factory) = match &mut catalog {
        Some(catalog) => {
            let selections = root_selections();
            let scenario = catalog.scenario(&selections).unwrap();
            assert!(!directory.read_dir().unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("root-")
            }));
            let prepared = catalog
                .prepare_root_native_world(
                    &selections,
                    scenario,
                    crucible_campaign::ExecutionId::from_bytes([94; 16]).unwrap(),
                )
                .unwrap();
            let target = prepared.world.realization.activation_record().clone();
            (
                Rc::new(prepared.world.graph),
                target,
                prepared.preservation.namespace,
                prepared.world.realization,
                prepared.preservation.factory,
            )
        }
        None => {
            let live = engine.prepare_initial().unwrap();
            let factory = Rc::new(RootNativeFactory::for_live(&live, engine.native.clone()));
            (
                live.graph,
                live.target,
                live.namespace,
                live.realization,
                factory,
            )
        }
    };
    let mut runtime = realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let preparations = runtime.prepared_node_records().unwrap().to_vec();
    let coordinator = runtime
        .initial_coordinator_snapshot(&graph, 16 * 1024 * 1024)
        .unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "root-public-cold",
        directory.join("cas"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let stored = publisher(&blobs, &refs, "root-source")
        .with_prepared_coordinator(target.clone(), preparations, coordinator)
        .unwrap();
    let mut publisher = RootPublisher::for_initial(stored, engine.native.clone());
    let activation = runtime.activate(&mut publisher).unwrap();
    assert_eq!(activation.prepared_owners().unwrap().len(), 2);
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }

    // Both independent owners reach the same exclusive physical boundary under
    // their actual original permissions. The fixed root is closed to ingress,
    // so this prefix cannot bypass an earlier input from another owner.
    let common = Position::new(1_000_000_000.into(), 0.into(), Phase::BoundaryControl);
    let root_bootstrap = advance_and_acknowledge(
        &mut runtime,
        &graph,
        &activation,
        "root",
        "original/root-bootstrap",
        common,
    );
    let clock = advance_and_acknowledge(
        &mut runtime,
        &graph,
        &activation,
        "clock",
        "original/clock-common-cut",
        common,
    );
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
        assert_eq!(
            runtime
                .scheduler(&graph, &activation)
                .unwrap()
                .position(node)
                .unwrap(),
            common,
        );
    }

    let grant = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(
            &id("root"),
            id("original/root-serial"),
            2_000_000_000.into(),
        )
        .unwrap();
    let BeginResult::Accepted(original) = runtime.begin_admitted(grant).unwrap() else {
        panic!("actual Root original grant was refused");
    };
    let held = finish(&mut runtime, &original);
    let serial = &held.scheduling.as_ref().unwrap().publications;
    assert_eq!(serial.len(), 1);
    assert_eq!(serial[0].payload_bytes, [91]);
    assert!(serial[0].causal_parents.is_empty());
    let cut = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .position(&id("clock"))
        .unwrap();
    assert_eq!(cut, common);
    let ordinal = U64::new(17);
    let before = runtime
        .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
        .unwrap();
    assert_eq!(before.operations.len(), 3);
    assert!(before.inputs.is_empty());
    let limits = limits();
    let archive_path = directory.join("native-archive");
    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let record = archive
        .capture_world_typed(
            &graph,
            &mut runtime,
            &activation,
            cut,
            ordinal,
            id("root-original-capture"),
            requirements(),
            &factory.immutable(),
            factory.as_ref(),
        )
        .unwrap();
    assert_eq!(record.runtime_snapshot().unwrap(), before);
    assert_eq!(record.owners().len(), 2);
    let artifact = record.artifact().clone();
    drop(original);
    drop(clock);
    drop(root_bootstrap);
    drop(runtime);
    drop(activation);
    drop(publisher);
    drop(factory);
    drop(graph);
    reclaim(&engine);
    std::fs::remove_dir_all(&namespace).unwrap();
    assert!(!namespace.exists());
    drop(record);
    drop(archive);

    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let (mut left, left_factory, left_namespace, second_graph) = restore(
        &engine,
        catalog.as_mut(),
        record.clone(),
        &blobs,
        &refs,
        "root-left",
        limits,
    );
    let (mut right, right_factory, right_namespace, _) = restore(
        &engine,
        catalog.as_mut(),
        record.clone(),
        &blobs,
        &refs,
        "root-right",
        limits,
    );
    assert_ne!(
        left.activation().record().owners,
        right.activation().record().owners
    );
    for fresh in [&left, &right] {
        assert_eq!(fresh.activation().record().boundary, cut);
        assert_eq!(fresh.activation().prepared_owners().unwrap().len(), 2);
        assert!(fresh.activation().coordinator_snapshot().is_some());
    }
    {
        let fresh = &mut right;
        let saved = fresh
            .runtime_mut()
            .runtime_snapshot(cut, ordinal, 16 * 1024 * 1024)
            .unwrap();
        assert!(saved.inputs.is_empty());
        for original in &before.operations {
            let current = saved
                .operations
                .iter()
                .find(|current| current.operation == original.operation)
                .unwrap();
            assert_eq!(current.request, original.request);
            assert_eq!(current.scheduling_commit, original.scheduling_commit);
        }
        let token = fresh
            .runtime_mut()
            .recover(&id("original/root-serial"))
            .unwrap();
        let outcome = finish(fresh.runtime_mut(), &token);
        assert_eq!(outcome.scheduling.as_ref().unwrap().publications, *serial);
        let receipt = fresh.runtime_mut().scheduling_receipt(&token).unwrap();
        let commit = fresh
            .runtime_mut()
            .commit_scheduling_receipt(receipt)
            .unwrap();
        fresh
            .runtime_mut()
            .acknowledge_scheduled(&token, &commit)
            .unwrap();
        assert!(fresh.runtime_mut().arm_all().is_err());
    }
    assert_archive_descriptors_are_shared(&directory.join("native-archive"), &record);

    // The left world still owns the exact held original prefix. Recapture uses
    // this fresh peer and its current public preparation, while the old request
    // and raw prefix scope remain unchanged signed ancestry.
    let second_activation = left.activation().clone();
    let second_ordinal = U64::new(18);
    let second_before = left
        .runtime_mut()
        .runtime_snapshot(cut, second_ordinal, 16 * 1024 * 1024)
        .unwrap();
    let second = archive
        .capture_world_typed(
            &second_graph,
            left.runtime_mut(),
            &second_activation,
            cut,
            second_ordinal,
            id("root-restored-recapture"),
            requirements(),
            &left_factory.immutable(),
            left_factory.as_ref(),
        )
        .unwrap();
    assert!(
        second
            .runtime_snapshot()
            .unwrap()
            .source_activation
            .generation
            > before.source_activation.generation
    );
    let second_artifact = second.artifact().clone();
    drop(second_activation);
    drop(left);
    drop(right);
    drop(left_factory);
    drop(right_factory);
    reclaim(&engine);
    for root in [&left_namespace, &right_namespace] {
        std::fs::remove_dir_all(root).unwrap();
        assert!(!root.exists());
    }
    drop(second);
    drop(archive);

    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let second = archive.load(&second_artifact).unwrap();
    let (mut third, third_factory, _, _) = restore(
        &engine,
        catalog.as_mut(),
        second,
        &blobs,
        &refs,
        "root-third",
        limits,
    );
    let third_activation = third.activation().clone();
    assert!(third_activation.record().generation > second_before.source_activation.generation);
    let third_saved = third
        .runtime_mut()
        .runtime_snapshot(cut, second_ordinal, 16 * 1024 * 1024)
        .unwrap();
    for original in &second_before.operations {
        let current = third_saved
            .operations
            .iter()
            .find(|current| current.operation == original.operation)
            .unwrap();
        assert_eq!(current.request, original.request);
        assert_eq!(current.scheduling_commit, original.scheduling_commit);
    }
    let token = third
        .runtime_mut()
        .recover(&id("original/root-serial"))
        .unwrap();
    let original = finish(third.runtime_mut(), &token);
    assert_eq!(original.scheduling.as_ref().unwrap().publications, *serial);
    let receipt = third.runtime_mut().scheduling_receipt(&token).unwrap();
    let commit = third
        .runtime_mut()
        .commit_scheduling_receipt(receipt)
        .unwrap();
    third
        .runtime_mut()
        .acknowledge_scheduled(&token, &commit)
        .unwrap();
    assert!(third.runtime_mut().arm_all().is_err());
    drop(third_activation);
    drop(third);
    drop(third_factory);
    reclaim(&engine);
}

fn restore(
    engine: &RootInstalledEngine,
    catalog: Option<&mut super::super::InstalledNodeCatalog>,
    record: NativeArchiveRecord,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
    limits: NativeArchiveLimits,
) -> (
    Box<RestoredWorld>,
    Rc<RootNativeFactory>,
    std::path::PathBuf,
    Rc<AdmittedGraph>,
) {
    let (namespace, graph, target, factory, public_plan) = match catalog {
        Some(catalog) => {
            let plan = catalog
                .prepare_root_native_restore(&root_selections(), record.clone())
                .unwrap();
            (
                plan.namespace.clone(),
                plan.graph.clone(),
                plan.target.clone(),
                plan.factory.clone(),
                Some(plan),
            )
        }
        None => {
            let plan = engine.prepare_cold(record.clone()).unwrap();
            let namespace = plan.namespace.clone();
            let graph = plan.graph.clone();
            let target = plan.target.clone();
            let factory = Rc::new(RootNativeFactory::for_cold(plan, engine.native.clone()));
            (namespace, graph, target, factory, None)
        }
    };
    let verified = record
        .admit(&graph, requirements(), factory.as_ref())
        .unwrap();
    let mut driver = match &public_plan {
        Some(plan) => plan.driver().unwrap(),
        None => NativeWorldRestoreDriver::new(
            graph.clone(),
            record.clone(),
            factory.clone(),
            engine.runtime.clone(),
        )
        .unwrap(),
    };
    let prepared = stage_restore(&graph, verified, target.clone(), &mut driver, limits.state)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    let mut publisher: Box<dyn crucible::node_contract::ActivationPublisher> = match &public_plan {
        Some(plan) => plan.publisher(publisher(blobs, refs, name)).unwrap(),
        None => Box::new(
            RootPublisher::for_restore(
                publisher(blobs, refs, name),
                engine.native.clone(),
                &record,
                &target,
            )
            .unwrap(),
        ),
    };
    let RestorePublication::Committed(restored) = prepared.publish(publisher.as_mut()) else {
        panic!("actual complete Root restored publication did not commit");
    };
    (restored, factory, namespace, graph)
}

fn advance_and_acknowledge(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &crucible::node_contract::WorldActivation,
    node: &str,
    operation: &str,
    expected: Position,
) -> OperationToken {
    let grant = runtime
        .scheduler(graph, activation)
        .unwrap()
        .admit_exact(&id(node), id(operation), expected.time_ps)
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("actual original common-cut grant was refused");
    };
    let outcome = finish(runtime, &token);
    assert_eq!(
        outcome.progress,
        crucible::node_contract::ProgressEvidence::Exact {
            reached: expected,
            stop: crucible::node_contract::StopReason::HorizonPark,
        },
    );
    assert!(outcome.scheduling.as_ref().unwrap().publications.is_empty());
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    token
}

fn finish(runtime: &mut NodeRuntime, token: &OperationToken) -> OperationOutcome {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        match runtime.poll(token, &mut context) {
            Poll::Pending => {}
            Poll::Ready(Ok(outcome)) => return outcome,
            Poll::Ready(Err(error)) => panic!("actual Root original operation failed: {error}"),
        }
    }
    panic!("actual Root original permission exceeded its finite prefix budget");
}

fn reclaim(engine: &RootInstalledEngine) {
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(120)).unwrap();
    while !engine.poll_reclamation().unwrap() {
        assert!(
            !deadline.expired(),
            "actual original Root groups did not reclaim"
        );
        deadline.pause(Duration::from_millis(10));
    }
}

fn publisher(
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
) -> StoredWorldActivationPublisher {
    StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new(format!("node-world-activations/{name}")).unwrap(),
    )
    .unwrap()
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
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

fn root_selections() -> Vec<super::super::InstalledNodeSelection> {
    vec![
        super::super::InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: super::super::InstalledNodeKind::HostClock,
        },
        super::super::InstalledNodeSelection {
            node: id("root"),
            owner: id("owner/root"),
            kind: super::super::InstalledNodeKind::Gem5ArmRoot,
        },
    ]
}

fn assert_archive_descriptors_are_shared(archive: &std::path::Path, source: &NativeArchiveRecord) {
    let original = source
        .owners()
        .iter()
        .find(|owner| owner.owner.as_str() == "owner/root")
        .unwrap();
    let mut expected = std::collections::BTreeMap::new();
    for artifact in &original.artifacts {
        let path = archive.join(format!("{}.native-object-v1", artifact.content.hash.digest));
        *expected.entry(path).or_insert(0usize) += 1;
    }
    let mut counts = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
        let path = entry.unwrap().path();
        let Ok(target) = std::fs::read_link(path) else {
            continue;
        };
        if target.starts_with(archive)
            && target
                .file_name()
                .is_some_and(|leaf| leaf.to_string_lossy().ends_with(".native-object-v1"))
        {
            *counts.entry(target).or_insert(0usize) += 1;
        }
    }
    assert!(
        !counts.is_empty(),
        "original archive descriptors must remain pinned"
    );
    // Distinct signed roles may share bytes. Each role remains credited and
    // retained; sibling worlds must not reopen an additional copy of that roster.
    assert_eq!(counts, expected);
}
