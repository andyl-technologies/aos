//! Exercises the actual installed Clock codec and independent durable branches.
//!
//! Admission uses locally regenerated policy and genuinely enrolled Clock
//! resources. No model graph, test-double native qualification or imported
//! caller-issued authority participates in this witness.

// crucible-lint: allow panic-shortcut -- These actual native Clock witnesses deliberately panic on failed installation, capture or fresh continuation invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{BeginResult, NodeRuntime, OperationOutcome, WorldActivation},
    node_state::{
        NativeArchive, NativeArchiveLimits, NativeArchiveRecord, NativeWorldRestoreDriver,
        RestorePublication, RestoredWorld, StateRequirements, StateRestoreMode, stage_restore,
    },
};
use crucible_campaign::ExecutionId;
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::{Id, Phase, Position, U64};

use super::super::{InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection};
use super::*;

fn resolve(catalog: &InstalledNodeCatalog) -> ResolvedCapabilityWorld {
    let selections = vec![InstalledNodeSelection {
        node: id("clock"),
        owner: id("owner/clock"),
        kind: InstalledNodeKind::HostClock,
    }];
    let baseline = catalog.scenario(&selections).unwrap();
    let mut demand = super::tests::requirements(&baseline);
    let facet = baseline.compatibility[0]
        .operating_contract
        .facets
        .iter()
        .find(|facet| facet.id.as_str() == "host/preservation-v1")
        .unwrap()
        .clone();
    demand.nodes[0].guarantees.durable_restart = true;
    for operation in ["capture", "durable_restart"] {
        demand.nodes[0]
            .operations
            .push(crucible::node_admission::OperationRequirement {
                operation: id(operation),
                facet: facet.clone(),
            });
    }
    demand.nodes[0]
        .operations
        .sort_by(|left, right| left.operation.cmp(&right.operation));
    catalog
        .resolve_capabilities(
            &[InstalledCapabilityCandidate {
                id: id("installed/standalone-clock"),
                selections,
            }],
            demand,
        )
        .unwrap()
}

use crate::node_observed_executor::StoredWorldActivationPublisher;

fn digest(value: &impl serde::Serialize) -> crucible_node_contract::HashRef {
    crucible_node_contract::canonical::json_hash("crucible.capability-native-test.v1", value)
        .unwrap()
}

fn native_clock(record: &NativeArchiveRecord, graph: &AdmittedGraph) -> Vec<u8> {
    let envelope = record
        .object_bytes(
            &record.owners()[0].state,
            limits().state.maximum_content_bytes,
        )
        .unwrap();
    crucible::node_adapters::validate_host_continuation(
        &envelope,
        &record.runtime_snapshot().unwrap(),
        graph.descriptor(&id("clock")).unwrap(),
        graph.binding(&id("clock")).unwrap(),
        super::native::resources(),
    )
    .unwrap()
    .native_model
    .bytes
}

fn id(text: &str) -> Id {
    Id::new(text).unwrap()
}
fn requirements() -> StateRequirements {
    StateRequirements {
        preservation_contract: id("host/preservation-v1"),
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    }
}
fn limits() -> NativeArchiveLimits {
    let mut limits = NativeArchiveLimits::default();
    // The complete test executable is an authenticated immutable input, not a
    // native state record. Its bounded size includes every daemon test target.
    limits.state.maximum_content_bytes = 128 * 1024 * 1024;
    limits
}

fn catalog(directory: &std::path::Path) -> InstalledNodeCatalog {
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    InstalledNodeCatalog::new(
        executable.clone(),
        super::super::measure_executable(&executable).unwrap(),
        directory.to_path_buf(),
        Duration::from_secs(5),
        4,
    )
    .unwrap()
}

fn publisher(
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    name: &str,
) -> StoredWorldActivationPublisher {
    StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new(format!("node-world-activations/capability-{name}")).unwrap(),
    )
    .unwrap()
}

fn reclaim(catalog: &InstalledNodeCatalog, remaining: usize) {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..32 {
        let _ = catalog.custody().clone().poll_reclamation(&mut context);
        if catalog.custody().reserved_worlds() == remaining {
            return;
        }
    }
    panic!("actual native Clock custody failed to reclaim");
}

fn execute(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    operation: &str,
    horizon: u64,
) -> OperationOutcome {
    let observation = runtime
        .observe_scheduling(activation, &id("clock"))
        .unwrap();
    runtime
        .scheduler(graph, activation)
        .unwrap()
        .accept_boundary_observation(observation)
        .unwrap();
    let grant = runtime
        .scheduler(graph, activation)
        .unwrap()
        .admit_exact(&id("clock"), id(operation), horizon.into())
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("actual admitted Clock refused");
    };
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
    else {
        panic!("actual synchronous Clock did not complete");
    };
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    outcome
}

fn restore(
    catalog: &mut InstalledNodeCatalog,
    record: NativeArchiveRecord,
    nonce: u8,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
) -> (Rc<AdmittedGraph>, Box<RestoredWorld>) {
    let profile = resolve(catalog);
    let factory = catalog
        .installed_capability_clock_factory(&profile)
        .unwrap();
    let original_slots = catalog.custody().reserved_worlds();
    let (prepared, target) = catalog
        .prepare_capability_clock_restore(
            &profile,
            ExecutionId::from_bytes([nonce; 16]).unwrap(),
            &record,
        )
        .unwrap();
    let graph = Rc::new(prepared.graph);
    drop(prepared.realization);
    reclaim(catalog, original_slots);
    let verified = record
        .admit(&graph, requirements(), factory.as_ref())
        .unwrap();
    let mut driver =
        NativeWorldRestoreDriver::new(graph.clone(), record, factory, catalog.custody().clone())
            .unwrap();
    let restored = stage_restore(&graph, verified, target, &mut driver, limits().state)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    let RestorePublication::Committed(world) =
        restored.publish(&mut publisher(blobs, refs, &format!("branch-{nonce}")))
    else {
        panic!("actual capability-bearing Clock activation failed");
    };
    (graph, world)
}

#[test]
#[ignore = "requires the actual source-built CRUCIBLE_REFERENCE_DEVICE installed catalog artifact"]
fn actual_capability_clock_survives_source_removal_in_two_fresh_native_worlds() {
    let directory = tempfile::tempdir().unwrap();
    let original_namespace = directory.path().join("original");
    std::fs::create_dir(&original_namespace).unwrap();
    let mut installed = catalog(&original_namespace);
    let profile = resolve(&installed);
    let factory = installed
        .installed_capability_clock_factory(&profile)
        .unwrap();
    let prepared = installed
        .prepare_capability_world(&profile, ExecutionId::from_bytes([71; 16]).unwrap())
        .unwrap();
    let graph = prepared.graph;
    assert!(graph.selected_extensions().is_empty());
    assert!(
        graph.capability_requirements().unwrap().nodes[0]
            .guarantees
            .durable_restart
    );
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "clock-label",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "source"))
        .unwrap();
    let first = execute(&mut runtime, &graph, &activation, "original/advance", 10);
    assert_eq!(
        first.scheduling.as_ref().unwrap().reached.time_ps,
        U64::new(10)
    );
    let cut = Position::new(10.into(), 0.into(), Phase::BoundaryControl);
    let original = runtime
        .runtime_snapshot(cut, 7.into(), limits().state.maximum_record_bytes)
        .unwrap();
    let archive_path = directory.path().join("archive");
    let archive = NativeArchive::open(&archive_path, limits()).unwrap();
    assert!(
        archive
            .capture_world(
                &graph,
                &mut runtime,
                &activation,
                cut,
                7.into(),
                id("capability/legacy-refusal"),
                requirements(),
                factory.as_ref(),
                factory.as_ref()
            )
            .is_err()
    );
    let record = archive
        .capture_world_typed(
            &graph,
            &mut runtime,
            &activation,
            cut,
            7.into(),
            id("capability/source"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    assert_eq!(record.runtime_snapshot().unwrap(), original);
    assert_eq!(
        native_clock(&record, &graph),
        crucible::node_adapters::host_clock_initial_bytes(10)
    );
    // The archived cut remains original while the source executes an independent
    // suffix oracle. Neither fresh branch may rerun that captured history.
    let oracle = execute(&mut runtime, &graph, &activation, "future/advance", 25);
    let artifact = record.artifact().clone();
    let selected = graph.capability_selection().unwrap().selection().clone();
    let source_requirements = graph.capability_requirements().unwrap().clone();
    drop(record);
    drop(archive);
    drop(runtime);
    reclaim(&installed, 0);
    drop(activation);
    drop(graph);
    drop(factory);
    drop(profile);
    drop(installed);
    std::fs::remove_dir_all(&original_namespace).unwrap();
    assert!(!original_namespace.exists());

    let archive = NativeArchive::open(&archive_path, limits()).unwrap();
    let record = archive.load(&artifact).unwrap();
    let left_namespace = directory.path().join("left");
    let right_namespace = directory.path().join("right");
    std::fs::create_dir(&left_namespace).unwrap();
    std::fs::create_dir(&right_namespace).unwrap();
    let mut left_catalog = catalog(&left_namespace);
    let mut right_catalog = catalog(&right_namespace);
    let (left_graph, mut left) = restore(&mut left_catalog, record.clone(), 72, &blobs, &refs);
    let (right_graph, mut right) = restore(&mut right_catalog, record, 73, &blobs, &refs);
    assert_eq!(
        digest(left_graph.capability_selection().unwrap().selection()),
        digest(&selected)
    );
    assert_eq!(
        digest(right_graph.capability_selection().unwrap().selection()),
        digest(&selected)
    );
    assert_eq!(
        digest(left_graph.capability_requirements().unwrap()),
        digest(&source_requirements)
    );
    assert_eq!(
        digest(right_graph.capability_requirements().unwrap()),
        digest(&source_requirements)
    );
    assert_ne!(
        left.activation().record().owners,
        right.activation().record().owners
    );
    assert_eq!(left.activation().record().boundary, cut);
    assert_eq!(right.activation().record().boundary, cut);
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    assert_eq!(
        left.runtime_mut()
            .runtime_snapshot(cut, 7.into(), limits().state.maximum_record_bytes)
            .unwrap()
            .operations[0]
            .operation,
        original.operations[0].operation
    );
    assert_eq!(
        right
            .runtime_mut()
            .runtime_snapshot(cut, 7.into(), limits().state.maximum_record_bytes)
            .unwrap()
            .operations[0]
            .operation,
        original.operations[0].operation
    );
    // Capture without advancing either restored native model: logical cursor
    // equality alone cannot establish that its actual integer state is 10.
    for (catalog, graph, world, name) in [
        (&left_catalog, &left_graph, &mut left, "left"),
        (&right_catalog, &right_graph, &mut right, "right"),
    ] {
        let resolved = resolve(catalog);
        let factory = catalog
            .installed_capability_clock_factory(&resolved)
            .unwrap();
        let activation = world.activation().clone();
        let unchanged = archive
            .capture_world_typed(
                graph,
                world.runtime_mut(),
                &activation,
                cut,
                7.into(),
                id(&format!("capability/unchanged-{name}")),
                requirements(),
                factory.as_ref(),
                factory.as_ref(),
            )
            .unwrap();
        assert_eq!(
            native_clock(&unchanged, graph),
            crucible::node_adapters::host_clock_initial_bytes(10)
        );
    }
    let left_suffix = execute(
        left.runtime_mut(),
        &left_graph,
        &left_activation,
        "future/advance",
        25,
    );
    let right_suffix = execute(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        "future/advance",
        25,
    );
    assert_eq!(left_suffix.progress, oracle.progress);
    assert_eq!(left_suffix.progress, right_suffix.progress);
    assert_eq!(left_suffix.retained_outputs, right_suffix.retained_outputs);
    assert_eq!(
        left_suffix.scheduling.as_ref().unwrap().reached,
        right_suffix.scheduling.as_ref().unwrap().reached
    );
    assert_eq!(
        left_suffix.scheduling.as_ref().unwrap().publications,
        right_suffix.scheduling.as_ref().unwrap().publications
    );
    // Independent receipts are insufficient: capture each actual future Clock
    // and authenticate its native integer bytes after the suffix has executed.
    for (catalog, graph, world, name) in [
        (&left_catalog, &left_graph, &mut left, "left"),
        (&right_catalog, &right_graph, &mut right, "right"),
    ] {
        let profile = resolve(catalog);
        let factory = catalog
            .installed_capability_clock_factory(&profile)
            .unwrap();
        let activation = world.activation().clone();
        let future = archive
            .capture_world_typed(
                graph,
                world.runtime_mut(),
                &activation,
                Position::new(25.into(), 0.into(), Phase::BoundaryControl),
                8.into(),
                id(&format!("capability/future-{name}")),
                requirements(),
                factory.as_ref(),
                factory.as_ref(),
            )
            .unwrap();
        let owner = &future.owners()[0];
        let envelope = future
            .object_bytes(&owner.state, limits().state.maximum_content_bytes)
            .unwrap();
        let inventory = crucible::node_adapters::validate_host_continuation(
            &envelope,
            &future.runtime_snapshot().unwrap(),
            graph.descriptor(&id("clock")).unwrap(),
            graph.binding(&id("clock")).unwrap(),
            super::native::resources(),
        )
        .unwrap();
        assert_eq!(
            inventory.native_model.bytes,
            crucible::node_adapters::host_clock_initial_bytes(25)
        );
    }
    drop(left);
    drop(right);
    reclaim(&left_catalog, 0);
    reclaim(&right_catalog, 0);
}

#[test]
#[ignore = "requires the source-built CRUCIBLE_REFERENCE_DEVICE measured installation artifact"]
fn actual_capability_clock_refuses_changed_raw_requirements_before_native_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let mut installed = catalog(directory.path());
    let original = resolve(&installed);
    let remaining = installed.custody().reserved_worlds();
    for mutation in 0..4 {
        let mut changed = resolve(&installed);
        match mutation {
            0 => changed.requirements.nodes[0].timing.phase_ps = Some(1.into()),
            1 => changed.requirements.nodes[0].operations[0].facet.version = 2,
            2 => {
                changed
                    .scenario
                    .content
                    .iter_mut()
                    .find(|object| {
                        object.reference.media_type
                            == crucible::node_admission::CAPABILITY_REQUIREMENTS_MEDIA_TYPE
                    })
                    .unwrap()
                    .bytes[0] ^= 1
            }
            3 => {
                changed.scenario.compatibility[0]
                    .implementation
                    .implementation_id = id("unknown/clock")
            }
            _ => unreachable!(),
        }
        assert!(
            installed
                .installed_capability_clock_factory(&changed)
                .is_err()
        );
        assert!(
            installed
                .prepare_capability_world(&changed, ExecutionId::from_bytes([88; 16]).unwrap())
                .is_err()
        );
        assert_eq!(installed.custody().reserved_worlds(), remaining);
    }
    assert!(
        installed
            .installed_capability_clock_factory(&original)
            .is_ok()
    );
}

#[test]
#[ignore = "requires the source-built CRUCIBLE_REFERENCE_DEVICE measured installation artifact"]
fn actual_capability_clock_reserves_complete_portable_credits_before_capture() {
    let directory = tempfile::tempdir().unwrap();
    let mut installed = catalog(directory.path());
    let resolved = resolve(&installed);
    let factory = installed
        .installed_capability_clock_factory(&resolved)
        .unwrap();
    let prepared = installed
        .prepare_capability_world(&resolved, ExecutionId::from_bytes([89; 16]).unwrap())
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "credit-clock",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "credit"))
        .unwrap();
    execute(&mut runtime, &graph, &activation, "original/credit", 10);
    let cut = Position::new(10.into(), 0.into(), Phase::BoundaryControl);
    let original = runtime
        .runtime_snapshot(cut, 2.into(), limits().state.maximum_record_bytes)
        .unwrap();
    let mut credit = limits();
    // This permits all original immutable bytes, but cannot reserve the
    // complete portable index/manifest/receipts plus native custody.
    credit.native.maximum_total_record_bytes = 1;
    let archive = NativeArchive::open(directory.path().join("credit-archive"), credit).unwrap();
    let failure = archive
        .capture_world_typed(
            &graph,
            &mut runtime,
            &activation,
            cut,
            2.into(),
            id("capability/credit-deficit"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .err()
        .unwrap();
    assert_eq!(
        failure.code,
        crucible::node_state::StateErrorCode::ResourceLimit
    );
    assert_eq!(
        runtime
            .runtime_snapshot(cut, 2.into(), limits().state.maximum_record_bytes)
            .unwrap(),
        original
    );
    drop(runtime);
    reclaim(&installed, 0);
}
