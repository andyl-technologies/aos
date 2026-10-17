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
        RestorePublication, RestoredWorld, StateErrorCode, StateRequirements, StateRestoreMode,
        stage_restore,
    },
};
use crucible_campaign::ExecutionId;
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::{Id, Phase, Position, U64};

use super::*;
use crate::node_observed_executor::StoredWorldActivationPublisher;

// This negative-only installation has no extension codec. Every native
// callback records an attempted allocation/authentication and refuses; it never
// constructs source provenance or operational authority.
#[derive(Default)]
struct UnqualifiedInstallation(std::cell::Cell<usize>);

impl UnqualifiedInstallation {
    fn refused(&self) -> crucible::node_state::StateError {
        self.0.set(self.0.get() + 1);
        state_error("negative installation must not receive native callbacks")
    }
}

impl crucible::node_state::NativeWorldFactory for UnqualifiedInstallation {
    fn authenticate_source(
        &self,
        _: &AdmittedGraph,
        _: &crucible_node_contract::CapturedOwner,
        _: &crucible::node_state::AuthenticatedNativeSource<'_>,
    ) -> Result<(), crucible::node_state::StateError> {
        Err(self.refused())
    }
    fn authenticate_coordinator(
        &self,
        _: &AdmittedGraph,
        _: &crucible::node_contract::RuntimeSnapshot,
        _: &crucible::node_scheduling::SchedulingSnapshot,
        _: &crucible::node_state::VerifiedStateContent,
    ) -> Result<(), crucible::node_state::StateError> {
        Err(self.refused())
    }
    fn reservation(
        &self,
        _: &AdmittedGraph,
        _: &crucible_node_contract::CapturedOwner,
        _: &crucible::node_state::AuthenticatedNativeSource<'_>,
        _: NativeArchiveLimits,
    ) -> Result<crucible::node_state::RestoreReservations, crucible::node_state::StateError> {
        Err(self.refused())
    }
    fn empty_staging(
        &self,
        _: Rc<AdmittedGraph>,
        _: NativeArchiveRecord,
        _: &crucible::node_contract::ActivationRecord,
        _: crucible::node_state::RestoreReservations,
        _: NativeArchiveLimits,
    ) -> Result<Box<dyn crucible::node_state::NativeRestoreStaging>, crucible::node_state::StateError>
    {
        Err(self.refused())
    }
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
        RefName::new(format!("node-world-activations/label-{name}")).unwrap(),
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
    let profile = catalog.installed_clock_label().unwrap();
    let factory = catalog.installed_clock_label_factory(&profile).unwrap();
    let original_slots = catalog.custody().reserved_worlds();
    let (prepared, target) = catalog
        .prepare_installed_clock_label(
            &profile,
            ExecutionId::from_bytes([nonce; 16]).unwrap(),
            Some(&record),
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
        panic!("actual labeled Clock activation failed");
    };
    (graph, world)
}

#[test]
#[ignore = "requires the actual source-built CRUCIBLE_REFERENCE_DEVICE installed catalog artifact"]
fn actual_labeled_clock_survives_source_removal_in_two_fresh_native_worlds() {
    let directory = tempfile::tempdir().unwrap();
    let original_namespace = directory.path().join("original");
    std::fs::create_dir(&original_namespace).unwrap();
    let mut installed = catalog(&original_namespace);
    let profile = installed.installed_clock_label().unwrap();
    let factory = installed.installed_clock_label_factory(&profile).unwrap();
    let (prepared, _) = installed
        .prepare_installed_clock_label(&profile, ExecutionId::from_bytes([71; 16]).unwrap(), None)
        .unwrap();
    let graph = prepared.graph;
    assert!(!graph.selected_extensions().is_empty());
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
                id("label/legacy-refusal"),
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
            id("label/source"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    assert_eq!(record.runtime_snapshot().unwrap(), original);
    let artifact = record.artifact().clone();
    let selected = graph.selected_extensions().identity().unwrap();
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
        left_graph.selected_extensions().identity().unwrap(),
        selected
    );
    assert_eq!(
        right_graph.selected_extensions().identity().unwrap(),
        selected
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
        let profile = catalog.installed_clock_label().unwrap();
        let factory = catalog.installed_clock_label_factory(&profile).unwrap();
        let activation = world.activation().clone();
        let future = archive
            .capture_world_typed(
                graph,
                world.runtime_mut(),
                &activation,
                Position::new(25.into(), 0.into(), Phase::BoundaryControl),
                8.into(),
                id(&format!("label/future-{name}")),
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
#[ignore = "requires the actual source-built CRUCIBLE_REFERENCE_DEVICE installed catalog artifact"]
fn installed_clock_label_refuses_changed_bodies_and_semantic_state_policy() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let profile = catalog.clock_label_profile().unwrap();
    let factory = catalog.clock_label_factory(profile.clone()).unwrap();
    let (prepared, _) = catalog
        .prepare_clock_label(
            profile.as_ref(),
            ExecutionId::from_bytes([74; 16]).unwrap(),
            None,
        )
        .unwrap();
    let graph = Rc::new(prepared.graph);
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "negative-label",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "negative"))
        .unwrap();
    let cut = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    let original = runtime
        .runtime_snapshot(cut, 1.into(), limits().state.maximum_record_bytes)
        .unwrap();
    let archive = NativeArchive::open(directory.path().join("archive"), limits()).unwrap();

    for mutation in 0..4 {
        let mut changed = catalog.clock_label_profile().unwrap();
        let changed_policy = Rc::get_mut(&mut changed).unwrap();
        match mutation {
            0 => {
                changed_policy.objects.insert(
                    changed_policy.preservation.clone(),
                    br#"{"state_effects":"new timers"}"#.to_vec(),
                );
            }
            1 => {
                changed_policy.handler = crucible_node_contract::canonical::content_ref(
                    b"unknown handler",
                    "text/plain",
                )
                .unwrap();
            }
            2 => {
                changed_policy.semantics.state_contract =
                    crucible_node_contract::canonical::content_ref(
                        b"new mutable state",
                        "text/plain",
                    )
                    .unwrap();
            }
            3 => {
                // A self-consistent new digest does not authenticate a new
                // semantic policy in the installed closed Clock profile.
                let bytes = br#"{"schema_version":1,"state_effects":"new timers"}"#.to_vec();
                changed_policy.preservation =
                    crucible_node_contract::canonical::content_ref(&bytes, "application/json")
                        .unwrap();
                changed_policy
                    .objects
                    .insert(changed_policy.preservation.clone(), bytes);
            }
            _ => unreachable!(),
        }
        let changed_factory = super::native::InstalledClockLabelFactory {
            profile: changed,
            installed: factory.installed.clone(),
        };
        let failure = archive
            .capture_world_typed(
                &graph,
                &mut runtime,
                &activation,
                cut,
                1.into(),
                id(&format!("label/refuse-{mutation}")),
                requirements(),
                factory.as_ref(),
                &changed_factory,
            )
            .err()
            .unwrap();
        assert!(matches!(
            failure.code,
            StateErrorCode::NativeEvidence | StateErrorCode::Content
        ));
        assert_eq!(
            runtime
                .runtime_snapshot(cut, 1.into(), limits().state.maximum_record_bytes)
                .unwrap(),
            original
        );
    }

    let unavailable = Rc::new(UnqualifiedInstallation::default());
    let failure = archive
        .capture_world_typed(
            &graph,
            &mut runtime,
            &activation,
            cut,
            1.into(),
            id("label/no-installed-codec"),
            requirements(),
            factory.as_ref(),
            unavailable.as_ref(),
        )
        .err()
        .unwrap();
    assert_eq!(failure.code, StateErrorCode::NativeEvidence);
    assert_eq!(unavailable.0.get(), 0);

    let original_record = archive
        .capture_world_typed(
            &graph,
            &mut runtime,
            &activation,
            cut,
            1.into(),
            id("label/negative-source"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    assert!(
        original_record
            .admit(&graph, requirements(), unavailable.as_ref())
            .is_err()
    );
    assert!(
        NativeWorldRestoreDriver::new(
            graph.clone(),
            original_record,
            unavailable.clone(),
            catalog.custody().clone(),
        )
        .is_err()
    );
    assert_eq!(unavailable.0.get(), 0);
    assert_eq!(
        runtime
            .runtime_snapshot(cut, 1.into(), limits().state.maximum_record_bytes)
            .unwrap(),
        original
    );

    // Complete known immutable bytes must reserve credit before native capture;
    // counting only the small selected semantic objects would falsely succeed.
    let mut exhausted = limits();
    exhausted.native.maximum_total_record_bytes = 1024 * 1024;
    let insufficient =
        NativeArchive::open(directory.path().join("insufficient"), exhausted).unwrap();
    let failure = insufficient
        .capture_world_typed(
            &graph,
            &mut runtime,
            &activation,
            cut,
            1.into(),
            id("label/credit-refusal"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .err()
        .unwrap();
    assert_eq!(failure.code, StateErrorCode::ResourceLimit);
    assert_eq!(
        runtime
            .runtime_snapshot(cut, 1.into(), limits().state.maximum_record_bytes)
            .unwrap(),
        original
    );
    drop(runtime);
    reclaim(&catalog, 0);
}
