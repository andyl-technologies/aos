//! Actual installed pending-transfer capture and two independent cold restorations.
//!
//! Native qualification comes from the production installed catalog and signed
//! source archive. No synthetic native proof or admission evidence is supplied.

// These native fixtures panic when an asserted custody or continuation invariant fails.
// crucible-lint: allow panic-shortcut -- These host state transfer tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "host_state_recorded_tests.rs"]
mod recorded;

#[path = "host_state_ninep_transfer_tests.rs"]
mod ninep;

#[path = "host_state_seeded_tests.rs"]
mod seeded;

#[path = "condition_debug_tests.rs"]
mod condition_debug;

use std::{
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible::{
    node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource},
    node_admission::AdmittedGraph,
    node_contract::{BeginResult, NodeRuntime, OperationOutcome, WorldActivation},
    node_scheduling::ExecutionAdmission,
    node_state::{
        HostArchive, HostArchiveRecord, HostWorldRestoreDriver, RestorePublication, RestoredWorld,
        StateLimits, StateRequirements, StateRestoreMode, stage_restore,
    },
};
use crucible_campaign::ExecutionId;
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::{Id, Phase, Position, U64, canonical};

use super::*;
use crate::node_observed_executor::{
    InstalledHostIoProfile, InstalledIoArtifact, InstalledScriptedSourceProfile,
    StoredWorldActivationPublisher,
};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn requirements() -> StateRequirements {
    StateRequirements {
        preservation_contract: id("host/preservation-v1"),
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
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

fn observe(runtime: &mut NodeRuntime, graph: &AdmittedGraph, activation: &WorldActivation) {
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(activation, node).unwrap();
        runtime
            .scheduler(graph, activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }
}

fn run(runtime: &mut NodeRuntime, grant: ExecutionAdmission) -> OperationOutcome {
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("genuine admitted host operation was refused");
    };
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut context) else {
        panic!("installed synchronous operation did not complete");
    };
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    outcome
}

fn exact(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    node: &str,
    operation: &str,
    horizon: u64,
) -> OperationOutcome {
    observe(runtime, graph, activation);
    let grant = runtime
        .scheduler(graph, activation)
        .unwrap()
        .admit_exact(&id(node), id(operation), horizon.into())
        .unwrap();
    run(runtime, grant)
}

fn settle(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    node: &str,
    operation: &str,
    cut: Position,
) {
    observe(runtime, graph, activation);
    let grant = runtime
        .scheduler(graph, activation)
        .unwrap()
        .admit_boundary_settlement(&id(node), id(operation), cut)
        .unwrap();
    run(runtime, grant);
}

fn pending(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
) -> Vec<crucible::node_scheduling::event::Delivery> {
    runtime
        .scheduler(graph, activation)
        .unwrap()
        .pending_inputs(&id("disk"))
        .unwrap()
        .into_iter()
        .cloned()
        .collect()
}

fn advance_disk(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    name: &str,
    horizon: u64,
) -> OperationOutcome {
    exact(
        runtime,
        graph,
        activation,
        "source",
        &format!("{name}/source"),
        horizon,
    );
    observe(runtime, graph, activation);
    let cutoff = runtime
        .scheduler(graph, activation)
        .unwrap()
        .preview_exact_input_cut(&id("disk"), horizon.into())
        .unwrap();
    let batch = runtime
        .scheduler(graph, activation)
        .unwrap()
        .prepare_input_batch(
            &id("disk"),
            id(&format!("{name}/stage")),
            id(&format!("{name}/batch")),
            cutoff,
        )
        .unwrap();
    let acknowledgement = runtime.stage_inputs(batch).unwrap();
    let commit = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&commit).unwrap();
    exact(
        runtime,
        graph,
        activation,
        "disk",
        &format!("{name}/disk"),
        horizon,
    )
}

fn restore(
    catalog: &mut InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    scenario: &NodeScenario,
    record: HostArchiveRecord,
    nonce: u8,
    storage: (&Arc<dyn ImmutableBlobBackend>, &Arc<dyn MutableRefBackend>),
    limits: StateLimits,
) -> (Rc<AdmittedGraph>, Box<RestoredWorld>) {
    let factory = catalog
        .host_state_factory_from_archive(selections, scenario, &record)
        .unwrap();
    let active_worlds = catalog.custody().reserved_worlds();
    let (graph, target) = catalog
        .prepare_host_restore_graph(
            selections,
            scenario,
            &record,
            ExecutionId::from_bytes([nonce; 16]).unwrap(),
        )
        .unwrap();
    reclaim_to(catalog, active_worlds);
    let graph = Rc::new(graph);
    let verified = record
        .admit(&graph, requirements(), factory.as_ref(), limits)
        .unwrap();
    let mut driver =
        HostWorldRestoreDriver::new(graph.clone(), record, factory, catalog.custody().clone())
            .unwrap();
    let prepared = stage_restore(&graph, verified, target, &mut driver, limits)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    let RestorePublication::Committed(restored) = prepared.publish(&mut publisher(
        storage.0,
        storage.1,
        &format!("restore-{nonce}"),
    )) else {
        panic!("genuine complete restore did not commit");
    };
    (graph, restored)
}

fn reclaim(catalog: &InstalledNodeCatalog) {
    reclaim_to(catalog, 0);
}

fn reclaim_to(catalog: &InstalledNodeCatalog, active_worlds: usize) {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..32 {
        let _ = catalog.custody().clone().poll_reclamation(&mut context);
        if catalog.custody().reserved_worlds() == active_worlds {
            return;
        }
    }
    panic!("original synchronous native resources did not retire");
}

#[test]
#[ignore = "requires the source-built CRUCIBLE_REFERENCE_DEVICE and candidate full storage archive qualification"]
fn installed_pending_request_transfer_survives_source_retirement_and_isolated_cold_branches() {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    let base = vec![0xab; 4096];
    let write = BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap();
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: write.clone(),
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: BlockRequest::read(102, 0, 3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let base_ref = canonical::content_ref(&base, "application/octet-stream").unwrap();
    let script_ref = canonical::content_ref(&script, "application/octet-stream").unwrap();
    let base_path = directory.path().join("base");
    let script_path = directory.path().join("script");
    std::fs::write(&base_path, &base).unwrap();
    std::fs::write(&script_path, &script).unwrap();
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(base_path.clone(), base_ref.clone()),
            InstalledIoArtifact::path(script_path.clone(), script_ref.clone()),
        ])
        .unwrap();
    let archive_policy = vec![
        InstalledIoArtifact::archive_only(base_ref.clone()),
        InstalledIoArtifact::archive_only(script_ref.clone()),
    ];
    let selections = vec![
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("disk-owner"),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Block {
                    base_image: base_ref,
                    source_node: 7,
                    read_ns: 1.into(),
                    write_ns: 1.into(),
                    flush_ns: 1.into(),
                    get_length_ns: 1.into(),
                    per_byte_ns: 1.into(),
                },
            },
        },
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: script_ref,
                    consumer: id("disk"),
                },
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let factory = catalog.host_state_factory(&selections, &scenario).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "transfer-capture",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let prepared = catalog
        .prepare_world(
            &selections,
            scenario.clone(),
            ExecutionId::from_bytes([91; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "source"))
        .unwrap();
    exact(
        &mut runtime,
        &graph,
        &activation,
        "source",
        "source/park",
        10,
    );
    exact(&mut runtime, &graph, &activation, "disk", "disk/park", 10);
    // The native evaluation is before this cut, but its future publication
    // remains coordinator-owned. The original birth grant transfers it once.
    let cut = Position::new(10.into(), 1.into(), Phase::BoundaryControl);
    settle(
        &mut runtime,
        &graph,
        &activation,
        "source",
        "source/publish",
        cut,
    );
    settle(
        &mut runtime,
        &graph,
        &activation,
        "disk",
        "disk/settle",
        cut,
    );
    let before = pending(&mut runtime, &graph, &activation);
    assert_eq!(before.len(), 1);
    assert_eq!(
        before[0].delivery,
        Position::new(10.into(), 1.into(), Phase::Delivery)
    );
    assert!(before[0].evaluation.unwrap() < cut);
    assert!(before[0].publication >= cut);
    assert_eq!(before[0].producer, id("source"));
    assert_eq!(before[0].native_sequence, U64::new(0));
    before[0].payload.verify(&write).unwrap();

    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive_path = directory.path().join("archive");
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive
        .capture_world(
            &graph,
            &mut runtime,
            &activation,
            cut,
            4.into(),
            id("capture/transfer"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let artifact = record.artifact().clone();
    drop(record);
    drop(runtime);
    reclaim(&catalog);
    drop(activation);
    drop(graph);
    drop(factory);
    drop(catalog);
    drop(archive);
    std::fs::remove_file(&base_path).unwrap();
    std::fs::remove_file(&script_path).unwrap();

    // A new host owner has only independently pinned operator references and
    // the authenticated archive. Every original native object and input path is gone.
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    catalog.install_artifacts(archive_policy).unwrap();
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let (left_graph, mut left) = restore(
        &mut catalog,
        &selections,
        &scenario,
        record.clone(),
        92,
        (&blobs, &refs),
        limits,
    );
    let (right_graph, mut right) = restore(
        &mut catalog,
        &selections,
        &scenario,
        record,
        93,
        (&blobs, &refs),
        limits,
    );
    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    assert_ne!(
        left_activation.record().owners,
        right_activation.record().owners
    );
    assert_eq!(
        pending(left.runtime_mut(), &left_graph, &left_activation),
        before
    );
    assert_eq!(
        pending(right.runtime_mut(), &right_graph, &right_activation),
        before
    );

    let completed_left = advance_disk(
        left.runtime_mut(),
        &left_graph,
        &left_activation,
        "left",
        11_000,
    );
    let pending_right = advance_disk(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        "right-pending",
        11,
    );
    assert!(
        pending_right
            .scheduling
            .as_ref()
            .unwrap()
            .publications
            .is_empty()
    );
    let completed_right = advance_disk(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        "right-complete",
        11_000,
    );
    let left_outputs = &completed_left.scheduling.as_ref().unwrap().publications;
    let right_outputs = &completed_right.scheduling.as_ref().unwrap().publications;
    assert_eq!(left_outputs.len(), 1);
    assert_eq!(right_outputs.len(), 1);
    assert_eq!(
        left_outputs[0].payload_bytes,
        right_outputs[0].payload_bytes
    );
    assert_eq!(left_outputs[0].publication, right_outputs[0].publication);
    assert_eq!(
        left_outputs[0].native_sequence,
        right_outputs[0].native_sequence
    );
    assert_eq!(
        left_outputs[0].causal_parents,
        right_outputs[0].causal_parents
    );
    assert_eq!(left_outputs[0].causal_parents.len(), 1);
    assert_eq!(
        BlockResponse::decode(&left_outputs[0].payload_bytes)
            .unwrap()
            .request_id,
        101
    );
    // The original future script read is born once in each restored source.
    // Its real reply observes the private overlay written from the saved FIFO.
    let read_cut = Position::new(50_000.into(), 1.into(), Phase::Delivery);
    for (branch, branch_graph, activation, name) in [
        (&mut left, &left_graph, &left_activation, "left-read"),
        (&mut right, &right_graph, &right_activation, "right-read"),
    ] {
        exact(
            branch.runtime_mut(),
            branch_graph,
            activation,
            "source",
            &format!("{name}/park"),
            50_000,
        );
        settle(
            branch.runtime_mut(),
            branch_graph,
            activation,
            "source",
            &format!("{name}/publish"),
            read_cut,
        );
        let outcome = advance_disk(
            branch.runtime_mut(),
            branch_graph,
            activation,
            name,
            100_000,
        );
        let publications = &outcome.scheduling.as_ref().unwrap().publications;
        assert_eq!(publications.len(), 1);
        assert_eq!(publications[0].native_sequence, U64::new(1));
        let reply = BlockResponse::decode(&publications[0].payload_bytes).unwrap();
        assert_eq!(reply.request_id, 102);
        assert_eq!(reply.data, vec![7, 8, 9]);
        assert!(pending(branch.runtime_mut(), branch_graph, activation).is_empty());
    }
    drop(left);
    drop(right);
    reclaim(&catalog);
}

#[path = "host_state_adverse_tests.rs"]
mod adverse;

#[path = "host_state_adverse_packet_tests.rs"]
mod adverse_packet;

#[path = "host_state_loss_tests.rs"]
mod loss;

#[path = "host_state_controlled_tests.rs"]
mod controlled;
