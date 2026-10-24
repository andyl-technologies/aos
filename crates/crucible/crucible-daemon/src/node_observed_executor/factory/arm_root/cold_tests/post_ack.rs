//! Requires a new native PL011 birth after source-gone twin reconstruction.
// SPDX-License-Identifier: Apache-2.0

// crucible-lint: allow panic-shortcut -- Native witness failures retain their original supervisors.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    os::unix::fs::PermissionsExt,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible_engine::{
    node_admission::AdmittedGraph,
    node_contract::{
        BeginResult, NodeRuntime, OperationOutcome, OperationToken, ProgressEvidence, RuntimeError,
        RuntimePollFailure, StopReason, WorldActivation,
    },
    node_scheduling::NativePublication,
    node_state::NativeArchive,
};
use crucible_node_format::{Id, Phase, Position, U64};
use crucible_store::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};

use super::super::{installed::RootInstalledEngine, tests::FailedWitnessSupervision};
use super::{
    advance_and_acknowledge, assert_archive_descriptors_are_shared, finish, id, limits, publisher,
    reclaim, requirements, restore, root_selections,
};
use crate::node_observed_executor::factory::{InstalledNodeCatalog, measure_executable};

const CONTINUATION_HORIZON_PS: u64 = 2_000_000_000;

#[test]
#[ignore = "requires the installed ARM Root model, independent opaque audits and measured companion"]
fn actual_ordinary_root_twins_produce_next_native_byte_after_source_gone_and_ack() {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = directory.canonicalize().unwrap();
    let companion = std::path::PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE")
            .expect("actual independently installed companion is required"),
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
    let selections = root_selections();
    let scenario = catalog.scenario(&selections).unwrap();
    let prepared = catalog
        .prepare_root_native_world(
            &selections,
            scenario,
            crucible_campaign::ExecutionId::from_bytes([95; 16]).unwrap(),
        )
        .unwrap();
    let namespace = prepared.preservation.namespace.clone();
    let factory = prepared.preservation.factory.clone();
    let target = prepared.world.realization.activation_record().clone();
    let graph = Rc::new(prepared.world.graph);
    let mut runtime = prepared
        .world
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let preparations = runtime.prepared_node_records().unwrap().to_vec();
    assert_eq!(preparations.len(), 2);
    assert!(
        preparations
            .iter()
            .all(|node| node.prepared_owners().is_some())
    );
    let coordinator = runtime
        .initial_coordinator_snapshot(&graph, 16 * 1024 * 1024)
        .unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "root-post-ack",
        directory.join("cas"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let stored = publisher(&blobs, &refs, "post-ack-source")
        .with_prepared_coordinator(target, preparations, coordinator)
        .unwrap();
    let mut publisher = prepared.preservation.publisher(stored).unwrap();
    let activation = runtime.activate(publisher.as_mut()).unwrap();
    let source_owners = activation.record().owners.clone();
    assert_eq!(activation.prepared_owners().unwrap().len(), 2);
    assert!(activation.coordinator_snapshot().is_some());
    for node in graph.node_ids() {
        observe(&mut runtime, &graph, &activation, node);
    }

    let common = Position::new(1_000_000_000.into(), 0.into(), Phase::BoundaryControl);
    let bootstrap = advance_and_acknowledge(
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
    let (original, held) = run(&mut runtime, &graph, &activation, "original/root-serial");
    let held_publication = serial(&held, 1).clone();
    assert_eq!(held_publication.payload_bytes, [91]);
    repeat(&mut runtime, &original, &held);

    // Capture observes the original held byte and common coordinator state.
    // The additional callback is requested only after both independent restores.
    let ordinal = U64::new(19);
    let before = runtime
        .runtime_snapshot(common, ordinal, 16 * 1024 * 1024)
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
            common,
            ordinal,
            id("root-post-ack-source-capture"),
            requirements(),
            &factory.immutable(),
            factory.as_ref(),
        )
        .unwrap();
    assert_eq!(record.runtime_snapshot().unwrap(), before);
    assert_eq!(
        runtime
            .runtime_snapshot(common, ordinal, 16 * 1024 * 1024)
            .unwrap(),
        before
    );
    let artifact = record.artifact().clone();
    drop(original);
    drop(clock);
    drop(bootstrap);
    drop(runtime);
    drop(activation);
    drop(publisher);
    drop(prepared.preservation);
    drop(factory);
    drop(graph);
    reclaim(&engine);
    assert!(engine.native.all_groups_reclaimed());
    std::fs::remove_dir_all(&namespace).unwrap();
    assert!(!namespace.exists());
    drop(record);
    drop(archive);

    let archive = NativeArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let (mut left, left_factory, left_namespace, left_graph) = restore(
        &engine,
        Some(&mut catalog),
        record.clone(),
        &blobs,
        &refs,
        "post-ack-left",
        limits,
    );
    let (mut right, right_factory, right_namespace, right_graph) = restore(
        &engine,
        Some(&mut catalog),
        record.clone(),
        &blobs,
        &refs,
        "post-ack-right",
        limits,
    );
    assert!(!namespace.exists());
    assert_ne!(left_namespace, right_namespace);
    assert_ne!(
        left.activation().record().owners,
        right.activation().record().owners
    );
    for fresh in [&left, &right] {
        assert_ne!(fresh.activation().record().owners, source_owners);
        assert_eq!(fresh.activation().record().boundary, common);
        assert_eq!(fresh.activation().prepared_owners().unwrap().len(), 2);
        assert!(fresh.activation().coordinator_snapshot().is_some());
    }
    for fresh in [&mut left, &mut right] {
        let saved = fresh
            .runtime_mut()
            .runtime_snapshot(common, ordinal, 16 * 1024 * 1024)
            .unwrap();
        assert_eq!(saved.operations.len(), before.operations.len());
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
    }
    assert_archive_descriptors_are_shared(&archive_path, &record);
    let left_held = left
        .runtime_mut()
        .recover(&id("original/root-serial"))
        .unwrap();
    let right_held = right
        .runtime_mut()
        .recover(&id("original/root-serial"))
        .unwrap();
    let left_recovered = finish(left.runtime_mut(), &left_held);
    let right_recovered = finish(right.runtime_mut(), &right_held);
    assert_eq!(serial(&left_recovered, 1), &held_publication);
    assert_eq!(serial(&right_recovered, 1), &held_publication);
    repeat(left.runtime_mut(), &left_held, &left_recovered);
    repeat(right.runtime_mut(), &right_held, &right_recovered);

    // A sibling's valid public receipt cannot publish or release this owner's
    // held native FIFO. Both checks stop before native acknowledgement dispatch.
    let right_before_foreign = right
        .runtime_mut()
        .runtime_snapshot(common, ordinal, 16 * 1024 * 1024)
        .unwrap();
    let foreign_receipt = left.runtime_mut().scheduling_receipt(&left_held).unwrap();
    assert!(matches!(
        right
            .runtime_mut()
            .commit_scheduling_receipt(foreign_receipt),
        Err(RuntimeError::ForeignAuthority)
    ));
    let left_receipt = left.runtime_mut().scheduling_receipt(&left_held).unwrap();
    let left_commit = left
        .runtime_mut()
        .commit_scheduling_receipt(left_receipt)
        .unwrap();
    assert!(matches!(
        right
            .runtime_mut()
            .acknowledge_scheduled(&right_held, &left_commit),
        Err(RuntimePollFailure::Admission(
            RuntimeError::ForeignAuthority
        ))
    ));
    assert_eq!(
        right
            .runtime_mut()
            .runtime_snapshot(common, ordinal, 16 * 1024 * 1024)
            .unwrap(),
        right_before_foreign
    );
    repeat(right.runtime_mut(), &right_held, &right_recovered);
    left.runtime_mut()
        .acknowledge_scheduled(&left_held, &left_commit)
        .unwrap();
    acknowledge(right.runtime_mut(), &right_held);
    drop(left_commit);
    drop(left_held);
    drop(right_held);

    let left_activation = left.activation().clone();
    let right_activation = right.activation().clone();
    let operation = "restored/post-ack/next-native-serial";
    let (left_next, left_outcome) =
        run(left.runtime_mut(), &left_graph, &left_activation, operation);
    let (right_next, right_outcome) = run(
        right.runtime_mut(),
        &right_graph,
        &right_activation,
        operation,
    );
    let left_publication = serial(&left_outcome, 2);
    let right_publication = serial(&right_outcome, 2);
    assert_ne!(left_outcome.operation, held.operation);
    assert_ne!(right_outcome.operation, held.operation);
    assert!(left_publication.publication > held_publication.publication);
    assert!(left_publication.evaluation > held_publication.evaluation);
    assert_eq!(left_publication, right_publication);
    assert_eq!(left_outcome.progress, right_outcome.progress);
    repeat(left.runtime_mut(), &left_next, &left_outcome);
    repeat(right.runtime_mut(), &right_next, &right_outcome);
    acknowledge(left.runtime_mut(), &left_next);
    acknowledge(right.runtime_mut(), &right_next);
    assert!(left.runtime_mut().arm_all().is_err());
    assert!(right.runtime_mut().arm_all().is_err());

    drop(left_next);
    drop(right_next);
    drop(left_activation);
    drop(right_activation);
    drop(left);
    drop(right);
    drop(left_factory);
    drop(right_factory);
    drop(left_graph);
    drop(right_graph);
    reclaim(&engine);
    assert!(engine.native.all_groups_reclaimed());
    for namespace in [&left_namespace, &right_namespace] {
        std::fs::remove_dir_all(namespace).unwrap();
        assert!(!namespace.exists());
    }
    drop(record);
    drop(archive);
    drop(catalog);
    drop(blobs);
    drop(refs);
    std::fs::remove_dir_all(&directory).unwrap();
    println!(
        "\narm_root_post_ack=source-gone,twin-fresh-native-byte,foreign-custody-refused,common-ack,children-reclaimed"
    );
}

fn observe(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    node: &Id,
) {
    let observation = runtime.observe_scheduling(activation, node).unwrap();
    runtime
        .scheduler(graph, activation)
        .unwrap()
        .accept_boundary_observation(observation)
        .unwrap();
}

fn run(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    operation: &str,
) -> (OperationToken, OperationOutcome) {
    let node = id("root");
    observe(runtime, graph, activation, &node);
    let request = crate::node_execution::ExactOperationRequest {
        graph,
        activation,
        node: &node,
        horizon: CONTINUATION_HORIZON_PS.into(),
        names: crate::node_execution::ExactOperationNames {
            operation: id(operation),
            stage: id(&format!("{operation}/stage")),
            batch: id(&format!("{operation}/batch")),
        },
    };
    let planned: Result<_, crate::node_control::NodeControlError> =
        crate::node_execution::plan_exact_operation(runtime, request, |_| {
            panic!("closed ARM continuation invented input staging");
        });
    let BeginResult::Accepted(token) = runtime.begin_admitted(planned.unwrap().unwrap()).unwrap()
    else {
        panic!("actual post-ACK native permission was refused");
    };
    let outcome = finish(runtime, &token);
    (token, outcome)
}

fn serial(outcome: &OperationOutcome, sequence: u64) -> &NativePublication {
    let ProgressEvidence::Exact {
        reached,
        stop: StopReason::Output,
    } = &outcome.progress
    else {
        panic!("post-ACK continuation did not produce a native serial birth");
    };
    let publications = &outcome.scheduling.as_ref().unwrap().publications;
    assert_eq!(publications.len(), 1);
    let publication = &publications[0];
    assert_eq!(publication.endpoint.node_id, id("root"));
    assert_eq!(publication.endpoint.port_id, id("serial"));
    assert_eq!(publication.endpoint.lane_id, id("output"));
    assert_eq!(publication.native_sequence, U64::new(sequence));
    assert_eq!(
        publication.publication_id,
        id(&format!("arm-root/serial/{sequence}"))
    );
    assert_eq!(
        outcome.retained_outputs,
        [publication.publication_id.clone()]
    );
    assert_eq!(publication.payload_bytes.len(), 1);
    publication
        .payload
        .verify(&publication.payload_bytes)
        .unwrap();
    assert!(publication.causal_parents.is_empty());
    let evaluation = publication.evaluation.unwrap();
    assert_eq!(evaluation.phase, Phase::Reaction);
    assert_eq!(
        evaluation.reaction_publication(1_000_000.into()).unwrap(),
        publication.publication
    );
    assert_eq!(publication.publication.phase, Phase::Publication);
    assert_eq!(
        *reached,
        Position::new(
            publication.publication.time_ps,
            publication.publication.microstep,
            Phase::BoundaryControl,
        )
    );
    publication
}

fn repeat(runtime: &mut NodeRuntime, token: &OperationToken, expected: &OperationOutcome) {
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        runtime.poll(token, &mut context),
        Poll::Ready(Ok(outcome)) if outcome == *expected
    ));
}

fn acknowledge(runtime: &mut NodeRuntime, token: &OperationToken) {
    let receipt = runtime.scheduling_receipt(token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(token, &commit).unwrap();
}
