//! Native-free adversaries for the test-only original custody comparator.

use super::*;
use crucible_core::{
    node_contract::{
        ExactBoundaryPolicy, Lifecycle, NodeRoute, OperationOutcome, OperationRequest,
        OwnerIdentity, ProgressEvidence, SavedRuntimeActivation, SavedRuntimeOwner,
        SavedSchedulingCommit, StopReason,
    },
    node_scheduling::{
        InputIdentity, InputPayload, NativeInputAcknowledgement, NativeInputProgress,
    },
};
use crucible_node_contract::{Phase, U64};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn endpoint(node: &str) -> Endpoint {
    Endpoint {
        node_id: id(node),
        port_id: id("port"),
        lane_id: id("lane"),
    }
}

fn reference(bytes: &[u8]) -> ContentRef {
    canonical::content_ref(bytes, "application/octet-stream").unwrap()
}

fn position(time: u64, phase: Phase) -> Position {
    Position::new(U64::new(time), U64::new(0), phase)
}

fn fixture(label: &str) -> (RuntimeSnapshot, SelectedRoute, Vec<(Id, NativePublication)>) {
    // This authored DTO supplies no native authority. Distinct IDs deliberately
    // exercise correspondence while all original causal positions remain exact.
    let owners: Vec<_> = ["source-a", "disk-a"]
        .into_iter()
        .map(|node| OwnerIdentity {
            owner: id(&format!("owner/{node}")),
            incarnation: id(&format!("{label}/{node}")),
            generation: U64::new(1),
        })
        .collect();
    let route = SelectedRoute {
        connection: id("source-to-disk"),
        producer: endpoint("source-a"),
        consumer: endpoint("disk-a"),
        policy: reference(b"same selected policy"),
        latency_ps: U64::new(0),
    };
    let producer = NativePublication {
        publication_id: id(&format!("{label}/source-output")),
        endpoint: route.producer.clone(),
        native_sequence: U64::new(0),
        publication: Position::new(U64::new(10), U64::new(1), Phase::Publication),
        evaluation: Some(position(10, Phase::Reaction)),
        causal_parents: Vec::new(),
        payload: reference(b"original request"),
        payload_bytes: b"original request".to_vec(),
    };
    let delivery = Delivery {
        connection_id: Some(route.connection.clone()),
        connection_policy_ref: Some(route.policy.clone()),
        external_root: None,
        provenance_ref: reference(format!("{label}/source-proof").as_bytes()),
        publication_id: producer.publication_id.clone(),
        producer: id("source-a"),
        consumer: id("disk-a"),
        producer_endpoint: route.producer.clone(),
        consumer_endpoint: route.consumer.clone(),
        source_sequence: U64::new(0),
        native_sequence: producer.native_sequence,
        evaluation: producer.evaluation,
        causal_parents: producer.causal_parents.clone(),
        publication: producer.publication,
        delivery: Position::new(U64::new(10), U64::new(1), Phase::Delivery),
        payload: producer.payload.clone(),
    };
    let disk = NativePublication {
        publication_id: id(&format!("{label}/disk-output")),
        endpoint: endpoint("disk-a"),
        native_sequence: U64::new(0),
        publication: Position::new(U64::new(1010), U64::new(1), Phase::Publication),
        evaluation: Some(position(1010, Phase::Reaction)),
        causal_parents: vec![delivery.delivery],
        payload: reference(b"original response"),
        payload_bytes: b"original response".to_vec(),
    };
    let mut input = SavedRuntimeInput {
        node: id("disk-a"),
        stage_operation: id(&format!("{label}/stage")),
        batch: id(&format!("{label}/batch")),
        owners: vec![owners[1].clone()],
        cutoff: position(2000, Phase::BoundaryControl),
        inventory: reference(b"replaced by canonical inventory"),
        deliveries: vec![delivery.clone()],
        payloads: vec![InputPayload {
            reference: producer.payload.clone(),
            bytes: producer.payload_bytes.clone(),
        }],
        provenance: None,
        acknowledgement: None,
        failure: None,
        committed: true,
        coordinator_committed: true,
    };
    let disk_proof = reference(format!("{label}/disk-proof").as_bytes());
    input.acknowledgement = Some(NativeInputAcknowledgement {
        stage_operation: input.stage_operation.clone(),
        batch: input.batch.clone(),
        node: input.node.clone(),
        owners: input.owners.clone(),
        cutoff: input.cutoff,
        inventory: input.inventory.clone(),
        proof_ref: reference(format!("{label}/input-ack").as_bytes()),
    });
    reseal_input(&mut input);

    let operations = [producer.clone(), disk.clone()]
        .into_iter()
        .enumerate()
        .map(|(index, publication)| {
            let operation = id(&format!("{label}/operation/{index}"));
            let node = publication.endpoint.node_id.clone();
            let retained_outputs = vec![publication.publication_id.clone()];
            let observation = NativeSchedulingObservation {
                node: node.clone(),
                owners: vec![owners[index].clone()],
                reached: input.cutoff,
                closed_prefix: input.cutoff,
                bounds: Vec::new(),
                publications: vec![publication],
                input_progress: (index == 1).then(|| NativeInputProgress {
                    batch: input.batch.clone(),
                    consumed: vec![InputIdentity {
                        producer: id("source-a"),
                        source_sequence: U64::new(0),
                    }],
                    proof_ref: disk_proof.clone(),
                }),
                external_inputs: Vec::new(),
                proof_ref: if index == 0 {
                    delivery.provenance_ref.clone()
                } else {
                    disk_proof.clone()
                },
            };
            let outcome = OperationOutcome {
                operation: operation.clone(),
                node: node.clone(),
                owners: observation.owners.clone(),
                progress: ProgressEvidence::Exact {
                    reached: input.cutoff,
                    stop: StopReason::HorizonPark,
                },
                retained_outputs: retained_outputs.clone(),
                scheduling: Some(observation),
            };
            SavedRuntimeOperation {
                operation: operation.clone(),
                route: NodeRoute {
                    node: node.clone(),
                    owners: outcome.owners.clone(),
                },
                request: OperationRequest::ExactRun {
                    start: position(0, Phase::BoundaryControl),
                    limit: input.cutoff,
                    boundary_policy: ExactBoundaryPolicy::HorizonPark,
                },
                input_batch: (index == 1).then(|| input.batch.clone()),
                result: SavedRuntimeResult::Acknowledged(outcome),
                close_submission: None,
                submission_effects: None,
                scheduling_commit: Some(SavedSchedulingCommit {
                    node,
                    operation,
                    retained_outputs,
                }),
            }
        })
        .collect();
    let runtime = RuntimeSnapshot {
        schema_version: 1,
        source_activation: SavedRuntimeActivation {
            generation: U64::new(1),
            activation_id: id(&format!("{label}/activation")),
            world_binding_hash: canonical::hash("test-only-comparator-world", b"same world")
                .unwrap(),
            owners: owners.clone(),
            boundary: position(0, Phase::BoundaryControl),
        },
        capture_cut: input.cutoff,
        capture_ordinal: U64::new(1),
        owners: owners
            .into_iter()
            .map(|identity| SavedRuntimeOwner {
                identity,
                lifecycle: Lifecycle::Stopped,
                operation: None,
                domains: Vec::new(),
            })
            .collect(),
        operations,
        inputs: vec![input],
        terminal: None,
        condition_stop: None,
    };
    let rows = vec![(id("source-a"), producer), (id("disk-a"), disk)];
    (runtime, route, rows)
}

fn reseal_input(input: &mut SavedRuntimeInput) {
    let bytes =
        canonical::canonical_json(&serde_json::to_value(&input.deliveries).unwrap()).unwrap();
    input.inventory =
        canonical::content_ref(&bytes, "application/vnd.crucible.input-inventory+json").unwrap();
    input.acknowledgement.as_mut().unwrap().inventory = input.inventory.clone();
}

fn acknowledged_observation(
    operation: &mut SavedRuntimeOperation,
) -> &mut NativeSchedulingObservation {
    let SavedRuntimeResult::Acknowledged(outcome) = &mut operation.result else {
        panic!("authored acknowledged outcome");
    };
    outcome.scheduling.as_mut().unwrap()
}

fn empty_consuming_operation(
    original: &SavedRuntimeOperation,
    name: &str,
    start: u64,
    end: u64,
) -> SavedRuntimeOperation {
    let mut consumer = original.clone();
    consumer.operation = id(name);
    consumer.request = OperationRequest::ExactRun {
        start: position(start, Phase::BoundaryControl),
        limit: position(end, Phase::BoundaryControl),
        boundary_policy: ExactBoundaryPolicy::HorizonPark,
    };
    let SavedRuntimeResult::Acknowledged(outcome) = &mut consumer.result else {
        panic!("authored acknowledged consumer");
    };
    outcome.operation = consumer.operation.clone();
    outcome.retained_outputs.clear();
    outcome.progress = ProgressEvidence::Exact {
        reached: position(end, Phase::BoundaryControl),
        stop: StopReason::HorizonPark,
    };
    let observation = outcome.scheduling.as_mut().unwrap();
    observation.reached = position(end, Phase::BoundaryControl);
    observation.closed_prefix = observation.reached;
    observation.publications.clear();
    let commit = consumer.scheduling_commit.as_mut().unwrap();
    commit.operation = consumer.operation.clone();
    commit.retained_outputs.clear();
    consumer
}

fn historical_fixture(
    label: &str,
) -> (RuntimeSnapshot, SelectedRoute, Vec<(Id, NativePublication)>) {
    let (mut runtime, route, rows) = fixture(label);
    let consumer = empty_consuming_operation(
        &runtime.operations[1],
        &format!("{label}/earlier-consumer"),
        0,
        500,
    );
    let producing = &mut runtime.operations[1];
    producing.input_batch = None;
    producing.request = OperationRequest::ExactRun {
        start: position(500, Phase::BoundaryControl),
        limit: position(2000, Phase::BoundaryControl),
        boundary_policy: ExactBoundaryPolicy::HorizonPark,
    };
    acknowledged_observation(producing).input_progress = None;
    runtime.operations.insert(1, consumer);
    let input = &mut runtime.inputs[0];
    input.cutoff = position(500, Phase::BoundaryControl);
    input.acknowledgement.as_mut().unwrap().cutoff = input.cutoff;
    (runtime, route, rows)
}

#[test]
fn different_original_ids_keep_complete_publication_and_delivery_correspondence() {
    let (left, route, left_rows) = fixture("left");
    let (right, _, right_rows) = fixture("right");
    let source = inspect(&left, &left_rows).unwrap();
    let target = inspect(&right, &right_rows).unwrap();

    let pairs = compare_sides(&source, &target, &route).unwrap();

    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[&id("left/source-output")], id("right/source-output"));
    assert_eq!(pairs[&id("left/disk-output")], id("right/disk-output"));
    assert_ne!(
        left_rows[0].1.publication_id,
        right_rows[0].1.publication_id
    );
    assert_eq!(
        left_rows[1].1.causal_parents,
        right_rows[1].1.causal_parents
    );
}

#[test]
fn missing_original_commit_input_or_ack_refuses_before_correspondence() {
    let (original, _, rows) = fixture("source");
    let mut missing = original.clone();
    missing.operations[0].scheduling_commit = None;
    assert!(inspect(&missing, &rows).is_err());

    missing = original.clone();
    missing.inputs.clear();
    assert!(inspect(&missing, &rows).is_err());

    missing = original;
    missing.inputs[0].acknowledgement = None;
    assert!(inspect(&missing, &rows).is_err());
}

#[test]
fn rehashed_foreign_provenance_or_endpoint_does_not_replace_original_delivery() {
    let (original, _, rows) = fixture("source");
    let mut foreign = original.clone();
    foreign.inputs[0].deliveries[0].provenance_ref = reference(b"foreign retained proof");
    reseal_input(&mut foreign.inputs[0]);
    assert!(inspect(&foreign, &rows).is_err());

    foreign = original;
    foreign.inputs[0].deliveries[0].producer_endpoint = endpoint("foreign");
    reseal_input(&mut foreign.inputs[0]);
    assert!(inspect(&foreign, &rows).is_err());
}

#[test]
fn self_consistent_changed_causal_edge_still_refuses_twin_correspondence() {
    let (left, route, left_rows) = fixture("left");
    let (mut right, _, right_rows) = fixture("right");
    right.inputs[0].deliveries[0].source_sequence = U64::new(2);
    reseal_input(&mut right.inputs[0]);
    let SavedRuntimeResult::Acknowledged(outcome) = &mut right.operations[1].result else {
        panic!("authored outcome");
    };
    outcome
        .scheduling
        .as_mut()
        .unwrap()
        .input_progress
        .as_mut()
        .unwrap()
        .consumed[0]
        .source_sequence = U64::new(2);
    let source = inspect(&left, &left_rows).unwrap();
    let target = inspect(&right, &right_rows).unwrap();

    assert_eq!(
        compare_sides(&source, &target, &route).unwrap_err(),
        "twin original routed causal edge changed"
    );
}

#[test]
fn missing_causal_parent_is_not_hidden_by_comparing_both_mutated_sides() {
    let (mut left, route, mut left_rows) = fixture("left");
    let (mut right, _, mut right_rows) = fixture("right");
    for (runtime, rows) in [(&mut left, &mut left_rows), (&mut right, &mut right_rows)] {
        rows[1].1.causal_parents.clear();
        let SavedRuntimeResult::Acknowledged(outcome) = &mut runtime.operations[1].result else {
            panic!("authored outcome");
        };
        outcome.scheduling.as_mut().unwrap().publications[0]
            .causal_parents
            .clear();
    }
    let source = inspect(&left, &left_rows).unwrap();
    let target = inspect(&right, &right_rows).unwrap();

    assert_eq!(
        compare_sides(&source, &target, &route).unwrap_err(),
        "closed fixture causal edge missing or foreign"
    );
}

#[test]
fn publishing_batch_cannot_borrow_consumption_from_a_later_operation() {
    let (mut runtime, route, rows) = fixture("original");
    let later = empty_consuming_operation(&runtime.operations[1], "later-consumer", 2000, 3000);
    acknowledged_observation(&mut runtime.operations[1])
        .input_progress
        .as_mut()
        .unwrap()
        .consumed
        .clear();
    runtime.operations.push(later);
    let side = inspect(&runtime, &rows).unwrap();

    assert_eq!(
        compare_sides(&side, &side, &route).unwrap_err(),
        "causal edge outside producing operation consumed prefix"
    );
}

#[test]
fn no_input_pending_response_keeps_its_unique_earlier_original_consumption() {
    let (left, route, left_rows) = historical_fixture("left");
    let (right, _, right_rows) = historical_fixture("right");
    let source = inspect(&left, &left_rows).unwrap();
    let target = inspect(&right, &right_rows).unwrap();

    let pairs = compare_sides(&source, &target, &route).unwrap();

    assert_eq!(pairs[&id("left/disk-output")], id("right/disk-output"));
    assert!(left.operations[2].input_batch.is_none());
    assert_eq!(left_rows[1].1.causal_parents.len(), 1);
}

#[test]
fn no_input_response_cannot_borrow_a_later_consumption_cut() {
    let (mut runtime, route, rows) = historical_fixture("original");
    runtime.operations[1] =
        empty_consuming_operation(&runtime.operations[1], "later-consumer", 2000, 3000);
    let side = inspect(&runtime, &rows).unwrap();

    assert_eq!(
        compare_sides(&side, &side, &route).unwrap_err(),
        "causal edge lacks earlier acknowledged original consumption"
    );
}
