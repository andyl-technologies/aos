//! Checks consumed input identities against the saved original producer history.
//!
//! The admitted fan-in fixture models an external input followed by a routed
//! input at the same recipient. Inert archived progress consumes only the first;
//! no Source, native receipt or restoration authority is issued by these tests.

use super::*;
use crate::node_contract::{ActivationRecord, OwnerIdentity};
use crate::node_scheduling::{
    InputIdentity, NativeInputAcknowledgement, ValidatedInputAcknowledgement,
};
use crucible_node_format::{Endpoint, Phase};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn boundary(time: u64) -> Position {
    Position::new(time.into(), 0.into(), Phase::BoundaryControl)
}

fn consumed_external_input() -> (AdmittedGraph, SchedulingSnapshot) {
    let (graph, _) = crate::node_admission::test_fixture_external_fanin();
    let connection = graph.world().connections[0].clone();
    let root = connection.consumer.clone();
    let mut owners: Vec<_> = graph
        .node_ids()
        .map(|node| {
            let binding = graph.binding(node).unwrap();
            OwnerIdentity {
                owner: binding.compatibility.execution_owner.id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                generation: binding.authority.owner_generation,
            }
        })
        .collect();
    owners.sort_by(|left, right| left.owner.cmp(&right.owner));
    let activation = WorldActivation {
        nodes: std::rc::Rc::from([]),
        preparation: None,
        authority: std::rc::Rc::new(()),
        record: ActivationRecord {
            world_binding_hash: graph.world_binding_hash().clone(),
            activation_id: id("original/fanin"),
            generation: 1.into(),
            owners,
            boundary: boundary(0),
        },
    };
    let mut scheduler = CausalScheduler::new(&graph, activation).unwrap();
    let bytes = b"original fan-in payload".to_vec();
    let payload =
        crucible_node_format::canonical::content_ref(&bytes, "application/octet-stream").unwrap();

    // These are passive archived publication facts. Different native endpoints
    // have independent FIFO histories even though both inputs reach one owner.
    let external = Delivery {
        connection_id: None,
        connection_policy_ref: None,
        external_root: Some(root.clone()),
        provenance_ref: payload.clone(),
        publication_id: id("external/original"),
        producer: root.node_id.clone(),
        consumer: root.node_id.clone(),
        producer_endpoint: root.clone(),
        consumer_endpoint: root.clone(),
        source_sequence: 0.into(),
        native_sequence: 8.into(),
        evaluation: None,
        causal_parents: Vec::new(),
        publication: Position::new(0.into(), 0.into(), Phase::Publication),
        delivery: Position::new(0.into(), 0.into(), Phase::Delivery),
        payload: payload.clone(),
    };
    let publication = Position::new(9.into(), 0.into(), Phase::Publication);
    let latency = match graph.connection_policy(&connection.id).unwrap().delivery {
        crate::node_admission::ConnectionDelivery::Fixed { latency_ps } => latency_ps,
    };
    let routed = Delivery {
        connection_id: Some(connection.id.clone()),
        connection_policy_ref: Some(connection.policy_ref.clone()),
        external_root: None,
        provenance_ref: payload.clone(),
        publication_id: id("routed/original"),
        producer: connection.producer.node_id.clone(),
        consumer: root.node_id.clone(),
        producer_endpoint: connection.producer.clone(),
        consumer_endpoint: root.clone(),
        source_sequence: 0.into(),
        native_sequence: 7.into(),
        evaluation: None,
        causal_parents: Vec::new(),
        publication,
        delivery: crate::node_scheduling::event::direct_delivery(publication, latency, None)
            .unwrap(),
        payload: payload.clone(),
    };
    scheduler.pending.insert(external.key(), external);
    scheduler.pending.insert(routed.key(), routed);
    scheduler.payloads.insert(payload.clone(), bytes);
    for endpoint in [&root, &connection.producer] {
        scheduler
            .sequences
            .restore_next(endpoint.node_id.clone(), Some(1.into()));
    }
    scheduler.native_sequences.insert(root.clone(), 8.into());
    scheduler
        .native_sequences
        .insert(connection.producer.clone(), 7.into());
    for endpoint in &graph.coordinator_policy().external_inputs {
        scheduler
            .external_closed_prefixes
            .insert(endpoint.clone(), boundary(20));
    }
    let producer = &connection.producer.node_id;
    scheduler
        .bounds
        .insert(producer.clone(), OutputBound::AfterInstant(20.into()));
    scheduler
        .closed_prefixes
        .insert(producer.clone(), boundary(20));
    let producer_owner = scheduler.node_owners[producer].clone();
    scheduler.owners.get_mut(&producer_owner).unwrap().cursor = boundary(20);

    let batch = scheduler
        .prepare_input_batch(
            &root.node_id,
            id("stage/fanin"),
            id("batch/fanin"),
            boundary(11),
        )
        .unwrap();
    assert_eq!(batch.deliveries().len(), 2);
    let acknowledgement = NativeInputAcknowledgement {
        stage_operation: batch.stage_operation().clone(),
        batch: batch.batch().clone(),
        node: batch.node().clone(),
        owners: batch.owners().to_vec(),
        cutoff: batch.cutoff(),
        inventory: batch.inventory().clone(),
        proof_ref: payload,
    };
    let commit = scheduler
        .accept_input_acknowledgement(ValidatedInputAcknowledgement::new(
            scheduler.activation.clone(),
            acknowledgement,
        ))
        .unwrap();
    scheduler.commit_input_custody(&commit).unwrap();
    let mut snapshot = scheduler.snapshot(boundary(20), 1.into()).unwrap();
    let consumed = &snapshot.input_batches[0].deliveries[0];
    assert_eq!(consumed.producer_endpoint, root);
    let identity = InputIdentity {
        producer: consumed.producer.clone(),
        source_sequence: consumed.source_sequence,
    };
    snapshot.input_batches[0].consumed.push(identity);
    snapshot.pending_deliveries.remove(0);
    let consumer_owner = snapshot.input_batches[0].owner.clone();
    snapshot
        .positions
        .iter_mut()
        .find(|row| row.owner == consumer_owner)
        .unwrap()
        .position = boundary(1);
    (graph, snapshot)
}

#[test]
fn consumed_input_retains_its_original_producer_sequence_history() {
    let (graph, original) = consumed_external_input();
    validate_saved_source(&graph, &original).unwrap();
    let mut changed = original.clone();
    let producer = changed.input_batches[0].deliveries[0].producer.clone();
    changed
        .producers
        .iter_mut()
        .find(|row| row.node == producer)
        .unwrap()
        .next_sequence = Some(0.into());

    assert!(matches!(
        validate_saved_source(&graph, &changed),
        Err(SchedulingError::InvalidSnapshot)
    ));
}

#[test]
fn consumed_input_retains_its_original_native_fifo_history() {
    let (graph, original) = consumed_external_input();
    validate_saved_source(&graph, &original).unwrap();
    let mut changed = original.clone();
    let endpoint: Endpoint = changed.input_batches[0].deliveries[0]
        .producer_endpoint
        .clone();
    changed
        .native_sequences
        .iter_mut()
        .find(|row| row.endpoint == endpoint)
        .unwrap()
        .last_sequence = 7.into();

    assert!(matches!(
        validate_saved_source(&graph, &changed),
        Err(SchedulingError::InvalidSnapshot)
    ));
}

#[test]
fn consumed_input_requires_its_original_native_fifo_history() {
    let (graph, original) = consumed_external_input();
    validate_saved_source(&graph, &original).unwrap();
    let mut changed = original.clone();
    let endpoint = &original.input_batches[0].deliveries[0].producer_endpoint;
    changed
        .native_sequences
        .retain(|row| &row.endpoint != endpoint);

    assert!(matches!(
        validate_saved_source(&graph, &changed),
        Err(SchedulingError::InvalidSnapshot)
    ));
}

#[test]
fn consumed_input_accepts_an_exhausted_public_sequence_history() {
    let (graph, original) = consumed_external_input();
    validate_saved_source(&graph, &original).unwrap();
    let mut exhausted = original.clone();
    let producer = &original.input_batches[0].deliveries[0].producer;
    exhausted
        .producers
        .iter_mut()
        .find(|row| &row.node == producer)
        .unwrap()
        .next_sequence = None;

    validate_saved_source(&graph, &exhausted).unwrap();
}
