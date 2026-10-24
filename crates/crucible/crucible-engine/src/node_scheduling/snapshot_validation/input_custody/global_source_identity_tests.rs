//! Checks original public input identity across distinct recipient custody.
//!
//! Two admitted recipients each retain a two-input batch. Passive archived
//! progress consumes one prefix independently; these fixtures issue no Source,
//! native receipt or restoration authority. Public inventories are recomputed
//! after mutation so identity collisions are tested beyond hash consistency.

use super::*;
use crate::node_contract::{ActivationRecord, OwnerIdentity};
use crate::node_scheduling::{
    InputIdentity, NativeInputAcknowledgement, ValidatedInputAcknowledgement,
};
use crucible_node_format::Phase;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn boundary(time: u64) -> Position {
    Position::new(time.into(), 0.into(), Phase::BoundaryControl)
}

fn two_recipient_snapshot(consume_routed: bool) -> (AdmittedGraph, SchedulingSnapshot) {
    let (graph, _) = crate::node_admission::test_fixture_with_execution(false);
    let connection = graph.world().connections[0].clone();
    let root = graph.coordinator_policy().external_inputs[0].clone();
    assert_eq!(root.node_id, connection.producer.node_id);
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
            activation_id: id("original/two-recipients"),
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
    let publication = Position::new(0.into(), 0.into(), Phase::Publication);
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
        consumer: connection.consumer.node_id.clone(),
        producer_endpoint: connection.producer.clone(),
        consumer_endpoint: connection.consumer.clone(),
        source_sequence: 2.into(),
        native_sequence: 7.into(),
        evaluation: None,
        causal_parents: Vec::new(),
        publication,
        delivery: crate::node_scheduling::event::direct_delivery(publication, latency, None)
            .unwrap(),
        payload: payload.clone(),
    };
    let mut external_later = external.clone();
    external_later.publication_id = id("external/later");
    external_later.source_sequence = 1.into();
    external_later.native_sequence = 9.into();
    external_later.publication = Position::new(3.into(), 0.into(), Phase::Publication);
    external_later.delivery = Position::new(3.into(), 0.into(), Phase::Delivery);
    let mut routed_later = routed.clone();
    routed_later.publication_id = id("routed/later");
    routed_later.source_sequence = 3.into();
    routed_later.native_sequence = 8.into();
    routed_later.publication = Position::new(9.into(), 0.into(), Phase::Publication);
    routed_later.delivery =
        crate::node_scheduling::event::direct_delivery(routed_later.publication, latency, None)
            .unwrap();

    for delivery in [external, routed, external_later, routed_later] {
        scheduler.pending.insert(delivery.key(), delivery);
    }
    scheduler.payloads.insert(payload.clone(), bytes);
    scheduler
        .sequences
        .restore_next(root.node_id.clone(), Some(4.into()));
    scheduler.native_sequences.insert(root.clone(), 9.into());
    scheduler
        .native_sequences
        .insert(connection.producer.clone(), 8.into());
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

    for (index, node) in [&root.node_id, &connection.consumer.node_id]
        .into_iter()
        .enumerate()
    {
        let batch = scheduler
            .prepare_input_batch(
                node,
                id(&format!("stage/{index}")),
                id(&format!("batch/{index}")),
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
            proof_ref: payload.clone(),
        };
        let commit = scheduler
            .accept_input_acknowledgement(ValidatedInputAcknowledgement::new(
                scheduler.activation.clone(),
                acknowledgement,
            ))
            .unwrap();
        scheduler.commit_input_custody(&commit).unwrap();
    }
    let mut snapshot = scheduler.snapshot(boundary(20), 1.into()).unwrap();
    assert_eq!(snapshot.input_batches[0].node, root.node_id);
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
    if consume_routed {
        let batch = snapshot
            .input_batches
            .iter_mut()
            .find(|batch| batch.node == connection.consumer.node_id)
            .unwrap();
        let delivery = &batch.deliveries[0];
        let identity = InputIdentity {
            producer: delivery.producer.clone(),
            source_sequence: delivery.source_sequence,
        };
        batch.consumed.push(identity);
        let owner = batch.owner.clone();
        snapshot.pending_deliveries.retain(|delivery| {
            delivery.consumer != connection.consumer.node_id
                || delivery.source_sequence != U64::new(2)
        });
        snapshot
            .positions
            .iter_mut()
            .find(|row| row.owner == owner)
            .unwrap()
            .position = boundary(2);
    }
    (graph, snapshot)
}

fn reuse_first_routed_identity(snapshot: &mut SchedulingSnapshot, recipient: &Id) {
    let batch = snapshot
        .input_batches
        .iter_mut()
        .find(|batch| &batch.node == recipient)
        .unwrap();
    assert_eq!(batch.deliveries[0].source_sequence, U64::new(2));
    batch.deliveries[0].source_sequence = 0.into();
    if let Some(consumed) = batch.consumed.first_mut() {
        consumed.source_sequence = 0.into();
    }

    let bytes = crucible_node_format::canonical::canonical_json(
        &serde_json::to_value(&batch.deliveries).unwrap(),
    )
    .unwrap();
    batch.inventory = crucible_node_format::canonical::content_ref(
        &bytes,
        "application/vnd.crucible.input-inventory+json",
    )
    .unwrap();
    batch.acknowledgement.as_mut().unwrap().inventory = batch.inventory.clone();
    for delivery in &mut snapshot.pending_deliveries {
        if &delivery.consumer == recipient && delivery.source_sequence == U64::new(2) {
            delivery.source_sequence = 0.into();
        }
    }
}

#[test]
fn consumed_public_identity_cannot_reappear_at_another_pending_recipient() {
    let (graph, original) = two_recipient_snapshot(false);
    validate_saved_source(&graph, &original).unwrap();
    let mut changed = original.clone();
    reuse_first_routed_identity(&mut changed, &graph.world().connections[0].consumer.node_id);

    assert!(matches!(
        validate_saved_source(&graph, &changed),
        Err(SchedulingError::InvalidSnapshot)
    ));
}

#[test]
fn consumed_public_identity_cannot_be_shared_by_two_recipient_prefixes() {
    let (graph, original) = two_recipient_snapshot(true);
    validate_saved_source(&graph, &original).unwrap();
    let mut changed = original.clone();
    reuse_first_routed_identity(&mut changed, &graph.world().connections[0].consumer.node_id);

    assert!(matches!(
        validate_saved_source(&graph, &changed),
        Err(SchedulingError::InvalidSnapshot)
    ));
}
