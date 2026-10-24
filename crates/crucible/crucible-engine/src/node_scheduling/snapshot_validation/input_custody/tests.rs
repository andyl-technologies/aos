//! Exercises saved input queues without issuing native restoration authority.

use super::*;
use crate::node_scheduling::{
    InputIdentity, NativeInputAcknowledgement, ValidatedInputAcknowledgement,
};
use crucible_node_format::{Endpoint, Phase};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn pending_snapshot() -> SchedulingSnapshot {
    let bytes = b"original queued payload".to_vec();
    let payload =
        crucible_node_format::canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    let mut scheduler = crate::node_scheduling::scheduler::tests::fixture(
        ExecutionPolicy::Exact {
            schema_version: 1,
            execution_proof_ref: payload.clone(),
            ceiling: ExactCeiling::StrictPredecessor,
            boundary_settlement_ref: Some(payload.clone()),
        },
        1,
        None,
    );
    for sequence in [7, 8] {
        let delivery = Delivery {
            connection_id: None,
            connection_policy_ref: None,
            external_root: None,
            provenance_ref: payload.clone(),
            publication_id: id(&format!("publication/{sequence}")),
            producer: id("Z"),
            consumer: id("A"),
            producer_endpoint: Endpoint {
                node_id: id("Z"),
                port_id: id("out"),
                lane_id: id("lane"),
            },
            consumer_endpoint: Endpoint {
                node_id: id("A"),
                port_id: id("in"),
                lane_id: id("lane"),
            },
            source_sequence: U64::new(sequence),
            native_sequence: U64::new(sequence),
            evaluation: None,
            causal_parents: Vec::new(),
            publication: Position::new(0.into(), 0.into(), Phase::Publication),
            delivery: Position::new(0.into(), 0.into(), Phase::Delivery),
            payload: payload.clone(),
        };
        scheduler.pending.insert(delivery.key(), delivery);
    }
    scheduler.payloads.insert(payload.clone(), bytes);
    let batch = scheduler
        .prepare_input_batch(
            &id("A"),
            id("stage/original"),
            id("batch/original"),
            Position::new(1.into(), 0.into(), Phase::BoundaryControl),
        )
        .unwrap();
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
    scheduler
        .snapshot(
            Position::new(0.into(), 0.into(), Phase::BoundaryControl),
            1.into(),
        )
        .unwrap()
}

// Models the archived consumed prefix, without inventing a native receipt.
fn partially_consumed_snapshot() -> SchedulingSnapshot {
    let mut snapshot = pending_snapshot();
    let delivery = &snapshot.input_batches[0].deliveries[0];
    snapshot.input_batches[0].consumed = vec![InputIdentity {
        producer: delivery.producer.clone(),
        source_sequence: delivery.source_sequence,
    }];
    snapshot.pending_deliveries.remove(0);
    snapshot
}

#[test]
fn pending_and_partially_consumed_input_inventories_remain_valid() {
    for snapshot in [pending_snapshot(), partially_consumed_snapshot()] {
        super::super::validate_structure(&snapshot).unwrap();
    }
}

#[test]
fn consumed_input_cannot_reappear_in_the_same_recipient_queue() {
    let original = partially_consumed_snapshot();
    for changed_position in [false, true] {
        let mut snapshot = original.clone();
        let mut replay = snapshot.input_batches[0].deliveries[0].clone();
        if changed_position {
            replay.delivery.time_ps = 1.into();
            replay.publication_id = id("replacement-publication");
        }
        snapshot.pending_deliveries.push(replay);
        snapshot.pending_deliveries.sort_by_key(Delivery::key);

        assert!(matches!(
            super::super::validate_structure(&snapshot),
            Err(SchedulingError::InvalidSnapshot)
        ));
    }
}

#[test]
fn consumed_input_does_not_remove_another_recipient_or_sequence() {
    let original = partially_consumed_snapshot();
    for other_recipient in [false, true] {
        let mut snapshot = original.clone();
        let mut independent = snapshot.input_batches[0].deliveries[0].clone();
        if other_recipient {
            independent.consumer = id("other-recipient");
            independent.consumer_endpoint.node_id = independent.consumer.clone();
        } else {
            independent.source_sequence = 9.into();
        }
        snapshot.pending_deliveries.push(independent);
        snapshot.pending_deliveries.sort_by_key(Delivery::key);

        super::super::validate_structure(&snapshot).unwrap();
    }
}
