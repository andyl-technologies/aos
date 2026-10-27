//! Exercises exact progressed-model comparison without fabricating a live scope.

use super::*;
use crate::reference_packet::{PacketEvent, PacketGrant, PacketInventory, PacketPublication};
use crucible_node_format::{Bytes, Phase, U64};

fn position(time: u64, phase: Phase) -> Position {
    Position::new(U64::new(time), U64::new(0), phase)
}
fn event(id: &str, time: u64, payload: bool) -> PacketEvent {
    PacketEvent {
        id: Id::new(id).unwrap(),
        evaluation: position(time, Phase::Reaction),
        completion: position(
            time + 1,
            if payload {
                Phase::Publication
            } else {
                Phase::Reaction
            },
        ),
        payload: payload.then(|| Bytes::new(vec![7, 11, 13])),
    }
}
fn inventory() -> PacketInventory {
    PacketInventory {
        reached: position(0, Phase::BoundaryControl),
        gate_closed: false,
        pending: vec![event("private", 2, false), event("packet", 5, true)],
        retained_outputs: Vec::new(),
        private_mutations: U64::new(0),
        packet_effects: U64::new(0),
    }
}

#[test]
fn two_progressed_operations_keep_real_prefix_and_refuse_rewritten_history() {
    let before = inventory();
    let first_id = Id::new("first-real-operation").unwrap();
    let first = PacketRestoredProducerOperationData {
        operation: &first_id,
        kind: BeginKind::ExactRun,
        start: before.reached,
        limit: position(5, Phase::BoundaryControl),
    };
    let mut middle = before.clone();
    middle.pending.remove(0);
    middle.private_mutations = U64::new(1);
    middle.reached = first.limit;
    let grant = PacketGrant {
        operation: first_id.clone(),
        start: first.start,
        limit: first.limit,
        inventory: middle.clone(),
        newborn: Vec::new(),
        complete: true,
    };
    completed::transition(&before, &grant, &first).unwrap();
    let second_id = Id::new("second-real-operation").unwrap();
    let second = PacketRestoredProducerOperationData {
        operation: &second_id,
        kind: BeginKind::ExactRun,
        start: middle.reached,
        limit: position(8, Phase::BoundaryControl),
    };
    let output = &middle.pending[0];
    let publication = PacketPublication {
        event: output.id.clone(),
        operation: second_id.clone(),
        sequence: U64::new(1),
        evaluation: output.evaluation,
        publication: output.completion,
        payload: output.payload.clone().unwrap(),
    };
    let mut after = middle.clone();
    after.pending.clear();
    after.retained_outputs = vec![publication.clone()];
    after.packet_effects = U64::new(1);
    after.reached = second.limit;
    let mut grant = PacketGrant {
        operation: second_id.clone(),
        start: second.start,
        limit: second.limit,
        inventory: after,
        newborn: vec![publication],
        complete: true,
    };
    completed::transition(&middle, &grant, &second).unwrap();
    grant.inventory.private_mutations = U64::new(0);
    assert!(completed::transition(&middle, &grant, &second).is_err());
    grant.inventory.private_mutations = U64::new(1);
    grant.newborn[0].operation = first_id;
    assert!(completed::transition(&middle, &grant, &second).is_err());
}

#[test]
fn exclusive_ceiling_leaves_straddled_callback_whole_and_partial_grants_refuse() {
    let mut before = inventory();
    before.pending.remove(0);
    before.private_mutations = U64::new(1);
    before.reached = position(5, Phase::BoundaryControl);
    let id = Id::new("attention-original").unwrap();
    let op = PacketRestoredProducerOperationData {
        operation: &id,
        kind: BeginKind::ExactRun,
        start: before.reached,
        limit: position(6, Phase::BoundaryControl),
    };
    let mut after = before.clone();
    after.reached = before.pending[0].evaluation;
    let mut grant = PacketGrant {
        operation: id.clone(),
        start: op.start,
        limit: op.limit,
        inventory: after,
        newborn: Vec::new(),
        complete: true,
    };
    completed::transition(&before, &grant, &op).unwrap();
    grant.complete = false;
    assert!(completed::transition(&before, &grant, &op).is_err());
    grant.complete = true;
    grant.inventory.pending.clear();
    assert!(completed::transition(&before, &grant, &op).is_err());
}

#[test]
fn preprepare_report_bound_has_no_live_checkpoint_and_one_short_refuses() {
    let row = report_storage::projection(usize::MAX).unwrap();
    assert!(row.maximum_encoded_bytes > 0);
    assert!(row.retained_value_backing_bytes > row.maximum_encoded_bytes);
    assert!(row.serializer_temporary_requested_bytes >= 8 * 32);
    let requested = row.requested_total().unwrap();
    assert!(report_storage::projection(requested - 1).is_err());
}
