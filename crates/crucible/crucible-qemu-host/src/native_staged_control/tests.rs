//! Actual Unix stream ordering with synthetic source receipt bodies.
//!
//! These controls authenticate byte custody and protocol ordering only. Their
//! synthetic peer and fixture plan grant no installed native Ready capability.

// crucible-lint: allow panic-shortcut -- Socket controls panic on invalid vectors or lost original custody.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_qemu_protocol::whole_control::WholeControlProfile;
use crucible_qemu_protocol::whole_control::inventory::{WholeQueueRecord, WholeQueueRole};
use crucible_qemu_protocol::whole_control::staged::body::StageInventoryParts;
use std::io::{Read, Write};

fn put_u32(body: &mut [u8], offset: usize, value: u32) {
    body[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(body: &mut [u8], offset: usize, value: u64) {
    body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn queue_plan() -> Vec<u8> {
    use crucible_qemu_protocol::whole_control::staged::queue_plan::QueueRole;

    let mut roles = Vec::new();
    for (role, index, header, entries) in [
        (WholeQueueRole::PacketDelivery, 4, 128, 4096),
        (WholeQueueRole::PacketPublication, 5, 256, 9216),
    ] {
        let role = QueueRole {
            role,
            ring_index: index,
            source_slot: 1,
            target_slot: 2,
            capacity: 1,
            generation: 7,
            header_offset: header,
            entries_offset: entries,
            transport_epoch: 0,
            producer_frontier: 9,
            node: "node/1",
            port: "packet",
            lane: "rx",
        };
        let mut body = vec![0; 80 + role.node.len() + role.port.len() + role.lane.len()];
        role.encode_into(&mut body).unwrap();
        roles.extend_from_slice(&body);
    }
    let mut body = vec![0; 128 + roles.len()];
    body[..8].copy_from_slice(b"CWHLQUE\0");
    put_u32(&mut body, 8, 2);
    let extent = body.len() as u32;
    put_u32(&mut body, 12, extent);
    body[16..48].fill(1);
    for (offset, value) in [
        (48, 7),
        (56, 8),
        (64, 9),
        (72, 16384),
        (88, 3),
        (96, 200),
        (104, 50),
    ] {
        put_u64(&mut body, offset, value);
    }
    put_u32(&mut body, 80, 2);
    put_u32(&mut body, 112, 50);
    put_u32(&mut body, 116, 1);
    body[128..].copy_from_slice(&roles);
    body
}

pub(super) fn profile() -> StagedControlProfile {
    StagedControlProfile {
        compute: WholeControlProfile {
            scope: [1; 32],
            operation_capacity: 4,
            body_byte_limit: 65536,
            native_history_byte_limit: 4 * 1024 * 1024,
            provider_history_byte_limit: 4 * 1024 * 1024,
            administrative_read_attempt_limit: 128,
            administrative_read_byte_limit: 4 * 1024 * 1024,
            administrative_write_attempt_limit: 128,
            administrative_write_byte_limit: 4 * 1024 * 1024,
            deadline_monotonic_ns: monotonic_ns().unwrap() + 10_000_000_000,
            cpu_retirement_limit: 4,
            event_step_limit: 4,
            input_byte_limit: 12,
            input_record_limit: 4,
            output_byte_limit: 0,
            output_record_limit: 0,
        },
        input_stage_limit: 9,
        stage_body_byte_limit: 1024,
    }
}

fn input_inventory() -> Vec<u8> {
    let record = WholeQueueRecord {
        role: WholeQueueRole::PacketDelivery,
        ring_index: 4,
        source_slot: 1,
        target_slot: 2,
        frame_sequence: 3,
        ring_generation: 7,
        read_index: 5,
        write_index: 5,
        transport_epoch: 0,
        native_id: 0,
        time_ps: 250,
        microstep: 0,
        phase: 2,
        delivery_state: 0,
        ring_offset: 128,
        entries_offset: 4096,
        capacity: 1,
        delivery_attempts: 0,
        last_attempt_icount: 0,
        frame_delivery_icount: 4,
        node: "node/1",
        port: "packet",
        lane: "rx",
        media_type: "application/octet-stream",
        common_envelope: b"complete-common-delivery",
        payload: b"abc",
    };
    let extent = 216
        + record.node.len()
        + record.port.len()
        + record.lane.len()
        + record.media_type.len()
        + record.common_envelope.len()
        + record.payload.len();
    let mut body = vec![0; 8 + extent];
    put_u32(&mut body, 0, 1);
    record.encode_into(&mut body[8..]).unwrap();
    body
}

fn stage(inventory: &[u8]) -> Vec<u8> {
    let parts = StageInventoryParts {
        scope: [1; 32],
        native_epoch: 7,
        stage_sequence: 1,
        stage_operation: "stage-1",
        batch: "batch-1",
        node: "node/1",
        cutoff_ps: 250,
        cutoff_microstep: 3,
        common_inventory_digest: [4; 32],
        common_batch: b"full-canonical-batch-and-original-evidence",
        queue_inventory: inventory,
    };
    let mut body = vec![
        0;
        128 + parts.stage_operation.len()
            + parts.batch.len()
            + parts.node.len()
            + parts.common_batch.len()
            + inventory.len()
    ];
    parts.encode_into(&mut body).unwrap();
    body
}

fn frame(kind: StagedFrameKind, body: &[u8]) -> Vec<u8> {
    let mut frame = encode_staged_frame_header(kind, body.len(), &profile())
        .unwrap()
        .to_vec();
    frame.extend_from_slice(body);
    frame
}

fn established() -> (NativeStagedControlTransport, UnixStream) {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let mut actor = NativeStagedControlTransport::new(socket, profile()).unwrap();
    let body = queue_plan();
    let plan_frame = frame(StagedFrameKind::QueuePlan, &body);
    peer.write_all(&plan_frame[..9]).unwrap();
    assert!(!actor.poll_original().unwrap());
    assert!(actor.original_queue_plan().is_none());
    peer.write_all(&plan_frame[9..]).unwrap();
    assert!(!actor.poll_original().unwrap());
    assert!(actor.poll_original().unwrap());
    assert_eq!(actor.original_queue_plan().unwrap(), body);
    assert!(actor.transmit_plan_acknowledgement().unwrap());
    let mut received = [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES];
    peer.read_exact(&mut received).unwrap();
    let ack = QueuePlanAcknowledgement::decode(&received[WHOLE_FRAME_HEADER_BYTES..]).unwrap();
    ack.validate_against(&QueuePlan::decode(&body).unwrap(), &actor.profile)
        .unwrap();
    (actor, peer)
}

fn offered_stage(
    actor: &mut NativeStagedControlTransport,
    peer: &mut UnixStream,
    sequence: u64,
) -> Vec<u8> {
    let mut body = stage(&input_inventory());
    put_u64(&mut body, 48, sequence);
    actor.retain_stage(&body).unwrap();
    assert!(actor.transmit_original().unwrap());
    let mut received = vec![0; WHOLE_FRAME_HEADER_BYTES + body.len()];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(received, frame(StagedFrameKind::StageInventory, &body));
    let inventory = StageInventory::decode(&body).unwrap();
    let receipt = StageReceipt {
        scope: inventory.scope,
        native_epoch: inventory.native_epoch,
        stage_sequence: sequence,
        stage_body_digest: inventory.digest(),
        common_inventory_digest: inventory.common_inventory_digest,
        queue_plan_digest: actor.queue_plan_digest,
        accepted_records: u64::from(inventory.queue_inventory.record_count()),
        accepted_payload_bytes: inventory.payload_byte_count().unwrap(),
        cutoff_ps: inventory.cutoff_ps,
        cutoff_microstep: inventory.cutoff_microstep,
        reservation_digest: [6; 32],
        stage_cut: sequence,
    }
    .encode()
    .unwrap();
    peer.write_all(&frame(StagedFrameKind::StageReceipt, &receipt))
        .unwrap();
    assert!(!actor.poll_original().unwrap());
    assert!(actor.poll_original().unwrap());
    assert_eq!(actor.original_stage_receipt(sequence).unwrap(), receipt);
    body
}

fn consumed_stage(
    actor: &mut NativeStagedControlTransport,
    peer: &mut UnixStream,
    sequence: u64,
) -> Vec<u8> {
    let body = offered_stage(actor, peer, sequence);
    assert!(actor.transmit_commit().unwrap());
    let mut commit = [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES];
    peer.read_exact(&mut commit).unwrap();
    let consumed = frame(
        StagedFrameKind::StageCommitAcknowledgement,
        &commit[WHOLE_FRAME_HEADER_BYTES..],
    );
    peer.write_all(&consumed).unwrap();
    assert!(!actor.poll_original().unwrap());
    assert!(actor.poll_original().unwrap());
    assert!(actor.stage_committed(sequence));
    body
}

fn compute(stage: &[u8], compute_sequence: u64) -> Vec<u8> {
    let stage = StageInventory::decode(stage).unwrap();
    let mut references = [0; 72];
    put_u32(&mut references, 0, 1);
    put_u64(&mut references, 8, stage.stage_sequence);
    put_u64(&mut references, 16, stage.stage_sequence);
    references[24..56].copy_from_slice(&stage.digest());
    put_u32(&mut references, 60, 1);
    let request = WholeRequest {
        scope: stage.scope,
        epoch: stage.native_epoch,
        sequence: compute_sequence,
        grant_digest: [2; 32],
        binding_digest: [3; 32],
        start_ps: 200,
        limit_ps: 300,
        quota: WholeOperationQuota {
            input_bytes: 3,
            input_records: 1,
            output_bytes: 0,
            output_records: 0,
            cpu_retirements: 2,
            event_steps: 1,
        },
        input_inventory: &references,
    };
    let mut body = vec![0; 256 + references.len()];
    request.encode_staged_into(&mut body).unwrap();
    body
}

#[test]
fn receipt_and_sent_commit_cannot_admit_compute_before_exact_consumed_commit() {
    let (mut actor, mut peer) = established();
    let body = offered_stage(&mut actor, &mut peer, 1);
    assert!(actor.transmit_commit().unwrap());
    let mut sent = [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES];
    peer.read_exact(&mut sent).unwrap();
    assert!(!actor.stage_committed(1));
    assert!(matches!(
        actor.retain_compute(&compute(&body, 1)),
        Err(NativeWholeControlError::Custody)
    ));
    assert_eq!(actor.custody.as_ref().unwrap().compute_count, 0);
    assert_eq!(
        actor.original_stage_receipt(1).unwrap().len(),
        STAGE_RECEIPT_BYTES
    );
    assert!(actor.refused);
}

#[test]
fn stage_and_compute_indexes_are_independent_and_input_is_charged_once() {
    let (mut actor, mut peer) = established();
    consumed_stage(&mut actor, &mut peer, 1);
    let second = consumed_stage(&mut actor, &mut peer, 2);
    let original = compute(&second, 1);
    actor.retain_compute(&original).unwrap();
    assert!(actor.transmit_original().unwrap());
    let mut received = vec![0; WHOLE_FRAME_HEADER_BYTES + original.len()];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(
        received,
        frame(StagedFrameKind::ExecutionRequest, &original)
    );
    actor.retain_compute(&original).unwrap();
    let custody = actor.custody.as_ref().unwrap();
    assert_eq!(custody.stage_count, 2);
    assert_eq!(custody.compute_count, 1);
    assert_eq!(custody.charged.input_records, 2);
    assert_eq!(custody.charged.input_bytes, 6);
    assert!(!custody.stages[0].selected[0]);
    assert!(custody.stages[1].selected[0]);
    assert_eq!(custody.charged.cpu_retirements, 2);
}

#[test]
fn changed_consumed_commit_keeps_partial_frame_receipt_and_world_custody() {
    let (mut actor, mut peer) = established();
    offered_stage(&mut actor, &mut peer, 1);
    assert!(actor.transmit_commit().unwrap());
    let mut offered = [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES];
    peer.read_exact(&mut offered).unwrap();
    offered[WHOLE_FRAME_HEADER_BYTES + 96] ^= 1;
    let changed = frame(
        StagedFrameKind::StageCommitAcknowledgement,
        &offered[WHOLE_FRAME_HEADER_BYTES..],
    );
    peer.write_all(&changed[..11]).unwrap();
    assert!(!actor.poll_original().unwrap());
    assert_eq!(actor.custody.as_ref().unwrap().received, 11);
    peer.write_all(&changed[11..]).unwrap();
    assert!(!actor.poll_original().unwrap());
    assert!(matches!(
        actor.poll_original(),
        Err(NativeWholeControlError::Custody)
    ));
    assert!(!actor.stage_committed(1));
    assert_eq!(
        &actor.custody.as_ref().unwrap().scratch[..changed.len()],
        changed
    );
    assert_eq!(
        actor.original_stage_receipt(1).unwrap().len(),
        STAGE_RECEIPT_BYTES
    );
}

#[test]
fn nonexistent_stage_and_foreign_plan_offsets_refuse_without_replacing_originals() {
    let (mut actor, mut peer) = established();
    let mut stage_body = consumed_stage(&mut actor, &mut peer, 1);
    put_u64(&mut stage_body, 48, 2);
    assert!(matches!(
        actor.retain_compute(&compute(&stage_body, 1)),
        Err(NativeWholeControlError::Custody)
    ));
    assert_eq!(actor.custody.as_ref().unwrap().compute_count, 0);

    let (mut actor, _peer) = established();
    let mut inventory = input_inventory();
    // Offset 112 in the complete queue record is the entries backing. The
    // changed region still parses, but it is foreign to the original plan.
    put_u64(&mut inventory, 8 + 112, 8192);
    let stage_body = stage(&inventory);
    assert!(actor.retain_stage(&stage_body).is_err());
    assert_eq!(actor.custody.as_ref().unwrap().stage_count, 0);
}

fn offered_compute(actor: &mut NativeStagedControlTransport, peer: &mut UnixStream) -> Vec<u8> {
    let body = consumed_stage(actor, peer, 1);
    let request = compute(&body, 1);
    actor.retain_compute(&request).unwrap();
    assert!(actor.transmit_original().unwrap());
    let mut received = vec![0; WHOLE_FRAME_HEADER_BYTES + request.len()];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(&received[WHOLE_FRAME_HEADER_BYTES..], request);
    request
}

fn result(
    request_body: &[u8],
    disposition: crucible_qemu_protocol::whole_control::body::WholeResultDisposition,
    records: u64,
    bytes: u64,
) -> Vec<u8> {
    let request = WholeRequest::decode_staged(request_body).unwrap();
    let result = WholeResult {
        scope: request.scope,
        epoch: request.epoch,
        sequence: request.sequence,
        request_digest: crucible_qemu_protocol::whole_control::body::whole_staged_request_digest(
            request_body,
        )
        .unwrap(),
        binding_digest: request.binding_digest,
        input_inventory_digest: request_body[120..152].try_into().unwrap(),
        stopped_ps: request.limit_ps,
        limit_ps: request.limit_ps,
        raw_before: 3,
        raw_after: 5,
        retired: 2,
        callbacks: 0,
        input_records: records,
        input_bytes: bytes,
        output_records: 0,
        output_bytes: 0,
        cut: 11,
        disposition,
        event_steps: 0,
        event_allowance: request.quota.event_steps,
        output_inventory: &[0; 8],
    };
    let mut body = vec![
        0;
        crucible_qemu_protocol::whole_control::WHOLE_RESULT_HEADER_BYTES
            + result.output_inventory.len()
    ];
    result.encode_into(&mut body).unwrap();
    body
}

#[test]
fn referenced_record_outside_original_half_open_interval_refuses_before_compute_offer() {
    let (mut actor, mut peer) = established();
    let stage = consumed_stage(&mut actor, &mut peer, 1);
    let mut request = compute(&stage, 1);
    // The referenced original record is due at 250ps; equality with the limit
    // belongs to the following operation and cannot be offered by this grant.
    put_u64(&mut request, 176, 250);
    assert!(actor.retain_compute(&request).is_err());
    assert_eq!(actor.custody.as_ref().unwrap().compute_count, 0);
    assert!(!actor.custody.as_ref().unwrap().stages[0].selected[0]);
}

#[test]
fn smaller_complete_input_prefix_cannot_settle_original_reference_or_receive_ack() {
    use crucible_qemu_protocol::whole_control::body::WholeResultDisposition;

    let (mut actor, mut peer) = established();
    let request = offered_compute(&mut actor, &mut peer);
    let response = frame(
        StagedFrameKind::ExecutionResult,
        &result(&request, WholeResultDisposition::Complete, 0, 0),
    );
    peer.write_all(&response).unwrap();
    assert!(!actor.poll_original().unwrap());
    assert!(actor.poll_original().is_err());
    assert!(actor.transmit_commit().is_err());
    let custody = actor.custody.as_ref().unwrap();
    assert!(custody.stages[0].selected[0]);
    assert_eq!(custody.charged.input_records, 1);
    assert!(!custody.computes[0].commit_offered);
    assert_eq!(&custody.scratch[..response.len()], response);
}

#[test]
fn unknown_input_prefix_preserves_full_result_without_acknowledgement_or_credit_refund() {
    use crucible_qemu_protocol::whole_control::body::WholeResultDisposition;

    let (mut actor, mut peer) = established();
    let request = offered_compute(&mut actor, &mut peer);
    let body = result(&request, WholeResultDisposition::Unknown, 0, 0);
    peer.write_all(&frame(StagedFrameKind::ExecutionResult, &body))
        .unwrap();
    assert!(!actor.poll_original().unwrap());
    assert!(actor.poll_original().unwrap());
    assert_eq!(actor.original_result(1).unwrap(), body);
    assert!(actor.transmit_commit().is_err());
    let custody = actor.custody.as_ref().unwrap();
    assert!(custody.stages[0].selected[0]);
    assert_eq!(custody.charged.input_records, 1);
    assert_eq!(custody.charged.input_bytes, 3);
    assert!(!custody.computes[0].committed);
}
