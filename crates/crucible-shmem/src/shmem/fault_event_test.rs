//! Fault-event codec and transport tests.

use super::*;

fn header() -> FaultEventHeaderV1 {
    FaultEventHeaderV1 {
        command_kind: FaultCommandKind::MemoryAccessTransform,
        outcome: FaultEventOutcomeV1::Applied,
        event_sequence: 1,
        rule_command_sequence: 2,
        observed_icount: 300,
        model_phase: 18,
        target_kind: 4,
        generation: 7,
        binding_hash: [1; 32],
        opportunity_hash: [2; 32],
        action_hash: [3; 32],
        target_hash: [4; 32],
        before_hash: [5; 32],
        after_hash: [6; 32],
        evidence_hash: [0; 32],
        payload_hash: [0; 32],
        payload_offset: 0,
        payload_length: 0,
    }
}

#[test]
fn event_transport_round_trips_authenticated_payload() {
    let ring = RingHeader::new();
    let mut slots = vec![FaultEventSlotV1::new(); 2];
    let arena_header = FaultPayloadArenaHeader::new();
    let mut arena = vec![0_u8; 4096];
    let payload = b"typed-memory-access-evidence";
    enqueue_fault_event(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        65_536,
        header(),
        payload,
    )
    .expect("valid event enqueues");
    let event = dequeue_fault_event(&ring, &mut slots, &arena_header, &arena, 65_536)
        .expect("valid event transport")
        .expect("one event is present");
    assert_eq!(
        event.header.command_kind,
        FaultCommandKind::MemoryAccessTransform
    );
    assert_eq!(event.header.observed_icount, 300);
    assert_eq!(event.payload, payload);
    assert!(
        dequeue_fault_event(&ring, &mut slots, &arena_header, &arena, 65_536)
            .expect("empty transport remains valid")
            .is_none()
    );
}

#[test]
fn event_snapshot_authenticates_without_consuming_transport_ownership() {
    let ring = RingHeader::new();
    let mut slots = vec![FaultEventSlotV1::new(); 2];
    let arena_header = FaultPayloadArenaHeader::new();
    let mut arena = vec![0_u8; 4096];
    let first_payload = b"first-lifecycle-evidence";
    let second_payload = b"second-lifecycle-evidence";
    enqueue_fault_event(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        65_536,
        header(),
        first_payload,
    )
    .expect("first event enqueues");
    let mut second = header();
    second.event_sequence = 2;
    enqueue_fault_event(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        65_536,
        second,
        second_payload,
    )
    .expect("second event enqueues");

    let mut preview = Vec::with_capacity(2);
    snapshot_fault_events(&ring, &slots, &arena_header, &arena, 65_536, &mut preview)
        .expect("published events snapshot");

    assert_eq!(preview.len(), 2);
    assert_eq!(preview[0].payload, first_payload);
    assert_eq!(preview[1].payload, second_payload);
    assert_eq!(fault_event_count(&ring, &slots), Ok(2));
    assert_eq!(
        dequeue_fault_event(&ring, &mut slots, &arena_header, &arena, 65_536)
            .expect("first event remains transport-owned")
            .expect("first event remains present"),
        preview[0]
    );
    assert_eq!(fault_event_count(&ring, &slots), Ok(1));
}

#[test]
fn passed_event_cannot_change_state_digest() {
    let mut value = header();
    value.outcome = FaultEventOutcomeV1::Passed;
    value.payload_length = 1;
    assert_eq!(value.validate(), Err(FaultEventError::Invariant));
}

#[test]
fn drained_event_checkpoint_round_trips_and_rejects_trailing_bytes() {
    let payload = b"typed-memory-access-evidence".to_vec();
    let mut event_header = header();
    event_header.payload_offset = 65_536;
    event_header.payload_length = u32::try_from(payload.len()).expect("payload length fits");
    event_header.payload_hash = *blake3::hash(&payload).as_bytes();
    event_header.evidence_hash = Sha256::digest(&payload).into();
    let event = DequeuedFaultEvent {
        header: event_header,
        payload,
    };
    let bytes = event
        .canonical_bytes()
        .expect("valid drained event encodes");
    assert_eq!(
        event.canonical_length().expect("event length validates"),
        bytes.len()
    );
    let restored =
        DequeuedFaultEvent::from_canonical_bytes(&bytes).expect("canonical drained event decodes");
    assert_eq!(restored, event);
    assert_eq!(
        DequeuedFaultEvent::from_canonical_vec(bytes.clone())
            .expect("owned canonical drained event decodes"),
        event
    );
    assert_eq!(
        restored
            .canonical_bytes()
            .expect("restored event remains valid"),
        bytes
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        DequeuedFaultEvent::from_canonical_bytes(&trailing),
        Err(FaultEventError::CheckpointLength)
    );
}
