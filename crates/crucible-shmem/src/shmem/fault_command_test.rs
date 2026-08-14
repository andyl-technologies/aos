//! Fault command ABI and transport tests.

use super::*;

fn hash(value: &[u8]) -> [u8; 32] {
    *blake3::hash(value).as_bytes()
}

fn command(payload: &[u8]) -> FaultCommandHeaderV1 {
    FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation,
        command_flags: FAULT_COMMAND_FLAG_NONE,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 7,
        target_node_hash: hash(b"node"),
        target_icount: 10,
        authorization_ceiling_icount: 12,
        binding_hash: hash(b"binding"),
        opportunity_hash: [0; 32],
        expected_precondition_hash: hash(b"before"),
        payload_hash: hash(payload),
        payload_offset: 2,
        payload_length: u32::try_from(payload.len())
            .unwrap_or_else(|error| panic!("test payload length: {error}")),
    }
}

#[test]
fn command_round_trip_authenticates_payload_and_reserved_bytes() {
    let payload = b"mutation";
    let mut arena = vec![0, 0];
    arena.extend_from_slice(payload);
    let value = command(payload);
    let bytes = value.encode();
    let (decoded, selected) = FaultCommandHeaderV1::decode(&bytes, &arena)
        .unwrap_or_else(|error| panic!("decode command: {error}"));
    assert_eq!(decoded, value);
    assert_eq!(selected, payload);

    let mut corrupt_payload = arena.clone();
    corrupt_payload[2] ^= 1;
    assert_eq!(
        FaultCommandHeaderV1::decode(&bytes, &corrupt_payload),
        Err(FaultAbiError::PayloadDigest)
    );
    let mut nonzero_reserved = bytes;
    nonzero_reserved[FAULT_COMMAND_HEADER_V1_BYTES - 1] = 1;
    assert_eq!(
        FaultCommandHeaderV1::decode(&nonzero_reserved, &arena),
        Err(FaultAbiError::ReservedNonzero)
    );
    let mut obsolete_minor = value;
    obsolete_minor.abi_minor = FAULT_COMMAND_ABI_MINOR - 1;
    assert_eq!(
        FaultCommandHeaderV1::decode(&obsolete_minor.encode(), &arena),
        Err(FaultAbiError::Version)
    );
}

#[test]
fn result_status_controls_mutation_evidence_invariants() {
    let payload = b"evidence";
    let value = FaultResultHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation as u16,
        status: FaultResultStatus::Applied,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 7,
        observed_icount: 10,
        applied_icount: 10,
        capability_version: 1,
        phase: FaultBoundaryPhase::NodeBoundary,
        before_hash: hash(b"before"),
        after_hash: hash(b"after"),
        evidence_hash: hash(b"handler-evidence"),
        result_payload_hash: hash(payload),
        result_offset: 0,
        result_length: u32::try_from(payload.len())
            .unwrap_or_else(|error| panic!("test result length: {error}")),
    };
    let bytes = value.encode();
    let (decoded, selected) = FaultResultHeaderV1::decode(&bytes, payload)
        .unwrap_or_else(|error| panic!("decode result: {error}"));
    assert_eq!(decoded, value);
    assert_eq!(selected, payload);

    let mut rejected = value.clone();
    rejected.status = FaultResultStatus::InvalidTarget;
    assert_eq!(
        FaultResultHeaderV1::decode(&rejected.encode(), payload),
        Err(FaultAbiError::ResultInvariant)
    );

    let mut prepared = value;
    prepared.status = FaultResultStatus::Prepared;
    prepared.applied_icount = 0;
    prepared.after_hash = prepared.before_hash;
    let decoded = FaultResultHeaderV1::decode(&prepared.encode(), payload)
        .unwrap_or_else(|error| panic!("decode prepared result: {error}"));
    assert_eq!(decoded.0, prepared);
    prepared.abi_minor = FAULT_COMMAND_ABI_MINOR - 1;
    assert_eq!(
        FaultResultHeaderV1::decode(&prepared.encode(), payload),
        Err(FaultAbiError::Version)
    );
}

#[test]
fn capability_manifest_is_sorted_bounded_and_content_addressed() {
    let row = |kind, scope| FaultCapabilityRowV1 {
        command_kind: kind,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        scope,
        phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
        maximum_payload_bytes: DEFAULT_FAULT_PAYLOAD_BYTES,
        maximum_pending_commands: DEFAULT_FAULT_COMMAND_CAPACITY,
        required_feature_bits: 1,
        capability_hash: hash(b"capability"),
    };
    let rows = [
        row(FaultCommandKind::NodeLifecycle, FaultCapabilityScope::All),
        row(FaultCommandKind::MemoryMutation, FaultCapabilityScope::All),
    ];
    let first = fault_capability_manifest_digest(&rows)
        .unwrap_or_else(|error| panic!("capability manifest: {error}"));
    let second = fault_capability_manifest_digest(&rows)
        .unwrap_or_else(|error| panic!("capability manifest twice: {error}"));
    assert_eq!(first, second);
    let encoded = encode_fault_capability_manifest(&rows)
        .unwrap_or_else(|error| panic!("encode capability manifest: {error}"));
    assert_eq!(
        decode_fault_capability_manifest(&encoded),
        Ok(rows.to_vec())
    );
    let mut corrupt = encoded;
    corrupt[16] ^= 1;
    assert_eq!(
        decode_fault_capability_manifest(&corrupt),
        Err(FaultAbiError::PayloadDigest)
    );
    assert_eq!(
        fault_capability_manifest_digest(&[rows[1].clone(), rows[0].clone()]),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut unknown_features = rows[0].clone();
    unknown_features.required_feature_bits = FAULT_CAPABILITY_FEATURES_V1_MASK + 1;
    assert_eq!(
        FaultCapabilityRowV1::decode(&unknown_features.encode()),
        Err(FaultAbiError::CapabilityInvariant)
    );
}

#[test]
fn result_preflight_reports_backpressure_without_mutating_transport() {
    let ring = RingHeader::new();
    let arena_header = FaultPayloadArenaHeader::new();
    let mut slots = vec![FaultResultSlotV1::new(); 2];
    let mut arena = vec![0_u8; 16];
    let rejected_result = |sequence| FaultResultHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::BoundaryProbe as u16,
        status: FaultResultStatus::InvalidTarget,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: sequence,
        observed_icount: 4,
        applied_icount: 0,
        capability_version: 1,
        phase: FaultBoundaryPhase::NodeBoundary,
        before_hash: [0; 32],
        after_hash: [0; 32],
        evidence_hash: hash(b"rejected"),
        result_payload_hash: [0; 32],
        result_offset: 0,
        result_length: 0,
    };

    enqueue_fault_result(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        8_192,
        rejected_result(1),
        b"0123456789abcdef",
    )
    .unwrap_or_else(|error| panic!("fill result arena: {error}"));
    let indices_before = (ring.read_index(), ring.write_index());
    let cursors_before = (arena_header.read_cursor(), arena_header.write_cursor());
    assert_eq!(
        can_enqueue_fault_result(&ring, &slots, &arena_header, &arena, 1),
        Ok(false)
    );
    assert_eq!((ring.read_index(), ring.write_index()), indices_before);
    assert_eq!(
        (arena_header.read_cursor(), arena_header.write_cursor()),
        cursors_before
    );

    enqueue_fault_result(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        8_192,
        rejected_result(2),
        &[],
    )
    .unwrap_or_else(|error| panic!("fill result ring: {error}"));
    let indices_before = (ring.read_index(), ring.write_index());
    let cursors_before = (arena_header.read_cursor(), arena_header.write_cursor());
    assert_eq!(
        can_enqueue_fault_result(&ring, &slots, &arena_header, &arena, 0),
        Ok(false)
    );
    assert_eq!((ring.read_index(), ring.write_index()), indices_before);
    assert_eq!(
        (arena_header.read_cursor(), arena_header.write_cursor()),
        cursors_before
    );
}

#[test]
fn command_transport_wraps_without_splitting_payloads() {
    let ring = RingHeader::new();
    let arena_header = FaultPayloadArenaHeader::new();
    let mut slots = vec![FaultCommandSlotV1::new(); 4];
    let mut arena = vec![0_u8; 16];

    enqueue_fault_command(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        4_096,
        command(&[]),
        b"abcdefghijkl",
    )
    .unwrap_or_else(|error| panic!("enqueue first command: {error}"));
    let first = dequeue_fault_command(&ring, &slots, &arena_header, &arena, 4_096)
        .unwrap_or_else(|error| panic!("dequeue first command: {error}"));
    assert!(matches!(
        first,
        Some(DequeuedFaultCommand::Valid { payload, .. }) if payload == b"abcdefghijkl"
    ));

    let mut second_header = command(&[]);
    second_header.command_sequence = 8;
    enqueue_fault_command(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        4_096,
        second_header,
        b"mnopqrst",
    )
    .unwrap_or_else(|error| panic!("enqueue wrapped command: {error}"));
    assert_eq!(&arena[..8], b"mnopqrst");
    let second = dequeue_fault_command(&ring, &slots, &arena_header, &arena, 4_096)
        .unwrap_or_else(|error| panic!("dequeue wrapped command: {error}"));
    assert!(matches!(
        second,
        Some(DequeuedFaultCommand::Valid { payload, .. }) if payload == b"mnopqrst"
    ));
    assert_eq!(arena_header.read_cursor(), 24);
    assert_eq!(arena_header.write_cursor(), 24);
}

#[test]
fn full_command_ring_fails_before_reserving_payload_bytes() {
    let ring = RingHeader::new();
    let arena_header = FaultPayloadArenaHeader::new();
    let mut slots = vec![FaultCommandSlotV1::new(); 2];
    let mut arena = vec![0_u8; 16];
    for sequence in [7, 8] {
        let mut header = command(&[]);
        header.command_sequence = sequence;
        enqueue_fault_command(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            4_096,
            header,
            b"x",
        )
        .unwrap_or_else(|error| panic!("fill command ring: {error}"));
    }
    let write_before = arena_header.write_cursor();
    let mut header = command(&[]);
    header.command_sequence = 9;
    assert_eq!(
        enqueue_fault_command(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            4_096,
            header,
            b"y",
        ),
        Err(FaultTransportError::RingFull { capacity: 2 })
    );
    assert_eq!(arena_header.write_cursor(), write_before);
}

#[test]
fn malformed_command_is_consumed_without_losing_raw_correlation() {
    let ring = RingHeader::new();
    let arena_header = FaultPayloadArenaHeader::new();
    let mut slots = vec![FaultCommandSlotV1::new(); 2];
    let mut arena = vec![0_u8; 16];
    enqueue_fault_command(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        4_096,
        command(&[]),
        b"bad-kind",
    )
    .unwrap_or_else(|error| panic!("enqueue command: {error}"));
    slots[0].header[FAULT_COMMAND_KIND_OFFSET..FAULT_COMMAND_KIND_OFFSET + 2]
        .copy_from_slice(&0xffff_u16.to_le_bytes());

    let dequeued = dequeue_fault_command(&ring, &slots, &arena_header, &arena, 4_096)
        .unwrap_or_else(|error| panic!("dequeue malformed command: {error}"));
    assert_eq!(
        dequeued,
        Some(DequeuedFaultCommand::Rejected {
            raw_command_kind: 0xffff,
            command_sequence: 7,
            error: FaultAbiError::UnknownCommandKind(0xffff),
        })
    );
    assert_eq!(ring.read_index(), ring.write_index());
    assert_eq!(arena_header.read_cursor(), arena_header.write_cursor());
}

#[test]
fn result_transport_accepts_unknown_kind_only_for_rejection() {
    let ring = RingHeader::new();
    let arena_header = FaultPayloadArenaHeader::new();
    let mut slots = vec![FaultResultSlotV1::new(); 2];
    let mut arena = vec![0_u8; 32];
    let before = hash(b"before");
    let result = FaultResultHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: 0xffff,
        status: FaultResultStatus::UnsupportedCapability,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 11,
        observed_icount: 4,
        applied_icount: 0,
        capability_version: 1,
        phase: FaultBoundaryPhase::NodeBoundary,
        before_hash: before,
        after_hash: before,
        evidence_hash: hash(b"unsupported"),
        result_payload_hash: hash(&[]),
        result_offset: 0,
        result_length: 0,
    };
    enqueue_fault_result(
        &ring,
        &mut slots,
        &arena_header,
        &mut arena,
        8_192,
        result.clone(),
        b"reason",
    )
    .unwrap_or_else(|error| panic!("enqueue result: {error}"));
    let dequeued = dequeue_fault_result(&ring, &slots, &arena_header, &arena, 8_192)
        .unwrap_or_else(|error| panic!("dequeue result: {error}"));
    assert!(matches!(
        dequeued,
        Some(DequeuedFaultResult::Valid { header, payload })
            if header.command_kind == 0xffff && payload == b"reason"
    ));

    let mut applied = result;
    applied.command_sequence = 12;
    applied.command_kind = 0xfffe;
    applied.status = FaultResultStatus::Applied;
    applied.applied_icount = 4;
    applied.after_hash = hash(b"after");
    assert_eq!(
        enqueue_fault_result(
            &ring,
            &mut slots,
            &arena_header,
            &mut arena,
            8_192,
            applied,
            &[],
        ),
        Err(FaultTransportError::Abi(FaultAbiError::UnknownCommandKind(
            0xfffe
        )))
    );
}
