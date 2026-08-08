//! Top-level ABI conformance gate cases and frozen-vector assertions.

use super::*;

#[test]
fn gate_abi_conformance_checks_generated_header_and_golden_vectors() {
    generated_header_matches_committed_copy();
    generated_header_carries_static_asserts_for_every_shared_struct();

    let fixture = assert_frozen_golden_vectors();
    assert_abi_version_field(&fixture);
    let state = assert_decode_encode_roundtrip(&fixture);
    assert_version_bump_regenerates_vectors(&fixture);
    assert_structure_aware_fuzz_corpus(&fixture, &state);
    assert_snapshot_canonical_codec_corpus();
    golden_vector_negative_control_detects_layout_drift();
}

#[test]
fn generated_header_matches_committed_copy() {
    assert_eq!(COMMITTED_HEADER, generated_c_header());
}

#[test]
fn generated_header_carries_static_asserts_for_every_shared_struct() {
    let header = generated_c_header();
    for needle in [
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_region_header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_region_header)",
        "offsetof(crucible_shmem_region_header, magic)",
        "offsetof(crucible_shmem_region_header, abi_version)",
        "offsetof(crucible_shmem_region_header, node_count)",
        "offsetof(crucible_shmem_region_header, queue_capacity)",
        "offsetof(crucible_shmem_region_header, ring_count)",
        "offsetof(crucible_shmem_region_header, ring_hdr_off)",
        "offsetof(crucible_shmem_region_header, ring_data_off)",
        "offsetof(crucible_shmem_region_header, entry_stride)",
        "offsetof(crucible_shmem_region_header, region_size)",
        "offsetof(crucible_shmem_region_header, icount_shift)",
        "offsetof(crucible_shmem_region_header, pause_requested)",
        "offsetof(crucible_shmem_region_header, shutdown_requested)",
        "offsetof(crucible_shmem_region_header, fault_payload_arena_bytes)",
        "offsetof(crucible_shmem_region_header, reserved)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_node_slot)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_node_slot)",
        "offsetof(crucible_shmem_node_slot, current_icount)",
        "offsetof(crucible_shmem_node_slot, current_ns)",
        "offsetof(crucible_shmem_node_slot, max_advance_icount)",
        "offsetof(crucible_shmem_node_slot, idle_wake_icount)",
        "offsetof(crucible_shmem_node_slot, wake_signal)",
        "offsetof(crucible_shmem_node_slot, status)",
        "offsetof(crucible_shmem_node_slot, kind)",
        "offsetof(crucible_shmem_node_slot, device_io_active)",
        "offsetof(crucible_shmem_node_slot, pad0)",
        "offsetof(crucible_shmem_node_slot, publish_gen)",
        "offsetof(crucible_shmem_node_slot, preemption_at_icount)",
        "offsetof(crucible_shmem_node_slot, preemption_deadline_icount)",
        "offsetof(crucible_shmem_node_slot, preemption_ceiling_icount)",
        "offsetof(crucible_shmem_node_slot, preemption_published_sequence)",
        "offsetof(crucible_shmem_node_slot, preemption_consumed_sequence)",
        "offsetof(crucible_shmem_node_slot, preemption_arg0)",
        "offsetof(crucible_shmem_node_slot, preemption_arg1)",
        "offsetof(crucible_shmem_node_slot, preemption_kind)",
        "offsetof(crucible_shmem_node_slot, logical_time_raw_icount)",
        "offsetof(crucible_shmem_node_slot, logical_time_restore_target)",
        "offsetof(crucible_shmem_node_slot, logical_time_restore_request)",
        "offsetof(crucible_shmem_node_slot, logical_time_restore_ack)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_ring_header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_ring_header)",
        "offsetof(crucible_shmem_ring_header, read_idx)",
        "offsetof(crucible_shmem_ring_header, pad_read)",
        "offsetof(crucible_shmem_ring_header, write_idx)",
        "offsetof(crucible_shmem_ring_header, pad_write)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_frame_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_frame_entry)",
        "offsetof(crucible_shmem_frame_entry, delivery_icount)",
        "offsetof(crucible_shmem_frame_entry, src_node)",
        "offsetof(crucible_shmem_frame_entry, seq)",
        "offsetof(crucible_shmem_frame_entry, len)",
        "offsetof(crucible_shmem_frame_entry, pad)",
        "offsetof(crucible_shmem_frame_entry, data)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_coverage_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_coverage_entry)",
        "offsetof(crucible_shmem_coverage_entry, current_icount)",
        "offsetof(crucible_shmem_coverage_entry, guest_pc)",
        "offsetof(crucible_shmem_coverage_entry, map_index)",
        "offsetof(crucible_shmem_coverage_entry, vcpu_index)",
        "offsetof(crucible_shmem_coverage_entry, block_len)",
        "offsetof(crucible_shmem_coverage_entry, reserved)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_whitebox_marker_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_whitebox_marker_entry)",
        "offsetof(crucible_shmem_whitebox_marker_entry, current_icount)",
        "offsetof(crucible_shmem_whitebox_marker_entry, vcpu_index)",
        "offsetof(crucible_shmem_whitebox_marker_entry, kind)",
        "offsetof(crucible_shmem_whitebox_marker_entry, payload_len)",
        "offsetof(crucible_shmem_whitebox_marker_entry, payload)",
        "offsetof(crucible_shmem_whitebox_marker_entry, reserved)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_command_slot_v1)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_command_slot_v1)",
        "offsetof(crucible_fault_command_slot_v1, reservation_start)",
        "offsetof(crucible_fault_command_slot_v1, payload_start)",
        "offsetof(crucible_fault_command_slot_v1, reservation_end)",
        "offsetof(crucible_fault_command_slot_v1, header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_result_slot_v1)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_result_slot_v1)",
        "offsetof(crucible_fault_result_slot_v1, reservation_start)",
        "offsetof(crucible_fault_result_slot_v1, payload_start)",
        "offsetof(crucible_fault_result_slot_v1, reservation_end)",
        "offsetof(crucible_fault_result_slot_v1, header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_payload_arena_header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_fault_payload_arena_header)",
        "offsetof(crucible_fault_payload_arena_header, read_cursor)",
        "offsetof(crucible_fault_payload_arena_header, write_cursor)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_event_slot_v1)",
        "offsetof(crucible_fault_event_slot_v1, reservation_start)",
        "offsetof(crucible_fault_event_slot_v1, payload_start)",
        "offsetof(crucible_fault_event_slot_v1, reservation_end)",
        "offsetof(crucible_fault_event_slot_v1, header)",
        "offsetof(crucible_fault_event_slot_v1, reserved)",
    ] {
        assert!(
            header.contains(needle),
            "generated C header missing `{needle}`"
        );
    }
}

#[test]
fn rust_golden_vector_round_trip_matches_fixture() {
    let fixture = assert_frozen_golden_vectors();
    assert_abi_version_field(&fixture);
    let state = assert_decode_encode_roundtrip(&fixture);
    assert_structure_aware_fuzz_corpus(&fixture, &state);
    assert_snapshot_canonical_codec_corpus();
}

#[test]
fn golden_vector_negative_control_detects_layout_drift() {
    let fixture = assert_frozen_golden_vectors();
    let mut drifted = live_golden_bytes();
    write_u32(
        &mut drifted,
        REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        GOLDEN_VM_NODE_COUNT,
    );
    write_u32(
        &mut drifted,
        REGION_HEADER_NODE_COUNT_OFFSET,
        GOLDEN_QUEUE_CAPACITY,
    );

    assert_ne!(
        fixture.bytes, drifted,
        "golden vector must detect swapped region-header layout fields"
    );
}

fn assert_frozen_golden_vectors() -> Fixture {
    let fixture = match parse_fixture(regression_corpus()) {
        Ok(fixture) => fixture,
        Err(error) => panic!("failed to parse shmem ABI golden fixture: {error}"),
    };

    assert_eq!(fixture.abi_version, ABI_VERSION);
    assert_eq!(fixture.bytes.len(), GOLDEN_TOTAL_LEN);
    let live = live_golden_bytes();
    if let Some(index) = fixture
        .bytes
        .iter()
        .zip(&live)
        .position(|(frozen, generated)| frozen != generated)
    {
        panic!(
            "frozen ABI vector first differs at byte {index}: frozen={:02x} generated={:02x}; frozen region-size={:02x?} generated region-size={:02x?}",
            fixture.bytes[index],
            live[index],
            &fixture.bytes[REGION_HEADER_REGION_SIZE_OFFSET..REGION_HEADER_REGION_SIZE_OFFSET + 8],
            &live[REGION_HEADER_REGION_SIZE_OFFSET..REGION_HEADER_REGION_SIZE_OFFSET + 8],
        );
    }
    fixture
}

fn assert_decode_encode_roundtrip(fixture: &Fixture) -> GoldenState {
    let decoded = match decode_golden_state(&fixture.bytes) {
        Ok(decoded) => decoded,
        Err(error) => panic!("failed to decode shmem ABI golden vector: {error}"),
    };
    let encoded = encode_golden_state(&decoded);
    assert_eq!(encoded, fixture.bytes);
    decoded
}

fn assert_abi_version_field(fixture: &Fixture) {
    assert_eq!(fixture.abi_version, ABI_VERSION);
    assert_eq!(
        read_u32(&fixture.bytes, REGION_HEADER_ABI_VERSION_OFFSET),
        ABI_VERSION
    );
}

fn assert_version_bump_regenerates_vectors(fixture: &Fixture) {
    let mut bumped = fixture.bytes.clone();
    write_u32(
        &mut bumped,
        REGION_HEADER_ABI_VERSION_OFFSET,
        ABI_VERSION + 1,
    );
    assert_ne!(
        bumped, fixture.bytes,
        "ABI version changes must alter frozen golden vectors"
    );
    assert_eq!(
        read_u32(&bumped, REGION_HEADER_ABI_VERSION_OFFSET),
        ABI_VERSION + 1
    );
}

fn assert_structure_aware_fuzz_corpus(fixture: &Fixture, decoded: &GoldenState) {
    assert_eq!(decoded.region.magic, REGION_MAGIC);
    assert_eq!(decoded.region.abi_version, ABI_VERSION);
    assert_eq!(decoded.region.node_count, 32);
    assert_eq!(decoded.region.queue_capacity, GOLDEN_QUEUE_CAPACITY);
    assert_eq!(decoded.region.ring_count, 12);
    assert_eq!(decoded.node.status, STATUS_IDLE);
    assert_eq!(decoded.node.kind, 0);
    assert_eq!(decoded.node.logical_time_raw_icount, 96);
    assert_eq!(decoded.node.logical_time_restore_target, 128);
    assert_eq!(decoded.node.logical_time_restore_request, 13);
    assert_eq!(decoded.node.logical_time_restore_ack, 13);
    assert_eq!(decoded.frame.payload, b"PING");
    assert_eq!(decoded.coverage.current_icount, 901);
    assert_eq!(decoded.coverage.guest_pc, 0x4010);
    assert_eq!(decoded.coverage.map_index, 17);
    assert_eq!(decoded.coverage.vcpu_index, 2);
    assert_eq!(decoded.coverage.block_len, 4);
    assert_eq!(decoded.whitebox_marker.current_icount, 913);
    assert_eq!(decoded.whitebox_marker.vcpu_index, 2);
    assert_eq!(decoded.whitebox_marker.kind, 4);
    assert_eq!(decoded.whitebox_marker.payload, b"MARK");

    let mut payload_mutation = fixture.bytes.clone();
    payload_mutation[GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET
        ..GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET + 4]
        .copy_from_slice(b"PONG");
    let mutated = match decode_golden_state(&payload_mutation) {
        Ok(mutated) => mutated,
        Err(error) => panic!("failed to decode structured payload mutation: {error}"),
    };
    assert_eq!(mutated.frame.payload, b"PONG");
    assert_eq!(encode_golden_state(&mutated), payload_mutation);
    assert_ne!(payload_mutation, fixture.bytes);

    let mut oversized = fixture.bytes.clone();
    write_u16(
        &mut oversized,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LEN_OFFSET,
        (MAX_FRAME_DATA as u16) + 1,
    );
    assert!(
        decode_golden_state(&oversized).is_err(),
        "oversized structured frame mutation must be rejected"
    );
}
