//! Construction of the complete live shared-memory golden vector.

use super::*;

pub(super) fn live_golden_bytes() -> Vec<u8> {
    let layout = match RegionLayout::for_config(RegionConfig::new(
        GOLDEN_VM_NODE_COUNT,
        GOLDEN_QUEUE_CAPACITY,
        GOLDEN_ICOUNT_SHIFT,
    )) {
        Ok(layout) => layout,
        Err(error) => panic!("failed to compute golden shmem layout: {error}"),
    };

    let mut bytes = vec![0; GOLDEN_TOTAL_LEN];

    write_u64(&mut bytes, REGION_HEADER_MAGIC_OFFSET, REGION_MAGIC);
    write_u32(&mut bytes, REGION_HEADER_ABI_VERSION_OFFSET, ABI_VERSION);
    write_u32(
        &mut bytes,
        REGION_HEADER_NODE_COUNT_OFFSET,
        layout.node_count,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        layout.queue_capacity,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_RING_COUNT_OFFSET,
        layout.ring_count,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_HDR_OFF_OFFSET,
        layout.ring_hdr_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_DATA_OFF_OFFSET,
        layout.ring_data_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_ENTRY_STRIDE_OFFSET,
        layout.entry_stride,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_REGION_SIZE_OFFSET,
        layout.region_size,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_ICOUNT_SHIFT_OFFSET,
        layout.icount_shift,
    );
    write_u8(&mut bytes, REGION_HEADER_PAUSE_REQUESTED_OFFSET, 1);
    write_u8(&mut bytes, REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET, 0);
    write_u32(
        &mut bytes,
        REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET,
        layout.fault_payload_arena_bytes,
    );

    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_ICOUNT_OFFSET,
        128,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_NS_OFFSET,
        2048,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
        256,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET,
        180,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_WAKE_SIGNAL_OFFSET,
        7,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_STATUS_OFFSET,
        STATUS_IDLE,
    );
    write_u8(&mut bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_KIND_OFFSET, 0);
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
        1,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PUBLISH_GEN_OFFSET,
        4,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET,
        11,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET,
        160,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET,
        128,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET,
        256,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET,
        9,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET,
        8,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_ARG0_OFFSET,
        0,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_ARG1_OFFSET,
        1,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_KIND_OFFSET,
        PREEMPTION_KIND_VCPU_SWITCH,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RAW_ICOUNT_OFFSET,
        96,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_TARGET_OFFSET,
        128,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_REQUEST_OFFSET,
        13,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_ACK_OFFSET,
        13,
    );

    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_READ_IDX_OFFSET,
        5,
    );
    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_WRITE_IDX_OFFSET,
        9,
    );
    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_PRODUCER_STATE_OFFSET,
        (1_u64 << 63) | 3,
    );

    write_u64(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
        777,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SRC_NODE_OFFSET,
        2,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SEQ_OFFSET,
        42,
    );
    write_u16(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LEN_OFFSET,
        4,
    );
    write_u8(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_STATE_OFFSET,
        FRAME_DELIVERY_RETAINED,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_ATTEMPTS_OFFSET,
        3,
    );
    write_u64(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LAST_DELIVERY_ATTEMPT_ICOUNT_OFFSET,
        777,
    );
    bytes[GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET
        ..GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET + 4]
        .copy_from_slice(b"PING");

    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
        901,
    );
    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_GUEST_PC_OFFSET,
        0x4010,
    );
    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_MAP_INDEX_OFFSET,
        17,
    );
    write_u32(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_VCPU_INDEX_OFFSET,
        2,
    );
    write_u32(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_BLOCK_LEN_OFFSET,
        4,
    );
    write_u64(
        &mut bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET,
        913,
    );
    write_u32(
        &mut bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_VCPU_INDEX_OFFSET,
        2,
    );
    write_u16(
        &mut bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_KIND_OFFSET,
        4,
    );
    write_u16(
        &mut bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_PAYLOAD_LEN_OFFSET,
        4,
    );
    bytes[GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET
        ..GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET + 4]
        .copy_from_slice(b"MARK");
    write_u64(
        &mut bytes,
        GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE + GUEST_INTROSPECTION_ENTRY_SEQUENCE_OFFSET,
        19,
    );
    write_u16(
        &mut bytes,
        GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE + GUEST_INTROSPECTION_ENTRY_LEN_OFFSET,
        GOLDEN_GUEST_INTROSPECTION_RECORD.len() as u16,
    );
    bytes[GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE + GUEST_INTROSPECTION_ENTRY_DATA_OFFSET
        ..GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE
            + GUEST_INTROSPECTION_ENTRY_DATA_OFFSET
            + GOLDEN_GUEST_INTROSPECTION_RECORD.len()]
        .copy_from_slice(GOLDEN_GUEST_INTROSPECTION_RECORD);
    write_u64(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_SEQUENCE_OFFSET,
        23,
    );
    write_u64(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_GENERATION_OFFSET,
        5,
    );
    bytes[GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DEVICE_ID_OFFSET
        ..GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DEVICE_ID_OFFSET + 32]
        .fill(0xa5);
    write_u16(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_CLASS_OFFSET,
        2,
    );
    write_u16(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_JOB_KIND_OFFSET,
        1,
    );
    write_u16(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_QUEUE_ID_OFFSET,
        7,
    );
    write_u16(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_PROTOCOL_VERSION_OFFSET,
        1,
    );
    write_u32(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DATA_LEN_OFFSET,
        4,
    );
    write_u64(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_SERVICE_UNITS_OFFSET,
        16,
    );
    bytes[GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DATA_OFFSET
        ..GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DATA_OFFSET + 4]
        .copy_from_slice(b"TENS");

    bytes
}
