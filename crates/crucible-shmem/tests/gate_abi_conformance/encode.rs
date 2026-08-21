//! Encoding typed test state into the shared-memory golden vector.

use super::*;

pub(super) fn encode_golden_state(state: &GoldenState) -> Vec<u8> {
    let mut bytes = vec![0; GOLDEN_TOTAL_LEN];

    write_u64(&mut bytes, REGION_HEADER_MAGIC_OFFSET, state.region.magic);
    write_u32(
        &mut bytes,
        REGION_HEADER_ABI_VERSION_OFFSET,
        state.region.abi_version,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_NODE_COUNT_OFFSET,
        state.region.node_count,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        state.region.queue_capacity,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_RING_COUNT_OFFSET,
        state.region.ring_count,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_HDR_OFF_OFFSET,
        state.region.ring_hdr_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_DATA_OFF_OFFSET,
        state.region.ring_data_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_ENTRY_STRIDE_OFFSET,
        state.region.entry_stride,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_REGION_SIZE_OFFSET,
        state.region.region_size,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_ICOUNT_SHIFT_OFFSET,
        state.region.icount_shift,
    );
    write_u8(
        &mut bytes,
        REGION_HEADER_PAUSE_REQUESTED_OFFSET,
        state.region.pause_requested,
    );
    write_u8(
        &mut bytes,
        REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET,
        state.region.shutdown_requested,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET,
        state.region.fault_payload_arena_bytes,
    );

    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_ICOUNT_OFFSET,
        state.node.current_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_NS_OFFSET,
        state.node.current_ns,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
        state.node.max_advance_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET,
        state.node.idle_wake_icount,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_WAKE_SIGNAL_OFFSET,
        state.node.wake_signal,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_STATUS_OFFSET,
        state.node.status,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_KIND_OFFSET,
        state.node.kind,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
        state.node.device_io_active,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PUBLISH_GEN_OFFSET,
        state.node.publish_gen,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET,
        state.node.control_boundary_ack,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET,
        state.node.preemption_at_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET,
        state.node.preemption_deadline_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET,
        state.node.preemption_ceiling_icount,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET,
        state.node.preemption_published_sequence,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET,
        state.node.preemption_consumed_sequence,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_ARG0_OFFSET,
        state.node.preemption_arg0,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_ARG1_OFFSET,
        state.node.preemption_arg1,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_KIND_OFFSET,
        state.node.preemption_kind,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RAW_ICOUNT_OFFSET,
        state.node.logical_time_raw_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_TARGET_OFFSET,
        state.node.logical_time_restore_target,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_REQUEST_OFFSET,
        state.node.logical_time_restore_request,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_ACK_OFFSET,
        state.node.logical_time_restore_ack,
    );

    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_READ_IDX_OFFSET,
        state.ring.read_idx,
    );
    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_WRITE_IDX_OFFSET,
        state.ring.write_idx,
    );

    write_u64(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
        state.frame.delivery_icount,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SRC_NODE_OFFSET,
        state.frame.src_node,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SEQ_OFFSET,
        state.frame.seq,
    );
    write_u16(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LEN_OFFSET,
        state.frame.payload.len() as u16,
    );
    write_u8(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_STATE_OFFSET,
        state.frame.delivery_state,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_ATTEMPTS_OFFSET,
        state.frame.delivery_attempts,
    );
    bytes[GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET
        ..GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET + state.frame.payload.len()]
        .copy_from_slice(&state.frame.payload);

    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
        state.coverage.current_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_GUEST_PC_OFFSET,
        state.coverage.guest_pc,
    );
    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_MAP_INDEX_OFFSET,
        state.coverage.map_index,
    );
    write_u32(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_VCPU_INDEX_OFFSET,
        state.coverage.vcpu_index,
    );
    write_u32(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_BLOCK_LEN_OFFSET,
        state.coverage.block_len,
    );
    write_u64(
        &mut bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET,
        state.whitebox_marker.current_icount,
    );
    write_u32(
        &mut bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_VCPU_INDEX_OFFSET,
        state.whitebox_marker.vcpu_index,
    );
    write_u16(
        &mut bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_KIND_OFFSET,
        state.whitebox_marker.kind,
    );
    write_u16(
        &mut bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_PAYLOAD_LEN_OFFSET,
        state.whitebox_marker.payload.len() as u16,
    );
    bytes[GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET
        ..GOLDEN_WHITEBOX_MARKER_ENTRY_BASE
            + WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET
            + state.whitebox_marker.payload.len()]
        .copy_from_slice(&state.whitebox_marker.payload);
    write_u64(
        &mut bytes,
        GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE + GUEST_INTROSPECTION_ENTRY_SEQUENCE_OFFSET,
        state.guest_introspection.sequence,
    );
    write_u16(
        &mut bytes,
        GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE + GUEST_INTROSPECTION_ENTRY_LEN_OFFSET,
        state.guest_introspection.record.len() as u16,
    );
    bytes[GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE + GUEST_INTROSPECTION_ENTRY_DATA_OFFSET
        ..GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE
            + GUEST_INTROSPECTION_ENTRY_DATA_OFFSET
            + state.guest_introspection.record.len()]
        .copy_from_slice(&state.guest_introspection.record);
    write_u64(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_SEQUENCE_OFFSET,
        state.accelerator.sequence,
    );
    write_u64(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_GENERATION_OFFSET,
        state.accelerator.generation,
    );
    bytes[GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DEVICE_ID_OFFSET
        ..GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DEVICE_ID_OFFSET + 32]
        .copy_from_slice(&state.accelerator.device_id);
    write_u16(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_CLASS_OFFSET,
        state.accelerator.class,
    );
    write_u16(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_JOB_KIND_OFFSET,
        state.accelerator.job_kind,
    );
    write_u16(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_QUEUE_ID_OFFSET,
        state.accelerator.queue_id,
    );
    write_u16(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_PROTOCOL_VERSION_OFFSET,
        1,
    );
    write_u32(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DATA_LEN_OFFSET,
        state.accelerator.data.len() as u32,
    );
    write_u64(
        &mut bytes,
        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_SERVICE_UNITS_OFFSET,
        state.accelerator.service_units,
    );
    bytes[GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DATA_OFFSET
        ..GOLDEN_ACCELERATOR_ENTRY_BASE
            + ACCELERATOR_ENTRY_DATA_OFFSET
            + state.accelerator.data.len()]
        .copy_from_slice(&state.accelerator.data);

    bytes
}
