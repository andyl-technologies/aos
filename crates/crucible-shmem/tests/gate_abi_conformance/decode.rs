//! Decoding the shared-memory golden vector into typed test state.

use super::*;

pub(super) fn decode_golden_state(bytes: &[u8]) -> Result<GoldenState, String> {
    if bytes.len() != GOLDEN_TOTAL_LEN {
        return Err(format!(
            "golden vector length {} does not match expected {GOLDEN_TOTAL_LEN}",
            bytes.len()
        ));
    }

    let frame_len = read_u16(bytes, GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LEN_OFFSET);
    let frame_len_usize = usize::from(frame_len);
    if frame_len_usize > MAX_FRAME_DATA {
        return Err(format!(
            "frame payload length {frame_len} exceeds MAX_FRAME_DATA"
        ));
    }
    let marker_len = read_u16(
        bytes,
        GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_PAYLOAD_LEN_OFFSET,
    );
    let marker_len_usize = usize::from(marker_len);
    if marker_len_usize > MAX_FRAME_DATA {
        return Err(format!(
            "white-box marker payload length {marker_len} exceeds MAX_FRAME_DATA"
        ));
    }
    let guest_introspection_len = usize::from(read_u16(
        bytes,
        GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE + GUEST_INTROSPECTION_ENTRY_LEN_OFFSET,
    ));
    if guest_introspection_len > MAX_FRAME_DATA {
        return Err(format!(
            "guest-introspection record length {guest_introspection_len} exceeds MAX_FRAME_DATA"
        ));
    }

    Ok(GoldenState {
        region: RegionHeaderState {
            magic: read_u64(bytes, REGION_HEADER_MAGIC_OFFSET),
            abi_version: read_u32(bytes, REGION_HEADER_ABI_VERSION_OFFSET),
            node_count: read_u32(bytes, REGION_HEADER_NODE_COUNT_OFFSET),
            queue_capacity: read_u32(bytes, REGION_HEADER_QUEUE_CAPACITY_OFFSET),
            ring_count: read_u32(bytes, REGION_HEADER_RING_COUNT_OFFSET),
            ring_hdr_off: read_u64(bytes, REGION_HEADER_RING_HDR_OFF_OFFSET),
            ring_data_off: read_u64(bytes, REGION_HEADER_RING_DATA_OFF_OFFSET),
            entry_stride: read_u64(bytes, REGION_HEADER_ENTRY_STRIDE_OFFSET),
            region_size: read_u64(bytes, REGION_HEADER_REGION_SIZE_OFFSET),
            icount_shift: read_u32(bytes, REGION_HEADER_ICOUNT_SHIFT_OFFSET),
            pause_requested: read_u8(bytes, REGION_HEADER_PAUSE_REQUESTED_OFFSET),
            shutdown_requested: read_u8(bytes, REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET),
            fault_payload_arena_bytes: read_u32(
                bytes,
                REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET,
            ),
        },
        node: NodeSlotState {
            current_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_ICOUNT_OFFSET,
            ),
            current_ns: read_u64(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_NS_OFFSET),
            max_advance_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
            ),
            idle_wake_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET,
            ),
            wake_signal: read_u32(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_WAKE_SIGNAL_OFFSET),
            status: read_u8(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_STATUS_OFFSET),
            kind: read_u8(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_KIND_OFFSET),
            device_io_active: read_u8(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
            ),
            publish_gen: read_u32(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PUBLISH_GEN_OFFSET),
            control_boundary_ack: read_u32(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET,
            ),
            preemption_at_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET,
            ),
            preemption_deadline_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET,
            ),
            preemption_ceiling_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET,
            ),
            preemption_published_sequence: read_u32(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET,
            ),
            preemption_consumed_sequence: read_u32(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET,
            ),
            preemption_arg0: read_u32(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_ARG0_OFFSET,
            ),
            preemption_arg1: read_u32(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_ARG1_OFFSET,
            ),
            preemption_kind: read_u8(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PREEMPTION_KIND_OFFSET,
            ),
            logical_time_raw_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RAW_ICOUNT_OFFSET,
            ),
            logical_time_restore_target: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_TARGET_OFFSET,
            ),
            logical_time_restore_request: read_u32(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_REQUEST_OFFSET,
            ),
            logical_time_restore_ack: read_u32(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_LOGICAL_TIME_RESTORE_ACK_OFFSET,
            ),
        },
        ring: RingHeaderState {
            read_idx: read_u64(bytes, GOLDEN_RING_HEADER_BASE + RING_HEADER_READ_IDX_OFFSET),
            write_idx: read_u64(
                bytes,
                GOLDEN_RING_HEADER_BASE + RING_HEADER_WRITE_IDX_OFFSET,
            ),
        },
        frame: FrameEntryState {
            delivery_icount: read_u64(
                bytes,
                GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
            ),
            src_node: read_u32(bytes, GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SRC_NODE_OFFSET),
            seq: read_u32(bytes, GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SEQ_OFFSET),
            payload: bytes[GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET
                ..GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET + frame_len_usize]
                .to_vec(),
        },
        coverage: CoverageEntryState {
            current_icount: read_u64(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
            ),
            guest_pc: read_u64(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_GUEST_PC_OFFSET,
            ),
            map_index: read_u64(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_MAP_INDEX_OFFSET,
            ),
            vcpu_index: read_u32(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_VCPU_INDEX_OFFSET,
            ),
            block_len: read_u32(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_BLOCK_LEN_OFFSET,
            ),
        },
        whitebox_marker: WhiteboxMarkerEntryState {
            current_icount: read_u64(
                bytes,
                GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET,
            ),
            vcpu_index: read_u32(
                bytes,
                GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_VCPU_INDEX_OFFSET,
            ),
            kind: read_u16(
                bytes,
                GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_KIND_OFFSET,
            ),
            payload: bytes[GOLDEN_WHITEBOX_MARKER_ENTRY_BASE + WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET
                ..GOLDEN_WHITEBOX_MARKER_ENTRY_BASE
                    + WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET
                    + marker_len_usize]
                .to_vec(),
        },
        guest_introspection: GuestIntrospectionEntryState {
            sequence: read_u64(
                bytes,
                GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE + GUEST_INTROSPECTION_ENTRY_SEQUENCE_OFFSET,
            ),
            record: bytes[GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE
                + GUEST_INTROSPECTION_ENTRY_DATA_OFFSET
                ..GOLDEN_GUEST_INTROSPECTION_ENTRY_BASE
                    + GUEST_INTROSPECTION_ENTRY_DATA_OFFSET
                    + guest_introspection_len]
                .to_vec(),
        },
        accelerator: AcceleratorEntryState {
            sequence: read_u64(
                bytes,
                GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_SEQUENCE_OFFSET,
            ),
            generation: read_u64(
                bytes,
                GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_GENERATION_OFFSET,
            ),
            device_id: bytes[GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DEVICE_ID_OFFSET
                ..GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DEVICE_ID_OFFSET + 32]
                .to_vec(),
            class: read_u16(
                bytes,
                GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_CLASS_OFFSET,
            ),
            job_kind: read_u16(
                bytes,
                GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_JOB_KIND_OFFSET,
            ),
            queue_id: read_u16(
                bytes,
                GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_QUEUE_ID_OFFSET,
            ),
            service_units: read_u64(
                bytes,
                GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_SERVICE_UNITS_OFFSET,
            ),
            data: bytes[GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DATA_OFFSET
                ..GOLDEN_ACCELERATOR_ENTRY_BASE
                    + ACCELERATOR_ENTRY_DATA_OFFSET
                    + read_u32(
                        bytes,
                        GOLDEN_ACCELERATOR_ENTRY_BASE + ACCELERATOR_ENTRY_DATA_LEN_OFFSET,
                    ) as usize]
                .to_vec(),
        },
    })
}
