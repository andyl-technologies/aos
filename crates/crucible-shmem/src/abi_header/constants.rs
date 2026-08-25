//! Generated C ABI constants and feature declarations.

use super::*;

pub(super) fn emit_constants(out: &mut String) {
    emit_define_u64_hex(out, "CRUCIBLE_SHMEM_REGION_MAGIC", REGION_MAGIC);
    emit_define_u32(out, "CRUCIBLE_SHMEM_ABI_VERSION", ABI_VERSION);
    emit_define_usize(out, "CRUCIBLE_SHMEM_MAX_FRAME_DATA", MAX_FRAME_DATA);
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_DEFAULT_QUEUE_CAPACITY",
        DEFAULT_QUEUE_CAPACITY,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_COVERAGE_QUEUE_CAPACITY",
        COVERAGE_QUEUE_CAPACITY,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_WHITEBOX_MARKER_QUEUE_CAPACITY",
        WHITEBOX_MARKER_QUEUE_CAPACITY,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_SELECTABLE_REPLY_QUEUE_CAPACITY",
        SELECTABLE_REPLY_QUEUE_CAPACITY,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_GUEST_INTROSPECTION_QUEUE_CAPACITY",
        GUEST_INTROSPECTION_QUEUE_CAPACITY,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_GUEST_INTROSPECTION_RINGS_PER_VM",
        GUEST_INTROSPECTION_RINGS_PER_VM,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_GUEST_INTROSPECTION_REQUEST_RING_OFFSET",
        GUEST_INTROSPECTION_REQUEST_RING_OFFSET,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_GUEST_INTROSPECTION_RESPONSE_RING_OFFSET",
        GUEST_INTROSPECTION_RESPONSE_RING_OFFSET,
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_DATA_BYTES",
        GUEST_INTROSPECTION_ENTRY_DATA_BYTES,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_ACCELERATOR_QUEUE_CAPACITY",
        ACCELERATOR_QUEUE_CAPACITY,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_ACCELERATOR_RINGS_PER_VM",
        ACCELERATOR_RINGS_PER_VM,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_ACCELERATOR_REQUEST_RING_OFFSET",
        ACCELERATOR_REQUEST_RING_OFFSET,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_ACCELERATOR_COMPLETION_RING_OFFSET",
        ACCELERATOR_COMPLETION_RING_OFFSET,
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_ACCELERATOR_ENTRY_DATA_BYTES",
        ACCELERATOR_ENTRY_DATA_BYTES,
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_ACCELERATOR_ENTRY_SIZE",
        ACCELERATOR_ENTRY_SIZE,
    );
    emit_define_u32(
        out,
        "CRUCIBLE_SHMEM_ACCELERATOR_PROTOCOL_VERSION",
        u32::from(ACCELERATOR_PROTOCOL_VERSION),
    );
    emit_define_usize(out, "CRUCIBLE_SHMEM_MAX_NODES", MAX_NODES);
    emit_define_usize(out, "CRUCIBLE_SHMEM_RESERVED_SLOTS", RESERVED_SLOTS);
    emit_define_usize(out, "CRUCIBLE_SHMEM_MAX_VM_NODES", MAX_VM_NODES);
    emit_define_usize(out, "CRUCIBLE_SHMEM_SLOT_NET_ROUTER", SLOT_NET_ROUTER);
    emit_define_usize(out, "CRUCIBLE_SHMEM_SLOT_BLK_IO", SLOT_BLK_IO);
    emit_define_usize(out, "CRUCIBLE_SHMEM_SLOT_9P_IO", SLOT_9P_IO);
    emit_define_str(
        out,
        "CRUCIBLE_SHMEM_LAYOUT_TARGET_TRIPLE",
        LAYOUT_TARGET_TRIPLE,
    );
    emit_define_bool(out, "CRUCIBLE_SHMEM_FUTEX_PRIVATE", FUTEX_PRIVATE);
    out.push('\n');

    emit_define_u8(out, "CRUCIBLE_SHMEM_STATUS_RUNNING", STATUS_RUNNING);
    emit_define_u8(out, "CRUCIBLE_SHMEM_STATUS_IDLE", STATUS_IDLE);
    emit_define_u8(out, "CRUCIBLE_SHMEM_STATUS_DONE", STATUS_DONE);
    emit_define_u8(out, "CRUCIBLE_SHMEM_KIND_VM", KIND_VM);
    emit_define_u8(out, "CRUCIBLE_SHMEM_KIND_NET", KIND_NET);
    emit_define_u8(out, "CRUCIBLE_SHMEM_KIND_BLK", KIND_BLK);
    emit_define_u8(out, "CRUCIBLE_SHMEM_KIND_9P", KIND_9P);
    emit_define_u8(
        out,
        "CRUCIBLE_SHMEM_PREEMPTION_KIND_NONE",
        PREEMPTION_KIND_NONE,
    );
    emit_define_u8(
        out,
        "CRUCIBLE_SHMEM_PREEMPTION_KIND_VCPU_SWITCH",
        PREEMPTION_KIND_VCPU_SWITCH,
    );
    emit_define_u8(
        out,
        "CRUCIBLE_SHMEM_PREEMPTION_KIND_INTERRUPT_AT",
        PREEMPTION_KIND_INTERRUPT_AT,
    );
    out.push('\n');

    emit_layout_constant_group(
        out,
        "REGION_HEADER",
        REGION_HEADER_SIZE,
        REGION_HEADER_ALIGN,
        &[
            ("MAGIC", REGION_HEADER_MAGIC_OFFSET),
            ("ABI_VERSION", REGION_HEADER_ABI_VERSION_OFFSET),
            ("NODE_COUNT", REGION_HEADER_NODE_COUNT_OFFSET),
            ("QUEUE_CAPACITY", REGION_HEADER_QUEUE_CAPACITY_OFFSET),
            ("RING_COUNT", REGION_HEADER_RING_COUNT_OFFSET),
            ("RING_HDR_OFF", REGION_HEADER_RING_HDR_OFF_OFFSET),
            ("RING_DATA_OFF", REGION_HEADER_RING_DATA_OFF_OFFSET),
            ("ENTRY_STRIDE", REGION_HEADER_ENTRY_STRIDE_OFFSET),
            ("REGION_SIZE", REGION_HEADER_REGION_SIZE_OFFSET),
            ("ICOUNT_SHIFT", REGION_HEADER_ICOUNT_SHIFT_OFFSET),
            ("PAUSE_REQUESTED", REGION_HEADER_PAUSE_REQUESTED_OFFSET),
            (
                "SHUTDOWN_REQUESTED",
                REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET,
            ),
            ("CONTROL_PADDING", REGION_HEADER_CONTROL_PADDING_OFFSET),
            (
                "FAULT_PAYLOAD_ARENA_BYTES",
                REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET,
            ),
            ("RESERVED", REGION_HEADER_RESERVED_OFFSET),
        ],
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_REGION_HEADER_RESERVED_LEN",
        REGION_HEADER_SIZE - REGION_HEADER_RESERVED_OFFSET,
    );
    out.push('\n');

    emit_layout_constant_group(
        out,
        "NODE_SLOT",
        NODE_SLOT_SIZE,
        NODE_SLOT_ALIGN,
        &[
            ("CURRENT_ICOUNT", NODE_SLOT_CURRENT_ICOUNT_OFFSET),
            ("CURRENT_NS", NODE_SLOT_CURRENT_NS_OFFSET),
            ("MAX_ADVANCE_ICOUNT", NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET),
            ("IDLE_WAKE_ICOUNT", NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET),
            ("WAKE_SIGNAL", NODE_SLOT_WAKE_SIGNAL_OFFSET),
            ("STATUS", NODE_SLOT_STATUS_OFFSET),
            ("KIND", NODE_SLOT_KIND_OFFSET),
            ("DEVICE_IO_ACTIVE", NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET),
            ("PAD0", NODE_SLOT_PAD0_OFFSET),
            ("PUBLISH_GEN", NODE_SLOT_PUBLISH_GEN_OFFSET),
            (
                "CONTROL_BOUNDARY_ACK",
                NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET,
            ),
            (
                "DEVICE_COMPLETION_DEADLINE_ICOUNT",
                NODE_SLOT_DEVICE_COMPLETION_DEADLINE_ICOUNT_OFFSET,
            ),
            (
                "PREEMPTION_AT_ICOUNT",
                NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET,
            ),
            (
                "PREEMPTION_DEADLINE_ICOUNT",
                NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET,
            ),
            (
                "PREEMPTION_CEILING_ICOUNT",
                NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET,
            ),
            (
                "PREEMPTION_PUBLISHED_SEQUENCE",
                NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET,
            ),
            (
                "PREEMPTION_CONSUMED_SEQUENCE",
                NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET,
            ),
            ("PREEMPTION_ARG0", NODE_SLOT_PREEMPTION_ARG0_OFFSET),
            ("PREEMPTION_ARG1", NODE_SLOT_PREEMPTION_ARG1_OFFSET),
            ("PREEMPTION_KIND", NODE_SLOT_PREEMPTION_KIND_OFFSET),
            ("PAD2", NODE_SLOT_PAD2_OFFSET),
            (
                "LOGICAL_TIME_RAW_ICOUNT",
                NODE_SLOT_LOGICAL_TIME_RAW_ICOUNT_OFFSET,
            ),
            (
                "LOGICAL_TIME_RESTORE_TARGET",
                NODE_SLOT_LOGICAL_TIME_RESTORE_TARGET_OFFSET,
            ),
            (
                "LOGICAL_TIME_RESTORE_REQUEST",
                NODE_SLOT_LOGICAL_TIME_RESTORE_REQUEST_OFFSET,
            ),
            (
                "LOGICAL_TIME_RESTORE_ACK",
                NODE_SLOT_LOGICAL_TIME_RESTORE_ACK_OFFSET,
            ),
        ],
    );
    out.push('\n');

    emit_layout_constant_group(
        out,
        "RING_HEADER",
        RING_HEADER_SIZE,
        RING_HEADER_ALIGN,
        &[
            ("READ_IDX", RING_HEADER_READ_IDX_OFFSET),
            ("PAD_READ", RING_HEADER_PAD_READ_OFFSET),
            ("WRITE_IDX", RING_HEADER_WRITE_IDX_OFFSET),
            ("PAD_WRITE", RING_HEADER_PAD_WRITE_OFFSET),
        ],
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_RING_HEADER_PAD_READ_LEN",
        RING_HEADER_WRITE_IDX_OFFSET - RING_HEADER_PAD_READ_OFFSET,
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_RING_HEADER_PAD_WRITE_LEN",
        RING_HEADER_SIZE - RING_HEADER_PAD_WRITE_OFFSET,
    );
    out.push('\n');

    emit_layout_constant_group(
        out,
        "FRAME_ENTRY",
        FRAME_ENTRY_SIZE,
        FRAME_ENTRY_ALIGN,
        &[
            ("DELIVERY_ICOUNT", FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET),
            ("SRC_NODE", FRAME_ENTRY_SRC_NODE_OFFSET),
            ("SEQ", FRAME_ENTRY_SEQ_OFFSET),
            ("LEN", FRAME_ENTRY_LEN_OFFSET),
            ("DELIVERY_STATE", FRAME_ENTRY_DELIVERY_STATE_OFFSET),
            ("PAD", FRAME_ENTRY_PAD_OFFSET),
            ("DELIVERY_ATTEMPTS", FRAME_ENTRY_DELIVERY_ATTEMPTS_OFFSET),
            (
                "LAST_DELIVERY_ATTEMPT_ICOUNT",
                FRAME_ENTRY_LAST_DELIVERY_ATTEMPT_ICOUNT_OFFSET,
            ),
            ("DATA", FRAME_ENTRY_DATA_OFFSET),
        ],
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_FRAME_ENTRY_PAD_LEN",
        FRAME_ENTRY_DELIVERY_ATTEMPTS_OFFSET - FRAME_ENTRY_PAD_OFFSET,
    );
    emit_define_u8(
        out,
        "CRUCIBLE_SHMEM_FRAME_DELIVERY_PENDING",
        FRAME_DELIVERY_PENDING,
    );
    emit_define_u8(
        out,
        "CRUCIBLE_SHMEM_FRAME_DELIVERY_RETAINED",
        FRAME_DELIVERY_RETAINED,
    );
    out.push('\n');

    emit_layout_constant_group(
        out,
        "COVERAGE_ENTRY",
        COVERAGE_ENTRY_SIZE,
        COVERAGE_ENTRY_ALIGN,
        &[
            ("CURRENT_ICOUNT", COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET),
            ("GUEST_PC", COVERAGE_ENTRY_GUEST_PC_OFFSET),
            ("MAP_INDEX", COVERAGE_ENTRY_MAP_INDEX_OFFSET),
            ("VCPU_INDEX", COVERAGE_ENTRY_VCPU_INDEX_OFFSET),
            ("BLOCK_LEN", COVERAGE_ENTRY_BLOCK_LEN_OFFSET),
            ("RESERVED", COVERAGE_ENTRY_RESERVED_OFFSET),
        ],
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_COVERAGE_ENTRY_RESERVED_LEN",
        COVERAGE_ENTRY_SIZE - COVERAGE_ENTRY_RESERVED_OFFSET,
    );
    out.push('\n');

    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_FINGERPRINT_DIGEST_BYTES",
        FINGERPRINT_DIGEST_BYTES,
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_FINGERPRINT_SAMPLE_MAX_VCPUS",
        FINGERPRINT_SAMPLE_MAX_VCPUS,
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_FINGERPRINT_SAMPLE_WORDS",
        FINGERPRINT_SAMPLE_WORDS,
    );
    emit_layout_constant_group(
        out,
        "FINGERPRINT_SAMPLE_SLOT",
        FINGERPRINT_SAMPLE_SLOT_SIZE,
        FINGERPRINT_SAMPLE_SLOT_ALIGN,
        &[
            ("GEN", FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET),
            ("RESERVED", FINGERPRINT_SAMPLE_SLOT_RESERVED_OFFSET),
            ("WORDS", FINGERPRINT_SAMPLE_SLOT_WORDS_OFFSET),
        ],
    );
    out.push('\n');

    emit_layout_constant_group(
        out,
        "WHITEBOX_MARKER_ENTRY",
        WHITEBOX_MARKER_ENTRY_SIZE,
        WHITEBOX_MARKER_ENTRY_ALIGN,
        &[
            (
                "CURRENT_ICOUNT",
                WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET,
            ),
            ("VCPU_INDEX", WHITEBOX_MARKER_ENTRY_VCPU_INDEX_OFFSET),
            ("KIND", WHITEBOX_MARKER_ENTRY_KIND_OFFSET),
            ("PAYLOAD_LEN", WHITEBOX_MARKER_ENTRY_PAYLOAD_LEN_OFFSET),
            ("PAYLOAD", WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET),
            ("RESERVED", WHITEBOX_MARKER_ENTRY_RESERVED_OFFSET),
        ],
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_WHITEBOX_MARKER_ENTRY_RESERVED_LEN",
        WHITEBOX_MARKER_ENTRY_SIZE - WHITEBOX_MARKER_ENTRY_RESERVED_OFFSET,
    );
    out.push('\n');

    emit_layout_constant_group(
        out,
        "GUEST_INTROSPECTION_ENTRY",
        GUEST_INTROSPECTION_ENTRY_SIZE,
        GUEST_INTROSPECTION_ENTRY_ALIGN,
        &[
            ("SEQUENCE", GUEST_INTROSPECTION_ENTRY_SEQUENCE_OFFSET),
            ("LEN", GUEST_INTROSPECTION_ENTRY_LEN_OFFSET),
            ("PAD", GUEST_INTROSPECTION_ENTRY_PAD_OFFSET),
            ("DATA", GUEST_INTROSPECTION_ENTRY_DATA_OFFSET),
            ("RESERVED", GUEST_INTROSPECTION_ENTRY_RESERVED_OFFSET),
        ],
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_PAD_LEN",
        GUEST_INTROSPECTION_ENTRY_DATA_OFFSET - GUEST_INTROSPECTION_ENTRY_PAD_OFFSET,
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_RESERVED_LEN",
        GUEST_INTROSPECTION_ENTRY_SIZE - GUEST_INTROSPECTION_ENTRY_RESERVED_OFFSET,
    );
    out.push('\n');
}
