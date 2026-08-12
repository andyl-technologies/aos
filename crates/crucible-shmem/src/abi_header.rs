//! Generated C header support for the shared-memory ABI.

mod node_slot;

use node_slot::emit_node_slot;

use crate::{
    ABI_VERSION, ACCELERATOR_COMPLETION_RING_OFFSET, ACCELERATOR_ENTRY_ALIGN,
    ACCELERATOR_ENTRY_CLASS_OFFSET, ACCELERATOR_ENTRY_DATA_BYTES,
    ACCELERATOR_ENTRY_DATA_LEN_OFFSET, ACCELERATOR_ENTRY_DATA_OFFSET,
    ACCELERATOR_ENTRY_DEVICE_ID_OFFSET, ACCELERATOR_ENTRY_FLAGS_OFFSET,
    ACCELERATOR_ENTRY_GENERATION_OFFSET, ACCELERATOR_ENTRY_JOB_KIND_OFFSET,
    ACCELERATOR_ENTRY_OUTPUT_CAPACITY_OFFSET,
    ACCELERATOR_ENTRY_PROTOCOL_VERSION_OFFSET, ACCELERATOR_ENTRY_QUEUE_ID_OFFSET,
    ACCELERATOR_ENTRY_RESERVED_OFFSET, ACCELERATOR_ENTRY_SEQUENCE_OFFSET,
    ACCELERATOR_ENTRY_SERVICE_UNITS_OFFSET, ACCELERATOR_ENTRY_SIZE,
    ACCELERATOR_ENTRY_STATUS_OFFSET, ACCELERATOR_PROTOCOL_VERSION, ACCELERATOR_QUEUE_CAPACITY,
    ACCELERATOR_REQUEST_RING_OFFSET, ACCELERATOR_RINGS_PER_VM, COVERAGE_ENTRY_ALIGN,
    COVERAGE_ENTRY_BLOCK_LEN_OFFSET, COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
    COVERAGE_ENTRY_GUEST_PC_OFFSET, COVERAGE_ENTRY_MAP_INDEX_OFFSET,
    COVERAGE_ENTRY_RESERVED_OFFSET, COVERAGE_ENTRY_SIZE, COVERAGE_ENTRY_VCPU_INDEX_OFFSET,
    COVERAGE_QUEUE_CAPACITY, DEFAULT_QUEUE_CAPACITY, FRAME_ENTRY_ALIGN, FRAME_ENTRY_DATA_OFFSET,
    FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET, FRAME_ENTRY_LEN_OFFSET, FRAME_ENTRY_PAD_OFFSET,
    FRAME_ENTRY_SEQ_OFFSET, FRAME_ENTRY_SIZE, FRAME_ENTRY_SRC_NODE_OFFSET, FUTEX_PRIVATE, KIND_9P,
    KIND_BLK, KIND_NET, KIND_VM, LAYOUT_TARGET_TRIPLE, MAX_FRAME_DATA, MAX_NODES, MAX_VM_NODES,
    NODE_SLOT_ALIGN, NODE_SLOT_CURRENT_ICOUNT_OFFSET, NODE_SLOT_CURRENT_NS_OFFSET,
    NODE_SLOT_DEVICE_COMPLETION_DEADLINE_ICOUNT_OFFSET, NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
    NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, NODE_SLOT_KIND_OFFSET,
    NODE_SLOT_LOGICAL_TIME_RAW_ICOUNT_OFFSET, NODE_SLOT_LOGICAL_TIME_RESTORE_ACK_OFFSET,
    NODE_SLOT_LOGICAL_TIME_RESTORE_REQUEST_OFFSET, NODE_SLOT_LOGICAL_TIME_RESTORE_TARGET_OFFSET,
    NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET, NODE_SLOT_PAD0_OFFSET, NODE_SLOT_PAD2_OFFSET,
    NODE_SLOT_PREEMPTION_ARG0_OFFSET, NODE_SLOT_PREEMPTION_ARG1_OFFSET,
    NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET, NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET,
    NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET, NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET,
    NODE_SLOT_PREEMPTION_KIND_OFFSET, NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET,
    NODE_SLOT_PUBLISH_GEN_OFFSET, NODE_SLOT_SIZE, NODE_SLOT_STATUS_OFFSET,
    NODE_SLOT_WAKE_SIGNAL_OFFSET, PREEMPTION_KIND_INTERRUPT_AT, PREEMPTION_KIND_NONE,
    PREEMPTION_KIND_VCPU_SWITCH, REGION_HEADER_ABI_VERSION_OFFSET, REGION_HEADER_ALIGN,
    REGION_HEADER_CONTROL_PADDING_OFFSET, REGION_HEADER_ENTRY_STRIDE_OFFSET,
    REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET, REGION_HEADER_ICOUNT_SHIFT_OFFSET,
    REGION_HEADER_MAGIC_OFFSET, REGION_HEADER_NODE_COUNT_OFFSET,
    REGION_HEADER_PAUSE_REQUESTED_OFFSET, REGION_HEADER_QUEUE_CAPACITY_OFFSET,
    REGION_HEADER_REGION_SIZE_OFFSET, REGION_HEADER_RESERVED_OFFSET,
    REGION_HEADER_RING_COUNT_OFFSET, REGION_HEADER_RING_DATA_OFF_OFFSET,
    REGION_HEADER_RING_HDR_OFF_OFFSET, REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET, REGION_HEADER_SIZE,
    REGION_MAGIC, RESERVED_SLOTS, RING_HEADER_ALIGN, RING_HEADER_PAD_READ_OFFSET,
    RING_HEADER_PAD_WRITE_OFFSET, RING_HEADER_READ_IDX_OFFSET, RING_HEADER_SIZE,
    RING_HEADER_WRITE_IDX_OFFSET, SLOT_9P_IO, SLOT_BLK_IO, SLOT_NET_ROUTER, STATUS_DONE,
    STATUS_IDLE, STATUS_RUNNING, WHITEBOX_MARKER_ENTRY_ALIGN,
    WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET, WHITEBOX_MARKER_ENTRY_KIND_OFFSET,
    WHITEBOX_MARKER_ENTRY_PAYLOAD_LEN_OFFSET, WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET,
    WHITEBOX_MARKER_ENTRY_RESERVED_OFFSET, WHITEBOX_MARKER_ENTRY_SIZE,
    WHITEBOX_MARKER_ENTRY_VCPU_INDEX_OFFSET, WHITEBOX_MARKER_QUEUE_CAPACITY,
};
use crate::{
    FINGERPRINT_DIGEST_BYTES, FINGERPRINT_SAMPLE_MAX_VCPUS, FINGERPRINT_SAMPLE_SLOT_ALIGN,
    FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET, FINGERPRINT_SAMPLE_SLOT_RESERVED_OFFSET,
    FINGERPRINT_SAMPLE_SLOT_SIZE, FINGERPRINT_SAMPLE_SLOT_WORDS_OFFSET, FINGERPRINT_SAMPLE_WORDS,
    GUEST_INTROSPECTION_ENTRY_ALIGN, GUEST_INTROSPECTION_ENTRY_DATA_BYTES,
    GUEST_INTROSPECTION_ENTRY_DATA_OFFSET, GUEST_INTROSPECTION_ENTRY_LEN_OFFSET,
    GUEST_INTROSPECTION_ENTRY_PAD_OFFSET, GUEST_INTROSPECTION_ENTRY_RESERVED_OFFSET,
    GUEST_INTROSPECTION_ENTRY_SEQUENCE_OFFSET, GUEST_INTROSPECTION_ENTRY_SIZE,
    GUEST_INTROSPECTION_QUEUE_CAPACITY, GUEST_INTROSPECTION_REQUEST_RING_OFFSET,
    GUEST_INTROSPECTION_RESPONSE_RING_OFFSET, GUEST_INTROSPECTION_RINGS_PER_VM,
};

/// Generates the committed `crucible_shmem_abi.h` contents.
///
/// The generated header is one independently consumable implementation view of
/// the public process ABI declared by `interface/crucible-shmem-abi.toml`. It
/// carries matching C `_Static_assert` checks for every shared struct size,
/// alignment, and field offset.
#[must_use]
pub fn generated_c_header() -> String {
    let mut out = String::new();
    emit_preamble(&mut out);
    emit_constants(&mut out);
    emit_region_header(&mut out);
    emit_node_slot(&mut out);
    emit_ring_header(&mut out);
    emit_frame_entry(&mut out);
    emit_coverage_entry(&mut out);
    emit_fingerprint_sample_slot(&mut out);
    emit_whitebox_marker_entry(&mut out);
    crate::emit_fault_command_c_header(&mut out);
    crate::emit_fault_target_manifest_c_header(&mut out);
    crate::emit_fault_register_evidence_c_header(&mut out);
    crate::emit_fault_instruction_evidence_c_header(&mut out);
    crate::emit_fault_terminal_evidence_c_header(&mut out);
    crate::emit_fault_node_c_header(&mut out);
    crate::emit_fault_event_c_header(&mut out);
    emit_guest_introspection_geometry_helpers(&mut out);
    emit_guest_introspection_entry(&mut out);
    emit_accelerator_entry(&mut out);
    emit_footer(&mut out);
    out
}

fn emit_preamble(out: &mut String) {
    out.push_str("/* SPDX-License-Identifier: MIT OR Apache-2.0 */\n");
    out.push_str("/* Generated by crucible-shmem. Do not edit by hand. */\n");
    out.push_str(
        "/* Public process ABI: independently implementable; contains no QEMU-private types. */\n",
    );
    out.push_str("#ifndef CRUCIBLE_SHMEM_ABI_H\n");
    out.push_str("#define CRUCIBLE_SHMEM_ABI_H\n\n");
    out.push_str("#include <stdatomic.h>\n");
    out.push_str("#include <stddef.h>\n");
    out.push_str("#include <stdint.h>\n\n");
    out.push_str("#if !defined(__GNUC__) && !defined(__clang__)\n");
    out.push_str(
        "#error \"crucible_shmem_abi.h requires a compiler with aligned attribute support\"\n",
    );
    out.push_str("#endif\n\n");
    out.push_str("#define CRUCIBLE_SHMEM_ALIGNED(N) __attribute__((aligned(N)))\n");
    out.push_str("#define CRUCIBLE_SHMEM_STATIC_ASSERT(COND, MSG) _Static_assert((COND), MSG)\n\n");
}

fn emit_constants(out: &mut String) {
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
            ("PAD", FRAME_ENTRY_PAD_OFFSET),
            ("DATA", FRAME_ENTRY_DATA_OFFSET),
        ],
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_FRAME_ENTRY_PAD_LEN",
        FRAME_ENTRY_DATA_OFFSET - FRAME_ENTRY_PAD_OFFSET,
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

fn emit_guest_introspection_geometry_helpers(out: &mut String) {
    out.push_str(
        r#"typedef struct crucible_shmem_guest_introspection_layout {
    uint32_t ring_count;
    uint32_t queue_capacity;
    uint64_t ring_hdr_off;
    uint64_t ring_data_off;
    uint64_t entry_stride;
    uint32_t accelerator_ring_count;
    uint32_t accelerator_queue_capacity;
    uint64_t accelerator_ring_hdr_off;
    uint64_t accelerator_ring_data_off;
    uint64_t accelerator_entry_stride;
    uint64_t region_size;
} crucible_shmem_guest_introspection_layout;

static inline int crucible_shmem_u64_checked_add(uint64_t left, uint64_t right, uint64_t *out) {
    if (out == NULL || left > UINT64_MAX - right) {
        return -1;
    }
    *out = left + right;
    return 0;
}

static inline int crucible_shmem_u64_checked_mul(uint64_t left, uint64_t right, uint64_t *out) {
    if (out == NULL || (right != 0u && left > UINT64_MAX / right)) {
        return -1;
    }
    *out = left * right;
    return 0;
}

static inline int crucible_shmem_u64_checked_align_up(uint64_t value, uint64_t alignment, uint64_t *out) {
    uint64_t remainder;
    uint64_t adjustment;
    if (out == NULL || alignment == 0u || (alignment & (alignment - 1u)) != 0u) {
        return -1;
    }
    remainder = value & (alignment - 1u);
    adjustment = remainder == 0u ? 0u : alignment - remainder;
    return crucible_shmem_u64_checked_add(value, adjustment, out);
}

static inline int crucible_shmem_guest_introspection_ring_index(
    uint32_t vm_slot,
    uint32_t direction_offset,
    uint32_t *out
) {
    if (out == NULL
        || direction_offset >= CRUCIBLE_SHMEM_GUEST_INTROSPECTION_RINGS_PER_VM
        || vm_slot > UINT32_MAX / CRUCIBLE_SHMEM_GUEST_INTROSPECTION_RINGS_PER_VM) {
        return -1;
    }
    *out = vm_slot * CRUCIBLE_SHMEM_GUEST_INTROSPECTION_RINGS_PER_VM + direction_offset;
    return 0;
}

static inline int crucible_shmem_guest_introspection_layout_compute(
    uint64_t frame_ring_data_off,
    uint32_t frame_ring_count,
    uint32_t frame_queue_capacity,
    uint64_t frame_entry_stride,
    uint32_t vm_node_count,
    uint32_t fault_payload_arena_bytes,
    uint64_t advertised_region_size,
    crucible_shmem_guest_introspection_layout *out
) {
    uint64_t count;
    uint64_t byte_len;
    uint64_t frame_data_end;
    uint64_t coverage_hdr_off;
    uint64_t coverage_data_off;
    uint64_t coverage_data_end;
    uint64_t fingerprint_off;
    uint64_t fingerprint_end;
    uint64_t marker_hdr_off;
    uint64_t marker_data_off;
    uint64_t marker_data_end;
    uint64_t fault_command_hdr_off;
    uint64_t fault_command_slot_off;
    uint64_t fault_command_slot_end;
    uint64_t fault_command_arena_hdr_off;
    uint64_t fault_command_arena_off;
    uint64_t fault_command_data_end;
    uint64_t fault_result_hdr_off;
    uint64_t fault_result_slot_off;
    uint64_t fault_result_slot_end;
    uint64_t fault_result_arena_hdr_off;
    uint64_t fault_result_arena_off;
    uint64_t fault_result_data_end;
    uint64_t fault_event_hdr_off;
    uint64_t fault_event_slot_off;
    uint64_t fault_event_slot_end;
    uint64_t fault_event_arena_hdr_off;
    uint64_t fault_event_arena_off;
    uint64_t fault_event_data_end;
    uint64_t guest_hdr_off;
    uint64_t guest_data_off;
    uint64_t guest_data_end;
    uint64_t accelerator_hdr_off;
    uint64_t accelerator_data_off;
    uint64_t computed_region_size;
    uint32_t guest_ring_count;
    uint32_t accelerator_ring_count;

    if (out == NULL
        || vm_node_count > CRUCIBLE_SHMEM_MAX_VM_NODES
        || frame_queue_capacity == 0u
        || (frame_queue_capacity & (frame_queue_capacity - 1u)) != 0u
        || frame_entry_stride != CRUCIBLE_SHMEM_FRAME_ENTRY_SIZE
        || fault_payload_arena_bytes < CRUCIBLE_FAULT_DEFAULT_PAYLOAD_BYTES
        || fault_payload_arena_bytes > CRUCIBLE_FAULT_HARD_PAYLOAD_ARENA_BYTES
        || frame_ring_count
            != vm_node_count * CRUCIBLE_SHMEM_RESERVED_SLOTS * 2u) {
        return -1;
    }
    if (crucible_shmem_u64_checked_mul(frame_ring_count, frame_queue_capacity, &count) != 0
        || crucible_shmem_u64_checked_mul(count, frame_entry_stride, &byte_len) != 0
        || crucible_shmem_u64_checked_add(frame_ring_data_off, byte_len, &frame_data_end) != 0
        || crucible_shmem_u64_checked_align_up(frame_data_end, CRUCIBLE_SHMEM_RING_HEADER_ALIGN, &coverage_hdr_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_SHMEM_RING_HEADER_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(coverage_hdr_off, byte_len, &coverage_data_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_SHMEM_COVERAGE_QUEUE_CAPACITY, &count) != 0
        || crucible_shmem_u64_checked_mul(count, CRUCIBLE_SHMEM_COVERAGE_ENTRY_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(coverage_data_off, byte_len, &coverage_data_end) != 0
        || crucible_shmem_u64_checked_align_up(coverage_data_end, CRUCIBLE_SHMEM_FINGERPRINT_SAMPLE_SLOT_ALIGN, &fingerprint_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_SHMEM_FINGERPRINT_SAMPLE_SLOT_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fingerprint_off, byte_len, &fingerprint_end) != 0
        || crucible_shmem_u64_checked_align_up(fingerprint_end, CRUCIBLE_SHMEM_RING_HEADER_ALIGN, &marker_hdr_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_SHMEM_RING_HEADER_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(marker_hdr_off, byte_len, &marker_data_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_SHMEM_WHITEBOX_MARKER_QUEUE_CAPACITY, &count) != 0
        || crucible_shmem_u64_checked_mul(count, CRUCIBLE_SHMEM_WHITEBOX_MARKER_ENTRY_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(marker_data_off, byte_len, &marker_data_end) != 0
        || crucible_shmem_u64_checked_align_up(marker_data_end, CRUCIBLE_SHMEM_RING_HEADER_ALIGN, &fault_command_hdr_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_SHMEM_RING_HEADER_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_command_hdr_off, byte_len, &fault_command_slot_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_FAULT_DEFAULT_COMMAND_CAPACITY, &count) != 0
        || crucible_shmem_u64_checked_mul(count, CRUCIBLE_FAULT_COMMAND_SLOT_V1_BYTES, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_command_slot_off, byte_len, &fault_command_slot_end) != 0
        || crucible_shmem_u64_checked_align_up(fault_command_slot_end, CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES, &fault_command_arena_hdr_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_command_arena_hdr_off, byte_len, &fault_command_arena_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, fault_payload_arena_bytes, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_command_arena_off, byte_len, &fault_command_data_end) != 0
        || crucible_shmem_u64_checked_align_up(fault_command_data_end, CRUCIBLE_SHMEM_RING_HEADER_ALIGN, &fault_result_hdr_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_SHMEM_RING_HEADER_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_result_hdr_off, byte_len, &fault_result_slot_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_FAULT_DEFAULT_COMMAND_CAPACITY, &count) != 0
        || crucible_shmem_u64_checked_mul(count, CRUCIBLE_FAULT_RESULT_SLOT_V1_BYTES, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_result_slot_off, byte_len, &fault_result_slot_end) != 0
        || crucible_shmem_u64_checked_align_up(fault_result_slot_end, CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES, &fault_result_arena_hdr_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_result_arena_hdr_off, byte_len, &fault_result_arena_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, fault_payload_arena_bytes, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_result_arena_off, byte_len, &fault_result_data_end) != 0
        || crucible_shmem_u64_checked_align_up(fault_result_data_end, CRUCIBLE_SHMEM_RING_HEADER_ALIGN, &fault_event_hdr_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_SHMEM_RING_HEADER_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_event_hdr_off, byte_len, &fault_event_slot_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_FAULT_EVENT_CAPACITY, &count) != 0
        || crucible_shmem_u64_checked_mul(count, CRUCIBLE_FAULT_EVENT_SLOT_V1_BYTES, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_event_slot_off, byte_len, &fault_event_slot_end) != 0
        || crucible_shmem_u64_checked_align_up(fault_event_slot_end, CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES, &fault_event_arena_hdr_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, CRUCIBLE_FAULT_PAYLOAD_ARENA_HEADER_BYTES, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_event_arena_hdr_off, byte_len, &fault_event_arena_off) != 0
        || crucible_shmem_u64_checked_mul(vm_node_count, fault_payload_arena_bytes, &byte_len) != 0
        || crucible_shmem_u64_checked_add(fault_event_arena_off, byte_len, &fault_event_data_end) != 0
        || crucible_shmem_u64_checked_align_up(fault_event_data_end, CRUCIBLE_SHMEM_RING_HEADER_ALIGN, &guest_hdr_off) != 0
        || vm_node_count > UINT32_MAX / CRUCIBLE_SHMEM_GUEST_INTROSPECTION_RINGS_PER_VM) {
        return -1;
    }
    guest_ring_count = vm_node_count * CRUCIBLE_SHMEM_GUEST_INTROSPECTION_RINGS_PER_VM;
    if (crucible_shmem_u64_checked_mul(guest_ring_count, CRUCIBLE_SHMEM_RING_HEADER_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(guest_hdr_off, byte_len, &guest_data_off) != 0
        || crucible_shmem_u64_checked_mul(guest_ring_count, CRUCIBLE_SHMEM_GUEST_INTROSPECTION_QUEUE_CAPACITY, &count) != 0
        || crucible_shmem_u64_checked_mul(count, CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(guest_data_off, byte_len, &guest_data_end) != 0
        || crucible_shmem_u64_checked_align_up(guest_data_end, CRUCIBLE_SHMEM_RING_HEADER_ALIGN, &accelerator_hdr_off) != 0
        || vm_node_count > UINT32_MAX / CRUCIBLE_SHMEM_ACCELERATOR_RINGS_PER_VM) {
        return -1;
    }
    accelerator_ring_count = vm_node_count * CRUCIBLE_SHMEM_ACCELERATOR_RINGS_PER_VM;
    if (crucible_shmem_u64_checked_mul(accelerator_ring_count, CRUCIBLE_SHMEM_RING_HEADER_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(accelerator_hdr_off, byte_len, &accelerator_data_off) != 0
        || crucible_shmem_u64_checked_mul(accelerator_ring_count, CRUCIBLE_SHMEM_ACCELERATOR_QUEUE_CAPACITY, &count) != 0
        || crucible_shmem_u64_checked_mul(count, CRUCIBLE_SHMEM_ACCELERATOR_ENTRY_SIZE, &byte_len) != 0
        || crucible_shmem_u64_checked_add(accelerator_data_off, byte_len, &computed_region_size) != 0
        || computed_region_size != advertised_region_size) {
        return -1;
    }

    out->ring_count = guest_ring_count;
    out->queue_capacity = CRUCIBLE_SHMEM_GUEST_INTROSPECTION_QUEUE_CAPACITY;
    out->ring_hdr_off = guest_hdr_off;
    out->ring_data_off = guest_data_off;
    out->entry_stride = CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_SIZE;
    out->accelerator_ring_count = accelerator_ring_count;
    out->accelerator_queue_capacity = CRUCIBLE_SHMEM_ACCELERATOR_QUEUE_CAPACITY;
    out->accelerator_ring_hdr_off = accelerator_hdr_off;
    out->accelerator_ring_data_off = accelerator_data_off;
    out->accelerator_entry_stride = CRUCIBLE_SHMEM_ACCELERATOR_ENTRY_SIZE;
    out->region_size = computed_region_size;
    return 0;
}

"#,
    );
}

fn emit_region_header(out: &mut String) {
    out.push_str("typedef struct CRUCIBLE_SHMEM_ALIGNED(128) crucible_shmem_region_header {\n");
    out.push_str("    _Atomic uint64_t magic;\n");
    out.push_str("    _Atomic uint32_t abi_version;\n");
    out.push_str("    _Atomic uint32_t node_count;\n");
    out.push_str("    _Atomic uint32_t queue_capacity;\n");
    out.push_str("    _Atomic uint32_t ring_count;\n");
    out.push_str("    _Atomic uint64_t ring_hdr_off;\n");
    out.push_str("    _Atomic uint64_t ring_data_off;\n");
    out.push_str("    _Atomic uint64_t entry_stride;\n");
    out.push_str("    _Atomic uint64_t region_size;\n");
    out.push_str("    _Atomic uint32_t icount_shift;\n");
    out.push_str("    _Atomic uint8_t pause_requested;\n");
    out.push_str("    _Atomic uint8_t shutdown_requested;\n");
    out.push_str("    uint8_t control_padding[2];\n");
    out.push_str("    _Atomic uint32_t fault_payload_arena_bytes;\n");
    out.push_str("    uint8_t reserved[CRUCIBLE_SHMEM_REGION_HEADER_RESERVED_LEN];\n");
    out.push_str("} crucible_shmem_region_header;\n\n");

    emit_static_asserts(
        out,
        "crucible_shmem_region_header",
        "REGION_HEADER",
        &[
            ("magic", "MAGIC"),
            ("abi_version", "ABI_VERSION"),
            ("node_count", "NODE_COUNT"),
            ("queue_capacity", "QUEUE_CAPACITY"),
            ("ring_count", "RING_COUNT"),
            ("ring_hdr_off", "RING_HDR_OFF"),
            ("ring_data_off", "RING_DATA_OFF"),
            ("entry_stride", "ENTRY_STRIDE"),
            ("region_size", "REGION_SIZE"),
            ("icount_shift", "ICOUNT_SHIFT"),
            ("pause_requested", "PAUSE_REQUESTED"),
            ("shutdown_requested", "SHUTDOWN_REQUESTED"),
            ("control_padding", "CONTROL_PADDING"),
            ("fault_payload_arena_bytes", "FAULT_PAYLOAD_ARENA_BYTES"),
            ("reserved", "RESERVED"),
        ],
    );
}

fn emit_ring_header(out: &mut String) {
    out.push_str("typedef struct CRUCIBLE_SHMEM_ALIGNED(128) crucible_shmem_ring_header {\n");
    out.push_str("    _Atomic uint64_t read_idx;\n");
    out.push_str("    uint8_t pad_read[CRUCIBLE_SHMEM_RING_HEADER_PAD_READ_LEN];\n");
    out.push_str("    _Atomic uint64_t write_idx;\n");
    out.push_str("    uint8_t pad_write[CRUCIBLE_SHMEM_RING_HEADER_PAD_WRITE_LEN];\n");
    out.push_str("} crucible_shmem_ring_header;\n\n");

    emit_static_asserts(
        out,
        "crucible_shmem_ring_header",
        "RING_HEADER",
        &[
            ("read_idx", "READ_IDX"),
            ("pad_read", "PAD_READ"),
            ("write_idx", "WRITE_IDX"),
            ("pad_write", "PAD_WRITE"),
        ],
    );
}

fn emit_frame_entry(out: &mut String) {
    out.push_str("typedef struct crucible_shmem_frame_entry {\n");
    out.push_str("    uint64_t delivery_icount;\n");
    out.push_str("    uint32_t src_node;\n");
    out.push_str("    uint32_t seq;\n");
    out.push_str("    uint16_t len;\n");
    out.push_str("    uint8_t pad[CRUCIBLE_SHMEM_FRAME_ENTRY_PAD_LEN];\n");
    out.push_str("    uint8_t data[CRUCIBLE_SHMEM_MAX_FRAME_DATA];\n");
    out.push_str("} crucible_shmem_frame_entry;\n\n");

    emit_static_asserts(
        out,
        "crucible_shmem_frame_entry",
        "FRAME_ENTRY",
        &[
            ("delivery_icount", "DELIVERY_ICOUNT"),
            ("src_node", "SRC_NODE"),
            ("seq", "SEQ"),
            ("len", "LEN"),
            ("pad", "PAD"),
            ("data", "DATA"),
        ],
    );
}

fn emit_fingerprint_sample_slot(out: &mut String) {
    out.push_str(&format!(
        "typedef struct CRUCIBLE_SHMEM_ALIGNED({FINGERPRINT_SAMPLE_SLOT_ALIGN}) crucible_shmem_fingerprint_sample_slot {{\n"
    ));
    out.push_str("    _Atomic uint32_t sample_gen;\n");
    out.push_str("    uint32_t reserved;\n");
    out.push_str("    _Atomic uint64_t words[CRUCIBLE_SHMEM_FINGERPRINT_SAMPLE_WORDS];\n");
    out.push_str("} crucible_shmem_fingerprint_sample_slot;\n\n");

    emit_static_asserts(
        out,
        "crucible_shmem_fingerprint_sample_slot",
        "FINGERPRINT_SAMPLE_SLOT",
        &[
            ("sample_gen", "GEN"),
            ("reserved", "RESERVED"),
            ("words", "WORDS"),
        ],
    );
}

fn emit_coverage_entry(out: &mut String) {
    out.push_str(&format!(
        "typedef struct CRUCIBLE_SHMEM_ALIGNED({COVERAGE_ENTRY_ALIGN}) crucible_shmem_coverage_entry {{\n"
    ));
    out.push_str("    uint64_t current_icount;\n");
    out.push_str("    uint64_t guest_pc;\n");
    out.push_str("    uint64_t map_index;\n");
    out.push_str("    uint32_t vcpu_index;\n");
    out.push_str("    uint32_t block_len;\n");
    out.push_str("    uint8_t reserved[CRUCIBLE_SHMEM_COVERAGE_ENTRY_RESERVED_LEN];\n");
    out.push_str("} crucible_shmem_coverage_entry;\n\n");

    emit_static_asserts(
        out,
        "crucible_shmem_coverage_entry",
        "COVERAGE_ENTRY",
        &[
            ("current_icount", "CURRENT_ICOUNT"),
            ("guest_pc", "GUEST_PC"),
            ("map_index", "MAP_INDEX"),
            ("vcpu_index", "VCPU_INDEX"),
            ("block_len", "BLOCK_LEN"),
            ("reserved", "RESERVED"),
        ],
    );
}

fn emit_whitebox_marker_entry(out: &mut String) {
    out.push_str(&format!(
        "typedef struct CRUCIBLE_SHMEM_ALIGNED({WHITEBOX_MARKER_ENTRY_ALIGN}) crucible_shmem_whitebox_marker_entry {{\n"
    ));
    out.push_str("    uint64_t current_icount;\n");
    out.push_str("    uint32_t vcpu_index;\n");
    out.push_str("    uint16_t kind;\n");
    out.push_str("    uint16_t payload_len;\n");
    out.push_str("    uint8_t payload[CRUCIBLE_SHMEM_MAX_FRAME_DATA];\n");
    out.push_str("    uint8_t reserved[CRUCIBLE_SHMEM_WHITEBOX_MARKER_ENTRY_RESERVED_LEN];\n");
    out.push_str("} crucible_shmem_whitebox_marker_entry;\n\n");

    emit_static_asserts(
        out,
        "crucible_shmem_whitebox_marker_entry",
        "WHITEBOX_MARKER_ENTRY",
        &[
            ("current_icount", "CURRENT_ICOUNT"),
            ("vcpu_index", "VCPU_INDEX"),
            ("kind", "KIND"),
            ("payload_len", "PAYLOAD_LEN"),
            ("payload", "PAYLOAD"),
            ("reserved", "RESERVED"),
        ],
    );
}

fn emit_guest_introspection_entry(out: &mut String) {
    out.push_str(&format!(
        "typedef struct CRUCIBLE_SHMEM_ALIGNED({GUEST_INTROSPECTION_ENTRY_ALIGN}) crucible_shmem_guest_introspection_entry {{\n"
    ));
    out.push_str("    uint64_t sequence;\n");
    out.push_str("    uint16_t len;\n");
    out.push_str("    uint8_t pad[CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_PAD_LEN];\n");
    out.push_str("    uint8_t data[CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_DATA_BYTES];\n");
    out.push_str("    uint8_t reserved[CRUCIBLE_SHMEM_GUEST_INTROSPECTION_ENTRY_RESERVED_LEN];\n");
    out.push_str("} crucible_shmem_guest_introspection_entry;\n\n");

    emit_static_asserts(
        out,
        "crucible_shmem_guest_introspection_entry",
        "GUEST_INTROSPECTION_ENTRY",
        &[
            ("sequence", "SEQUENCE"),
            ("len", "LEN"),
            ("pad", "PAD"),
            ("data", "DATA"),
            ("reserved", "RESERVED"),
        ],
    );
}

fn emit_accelerator_entry(out: &mut String) {
    emit_layout_constant_group(
        out,
        "ACCELERATOR_ENTRY",
        ACCELERATOR_ENTRY_SIZE,
        ACCELERATOR_ENTRY_ALIGN,
        &[
            ("SEQUENCE", ACCELERATOR_ENTRY_SEQUENCE_OFFSET),
            ("GENERATION", ACCELERATOR_ENTRY_GENERATION_OFFSET),
            ("DEVICE_ID", ACCELERATOR_ENTRY_DEVICE_ID_OFFSET),
            ("CLASS", ACCELERATOR_ENTRY_CLASS_OFFSET),
            ("JOB_KIND", ACCELERATOR_ENTRY_JOB_KIND_OFFSET),
            ("QUEUE_ID", ACCELERATOR_ENTRY_QUEUE_ID_OFFSET),
            ("STATUS", ACCELERATOR_ENTRY_STATUS_OFFSET),
            (
                "PROTOCOL_VERSION",
                ACCELERATOR_ENTRY_PROTOCOL_VERSION_OFFSET,
            ),
            ("FLAGS", ACCELERATOR_ENTRY_FLAGS_OFFSET),
            ("DATA_LEN", ACCELERATOR_ENTRY_DATA_LEN_OFFSET),
            ("SERVICE_UNITS", ACCELERATOR_ENTRY_SERVICE_UNITS_OFFSET),
            ("OUTPUT_CAPACITY", ACCELERATOR_ENTRY_OUTPUT_CAPACITY_OFFSET),
            ("DATA", ACCELERATOR_ENTRY_DATA_OFFSET),
            ("RESERVED", ACCELERATOR_ENTRY_RESERVED_OFFSET),
        ],
    );
    emit_define_usize(
        out,
        "CRUCIBLE_SHMEM_ACCELERATOR_ENTRY_RESERVED_LEN",
        ACCELERATOR_ENTRY_SIZE - ACCELERATOR_ENTRY_RESERVED_OFFSET,
    );
    out.push_str(&format!(
        "typedef struct CRUCIBLE_SHMEM_ALIGNED({ACCELERATOR_ENTRY_ALIGN}) crucible_shmem_accelerator_entry {{\n"
    ));
    out.push_str("    uint64_t sequence;\n");
    out.push_str("    uint64_t generation;\n");
    out.push_str("    uint8_t device_id[32];\n");
    out.push_str("    uint16_t class_id;\n");
    out.push_str("    uint16_t job_kind;\n");
    out.push_str("    uint16_t queue_id;\n");
    out.push_str("    uint16_t status;\n");
    out.push_str("    uint16_t protocol_version;\n");
    out.push_str("    uint16_t flags;\n");
    out.push_str("    uint32_t data_len;\n");
    out.push_str("    uint64_t service_units;\n");
    out.push_str("    uint32_t output_capacity;\n");
    out.push_str("    uint8_t data[CRUCIBLE_SHMEM_ACCELERATOR_ENTRY_DATA_BYTES];\n");
    out.push_str("    uint8_t reserved[CRUCIBLE_SHMEM_ACCELERATOR_ENTRY_RESERVED_LEN];\n");
    out.push_str("} crucible_shmem_accelerator_entry;\n\n");
    emit_static_asserts(
        out,
        "crucible_shmem_accelerator_entry",
        "ACCELERATOR_ENTRY",
        &[
            ("sequence", "SEQUENCE"),
            ("generation", "GENERATION"),
            ("device_id", "DEVICE_ID"),
            ("class_id", "CLASS"),
            ("job_kind", "JOB_KIND"),
            ("queue_id", "QUEUE_ID"),
            ("status", "STATUS"),
            ("protocol_version", "PROTOCOL_VERSION"),
            ("flags", "FLAGS"),
            ("data_len", "DATA_LEN"),
            ("service_units", "SERVICE_UNITS"),
            ("output_capacity", "OUTPUT_CAPACITY"),
            ("data", "DATA"),
            ("reserved", "RESERVED"),
        ],
    );
}

fn emit_static_asserts(
    out: &mut String,
    c_type: &str,
    layout_prefix: &str,
    fields: &[(&str, &str)],
) {
    out.push_str(&format!(
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof({c_type}) == CRUCIBLE_SHMEM_{layout_prefix}_SIZE, \"{c_type} size\");\n"
    ));
    out.push_str(&format!(
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof({c_type}) == CRUCIBLE_SHMEM_{layout_prefix}_ALIGN, \"{c_type} alignment\");\n"
    ));
    for (field, offset_suffix) in fields {
        out.push_str(&format!(
            "CRUCIBLE_SHMEM_STATIC_ASSERT(offsetof({c_type}, {field}) == CRUCIBLE_SHMEM_{layout_prefix}_{offset_suffix}_OFFSET, \"{c_type}.{field} offset\");\n"
        ));
    }
    out.push('\n');
}

fn emit_layout_constant_group(
    out: &mut String,
    prefix: &str,
    size: usize,
    align: usize,
    offsets: &[(&str, usize)],
) {
    emit_define_usize(out, &format!("CRUCIBLE_SHMEM_{prefix}_SIZE"), size);
    emit_define_usize(out, &format!("CRUCIBLE_SHMEM_{prefix}_ALIGN"), align);
    for (field, offset) in offsets {
        emit_define_usize(
            out,
            &format!("CRUCIBLE_SHMEM_{prefix}_{field}_OFFSET"),
            *offset,
        );
    }
}

fn emit_define_bool(out: &mut String, name: &str, value: bool) {
    let value = if value { 1 } else { 0 };
    out.push_str(&format!("#define {name} {value}\n"));
}

fn emit_define_str(out: &mut String, name: &str, value: &str) {
    out.push_str(&format!("#define {name} \"{value}\"\n"));
}

fn emit_define_u8(out: &mut String, name: &str, value: u8) {
    out.push_str(&format!("#define {name} {value}u\n"));
}

fn emit_define_u32(out: &mut String, name: &str, value: u32) {
    out.push_str(&format!("#define {name} {value}u\n"));
}

fn emit_define_u64_hex(out: &mut String, name: &str, value: u64) {
    out.push_str(&format!("#define {name} UINT64_C(0x{value:016x})\n"));
}

fn emit_define_usize(out: &mut String, name: &str, value: usize) {
    out.push_str(&format!("#define {name} {value}u\n"));
}

fn emit_footer(out: &mut String) {
    out.push_str("#endif /* CRUCIBLE_SHMEM_ABI_H */\n");
}
