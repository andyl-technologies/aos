//! Generated guest-introspection geometry helpers.

use super::*;

pub(super) fn emit_guest_introspection_geometry_helpers(out: &mut String) {
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
