//! C declaration and static assertions for the per-node shared-memory slot.

use super::emit_static_asserts;

pub(super) fn emit_node_slot(out: &mut String) {
    out.push_str("typedef struct CRUCIBLE_SHMEM_ALIGNED(128) crucible_shmem_node_slot {\n");
    out.push_str("    _Atomic uint64_t current_icount;\n");
    out.push_str("    _Atomic uint64_t current_ns;\n");
    out.push_str("    _Atomic uint64_t max_advance_icount;\n");
    out.push_str("    _Atomic uint64_t idle_wake_icount;\n");
    out.push_str("    _Atomic uint32_t wake_signal;\n");
    out.push_str("    _Atomic uint8_t status;\n");
    out.push_str("    _Atomic uint8_t kind;\n");
    out.push_str("    _Atomic uint8_t device_io_active;\n");
    out.push_str("    uint8_t pad0;\n");
    out.push_str("    _Atomic uint32_t publish_gen;\n");
    out.push_str("    _Atomic uint32_t control_boundary_ack;\n");
    out.push_str("    _Atomic uint64_t device_completion_deadline_icount;\n");
    out.push_str("    _Atomic uint64_t preemption_at_icount;\n");
    out.push_str("    _Atomic uint64_t preemption_deadline_icount;\n");
    out.push_str("    _Atomic uint64_t preemption_ceiling_icount;\n");
    out.push_str("    _Atomic uint32_t preemption_published_sequence;\n");
    out.push_str("    _Atomic uint32_t preemption_consumed_sequence;\n");
    out.push_str("    _Atomic uint32_t preemption_arg0;\n");
    out.push_str("    _Atomic uint32_t preemption_arg1;\n");
    out.push_str("    _Atomic uint8_t preemption_kind;\n");
    out.push_str("    uint8_t pad2[7];\n");
    out.push_str("    _Atomic uint64_t logical_time_raw_icount;\n");
    out.push_str("    _Atomic uint64_t logical_time_restore_target;\n");
    out.push_str("    _Atomic uint32_t logical_time_restore_request;\n");
    out.push_str("    _Atomic uint32_t logical_time_restore_ack;\n");
    out.push_str("} crucible_shmem_node_slot;\n\n");

    emit_static_asserts(
        out,
        "crucible_shmem_node_slot",
        "NODE_SLOT",
        &[
            ("current_icount", "CURRENT_ICOUNT"),
            ("current_ns", "CURRENT_NS"),
            ("max_advance_icount", "MAX_ADVANCE_ICOUNT"),
            ("idle_wake_icount", "IDLE_WAKE_ICOUNT"),
            ("wake_signal", "WAKE_SIGNAL"),
            ("status", "STATUS"),
            ("kind", "KIND"),
            ("device_io_active", "DEVICE_IO_ACTIVE"),
            ("pad0", "PAD0"),
            ("publish_gen", "PUBLISH_GEN"),
            ("control_boundary_ack", "CONTROL_BOUNDARY_ACK"),
            (
                "device_completion_deadline_icount",
                "DEVICE_COMPLETION_DEADLINE_ICOUNT",
            ),
            ("preemption_at_icount", "PREEMPTION_AT_ICOUNT"),
            ("preemption_deadline_icount", "PREEMPTION_DEADLINE_ICOUNT"),
            ("preemption_ceiling_icount", "PREEMPTION_CEILING_ICOUNT"),
            (
                "preemption_published_sequence",
                "PREEMPTION_PUBLISHED_SEQUENCE",
            ),
            (
                "preemption_consumed_sequence",
                "PREEMPTION_CONSUMED_SEQUENCE",
            ),
            ("preemption_arg0", "PREEMPTION_ARG0"),
            ("preemption_arg1", "PREEMPTION_ARG1"),
            ("preemption_kind", "PREEMPTION_KIND"),
            ("pad2", "PAD2"),
            ("logical_time_raw_icount", "LOGICAL_TIME_RAW_ICOUNT"),
            ("logical_time_restore_target", "LOGICAL_TIME_RESTORE_TARGET"),
            (
                "logical_time_restore_request",
                "LOGICAL_TIME_RESTORE_REQUEST",
            ),
            ("logical_time_restore_ack", "LOGICAL_TIME_RESTORE_ACK"),
        ],
    );
}
