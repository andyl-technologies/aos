//! Checks the generated C ABI header against the committed copy.

#![forbid(unsafe_code)]

use crucible_shmem::generated_c_header;

const COMMITTED_HEADER: &str = include_str!("../include/crucible_shmem_abi.h");

#[test]
fn committed_header_matches_generated_rust_layout() {
    assert_eq!(COMMITTED_HEADER, generated_c_header());
}

#[test]
fn generated_header_preserves_public_abi_license_notice() {
    let header = generated_c_header();
    assert!(header.starts_with("/* SPDX-License-Identifier: MIT OR Apache-2.0 */\n"));
    assert!(header.contains("Public process ABI: independently implementable"));
}

#[test]
fn generated_header_asserts_every_shared_struct_layout() {
    let header = generated_c_header();
    for needle in [
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_region_header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_region_header)",
        "offsetof(crucible_shmem_region_header, magic)",
        "offsetof(crucible_shmem_region_header, shutdown_requested)",
        "offsetof(crucible_shmem_region_header, reserved)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_node_slot)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_node_slot)",
        "offsetof(crucible_shmem_node_slot, current_icount)",
        "offsetof(crucible_shmem_node_slot, publish_gen)",
        "offsetof(crucible_shmem_node_slot, control_boundary_ack)",
        "offsetof(crucible_shmem_node_slot, logical_time_raw_icount)",
        "offsetof(crucible_shmem_node_slot, logical_time_restore_ack)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_ring_header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_ring_header)",
        "offsetof(crucible_shmem_ring_header, read_idx)",
        "offsetof(crucible_shmem_ring_header, write_idx)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_frame_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_frame_entry)",
        "offsetof(crucible_shmem_frame_entry, delivery_icount)",
        "offsetof(crucible_shmem_frame_entry, delivery_state)",
        "offsetof(crucible_shmem_frame_entry, delivery_attempts)",
        "offsetof(crucible_shmem_frame_entry, last_delivery_attempt_icount)",
        "offsetof(crucible_shmem_frame_entry, data)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_coverage_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_coverage_entry)",
        "offsetof(crucible_shmem_coverage_entry, current_icount)",
        "offsetof(crucible_shmem_coverage_entry, guest_pc)",
        "offsetof(crucible_shmem_coverage_entry, map_index)",
        "offsetof(crucible_shmem_coverage_entry, vcpu_index)",
        "offsetof(crucible_shmem_coverage_entry, block_len)",
        "offsetof(crucible_shmem_coverage_entry, reserved)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_command_slot_v1)",
        "offsetof(crucible_fault_command_slot_v1, header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_result_slot_v1)",
        "offsetof(crucible_fault_result_slot_v1, header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_fault_payload_arena_header)",
        "offsetof(crucible_fault_payload_arena_header, read_cursor)",
        "offsetof(crucible_fault_payload_arena_header, write_cursor)",
        "CRUCIBLE_FAULT_TARGET_MANIFEST_QUERY_MAGIC_V1 \"CRUCFTQ1\"",
        "CRUCIBLE_FAULT_REGISTER_MANIFEST_BODY_DIGEST_OFFSET 24",
        "CRUCIBLE_FAULT_REGISTER_ROW_LENGTH_OFFSET 38",
        "CRUCIBLE_FAULT_REGISTER_SIDE_EFFECTS_V1_MASK 63",
        "CRUCIBLE_FAULT_TARGET_MANIFEST_KIND_HARDWARE_ERROR 3",
        "CRUCIBLE_FAULT_HARDWARE_ERROR_MANIFEST_MAGIC_V1 \"CRUCHWM1\"",
        "CRUCIBLE_FAULT_HARDWARE_ERROR_ROW_STATUS_REQUIRED_OFFSET 24",
        "CRUCIBLE_FAULT_HARDWARE_ERROR_CLASS_FATAL 3",
        "CRUCIBLE_FAULT_HARDWARE_ERROR_MECHANISM_ACPI_GHES 2",
        "CRUCIBLE_FAULT_REGISTER_EVIDENCE_MAGIC_V1 \"CRUCREG1\"",
        "CRUCIBLE_FAULT_REGISTER_EVIDENCE_HEADER_V1_BYTES 256",
        "CRUCIBLE_FAULT_REGISTER_EVIDENCE_EXECUTION_FINGERPRINT_OFFSET 216",
        "CRUCIBLE_FAULT_REGISTER_MUTATION_REPLACE 3",
    ] {
        assert!(
            header.contains(needle),
            "generated C header missing `{needle}`"
        );
    }
}
