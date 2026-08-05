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
        "offsetof(crucible_shmem_node_slot, reserved)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_ring_header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_ring_header)",
        "offsetof(crucible_shmem_ring_header, read_idx)",
        "offsetof(crucible_shmem_ring_header, write_idx)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_frame_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_frame_entry)",
        "offsetof(crucible_shmem_frame_entry, delivery_icount)",
        "offsetof(crucible_shmem_frame_entry, data)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_coverage_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_coverage_entry)",
        "offsetof(crucible_shmem_coverage_entry, current_icount)",
        "offsetof(crucible_shmem_coverage_entry, guest_pc)",
        "offsetof(crucible_shmem_coverage_entry, map_index)",
        "offsetof(crucible_shmem_coverage_entry, vcpu_index)",
        "offsetof(crucible_shmem_coverage_entry, block_len)",
        "offsetof(crucible_shmem_coverage_entry, reserved)",
    ] {
        assert!(
            header.contains(needle),
            "generated C header missing `{needle}`"
        );
    }
}
