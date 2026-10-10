//! Verifies that predecessor RAM semantics fail before shared slot admission.

// crucible-lint: allow panic-shortcut -- validated shared-memory fixture setup must stop the test on error.
#![allow(clippy::expect_used)]
#![forbid(unsafe_code)]

use crucible_shmem::{
    ABI_VERSION, DEFAULT_QUEUE_CAPACITY, RegionConfig, RegionHeader, RegionHeaderSnapshot,
    RegionLayout, RegionSetupValidationError, validate_setup_region_header,
};

const PREDECESSOR_SHMEM_ABI: u32 = 30;

fn current_header() -> (RegionLayout, RegionHeaderSnapshot) {
    assert_eq!(ABI_VERSION, 31);
    let layout = RegionLayout::for_config(RegionConfig::new(1, DEFAULT_QUEUE_CAPACITY))
        .expect("admit current shared-memory fixture geometry");
    let header = RegionHeader::new(layout);
    (layout, header.snapshot())
}

#[test]
fn current_ram_semantic_header_is_admitted() {
    let (layout, header) = current_header();

    let admitted = validate_setup_region_header(header, layout.region_size)
        .expect("admit current shared-memory fixture header");

    assert_eq!(admitted.abi_version, ABI_VERSION);
    assert_eq!(admitted.region_len, layout.region_size);
}

#[test]
fn identical_layout_cannot_relabel_predecessor_ram_semantics() {
    let (layout, header) = current_header();
    let old_header = RegionHeaderSnapshot {
        abi_version: PREDECESSOR_SHMEM_ABI,
        ..header
    };

    let refused = validate_setup_region_header(old_header, layout.region_size);

    assert_eq!(
        refused,
        Err(RegionSetupValidationError::AbiVersionMismatch {
            actual: PREDECESSOR_SHMEM_ABI,
            expected: ABI_VERSION,
        })
    );
    assert!(validate_setup_region_header(header, layout.region_size).is_ok());
}

#[test]
fn predecessor_is_refused_before_geometry_or_clock_admission() {
    let (layout, header) = current_header();
    let malformed_old_header = RegionHeaderSnapshot {
        abi_version: PREDECESSOR_SHMEM_ABI,
        node_count: u32::MAX,
        queue_capacity: u32::MAX,
        ticks_per_ns: 0,
        ..header
    };

    let refused = validate_setup_region_header(malformed_old_header, layout.region_size);

    assert_eq!(
        refused,
        Err(RegionSetupValidationError::AbiVersionMismatch {
            actual: PREDECESSOR_SHMEM_ABI,
            expected: ABI_VERSION,
        })
    );
}
