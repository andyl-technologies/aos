//! Checks setup-time shared-memory mapping and header validation.

#![forbid(unsafe_code)]

use crucible_shmem::{
    ABI_VERSION, DEFAULT_QUEUE_CAPACITY, REGION_HEADER_SIZE, REGION_MAGIC, RING_HEADER_SIZE,
    RegionConfig, RegionHeader, RegionHeaderSnapshot, RegionLayout, RegionSetupValidationError,
    ValidatedSetupRegion, validate_setup_region_header,
};

#[cfg(unix)]
use crucible_shmem::{SetupRegionMapError, mmap_setup_region};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn setup_region_header_validation_accepts_magic_abi_and_region_len() {
    let (layout, snapshot) = valid_snapshot();

    assert_eq!(
        validate_setup_region_header(snapshot, layout.region_size),
        Ok(ValidatedSetupRegion {
            region_len: layout.region_size,
            abi_version: ABI_VERSION,
        })
    );
}

#[test]
fn setup_region_header_validation_rejects_invalid_abi_marker() {
    let (layout, snapshot) = valid_snapshot();

    assert_eq!(
        validate_setup_region_header(
            RegionHeaderSnapshot {
                magic: 0,
                ..snapshot
            },
            layout.region_size,
        ),
        Err(RegionSetupValidationError::InvalidMagic {
            actual: 0,
            expected: REGION_MAGIC,
        })
    );
    assert_eq!(
        validate_setup_region_header(
            RegionHeaderSnapshot {
                abi_version: ABI_VERSION + 1,
                ..snapshot
            },
            layout.region_size,
        ),
        Err(RegionSetupValidationError::AbiVersionMismatch {
            actual: ABI_VERSION + 1,
            expected: ABI_VERSION,
        })
    );
}

#[test]
fn setup_region_header_validation_rejects_wrong_region_len() {
    let (layout, snapshot) = valid_snapshot();
    let short_region_len = layout.region_size - 1;

    assert_eq!(
        validate_setup_region_header(snapshot, short_region_len),
        Err(RegionSetupValidationError::RegionLengthMismatch {
            setup_region_len: short_region_len,
            header_region_size: layout.region_size,
        })
    );
    assert_eq!(
        validate_setup_region_header(snapshot, REGION_HEADER_SIZE as u64 - 1),
        Err(RegionSetupValidationError::RegionTooSmall {
            region_len: REGION_HEADER_SIZE as u64 - 1,
            minimum_len: REGION_HEADER_SIZE as u64,
        })
    );
}

#[test]
fn setup_region_header_validation_rejects_invalid_geometry() {
    let (layout, snapshot) = valid_snapshot();

    assert_eq!(
        validate_setup_region_header(
            RegionHeaderSnapshot {
                ring_data_off: snapshot.ring_data_off + RING_HEADER_SIZE as u64,
                ..snapshot
            },
            layout.region_size,
        ),
        Err(RegionSetupValidationError::InvalidRingDataOffset {
            actual: snapshot.ring_data_off + RING_HEADER_SIZE as u64,
            expected: snapshot.ring_data_off,
        })
    );
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_maps_exact_region_len_before_header_validation() {
    let temp = temp_region_file();
    let region_len = REGION_HEADER_SIZE as u64;
    if let Err(error) = temp.set_len(region_len) {
        panic!("failed to size temporary setup region: {error}");
    }

    let mapped = match mmap_setup_region(temp.as_fd(), region_len) {
        Ok(mapped) => mapped,
        Err(error) => panic!("setup region mmap should succeed: {error}"),
    };

    assert_eq!(mapped.region_len(), region_len);
    assert_eq!(
        mapped.validate_header(),
        Err(RegionSetupValidationError::InvalidMagic {
            actual: 0,
            expected: REGION_MAGIC,
        })
    );
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_rejects_lengths_smaller_than_header() {
    let temp = temp_region_file();
    let region_len = REGION_HEADER_SIZE as u64 - 1;

    assert_eq!(
        mmap_setup_region(temp.as_fd(), region_len).map(|mapped| mapped.region_len()),
        Err(SetupRegionMapError::RegionTooSmall {
            region_len,
            minimum_len: REGION_HEADER_SIZE as u64,
        })
    );
}

fn valid_snapshot() -> (RegionLayout, RegionHeaderSnapshot) {
    let layout = match RegionLayout::for_config(RegionConfig::new(2, DEFAULT_QUEUE_CAPACITY, 3)) {
        Ok(layout) => layout,
        Err(error) => panic!("valid setup region layout should build: {error}"),
    };
    let header = RegionHeader::new(layout);
    (layout, header.snapshot())
}

#[cfg(unix)]
fn temp_region_file() -> std::fs::File {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crucible-shmem-setup-validation-{}-{}",
        std::process::id(),
        unique_temp_suffix()
    ));

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) => panic!("failed to create temporary setup region: {error}"),
    };
    if let Err(error) = std::fs::remove_file(&path) {
        panic!("failed to unlink temporary setup region: {error}");
    }
    file
}

#[cfg(unix)]
fn unique_temp_suffix() -> u64 {
    NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
}
