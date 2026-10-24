//! Actual setup-region construction and refusal allocation controls.
//!
//! These component descriptors issue no Source or child-process authority.

use std::error::Error;

use crucible_host_resources::test_support::TestAllocationObserver;
use rustix::fs::{SealFlags, fcntl_get_seals, fstat, ftruncate};
use rustix::io::{FdFlags, fcntl_getfd, pread, pwrite};

use super::{QemuSpawnError, memfd_region};

#[test]
fn real_setup_memfd_preserves_length_seal_and_writes_without_heap_allocation()
-> Result<(), Box<dyn Error>> {
    let (region, counts) = TestAllocationObserver::count(|| memfd_region(4096));
    let region = region?;

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(fstat(&region)?.st_size, 4096);
    assert!(fcntl_getfd(&region)?.contains(FdFlags::CLOEXEC));
    assert!(fcntl_get_seals(&region)?.contains(SealFlags::SHRINK));

    assert_eq!(pwrite(&region, b"owned", 0)?, 5);
    let mut bytes = [0; 5];
    assert_eq!(pread(&region, &mut bytes, 0)?, 5);
    assert_eq!(&bytes, b"owned");
    assert_eq!(ftruncate(&region, 0), Err(rustix::io::Errno::PERM));
    assert_eq!(fstat(&region)?.st_size, 4096);
    Ok(())
}

#[test]
fn oversized_setup_memfd_preserves_typed_refusal_without_allocating() {
    let (result, counts) = TestAllocationObserver::count(|| memfd_region(u64::MAX));

    assert!(matches!(
        result,
        Err(QemuSpawnError::RegionLengthTooLarge {
            region_len: u64::MAX
        }),
    ));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
}
