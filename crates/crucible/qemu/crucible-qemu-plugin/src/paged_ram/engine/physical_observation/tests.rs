//! Physical bitmap, exact coverage and retained original charge controls.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

#[test]
fn residency_counts_logical_tail_and_only_kernel_low_bit() {
    assert_eq!(
        resident_logical_bytes(&[1, 0, 0x81], 8193).unwrap_or_else(|e| panic!("{e}")),
        4097
    );
    assert_eq!(
        resident_logical_bytes(&[0x80, 1], 4097).unwrap_or_else(|e| panic!("{e}")),
        1
    );
    assert!(resident_logical_bytes(&[], 1).is_err());
    assert!(resident_logical_bytes(&[1], 8192).is_err());
    assert!(resident_logical_bytes(&[], 0).is_err());
}

#[test]
fn observation_control_refuses_before_birth_and_returns_credit_after_body() {
    let bytes = size_of::<Mutex<Option<RamControlResidentObservation>>>() as u64;
    let insufficient = crucible_ram::MetadataBudget::new(bytes - 1);
    assert!(ResidentObservationState::prepare(&insufficient).is_err());
    assert_eq!(insufficient.used_bytes(), 0);

    let budget = crucible_ram::MetadataBudget::new(bytes);
    let owner = ResidentObservationState::prepare(&budget).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(budget.used_bytes(), bytes);
    let held = owner.try_lock().unwrap_or_else(|e| panic!("{e}"));
    assert!(owner.try_lock().is_err());
    assert!(ResidentObservationState::prepare(&budget).is_err());
    drop(held);
    drop(owner);
    assert_eq!(budget.used_bytes(), 0);
    assert!(super::super::admission::verify_service_header_extent().is_ok());
}

struct Mapping {
    address: *mut c_void,
    length: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this fixture exclusively owns the original complete mmap.
        let status = unsafe { libc::munmap(self.address, self.length) };
        assert_eq!(status, 0);
    }
}

#[test]
fn actual_kernel_residency_changes_without_reading_cold_guest_bytes() {
    let length = 4 * PAGE_BYTES;
    // SAFETY: anonymous mmap creates a private fixture mapping, not guest or
    // native registered memory. This fixture retains its sole close owner.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(address, libc::MAP_FAILED);
    let mapping = Mapping { address, length };
    // SAFETY: this fixture's sole complete anonymous mapping remains owned;
    // disabling hugepage promotion fixes the four-page observation geometry.
    let status = unsafe { libc::madvise(mapping.address, length, libc::MADV_NOHUGEPAGE) };
    assert_eq!(status, 0);

    let mut bits = [0_u8; 4];
    let sample = |bits: &mut [u8]| {
        sample_resident_chunk(mapping.address as u64, length as u64, bits)
            .unwrap_or_else(|e| panic!("{e}"))
    };
    assert_eq!(sample(&mut bits), 0);

    // SAFETY: the same exclusive mapping supplies these two writable pages.
    unsafe {
        (mapping.address as *mut u8).write_volatile(7);
        (mapping.address as *mut u8)
            .add(2 * PAGE_BYTES)
            .write_volatile(9);
    }
    assert_eq!(sample(&mut bits), 2 * PAGE_BYTES as u64);

    // SAFETY: discard acts only on the second populated fixture page, never
    // guest RAM. mincore afterward does not read or fault that page back in.
    let status = unsafe {
        libc::madvise(
            (mapping.address as *mut u8).add(2 * PAGE_BYTES).cast(),
            PAGE_BYTES,
            libc::MADV_DONTNEED,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(sample(&mut bits), PAGE_BYTES as u64);
}

#[test]
fn kernel_chunk_rejects_unbounded_or_unrepresentable_geometry_before_query() {
    let mut scratch = [0_u8; 4];
    for (address, logical) in [
        (0, 4096),
        (1, 4096),
        (4096, 0),
        (4096, 5 * 4096),
        (u64::MAX - 4095, 4096),
    ] {
        assert!(sample_resident_chunk(address, logical, &mut scratch).is_err());
    }
    assert_eq!(scratch, [0; 4]);
}

#[test]
fn poisoned_result_custody_refuses_observation_without_returning_live_credit() {
    let bytes = size_of::<Mutex<Option<RamControlResidentObservation>>>() as u64;
    let budget = crucible_ram::MetadataBudget::new(bytes);
    let owner = ResidentObservationState::prepare(&budget).unwrap_or_else(|e| panic!("{e}"));
    let poisoned = std::panic::catch_unwind(|| {
        let _held = owner.try_lock().unwrap_or_else(|e| panic!("{e}"));
        panic!("fixture poisons the actual result guard");
    });
    assert!(poisoned.is_err());
    assert!(owner.try_lock().is_err());
    assert_eq!(budget.used_bytes(), bytes);
    drop(owner);
    assert_eq!(budget.used_bytes(), 0);
}
