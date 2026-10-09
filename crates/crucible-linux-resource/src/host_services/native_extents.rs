//! Admits unequal native resident and metadata extents before lease controls.
//!
//! The metadata amount is a subset of the resident amount. These original
//! counter reservations create neither a native role nor backing, Source,
//! CPU, protocol, or physical-domain authority.

use super::{HostServiceAllocator, HostServiceError, HostServiceLease};

impl HostServiceAllocator {
    /// Reserves full native residency and TOTAL metadata from the same accounts.
    ///
    /// Task and descriptor charges belong to the resident account only. The
    /// metadata account independently tracks its subset; it does not add that
    /// amount to physical residency. Both stack reservations succeed before
    /// either shared lease control is allocated. The caller must include both
    /// controls in the admitted metadata purpose and retain the pair outside
    /// every allocation it funds until physical control closure.
    ///
    /// This method lends existing capacity only. A certified native issuer must
    /// separately bind the genuine full resource vector, Source, backing,
    /// original deadline and physical domain before using these reservations.
    ///
    /// # Errors
    /// Refuses zero extents, metadata larger than residency, either exhausted
    /// or poisoned account, overflow, or a request with no admitted resources.
    /// A second refusal rolls back the first stack charge without creating a
    /// lease control or keeping an accounting lock across rollback.
    pub fn reserve_native_pair(
        &self,
        metadata: &Self,
        tasks: u64,
        descriptors: u64,
        resident_bytes: u64,
        total_metadata_bytes: u64,
    ) -> Result<(HostServiceLease, HostServiceLease), HostServiceError> {
        if resident_bytes == 0 || total_metadata_bytes == 0 || total_metadata_bytes > resident_bytes
        {
            return Err(HostServiceError::InvalidContract);
        }

        let resident =
            self.reserve_completed(tasks, descriptors, resident_bytes, std::convert::identity)?;
        let metadata =
            metadata.reserve_completed(0, 0, total_metadata_bytes, std::convert::identity)?;

        Ok((resident.into_lease(), metadata.into_lease()))
    }
}

#[cfg(all(test, feature = "test-support"))]
// crucible-lint: allow rust-allow -- these exact admission and allocation controls panic only when the original-counter invariant fails.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::host_services::HostServiceLeasePair;
    use crate::test_support::TestAllocationObserver;

    #[test]
    fn second_refusal_creates_no_controls_and_rolls_back_the_full_first_extent() {
        let resident = HostServiceAllocator::new(69, 1056, 1536 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 1, 512 << 20).unwrap();
        let occupied = metadata.reserve_resources(0, 0, 1).unwrap();

        let (result, counts) = TestAllocationObserver::count(|| {
            resident.reserve_native_pair(&metadata, 69, 1056, 1536 << 20, 512 << 20)
        });

        assert!(matches!(result, Err(HostServiceError::CapacityExhausted)));
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(resident.capacity.used.lock().unwrap().resident_bytes, 0);
        assert_eq!(resident.capacity.used.lock().unwrap().tasks, 0);
        assert_eq!(resident.capacity.used.lock().unwrap().descriptors, 0);
        assert_eq!(metadata.capacity.used.lock().unwrap().resident_bytes, 1);
        drop(occupied);
    }

    #[test]
    fn full_resident_and_total_metadata_remain_distinct_until_both_controls_close() {
        let resident = HostServiceAllocator::new(69, 1056, 1536 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 1, 512 << 20).unwrap();

        let (result, counts) = TestAllocationObserver::count(|| {
            resident.reserve_native_pair(&metadata, 69, 1056, 1536 << 20, 512 << 20)
        });
        let (resident_lease, metadata_lease) = result.unwrap();

        assert_eq!(counts.allocations, 2);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(resident_lease.resident_bytes(), 1536 << 20);
        assert_eq!(metadata_lease.resident_bytes(), 512 << 20);
        assert_eq!(resident_lease.tasks(), 69);
        assert_eq!(resident_lease.file_descriptors(), 1056);
        assert_eq!(metadata_lease.tasks(), 0);
        assert_eq!(metadata_lease.file_descriptors(), 0);

        drop(HostServiceLeasePair::new(resident_lease, metadata_lease));

        assert_eq!(resident.capacity.used.lock().unwrap().resident_bytes, 0);
        assert_eq!(metadata.capacity.used.lock().unwrap().resident_bytes, 0);
    }

    #[test]
    fn a_metadata_subset_cannot_exceed_its_full_resident_extent() {
        let resident = HostServiceAllocator::new(1, 1, 64).unwrap();
        let metadata = HostServiceAllocator::new(1, 1, 64).unwrap();

        for (full, subset) in [(0, 1), (1, 0), (31, 32)] {
            let (result, counts) = TestAllocationObserver::count(|| {
                resident.reserve_native_pair(&metadata, 1, 1, full, subset)
            });

            assert!(matches!(result, Err(HostServiceError::InvalidContract)));
            assert_eq!(counts.allocations, 0);
            assert_eq!(resident.capacity.used.lock().unwrap().resident_bytes, 0);
            assert_eq!(metadata.capacity.used.lock().unwrap().resident_bytes, 0);
        }
    }
}
