//! Physical wrappers refuse sources that cannot preserve their owning checks.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{CheckedReadAccess, OwnedBlobBytes};
use crate::owned_decode::DecodeBudget;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Quota(FixtureResourceBudget);

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.reserve(descriptors, bytes)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

struct WholeOnlySource {
    access: CheckedReadAccess,
    whole_attempts: AtomicUsize,
    raw_attempts: AtomicUsize,
}

impl BlobSource for WholeOnlySource {
    fn checked_read_access(&self) -> CheckedReadAccess {
        self.access
    }

    fn logical_length(&self) -> u64 {
        1
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.raw_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(std::io::Cursor::new([7])))
    }

    fn read_all_with_boundary(
        &self,
        original: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        self.whole_attempts.fetch_add(1, Ordering::SeqCst);
        BlobHandle::from_bytes([7]).read_all_with_boundary(original, maximum, boundary)
    }
}

#[test]
fn physical_owning_contract_never_retries_a_whole_only_or_opaque_child() {
    for access in [CheckedReadAccess::Whole, CheckedReadAccess::Unsupported] {
        let quota = Arc::new(Quota(FixtureResourceBudget::new(8, 4 * 1024 * 1024)));
        let caller = DecodeBudget::for_store(quota.clone()).unwrap();
        let source = Arc::new(WholeOnlySource {
            access,
            whole_attempts: AtomicUsize::new(0),
            raw_attempts: AtomicUsize::new(0),
        });
        let resources = quota
            .reserve_resources(0, deferred_source_metadata_bytes() as u64)
            .unwrap();
        let credit = caller
            .reserve_scratch_bytes(deferred_source_metadata_bytes() as u64)
            .unwrap();
        let wrapped = BlobHandle::new(Arc::new(PhysicalQuotaBlobSource {
            handle: BlobHandle::new(source.clone()),
            guard: quota.clone(),
            reader_bytes: 0,
            original: Some(caller.clone()),
            _credit: Some(credit),
            _resources: resources,
        }));
        let retained = quota.0.usage().unwrap();

        let error = wrapped
            .read_all_with_boundary(&caller, 1, &mut || Ok(()))
            .unwrap_err();

        assert!(matches!(
            error.original_failure(),
            StoreError::Unsupported { .. }
        ));
        assert_eq!(source.whole_attempts.load(Ordering::SeqCst), 0);
        assert_eq!(source.raw_attempts.load(Ordering::SeqCst), 0);
        assert_eq!(
            quota.0.usage().unwrap(),
            retained,
            "failed owning controls refund after drop"
        );
        drop(error);
        drop(wrapped);
        drop(caller);
        assert_eq!(quota.0.usage().unwrap(), (0, 0));
    }
}
