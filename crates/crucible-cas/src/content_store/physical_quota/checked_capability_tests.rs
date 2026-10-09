//! Physical wrappers refuse sources that cannot preserve their owning checks.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{CheckedReadAccess, OwnedBlobBytes};
use crate::owned_decode::DecodeBudget;
use std::sync::atomic::{AtomicUsize, Ordering};

struct OrderedQuota {
    resources: FixtureResourceBudget,
    calls: AtomicUsize,
    refusal: AtomicUsize,
    poison: std::sync::Mutex<Option<DecodeBudget>>,
}

impl OrderedQuota {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            resources: FixtureResourceBudget::new(128, 256 << 20),
            calls: AtomicUsize::new(0),
            refusal: AtomicUsize::new(0),
            poison: std::sync::Mutex::new(None),
        })
    }
}

impl StorePhysicalQuotaGuard for OrderedQuota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(256 << 20)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.resources.reserve(descriptors, bytes)
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.refusal.load(Ordering::SeqCst) {
            1 => Err(StoreError::Unauthorized),
            2 => Err(StoreError::Quota),
            3 => {
                self.poison
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .charge_bytes(u64::MAX)
                    .unwrap_err();
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

struct OrderedSupervisor(Arc<OrderedQuota>);
struct OrderedOperation;

impl crate::content_store::SqliteCatalogSupervisor for OrderedSupervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.reserve_resources(0, bytes)
    }

    fn begin(
        &self,
        _: crate::content_store::SqliteCatalogOperationKind,
    ) -> Result<Box<dyn crate::content_store::SqliteCatalogOperation>, StoreError> {
        Ok(Box::new(OrderedOperation))
    }
}

impl crate::content_store::SqliteCatalogOperation for OrderedOperation {
    fn check(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        Ok(())
    }
}

#[test]
fn nested_sqlite_nominal_checks_outer_physical_first_and_original_between_owners() {
    let directory = tempfile::tempdir().unwrap();
    let deepest = OrderedQuota::new();
    let authorities = crate::content_store::SqliteBlobBackend::open_with_physical_quota_and_admin(
        "physical-order",
        directory.path(),
        deepest.clone(),
        8 << 20,
        Arc::new(OrderedSupervisor(deepest)),
        &crate::content_store::fixture_sqlite_heap().unwrap(),
    )
    .unwrap();
    let inner_guard = OrderedQuota::new();
    let inner: Arc<dyn ImmutableBlobBackend> = Arc::new(
        PhysicalQuotaStore::new(
            "inner",
            authorities.0,
            authorities.1.clone(),
            inner_guard.clone(),
        )
        .unwrap(),
    );
    let outer_guard = OrderedQuota::new();
    let outer =
        PhysicalQuotaStore::new("outer", inner, authorities.1, outer_guard.clone()).unwrap();
    let namespace = DecodeBudget::for_store(OrderedQuota::new()).unwrap();
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, b"no query may run");
    inner_guard.refusal.store(2, Ordering::SeqCst);

    for poison_original in [false, true] {
        let operation = namespace.child().unwrap();
        outer_guard
            .refusal
            .store(if poison_original { 3 } else { 1 }, Ordering::SeqCst);
        *outer_guard.poison.lock().unwrap() = Some(operation.clone());
        outer_guard.calls.store(0, Ordering::SeqCst);
        inner_guard.calls.store(0, Ordering::SeqCst);
        let error = crate::ram::read_tree_for_test(
            &outer,
            &operation,
            id,
            crucible_ram::NodeDigest::from_bytes([0; 32]),
            &mut || Ok(()),
        )
        .unwrap_err();

        let crate::ram::RamStoreError::Store(error) = error else {
            panic!("lost original category")
        };
        if poison_original {
            assert!(matches!(
                error.original_failure(),
                StoreError::DecodeAdmission { .. }
            ));
        } else {
            assert!(matches!(error.original_failure(), StoreError::Unauthorized));
        }
        assert_eq!(outer_guard.calls.load(Ordering::SeqCst), 1);
        assert_eq!(inner_guard.calls.load(Ordering::SeqCst), 0);
        outer_guard.poison.lock().unwrap().take();
        drop(error);
        drop(operation);
        namespace.verify_live().unwrap();
    }
}

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

#[derive(Clone)]
struct WholeOnlySource {
    access: CheckedReadAccess,
    whole_attempts: Arc<AtomicUsize>,
    raw_attempts: Arc<AtomicUsize>,
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
        let source = WholeOnlySource {
            access,
            whole_attempts: Arc::new(AtomicUsize::new(0)),
            raw_attempts: Arc::new(AtomicUsize::new(0)),
        };
        let resources = quota
            .reserve_resources(0, deferred_source_metadata_bytes() as u64)
            .unwrap();
        let credit = caller
            .reserve_scratch_bytes(deferred_source_metadata_bytes() as u64)
            .unwrap();
        let wrapped = BlobHandle::new(PhysicalQuotaBlobSource {
            handle: BlobHandle::new(source.clone()),
            guard: quota.clone(),
            reader_bytes: 0,
            _credit: Some(credit),
            _resources: resources,
        });
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
