//! Physical wrappers retain authority across synchronous and owning checked reads.

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
fn physical_checked_contract_preserves_whole_and_refuses_opaque_without_raw_reads() {
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

        let result = wrapped.read_all_with_boundary(&caller, 1, &mut || Ok(()));
        match access {
            CheckedReadAccess::Whole => {
                let bytes = result.unwrap();
                assert_eq!(&*bytes, &[7]);
                assert_eq!(source.whole_attempts.load(Ordering::SeqCst), 1);
                drop(bytes);
            }
            CheckedReadAccess::Unsupported => {
                let error = result.unwrap_err();
                assert!(matches!(
                    error.original_failure(),
                    StoreError::Unsupported { .. }
                ));
                assert_eq!(source.whole_attempts.load(Ordering::SeqCst), 0);
                drop(error);
            }
            CheckedReadAccess::Owning => unreachable!(),
        }
        assert_eq!(source.raw_attempts.load(Ordering::SeqCst), 0);
        assert_eq!(
            quota.0.usage().unwrap(),
            retained,
            "synchronous read resources refund after output or error closes"
        );
        drop(wrapped);
        drop(caller);
        assert_eq!(quota.0.usage().unwrap(), (0, 0));
    }
}

#[derive(Clone, Copy)]
enum WholeCut {
    Healthy,
    PhysicalDuringChild,
    OriginalDuringChild,
    ChildErrorBeforePhysical,
    PhysicalAfterChild,
}

struct CutWholeSource {
    guard: Arc<OrderedQuota>,
    calls: Arc<AtomicUsize>,
    cut: WholeCut,
}

impl BlobSource for CutWholeSource {
    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Whole
    }

    fn logical_length(&self) -> u64 {
        1
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        panic!("checked Whole forwarding must never open an ordinary reader")
    }

    fn read_all_with_boundary(
        &self,
        original: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.cut {
            WholeCut::PhysicalDuringChild => {
                self.guard.refusal.store(1, Ordering::SeqCst);
                boundary()?;
            }
            WholeCut::OriginalDuringChild => {
                original.charge_bytes(u64::MAX).unwrap_err();
                boundary()?;
            }
            WholeCut::ChildErrorBeforePhysical => {
                self.guard.refusal.store(1, Ordering::SeqCst);
                return Err(StoreError::Corrupt {
                    id: ContentId::for_bytes(ObjectKind::RamTree, 1, &[7]),
                });
            }
            WholeCut::Healthy | WholeCut::PhysicalAfterChild => {}
        }
        let bytes =
            BlobHandle::from_bytes([7]).read_all_with_boundary(original, maximum, boundary)?;
        if matches!(self.cut, WholeCut::PhysicalAfterChild) {
            self.guard.refusal.store(1, Ordering::SeqCst);
        }
        Ok(bytes)
    }
}

fn cut_whole_handle(
    guard: &Arc<OrderedQuota>,
    original: &DecodeBudget,
    calls: Arc<AtomicUsize>,
    cut: WholeCut,
) -> BlobHandle {
    let resources = guard
        .reserve_resources(0, deferred_source_metadata_bytes() as u64)
        .unwrap();
    let credit = original
        .reserve_scratch_bytes(deferred_source_metadata_bytes() as u64)
        .unwrap();
    BlobHandle::new(PhysicalQuotaBlobSource {
        handle: BlobHandle::new(CutWholeSource {
            guard: guard.clone(),
            calls,
            cut,
        }),
        guard: guard.clone(),
        reader_bytes: 0,
        _credit: Some(credit),
        _resources: resources,
    })
}

#[test]
fn physical_whole_preserves_child_cause_before_later_physical_refusal() {
    for cut in [
        WholeCut::PhysicalDuringChild,
        WholeCut::OriginalDuringChild,
        WholeCut::ChildErrorBeforePhysical,
        WholeCut::PhysicalAfterChild,
    ] {
        let guard = OrderedQuota::new();
        let namespace = DecodeBudget::for_store(guard.clone()).unwrap();
        let original = namespace.child().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let source = cut_whole_handle(&guard, &original, calls.clone(), cut);
        let retained = guard.resources.usage().unwrap();

        let error = source
            .read_all_with_boundary(&original, 1, &mut || Ok(()))
            .unwrap_err();

        match cut {
            WholeCut::ChildErrorBeforePhysical => assert!(matches!(
                error.original_failure(),
                StoreError::Corrupt { .. }
            )),
            WholeCut::OriginalDuringChild => assert!(matches!(
                error.original_failure(),
                StoreError::DecodeAdmission { .. }
            )),
            _ => assert!(matches!(error.original_failure(), StoreError::Unauthorized)),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(guard.resources.usage().unwrap(), retained);
        drop(error);
        drop(source);
        drop(original);
        // The fixture's physical refusal is independent of the released
        // child account. Restore that test policy before checking its parent.
        guard.refusal.store(0, Ordering::SeqCst);
        namespace.verify_live().unwrap();
        drop(namespace);
        assert_eq!(guard.resources.usage().unwrap(), (0, 0));
    }
}

#[test]
fn physical_whole_retains_saved_guard_and_refuses_before_child_effects() {
    for exhaust_resources in [false, true] {
        let guard = OrderedQuota::new();
        let replacement = OrderedQuota::new();
        replacement.refusal.store(1, Ordering::SeqCst);
        let original = DecodeBudget::for_store(guard.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let source = cut_whole_handle(&guard, &original, calls.clone(), WholeCut::Healthy);
        // A separate replacement owner cannot change the retained source's
        // physical authority. The actual retained guard alone accepts it.
        let bytes = source
            .read_all_with_boundary(&original, 1, &mut || Ok(()))
            .unwrap();
        assert_eq!(&*bytes, &[7]);
        drop(bytes);
        assert_eq!(replacement.calls.load(Ordering::SeqCst), 0);
        calls.store(0, Ordering::SeqCst);
        let retained = guard.resources.usage().unwrap();
        let blocker = if exhaust_resources {
            Some(
                guard
                    .reserve_resources(0, (256 << 20) - retained.1)
                    .unwrap(),
            )
        } else {
            guard.refusal.store(1, Ordering::SeqCst);
            None
        };

        let error = source
            .read_all_with_boundary(&original, 1, &mut || Ok(()))
            .unwrap_err();

        if exhaust_resources {
            assert!(matches!(error.original_failure(), StoreError::Quota));
        } else {
            assert!(matches!(error.original_failure(), StoreError::Unauthorized));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(error);
        drop(blocker);
        assert_eq!(guard.resources.usage().unwrap(), retained);
        drop(source);
        drop(original);
        assert_eq!(guard.resources.usage().unwrap(), (0, 0));
    }
}

#[test]
fn merkle_native_route_keeps_nested_physical_and_original_checks_before_child_io() {
    let directory = tempfile::tempdir().unwrap();
    let deepest = OrderedQuota::new();
    let authorities = crate::content_store::SqliteBlobBackend::open_with_physical_quota_and_admin(
        "merkle-physical-order",
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
    let id = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"no query may run");
    inner_guard.refusal.store(2, Ordering::SeqCst);

    for poison_original in [false, true] {
        let operation = namespace.child().unwrap();
        outer_guard
            .refusal
            .store(if poison_original { 3 } else { 1 }, Ordering::SeqCst);
        *outer_guard.poison.lock().unwrap() = Some(operation.clone());
        outer_guard.calls.store(0, Ordering::SeqCst);
        inner_guard.calls.store(0, Ordering::SeqCst);
        let error = outer
            .read_merkle_node_with_boundary(&operation, id, &mut || Ok(()))
            .unwrap_err();
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
