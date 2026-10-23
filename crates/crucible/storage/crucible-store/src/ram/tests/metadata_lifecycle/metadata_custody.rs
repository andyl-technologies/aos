//! Actual admitted-root credit and shared-control closure in finite components.
//!
//! Namespace admission funds decoded metadata, independently of GC retention.
//! These controls establish no kernel quota, native launch or physical OOM.

use super::*;
use crate::owned_decode::ResourceLoan;
use crucible_host_resources::test_support::{CloseMarkerOutcome, TestAllocationObserver};
use std::alloc::Layout;
use std::sync::atomic::AtomicBool;

static CONTROL_CLOSED: AtomicBool = AtomicBool::new(false);
static WATCH_REFUND: AtomicBool = AtomicBool::new(false);
static EARLY_REFUND: AtomicBool = AtomicBool::new(false);

struct MetadataQuota {
    used: Arc<AtomicU64>,
    maximum: u64,
    last_request: AtomicU64,
}

struct MetadataCredit {
    used: Arc<AtomicU64>,
    bytes: u64,
    metadata: bool,
}

impl Drop for MetadataCredit {
    fn drop(&mut self) {
        if self.metadata
            && WATCH_REFUND.load(Ordering::SeqCst)
            && !CONTROL_CLOSED.load(Ordering::SeqCst)
        {
            EARLY_REFUND.store(true, Ordering::SeqCst);
        }
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl StorePhysicalQuotaGuard for MetadataQuota {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        assert_eq!(descriptors, 0);
        self.last_request.store(bytes, Ordering::SeqCst);
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| StoreError::Quota)?;
        Ok(ResourceLoan::new(MetadataCredit {
            used: self.used.clone(),
            bytes,
            metadata: bytes == crate::ram::metadata::allocation_bytes(1).unwrap(),
        }))
    }
}

fn controlled_store(path: &std::path::Path, maximum: u64) -> (RamStore, Arc<MetadataQuota>) {
    let quota = Arc::new(MetadataQuota {
        used: Arc::new(AtomicU64::new(0)),
        maximum,
        last_request: AtomicU64::new(0),
    });
    let backend =
        DirectoryBlobBackend::new_with_physical_quota("root-metadata-custody", path, quota.clone())
            .unwrap();
    let store = RamStore::new(
        backend,
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap();
    (store, quota)
}

fn resource_layout() -> Layout {
    let (layout, _) = Layout::new::<[usize; 2]>()
        .extend(Layout::new::<crate::ram::metadata::RootMetadataResources>())
        .unwrap();
    let layout = layout.pad_to_align();
    assert_eq!(
        layout.size() as u64,
        ResourceLoan::allocation_bytes::<crate::ram::metadata::RootMetadataResources>()
    );
    layout
}

#[test]
fn admitted_metadata_control_closes_before_original_refund_after_final_alias() {
    // Isolate the process-wide exact physical-close marker from other cases.
    if sqlite_process::isolated() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let (store, quota) = controlled_store(directory.path(), 256 << 20);
    let bytes = crate::ram::metadata::allocation_bytes(1).unwrap();
    let baseline = quota.used.load(Ordering::SeqCst);
    let (resources, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(resource_layout(), || {
            store.reserve_root_metadata(1).unwrap()
        });
    let (alias, clone_counts) = TestAllocationObserver::count(|| resources.clone());
    assert_eq!(clone_counts.allocations, 0);
    assert_eq!(clone_counts.reallocations, 0);
    assert_eq!(counts.allocations, 2); // Original receipt and one terminal owner.
    assert_eq!(counts.reallocations, 0);
    assert_eq!(quota.last_request.load(Ordering::SeqCst), bytes);
    assert_eq!(quota.used.load(Ordering::SeqCst), baseline + bytes);
    WATCH_REFUND.store(true, Ordering::SeqCst);

    let ((), outcome) = TestAllocationObserver::observe_close_marker_after_free(
        &CONTROL_CLOSED,
        identity.unwrap(),
        || {
            drop(resources);
            assert!(!CONTROL_CLOSED.load(Ordering::SeqCst));
            assert_eq!(quota.used.load(Ordering::SeqCst), baseline + bytes);
            drop(store);
            drop(alias);
        },
    )
    .unwrap();

    WATCH_REFUND.store(false, Ordering::SeqCst);
    assert_eq!(outcome, CloseMarkerOutcome::Published);
    assert!(!EARLY_REFUND.load(Ordering::SeqCst));
    assert_eq!(quota.used.load(Ordering::SeqCst), 0);
}

#[test]
fn admitted_metadata_refusal_precedes_terminal_control_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let (store, quota) = controlled_store(directory.path(), 4096);
    let baseline = quota.used.load(Ordering::SeqCst);
    let (result, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(resource_layout(), || {
            store.reserve_root_metadata(1)
        });
    let error = result.unwrap_err();

    assert!(matches!(error, RamStoreError::Store(StoreError::Quota)));
    assert!(identity.is_none());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert_eq!(quota.used.load(Ordering::SeqCst), baseline);
    assert_eq!(
        quota.last_request.load(Ordering::SeqCst),
        crate::ram::metadata::allocation_bytes(1).unwrap()
    );
    assert!(crate::ram::metadata::allocation_bytes(u64::MAX).is_err());
}

#[test]
fn transferred_admitted_metadata_retains_origin_financial_credit_after_source_close() {
    if sqlite_process::isolated() {
        return;
    }
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let (source_store, source_quota) =
        admitted_store(source_directory.path(), RamStoreLimits::default());
    let (destination_store, destination_quota) =
        admitted_store(destination_directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let captured = source_store
        .capture(
            topology(8193),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&source_store),
            &mut || Ok(()),
        )
        .unwrap();
    let source = source_store
        .open_with_metadata_resources(
            retention.retain_root(captured.object_id()).unwrap(),
            &fixture_original(&source_store),
            &mut || Ok(()),
        )
        .unwrap();
    drop(captured);
    let alias = source.clone();
    let source_bytes = source_quota.0.usage().unwrap().1;
    assert!(source_bytes >= crate::ram::metadata::allocation_bytes(1).unwrap());
    assert!(source.metadata_resources.as_ref().is_some());
    let transferred = source_store
        .transfer_to(
            &source,
            &destination_store,
            &Retention::default(),
            &fixture_original(&source_store),
            &fixture_original(&destination_store),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(Arc::ptr_eq(&source.record, &transferred.root().record));
    assert!(Arc::ptr_eq(&source.regions, &transferred.root().regions));
    drop(source);
    drop(source_store);
    drop(alias);

    assert_eq!(
        source_quota.0.usage().unwrap().1,
        crate::ram::metadata::allocation_bytes(1).unwrap()
    );
    destination_store
        .verify(
            transferred.root(),
            &fixture_original(&destination_store),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(transferred.root().record().scope(), Scope::Exact);
    drop(transferred);
    assert_eq!(source_quota.0.usage().unwrap(), (0, 0));
    drop(destination_store);
    assert_eq!(destination_quota.0.usage().unwrap(), (0, 0));
}
