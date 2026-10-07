//! Original-bank observations for completed RAM object codec lifetimes.
//!
//! These use a durable directory and explicit finite component resources. They
//! measure loan lifetime, without certifying kernel quotas or guest execution.

use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{
    BlobStoreAdmin, DirectoryBlobBackend, MemoryBlobBackend, StorePhysicalQuotaGuard,
};
use crate::owned_decode::DecodeBudget;

use super::*;

mod checked_sources;
mod hash_reuse;
mod record_prepay;

const METADATA_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("original component authority was revoked")]
struct RevokedOriginalAuthority;

struct ObservedQuota {
    resources: FixtureResourceBudget,
    limit: u64,
    peak: AtomicU64,
    reservations: AtomicU64,
    verifications: AtomicU64,
    revoke_after_verifications: AtomicU64,
    revoked: std::sync::atomic::AtomicBool,
    refusal: Mutex<Option<(u64, u64)>>,
}

impl ObservedQuota {
    fn new() -> Arc<Self> {
        Self::with_limit(METADATA_BYTES)
    }

    fn with_limit(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            resources: FixtureResourceBudget::new(128, limit),
            limit,
            peak: AtomicU64::new(0),
            reservations: AtomicU64::new(0),
            verifications: AtomicU64::new(0),
            revoke_after_verifications: AtomicU64::new(0),
            revoked: std::sync::atomic::AtomicBool::new(false),
            refusal: Mutex::new(None),
        })
    }

    fn used(&self) -> u64 {
        self.resources.usage().unwrap().1
    }
}

impl StorePhysicalQuotaGuard for ObservedQuota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(self.limit)
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        if self.revoke_after_verifications.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |remaining| remaining.checked_sub(1),
        ) == Ok(1)
        {
            self.revoked.store(true, Ordering::SeqCst);
        }
        if self.revoked.load(Ordering::SeqCst) {
            return Err(StoreError::Supervision {
                source: Box::new(RevokedOriginalAuthority),
            });
        }
        Ok(())
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        self.reservations.fetch_add(1, Ordering::SeqCst);
        let result = self.resources.reserve(descriptors, bytes);
        let used = self.used();
        self.peak.fetch_max(used, Ordering::SeqCst);
        if result.is_err() {
            *self.refusal.lock().unwrap() = Some((used, bytes));
        }
        result
    }
}

fn directory_store(path: &std::path::Path, quota: &Arc<ObservedQuota>) -> RamStore {
    let backend =
        DirectoryBlobBackend::new_with_physical_quota("codec-lifetime", path, quota.clone())
            .unwrap();
    RamStore::new(
        backend,
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap()
}

fn contains_original_quota(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if matches!(error.downcast_ref::<StoreError>(), Some(StoreError::Quota)) {
            return true;
        }
        if matches!(
            error.downcast_ref::<RamStoreError>(),
            Some(RamStoreError::Store(StoreError::Quota))
        ) {
            return true;
        }
        current = error.source();
    }
    false
}

fn page_object(store: &RamStore) -> ContentId {
    let retention = Retention::default();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &mut boundary);
    store.put_page(&[7; 4096], &retention, &mut work).unwrap().0
}

#[test]
fn completed_page_reads_accumulate_in_the_original_long_lived_account() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let page = page_object(&store);
    let baseline = quota.used();
    let budget = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = budget.enter();
    let mut completed = 0;
    let error = loop {
        // One attacker-controlled decode retains its monotone contract. This
        // explicitly exercises the baseline codec rather than RAM's completed
        // per-object boundary, whose child custody now closes independently.
        let decoded = (|| -> Result<_, RamStoreError> {
            let source = store.backend.read(page, None)?;
            let bytes = source.read_all(8192)?;
            Ok(ContentEnvelope::from_canonical_bytes_with_child_limit(
                &bytes, 0,
            )?)
        })();
        match decoded {
            Ok(envelope) => {
                assert_eq!(envelope.body().len(), 4132);
                drop(envelope);
                completed += 1;
                assert!(completed < 1000, "finite original bank must refuse");
            }
            Err(error) => break error,
        }
    };

    assert!(completed > 100);
    assert!(contains_original_quota(&error), "{error:?}");
    let (used, requested) = quota.refusal.lock().unwrap().unwrap();
    assert!(used + requested > METADATA_BYTES);
    assert!(used > 3 * 1024 * 1024);
    assert!(quota.used() > baseline + 3 * 1024 * 1024);

    // crucible-lint: allow direct-diagnostic -- this component repro reports original finite-bank observations, without claiming native qualification.
    eprintln!(
        "completed_reads={completed} used_at_refusal={used} requested={requested} original_limit={METADATA_BYTES} retained_after_error={}",
        quota.used()
    );

    drop(error);
    drop(scope);
    drop(budget);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn completed_child_codec_accounts_reuse_only_the_same_original_bank() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let page = page_object(&store);
    let baseline = quota.used();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let parent_used = quota.used();

    for _ in 0..500 {
        let child = parent.child().unwrap();
        let scope = child.enter();
        let mut boundary = || Ok(());
        let mut work = Work::new(store.limits, &mut boundary);
        let envelope = store.read_envelope(page, &mut work).unwrap();
        assert_eq!(envelope.body().len(), 4132);
        drop(envelope);
        drop(scope);
        drop(child);
        assert_eq!(quota.used(), parent_used);
    }
    assert!(quota.peak.load(Ordering::SeqCst) < 512 * 1024);
    // crucible-lint: allow direct-diagnostic -- this component repro reports the original bank's observed codec peak.
    eprintln!(
        "child_completed_reads=500 peak={} original_limit={METADATA_BYTES}",
        quota.peak.load(Ordering::SeqCst)
    );

    // Simultaneously live decoded owners cannot mint more capacity by creating
    // fresh children. Their bodies and original account custody stay paired.
    let mut retained = Vec::new();
    let error = loop {
        let child = parent.child().unwrap();
        let scope = child.enter();
        let mut boundary = || Ok(());
        let mut work = Work::new(store.limits, &mut boundary);
        match store.read_envelope(page, &mut work) {
            Ok(envelope) => retained.push((envelope, child.custody())),
            Err(error) => break error,
        }
        drop(scope);
        drop(child);
        assert!(retained.len() < 1000);
    };
    assert!(
        retained.len() >= 449,
        "original retained-owner capacity regressed"
    );
    assert!(contains_original_quota(&error), "{error:?}");
    assert!(quota.used() > parent_used + 3 * 1024 * 1024);
    let (used, requested) = quota.refusal.lock().unwrap().unwrap();
    assert!(used + requested > METADATA_BYTES);
    // crucible-lint: allow direct-diagnostic -- this component repro reports actual simultaneously retained owners and the original bank refusal.
    eprintln!(
        "live_decoded_owners={} used_at_refusal={used} requested={requested} original_limit={METADATA_BYTES}",
        retained.len()
    );
    drop(error);
    drop(retained);
    assert_eq!(quota.used(), parent_used);
    drop(parent);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn capture_and_verification_release_completed_object_codec_credits() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let baseline = quota.used();
    let budget = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = budget.enter();
    let mut pages = 0;
    let reservation_start = quota.reservations.load(Ordering::SeqCst);
    let verification_start = quota.verifications.load(Ordering::SeqCst);
    let result = store.capture(
        topology(256 * 4096),
        Scope::Exact,
        &mut |_, index, bytes| {
            pages += 1;
            bytes.fill(0);
            bytes[..8].copy_from_slice(&index.to_be_bytes());
            Ok(())
        },
        &Retention::default(),
        &mut || Ok(()),
    );
    let root = result.unwrap();
    assert_eq!(pages, 256);
    let capture_reservations = quota.reservations.load(Ordering::SeqCst) - reservation_start;
    let capture_verifications = quota.verifications.load(Ordering::SeqCst) - verification_start;
    let reservation_start = quota.reservations.load(Ordering::SeqCst);
    let verification_start = quota.verifications.load(Ordering::SeqCst);
    let verified = store.verify(&root, &mut || Ok(())).unwrap();
    assert_eq!(verified.pages, 256);
    assert_eq!(verified.logical_bytes, 256 * 4096);
    assert!(quota.refusal.lock().unwrap().is_none());
    // The unchanged original implementation's observed peak is the ceiling;
    // additional sharing and batch-control credits cannot consume more bank.
    assert!(quota.peak.load(Ordering::SeqCst) <= 819_663);
    let reference = crucible_ram::oracle::recompute(
        &topology(256 * 4096),
        Scope::Exact,
        256,
        |_, index, bytes| {
            bytes.fill(0);
            bytes[..8].copy_from_slice(&index.to_be_bytes());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(root.record().digest(), reference);
    assert!(quota.used() < baseline + 64 * 1024);

    // crucible-lint: allow direct-diagnostic -- this component reports real bounded-bank capture/verification counters, without a scale qualification claim.
    eprintln!(
        "capture_pages={pages} verification_pages={} peak={} original_limit={METADATA_BYTES} capture_reservations={capture_reservations} capture_verifications={capture_verifications} read_reservations={} read_verifications={}",
        verified.pages,
        quota.peak.load(Ordering::SeqCst),
        quota.reservations.load(Ordering::SeqCst) - reservation_start,
        quota.verifications.load(Ordering::SeqCst) - verification_start,
    );
    drop(root);
    drop(scope);
    drop(budget);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn memory_cache_deletion_retains_original_copy_credits_through_last_reader() {
    let quota = ObservedQuota::new();
    let cache = MemoryBlobBackend::new("retained-cache", 1024 * 1024);
    let bytes = vec![5; 4096];
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
    let source = BlobHandle::from_bytes(bytes);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    cache.put_if_absent(id, &source).unwrap();
    let retained_copy = quota.used();
    cache.put_if_absent(id, &source).unwrap();
    assert_eq!(quota.used(), retained_copy);

    // A simultaneous original-bank borrower may refuse a new reader. Closing
    // that borrower does not reset the immutable body's monotone copy ledger.
    let competing = quota
        .resources
        .reserve(0, METADATA_BYTES - quota.used())
        .unwrap();
    let refused = cache.read(id, None).err().unwrap();
    assert!(contains_original_quota(&refused));
    drop(refused);
    drop(competing);

    let handle = cache.read(id, None).unwrap();
    let clone = handle.clone();
    let mut reader = clone.open().unwrap();
    let second_reader = handle.open().unwrap();
    drop(scope);
    drop(parent);
    let retained_readers = quota.used();
    assert!(retained_readers > 4096);
    let mut fence = cache.acquire_inventory_fence().unwrap();
    assert!(matches!(
        fence.delete_candidate(id).unwrap(),
        crate::content_store::PlannedDeleteDisposition::Deleted
    ));
    drop(fence);
    assert_eq!(cache.object_count().unwrap(), 0);
    assert_eq!(quota.used(), retained_readers);
    drop(handle);
    drop(clone);
    drop(second_reader);
    assert!(quota.used() > 4096);

    let mut observed = [0; 4096];
    reader.read_exact(&mut observed).unwrap();
    assert_eq!(observed, [5; 4096]);
    drop(reader);
    assert_eq!(quota.used(), 0);

    // An empty but live cache retains no old map node. Its next insertion
    // acquires a new original-bank copy and node loan before publication.
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    cache.put_if_absent(id, &source).unwrap();
    assert!(quota.used() > 4096);
    drop(scope);
    drop(parent);
    assert!(quota.used() > 4096);
    let mut fence = cache.acquire_inventory_fence().unwrap();
    fence.delete_candidate(id).unwrap();
    drop(fence);
    assert_eq!(quota.used(), 0);
    drop(cache);
}

#[test]
fn memory_copy_refusal_preserves_the_map_and_generation() {
    let quota = ObservedQuota::new();
    let cache = MemoryBlobBackend::new("finite-cache", 8 * 1024 * 1024);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let mut completed = 0;
    let (error, basis_before_refusal) = loop {
        let mut bytes = vec![0; 4096];
        bytes[..8].copy_from_slice(&(completed as u64).to_be_bytes());
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
        let source = BlobHandle::from_bytes(bytes);
        let basis = cache
            .acquire_inventory_fence()
            .unwrap()
            .visit_inventory(&mut |_| Ok(()))
            .unwrap();
        match cache.put_if_absent(id, &source) {
            Ok(_) => completed += 1,
            Err(error) => break (error, basis),
        }
        assert!(completed < 1000);
    };
    assert!(completed > 100);
    assert!(contains_original_quota(&error));
    assert_eq!(cache.object_count().unwrap(), completed);
    assert_eq!(cache.logical_bytes().unwrap(), (completed * 4096) as u64);
    let mut fence = cache.acquire_inventory_fence().unwrap();
    let summary = fence.visit_inventory(&mut |_| Ok(())).unwrap();
    assert_eq!(summary, basis_before_refusal);
    drop(fence);
    drop(error);
    drop(cache);
    let parent_used = quota.used();
    assert!(parent_used < 4096);
    drop(scope);
    drop(parent);
    assert_eq!(quota.used(), 0);
}

#[test]
fn encoded_publication_source_keeps_its_loan_through_the_last_open_reader() {
    let quota = ObservedQuota::new();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let child = parent.child().unwrap();
    let scope = child.enter();
    child.charge_array::<u8>(4096).unwrap();
    let source =
        crate::ram::codec_ownership::encoded_source(vec![9; 4096], &child, &child).unwrap();
    let clone = source.clone();
    let mut reader = clone.open().unwrap();
    drop(scope);
    drop(child);
    drop(parent);
    drop(source);
    drop(clone);
    assert!(quota.used() > 4096);
    let mut bytes = [0; 4096];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [9; 4096]);
    drop(reader);
    assert_eq!(quota.used(), 0);
}

#[test]
fn capture_cancellation_discards_only_transient_batch_custody() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let before = quota.used();
    let mut pages = 0;
    let error = store
        .capture(
            topology(256 * 4096),
            Scope::Exact,
            &mut |_, index, bytes| {
                if pages == 70 {
                    return Err(RamStoreError::Canceled);
                }
                pages += 1;
                bytes.fill(0);
                bytes[..8].copy_from_slice(&index.to_be_bytes());
                Ok(())
            },
            &Retention::default(),
            &mut || Ok(()),
        )
        .unwrap_err();
    assert!(matches!(error, RamStoreError::Canceled));
    assert_eq!(pages, 70);
    assert_eq!(quota.used(), before);
    assert!(parent.check().is_ok());
    drop(scope);
    drop(parent);
}

#[test]
fn transfer_object_clones_share_final_canonical_byte_custody() {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let scope = parent.enter();
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &mut || Ok(()),
        )
        .unwrap();
    let object = store
        .read_transfer_object(
            &root,
            &RamObjectCoordinate::Page {
                region_id: "main".into(),
                page_index: 0,
            },
            &mut || Ok(()),
        )
        .unwrap();
    let clone = object.clone();
    assert!(std::ptr::eq(
        object.canonical_bytes().as_ptr(),
        clone.canonical_bytes().as_ptr()
    ));
    let id = object.id();
    drop(object);
    drop(root);
    drop(scope);
    drop(parent);
    drop(store);
    assert!(quota.used() > 4096);
    assert!(id.authenticates(clone.canonical_bytes()));
    drop(clone);
    assert_eq!(quota.used(), 0);
}

#[test]
fn receiver_refuses_an_oversized_page_before_assembly_allocation() {
    use crucible_protocol::ram_transfer::{RamTransferControl, RamTransferMessage};

    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = source
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let mut sender = RamTransferSender::new(
        source,
        root.clone(),
        [11; 32],
        archive_offer(&root, 64 * 1024),
    )
    .unwrap();
    let mut receiver =
        RamTransferReceiver::new(destination.clone(), &retention, sender.offer()).unwrap();
    let mut altered = false;
    let mut exchange = |message: RamTransferMessage| {
        let mut response = sender.respond(message, &mut || Ok(()))?;
        if let RamTransferControl::ObjectChunk {
            object,
            length,
            last,
            ..
        } = &mut response.control
            && object.starts_with("ram-extent.1.")
        {
            *length = 8193;
            *last = false;
            altered = true;
            // The generic portable chunk remains valid; only the bounded
            // physical page contract refuses the declared assembly length.
            response.encode().unwrap();
        }
        Ok(response)
    };

    let error = receiver.receive(&mut exchange, &mut || Ok(())).unwrap_err();
    assert!(altered);
    assert!(matches!(
        error,
        RamStoreError::Invalid("transfer chunk identity or order")
    ));
    assert!(!destination.backend.contains(root.object_id()).unwrap());
}

#[test]
fn receiver_multichunk_scratch_reuses_the_original_bank_after_refusal() {
    use crucible_protocol::ram_transfer::{RamTransferControl, RamTransferMessage};

    const RECEIVER_METADATA_BYTES: u64 = 64 * 1024 * 1024;
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let quota = ObservedQuota::with_limit(RECEIVER_METADATA_BYTES);
    let destination = directory_store(destination_directory.path(), &quota);
    let baseline = quota.used();
    let retention = Retention::default();
    let root = source
        .capture(
            topology(32 * 4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();

    for refuse in [true, false] {
        let mut sender = RamTransferSender::new(
            source.clone(),
            root.clone(),
            [12; 32],
            archive_offer(&root, 17),
        )
        .unwrap();
        let mut receiver =
            RamTransferReceiver::new(destination.clone(), &retention, sender.offer()).unwrap();
        let budget = DecodeBudget::for_store(quota.clone()).unwrap();
        let scope = budget.enter();
        let mut competing = None;
        let mut chunks = 0;
        let mut exchange = |message: RamTransferMessage| {
            let response = sender.respond(message, &mut || Ok(()))?;
            if matches!(response.control, RamTransferControl::ObjectChunk { .. }) {
                chunks += 1;
                if refuse && competing.is_none() {
                    competing = Some(
                        quota
                            .resources
                            .reserve(0, RECEIVER_METADATA_BYTES - quota.used())
                            .unwrap(),
                    );
                }
            }
            Ok(response)
        };
        let result = receiver.receive(&mut exchange, &mut || Ok(()));
        drop(competing);
        if refuse {
            let error = result.unwrap_err();
            assert!(contains_original_quota(&error), "{error:?}");
            assert!(!destination.backend.contains(root.object_id()).unwrap());
        } else {
            let RamTransferStep::ClosureStored(stored) = result.unwrap() else {
                panic!("expected complete stored closure")
            };
            assert!(chunks > 8192, "one small credit per actual wire chunk");
            assert_eq!(stored.root().logical_digest(), root.logical_digest());
            assert_eq!(quota.limit, RECEIVER_METADATA_BYTES);
            destination.verify(stored.root(), &mut || Ok(())).unwrap();
            drop(stored);
        }
        budget.check().unwrap();
        drop(scope);
        drop(budget);
        drop(receiver);
        drop(sender);
        assert_eq!(quota.used(), baseline);
    }
}
