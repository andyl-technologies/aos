//! Checked receiver batching, durable prefixes and cancellation disposition.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crucible_protocol::ram_transfer::{RamTransferControl, RamTransferMessage};

struct BatchBackend {
    backend: Arc<dyn ImmutableBlobBackend>,
    sizes: Mutex<[usize; 192]>,
    calls: AtomicUsize,
    committed: AtomicBool,
    reading: AtomicBool,
    fail_call: usize,
    _credit: crate::owned_decode::DecodeScratch,
}

impl BatchBackend {
    fn wrap(
        store: RamStore,
        original: &crate::owned_decode::DecodeBudget,
        fail_call: usize,
    ) -> (RamStore, Arc<Self>) {
        let (layout, _) = std::alloc::Layout::new::<[usize; 2]>()
            .extend(std::alloc::Layout::new::<Self>())
            .unwrap();
        let credit = original
            .reserve_scratch_bytes(layout.pad_to_align().size() as u64)
            .unwrap();
        let backend = Arc::new(Self {
            backend: store.backend,
            sizes: Mutex::new([0; 192]),
            calls: AtomicUsize::new(0),
            committed: AtomicBool::new(false),
            reading: AtomicBool::new(false),
            fail_call,
            _credit: credit,
        });
        let store = RamStore::new(backend.clone(), store.durability, store.limits).unwrap();
        (store, backend)
    }

    fn sizes(&self) -> Vec<usize> {
        self.sizes.lock().unwrap()[..self.calls.load(Ordering::SeqCst)].to_vec()
    }
}

impl ImmutableBlobBackend for BatchBackend {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities()
    }

    fn metadata_resources(
        &self,
    ) -> Result<Arc<dyn crate::content_store::StorePhysicalQuotaGuard>, StoreError> {
        self.backend.metadata_resources()
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.backend.admit_object_graph(objects)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.backend.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.backend.read(id, range)
    }

    fn read_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        self.reading.store(true, Ordering::SeqCst);
        let result = self
            .backend
            .read_with_boundary(original, id, range, boundary);
        self.reading.store(false, Ordering::SeqCst);
        result
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.backend.put_if_absent(id, source)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crate::content_store::PutBatchReceipt, StoreError> {
        fixture_boundary(original, boundary)?;
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.sizes.lock().unwrap()[call - 1] = objects.len();
        if call == self.fail_call {
            return Err(StoreError::StreamIo {
                operation: "receiver batch publication fixture",
                source: std::io::Error::from_raw_os_error(28),
            });
        }
        let receipt = self
            .backend
            .put_many_if_absent_with_boundary(original, objects, boundary)?;
        self.committed.store(true, Ordering::SeqCst);
        Ok(receipt)
    }
}

fn sender(
    source: &RamStore,
    root: &LeasedRamRoot,
    original: &crate::owned_decode::DecodeBudget,
) -> RamTransferSender {
    let offer = archive_offer(root, 4096);
    RamTransferSender::new(
        source.clone(),
        root.clone(),
        [81; 32],
        ContentId::parse(&offer.whole_world_root).unwrap(),
        &offer.destination,
        offer.durable_placements,
        offer.limits,
        original,
    )
    .unwrap()
}

#[test]
fn receiver_commits_bounded_groups_and_only_then_the_singleton_root() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let source_original = fixture_original(&source);
    let destination_original = fixture_original(&destination);
    let root = source
        .capture(
            topology(64 * 4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    let (destination, batches) = BatchBackend::wrap(destination, &destination_original, 0);
    let mut sender = sender(&source, &root, &source_original);
    let offered = super::super::response::decode_local(
        &sender.offer().unwrap(),
        &source_original,
        &destination_original,
    )
    .unwrap();
    let retention = Retention::default();
    let mut receiver = RamTransferReceiver::new(destination.clone(), &retention, offered).unwrap();
    let mut acknowledgments = 0;

    let result = receiver
        .receive(
            &mut |message| {
                if matches!(message.control, RamTransferControl::ClosureStored { .. }) {
                    acknowledgments += 1;
                    assert_eq!(batches.sizes(), [64, 64, 63, 1]);
                    assert!(destination.backend.contains(root.object_id()).unwrap());
                }
                sender.respond(message, &mut || Ok(()))
            },
            &destination_original,
            &mut || Ok(()),
        )
        .unwrap();

    let RamTransferStep::ClosureStored(stored) = result else {
        panic!("complete durable closure");
    };
    assert_eq!(acknowledgments, 1);
    assert_eq!(stored.report().copied_objects, 192);
    assert_eq!(stored.report().authenticated_existing_objects, 0);
    assert_eq!(
        destination
            .verify(stored.root(), &destination_original, &mut || Ok(()))
            .unwrap()
            .pages,
        64
    );
}

#[test]
fn receiver_pending_duplicate_is_durable_before_existing_read_and_not_requested_twice() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let source_original = fixture_original(&source);
    let destination_original = fixture_original(&destination);
    let root = source
        .capture(
            topology(8192),
            Scope::Exact,
            &mut |_, _, bytes| {
                bytes.fill(7);
                Ok(())
            },
            &Retention::default(),
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    let (destination, batches) = BatchBackend::wrap(destination, &destination_original, 0);
    let mut sender = sender(&source, &root, &source_original);
    let offered = super::super::response::decode_local(
        &sender.offer().unwrap(),
        &source_original,
        &destination_original,
    )
    .unwrap();
    let retention = Retention::default();
    let mut receiver = RamTransferReceiver::new(destination, &retention, offered).unwrap();
    let mut page_requests = 0;

    let result = receiver
        .receive(
            &mut |message| {
                if matches!(message.control, RamTransferControl::WantObject { .. }) {
                    page_requests += 1;
                }
                sender.respond(message, &mut || Ok(()))
            },
            &destination_original,
            &mut || Ok(()),
        )
        .unwrap();

    let RamTransferStep::ClosureStored(stored) = result else {
        panic!("complete repeated-page closure");
    };
    assert_eq!(page_requests, 1);
    assert_eq!(batches.sizes(), [3, 2, 1]);
    assert_eq!(stored.report().copied_objects, 4);
    assert_eq!(stored.report().authenticated_existing_objects, 2);
}

#[test]
fn failed_second_group_keeps_durable_prefix_and_exact_storage_cause_without_root_or_ack() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let source_original = fixture_original(&source);
    let destination_original = fixture_original(&destination);
    let root = source
        .capture(
            topology(64 * 4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    let (destination, batches) = BatchBackend::wrap(destination, &destination_original, 2);
    let mut sender = sender(&source, &root, &source_original);
    let offered = super::super::response::decode_local(
        &sender.offer().unwrap(),
        &source_original,
        &destination_original,
    )
    .unwrap();
    let retention = Retention::default();
    let mut receiver = RamTransferReceiver::new(destination.clone(), &retention, offered).unwrap();
    let mut acknowledgments = 0;
    let mut cancellations = 0;

    let error = receiver
        .receive(
            &mut |message| {
                match message.control {
                    RamTransferControl::ClosureStored { .. } => acknowledgments += 1,
                    RamTransferControl::Cancel => cancellations += 1,
                    _ => {}
                }
                sender.respond(message, &mut || Ok(()))
            },
            &destination_original,
            &mut || Ok(()),
        )
        .unwrap_err();

    let RamStoreError::Store(storage) = error else {
        panic!("exact checked storage failure");
    };
    let StoreError::StreamIo { source, .. } = storage.original_failure() else {
        panic!("original storage errno");
    };
    assert_eq!(source.raw_os_error(), Some(28));
    assert_eq!(batches.sizes(), [64, 64]);
    assert!(batches.committed.load(Ordering::SeqCst));
    assert_eq!(acknowledgments, 0);
    assert_eq!(cancellations, 1);
    assert!(!destination.backend.contains(root.object_id()).unwrap());
    assert!(destination.backend.contains(root.regions[0].id).unwrap());
    let retained = retention.objects.lock().unwrap();
    assert_eq!(
        retained
            .iter()
            .filter(|id| destination.backend.contains(**id).unwrap())
            .count(),
        64
    );
}

#[test]
fn committed_batch_readback_preserves_cancellation_and_durable_prefix_without_root_or_ack() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let source_original = fixture_original(&source);
    let destination_original = fixture_original(&destination);
    let root = source
        .capture(
            topology(64 * 4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    let (destination, batches) = BatchBackend::wrap(destination, &destination_original, 0);
    let mut sender = sender(&source, &root, &source_original);
    let offered = super::super::response::decode_local(
        &sender.offer().unwrap(),
        &source_original,
        &destination_original,
    )
    .unwrap();
    let retention = Retention::default();
    let mut receiver = RamTransferReceiver::new(destination.clone(), &retention, offered).unwrap();
    let mut acknowledgments = 0;
    let mut cancellations = 0;

    let error = receiver
        .receive(
            &mut |message| {
                match message.control {
                    RamTransferControl::ClosureStored { .. } => acknowledgments += 1,
                    RamTransferControl::Cancel => cancellations += 1,
                    _ => {}
                }
                sender.respond(message, &mut || Ok(()))
            },
            &destination_original,
            &mut || {
                if batches.committed.load(Ordering::SeqCst)
                    && batches.reading.load(Ordering::SeqCst)
                {
                    Err(RamStoreError::Canceled)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

    let RamStoreError::Store(storage) = error else {
        panic!("exact checked storage failure");
    };
    let StoreError::SqliteScope { source: scope } = storage else {
        panic!("actual committed publication retains its refusal: {storage:?}");
    };
    let Some(StoreError::RamReadBoundary { source: first }) = scope.work_failure() else {
        panic!("committed readback retains the first callback: {scope:?}");
    };
    assert!(matches!(
        first.first_boundary(),
        Some(RamStoreError::Canceled)
    ));
    assert!(matches!(
        first.storage_failure(),
        RamStoreError::Store(StoreError::RamBoundary { .. })
    ));
    assert_eq!(
        scope.outcome(),
        crate::content_store::SqliteCommitOutcome::Committed
    );
    assert!(scope.rollback_failure().is_none());
    assert!(scope.restoration_failure().is_none());
    assert!(scope.blob_close_failure().is_none());
    assert!(scope.metadata_completion_failure().is_none());
    assert!(scope.metadata_finalization_failure().is_none());
    assert_eq!(batches.sizes(), [64]);
    assert!(batches.committed.load(Ordering::SeqCst));
    assert_eq!(acknowledgments, 0);
    assert_eq!(cancellations, 1);
    assert!(!destination.backend.contains(root.object_id()).unwrap());
    assert!(destination.backend.contains(root.regions[0].id).unwrap());
    let retained = retention.objects.lock().unwrap();
    assert_eq!(
        retained
            .iter()
            .filter(|id| destination.backend.contains(**id).unwrap())
            .count(),
        64
    );
}

#[test]
fn cancellation_disposes_pending_credits_before_peer_cancel() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let (destination, quota) =
        admitted_store(destination_directory.path(), RamStoreLimits::default());
    let source_original = fixture_original(&source);
    let destination_original = fixture_original(&destination);
    let root = source
        .capture(
            topology(128),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    let mut sender = sender(&source, &root, &source_original);
    let offered = super::super::response::decode_local(
        &sender.offer().unwrap(),
        &source_original,
        &destination_original,
    )
    .unwrap();
    let retention = Retention::default();
    let mut receiver = RamTransferReceiver::new(destination.clone(), &retention, offered).unwrap();
    let baseline = quota.0.usage().unwrap().1;
    let slots = PreparedRamFailure::<RamStoreError>::allocation_bytes().unwrap()
        + PreparedRamFailure::<std::convert::Infallible>::allocation_bytes().unwrap();
    let mut cancellations = 0;

    let error = receiver
        .receive(
            &mut |message: RamTransferMessage| {
                match message.control {
                    RamTransferControl::WantObject { .. } => return Err(RamStoreError::Canceled),
                    RamTransferControl::Cancel => {
                        cancellations += 1;
                        assert_eq!(
                            quota.0.usage().unwrap().1,
                            baseline + slots,
                            "only existing Work refusal slots remain, not a pending batch"
                        );
                        assert!(!destination.backend.contains(root.regions[0].id).unwrap());
                        assert!(!destination.backend.contains(root.object_id()).unwrap());
                    }
                    RamTransferControl::ClosureStored { .. } => {
                        panic!("canceled closure cannot acknowledge storage")
                    }
                    _ => {}
                }
                sender.respond(message, &mut || Ok(()))
            },
            &destination_original,
            &mut || Ok(()),
        )
        .unwrap_err();

    assert!(matches!(error, RamStoreError::Canceled));
    assert_eq!(cancellations, 1);
    assert_eq!(quota.0.usage().unwrap().1, baseline);
}
