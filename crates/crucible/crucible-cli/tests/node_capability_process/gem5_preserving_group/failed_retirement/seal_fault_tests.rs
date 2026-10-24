//! Checks bounded immutable fault custody without a native process or permit.

use super::*;
use crucible_store::content_store::DirectoryBlobBackend;
use std::sync::mpsc;

struct BlockedPlacement {
    inner: Arc<dyn ImmutableBlobBackend>,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ImmutableBlobBackend for BlockedPlacement {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.entered
            .send(())
            .map_err(|_| StoreError::Incompatible)?;
        self.release
            .lock()
            .map_err(|_| StoreError::Incompatible)?
            .recv()
            .map_err(|_| StoreError::Incompatible)?;
        self.inner.put_if_absent(id, source)
    }
}

fn seal(request: ContentId, diagnostic: &str) -> BlobHandle {
    BlobHandle::from_bytes(
        canonical::canonical_json(&json!({
            "body": {
                "format": "crucible.capability-failed-retirement",
                "version": 1,
                "request": request.encode(),
                "diagnostic": diagnostic
            },
            "authentication": "synthetic data, no native release authority"
        }))
        .unwrap(),
    )
}

fn identity(body: &BlobHandle) -> ContentId {
    ContentId::for_bytes(ObjectKind::Trace, 1, &body.read_all(SEAL_BYTES).unwrap())
}

#[test]
fn original_placed_body_stays_fixed_until_same_byte_storage_reconciliation() {
    let directory = tempfile::tempdir().unwrap();
    let inner = Arc::new(DirectoryBlobBackend::new("seal-model", directory.path()));
    let backend = SealPlacement::new(inner.clone());
    let request = ContentId::for_bytes(ObjectKind::Trace, 1, b"original model request");
    backend.bind(request).unwrap();
    let body = seal(request, "original");
    let original = body.read_all(SEAL_BYTES).unwrap();
    let identity = identity(&body);

    assert!(backend.put_if_absent(identity, &body).is_err());
    assert!(inner.contains(identity).unwrap());
    assert_eq!(backend.original(), (identity, original.clone()));
    assert_eq!(backend.attempts(), 1);
    assert_eq!(backend.completed_placements(), 1);
    assert!(backend.put_if_absent(identity, &body).is_err());
    assert_eq!(backend.attempts(), 2);

    backend.release_storage_fault();
    assert!(backend.put_if_absent(identity, &body).unwrap().is_durable());
    assert_eq!(backend.original(), (identity, original));
    assert_eq!(backend.attempts(), 3);
    assert_eq!(backend.completed_placements(), 3);
}

#[test]
fn changed_seal_and_second_request_binding_cannot_replace_original_custody() {
    let directory = tempfile::tempdir().unwrap();
    let inner = Arc::new(DirectoryBlobBackend::new("seal-model", directory.path()));
    let backend = SealPlacement::new(inner.clone());
    let request = ContentId::for_bytes(ObjectKind::Trace, 1, b"original model request");
    backend.bind(request).unwrap();
    let first = seal(request, "original");
    let original = first.read_all(SEAL_BYTES).unwrap();
    let first_id = identity(&first);
    assert!(backend.put_if_absent(first_id, &first).is_err());

    let changed = seal(request, "different");
    let changed_id = identity(&changed);
    assert!(backend.bind(request).is_err());
    assert!(backend.put_if_absent(changed_id, &changed).is_err());
    assert!(!inner.contains(changed_id).unwrap());
    assert_eq!(backend.original(), (first_id, original.clone()));
    assert_eq!(backend.attempts(), 1);

    backend.release_storage_fault();
    assert!(backend.put_if_absent(changed_id, &changed).is_err());
    assert_eq!(backend.original(), (first_id, original));
    assert!(
        backend
            .put_if_absent(first_id, &first)
            .unwrap()
            .is_durable()
    );
}

#[test]
fn foreign_request_and_large_source_bypass_only_the_selected_fault_holder() {
    let directory = tempfile::tempdir().unwrap();
    let inner = Arc::new(DirectoryBlobBackend::new("seal-model", directory.path()));
    let backend = SealPlacement::new(inner.clone());
    let request = ContentId::for_bytes(ObjectKind::Trace, 1, b"original model request");
    backend.bind(request).unwrap();
    let foreign = seal(
        ContentId::for_bytes(ObjectKind::Trace, 1, b"foreign request"),
        "unselected",
    );
    let foreign_id = identity(&foreign);
    assert!(
        backend
            .put_if_absent(foreign_id, &foreign)
            .unwrap()
            .is_durable()
    );

    let bytes = vec![0x37; SEAL_BYTES as usize + 1];
    let large_id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let large = BlobHandle::from_bytes(bytes);
    assert!(
        backend
            .put_if_absent(large_id, &large)
            .unwrap()
            .is_durable()
    );
    assert_eq!(backend.attempts(), 0);
    let held = backend.original.lock().unwrap();
    assert!(held.identity.is_none());
    assert_eq!(held.bytes.len(), 0);
    assert!(held.bytes.capacity() >= SEAL_BYTES as usize);
}

#[test]
fn callback_entry_cannot_publish_durable_placement_readiness() {
    let directory = tempfile::tempdir().unwrap();
    let inner = Arc::new(DirectoryBlobBackend::new("seal-model", directory.path()));
    let (entered, observed_entry) = mpsc::sync_channel(1);
    let (release, wait_release) = mpsc::sync_channel(1);
    let blocked = Arc::new(BlockedPlacement {
        inner: inner.clone(),
        entered,
        release: Mutex::new(wait_release),
    });
    let backend = Arc::new(SealPlacement::new(blocked));
    let request = ContentId::for_bytes(ObjectKind::Trace, 1, b"original model request");
    backend.bind(request).unwrap();
    let body = seal(request, "original");
    let id = identity(&body);
    let worker_backend = backend.clone();
    let worker = std::thread::spawn(move || worker_backend.put_if_absent(id, &body));

    // The real callback is blocked before its immutable placement. The entry
    // diagnostic cannot let another thread read a body that does not yet exist.
    observed_entry.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(backend.attempts(), 1);
    assert_eq!(backend.completed_placements(), 0);
    assert!(!inner.contains(id).unwrap());
    release.send(()).unwrap();
    assert!(worker.join().unwrap().is_err());

    assert!(inner.contains(id).unwrap());
    assert_eq!(backend.completed_placements(), 1);
    let (held_id, held_bytes) = backend.original();
    assert_eq!(held_id, id);
    assert_eq!(
        inner.read(id, None).unwrap().read_all(SEAL_BYTES).unwrap(),
        held_bytes
    );
}
