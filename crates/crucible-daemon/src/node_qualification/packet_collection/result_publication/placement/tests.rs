//! Exercises original closure placement against actual durable Directory stores.
//!
//! Fault wrappers affect storage replies/readbacks only. They do not install a
//! packet source, native permission, accepted qualification or collecting world.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Storage assertions preserve the exact original body/current-root oracle; no native permission is installed.
#![allow(clippy::unwrap_used)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, DirectoryBlobBackend,
    DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, ObjectKind, PutReceipt,
    RefBackendCapabilities, RefCasOutcome, RefName, RefPublicationGuard, RefScanPage, StoreError,
};

use super::{PreparedPacketPlacement, PublicationStatus, RuntimeError};

struct Faults {
    refs: Arc<DirectoryRefBackend>,
    reference: RefName,
    current: AtomicBool,
    lose_put: AtomicBool,
    lose_cas: AtomicBool,
    revoke_capabilities: AtomicBool,
    missing_body: AtomicBool,
    wrong_body: AtomicBool,
    change_root_at_read: AtomicUsize,
    puts: AtomicUsize,
    reads: AtomicUsize,
    exchanges: AtomicUsize,
}

impl Faults {
    fn current(&self) -> Result<(), RuntimeError> {
        if self.current.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(RuntimeError::ForeignAuthority)
        }
    }
}

struct Blobs {
    inner: DirectoryBlobBackend,
    faults: Arc<Faults>,
}

impl ImmutableBlobBackend for Blobs {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        let capabilities = self.inner.capabilities();
        if self.faults.revoke_capabilities.load(Ordering::SeqCst) {
            self.faults.current.store(false, Ordering::SeqCst);
        }
        capabilities
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let ordinal = self.faults.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if self.faults.change_root_at_read.load(Ordering::SeqCst) == ordinal {
            let old = self.faults.refs.read_ref(&self.faults.reference)?;
            let foreign = ContentId::for_bytes(ObjectKind::Trace, 1, b"foreign-result-root");
            self.faults
                .refs
                .compare_exchange(&self.faults.reference, old, foreign)?;
        }
        if self.faults.missing_body.load(Ordering::SeqCst) {
            return Err(StoreError::NotFound { id });
        }
        if self.faults.wrong_body.load(Ordering::SeqCst) {
            return Ok(BlobHandle::from_bytes(b"different-original-body".to_vec()));
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.faults.puts.fetch_add(1, Ordering::SeqCst);
        let receipt = self.inner.put_if_absent(id, source)?;
        if self.faults.lose_put.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Incompatible);
        }
        Ok(receipt)
    }
}

struct Refs(Arc<Faults>);

impl MutableRefBackend for Refs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.0.refs.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.0.refs.acquire_publication_guard()
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.0.refs.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.0.refs.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        self.0.exchanges.fetch_add(1, Ordering::SeqCst);
        let result = self.0.refs.compare_exchange(name, expected, next)?;
        if self.0.lose_cas.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Incompatible);
        }
        Ok(result)
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    faults: Arc<Faults>,
    blobs: Arc<Blobs>,
    refs: Arc<Refs>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let actual_refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
        let faults = Arc::new(Faults {
            refs: actual_refs,
            reference: RefName::new("node-packet-collecting-results/original").unwrap(),
            current: AtomicBool::new(true),
            lose_put: AtomicBool::new(false),
            lose_cas: AtomicBool::new(false),
            revoke_capabilities: AtomicBool::new(false),
            missing_body: AtomicBool::new(false),
            wrong_body: AtomicBool::new(false),
            change_root_at_read: AtomicUsize::new(0),
            puts: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            exchanges: AtomicUsize::new(0),
        });
        let blobs = Arc::new(Blobs {
            inner: DirectoryBlobBackend::new(
                "original-packet-result",
                directory.path().join("blobs"),
            ),
            faults: faults.clone(),
        });
        Self {
            _directory: directory,
            faults: faults.clone(),
            blobs,
            refs: Arc::new(Refs(faults)),
        }
    }

    fn prepare(&self, maximum: usize) -> Result<PreparedPacketPlacement, RuntimeError> {
        PreparedPacketPlacement::prepare(
            self.blobs.clone(),
            self.refs.clone(),
            self.faults.reference.clone(),
            [
                b"plan".to_vec(),
                b"refused-audit".to_vec(),
                b"original-report".to_vec(),
                b"original-root".to_vec(),
            ],
            maximum,
        )
    }
}

#[test]
fn exact_whole_closure_credit_precedes_handle_copies() {
    let fixture = Fixture::new();
    let extent =
        b"plan".len() + b"refused-audit".len() + b"original-report".len() + b"original-root".len();

    assert!(fixture.prepare(extent * 4).is_ok());
    assert!(matches!(
        fixture.prepare(extent * 4 - 1),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(fixture.faults.puts.load(Ordering::SeqCst), 0);
    assert!(
        fixture
            .refs
            .read_ref(&fixture.faults.reference)
            .unwrap()
            .is_none()
    );
}

#[test]
fn lost_original_put_and_cas_replies_reconcile_exact_closure() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare(4096).unwrap();
    fixture.faults.lose_put.store(true, Ordering::SeqCst);
    fixture.faults.lose_cas.store(true, Ordering::SeqCst);

    assert_eq!(
        prepared.publish(|| fixture.faults.current()).unwrap(),
        PublicationStatus::Committed
    );
    assert_eq!(
        prepared.reconcile(|| fixture.faults.current()).unwrap(),
        PublicationStatus::Committed
    );
    assert_eq!(fixture.faults.puts.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.faults.exchanges.load(Ordering::SeqCst), 1);
}

#[test]
fn metadata_callback_revocation_prevents_any_placement() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare(4096).unwrap();
    fixture
        .faults
        .revoke_capabilities
        .store(true, Ordering::SeqCst);

    assert!(matches!(
        prepared.publish(|| fixture.faults.current()),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert_eq!(fixture.faults.puts.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.faults.exchanges.load(Ordering::SeqCst), 0);
    assert!(
        fixture
            .refs
            .read_ref(&fixture.faults.reference)
            .unwrap()
            .is_none()
    );
}

#[test]
fn root_changed_during_body_readback_is_not_historical_committed() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare(4096).unwrap();
    // Four original Put readbacks precede the first post-CAS closure body.
    fixture
        .faults
        .change_root_at_read
        .store(5, Ordering::SeqCst);

    assert_eq!(
        prepared.publish(|| fixture.faults.current()).unwrap(),
        PublicationStatus::NotCommitted
    );
    assert_eq!(fixture.faults.exchanges.load(Ordering::SeqCst), 1);
}

#[test]
fn missing_or_changed_original_body_refuses_current_commitment() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare(4096).unwrap();
    assert_eq!(
        prepared.publish(|| fixture.faults.current()).unwrap(),
        PublicationStatus::Committed
    );

    fixture.faults.missing_body.store(true, Ordering::SeqCst);
    assert_eq!(
        prepared.reconcile(|| fixture.faults.current()).unwrap(),
        PublicationStatus::Unknown
    );
    fixture.faults.missing_body.store(false, Ordering::SeqCst);
    fixture.faults.wrong_body.store(true, Ordering::SeqCst);
    assert_eq!(
        prepared.reconcile(|| fixture.faults.current()).unwrap(),
        PublicationStatus::Unknown
    );
    fixture.faults.wrong_body.store(false, Ordering::SeqCst);
    assert_eq!(
        prepared.reconcile(|| fixture.faults.current()).unwrap(),
        PublicationStatus::Committed
    );
    assert_eq!(fixture.faults.puts.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.faults.exchanges.load(Ordering::SeqCst), 1);
}
