//! Exercises durable root reconciliation and pre-ACK uncertainty containment.

use std::{
    cell::Cell,
    sync::atomic::{AtomicBool, Ordering},
};

use crucible_cas::content_store::{
    BackendCapabilities, ByteRange, DirectoryBlobBackend, DirectoryRefBackend, PutReceipt,
    RefBackendCapabilities, RefPublicationGuard, RefScanPage,
};

use super::*;

// Test failures retain the original typed error instead of a panic or erased error.
#[derive(Debug, thiserror::Error)]
enum PublicationTestError {
    #[error(transparent)]
    Contract(crucible_node_contract::ContractError),
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    Runtime(RuntimeError),
    #[error(transparent)]
    Io(std::io::Error),
}

fn original() -> Result<RetainedRecord, PublicationTestError> {
    let bytes = b"original complete public result bodies".to_vec();
    Ok(RetainedRecord {
        operation: Id::new("original/window/0").map_err(PublicationTestError::Contract)?,
        reference: RefName::new("node-world-coordinators/conformance/original-window-0")
            .map_err(PublicationTestError::Store)?,
        id: ContentId::for_bytes(ObjectKind::Trace, 1, &bytes),
        bytes,
    })
}

#[test]
fn complete_directory_readback_reconciles_the_same_root() -> Result<(), PublicationTestError> {
    let directory = tempfile::tempdir().map_err(PublicationTestError::Io)?;
    let blobs = DirectoryBlobBackend::new("original-results", directory.path().join("blobs"));
    let refs = DirectoryRefBackend::new(directory.path().join("refs"));
    let record = original()?;

    assert_eq!(
        store_record(&blobs, &refs, &record, &|| Ok(())).map_err(PublicationTestError::Runtime)?,
        PublicationStatus::Committed,
    );
    assert_eq!(
        store_record(&blobs, &refs, &record, &|| Ok(())).map_err(PublicationTestError::Runtime)?,
        PublicationStatus::Committed,
    );
    assert_eq!(
        refs.read_ref(&record.reference)
            .map_err(PublicationTestError::Store)?,
        Some(record.id)
    );
    assert_eq!(
        blobs
            .read(record.id, None)
            .map_err(PublicationTestError::Store)?
            .read_all(1024)
            .map_err(PublicationTestError::Store)?,
        record.bytes,
    );
    Ok(())
}

struct UncertainRefs {
    inner: DirectoryRefBackend,
    armed: AtomicBool,
}

impl MutableRefBackend for UncertainRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.inner.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.inner.acquire_publication_guard()
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.inner.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let actual = self.inner.compare_exchange(name, expected, next)?;
        if self.armed.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Incompatible);
        }
        Ok(actual)
    }
}

#[test]
fn uncertain_actual_cas_retains_and_reconciles_the_original_record()
-> Result<(), PublicationTestError> {
    let directory = tempfile::tempdir().map_err(PublicationTestError::Io)?;
    let blobs = DirectoryBlobBackend::new("original-results", directory.path().join("blobs"));
    let refs = UncertainRefs {
        inner: DirectoryRefBackend::new(directory.path().join("refs")),
        armed: AtomicBool::new(true),
    };
    let record = original()?;

    assert_eq!(
        store_record(&blobs, &refs, &record, &|| Ok(())).map_err(PublicationTestError::Runtime)?,
        PublicationStatus::Unknown,
    );
    assert_eq!(
        refs.read_ref(&record.reference)
            .map_err(PublicationTestError::Store)?,
        Some(record.id)
    );
    assert!(record.id.authenticates(&record.bytes));
    assert_eq!(
        store_record(&blobs, &refs, &record, &|| Ok(())).map_err(PublicationTestError::Runtime)?,
        PublicationStatus::Committed,
    );
    Ok(())
}

struct UncertainBlobs {
    inner: DirectoryBlobBackend,
    armed: AtomicBool,
}

impl ImmutableBlobBackend for UncertainBlobs {
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
        let receipt = self.inner.put_if_absent(id, source)?;
        if self.armed.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Incompatible);
        }
        Ok(receipt)
    }
}

#[test]
fn uncertain_immutable_put_keeps_original_bytes_without_advancing_the_root()
-> Result<(), PublicationTestError> {
    let directory = tempfile::tempdir().map_err(PublicationTestError::Io)?;
    let blobs = UncertainBlobs {
        inner: DirectoryBlobBackend::new("original-results", directory.path().join("blobs")),
        armed: AtomicBool::new(true),
    };
    let refs = DirectoryRefBackend::new(directory.path().join("refs"));
    let record = original()?;

    assert_eq!(
        store_record(&blobs, &refs, &record, &|| Ok(())).map_err(PublicationTestError::Runtime)?,
        PublicationStatus::Unknown,
    );
    assert_eq!(
        refs.read_ref(&record.reference)
            .map_err(PublicationTestError::Store)?,
        None
    );
    assert_eq!(
        blobs
            .read(record.id, None)
            .map_err(PublicationTestError::Store)?
            .read_all(1024)
            .map_err(PublicationTestError::Store)?,
        record.bytes,
    );

    assert_eq!(
        store_record(&blobs, &refs, &record, &|| Ok(())).map_err(PublicationTestError::Runtime)?,
        PublicationStatus::Committed,
    );
    assert_eq!(
        refs.read_ref(&record.reference)
            .map_err(PublicationTestError::Store)?,
        Some(record.id)
    );
    Ok(())
}

#[test]
fn late_scope_withdrawal_after_actual_cas_never_returns_committed()
-> Result<(), PublicationTestError> {
    let directory = tempfile::tempdir().map_err(PublicationTestError::Io)?;
    let blobs = DirectoryBlobBackend::new("original-results", directory.path().join("blobs"));
    let refs = DirectoryRefBackend::new(directory.path().join("refs"));
    let record = original()?;
    let calls = Cell::new(0);
    let current = || {
        calls.set(calls.get() + 1);
        if calls.get() >= 4 {
            Err(RuntimeError::ForeignAuthority)
        } else {
            Ok(())
        }
    };

    assert_eq!(
        store_record(&blobs, &refs, &record, &current),
        Err(RuntimeError::ForeignAuthority),
    );
    assert_eq!(
        refs.read_ref(&record.reference)
            .map_err(PublicationTestError::Store)?,
        Some(record.id)
    );
    assert_eq!(
        blobs
            .read(record.id, None)
            .map_err(PublicationTestError::Store)?
            .read_all(1024)
            .map_err(PublicationTestError::Store)?,
        record.bytes,
    );
    Ok(())
}

#[test]
fn a_foreign_existing_root_is_not_replaced() -> Result<(), PublicationTestError> {
    let directory = tempfile::tempdir().map_err(PublicationTestError::Io)?;
    let blobs = DirectoryBlobBackend::new("original-results", directory.path().join("blobs"));
    let refs = DirectoryRefBackend::new(directory.path().join("refs"));
    let record = original()?;
    let foreign = ContentId::for_bytes(ObjectKind::Trace, 1, b"different original");
    refs.compare_exchange(&record.reference, None, foreign)
        .map_err(PublicationTestError::Store)?;

    assert_eq!(
        store_record(&blobs, &refs, &record, &|| Ok(())).map_err(PublicationTestError::Runtime)?,
        PublicationStatus::NotCommitted,
    );
    assert_eq!(
        refs.read_ref(&record.reference)
            .map_err(PublicationTestError::Store)?,
        Some(foreign)
    );
    Ok(())
}
