//! Injects one request-bound failure after real immutable placement.
//!
//! The preallocated holder keeps the first complete signed seal and rejects any
//! changed reconciliation body. Releasing this storage fault grants no native
//! authority; the owning daemon must still authenticate its original supervisor.

use super::*;
use crucible_store::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, ObjectKind,
    PutReceipt, StoreError,
};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

/// Matches the existing signed failed-retirement record ceiling.
pub(super) const SEAL_BYTES: u64 = 128 * 1024;

struct OriginalSeal {
    request: Option<ContentId>,
    identity: Option<ContentId>,
    bytes: Vec<u8>,
}

/// Retains one complete original seal while injecting a storage-only refusal.
pub(super) struct SealPlacement {
    /// Performs real immutable placement before the selected return is refused.
    pub(super) inner: Arc<dyn ImmutableBlobBackend>,
    original: Mutex<OriginalSeal>,
    released: AtomicBool,
    attempts: AtomicUsize,
    completed_placements: AtomicUsize,
}

impl SealPlacement {
    /// Reserves the complete fault holder before any service or native effects.
    pub(super) fn new(inner: Arc<dyn ImmutableBlobBackend>) -> Self {
        Self {
            inner,
            original: Mutex::new(OriginalSeal {
                request: None,
                identity: None,
                bytes: Vec::with_capacity(SEAL_BYTES as usize),
            }),
            released: AtomicBool::new(false),
            attempts: AtomicUsize::new(0),
            completed_placements: AtomicUsize::new(0),
        }
    }

    /// Binds storage selection to the complete original request CAS identity.
    ///
    /// # Errors
    /// Refuses a poisoned holder or a second binding, including the same request.
    pub(super) fn bind(&self, request: ContentId) -> Result<(), StoreError> {
        let mut original = self.original.lock().map_err(|_| StoreError::Incompatible)?;
        if original.request.is_some() {
            return Err(StoreError::Incompatible);
        }
        original.request = Some(request);
        Ok(())
    }

    /// Counts actual same-body placement attempts, excluding rejected replacements.
    pub(super) fn attempts(&self) -> usize {
        self.attempts.load(Ordering::Acquire)
    }

    /// Counts completed durable inner placements, not callback entry.
    pub(super) fn completed_placements(&self) -> usize {
        self.completed_placements.load(Ordering::Acquire)
    }

    /// Returns bounded data for comparisons; it creates no release permit.
    ///
    /// # Panics
    /// Panics if the holder is poisoned or no actual selected placement occurred.
    pub(super) fn original(&self) -> (ContentId, Vec<u8>) {
        let original = self.original.lock().unwrap();
        (original.identity.unwrap(), original.bytes.clone())
    }

    /// Removes only the fixed storage refusal; native release remains conjunctive.
    pub(super) fn release_storage_fault(&self) {
        self.released.store(true, Ordering::Release);
    }
}

impl ImmutableBlobBackend for SealPlacement {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, identity: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(identity)
    }

    fn read(
        &self,
        identity: ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        self.inner.read(identity, range)
    }

    fn put_if_absent(
        &self,
        identity: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        // Large source/native objects bypass the test parser without copying.
        // The actual signed failure interface has its own unchanged 128 KiB cap.
        if source.logical_length() > SEAL_BYTES {
            return self.inner.put_if_absent(identity, source);
        }
        let request = self
            .original
            .lock()
            .map_err(|_| StoreError::Incompatible)?
            .request;
        let Some(request) = request else {
            return self.inner.put_if_absent(identity, source);
        };
        let bytes = source.read_all(SEAL_BYTES)?;
        let Ok(value) = canonical::parse_json(&bytes, SEAL_BYTES as usize) else {
            return self.inner.put_if_absent(identity, source);
        };
        let body = &value["body"];
        if body["format"] != "crucible.capability-failed-retirement"
            || body["version"] != 1
            || body["request"] != request.encode()
        {
            return self.inner.put_if_absent(identity, source);
        }
        if identity.kind() != ObjectKind::Trace
            || identity.schema_version() != 1
            || !identity.authenticates(&bytes)
        {
            return Err(StoreError::Incompatible);
        }

        // Keep the original outside the placement callback. Changed bytes never
        // replace the first capsule obligation, even after fault release.
        let mut original = self.original.lock().map_err(|_| StoreError::Incompatible)?;
        if let Some(first) = original.identity {
            if first != identity || original.bytes != bytes {
                return Err(StoreError::Incompatible);
            }
        } else {
            original.bytes.extend_from_slice(&bytes);
            original.identity = Some(identity);
        }
        drop(original);
        self.attempts.fetch_add(1, Ordering::AcqRel);

        // The underlying durable blob placement really happens. Its refused
        // return must not release the original worker or publish the seal root.
        let placed = self.inner.put_if_absent(identity, source)?;
        if placed.id != identity || !placed.is_durable() {
            return Err(StoreError::Incompatible);
        }
        let stored = self.inner.read(identity, None)?;
        if stored.logical_length() != bytes.len() as u64 || stored.read_all(SEAL_BYTES)? != bytes {
            return Err(StoreError::Incompatible);
        }
        self.completed_placements.fetch_add(1, Ordering::AcqRel);
        if self.released.load(Ordering::Acquire) {
            Ok(placed)
        } else {
            Err(StoreError::Incompatible)
        }
    }
}

#[path = "seal_fault_tests.rs"]
mod tests;
