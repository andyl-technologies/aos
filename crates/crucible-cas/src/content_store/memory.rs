//! In-memory immutable-blob and mutable-ref store leaves.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::*;

/// Bounded process-local logical-object store used by tests and hot caches.
#[derive(Debug)]
pub struct MemoryBlobBackend {
    name: String,
    max_logical_bytes: u64,
    state: Mutex<MemoryBlobState>,
}

#[derive(Debug, Default)]
struct MemoryBlobState {
    objects: BTreeMap<ContentId, Vec<u8>>,
    logical_bytes: u64,
}

impl MemoryBlobBackend {
    /// Creates an empty non-durable memory backend with a hard logical-byte cap.
    #[must_use]
    pub fn new(name: impl Into<String>, max_logical_bytes: u64) -> Self {
        Self {
            name: name.into(),
            max_logical_bytes,
            state: Mutex::new(MemoryBlobState::default()),
        }
    }

    /// Returns the number of unique logical objects.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Poisoned`] after a panic while holding the map.
    pub fn object_count(&self) -> Result<usize, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-object-count",
        })?;
        Ok(state.objects.len())
    }

    /// Returns the authenticated logical bytes currently retained.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Poisoned`] after a panic while holding the map.
    pub fn logical_bytes(&self) -> Result<u64, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-logical-bytes",
        })?;
        Ok(state.logical_bytes)
    }
}

impl ImmutableBlobBackend for MemoryBlobBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: false,
            range_read: true,
            conditional_create: true,
            streaming_put: false,
            repair_inventory: false,
            planned_delete: false,
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-contains",
        })?;
        let Some(bytes) = state.objects.get(&id) else {
            return Ok(false);
        };
        validate_bytes(id, bytes)?;
        Ok(true)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-read",
        })?;
        let bytes = state
            .objects
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound { id })?;
        validate_bytes(id, &bytes)?;
        slice_range(bytes, range)
    }

    fn put_if_absent(&self, id: ContentId, bytes: &[u8]) -> Result<PutReceipt, StoreError> {
        validate_bytes(id, bytes)?;
        let mut state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-put",
        })?;
        if let Some(existing) = state.objects.get(&id) {
            validate_bytes(id, existing)?;
        } else {
            let logical_length = u64::try_from(bytes.len()).map_err(|_| StoreError::Quota)?;
            let next_logical_bytes = state
                .logical_bytes
                .checked_add(logical_length)
                .ok_or(StoreError::Quota)?;
            if next_logical_bytes > self.max_logical_bytes {
                return Err(StoreError::Quota);
            }
            state.objects.insert(id, bytes.to_vec());
            state.logical_bytes = next_logical_bytes;
        }
        Ok(PutReceipt::one(
            id,
            PlacementReceipt {
                backend: self.name.clone(),
                durable: false,
                logical_length: bytes.len() as u64,
            },
        ))
    }
}

/// Process-local authoritative ref backend used by model tests.
#[derive(Debug)]
pub struct MemoryRefBackend {
    refs: Mutex<BTreeMap<RefName, ContentId>>,
}

impl MemoryRefBackend {
    /// Creates an empty mutable-ref backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            refs: Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for MemoryRefBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MutableRefBackend for MemoryRefBackend {
    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let refs = self.refs.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-read-ref",
        })?;
        Ok(refs.get(name).copied())
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let mut refs = self.refs.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-cas-ref",
        })?;
        let current = refs.get(name).copied();
        if current != expected {
            return Ok(RefCasOutcome::Conflict { expected, current });
        }
        refs.insert(name.clone(), next);
        Ok(RefCasOutcome::Advanced { next })
    }
}
