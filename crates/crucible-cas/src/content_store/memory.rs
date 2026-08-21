//! In-memory immutable-blob and mutable-ref store leaves.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::admin::{
    InventoryCounter, persistent_inventory_generation, persistent_ref_inventory_generation,
};
use super::*;

static MEMORY_INVENTORY_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);
static MEMORY_REF_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Bounded process-local logical-object store used by tests and hot caches.
#[derive(Debug)]
pub struct MemoryBlobBackend {
    name: String,
    max_logical_bytes: u64,
    inventory_instance: [u8; 32],
    state: Mutex<MemoryBlobState>,
}

#[derive(Debug)]
struct MemoryBlobState {
    objects: BTreeMap<ContentId, Arc<[u8]>>,
    logical_bytes: u64,
    generation: u64,
}

impl MemoryBlobBackend {
    /// Creates an empty non-durable memory backend with a hard logical-byte cap.
    #[must_use]
    pub fn new(name: impl Into<String>, max_logical_bytes: u64) -> Self {
        let name = name.into();
        Self {
            inventory_instance: new_memory_inventory_instance(&name),
            name,
            max_logical_bytes,
            state: Mutex::new(MemoryBlobState {
                objects: BTreeMap::new(),
                logical_bytes: 0,
                generation: 1,
            }),
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
            deferred_write: false,
            range_read: true,
            streaming_read: true,
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

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-read",
        })?;
        let bytes = state
            .objects
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound { id })?;
        validate_bytes(id, &bytes)?;
        BlobHandle::from_authenticated_bytes(id, bytes).slice(range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let logical_length = source.logical_length();
        if logical_length > self.max_logical_bytes {
            source.verified_as(id)?;
            return Err(StoreError::Quota);
        }
        let bytes = match read_handle_all(source, self.max_logical_bytes) {
            Err(StoreError::InvalidSourceLength { .. }) => return Err(StoreError::Corrupt { id }),
            result => result?,
        };
        validate_bytes(id, &bytes)?;
        let mut state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-put",
        })?;
        if let Some(existing) = state.objects.get(&id) {
            validate_bytes(id, existing)?;
        } else {
            let next_logical_bytes = state
                .logical_bytes
                .checked_add(logical_length)
                .ok_or(StoreError::Quota)?;
            if next_logical_bytes > self.max_logical_bytes {
                return Err(StoreError::Quota);
            }
            state.generation = state.generation.checked_add(1).ok_or(StoreError::Quota)?;
            state.objects.insert(id, Arc::from(bytes));
            state.logical_bytes = next_logical_bytes;
        }
        Ok(PutReceipt::one(
            id,
            PlacementReceipt {
                backend: self.name.clone(),
                durable: false,
                logical_length,
            },
        ))
    }
}

impl BlobStoreAdmin for MemoryBlobBackend {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-inventory-fence",
        })?;
        Ok(Box::new(MemoryBlobInventoryFence {
            backend: &self.name,
            instance: self.inventory_instance,
            state,
        }))
    }
}

struct MemoryBlobInventoryFence<'a> {
    backend: &'a str,
    instance: [u8; 32],
    state: MutexGuard<'a, MemoryBlobState>,
}

impl BlobInventoryFence for MemoryBlobInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let generation =
            persistent_inventory_generation(self.backend, self.instance, self.state.generation)?;
        let mut inventory = InventoryCounter::new(generation);
        for (id, bytes) in &self.state.objects {
            let logical_length = u64::try_from(bytes.len()).map_err(|_| StoreError::Quota)?;
            let record = BlobInventoryRecord::new(*id, logical_length);
            inventory.push(record)?;
            visitor(record)?;
        }
        Ok(inventory.finish(self.backend.to_owned()))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        if !self.state.objects.contains_key(&id) {
            return Ok(PlannedDeleteDisposition::AlreadyAbsent);
        }
        let next_generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(StoreError::Quota)?;
        let bytes = self.state.objects.remove(&id).ok_or(StoreError::Poisoned {
            operation: "memory-delete-candidate",
        })?;
        let logical_length = u64::try_from(bytes.len()).map_err(|_| StoreError::Quota)?;
        self.state.logical_bytes =
            self.state
                .logical_bytes
                .checked_sub(logical_length)
                .ok_or(StoreError::Poisoned {
                    operation: "memory-delete-accounting",
                })?;
        self.state.generation = next_generation;
        Ok(PlannedDeleteDisposition::Deleted)
    }
}

fn new_memory_inventory_instance(name: &str) -> [u8; 32] {
    let ordinal = MEMORY_INVENTORY_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.content-store.memory-inventory-instance.v1");
    hasher.update(name.as_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&ordinal.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Process-local authoritative ref backend used by model tests.
#[derive(Debug)]
pub struct MemoryRefBackend {
    inventory_instance: [u8; 32],
    publication: RwLock<()>,
    state: Mutex<MemoryRefState>,
}

#[derive(Debug)]
struct MemoryRefState {
    refs: BTreeMap<RefName, ContentId>,
    generation: u64,
}

impl MemoryRefBackend {
    /// Creates an empty mutable-ref backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inventory_instance: new_memory_ref_instance(),
            publication: RwLock::new(()),
            state: Mutex::new(MemoryRefState {
                refs: BTreeMap::new(),
                generation: 1,
            }),
        }
    }
}

impl Default for MemoryRefBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MutableRefBackend for MemoryRefBackend {
    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        let guard = self.publication.read().map_err(|_| StoreError::Poisoned {
            operation: "memory-ref-publication-guard",
        })?;
        Ok(Box::new(MemoryRefPublicationGuard { _guard: guard }))
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-read-ref",
        })?;
        Ok(state.refs.get(name).copied())
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-cas-ref",
        })?;
        let current = state.refs.get(name).copied();
        if current != expected {
            return Ok(RefCasOutcome::Conflict { expected, current });
        }
        state.generation = state.generation.checked_add(1).ok_or(StoreError::Quota)?;
        state.refs.insert(name.clone(), next);
        Ok(RefCasOutcome::Advanced { next })
    }
}

impl RefStoreAdmin for MemoryRefBackend {
    fn acquire_ref_inventory_fence(&self) -> Result<Box<dyn RefInventoryFence + '_>, StoreError> {
        let publication = self.publication.write().map_err(|_| StoreError::Poisoned {
            operation: "memory-ref-publication-fence",
        })?;
        let state = self.state.lock().map_err(|_| StoreError::Poisoned {
            operation: "memory-ref-inventory-fence",
        })?;
        Ok(Box::new(MemoryRefInventoryFence {
            instance: self.inventory_instance,
            _publication: publication,
            state,
        }))
    }
}

struct MemoryRefPublicationGuard<'a> {
    _guard: RwLockReadGuard<'a, ()>,
}

impl RefPublicationGuard for MemoryRefPublicationGuard<'_> {}

struct MemoryRefInventoryFence<'a> {
    instance: [u8; 32],
    _publication: RwLockWriteGuard<'a, ()>,
    state: MutexGuard<'a, MemoryRefState>,
}

impl RefInventoryFence for MemoryRefInventoryFence<'_> {
    fn visit_refs(
        &mut self,
        visitor: &mut dyn FnMut(RefInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<RefInventorySummary, StoreError> {
        let generation = persistent_ref_inventory_generation(self.instance, self.state.generation);
        let mut refs = 0_u64;
        for (name, target) in &self.state.refs {
            refs = refs.checked_add(1).ok_or(StoreError::Quota)?;
            visitor(RefInventoryRecord::new(name.clone(), *target))?;
        }
        Ok(RefInventorySummary::from_parts(generation, refs))
    }
}

fn new_memory_ref_instance() -> [u8; 32] {
    let ordinal = MEMORY_REF_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.content-store.memory-ref-inventory-instance.v1");
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&ordinal.to_le_bytes());
    *hasher.finalize().as_bytes()
}
