//! Exclusive physical-inventory fences for generation-bound administration.
//!
//! Blob inventory/deletion and ref-namespace inventory are deliberately absent
//! from [`ImmutableBlobBackend`] and [`MutableRefBackend`]. Campaign
//! repositories receive only normal object/ref authority; a daemon maintenance
//! owner must be given separate [`BlobStoreAdmin`] and [`RefStoreAdmin`]
//! capabilities before it can inspect placement, enumerate every authoritative
//! name, or remove a planned candidate.

use super::*;

/// Exact digest of one stable physical blob inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InventoryGeneration([u8; 32]);

impl InventoryGeneration {
    /// Builds a backend generation from exactly 32 canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw generation digest.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Renders the generation as canonical lowercase hexadecimal text.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

/// One logical object observed in a fenced physical inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobInventoryRecord {
    id: ContentId,
    logical_length: u64,
}

impl BlobInventoryRecord {
    pub(crate) const fn new(id: ContentId, logical_length: u64) -> Self {
        Self { id, logical_length }
    }

    /// Returns the exact logical object identity represented by the placement.
    #[must_use]
    pub const fn id(self) -> ContentId {
        self.id
    }

    /// Returns the logical object's authenticated byte length.
    #[must_use]
    pub const fn logical_length(self) -> u64 {
        self.logical_length
    }
}

/// Terminal evidence that one fenced physical inventory completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobInventorySummary {
    backend: String,
    generation: InventoryGeneration,
    objects: u64,
    logical_bytes: u64,
}

impl BlobInventorySummary {
    pub(crate) fn new(
        backend: String,
        generation: InventoryGeneration,
        objects: u64,
        logical_bytes: u64,
    ) -> Self {
        Self {
            backend,
            generation,
            objects,
            logical_bytes,
        }
    }

    /// Returns the exact backend instance name bound into the generation.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Returns the terminal physical-inventory generation.
    #[must_use]
    pub const fn generation(&self) -> InventoryGeneration {
        self.generation
    }

    /// Returns the number of logical objects visited.
    #[must_use]
    pub const fn objects(&self) -> u64 {
        self.objects
    }

    /// Returns the checked sum of authenticated logical-object byte lengths.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
}

/// Outcome of removing one exact candidate while an inventory fence is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlannedDeleteDisposition {
    /// The exact logical candidate was removed durably from the inventory.
    Deleted,
    /// The exact placement was already absent during an idempotent retry.
    AlreadyAbsent,
}

/// Exclusive physical-inventory authority held across validation and deletion.
///
/// Normal conditional puts into the same cooperating backend must block while
/// this fence exists. Inventory visitors may observe a prefix on error and must
/// discard it unless [`BlobInventoryFence::visit_inventory`] returns a terminal
/// summary. Removing a candidate remains an administrative primitive: callers
/// must first validate a complete immutable GC plan and every external root-set
/// fence required by that plan. A visitor must not call back into the fenced
/// backend; the exclusive fence is intentionally non-reentrant.
pub trait BlobInventoryFence {
    /// Streams every exact logical-object placement while fenced.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when enumeration is incomplete, physical
    /// placement metadata is malformed or unsupported, or terminal counters
    /// overflow.
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError>;

    /// Removes one exact plan-approved logical-object candidate.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the placement cannot be inspected, removed,
    /// or made durable. A packed backend may retain shared physical pack bytes
    /// until its final logical entry is removed or a later repack reclaims the
    /// sparse pack. This primitive does not decide reachability.
    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError>;
}

/// Separate administrative capability for a physical blob backend.
pub trait BlobStoreAdmin: Send + Sync {
    /// Acquires exclusive inventory/delete authority for this backend.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot establish the exact
    /// physical fence required to exclude cooperating conditional puts.
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError>;
}

/// Exact digest of one stable authoritative-reference inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefInventoryGeneration([u8; 32]);

impl RefInventoryGeneration {
    /// Builds a ref-namespace generation from exactly 32 canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw generation digest.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Renders the generation as canonical lowercase hexadecimal text.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

/// One exact authoritative name binding observed while fenced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefInventoryRecord {
    name: RefName,
    target: ContentId,
}

impl RefInventoryRecord {
    pub(crate) const fn new(name: RefName, target: ContentId) -> Self {
        Self { name, target }
    }

    /// Returns the canonical authoritative name.
    #[must_use]
    pub const fn name(&self) -> &RefName {
        &self.name
    }

    /// Returns the exact content identity named by the ref.
    #[must_use]
    pub const fn target(&self) -> ContentId {
        self.target
    }
}

/// Terminal evidence that one fenced ref inventory completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefInventorySummary {
    generation: RefInventoryGeneration,
    refs: u64,
}

impl RefInventorySummary {
    /// Builds terminal counters for one completed backend ref inventory.
    #[must_use]
    pub const fn from_parts(generation: RefInventoryGeneration, refs: u64) -> Self {
        Self { generation, refs }
    }

    /// Returns the exact authoritative-namespace generation.
    #[must_use]
    pub const fn generation(self) -> RefInventoryGeneration {
        self.generation
    }

    /// Returns the number of authoritative bindings visited.
    #[must_use]
    pub const fn refs(self) -> u64 {
        self.refs
    }
}

/// Exclusive authority over one cooperating mutable-ref namespace.
///
/// Normal reads and conditional replacements in the same backend block while
/// this fence exists. Visitor output is tentative until terminal success. The
/// visitor must not reenter the fenced backend.
pub trait RefInventoryFence {
    /// Streams every exact authoritative name binding while fenced.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when enumeration is incomplete, a ref name or
    /// value is malformed, the visitor fails, or terminal counters overflow.
    fn visit_refs(
        &mut self,
        visitor: &mut dyn FnMut(RefInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<RefInventorySummary, StoreError>;
}

/// Shared lifetime guard for one children-before-ref publication transaction.
///
/// A repository acquires this guard before its first immutable child write and
/// retains it through the authoritative ref comparison. Ref inventory acquires
/// the exclusive side of the same backend lifecycle lock. That ordering keeps
/// a GC apply from deleting newly written children while their publishing
/// transaction is waiting to make the ref authoritative.
pub trait RefPublicationGuard {}

/// Separate administrative capability for an authoritative ref backend.
pub trait RefStoreAdmin: Send + Sync {
    /// Acquires exclusive inventory authority for the complete namespace.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the backend cannot exclude cooperating ref
    /// reads and conditional replacements or load its persistent generation.
    fn acquire_ref_inventory_fence(&self) -> Result<Box<dyn RefInventoryFence + '_>, StoreError>;
}

pub(crate) struct InventoryCounter {
    generation: InventoryGeneration,
    objects: u64,
    logical_bytes: u64,
}

impl InventoryCounter {
    pub(crate) const fn new(generation: InventoryGeneration) -> Self {
        Self {
            generation,
            objects: 0,
            logical_bytes: 0,
        }
    }

    pub(crate) fn push(&mut self, record: BlobInventoryRecord) -> Result<(), StoreError> {
        self.objects = self.objects.checked_add(1).ok_or(StoreError::Quota)?;
        self.logical_bytes = self
            .logical_bytes
            .checked_add(record.logical_length)
            .ok_or(StoreError::Quota)?;
        Ok(())
    }

    pub(crate) fn finish(self, backend: String) -> BlobInventorySummary {
        BlobInventorySummary::new(backend, self.generation, self.objects, self.logical_bytes)
    }
}

pub(crate) fn persistent_inventory_generation(
    backend: &str,
    instance: [u8; 32],
    generation: u64,
) -> Result<InventoryGeneration, StoreError> {
    let backend_length = u64::try_from(backend.len()).map_err(|_| StoreError::Quota)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.content-store.persistent-inventory-generation.v1");
    hasher.update(&backend_length.to_le_bytes());
    hasher.update(backend.as_bytes());
    hasher.update(&instance);
    hasher.update(&generation.to_le_bytes());
    Ok(InventoryGeneration(*hasher.finalize().as_bytes()))
}

pub(crate) fn persistent_ref_inventory_generation(
    instance: [u8; 32],
    generation: u64,
) -> RefInventoryGeneration {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.content-store.ref-inventory-generation.v1");
    hasher.update(&instance);
    hasher.update(&generation.to_le_bytes());
    RefInventoryGeneration(*hasher.finalize().as_bytes())
}
