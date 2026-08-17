//! Shared-mode flat objects: reservation or slot-backed publication.
//!
//! RFC-0007 doc 30 stage FV-1 names shared-mode flattening as the parallel
//! analog of the serial flat store: strings and paths allocated by one worker
//! must resolve from every worker without a per-worker address index probe,
//! while preserving the shared arena's P3a publication protocol exactly —
//! records publish at **stable slot addresses** with release/acquire
//! ordering.
//!
//! ```text
//! shared flat store (one per worker shard):
//!
//!   production: geometric levels in one shared 4 GiB reservation
//!     [ object | object | ... ]        u32 byte offsets
//!       compact AtomicU8 publication sidecar
//!
//!   compatibility/test backend: geometric OnceLock slot levels
//!
//!   object:
//!     ┌───────────────────────────────────────────────┐
//!     │ kind word  = FLAT_OBJECT_MAGIC << 32 | kind    │
//!     │ hash word  (the hash-cons key)                 │
//!     │ payload: T (written once, immutable after)     │
//!     └───────────────────────────────────────────────┘
//! ```
//!
//! The object address remains the active pointer-ABI handle. Production stores
//! place geometric runs of typed objects directly in one [`ReservedArena`]. A
//! compact one-byte atomic sidecar supplies the release/acquire publication
//! edge and exact allocation-membership witness; resolution is range/stride
//! arithmetic without a lock or address-index search. The
//! compatibility backend retains complete objects in the original geometric
//! `OnceLock` levels for isolated tests and fallback construction.
//!
//! # Concurrency contract
//!
//! Allocation is multi-writer safe, although production gives each store one
//! worker-shard writer. Published objects are immutable: shared mode quiesces
//! GC, so no epoch stamping or payload mutation ever occurs. A reservation
//! store drops only slots carrying a publication marker before the last arena
//! handle unmaps the shared address space.

use std::marker::PhantomData;
use std::mem;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use std::ptr::NonNull;

use crate::heap::ReservedArena;
use crate::value::HeapObject;

use super::{FLAT_OBJECT_MAGIC, FlatKindSet, FlatObjectKind};

/// Slots per level-0 chunk; level `c` holds `CHUNK_LEN << c` slots.
///
/// Matches the shared heap arena's chunk geometry so slot-count capacity
/// behaves identically for flat and record-backed shared objects.
const CHUNK_LEN: usize = 256;

/// One published shared flat object: header words plus the typed payload.
#[repr(C, align(8))]
#[derive(Debug)]
pub struct SharedFlatObject<T> {
    /// `FLAT_OBJECT_MAGIC << 32 | kind` — the resolution validity check.
    kind_word: u64,
    /// The structural hash the object was hash-consed under.
    hash: u64,
    /// The typed payload, immutable after publication.
    payload: T,
}

#[derive(Debug)]
enum SharedFlatStorage<T> {
    /// Original geometric slot levels, retained for isolated tests/fallback.
    BoxedLevels {
        levels: Box<[OnceLock<SharedFlatLevel<T>>]>,
    },
    /// Production Candidate-C address space shared by all worker shards.
    Reserved {
        arena: Arc<ReservedArena>,
        levels: Box<[OnceLock<Result<ReservedSharedFlatLevel<T>, SharedFlatObjectError>>]>,
        allowed_kinds: FlatKindSet,
    },
}

impl<T> SharedFlatObject<T> {
    /// Returns the object's kind, if the header carries the flat magic.
    pub fn kind(&self) -> Option<FlatObjectKind> {
        FlatObjectKind::from_kind_word(self.kind_word)
    }

    /// Returns the structural hash the object was interned under.
    pub const fn structural_hash(&self) -> u64 {
        self.hash
    }

    /// Returns the typed payload.
    pub const fn payload(&self) -> &T {
        &self.payload
    }
}

/// A level of published slots plus the address range they occupy.
#[derive(Debug)]
struct SharedFlatLevel<T> {
    slots: Box<[OnceLock<SharedFlatObject<T>>]>,
    /// First slot address, cached so membership checks are range compares.
    base: usize,
}

/// One reservation-backed object level plus its compact publication sidecar.
#[derive(Debug)]
struct ReservedSharedFlatLevel<T> {
    /// First object address inside the common reservation.
    base: usize,
    /// Byte distance between adjacent aligned object slots.
    stride: usize,
    /// Release/acquire publication witnesses for the object slots.
    published: Box<[AtomicU8]>,
    /// Makes this level carry the same send/sync requirements as its payload.
    payload: PhantomData<T>,
}

impl<T> ReservedSharedFlatLevel<T> {
    fn with_len(arena: &ReservedArena, len: usize) -> Result<Self, SharedFlatObjectError> {
        let align = mem::align_of::<SharedFlatObject<T>>();
        let stride = mem::size_of::<SharedFlatObject<T>>();
        let size =
            stride
                .checked_mul(len)
                .ok_or(SharedFlatObjectError::ReservationAllocationFailed {
                    size: usize::MAX,
                    align,
                })?;
        let allocation = arena
            .alloc(size, align)
            .map_err(|_| SharedFlatObjectError::ReservationAllocationFailed { size, align })?;
        let mut published = Vec::with_capacity(len);
        published.resize_with(len, || AtomicU8::new(0));
        Ok(Self {
            base: allocation.ptr.as_ptr() as usize,
            stride,
            published: published.into_boxed_slice(),
            payload: PhantomData,
        })
    }

    fn address_of(&self, slot: usize) -> Option<usize> {
        self.published
            .get(slot)
            .map(|_| slot)
            .and_then(|slot| slot.checked_mul(self.stride))
            .and_then(|offset| self.base.checked_add(offset))
    }

    /// Returns the exact logical slot at `address`, if it is in this level.
    fn slot_at_address(&self, address: usize) -> Option<(usize, &AtomicU8)> {
        let offset = address.checked_sub(self.base)?;
        if offset % self.stride != 0 {
            return None;
        }
        let slot_index = offset / self.stride;
        self.published
            .get(slot_index)
            .map(|marker| (slot_index, marker))
    }

    fn marker(&self, slot: usize) -> Option<&AtomicU8> {
        self.published.get(slot)
    }
}

impl<T> SharedFlatLevel<T> {
    fn with_len(len: usize) -> Self {
        let mut slots = Vec::with_capacity(len);
        slots.resize_with(len, OnceLock::new);
        let slots = slots.into_boxed_slice();
        let base = slots.as_ptr() as usize;
        Self { slots, base }
    }

    /// Returns the slot containing `address`, if it lies on a slot boundary
    /// inside this level.
    fn slot_at_address(&self, address: usize) -> Option<&OnceLock<SharedFlatObject<T>>> {
        let stride = std::mem::size_of::<OnceLock<SharedFlatObject<T>>>();
        let offset = address.checked_sub(self.base)?;
        if offset % stride != 0 {
            return None;
        }
        self.slots.get(offset / stride)
    }
}

/// An append-only store of shared flat objects published at slot addresses.
///
/// See the [module documentation](self) for the layout, the publication
/// protocol, and the concurrency contract.
#[derive(Debug)]
pub struct SharedFlatObjectStore<T> {
    storage: SharedFlatStorage<T>,
    /// Bump cursor over the logical slot id space.
    next: AtomicUsize,
    /// Total logical slot capacity across all levels.
    capacity: usize,
    /// Published object count (release on publish, acquire on read).
    published: AtomicUsize,
    /// Approximate published payload bytes, for allocator accounting.
    payload_bytes: AtomicUsize,
}

/// A shared flat allocation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SharedFlatObjectError {
    /// The store's slot capacity is exhausted.
    #[error("shared flat object store capacity exhausted at {capacity} slots")]
    CapacityExhausted {
        /// The store's total slot capacity.
        capacity: usize,
    },
    /// A reservation-backed store rejected an object kind outside its domain.
    #[error("shared reservation store does not admit {kind:?}")]
    KindNotAllowed {
        /// The rejected flat-object kind.
        kind: FlatObjectKind,
    },
    /// The shared reservation could not fit the typed object.
    #[error("shared reservation cannot allocate {size} bytes at alignment {align}")]
    ReservationAllocationFailed {
        /// The typed object size.
        size: usize,
        /// The typed object alignment.
        align: usize,
    },
}

impl<T> SharedFlatObjectStore<T> {
    /// Creates a store with capacity for at least `capacity` objects.
    pub fn with_capacity(capacity: usize) -> Self {
        let (levels, total) = level_geometry(capacity);
        let mut level_cells = Vec::with_capacity(levels);
        level_cells.resize_with(levels, OnceLock::new);
        Self {
            storage: SharedFlatStorage::BoxedLevels {
                levels: level_cells.into_boxed_slice(),
            },
            next: AtomicUsize::new(0),
            capacity: total,
            published: AtomicUsize::new(0),
            payload_bytes: AtomicUsize::new(0),
        }
    }

    /// Creates a production store inside one shared Candidate-C reservation.
    ///
    /// `allowed_kinds` is the typed-cast witness for this `T`. Stores sharing
    /// an arena may use the same `T`/kind domain in different worker shards;
    /// each store's geometric levels still witness only its own objects.
    pub fn with_reservation(
        arena: Arc<ReservedArena>,
        capacity: usize,
        allowed_kinds: FlatKindSet,
    ) -> Self {
        let (level_count, total) = level_geometry(capacity);
        let mut levels = Vec::with_capacity(level_count);
        levels.resize_with(level_count, OnceLock::new);
        Self {
            storage: SharedFlatStorage::Reserved {
                arena,
                levels: levels.into_boxed_slice(),
                allowed_kinds,
            },
            next: AtomicUsize::new(0),
            capacity: total,
            published: AtomicUsize::new(0),
            payload_bytes: AtomicUsize::new(0),
        }
    }

    /// Returns whether objects are placed in the shared reservation backend.
    pub const fn uses_reservation(&self) -> bool {
        matches!(&self.storage, SharedFlatStorage::Reserved { .. })
    }

    /// Returns the number of published objects.
    pub fn len(&self) -> usize {
        self.published.load(Ordering::Acquire)
    }

    /// Returns whether the store has published no objects.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the approximate published payload byte volume.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes.load(Ordering::Acquire)
    }

    /// Publishes a flat object and returns its stable slot address.
    ///
    /// The object is fully written into its slot before the backend's release
    /// publication makes it visible, so any reader that acquires the returned
    /// address through a published value observes the complete header and
    /// payload.
    ///
    /// # Errors
    ///
    /// Returns [`SharedFlatObjectError::CapacityExhausted`] when every slot has
    /// been claimed, [`SharedFlatObjectError::KindNotAllowed`] when a
    /// reservation store rejects `kind`, or
    /// [`SharedFlatObjectError::ReservationAllocationFailed`] when a new
    /// geometric level does not fit the common reservation.
    pub fn publish(
        &self,
        kind: FlatObjectKind,
        hash: u64,
        payload_bytes: usize,
        payload: T,
    ) -> Result<NonNull<HeapObject>, SharedFlatObjectError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id >= self.capacity {
            return Err(SharedFlatObjectError::CapacityExhausted {
                capacity: self.capacity,
            });
        }
        let ptr = match &self.storage {
            SharedFlatStorage::BoxedLevels { levels } => {
                publish_boxed(levels, id, self.capacity, kind, hash, payload)?
            }
            SharedFlatStorage::Reserved {
                arena,
                levels,
                allowed_kinds,
            } => publish_reserved(
                arena,
                levels,
                self.capacity,
                *allowed_kinds,
                id,
                kind,
                hash,
                payload,
            )?,
        };
        self.payload_bytes
            .fetch_add(payload_bytes, Ordering::Release);
        self.published.fetch_add(1, Ordering::Release);
        Ok(ptr)
    }

    /// Resolves `ptr` as a published flat object of `kind`.
    ///
    /// Returns `None` when the address does not name a published slot of this
    /// store or the slot's kind disagrees; the caller decides error fidelity.
    #[inline]
    pub fn resolve(
        &self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Option<&SharedFlatObject<T>> {
        let object = self.resolve_any(ptr)?;
        (object.kind() == Some(kind)).then_some(object)
    }

    /// Resolves `ptr` as a published flat object of any kind.
    #[inline]
    pub fn resolve_any(&self, ptr: NonNull<HeapObject>) -> Option<&SharedFlatObject<T>> {
        match &self.storage {
            SharedFlatStorage::BoxedLevels { levels } => {
                let address = ptr.as_ptr() as usize;
                for level_cell in levels {
                    let Some(level) = level_cell.get() else {
                        // A racing reader may observe a later level first.
                        continue;
                    };
                    if let Some(slot) = level.slot_at_address(address) {
                        return slot.get();
                    }
                }
                None
            }
            SharedFlatStorage::Reserved {
                levels,
                allowed_kinds,
                ..
            } => resolve_reserved(levels, *allowed_kinds, ptr),
        }
    }

    /// Iterates every published object with its slot address.
    pub fn iter(&self) -> Box<dyn Iterator<Item = (usize, &SharedFlatObject<T>)> + '_> {
        match &self.storage {
            SharedFlatStorage::BoxedLevels { levels } => Box::new(
                levels
                    .iter()
                    .filter_map(|cell| cell.get())
                    .flat_map(|level| {
                        level.slots.iter().filter_map(|slot| {
                            slot.get().map(|object| (slot as *const _ as usize, object))
                        })
                    }),
            ),
            SharedFlatStorage::Reserved { levels, .. } => Box::new(
                levels
                    .iter()
                    .filter_map(|cell| cell.get()?.as_ref().ok())
                    .flat_map(|level| {
                        (0..level.published.len()).filter_map(|index| {
                            let marker = level.marker(index)?;
                            (marker.load(Ordering::Acquire) != 0).then_some(())?;
                            let address = level.address_of(index)?;
                            let ptr = NonNull::new(address as *mut HeapObject)?;
                            self.resolve_any(ptr).map(|object| (address, object))
                        })
                    }),
            ),
        }
    }
}

impl<T> Drop for SharedFlatObjectStore<T> {
    fn drop(&mut self) {
        let SharedFlatStorage::Reserved { levels, .. } = &mut self.storage else {
            return;
        };
        for level_cell in levels.iter_mut().rev() {
            let Some(Ok(level)) = level_cell.get_mut() else {
                continue;
            };
            let base = level.base;
            let stride = level.stride;
            for index in (0..level.published.len()).rev() {
                let Some(marker) = level.marker(index) else {
                    debug_assert!(false, "reservation slot marker remains valid");
                    continue;
                };
                if marker.load(Ordering::Relaxed) == 0 {
                    continue;
                }
                let Some(address) = index
                    .checked_mul(stride)
                    .and_then(|offset| base.checked_add(offset))
                else {
                    debug_assert!(false, "published reservation slot address remains valid");
                    continue;
                };
                let object = address as *mut SharedFlatObject<T>;
                // SAFETY: This level's publication marker is set only after
                // exactly one `SharedFlatObject<T>` placement write at this
                // exact aligned slot. Drop has exclusive store ownership, and
                // the arena field remains mapped until all levels drop.
                unsafe { object.drop_in_place() };
            }
        }
    }
}

fn publish_boxed<T>(
    levels: &[OnceLock<SharedFlatLevel<T>>],
    id: usize,
    capacity: usize,
    kind: FlatObjectKind,
    hash: u64,
    payload: T,
) -> Result<NonNull<HeapObject>, SharedFlatObjectError> {
    let (level_index, slot_index) = slot_location(id);
    let Some(level_cell) = levels.get(level_index) else {
        return Err(SharedFlatObjectError::CapacityExhausted { capacity });
    };
    let level_len = CHUNK_LEN
        .checked_shl(level_index as u32)
        .ok_or(SharedFlatObjectError::CapacityExhausted { capacity })?;
    let level = level_cell.get_or_init(|| SharedFlatLevel::with_len(level_len));
    let Some(slot) = level.slots.get(slot_index) else {
        return Err(SharedFlatObjectError::CapacityExhausted { capacity });
    };
    let address = slot as *const OnceLock<SharedFlatObject<T>> as usize;
    let published = slot.set(SharedFlatObject {
        kind_word: (FLAT_OBJECT_MAGIC << 32) | kind as u64,
        hash,
        payload,
    });
    debug_assert!(published.is_ok(), "bump-claimed slot published twice");
    NonNull::new(address as *mut HeapObject)
        .ok_or(SharedFlatObjectError::CapacityExhausted { capacity })
}

fn publish_reserved<T>(
    arena: &Arc<ReservedArena>,
    levels: &[OnceLock<Result<ReservedSharedFlatLevel<T>, SharedFlatObjectError>>],
    capacity: usize,
    allowed_kinds: FlatKindSet,
    id: usize,
    kind: FlatObjectKind,
    hash: u64,
    payload: T,
) -> Result<NonNull<HeapObject>, SharedFlatObjectError> {
    if !allowed_kinds.contains(kind) {
        return Err(SharedFlatObjectError::KindNotAllowed { kind });
    }
    let (level_index, slot_index) = slot_location(id);
    let Some(level_cell) = levels.get(level_index) else {
        return Err(SharedFlatObjectError::CapacityExhausted { capacity });
    };
    let level_len = CHUNK_LEN
        .checked_shl(level_index as u32)
        .ok_or(SharedFlatObjectError::CapacityExhausted { capacity })?;
    let level = level_cell
        .get_or_init(|| ReservedSharedFlatLevel::with_len(arena, level_len))
        .as_ref()
        .map_err(|error| *error)?;
    let Some(marker) = level.marker(slot_index) else {
        return Err(SharedFlatObjectError::CapacityExhausted { capacity });
    };
    let Some(address) = level.address_of(slot_index) else {
        return Err(SharedFlatObjectError::CapacityExhausted { capacity });
    };
    let object = address as *mut SharedFlatObject<T>;
    // SAFETY: Level initialization claimed one aligned reservation run whose
    // stride covers every complete `SharedFlatObject<T>`. The bump id uniquely
    // claims this slot, and its marker remains unset until the write completes.
    unsafe {
        object.write(SharedFlatObject {
            kind_word: (FLAT_OBJECT_MAGIC << 32) | kind as u64,
            hash,
            payload,
        })
    };
    debug_assert_eq!(
        marker.load(Ordering::Relaxed),
        0,
        "bump-claimed reservation slot published twice"
    );
    marker.store(1, Ordering::Release);
    NonNull::new(address as *mut HeapObject)
        .ok_or(SharedFlatObjectError::CapacityExhausted { capacity })
}

fn resolve_reserved<'a, T>(
    levels: &'a [OnceLock<Result<ReservedSharedFlatLevel<T>, SharedFlatObjectError>>],
    allowed_kinds: FlatKindSet,
    ptr: NonNull<HeapObject>,
) -> Option<&'a SharedFlatObject<T>> {
    let address = ptr.as_ptr() as usize;
    for level in levels.iter().filter_map(|cell| cell.get()?.as_ref().ok()) {
        let Some((_slot_index, marker)) = level.slot_at_address(address) else {
            continue;
        };
        (marker.load(Ordering::Acquire) != 0).then_some(())?;
        // SAFETY: Exact range/stride membership and this slot's acquire-loaded
        // marker prove that the store initialized a `SharedFlatObject<T>` here
        // before publishing the marker. Objects remain immutable and the
        // reservation-backed level outlives the returned borrow.
        let object = unsafe { ptr.cast::<SharedFlatObject<T>>().as_ref() };
        let kind = object.kind()?;
        return allowed_kinds.contains(kind).then_some(object);
    }
    None
}

/// Returns geometric level count and rounded total capacity.
fn level_geometry(capacity: usize) -> (usize, usize) {
    let mut levels = 0usize;
    let mut total = 0usize;
    while total < capacity {
        let Some(level_capacity) = CHUNK_LEN.checked_shl(levels as u32) else {
            total = usize::MAX;
            break;
        };
        total = total.saturating_add(level_capacity);
        levels += 1;
    }
    (levels.max(1), total.max(CHUNK_LEN))
}

/// Maps a logical slot id to its level and in-level index.
const fn slot_location(id: usize) -> (usize, usize) {
    let scaled = id / CHUNK_LEN + 1;
    let level = (usize::BITS - 1 - scaled.leading_zeros()) as usize;
    let level_base = CHUNK_LEN * ((1 << level) - 1);
    (level, id - level_base)
}

#[cfg(test)]
mod tests;
