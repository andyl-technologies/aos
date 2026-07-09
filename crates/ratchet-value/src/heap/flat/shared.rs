//! Shared-mode flat objects: slot-addressed header + payload publication.
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
//!   level 0: [ slot | slot | ... ]            CHUNK_LEN slots
//!   level 1: [ slot | slot | ... ]            CHUNK_LEN << 1 slots
//!   ...      (each level allocated on first use, then never moved)
//!
//!   slot = OnceLock<SharedFlatObject<T>>:
//!     ┌───────────────────────────────────────────────┐
//!     │ kind word  = FLAT_OBJECT_MAGIC << 32 | kind    │
//!     │ hash word  (the hash-cons key)                 │
//!     │ payload: T (written once, immutable after)     │
//!     └───────────────────────────────────────────────┘
//! ```
//!
//! The slot address **is** the runtime value handle: resolution walks the
//! store's initialized levels (an `OnceLock` acquire per level), checks the
//! address against each level's slot range, indexes the slot, and reads it
//! through `OnceLock::get` — the same acquire that pairs with the publishing
//! worker's `OnceLock::set` release, so a cross-worker reader that obtained
//! the address from a published value observes the fully written object. No
//! address map, no lock, and — unlike the serial flat store — **no unsafe
//! code**: membership arithmetic selects a safe slice index.
//!
//! # Concurrency contract
//!
//! Allocation is multi-writer safe (the bump cursor is a `fetch_add`) but by
//! construction each store belongs to one worker's shard, matching the shared
//! arena's single-writer discipline. Published objects are immutable: shared
//! mode quiesces GC, so no epoch stamping or payload mutation ever occurs.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::value::HeapObject;
use std::ptr::NonNull;

use super::{FLAT_OBJECT_MAGIC, FlatObjectKind};

/// Slots per level-0 chunk; level `c` holds `CHUNK_LEN << c` slots.
///
/// Matches the shared heap arena's chunk geometry so slot-count capacity
/// behaves identically for flat and record-backed shared objects.
const CHUNK_LEN: usize = 256;

/// One published shared flat object: header words plus the typed payload.
#[derive(Debug)]
pub struct SharedFlatObject<T> {
    /// `FLAT_OBJECT_MAGIC << 32 | kind` — the resolution validity check.
    kind_word: u64,
    /// The structural hash the object was hash-consed under.
    hash: u64,
    /// The typed payload, immutable after publication.
    payload: T,
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
    /// Geometrically growing levels; level `c` holds `CHUNK_LEN << c` slots.
    levels: Box<[OnceLock<SharedFlatLevel<T>>]>,
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
}

impl<T> SharedFlatObjectStore<T> {
    /// Creates a store with capacity for at least `capacity` objects.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut levels = 0usize;
        let mut total = 0usize;
        while total < capacity && levels < usize::BITS as usize {
            total = total.saturating_add(CHUNK_LEN << levels);
            levels += 1;
        }
        let levels = levels.max(1);
        let mut level_cells = Vec::with_capacity(levels);
        level_cells.resize_with(levels, OnceLock::new);
        Self {
            levels: level_cells.into_boxed_slice(),
            next: AtomicUsize::new(0),
            capacity: total.max(CHUNK_LEN),
            published: AtomicUsize::new(0),
            payload_bytes: AtomicUsize::new(0),
        }
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
    /// The object is fully written into its slot before the slot's
    /// `OnceLock::set` release makes it visible, so any reader that acquires
    /// the returned address through a published value observes the complete
    /// header and payload.
    ///
    /// # Errors
    ///
    /// Returns [`SharedFlatObjectError::CapacityExhausted`] when every slot
    /// has been claimed.
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
        let (level_index, slot_index) = slot_location(id);
        let Some(level_cell) = self.levels.get(level_index) else {
            return Err(SharedFlatObjectError::CapacityExhausted {
                capacity: self.capacity,
            });
        };
        let level = level_cell.get_or_init(|| SharedFlatLevel::with_len(CHUNK_LEN << level_index));
        let Some(slot) = level.slots.get(slot_index) else {
            return Err(SharedFlatObjectError::CapacityExhausted {
                capacity: self.capacity,
            });
        };
        let address = slot as *const OnceLock<SharedFlatObject<T>> as usize;
        let published = slot.set(SharedFlatObject {
            kind_word: (FLAT_OBJECT_MAGIC << 32) | kind as u64,
            hash,
            payload,
        });
        debug_assert!(published.is_ok(), "bump-claimed slot published twice");
        self.payload_bytes
            .fetch_add(payload_bytes, Ordering::Release);
        self.published.fetch_add(1, Ordering::Release);
        let Some(ptr) = NonNull::new(address as *mut HeapObject) else {
            // A live slot reference can never sit at the null address.
            return Err(SharedFlatObjectError::CapacityExhausted {
                capacity: self.capacity,
            });
        };
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
        let address = ptr.as_ptr() as usize;
        for level_cell in &self.levels {
            let Some(level) = level_cell.get() else {
                // Levels usually initialize in id order, but a racing reader
                // may observe a later level before an earlier one; keep
                // scanning rather than reasoning about initialization order.
                continue;
            };
            if let Some(slot) = level.slot_at_address(address) {
                return slot.get();
            }
        }
        None
    }

    /// Iterates every published object with its slot address.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &SharedFlatObject<T>)> {
        self.levels
            .iter()
            .filter_map(|cell| cell.get())
            .flat_map(|level| {
                level.slots.iter().filter_map(|slot| {
                    slot.get()
                        .map(|object| (slot as *const _ as usize, object))
                })
            })
    }
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
