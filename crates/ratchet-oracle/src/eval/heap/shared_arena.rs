//! Cross-worker-readable, sharded evaluator heap for parallel forcing (L2-P3a).
//!
//! # Why this module exists
//!
//! A runtime [`Value`] is two words: a [`ValueTag`] plus an opaque
//! [`NonNull<HeapObject>`] pointer. The *typed* payload behind that pointer -
//! the [`NixString`], [`NixList`], [`FlatAttrs`], or `Arc`-shared thunk/lambda/
//! primop - does **not** live at the pointer. It lives in a side table owned by
//! one evaluator ([`super::HeapRecordTable`]). Resolving a value therefore is
//! *not* pointer arithmetic: `get_string`/`get_list`/`get_attrs` all funnel
//! through `records.find(ptr)`, an address-keyed lookup into that owner's table
//! (see [`super::EvalHeap::record_or_unknown`]). A worker thus cannot
//! dereference a value another worker allocated unless it can read that other
//! worker's record table.
//!
//! That is the exact blocker the P2 harness documented: the serial
//! [`super::EvalHeap`] mutates its record `Vec`, hash-cons tables, bump arenas,
//! *and* a per-record `last_touch_epoch` `Cell` on the **read** path
//! (`touch_record`), so it is neither `Sync` nor shardable in place.
//!
//! # What this module provides
//!
//! [`SharedHeapArena`] is a `Sync` heap that K worker threads share:
//!
//! - **Per-worker allocation shards.** Each worker owns one [`SharedHeapShard`]
//!   and allocates only into it (single-writer per shard). Allocation is
//!   `&self`, so a shard can be driven from a scoped worker thread holding only
//!   an [`Arc`].
//! - **Stable record addresses.** Records live in an append-only table of
//!   geometrically growing chunks ([`OnceLock`] slots inside boxed chunks;
//!   level `c` holds `CHUNK_LEN << c` slots, so capacity doubles per level the
//!   way a `Vec` doubles, without ever relocating a published record). A chunk
//!   box is allocated once and never moves, so a record's slot address is
//!   stable for the arena's lifetime. That slot address *is* the value's opaque
//!   `HeapObject` handle - a safe raw-pointer cast that is never dereferenced as
//!   a `HeapObject` (the type is a zero-sized opaque key, exactly as the
//!   production heap treats it).
//! - **Release/Acquire publication.** A record is published by
//!   [`OnceLock::set`] (Release) and by inserting its address into the shard's
//!   index under a write lock; readers observe it through [`OnceLock::get`]
//!   (Acquire) and a read lock. A reader can therefore never observe a torn or
//!   half-initialized record.
//! - **Cross-shard resolution.** [`SharedHeapArena::resolve`] probes every
//!   shard's address index and returns a borrow into the stable chunk store -
//!   a borrow that is *not* tied to the transient index lock, because record
//!   storage and the address index are separate structures.
//!
//! ```text
//! worker 0 ── shard 0 ─ chunks:[ r r r ... ]  index:{addr->id}
//! worker 1 ── shard 1 ─ chunks:[ r r ...   ]  index:{addr->id}   arena.resolve(ptr):
//! worker 2 ── shard 2 ─ chunks:[ r ...     ]  index:{addr->id}     for each shard:
//! worker 3 ── shard 3 ─ chunks:[ r r r r...]  index:{addr->id}       shard.index.read()[addr]?
//! ```
//!
//! # Shared versus per-worker state
//!
//! | State | Placement | Rationale |
//! |-------|-----------|-----------|
//! | Record storage (typed payloads) | Shared, per-shard append-only chunks | Cross-worker deref needs stable, Acquire-published records |
//! | Address index (addr -> record id) | Shared, per-shard `RwLock<HashMap>` (insert-only) | Resolve consults it; single writer inserts, many readers probe `O(1)` |
//! | Bump cursor (`next` slot) | Per-shard, single writer | Only the owning worker allocates in its shard |
//! | Hash-cons interning | **Per-worker (none here)** | The arena stores no cons tables; each worker's [`super::EvalHeap`] keeps its own (see `shared_backend`). Cross-worker dedup loss only costs memory, never changes semantics, and pointer-equality fast paths in `eval_compare` fall back to content comparison |
//! | `last_touch_epoch` / access epoch | **Dropped here** | GC is quiesced under parallel mode, so idle-epoch tracking is a serial-only concern; dropping it removes the interior-mutable `Cell` that made reads non-`Sync` |
//!
//! # Memory tradeoff of per-worker hash-cons
//!
//! Because each worker interns independently, two workers that both allocate the
//! structurally identical string `"x86_64-linux"` get two distinct records and
//! two distinct handles. That costs extra memory (bounded by worker count times
//! the per-eval interned-value count) but is semantically invisible: Nix value
//! equality is by content, and the evaluator's equality paths never rely on
//! handle identity as anything stronger than a *fast-path shortcut that falls
//! through to content comparison*. Cross-worker canonicalization is a P4 tuning
//! concern, planned via the deterministic merge in [`super::super::parallel_heap`].
//!
//! # Serial mode
//!
//! Nothing here is reachable unless a parallel driver constructs a
//! [`SharedHeapArena`] (production wiring: [`super::EvalHeap::with_shared_shard`]
//! under `TreeWalkOptions::parallel_workers`). The serial [`super::EvalHeap`]
//! allocation and resolution paths pay only a branch-predictable check of the
//! always-`None` backend option; see the `shared_backend` module for the seam.

use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::sync::OnceLock;

use thiserror::Error;

use crate::attrs::FlatAttrs;
use crate::list::NixList;
use crate::string::NixString;
use crate::value::{HeapObject, Value, ValueError, ValueTag};

use super::HeapObjectValue;
use super::record_table::AddressHasher;

/// Records in the first (level-0) chunk. Level `c` holds `CHUNK_LEN << c`
/// records, so chunk sizes grow geometrically like a `Vec`'s doubling while
/// every already-boxed chunk keeps its records at stable addresses. A power of
/// two keeps the level/offset split cheap bit math.
const CHUNK_LEN: usize = 256;

/// An address-keyed index of published records, shared with readers.
type SharedAddressIndex = HashMap<usize, usize, BuildHasherDefault<AddressHasher>>;

/// A failure allocating into or resolving through a [`SharedHeapArena`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SharedHeapError {
    /// The requested shard index does not name a shard of this arena.
    #[error("shard index {index} is out of range for an arena of {shards} shard(s)")]
    ShardOutOfRange {
        /// The requested shard index.
        index: usize,
        /// The number of shards in the arena.
        shards: usize,
    },
    /// A shard reached its fixed record capacity.
    #[error("shard {shard} is full at its capacity of {capacity} record(s)")]
    ShardFull {
        /// The shard that ran out of record slots.
        shard: usize,
        /// The shard's fixed record capacity.
        capacity: usize,
    },
    /// A freshly bump-allocated slot was already occupied.
    ///
    /// This can only happen if a shard is written by more than one thread,
    /// violating the single-writer-per-shard contract. It is reported as an
    /// error rather than a panic so no invariant break is silently absorbed.
    #[error("shard {shard} slot {slot} was already published (single-writer contract violated)")]
    SlotAlreadyPublished {
        /// The shard whose slot collided.
        shard: usize,
        /// The colliding record slot.
        slot: usize,
    },
    /// Building a runtime [`Value`] from a record handle failed.
    #[error("shared heap value construction failed: {0}")]
    Value(#[from] ValueError),
    /// The value handle does not belong to any shard of this arena.
    #[error("heap pointer {address:#x} does not belong to this shared arena")]
    UnknownPointer {
        /// The offending handle address.
        address: usize,
    },
    /// The handle resolved to a record of a different typed payload.
    #[error("expected a {expected:?} record but the handle resolved to {actual:?}")]
    RecordTypeMismatch {
        /// The tag the caller expected.
        expected: ValueTag,
        /// The tag actually stored at the handle.
        actual: ValueTag,
    },
}

/// A single typed heap record published into a shard.
///
/// The handle is stored as a raw address (`usize`) rather than a
/// [`NonNull<HeapObject>`] so the record is unconditionally [`Send`] + [`Sync`]
/// without an `unsafe impl`; the pointer is rebuilt with the safe
/// [`NonNull::new`] on read and is never dereferenced.
#[derive(Debug)]
struct SharedHeapRecord {
    /// The record's stable slot address, used as the opaque value handle.
    address: usize,
    /// The typed payload behind the handle.
    object: HeapObjectValue,
}

// The record must be shareable across worker threads. `HeapObjectValue` is
// `Send + Sync` after L2-P1 (Arc-shared thunk/lambda/primop payloads plus plain
// string/list/attrs data); this static assertion pins that guarantee here so a
// future non-`Sync` payload breaks the build in this module.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SharedHeapRecord>();
    assert_send_sync::<SharedHeapShard>();
    assert_send_sync::<SharedHeapArena>();
};

/// A boxed, never-moved run of record slots.
type HeapChunk = Box<[OnceLock<SharedHeapRecord>]>;

/// One worker's allocation shard: append-only record storage plus an address
/// index for cross-shard resolution.
///
/// Allocation is single-writer (the owning worker); resolution is multi-reader
/// (every worker). See the [module documentation](self) for the publication and
/// visibility argument.
#[derive(Debug)]
pub struct SharedHeapShard {
    /// This shard's index within its arena.
    shard_id: usize,
    /// Fixed table of chunk levels. Level `c` is boxed on demand with
    /// `CHUNK_LEN << c` slots and then never moves, so slot addresses are
    /// stable while total capacity grows geometrically.
    chunks: Box<[OnceLock<HeapChunk>]>,
    /// Next record slot the owning worker will fill (single-writer bump).
    next: AtomicUsize,
    /// Count of published records, for diagnostics and stats merging.
    published: AtomicUsize,
    /// Approximate payload bytes published, for arena-level accounting when a
    /// process resident-set sample is unavailable.
    payload_bytes: AtomicUsize,
    /// Maps a record's handle address to its record id for resolution.
    index: RwLock<SharedAddressIndex>,
    /// The shard's record capacity (`CHUNK_LEN * (2^levels - 1)`, the smallest
    /// whole number of geometric levels covering the requested capacity).
    capacity: usize,
}

/// Returns the chunk level and in-chunk offset of record `id`.
///
/// Level `c` covers ids `[CHUNK_LEN * (2^c - 1), CHUNK_LEN * (2^(c+1) - 1))`
/// with `CHUNK_LEN << c` slots.
const fn slot_location(id: usize) -> (usize, usize) {
    let scaled = id / CHUNK_LEN + 1;
    let level = (usize::BITS - 1 - scaled.leading_zeros()) as usize;
    let level_base = CHUNK_LEN * ((1 << level) - 1);
    (level, id - level_base)
}

/// Returns the number of geometric chunk levels needed to hold `capacity`
/// records (at least one level).
const fn levels_for_capacity(capacity: usize) -> u32 {
    let mut levels = 1u32;
    // Total capacity with `levels` levels is `CHUNK_LEN * (2^levels - 1)`.
    // 63 levels already exceed any addressable record count.
    while levels < 63 && CHUNK_LEN * ((1usize << levels) - 1) < capacity {
        levels += 1;
    }
    levels
}

impl SharedHeapShard {
    /// Builds an empty shard sized to hold at least `capacity` records
    /// (rounded up to a whole number of geometric chunk levels).
    fn new(shard_id: usize, capacity: usize) -> Self {
        let levels = levels_for_capacity(capacity);
        let chunks = (0..levels).map(|_| OnceLock::new()).collect();
        Self {
            shard_id,
            chunks,
            next: AtomicUsize::new(0),
            published: AtomicUsize::new(0),
            payload_bytes: AtomicUsize::new(0),
            index: RwLock::new(SharedAddressIndex::default()),
            capacity: CHUNK_LEN * ((1usize << levels) - 1),
        }
    }

    /// Returns this shard's index within its arena.
    pub const fn shard_id(&self) -> usize {
        self.shard_id
    }

    /// Returns this shard's fixed record capacity.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of records published into this shard so far.
    pub fn published_len(&self) -> usize {
        self.published.load(Ordering::Acquire)
    }

    /// Returns the approximate payload bytes published into this shard.
    ///
    /// This is a logical-size estimate for arena-fallback memory accounting;
    /// the primary parallel-mode budget source is the process resident set.
    pub fn published_payload_bytes(&self) -> usize {
        self.payload_bytes.load(Ordering::Acquire)
    }

    /// Publishes `object` into the next free slot and returns its runtime
    /// value plus the record id within this shard.
    ///
    /// The owning worker is the only writer, so the bump cursor advances with a
    /// relaxed fetch-add; the record is made visible to readers by
    /// [`OnceLock::set`] (Release) followed by an index insert under the write
    /// lock. The returned [`Value`] carries the slot address as its opaque
    /// handle; the record id lets the owning worker keep a lock-free private
    /// address index for its own allocations.
    ///
    /// # Errors
    ///
    /// Returns [`SharedHeapError::ShardFull`] when the shard's capacity is
    /// exhausted, [`SharedHeapError::SlotAlreadyPublished`] if the
    /// single-writer contract was violated, or [`SharedHeapError::Value`] if the
    /// slot address cannot form a valid heap value (it always can in practice;
    /// chunk slots are pointer-aligned).
    pub(super) fn alloc_object(
        &self,
        object: HeapObjectValue,
    ) -> Result<(Value, usize), SharedHeapError> {
        let tag = object.tag();
        let payload_estimate = payload_size_estimate(&object);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id >= self.capacity {
            // Saturate the cursor so a full shard reports full rather than
            // wrapping on repeated attempts.
            self.next.store(self.capacity, Ordering::Relaxed);
            return Err(SharedHeapError::ShardFull {
                shard: self.shard_id,
                capacity: self.capacity,
            });
        }
        let (level, slot_idx) = slot_location(id);
        let chunk = self.chunks[level].get_or_init(|| new_chunk(CHUNK_LEN << level));
        let slot = &chunk[slot_idx];
        let address = slot as *const OnceLock<SharedHeapRecord> as usize;
        debug_assert_eq!(address & 0x7, 0, "record slot is 8-byte aligned");

        let value = Value::heap(tag, handle(address)?)?;
        if slot.set(SharedHeapRecord { address, object }).is_err() {
            return Err(SharedHeapError::SlotAlreadyPublished {
                shard: self.shard_id,
                slot: id,
            });
        }
        // Publish the address so cross-shard resolution can find it. The write
        // lock's release synchronizes-with every later reader's read lock.
        if let Ok(mut index) = self.index.write() {
            index.insert(address, id);
        }
        self.payload_bytes
            .fetch_add(payload_estimate, Ordering::Release);
        self.published.fetch_add(1, Ordering::Release);
        Ok((value, id))
    }

    /// Convenience: publishes a string value.
    ///
    /// # Errors
    ///
    /// Propagates any allocation failure from the shard.
    pub fn alloc_string(&self, string: NixString) -> Result<Value, SharedHeapError> {
        Ok(self.alloc_object(HeapObjectValue::String(string))?.0)
    }

    /// Convenience: publishes a list value.
    ///
    /// # Errors
    ///
    /// Propagates any allocation failure from the shard.
    pub fn alloc_list(&self, list: NixList) -> Result<Value, SharedHeapError> {
        Ok(self.alloc_object(HeapObjectValue::List(list))?.0)
    }

    /// Returns the record at `id`, if it has been published.
    fn record(&self, id: usize) -> Option<&SharedHeapRecord> {
        let (level, slot_idx) = slot_location(id);
        let chunk = self.chunks.get(level)?.get()?;
        chunk.get(slot_idx)?.get()
    }

    /// Returns the typed object of the published record at `id`.
    ///
    /// This is the owning worker's lock-free fast path: it pairs with the
    /// record id returned by [`SharedHeapShard::alloc_object`], so the caller
    /// already proved the id names a published record of this shard.
    pub(super) fn object_at(&self, id: usize) -> Option<&HeapObjectValue> {
        Some(&self.record(id)?.object)
    }

    /// Resolves `address` to its record within this shard, if it owns it.
    fn resolve_address(&self, address: usize) -> Option<&SharedHeapRecord> {
        let id = {
            let index = self.index.read().ok()?;
            index.get(&address).copied()?
        };
        let record = self.record(id)?;
        debug_assert_eq!(
            record.address, address,
            "shard index mapped an address to a record with a different handle"
        );
        Some(record)
    }
}

/// Estimates the resident payload bytes of one typed record.
///
/// Used only for arena-fallback memory accounting; `Arc`-shared payloads count
/// their handle size because their bodies are shared with the value graph.
fn payload_size_estimate(object: &HeapObjectValue) -> usize {
    let inline = std::mem::size_of::<SharedHeapRecord>();
    let out_of_line = match object {
        HeapObjectValue::String(string) | HeapObjectValue::Path(string) => string.len(),
        HeapObjectValue::List(list) => list.len() * std::mem::size_of::<Value>(),
        HeapObjectValue::Attrs { attrs, .. } => attrs.len() * 2 * std::mem::size_of::<Value>(),
        HeapObjectValue::Lambda(_) | HeapObjectValue::Primop(_) | HeapObjectValue::Thunk(_) => 0,
    };
    inline.saturating_add(out_of_line)
}

/// A `Sync` evaluator heap shared by K parallel worker threads.
///
/// Construct one with [`SharedHeapArena::new`] before spawning workers, wrap it
/// in an [`Arc`], and give each worker its own shard via [`SharedHeapArena::shard`].
/// Any worker can resolve a value allocated by any other worker with
/// [`SharedHeapArena::resolve`] and the typed getters.
#[derive(Debug)]
pub struct SharedHeapArena {
    /// One allocation shard per worker.
    shards: Vec<Arc<SharedHeapShard>>,
}

impl SharedHeapArena {
    /// Builds an arena with one shard per worker, each sized for
    /// `capacity_per_shard` records.
    ///
    /// `worker_count` must be at least one; a zero count yields a single shard
    /// so the arena is always usable.
    pub fn new(worker_count: usize, capacity_per_shard: usize) -> Self {
        let shard_count = worker_count.max(1);
        let shards = (0..shard_count)
            .map(|shard_id| Arc::new(SharedHeapShard::new(shard_id, capacity_per_shard)))
            .collect();
        Self { shards }
    }

    /// Returns the number of shards (workers) in this arena.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Returns the shard owned by `index`.
    ///
    /// # Errors
    ///
    /// Returns [`SharedHeapError::ShardOutOfRange`] if `index` is not a shard.
    pub fn shard(&self, index: usize) -> Result<&Arc<SharedHeapShard>, SharedHeapError> {
        self.shards
            .get(index)
            .ok_or(SharedHeapError::ShardOutOfRange {
                index,
                shards: self.shards.len(),
            })
    }

    /// Total records published across every shard.
    pub fn published_len(&self) -> usize {
        self.shards.iter().map(|shard| shard.published_len()).sum()
    }

    /// Approximate payload bytes published across every shard.
    ///
    /// Summed from per-shard atomic counters, so concurrent readers never
    /// block allocation and no shard is double-counted.
    pub fn published_payload_bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.published_payload_bytes())
            .fold(0usize, usize::saturating_add)
    }

    /// Resolves an opaque heap pointer to its typed object, across all shards.
    ///
    /// This is the cross-worker dereference primitive used by the production
    /// heap backend when a handle is not covered by the worker's own private
    /// index (a value allocated by another worker).
    pub(super) fn resolve_object(&self, ptr: NonNull<HeapObject>) -> Option<&HeapObjectValue> {
        self.resolve(ptr).ok().map(|record| &record.object)
    }

    /// Resolves an opaque heap pointer to its record, across all shards.
    ///
    /// This is the cross-worker dereference primitive: the handle may name a
    /// record any worker allocated. It probes each shard's address index and
    /// returns a borrow into stable chunk storage, so the returned reference is
    /// not tied to the transient index lock.
    ///
    /// # Errors
    ///
    /// Returns [`SharedHeapError::UnknownPointer`] if no shard owns `ptr`.
    fn resolve(&self, ptr: NonNull<HeapObject>) -> Result<&SharedHeapRecord, SharedHeapError> {
        let address = ptr.as_ptr() as usize;
        self.shards
            .iter()
            .find_map(|shard| shard.resolve_address(address))
            .ok_or(SharedHeapError::UnknownPointer { address })
    }

    /// Returns the typed object a value refers to, from any shard.
    ///
    /// # Errors
    ///
    /// Returns [`SharedHeapError::Value`] if `value` is not a heap value, or
    /// [`SharedHeapError::UnknownPointer`] if no shard owns the handle.
    fn resolve_value(&self, value: Value) -> Result<&HeapObjectValue, SharedHeapError> {
        let ptr = heap_ptr(value)?;
        Ok(&self.resolve(ptr)?.object)
    }

    /// Returns the string a value refers to, from any shard.
    ///
    /// # Errors
    ///
    /// Returns [`SharedHeapError::Value`] if `value` is not a heap value,
    /// [`SharedHeapError::UnknownPointer`] if no shard owns the handle, or
    /// [`SharedHeapError::RecordTypeMismatch`] if it is not a string.
    pub fn get_string(&self, value: Value) -> Result<&NixString, SharedHeapError> {
        match self.resolve_value(value)? {
            HeapObjectValue::String(string) => Ok(string),
            other => Err(SharedHeapError::RecordTypeMismatch {
                expected: ValueTag::String,
                actual: other.tag(),
            }),
        }
    }

    /// Returns the list a value refers to, from any shard.
    ///
    /// # Errors
    ///
    /// Returns [`SharedHeapError::Value`] if `value` is not a heap value,
    /// [`SharedHeapError::UnknownPointer`] if no shard owns the handle, or
    /// [`SharedHeapError::RecordTypeMismatch`] if it is not a list.
    pub fn get_list(&self, value: Value) -> Result<&NixList, SharedHeapError> {
        match self.resolve_value(value)? {
            HeapObjectValue::List(list) => Ok(list),
            other => Err(SharedHeapError::RecordTypeMismatch {
                expected: ValueTag::List,
                actual: other.tag(),
            }),
        }
    }

    /// Returns the attrset a value refers to, from any shard.
    ///
    /// # Errors
    ///
    /// Returns [`SharedHeapError::Value`] if `value` is not a heap value,
    /// [`SharedHeapError::UnknownPointer`] if no shard owns the handle, or
    /// [`SharedHeapError::RecordTypeMismatch`] if it is not an attrset.
    pub fn get_attrs(&self, value: Value) -> Result<&FlatAttrs, SharedHeapError> {
        match self.resolve_value(value)? {
            HeapObjectValue::Attrs { attrs, .. } => Ok(attrs),
            other => Err(SharedHeapError::RecordTypeMismatch {
                expected: ValueTag::Attrs,
                actual: other.tag(),
            }),
        }
    }
}

/// Allocates one fresh, empty record chunk with `len` slots.
fn new_chunk(len: usize) -> HeapChunk {
    (0..len).map(|_| OnceLock::new()).collect()
}

/// Builds a non-null heap handle from a slot address.
///
/// # Errors
///
/// Returns [`SharedHeapError::UnknownPointer`] if `address` is zero, which a
/// live slot address never is.
fn handle(address: usize) -> Result<NonNull<HeapObject>, SharedHeapError> {
    NonNull::new(address as *mut HeapObject).ok_or(SharedHeapError::UnknownPointer { address })
}

/// Extracts the opaque heap pointer from any heap-tagged value.
///
/// # Errors
///
/// Returns [`SharedHeapError::Value`] if `value` is an inline (non-heap) value.
fn heap_ptr(value: Value) -> Result<NonNull<HeapObject>, SharedHeapError> {
    let tag = value.tag();
    let address = value.payload_bits() as usize;
    if !tag.is_heap() {
        return Err(SharedHeapError::Value(ValueError::NotHeapTag { tag }));
    }
    handle(address)
}

#[cfg(test)]
mod tests;
