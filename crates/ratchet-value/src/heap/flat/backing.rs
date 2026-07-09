//! Shared multi-store arena backing for flat object stores (doc 30 FV-4).
//!
//! Until FV-4, every [`FlatObjectStore`] owned a dedicated [`BumpArena`], so a
//! heap hosting strings/paths, lists, and attrsets carried three independent
//! chunk tails — up to one `MAX_CHUNK_BYTES`-sized doubling step of mapped
//! slack *per payload type*. A [`SharedFlatStoreArena`] is one bump arena
//! shared by several stores through a cheap single-threaded handle: each
//! store keeps its own registry and its own membership-region cache, but all
//! of them reserve object storage from the same chunks, collapsing the
//! per-type slack to one tail.
//!
//! # Soundness structure
//!
//! - **Type safety across stores.** Chunks now interleave objects of every
//!   sharing store, so region membership alone no longer implies a store's
//!   payload type. The stores therefore carry an allowed-kind set
//!   ([`FlatKindSet`]) and the header kind word is the type witness: a store
//!   only types an address as `FlatObject<T>` after reading a kind it is
//!   itself allowed to allocate. Sharing stores must be given disjoint kind
//!   sets; the evaluator heap assigns `{String, Path}` / `{List}` / `{Attrs}`.
//! - **Unmap ordering.** Every sharing store holds a strong handle, so the
//!   arena's chunks stay mapped until the *last* store drops — payload drop
//!   glue in each store's `Drop` always runs against live mappings, exactly
//!   as with an owned arena.
//! - **No region pops.** Lexical-region pops rewind a bump cursor, which is
//!   only sound when one store's allocations own the rewound suffix. Shared
//!   backings therefore reject `pop_region`; the worker-domain closure store,
//!   which pops, keeps its dedicated owned arena.
//!
//! # Concurrency contract
//!
//! The handle is `Rc<RefCell<..>>`: serial evaluator heaps are single-thread
//! owned (parallel workers build their own heaps on their own threads and
//! publish through the shared-shard slot stores instead), so no cross-thread
//! sharing exists to synchronize.
//!
//! [`FlatObjectStore`]: super::FlatObjectStore

use std::cell::RefCell;
use std::rc::Rc;

use super::FlatObjectKind;
use crate::heap::advice::MemoryAdviceKind;
use crate::heap::arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaStats, BumpArena,
};

/// A set of [`FlatObjectKind`]s one store is allowed to allocate and type.
///
/// Kind discriminants are small (`0x01..=0x07`), so the set is a bit mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlatKindSet(u32);

impl FlatKindSet {
    /// The set containing every flat object kind.
    pub const ALL: Self = Self(u32::MAX);

    /// Creates a set from the given kinds.
    pub const fn of(kinds: &[FlatObjectKind]) -> Self {
        let mut bits = 0u32;
        let mut index = 0;
        while index < kinds.len() {
            bits |= 1 << kinds[index] as u32;
            index += 1;
        }
        Self(bits)
    }

    /// Returns whether the set contains `kind`.
    pub const fn contains(self, kind: FlatObjectKind) -> bool {
        self.0 & (1 << kind as u32) != 0
    }
}

/// A shared handle to one Tier-A bump arena hosting several flat stores.
///
/// See this module's documentation (`backing`) for the sharing structure
/// and its soundness argument. Cloning the handle shares the same arena.
#[derive(Clone, Debug)]
pub struct SharedFlatStoreArena {
    inner: Rc<RefCell<BumpArena>>,
}

impl Default for SharedFlatStoreArena {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedFlatStoreArena {
    /// Creates a shared arena with the flat stores' default chunk geometry.
    pub fn new() -> Self {
        match Self::with_initial_chunk_bytes(super::INITIAL_CHUNK_BYTES) {
            Ok(arena) => arena,
            // Unreachable: the constant is non-zero and word-alignable.
            Err(_) => {
                let mut arena = BumpArena::new();
                arena.limit_chunk_growth(super::MAX_CHUNK_BYTES);
                Self {
                    inner: Rc::new(RefCell::new(arena)),
                }
            }
        }
    }

    /// Creates a shared arena whose first chunk has the given size, doubling
    /// up to the flat stores' chunk-growth cap thereafter.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        let mut arena = BumpArena::with_initial_chunk_bytes(chunk_bytes)?;
        arena.limit_chunk_growth(super::MAX_CHUNK_BYTES.max(chunk_bytes));
        Ok(Self {
            inner: Rc::new(RefCell::new(arena)),
        })
    }

    /// Reserves `size` bytes at `align` for a flat object of `kind`.
    ///
    /// # Errors
    ///
    /// Returns the underlying arena error, or [`ArenaError::SizeOverflow`] if
    /// the handle is unexpectedly re-entered (the arena is busy).
    pub(super) fn alloc_raw(
        &self,
        size: usize,
        align: usize,
        kind: FlatObjectKind,
    ) -> Result<ArenaAllocation, ArenaError> {
        let Ok(mut arena) = self.inner.try_borrow_mut() else {
            // Unreachable in practice: allocation never re-enters the handle.
            return Err(ArenaError::SizeOverflow);
        };
        arena.aos_alloc_raw(size, align, kind as u32)
    }

    /// Returns the shared arena's accounting.
    ///
    /// Callers merging per-store statistics must read the shared arena
    /// exactly once; every sharing store reports these same numbers. Walks
    /// every chunk; per-allocation staleness checks use the constant-time
    /// crate-internal chunk-count accessor instead.
    pub fn stats(&self) -> ArenaStats {
        self.inner.borrow().stats()
    }

    /// Returns the number of chunks currently owned by the shared arena
    /// (constant-time).
    pub(super) fn chunk_count(&self) -> usize {
        self.inner.borrow().chunk_count()
    }

    /// Copies the arena's current chunk byte regions into `regions`.
    pub(super) fn snapshot_chunk_regions(&self, regions: &mut Vec<(usize, usize)>) {
        let arena = self.inner.borrow();
        regions.clear();
        regions.extend(arena.chunk_regions());
        regions.sort_unstable();
    }

    /// Advises unused bytes at the end of the shared arena's chunks.
    ///
    /// Callers merging per-store advice must issue this exactly once per
    /// shared arena, not once per sharing store.
    pub fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        self.inner.borrow().advise_unused_tail(kind)
    }

    /// Returns unused-tail bytes this platform can lower to page advice.
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        self.inner.borrow().supported_unused_tail_advice_bytes()
    }
}
