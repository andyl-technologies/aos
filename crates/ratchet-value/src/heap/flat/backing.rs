//! Shared multi-store arena backing for flat object stores (doc 30 FV-4).
//!
//! Until FV-4, every [`FlatObjectStore`] owned a dedicated [`BumpArena`], so a
//! heap hosting strings/paths, lists, and attrsets carried three independent
//! chunk tails. [`SharedFlatStoreArena`] first collapsed those stores into one
//! chunked bump arena; Candidate C now places the production serial permanent
//! domain in one demand-paged 4 GiB [`ReservedArena`]. Explicit chunk-geometry
//! constructors and unsupported mappings retain the chunked backend. Each
//! store keeps its own registry and kind domain while all production object
//! addresses share one checked `u32` offset space.
//!
//! # Soundness structure
//!
//! - **Type safety across stores.** The backing interleaves objects of every
//!   sharing store, so mapping membership alone no longer implies a store's
//!   payload type. The stores therefore carry an allowed-kind set
//!   ([`FlatKindSet`]) and the header kind word is the type witness: a store
//!   only types an address as `FlatObject<T>` after reading a kind it is
//!   itself allowed to allocate. Sharing stores must be given disjoint kind
//!   sets; the evaluator heap assigns `{String, Path}` / `{List}` / `{Attrs}`.
//! - **Unmap ordering.** Every sharing store holds a strong handle, so the
//!   backing stays mapped until the *last* store drops — payload drop
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
//! sharing exists to synchronize. Reservation allocation therefore uses the
//! exclusive non-atomic cursor door; parallel shared stores use the atomic
//! reservation API in `flat/shared.rs`.
//!
//! [`FlatObjectStore`]: super::FlatObjectStore

use std::cell::RefCell;
use std::rc::Rc;

use super::FlatObjectKind;
use crate::heap::advice::MemoryAdviceKind;
use crate::heap::arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaStats, BumpArena, HeapObjectKind,
};
use crate::heap::{ArenaIndex, ReservedArena, ReservedArenaError, ReservedArenaStats};
use crate::value::HeapObject;

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

/// The allocation backend behind a serial multi-store flat arena.
#[derive(Debug)]
enum SharedFlatStoreBacking {
    /// Candidate-C production address space.
    Reserved(ReservedArena),
    /// Chunked compatibility backend for explicit geometry and fallback.
    Chunked(BumpArena),
}

/// A shared handle to one serial permanent-domain arena hosting several stores.
///
/// See this module's documentation (`backing`) for the sharing structure
/// and its soundness argument. Cloning the handle shares the same arena.
#[derive(Clone, Debug)]
pub struct SharedFlatStoreArena {
    inner: Rc<RefCell<SharedFlatStoreBacking>>,
}

impl Default for SharedFlatStoreArena {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedFlatStoreArena {
    /// Creates a production arena in one Candidate-C reservation.
    ///
    /// Unsupported platforms or a failed virtual mapping fall back to the
    /// prior chunked arena so evaluator construction remains infallible.
    pub fn new() -> Self {
        let backing = match ReservedArena::new() {
            Ok(arena) => SharedFlatStoreBacking::Reserved(arena),
            Err(_) => {
                let mut arena = BumpArena::new();
                arena.limit_chunk_growth(super::MAX_CHUNK_BYTES);
                SharedFlatStoreBacking::Chunked(arena)
            }
        };
        Self {
            inner: Rc::new(RefCell::new(backing)),
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
            inner: Rc::new(RefCell::new(SharedFlatStoreBacking::Chunked(arena))),
        })
    }

    /// Reserves `size` bytes at `align` for a flat object of `kind`.
    ///
    /// # Errors
    ///
    /// Returns the underlying arena error, or [`ArenaError::SizeOverflow`] if
    /// the handle is unexpectedly re-entered (the arena is busy).
    #[inline]
    pub(super) fn alloc_raw(
        &self,
        size: usize,
        align: usize,
        kind: FlatObjectKind,
    ) -> Result<ArenaAllocation, ArenaError> {
        let Ok(mut backing) = self.inner.try_borrow_mut() else {
            // Unreachable in practice: allocation never re-enters the handle.
            return Err(ArenaError::SizeOverflow);
        };
        match &mut *backing {
            SharedFlatStoreBacking::Chunked(arena) => arena.aos_alloc_raw(size, align, kind as u32),
            SharedFlatStoreBacking::Reserved(arena) => {
                let reserved_size = size
                    .max(1)
                    .checked_add(super::MAX_ALIGN - 1)
                    .map(|size| size & !(super::MAX_ALIGN - 1))
                    .ok_or(ArenaError::SizeOverflow)?;
                let allocation = arena
                    .alloc_exclusive(reserved_size, align)
                    .map_err(|error| reservation_allocation_error(error, size))?;
                Ok(ArenaAllocation {
                    ptr: allocation.ptr,
                    kind: HeapObjectKind::Raw {
                        type_tag: kind as u32,
                    },
                    requested_size: size,
                    reserved_size: allocation.reserved_size,
                    align: allocation.align,
                })
            }
        }
    }

    /// Returns whether this handle uses the Candidate-C reservation backend.
    pub fn uses_reservation(&self) -> bool {
        matches!(&*self.inner.borrow(), SharedFlatStoreBacking::Reserved(_))
    }

    /// Returns Candidate-C reservation accounting when that backend is active.
    pub fn reservation_stats(&self) -> Option<ReservedArenaStats> {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => Some(arena.stats()),
            SharedFlatStoreBacking::Chunked(_) => None,
        }
    }

    /// Returns the compressed index for one live reservation pointer.
    pub fn index_for_pointer(&self, ptr: std::ptr::NonNull<HeapObject>) -> Option<ArenaIndex> {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => arena.index_for_pointer(ptr).ok(),
            SharedFlatStoreBacking::Chunked(_) => None,
        }
    }

    /// Returns the shared arena's accounting.
    ///
    /// Callers merging per-store statistics must read the shared arena
    /// exactly once; every sharing store reports these same numbers. Walks
    /// every chunk; per-allocation staleness checks use the constant-time
    /// crate-internal chunk-count accessor instead.
    pub fn stats(&self) -> ArenaStats {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Chunked(arena) => arena.stats(),
            SharedFlatStoreBacking::Reserved(arena) => {
                let used_bytes = arena.stats().used_bytes;
                ArenaStats {
                    chunks: usize::from(used_bytes != 0),
                    reserved_bytes: used_bytes,
                    mapped_bytes: used_bytes,
                    used_bytes,
                }
            }
        }
    }

    /// Returns the number of chunks currently owned by the shared arena
    /// (constant-time).
    pub(super) fn chunk_count(&self) -> usize {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Chunked(arena) => arena.chunk_count(),
            SharedFlatStoreBacking::Reserved(arena) => usize::from(arena.used_region().is_some()),
        }
    }

    /// Copies the arena's current chunk byte regions into `regions`.
    pub(super) fn snapshot_chunk_regions(&self, regions: &mut Vec<(usize, usize)>) {
        regions.clear();
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Chunked(arena) => regions.extend(arena.chunk_regions()),
            SharedFlatStoreBacking::Reserved(arena) => regions.extend(arena.mapped_region()),
        }
        regions.sort_unstable();
    }

    /// Advises unused bytes at the end of the shared arena's chunks.
    ///
    /// Callers merging per-store advice must issue this exactly once per
    /// shared arena, not once per sharing store.
    pub fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Chunked(arena) => arena.advise_unused_tail(kind),
            SharedFlatStoreBacking::Reserved(_) => ArenaMemoryAdviceReport::empty(kind),
        }
    }

    /// Returns unused-tail bytes this platform can lower to page advice.
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Chunked(arena) => arena.supported_unused_tail_advice_bytes(),
            SharedFlatStoreBacking::Reserved(_) => 0,
        }
    }
}

fn reservation_allocation_error(error: ReservedArenaError, size: usize) -> ArenaError {
    match error {
        ReservedArenaError::InvalidAlignment { align } => ArenaError::InvalidAlignment { align },
        ReservedArenaError::SizeOverflow => ArenaError::SizeOverflow,
        ReservedArenaError::NullAllocationPointer => ArenaError::NullChunkPointer,
        _ => ArenaError::AllocationFailed { bytes: size },
    }
}
