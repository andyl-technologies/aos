//! Shared multi-store arena backing for flat object stores (doc 30 FV-4).
//!
//! Until FV-4, every [`FlatObjectStore`] owned a dedicated [`BumpArena`], so a
//! heap hosting strings/paths, lists, and attrsets carried three independent
//! chunk tails. [`SharedFlatStoreArena`] first collapsed those stores into one
//! chunked bump arena; Candidate C now places the complete production serial
//! flat domain in one demand-paged 4 GiB [`ReservedArena`]. Permanent objects
//! grow upward while the exclusive region-popped closure lane grows downward.
//! Explicit chunk geometry and unsupported mappings retain chunked backends.
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
//! - **Independent rewind.** Permanent stores own the low lane and reject
//!   region operations. Exactly one closure store claims the high lane; its
//!   allocations descend, so a LIFO rewind cannot cross interleaved immortal
//!   objects. Dropping/resetting that store rewinds to its claimed origin.
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

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::FlatObjectKind;
use crate::heap::advice::MemoryAdviceKind;
use crate::heap::arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaRegionPopReport, ArenaStats,
    BumpArena, HeapObjectKind,
};
use crate::heap::{
    ArenaIndex, MemoryAdviceOutcome, ReservedArena, ReservedArenaError, ReservedArenaHighMark,
    ReservedArenaStats,
};
use crate::value::HeapObject;

/// A set of [`FlatObjectKind`]s one store is allowed to allocate and type.
///
/// Kind discriminants are small (`0x01..=0x09`), so the set is a bit mask.
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

/// A shared handle to one serial flat-domain arena hosting several stores.
///
/// See this module's documentation (`backing`) for the sharing structure
/// and its soundness argument. Cloning the handle shares the same arena.
#[derive(Clone, Debug)]
pub struct SharedFlatStoreArena {
    inner: Rc<RefCell<SharedFlatStoreBacking>>,
    rewindable_claimed: Rc<Cell<bool>>,
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
            rewindable_claimed: Rc::new(Cell::new(false)),
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
            rewindable_claimed: Rc::new(Cell::new(false)),
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
            SharedFlatStoreBacking::Reserved(arena) => reserved_allocation(
                arena.alloc_exclusive(word_rounded_size(size)?, align),
                size,
                kind,
            ),
        }
    }

    /// Reserves an object from the downward-growing region-pop lane.
    ///
    /// # Errors
    ///
    /// Returns an allocation error if the lanes collide, or
    /// [`ArenaError::InvalidRegionMark`] when no reservation is active.
    #[inline]
    pub(super) fn alloc_rewindable_raw(
        &self,
        size: usize,
        align: usize,
        kind: FlatObjectKind,
    ) -> Result<ArenaAllocation, ArenaError> {
        if !self.rewindable_claimed.get() {
            return Err(ArenaError::InvalidRegionMark);
        }
        let Ok(mut backing) = self.inner.try_borrow_mut() else {
            return Err(ArenaError::SizeOverflow);
        };
        let SharedFlatStoreBacking::Reserved(arena) = &mut *backing else {
            return Err(ArenaError::InvalidRegionMark);
        };
        reserved_allocation(
            arena.alloc_exclusive_high(word_rounded_size(size)?, align),
            size,
            kind,
        )
    }

    /// Exclusively claims the reservation's high lane for one flat store.
    pub(super) fn claim_rewindable_lane(&self) -> Result<ReservedArenaHighMark, ArenaError> {
        if self.rewindable_claimed.replace(true) {
            return Err(ArenaError::InvalidRegionMark);
        }
        let mark = match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => Ok(arena.high_mark()),
            SharedFlatStoreBacking::Chunked(_) => Err(ArenaError::InvalidRegionMark),
        };
        if mark.is_err() {
            self.rewindable_claimed.set(false);
        }
        mark
    }

    /// Rewinds and releases the exclusively claimed high lane.
    pub(super) fn release_rewindable_lane(
        &self,
        origin: ReservedArenaHighMark,
    ) -> Result<(), ArenaError> {
        let result = self.pop_rewindable_to_mark(origin).map(|_| ());
        self.rewindable_claimed.set(false);
        result
    }

    /// Captures the rewindable lane's current cursor.
    pub(super) fn rewindable_mark(&self) -> Result<ReservedArenaHighMark, ArenaError> {
        if !self.rewindable_claimed.get() {
            return Err(ArenaError::InvalidRegionMark);
        }
        let SharedFlatStoreBacking::Reserved(arena) = &*self.inner.borrow() else {
            return Err(ArenaError::InvalidRegionMark);
        };
        Ok(arena.high_mark())
    }

    /// Validates one marker against the rewindable lane.
    pub(super) fn validate_rewindable_mark(
        &self,
        mark: ReservedArenaHighMark,
    ) -> Result<(), ArenaError> {
        if !self.rewindable_claimed.get() {
            return Err(ArenaError::InvalidRegionMark);
        }
        let SharedFlatStoreBacking::Reserved(arena) = &*self.inner.borrow() else {
            return Err(ArenaError::InvalidRegionMark);
        };
        arena
            .validate_high_mark(mark)
            .map_err(|_| ArenaError::InvalidRegionMark)
    }

    /// Rewinds the high lane to a caller-validated marker.
    pub(super) fn pop_rewindable_to_mark(
        &self,
        mark: ReservedArenaHighMark,
    ) -> Result<ArenaRegionPopReport, ArenaError> {
        if !self.rewindable_claimed.get() {
            return Err(ArenaError::InvalidRegionMark);
        }
        let Ok(mut backing) = self.inner.try_borrow_mut() else {
            return Err(ArenaError::InvalidRegionMark);
        };
        let SharedFlatStoreBacking::Reserved(arena) = &mut *backing else {
            return Err(ArenaError::InvalidRegionMark);
        };
        let before = reserved_lane_stats(arena.stats().high_used_bytes);
        arena
            .pop_high_caller_validated_to_mark(mark)
            .map_err(|_| ArenaError::InvalidRegionMark)?;
        Ok(ArenaRegionPopReport::new(
            before,
            reserved_lane_stats(arena.stats().high_used_bytes),
            0,
            0,
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Dead,
            },
        ))
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

    /// Returns the live reservation pointer for one compressed index.
    pub fn pointer_for_index(&self, index: ArenaIndex) -> Option<std::ptr::NonNull<HeapObject>> {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => arena.pointer_for_index(index).ok(),
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
            SharedFlatStoreBacking::Reserved(arena) => reserved_arena_stats(arena),
        }
    }

    /// Returns only the upward-growing permanent lane's accounting.
    pub fn permanent_stats(&self) -> ArenaStats {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Chunked(arena) => arena.stats(),
            SharedFlatStoreBacking::Reserved(arena) => {
                reserved_lane_stats(arena.stats().low_used_bytes)
            }
        }
    }

    /// Returns only the downward-growing rewindable lane's accounting.
    pub(super) fn rewindable_stats(&self) -> ArenaStats {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Chunked(_) => ArenaStats::default(),
            SharedFlatStoreBacking::Reserved(arena) => {
                reserved_lane_stats(arena.stats().high_used_bytes)
            }
        }
    }

    /// Returns the number of chunks currently owned by the shared arena
    /// (constant-time).
    pub(super) fn chunk_count(&self) -> usize {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Chunked(arena) => arena.chunk_count(),
            SharedFlatStoreBacking::Reserved(arena) => usize::from(arena.has_allocations()),
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

fn word_rounded_size(size: usize) -> Result<usize, ArenaError> {
    size.max(1)
        .checked_add(super::MAX_ALIGN - 1)
        .map(|size| size & !(super::MAX_ALIGN - 1))
        .ok_or(ArenaError::SizeOverflow)
}

fn reserved_allocation(
    allocation: Result<crate::heap::ReservedArenaAllocation, ReservedArenaError>,
    size: usize,
    kind: FlatObjectKind,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocation.map_err(|error| reservation_allocation_error(error, size))?;
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

fn reserved_arena_stats(arena: &ReservedArena) -> ArenaStats {
    reserved_lane_stats(arena.stats().used_bytes)
}

fn reserved_lane_stats(used_bytes: usize) -> ArenaStats {
    ArenaStats {
        chunks: usize::from(used_bytes != 0),
        reserved_bytes: used_bytes,
        mapped_bytes: used_bytes,
        used_bytes,
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
