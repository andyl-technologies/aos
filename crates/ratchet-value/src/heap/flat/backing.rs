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
use std::ptr::NonNull;
use std::rc::Rc;

use super::FlatObjectKind;
use crate::heap::advice::MemoryAdviceKind;
use crate::heap::arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaRegionPopReport, ArenaStats,
    BumpArena, HeapObjectKind,
};
use crate::heap::{
    ArenaDomainId, ArenaIndex, MemoryAdviceOutcome, ReservedArena, ReservedArenaDeadPageAdvice,
    ReservedArenaDeadPageAdviceError, ReservedArenaError, ReservedArenaHighMark,
    ReservedArenaResidency, ReservedArenaStats,
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

/// Aggregate result of safely discarding zero-liveness reservation pages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedReservationZeroPageAdviceReport {
    candidate_pages: usize,
    runs: usize,
    applied_pages: usize,
}

impl SharedReservationZeroPageAdviceReport {
    /// Returns the number of whole used-lane pages with no typed allocation.
    pub const fn candidate_pages(self) -> usize {
        self.candidate_pages
    }

    /// Returns the number of contiguous page runs presented to the OS.
    pub const fn runs(self) -> usize {
        self.runs
    }

    /// Returns the number of pages for which the OS applied dead-page advice.
    pub const fn applied_pages(self) -> usize {
        self.applied_pages
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
    page_liveness: Rc<RefCell<ReservationPageLiveness>>,
}

/// Arena-owned typed-allocation counts for Candidate-C reservation pages.
#[derive(Debug)]
enum ReservationPageLiveness {
    /// Page accounting is unavailable or failed closed.
    Disabled,
    /// Geometry is known, but the dense count table has not been committed.
    Uninitialized {
        page_size: usize,
        reservation_pages: usize,
    },
    /// One checked live-allocation count per reservation page.
    Tracking {
        page_size: usize,
        counts: Box<[u16]>,
    },
}

impl ReservationPageLiveness {
    fn for_backing(backing: &SharedFlatStoreBacking) -> Self {
        let SharedFlatStoreBacking::Reserved(arena) = backing else {
            return Self::Disabled;
        };
        let Ok(residency) = arena.residency() else {
            return Self::Disabled;
        };
        let stats = arena.stats();
        let Some(reservation_pages) = stats
            .virtual_reserved_bytes
            .checked_div(residency.page_size)
        else {
            return Self::Disabled;
        };
        Self::Uninitialized {
            page_size: residency.page_size,
            reservation_pages,
        }
    }

    /// Records one newly exposed typed allocation, failing closed on error.
    fn record(&mut self, start: ArenaIndex, byte_len: usize) {
        if matches!(self, Self::Disabled) {
            return;
        }
        if let Self::Uninitialized {
            page_size,
            reservation_pages,
        } = *self
        {
            let mut counts = Vec::new();
            if counts.try_reserve_exact(reservation_pages).is_err() {
                *self = Self::Disabled;
                return;
            }
            counts.resize(reservation_pages, 0);
            *self = Self::Tracking {
                page_size,
                counts: counts.into_boxed_slice(),
            };
        }
        let Self::Tracking { page_size, counts } = self else {
            return;
        };
        let Some((first, last)) = allocation_page_interval(start, byte_len, *page_size) else {
            *self = Self::Disabled;
            return;
        };
        let Some(slice) = counts.get_mut(first..=last) else {
            *self = Self::Disabled;
            return;
        };
        if slice.iter().any(|count| *count == u16::MAX) {
            *self = Self::Disabled;
            return;
        }
        for count in slice {
            *count += 1;
        }
    }

    /// Removes one successfully destroyed typed allocation.
    fn retire(&mut self, start: ArenaIndex, byte_len: usize) {
        let Self::Tracking { page_size, counts } = self else {
            return;
        };
        let Some((first, last)) = allocation_page_interval(start, byte_len, *page_size) else {
            *self = Self::Disabled;
            return;
        };
        let Some(slice) = counts.get_mut(first..=last) else {
            *self = Self::Disabled;
            return;
        };
        if slice.contains(&0) {
            *self = Self::Disabled;
            return;
        }
        for count in slice {
            *count -= 1;
        }
    }

    /// Clears pages wholly outside the high lane after a validated rewind.
    fn clear_rewound_high_pages(&mut self, old_cursor: usize, new_cursor: usize) {
        let Self::Tracking { page_size, counts } = self else {
            return;
        };
        let first = old_cursor.div_ceil(*page_size);
        let last_exclusive = new_cursor / *page_size;
        if let Some(slice) = counts.get_mut(first..last_exclusive) {
            slice.fill(0);
        } else {
            *self = Self::Disabled;
        }
    }
}

fn allocation_page_interval(
    start: ArenaIndex,
    byte_len: usize,
    page_size: usize,
) -> Option<(usize, usize)> {
    if byte_len == 0 || page_size == 0 {
        return None;
    }
    let start = start.raw() as usize;
    let end_inclusive = start.checked_add(byte_len)?.checked_sub(1)?;
    Some((start / page_size, end_inclusive / page_size))
}

impl Default for SharedFlatStoreArena {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedFlatStoreArena {
    /// Returns whether two handles allocate from the same physical backing.
    pub(super) fn shares_allocation_backing(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

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
        let page_liveness = ReservationPageLiveness::for_backing(&backing);
        Self {
            inner: Rc::new(RefCell::new(backing)),
            rewindable_claimed: Rc::new(Cell::new(false)),
            page_liveness: Rc::new(RefCell::new(page_liveness)),
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
        let backing = SharedFlatStoreBacking::Chunked(arena);
        Ok(Self {
            inner: Rc::new(RefCell::new(backing)),
            rewindable_claimed: Rc::new(Cell::new(false)),
            page_liveness: Rc::new(RefCell::new(ReservationPageLiveness::Disabled)),
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
        let allocation = match &mut *backing {
            SharedFlatStoreBacking::Chunked(arena) => arena.aos_alloc_raw(size, align, kind as u32),
            SharedFlatStoreBacking::Reserved(arena) => reserved_allocation(
                arena.alloc_exclusive(word_rounded_size(size)?, align),
                size,
                kind,
            ),
        }?;
        if let SharedFlatStoreBacking::Reserved(arena) = &*backing {
            if let Ok(index) = arena.index_for_pointer(allocation.ptr) {
                self.page_liveness
                    .borrow_mut()
                    .record(index, allocation.reserved_size);
            } else {
                *self.page_liveness.borrow_mut() = ReservationPageLiveness::Disabled;
            }
        }
        Ok(allocation)
    }

    /// Reserves one raw block for a headerless fixed-stride flat lane.
    ///
    /// The caller owns initialization, exact slot membership, and payload
    /// destruction for the returned range. Keeping this door on the shared
    /// backing ensures headerless values occupy the same Candidate-C domain as
    /// ordinary permanent flat objects.
    pub(super) fn alloc_headerless_block_raw(
        &self,
        size: usize,
        align: usize,
        kind: FlatObjectKind,
    ) -> Result<ArenaAllocation, ArenaError> {
        self.alloc_raw(size, align, kind)
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
        let allocation = reserved_allocation(
            arena.alloc_exclusive_high(word_rounded_size(size)?, align),
            size,
            kind,
        )?;
        if let Ok(index) = arena.index_for_pointer(allocation.ptr) {
            self.page_liveness
                .borrow_mut()
                .record(index, allocation.reserved_size);
        } else {
            *self.page_liveness.borrow_mut() = ReservationPageLiveness::Disabled;
        }
        Ok(allocation)
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
        let old_cursor = arena.high_mark().cursor();
        arena
            .pop_high_caller_validated_to_mark(mark)
            .map_err(|_| ArenaError::InvalidRegionMark)?;
        self.page_liveness
            .borrow_mut()
            .clear_rewound_high_pages(old_cursor, mark.cursor());
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

    /// Samples physical residency when the Candidate-C backend is active.
    ///
    /// Returns `None` for the chunked compatibility backend. A present error
    /// means the operating system rejected the reservation query.
    pub fn reservation_residency(
        &self,
    ) -> Option<Result<ReservedArenaResidency, ReservedArenaError>> {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => Some(arena.residency()),
            SharedFlatStoreBacking::Chunked(_) => None,
        }
    }

    /// Returns the reservation identity encoded into Candidate-C words.
    pub fn arena_domain_id(&self) -> Option<ArenaDomainId> {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => Some(arena.domain_id()),
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

    /// Returns whether the reservation page containing `index` is resident.
    ///
    /// Returns `None` for the chunked compatibility backend. A present error
    /// means the operating system rejected the page-residency query.
    pub fn page_is_resident_at_index(
        &self,
        index: ArenaIndex,
    ) -> Option<Result<bool, ReservedArenaError>> {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => Some(arena.page_is_resident_at_index(index)),
            SharedFlatStoreBacking::Chunked(_) => None,
        }
    }

    /// Discards a caller-proven-dead run of whole Candidate-C pages.
    ///
    /// Returns `None` for the chunked compatibility backend. The reservation
    /// validates page alignment, bounds, and used-lane ownership before
    /// issuing advice.
    ///
    /// # Safety
    ///
    /// Before calling this method, the caller must prove that every typed
    /// allocation intersecting the page run has been tombstoned or moved and
    /// that no live reference can read its former bytes.
    pub unsafe fn advise_dead_pages_caller_validated(
        &self,
        start: ArenaIndex,
        byte_len: usize,
    ) -> Option<Result<ReservedArenaDeadPageAdvice, ReservedArenaDeadPageAdviceError>> {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => {
                // SAFETY: the forwarding method preserves the reservation
                // method's caller proof obligation unchanged.
                Some(unsafe { arena.advise_dead_pages_caller_validated(start, byte_len) })
            }
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

    /// Captures the reservation's domain, capacity, and used-lane bytes for a
    /// Candidate-C heap-image dump (RFC-0007 doc 31 §1, stage 1).
    ///
    /// Returns `None` on the chunked compatibility backend, which is not
    /// address-free and therefore not snapshottable. The two byte vectors are
    /// the permanent (upward) and rewindable (downward) used lanes; see
    /// [`ReservedArena::copy_used_lanes`].
    #[cfg(feature = "candidate_c_value")]
    pub(crate) fn capture_reservation_image(
        &self,
    ) -> Option<(ArenaDomainId, usize, Vec<u8>, Vec<u8>)> {
        match &*self.inner.borrow() {
            SharedFlatStoreBacking::Reserved(arena) => {
                let capacity = arena.stats().virtual_reserved_bytes;
                let (low, high) = arena.copy_used_lanes();
                Some((arena.domain_id(), capacity, low, high))
            }
            SharedFlatStoreBacking::Chunked(_) => None,
        }
    }

    /// Wraps a reloaded Candidate-C reservation as a serial shared flat arena.
    ///
    /// Used by [`crate::heap::snapshot`] to present a restored heap image through
    /// the same handle production allocation uses. The rewindable high lane is
    /// unclaimed: a restored image is read as an immortal prelude generation
    /// (doc 31 §6.3), not region-popped.
    #[cfg(feature = "candidate_c_value")]
    pub(crate) fn from_reserved(arena: ReservedArena) -> Self {
        Self {
            inner: Rc::new(RefCell::new(SharedFlatStoreBacking::Reserved(arena))),
            rewindable_claimed: Rc::new(Cell::new(false)),
            // Restored typed registries are adopted after this constructor, so
            // allocation-time page counts cannot be reconstructed here.
            page_liveness: Rc::new(RefCell::new(ReservationPageLiveness::Disabled)),
        }
    }

    /// Records successful destruction of one exact flat allocation.
    pub(super) fn retire_raw(&self, ptr: NonNull<HeapObject>, byte_len: usize) {
        let SharedFlatStoreBacking::Reserved(arena) = &*self.inner.borrow() else {
            return;
        };
        let Ok(index) = arena.index_for_pointer(ptr) else {
            *self.page_liveness.borrow_mut() = ReservationPageLiveness::Disabled;
            return;
        };
        let Ok(reserved_size) = word_rounded_size(byte_len) else {
            *self.page_liveness.borrow_mut() = ReservationPageLiveness::Disabled;
            return;
        };
        self.page_liveness.borrow_mut().retire(index, reserved_size);
    }

    /// Discards whole used-lane pages with no arena-tracked typed allocation.
    ///
    /// The operation is unavailable for chunked or restored backings and
    /// fails closed if allocation accounting could not be maintained.
    ///
    /// # Errors
    ///
    /// Returns a validation error if the reservation rejects a run selected
    /// from its current lane geometry.
    pub fn advise_zero_liveness_pages(
        &self,
    ) -> Option<Result<SharedReservationZeroPageAdviceReport, ReservedArenaDeadPageAdviceError>>
    {
        let backing = self.inner.borrow();
        let SharedFlatStoreBacking::Reserved(arena) = &*backing else {
            return None;
        };
        let liveness = self.page_liveness.borrow();
        let ReservationPageLiveness::Tracking { page_size, counts } = &*liveness else {
            return None;
        };
        let stats = arena.stats();
        let low_pages = stats.low_used_bytes / *page_size;
        let high_start = stats
            .virtual_reserved_bytes
            .saturating_sub(stats.high_used_bytes);
        let high_first_page = high_start.div_ceil(*page_size);
        let reservation_pages = counts.len();
        let mut report = SharedReservationZeroPageAdviceReport::default();

        let mut scan = |first: usize, end: usize| -> Result<(), ReservedArenaDeadPageAdviceError> {
            let mut page = first;
            while page < end {
                if counts[page] != 0 {
                    page += 1;
                    continue;
                }
                let run_start = page;
                while page < end && counts[page] == 0 {
                    page += 1;
                }
                let run_pages = page - run_start;
                report.candidate_pages = report.candidate_pages.saturating_add(run_pages);
                report.runs = report.runs.saturating_add(1);
                let start_bytes = run_start
                    .checked_mul(*page_size)
                    .ok_or(ReservedArenaDeadPageAdviceError::RangeOverflow)?;
                let byte_len = run_pages
                    .checked_mul(*page_size)
                    .ok_or(ReservedArenaDeadPageAdviceError::RangeOverflow)?;
                let start = u32::try_from(start_bytes)
                    .map_err(|_| ReservedArenaDeadPageAdviceError::RangeOverflow)?;
                // SAFETY: every allocation door increments each intersected
                // page before returning the typed storage, and successful
                // destruction decrements it only after payload drop. A zero
                // count therefore proves that no live typed allocation
                // intersects this whole used-lane page run.
                let advice = unsafe {
                    arena.advise_dead_pages_caller_validated(ArenaIndex::new(start), byte_len)
                }?;
                if matches!(
                    advice.outcome(),
                    MemoryAdviceOutcome::Applied {
                        kind: MemoryAdviceKind::Dead
                    }
                ) {
                    report.applied_pages = report.applied_pages.saturating_add(run_pages);
                }
            }
            Ok(())
        };
        if let Err(error) = scan(0, low_pages) {
            return Some(Err(error));
        }
        if let Err(error) = scan(high_first_page, reservation_pages) {
            return Some(Err(error));
        }
        Some(Ok(report))
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
