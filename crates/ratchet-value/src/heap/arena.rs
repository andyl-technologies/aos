//! Tier-A one-shot bump arena.
//!
//! This is the Tier-A allocator substrate for the tree-walk oracle. It
//! reserves aligned slots in anonymous `mmap` chunks, returns opaque
//! [`HeapObject`] handles, and never frees individual allocations. The
//! implementation deliberately avoids raw memory writes until concrete heap
//! object layouts exist.

use std::cell::RefCell;
use std::mem;
use std::ptr;

use thiserror::Error;

use super::{MemoryAdviceKind, MemoryAdviceOutcome, MemoryAdviceRange, advise_range};
use crate::value::{HeapObject, Value};

const DEFAULT_CHUNK_BYTES: usize = 2 * 1024 * 1024;
const WORD_BYTES: usize = mem::size_of::<u64>();
const MAX_ALIGN: usize = mem::align_of::<u64>();
const OBJECT_HEADER_BYTES: usize = 2 * WORD_BYTES;
const THUNK_BYTES: usize = 3 * WORD_BYTES;
const LAMBDA_BYTES: usize = 4 * WORD_BYTES;
// Header plus u32 length, padded so the inline Value tail starts 8-byte aligned.
const LIST_ELEMENTS_OFFSET_BYTES: usize = OBJECT_HEADER_BYTES + WORD_BYTES;
const CONS_BYTES: usize = OBJECT_HEADER_BYTES + mem::size_of::<Value>() + WORD_BYTES;
const MAX_MMAP_BYTES: usize = isize::MAX as usize;

#[cfg(any(target_os = "android", target_os = "linux"))]
const MAP_ANONYMOUS_FLAG: libc::c_int = libc::MAP_ANONYMOUS;

#[cfg(not(any(target_os = "android", target_os = "linux")))]
const MAP_ANONYMOUS_FLAG: libc::c_int = libc::MAP_ANON;

/// The logical heap object kind requested through an allocation entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapObjectKind {
    /// A suspended thunk object.
    Thunk,
    /// A user lambda closure object.
    Lambda,
    /// An attribute set with `slots` value cells.
    Attrs {
        /// The hidden-class shape id associated with the attrset.
        shape: u32,
        /// The number of value slots requested.
        slots: u32,
    },
    /// A list cons cell.
    Cons,
    /// A contiguous list spine with `len` elements.
    List {
        /// The number of value cells requested.
        len: u32,
    },
    /// A byte string payload with `len` bytes.
    String {
        /// The byte length requested for the string payload.
        len: usize,
    },
    /// A raw allocation for a future concrete runtime type.
    Raw {
        /// Runtime-specific type tag carried for diagnostics and future GC
        /// layout selection.
        type_tag: u32,
    },
}

/// One allocation returned by the bump arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaAllocation {
    /// The opaque heap-object address reserved for this allocation.
    pub ptr: std::ptr::NonNull<HeapObject>,
    /// The logical object kind requested by the caller.
    pub kind: HeapObjectKind,
    /// The caller-requested payload size in bytes.
    pub requested_size: usize,
    /// The actual bump distance in bytes after alignment and word rounding.
    pub reserved_size: usize,
    /// The requested alignment in bytes.
    pub align: usize,
}

/// Current bump-arena accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArenaStats {
    /// Number of chunks currently owned by the arena.
    pub chunks: usize,
    /// Logical bytes reserved by all chunks for bump allocation.
    pub reserved_bytes: usize,
    /// Page-rounded bytes mapped from the host OS.
    pub mapped_bytes: usize,
    /// Number of bytes consumed by allocations, including alignment padding and
    /// word rounding.
    pub used_bytes: usize,
}

/// A LIFO marker for a future lexical allocation subregion.
///
/// Markers are produced by [`BumpArena::region_mark`] and can be passed back to
/// [`BumpArena::pop_region_to_mark`] once the caller has proven that every
/// allocation above the marker is dead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaRegionMark {
    chunk_count: usize,
    cursor: usize,
    next_chunk_bytes: usize,
}

impl ArenaRegionMark {
    /// Returns the number of chunks present when the marker was captured.
    pub const fn chunk_count(self) -> usize {
        self.chunk_count
    }

    /// Returns the bump cursor in the last retained chunk.
    pub const fn cursor(self) -> usize {
        self.cursor
    }
}

/// Accounting returned after popping a lexical allocation subregion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaRegionPopReport {
    before: ArenaStats,
    after: ArenaStats,
    used_bytes_released: usize,
    released_mapped_bytes: usize,
    dead_range_bytes: usize,
    dead_range_outcome: MemoryAdviceOutcome,
}

impl ArenaRegionPopReport {
    const fn new(
        before: ArenaStats,
        after: ArenaStats,
        released_mapped_bytes: usize,
        dead_range_bytes: usize,
        dead_range_outcome: MemoryAdviceOutcome,
    ) -> Self {
        Self {
            before,
            after,
            used_bytes_released: before.used_bytes.saturating_sub(after.used_bytes),
            released_mapped_bytes,
            dead_range_bytes,
            dead_range_outcome,
        }
    }

    /// Returns arena accounting before the region pop.
    pub const fn before_stats(self) -> ArenaStats {
        self.before
    }

    /// Returns arena accounting after the region pop.
    pub const fn after_stats(self) -> ArenaStats {
        self.after
    }

    /// Returns used bytes made unavailable by cursor rewind or chunk release.
    pub const fn used_bytes_released(self) -> usize {
        self.used_bytes_released
    }

    /// Returns mapped bytes released by dropping whole chunks above the marker.
    pub const fn released_mapped_bytes(self) -> usize {
        self.released_mapped_bytes
    }

    /// Returns retained-chunk bytes made dead by rewinding the bump cursor.
    pub const fn dead_range_bytes(self) -> usize {
        self.dead_range_bytes
    }

    /// Returns the advisory outcome for the retained-chunk dead range.
    pub const fn dead_range_outcome(self) -> MemoryAdviceOutcome {
        self.dead_range_outcome
    }
}

/// Summary of memory advice applied to one bump arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaMemoryAdviceReport {
    kind: MemoryAdviceKind,
    chunks: usize,
    requested_bytes: usize,
    applied: usize,
    unsupported: usize,
    empty: usize,
    rejected: usize,
}

impl ArenaMemoryAdviceReport {
    const fn for_kind(kind: MemoryAdviceKind) -> Self {
        Self {
            kind,
            chunks: 0,
            requested_bytes: 0,
            applied: 0,
            unsupported: 0,
            empty: 0,
            rejected: 0,
        }
    }

    fn record(&mut self, requested_bytes: usize, outcome: MemoryAdviceOutcome) {
        self.chunks = self.chunks.saturating_add(1);
        self.requested_bytes = self.requested_bytes.saturating_add(requested_bytes);
        match outcome {
            MemoryAdviceOutcome::Applied { .. } => {
                self.applied = self.applied.saturating_add(1);
            }
            MemoryAdviceOutcome::Unsupported { .. } => {
                self.unsupported = self.unsupported.saturating_add(1);
            }
            MemoryAdviceOutcome::EmptyRange { .. } => {
                self.empty = self.empty.saturating_add(1);
            }
            MemoryAdviceOutcome::Rejected { .. } => {
                self.rejected = self.rejected.saturating_add(1);
            }
        }
    }

    /// Returns the field-wise sum of two advice reports.
    ///
    /// Used when one logical allocation domain spans more than one arena
    /// (the evaluator's permanent domain plus the flat-object store). Keeps
    /// `self`'s advice kind; callers pass reports produced for the same kind.
    pub fn merged(self, other: Self) -> Self {
        Self {
            kind: self.kind,
            chunks: self.chunks.saturating_add(other.chunks),
            requested_bytes: self.requested_bytes.saturating_add(other.requested_bytes),
            applied: self.applied.saturating_add(other.applied),
            unsupported: self.unsupported.saturating_add(other.unsupported),
            empty: self.empty.saturating_add(other.empty),
            rejected: self.rejected.saturating_add(other.rejected),
        }
    }

    /// Returns the advice kind requested for every chunk tail.
    pub const fn kind(self) -> MemoryAdviceKind {
        self.kind
    }

    /// Returns how many arena chunks were considered.
    pub const fn chunks(self) -> usize {
        self.chunks
    }

    /// Returns the total unused-tail bytes passed to the advice shim.
    pub const fn requested_bytes(self) -> usize {
        self.requested_bytes
    }

    /// Returns how many chunk-tail advice calls the operating system accepted.
    pub const fn applied(self) -> usize {
        self.applied
    }

    /// Returns how many chunk-tail advice calls had no platform lowering.
    pub const fn unsupported(self) -> usize {
        self.unsupported
    }

    /// Returns how many chunk tails contained no complete page to advise.
    pub const fn empty_ranges(self) -> usize {
        self.empty
    }

    /// Returns how many chunk-tail advice calls the platform rejected.
    pub const fn rejected(self) -> usize {
        self.rejected
    }
}

/// A safe API over a never-free bump arena for one evaluator invocation.
#[derive(Debug)]
pub struct BumpArena {
    chunks: Vec<Chunk>,
    next_chunk_bytes: usize,
    /// Optional ceiling on geometric chunk growth.
    ///
    /// The default (`None`) doubles every chunk without bound, which keeps
    /// chunk counts logarithmic but lets the *mapped* peak run ahead of the
    /// used bytes by up to one whole doubling step. Byte-heavy owners (the
    /// flat object stores, doc 30 FV-1) cap growth so their mapped peak
    /// tracks the payload mass linearly past the cap.
    max_chunk_bytes: Option<usize>,
}

thread_local! {
    static THREAD_LOCAL_ARENA: RefCell<BumpArena> = RefCell::new(BumpArena::new());
}

impl Default for BumpArena {
    fn default() -> Self {
        Self::new()
    }
}

impl BumpArena {
    /// Creates an empty arena using the default first chunk size.
    pub const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            next_chunk_bytes: DEFAULT_CHUNK_BYTES,
            max_chunk_bytes: None,
        }
    }

    /// Creates an empty arena with an explicit first chunk size.
    ///
    /// The size is rounded up to the arena word size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        if chunk_bytes == 0 {
            return Err(ArenaError::InvalidChunkSize { chunk_bytes });
        }
        Ok(Self {
            chunks: Vec::new(),
            next_chunk_bytes: round_up(chunk_bytes, WORD_BYTES)?,
            max_chunk_bytes: None,
        })
    }

    /// Caps geometric chunk growth at `max_chunk_bytes` per chunk.
    ///
    /// Growth still doubles up to the cap and single oversized allocations
    /// still get a chunk of their own exact size; only the *default* next
    /// chunk size stops doubling. A zero cap is ignored.
    pub fn limit_chunk_growth(&mut self, max_chunk_bytes: usize) {
        if max_chunk_bytes == 0 {
            return;
        }
        self.max_chunk_bytes = Some(max_chunk_bytes);
        self.next_chunk_bytes = self.next_chunk_bytes.min(max_chunk_bytes);
    }

    /// Returns current chunk and byte accounting.
    pub fn stats(&self) -> ArenaStats {
        let mut stats = ArenaStats {
            chunks: self.chunks.len(),
            reserved_bytes: 0,
            mapped_bytes: 0,
            used_bytes: 0,
        };
        for chunk in &self.chunks {
            stats.reserved_bytes += chunk.capacity_bytes();
            stats.mapped_bytes += chunk.mapped_bytes();
            stats.used_bytes += chunk.cursor;
        }
        stats
    }

    /// Returns whether no allocation has been served yet.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Returns each chunk's `(start, end)` logical byte region.
    ///
    /// Regions cover the chunks' reserved bump capacity, so every address this
    /// arena has handed out (and every address it can still hand out) lies in
    /// exactly one region. Used by the flat-object store's membership check.
    pub fn chunk_regions(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.chunks.iter().map(|chunk| {
            let start = chunk.ptr.as_ptr() as usize;
            (start, start.saturating_add(chunk.capacity_bytes()))
        })
    }

    /// Captures the current bump position for a future lexical subregion pop.
    pub fn region_mark(&self) -> ArenaRegionMark {
        let (chunk_count, cursor) = self
            .chunks
            .last()
            .map(|chunk| (self.chunks.len(), chunk.cursor))
            .unwrap_or((0, 0));
        ArenaRegionMark {
            chunk_count,
            cursor,
            next_chunk_bytes: self.next_chunk_bytes,
        }
    }

    /// Rewinds this arena to a previously captured lexical subregion marker.
    ///
    /// The retained chunk's newly-dead suffix receives
    /// [`MemoryAdviceKind::Dead`] advice. Whole chunks above the marker are
    /// dropped, which releases their mappings through [`Drop`] instead of
    /// issuing advice first. The marker also restores the arena's geometric
    /// next-chunk size so temporary large regions do not perturb later growth.
    ///
    /// # Safety
    ///
    /// The caller must prove that `mark` was captured from this arena, describes
    /// the current innermost live region in LIFO order, and has not been made
    /// stale by an intervening pop. The caller must also prove that no live
    /// [`HeapObject`] handle, [`Value`], or typed heap side-table entry still
    /// refers to any allocation performed after `mark` was captured. Structural
    /// validation does not prove marker freshness, arena identity, or LIFO
    /// discipline. Passing a stale or cross-arena marker, or continuing to use a
    /// rewound allocation, can produce dangling logical heap references.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidRegionMark`] if the marker cannot describe
    /// the arena's current prefix.
    pub unsafe fn pop_region_to_mark(
        &mut self,
        mark: ArenaRegionMark,
    ) -> Result<ArenaRegionPopReport, ArenaError> {
        self.validate_region_mark(mark)?;

        let before = self.stats();
        let released_mapped_bytes = self.chunks[mark.chunk_count..]
            .iter()
            .fold(0usize, |bytes, chunk| {
                bytes.saturating_add(chunk.mapped_bytes())
            });
        let mut dead_range_bytes = 0usize;
        let mut dead_range_outcome = MemoryAdviceOutcome::EmptyRange {
            kind: MemoryAdviceKind::Dead,
        };

        if mark.chunk_count == 0 {
            self.chunks.clear();
        } else {
            let retained_index = mark.chunk_count - 1;
            let retained_cursor = self.chunks[retained_index].cursor;
            dead_range_bytes = retained_cursor.saturating_sub(mark.cursor);
            if dead_range_bytes != 0 {
                let range = self.chunks[retained_index].range_between(mark.cursor, retained_cursor);
                dead_range_outcome = advise_range(MemoryAdviceKind::Dead, range);
            }
            self.chunks.truncate(mark.chunk_count);
            if let Some(chunk) = self.chunks.last_mut() {
                chunk.cursor = mark.cursor;
            }
        }
        self.next_chunk_bytes = mark.next_chunk_bytes;

        Ok(ArenaRegionPopReport::new(
            before,
            self.stats(),
            released_mapped_bytes,
            dead_range_bytes,
            dead_range_outcome,
        ))
    }

    /// Advises unused bytes at the end of every arena chunk.
    ///
    /// This method never advises bytes below a chunk's bump cursor, so live
    /// allocations are excluded. The advice shim trims each tail to complete
    /// pages before calling the operating system, and later allocations may
    /// reuse the advised tail without changing arena accounting.
    pub fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        let mut report = ArenaMemoryAdviceReport::for_kind(kind);
        for chunk in &self.chunks {
            let range = chunk.unused_tail_range();
            report.record(range.len(), advise_range(kind, range));
        }
        report
    }

    /// Returns unused-tail bytes this platform can lower to page advice.
    ///
    /// Non-Linux platforms return zero because the advice shim reports
    /// unsupported outcomes there. Linux counts only complete pages wholly
    /// contained in each chunk tail, matching the shim's page trimming.
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        if !cfg!(target_os = "linux") {
            return 0;
        }
        let Ok(page_size) = system_page_size() else {
            return 0;
        };
        self.chunks.iter().fold(0usize, |bytes, chunk| {
            bytes.saturating_add(chunk.supported_unused_tail_advice_bytes(page_size))
        })
    }

    /// Allocates a thunk-sized object through the Phase-1 `aos_alloc_thunk`
    /// entry-point shape.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the allocation size overflows or the chunk
    /// storage cannot be reserved.
    pub fn aos_alloc_thunk(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(THUNK_BYTES, MAX_ALIGN, HeapObjectKind::Thunk)
    }

    /// Allocates a lambda-sized object through the Phase-1 `aos_alloc_lambda`
    /// entry point.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if reserving the object would overflow or if a new
    /// chunk cannot be allocated.
    pub fn aos_alloc_lambda(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(LAMBDA_BYTES, MAX_ALIGN, HeapObjectKind::Lambda)
    }

    /// Allocates an attrset object through the Phase-1 `aos_alloc_attrs`
    /// entry-point shape.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the object size overflows or the chunk storage
    /// cannot be reserved.
    pub fn aos_alloc_attrs(
        &mut self,
        shape: u32,
        slots: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        let slot_count = usize::try_from(slots).map_err(|_| ArenaError::SizeOverflow)?;
        let values = slot_count
            .checked_mul(mem::size_of::<Value>())
            .ok_or(ArenaError::SizeOverflow)?;
        let size = OBJECT_HEADER_BYTES
            .checked_add(values)
            .ok_or(ArenaError::SizeOverflow)?;
        self.allocate(size, MAX_ALIGN, HeapObjectKind::Attrs { shape, slots })
    }

    /// Allocates a list cons cell through the Phase-1 `aos_alloc_cons`
    /// entry-point shape.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the allocation size overflows or the chunk
    /// storage cannot be reserved.
    pub fn aos_alloc_cons(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(CONS_BYTES, MAX_ALIGN, HeapObjectKind::Cons)
    }

    /// Allocates a contiguous list object through the Phase-1 `aos_alloc_list`
    /// entry-point shape.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if `len` does not fit the runtime list header, if
    /// the object size overflows, or if the chunk storage cannot be reserved.
    pub fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let header_len = u32::try_from(len).map_err(|_| ArenaError::SizeOverflow)?;
        let elements = len
            .checked_mul(mem::size_of::<Value>())
            .ok_or(ArenaError::SizeOverflow)?;
        let size = LIST_ELEMENTS_OFFSET_BYTES
            .checked_add(elements)
            .ok_or(ArenaError::SizeOverflow)?;
        self.allocate(size, MAX_ALIGN, HeapObjectKind::List { len: header_len })
    }

    /// Allocates a string object through the Phase-1 `aos_alloc_string`
    /// entry-point shape.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the object size overflows or the chunk storage
    /// cannot be reserved.
    pub fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let size = OBJECT_HEADER_BYTES
            .checked_add(len)
            .ok_or(ArenaError::SizeOverflow)?;
        self.allocate(size, MAX_ALIGN, HeapObjectKind::String { len })
    }

    /// Allocates raw heap storage through the Phase-1 `aos_alloc_raw`
    /// entry-point shape.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidAlignment`] when `align` is zero, not a
    /// power of two, or larger than the Phase-1 heap-object alignment. Returns
    /// [`ArenaError::SizeOverflow`] if rounding the size overflows. Returns
    /// [`ArenaError::AllocationFailed`] if chunk storage cannot be reserved.
    pub fn aos_alloc_raw(
        &mut self,
        size: usize,
        align: usize,
        type_tag: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(size, align, HeapObjectKind::Raw { type_tag })
    }

    fn allocate(
        &mut self,
        requested_size: usize,
        align: usize,
        kind: HeapObjectKind,
    ) -> Result<ArenaAllocation, ArenaError> {
        validate_align(align)?;
        let reserved_size = round_up(requested_size.max(1), WORD_BYTES)?;
        self.ensure_chunk(reserved_size, align)?;
        let chunk = self
            .chunks
            .last_mut()
            .ok_or(ArenaError::InternalMissingChunk)?;
        let ptr = chunk.allocate(reserved_size, align)?;
        Ok(ArenaAllocation {
            ptr,
            kind,
            requested_size,
            reserved_size,
            align,
        })
    }

    fn ensure_chunk(&mut self, size: usize, align: usize) -> Result<(), ArenaError> {
        if self
            .chunks
            .last()
            .is_some_and(|chunk| chunk.can_fit(size, align))
        {
            return Ok(());
        }

        let chunk_bytes = self.next_chunk_bytes.max(round_up(size, WORD_BYTES)?);
        self.chunks
            .try_reserve_exact(1)
            .map_err(|_| ArenaError::AllocationFailed {
                bytes: mem::size_of::<Chunk>(),
            })?;
        let chunk = Chunk::new(chunk_bytes)?;
        self.chunks.push(chunk);
        if let Some(next_chunk_bytes) = self.next_chunk_bytes.checked_mul(2) {
            self.next_chunk_bytes = match self.max_chunk_bytes {
                Some(max_chunk_bytes) => next_chunk_bytes.min(max_chunk_bytes),
                None => next_chunk_bytes,
            };
        }
        Ok(())
    }

    fn validate_region_mark(&self, mark: ArenaRegionMark) -> Result<(), ArenaError> {
        if mark.chunk_count == 0 {
            if mark.cursor == 0 {
                return Ok(());
            }
            return Err(ArenaError::InvalidRegionMark);
        }
        if mark.chunk_count > self.chunks.len() {
            return Err(ArenaError::InvalidRegionMark);
        }
        let retained = &self.chunks[mark.chunk_count - 1];
        if mark.cursor > retained.cursor {
            return Err(ArenaError::InvalidRegionMark);
        }
        Ok(())
    }
}

/// Access to the Tier-A arena owned by the current evaluator worker thread.
///
/// Each OS thread receives an independent never-free bump arena. This is the
/// allocation substrate for the Phase-3 per-worker model; the sequential
/// tree-walk oracle may still own an explicit [`BumpArena`] directly when it
/// needs deterministic per-evaluation accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadLocalBumpArena;

impl ThreadLocalBumpArena {
    /// Runs `f` with mutable access to the current thread's Tier-A arena.
    ///
    /// # Panics
    ///
    /// Panics if `f` re-enters [`ThreadLocalBumpArena::with_current`] or
    /// [`ThreadLocalBumpArena::reset_current`] on the same thread before the
    /// outer borrow returns.
    pub fn with_current<R>(f: impl FnOnce(&mut BumpArena) -> R) -> R {
        THREAD_LOCAL_ARENA.with(|arena| f(&mut arena.borrow_mut()))
    }

    /// Drops the current thread's arena and replaces it with an empty one.
    ///
    /// Returns the accounting from the dropped arena so callers can record
    /// per-worker allocation totals before reset.
    ///
    /// # Panics
    ///
    /// Panics if the current thread's arena is already mutably borrowed through
    /// [`ThreadLocalBumpArena::with_current`].
    pub fn reset_current() -> ArenaStats {
        THREAD_LOCAL_ARENA.with(|arena| {
            let mut arena = arena.borrow_mut();
            let previous = mem::take(&mut *arena);
            let stats = previous.stats();
            drop(previous);
            stats
        })
    }
}

#[derive(Debug)]
struct Chunk {
    ptr: std::ptr::NonNull<u8>,
    logical_bytes: usize,
    mapped_bytes: usize,
    cursor: usize,
}

// SAFETY: `Chunk` uniquely owns an anonymous mapping returned by `mmap`, and
// the mapping is not tied to the thread that created it. Mutation of the bump
// cursor requires `&mut Chunk`; shared references expose only immutable metadata.
// Dropping a moved `Chunk` on another thread calls `munmap` with the exact
// owned mapping address and length.
unsafe impl Send for Chunk {}

// SAFETY: Shared `&Chunk` access cannot mutate the cursor or the mapped bytes,
// and the raw mapping pointer is never dereferenced through shared references.
// All allocation and unmapping require unique ownership or `&mut Chunk`.
unsafe impl Sync for Chunk {}

impl Chunk {
    fn new(bytes: usize) -> Result<Self, ArenaError> {
        let logical_bytes = round_up(bytes, WORD_BYTES)?;
        if logical_bytes == 0 {
            return Err(ArenaError::InvalidChunkSize { chunk_bytes: bytes });
        }
        if logical_bytes > MAX_MMAP_BYTES {
            return Err(ArenaError::AllocationFailed {
                bytes: logical_bytes,
            });
        }
        let mapped_bytes = round_up(logical_bytes, system_page_size()?)?;
        if mapped_bytes > MAX_MMAP_BYTES {
            return Err(ArenaError::AllocationFailed {
                bytes: logical_bytes,
            });
        }

        let raw_ptr = {
            // SAFETY: The mapping request uses a null address hint, a non-zero
            // page-rounded length, read/write protection, and an anonymous
            // private mapping with `fd = -1`, as required by POSIX mmap for
            // anonymous memory. The returned pointer is checked for
            // `MAP_FAILED` and null before it is stored.
            unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    mapped_bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | MAP_ANONYMOUS_FLAG,
                    -1,
                    0,
                )
            }
        };
        if raw_ptr == libc::MAP_FAILED {
            return Err(ArenaError::AllocationFailed {
                bytes: logical_bytes,
            });
        }
        if raw_ptr.is_null() {
            // SAFETY: A null return that is not `MAP_FAILED` is still a mapping
            // returned by `mmap`; this arena cannot represent null heap handles,
            // so it immediately releases the mapping with the exact length.
            unsafe {
                libc::munmap(raw_ptr, mapped_bytes);
            }
            return Err(ArenaError::NullChunkPointer);
        }
        let ptr =
            std::ptr::NonNull::new(raw_ptr.cast::<u8>()).ok_or(ArenaError::NullChunkPointer)?;
        super::gauges::record_chunk_mapped(mapped_bytes);
        Ok(Self {
            ptr,
            logical_bytes,
            mapped_bytes,
            cursor: 0,
        })
    }

    fn capacity_bytes(&self) -> usize {
        self.logical_bytes
    }

    fn mapped_bytes(&self) -> usize {
        self.mapped_bytes
    }

    fn can_fit(&self, size: usize, align: usize) -> bool {
        let Ok(start) = align_up(self.cursor, align) else {
            return false;
        };
        let Some(end) = start.checked_add(size) else {
            return false;
        };
        end <= self.capacity_bytes()
    }

    fn allocate(
        &mut self,
        size: usize,
        align: usize,
    ) -> Result<std::ptr::NonNull<HeapObject>, ArenaError> {
        let start = align_up(self.cursor, align)?;
        let end = start.checked_add(size).ok_or(ArenaError::SizeOverflow)?;
        if end > self.capacity_bytes() {
            return Err(ArenaError::ChunkExhausted);
        }
        let base = self.ptr.as_ptr();
        let ptr = std::ptr::NonNull::new(base.wrapping_add(start).cast::<HeapObject>())
            .ok_or(ArenaError::NullChunkPointer)?;
        self.cursor = end;
        Ok(ptr)
    }

    fn unused_tail_range(&self) -> MemoryAdviceRange {
        let len = self.mapped_bytes.saturating_sub(self.cursor);
        if len == 0 {
            return MemoryAdviceRange::empty();
        }
        let ptr = self.ptr.as_ptr().wrapping_add(self.cursor);
        let Some(ptr) = std::ptr::NonNull::new(ptr) else {
            return MemoryAdviceRange::empty();
        };
        // SAFETY: `ptr` starts inside this chunk's live anonymous mapping at the
        // current bump cursor, and `len` extends only to the mapping end. Bytes
        // at or above the cursor have not been handed out as live heap objects.
        unsafe { MemoryAdviceRange::from_raw_parts(ptr, len) }
    }

    fn supported_unused_tail_advice_bytes(&self, page_size: usize) -> usize {
        supported_advice_bytes_in_range(self.unused_tail_range(), page_size)
    }

    fn range_between(&self, start: usize, end: usize) -> MemoryAdviceRange {
        if start >= end || end > self.mapped_bytes {
            return MemoryAdviceRange::empty();
        }
        let ptr = self.ptr.as_ptr().wrapping_add(start);
        let Some(ptr) = std::ptr::NonNull::new(ptr) else {
            return MemoryAdviceRange::empty();
        };
        // SAFETY: `start..end` has been validated to lie within this chunk's
        // live anonymous mapping. Callers use this only for allocation ranges
        // proven dead by a region-pop marker.
        unsafe { MemoryAdviceRange::from_raw_parts(ptr, end - start) }
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        let rc = {
            // SAFETY: `ptr` and `mapped_bytes` are exactly the address and
            // length returned by a successful anonymous `mmap` in `Chunk::new`,
            // and `Chunk` owns that mapping until this drop runs.
            unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.mapped_bytes) }
        };
        super::gauges::record_chunk_unmapped(self.mapped_bytes);
        if rc != 0 {
            debug_assert!(
                false,
                "munmap failed for arena chunk: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// A bump-arena allocation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ArenaError {
    /// A configured chunk size was zero.
    #[error("invalid arena chunk size {chunk_bytes}")]
    InvalidChunkSize {
        /// The rejected chunk size.
        chunk_bytes: usize,
    },
    /// An allocation requested an unsupported alignment.
    #[error("invalid arena allocation alignment {align}")]
    InvalidAlignment {
        /// The rejected alignment.
        align: usize,
    },
    /// An allocation size computation overflowed.
    #[error("arena allocation size overflow")]
    SizeOverflow,
    /// The host page size could not be read.
    #[error("arena failed to read the host page size")]
    PageSizeUnavailable,
    /// Arena storage could not be reserved.
    #[error("arena failed to reserve {bytes} bytes of storage")]
    AllocationFailed {
        /// The rejected chunk or metadata reservation size in bytes.
        bytes: usize,
    },
    /// A chunk was unexpectedly unavailable after growth.
    #[error("arena did not contain a chunk after growth")]
    InternalMissingChunk,
    /// A chunk did not have enough remaining space after selection.
    #[error("arena chunk exhausted unexpectedly")]
    ChunkExhausted,
    /// A chunk base pointer was unexpectedly null.
    #[error("arena chunk base pointer was null")]
    NullChunkPointer,
    /// A lexical subregion marker did not match the current arena prefix.
    #[error("invalid arena region mark")]
    InvalidRegionMark,
}

fn validate_align(align: usize) -> Result<(), ArenaError> {
    if align == 0 || !align.is_power_of_two() || align > MAX_ALIGN {
        return Err(ArenaError::InvalidAlignment { align });
    }
    Ok(())
}

fn align_up(value: usize, align: usize) -> Result<usize, ArenaError> {
    debug_assert!(align.is_power_of_two());
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or(ArenaError::SizeOverflow)
}

fn round_up(value: usize, align: usize) -> Result<usize, ArenaError> {
    align_up(value, align)
}

fn supported_advice_bytes_in_range(range: MemoryAdviceRange, page_size: usize) -> usize {
    if range.is_empty() || page_size == 0 {
        return 0;
    }
    let start = range.ptr().as_ptr() as usize;
    let Some(end) = start.checked_add(range.len()) else {
        return 0;
    };
    let Some(aligned_start) = round_up_to_multiple(start, page_size) else {
        return 0;
    };
    let aligned_end = round_down_to_multiple(end, page_size);
    aligned_end.saturating_sub(aligned_start)
}

fn round_up_to_multiple(value: usize, multiple: usize) -> Option<usize> {
    debug_assert!(multiple != 0);
    let remainder = value % multiple;
    if remainder == 0 {
        return Some(value);
    }
    value.checked_add(multiple - remainder)
}

fn round_down_to_multiple(value: usize, multiple: usize) -> usize {
    debug_assert!(multiple != 0);
    value - (value % multiple)
}

fn system_page_size() -> Result<usize, ArenaError> {
    let page_size = {
        // SAFETY: `sysconf(_SC_PAGESIZE)` is a side-effect-free libc query. The
        // return value is validated before conversion to `usize`.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
    };
    if page_size <= 0 {
        return Err(ArenaError::PageSizeUnavailable);
    }
    usize::try_from(page_size).map_err(|_| ArenaError::PageSizeUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn arena_handles_are_send_sync_for_worker_handoff() {
        assert_send_sync::<BumpArena>();
        assert_send_sync::<ThreadLocalBumpArena>();
    }

    #[test]
    fn empty_arena_has_no_chunks() {
        let arena = BumpArena::new();
        assert!(arena.is_empty());
        assert_eq!(arena.stats(), ArenaStats::default());
    }

    #[test]
    fn empty_arena_advice_reports_no_chunk_tails() {
        let arena = BumpArena::new();
        let report = arena.advise_unused_tail(MemoryAdviceKind::Dead);

        assert_eq!(arena.supported_unused_tail_advice_bytes(), 0);
        assert_eq!(report.kind(), MemoryAdviceKind::Dead);
        assert_eq!(report.chunks(), 0);
        assert_eq!(report.requested_bytes(), 0);
        assert_eq!(report.applied(), 0);
        assert_eq!(report.unsupported(), 0);
        assert_eq!(report.empty_ranges(), 0);
        assert_eq!(report.rejected(), 0);
    }

    #[test]
    fn custom_initial_chunk_size_is_word_rounded() {
        let mut arena = BumpArena::with_initial_chunk_bytes(9).expect("arena creates");
        let allocation = arena
            .aos_alloc_raw(1, 1, 7)
            .expect("raw allocation succeeds");
        assert_eq!(allocation.reserved_size, WORD_BYTES);
        let stats = arena.stats();
        assert_eq!(stats.reserved_bytes, 16);
        assert!(stats.mapped_bytes >= system_page_size().expect("page size"));
    }

    #[test]
    fn unused_tail_advice_excludes_live_prefix_and_preserves_accounting() {
        let page_size = system_page_size().expect("page size");
        let chunk_bytes = page_size.checked_mul(2).expect("two pages fit");
        let mut arena = BumpArena::with_initial_chunk_bytes(chunk_bytes).expect("arena creates");
        let first = arena
            .aos_alloc_raw(1, 1, 7)
            .expect("first allocation succeeds");
        let stats_before = arena.stats();
        let supported_tail_advice_bytes = arena.supported_unused_tail_advice_bytes();

        let report = arena.advise_unused_tail(MemoryAdviceKind::Dead);

        assert_eq!(report.kind(), MemoryAdviceKind::Dead);
        assert_eq!(report.chunks(), 1);
        assert_eq!(
            report.requested_bytes(),
            stats_before.mapped_bytes - stats_before.used_bytes
        );
        assert_eq!(
            report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
            1
        );
        #[cfg(target_os = "linux")]
        assert_eq!(report.applied(), 1);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(report.unsupported(), 1);
        #[cfg(target_os = "linux")]
        assert!(supported_tail_advice_bytes > 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(supported_tail_advice_bytes, 0);
        assert!(supported_tail_advice_bytes <= report.requested_bytes());
        assert_eq!(arena.stats(), stats_before);

        let second = arena
            .aos_alloc_raw(page_size, 1, 8)
            .expect("advised tail remains allocatable");
        assert!(second.ptr.as_ptr() as usize > first.ptr.as_ptr() as usize);
    }

    #[test]
    fn region_pop_rewinds_current_chunk_and_advises_dead_range() {
        let page_size = system_page_size().expect("page size");
        let chunk_bytes = page_size.checked_mul(3).expect("three pages fit");
        let mut arena = BumpArena::with_initial_chunk_bytes(chunk_bytes).expect("arena creates");
        arena
            .aos_alloc_raw(page_size, 8, 1)
            .expect("prefix allocation succeeds");
        let mark = arena.region_mark();
        let dead = arena
            .aos_alloc_raw(page_size, 8, 2)
            .expect("region allocation succeeds");
        let before = arena.stats();

        // SAFETY: the test never observes `dead` after popping the region, and
        // no typed side table exists for this raw arena allocation.
        let report = unsafe { arena.pop_region_to_mark(mark) }.expect("region pop succeeds");

        assert_eq!(report.before_stats(), before);
        assert_eq!(report.after_stats(), arena.stats());
        assert_eq!(report.after_stats().chunks, 1);
        assert_eq!(report.after_stats().used_bytes, page_size);
        assert_eq!(report.used_bytes_released(), page_size);
        assert_eq!(report.released_mapped_bytes(), 0);
        assert_eq!(report.dead_range_bytes(), page_size);
        match report.dead_range_outcome() {
            MemoryAdviceOutcome::Applied {
                kind: MemoryAdviceKind::Dead,
            }
            | MemoryAdviceOutcome::Unsupported {
                kind: MemoryAdviceKind::Dead,
            }
            | MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Dead,
            }
            | MemoryAdviceOutcome::Rejected {
                kind: MemoryAdviceKind::Dead,
                ..
            } => {}
            other => panic!("unexpected dead-range advice outcome: {other:?}"),
        }

        let reused = arena
            .aos_alloc_raw(page_size, 8, 3)
            .expect("rewound space is reusable");
        assert_eq!(reused.ptr, dead.ptr);
    }

    #[test]
    fn region_pop_drops_later_chunks_and_restores_growth_state() {
        let mut arena = BumpArena::with_initial_chunk_bytes(16).expect("arena creates");
        arena
            .aos_alloc_raw(16, 8, 1)
            .expect("first chunk allocation succeeds");
        let mark = arena.region_mark();
        arena
            .aos_alloc_raw(24, 8, 2)
            .expect("second chunk allocation succeeds");
        let before = arena.stats();
        assert_eq!(before.chunks, 2);
        assert_eq!(before.reserved_bytes, 48);

        // SAFETY: the allocation in the second chunk is not used after this
        // point, so the marker describes a dead suffix of the arena.
        let report = unsafe { arena.pop_region_to_mark(mark) }.expect("region pop succeeds");

        assert_eq!(report.before_stats(), before);
        assert_eq!(report.after_stats().chunks, 1);
        assert_eq!(report.after_stats().reserved_bytes, 16);
        assert_eq!(report.after_stats().used_bytes, 16);
        assert_eq!(report.used_bytes_released(), 24);
        assert!(report.released_mapped_bytes() >= 32);
        assert_eq!(report.dead_range_bytes(), 0);
        assert_eq!(
            report.dead_range_outcome(),
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Dead,
            }
        );

        arena
            .aos_alloc_raw(24, 8, 3)
            .expect("post-pop allocation succeeds");
        let after_reuse = arena.stats();
        assert_eq!(after_reuse.chunks, 2);
        assert_eq!(
            after_reuse.reserved_bytes, 48,
            "region pop restores next chunk growth to the marker state"
        );
    }

    #[test]
    fn invalid_region_mark_is_rejected_without_side_effects() {
        let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
        arena.aos_alloc_raw(8, 8, 1).expect("allocation succeeds");
        let before = arena.stats();
        let invalid = ArenaRegionMark {
            chunk_count: 1,
            cursor: before.used_bytes + 8,
            next_chunk_bytes: 64,
        };

        // SAFETY: this intentionally invalid marker must be rejected before any
        // arena mutation can invalidate allocations.
        let invalid_pop = unsafe { arena.pop_region_to_mark(invalid) };
        assert_eq!(invalid_pop, Err(ArenaError::InvalidRegionMark));
        assert_eq!(arena.stats(), before);
    }

    #[test]
    fn subpage_unused_tail_has_no_supported_advice_bytes() {
        let mut arena = BumpArena::with_initial_chunk_bytes(128).expect("arena creates");
        arena.aos_alloc_raw(1, 1, 7).expect("allocation succeeds");

        assert_eq!(arena.supported_unused_tail_advice_bytes(), 0);
    }

    #[test]
    fn allocations_are_aligned_and_monotonic_within_a_chunk() {
        let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
        let first = arena
            .aos_alloc_raw(1, 1, 1)
            .expect("first allocation succeeds");
        let second = arena
            .aos_alloc_raw(9, 8, 2)
            .expect("second allocation succeeds");

        let first_addr = first.ptr.as_ptr() as usize;
        let second_addr = second.ptr.as_ptr() as usize;
        assert_eq!(first_addr % 8, 0);
        assert_eq!(second_addr % 8, 0);
        assert!(second_addr > first_addr);
        assert_eq!(first.reserved_size, WORD_BYTES);
        assert_eq!(second.reserved_size, 16);
        assert_eq!(arena.stats().chunks, 1);
        assert_eq!(arena.stats().used_bytes, 24);
    }

    #[test]
    fn arena_grows_geometrically_when_chunks_fill() {
        let mut arena = BumpArena::with_initial_chunk_bytes(16).expect("arena creates");
        let _first = arena
            .aos_alloc_raw(16, 8, 1)
            .expect("first allocation fills first chunk");
        let _second = arena
            .aos_alloc_raw(24, 8, 2)
            .expect("second allocation gets larger chunk");
        let stats = arena.stats();
        assert_eq!(stats.chunks, 2);
        assert_eq!(stats.reserved_bytes, 48);
        assert_eq!(stats.used_bytes, 40);
    }

    #[test]
    fn oversized_allocation_gets_a_dedicated_chunk() {
        let mut arena = BumpArena::with_initial_chunk_bytes(16).expect("arena creates");
        let allocation = arena
            .aos_alloc_raw(80, 8, 1)
            .expect("large allocation succeeds");
        let stats = arena.stats();
        assert_eq!(allocation.reserved_size, 80);
        assert_eq!(stats.chunks, 1);
        assert_eq!(stats.reserved_bytes, 80);
        assert!(stats.mapped_bytes >= stats.reserved_bytes);
        assert_eq!(stats.used_bytes, 80);
    }

    #[test]
    fn entrypoint_layouts_are_stable() {
        let mut arena = BumpArena::with_initial_chunk_bytes(512).expect("arena creates");
        let thunk = arena.aos_alloc_thunk().expect("thunk allocates");
        assert_eq!(thunk.kind, HeapObjectKind::Thunk);
        assert_eq!(thunk.requested_size, THUNK_BYTES);

        let lambda = arena.aos_alloc_lambda().expect("lambda allocates");
        assert_eq!(lambda.kind, HeapObjectKind::Lambda);
        assert_eq!(lambda.requested_size, LAMBDA_BYTES);

        let attrs = arena.aos_alloc_attrs(42, 3).expect("attrset allocates");
        assert_eq!(
            attrs.kind,
            HeapObjectKind::Attrs {
                shape: 42,
                slots: 3,
            }
        );
        assert_eq!(
            attrs.requested_size,
            OBJECT_HEADER_BYTES + 3 * mem::size_of::<Value>()
        );

        let cons = arena.aos_alloc_cons().expect("cons allocates");
        assert_eq!(cons.kind, HeapObjectKind::Cons);
        assert_eq!(cons.requested_size, CONS_BYTES);

        let list = arena.aos_alloc_list(4).expect("list allocates");
        assert_eq!(list.kind, HeapObjectKind::List { len: 4 });
        assert_eq!(
            list.requested_size,
            LIST_ELEMENTS_OFFSET_BYTES + 4 * mem::size_of::<Value>()
        );

        let string = arena.aos_alloc_string(11).expect("string allocates");
        assert_eq!(string.kind, HeapObjectKind::String { len: 11 });
        assert_eq!(string.requested_size, OBJECT_HEADER_BYTES + 11);
    }

    #[test]
    fn invalid_alignment_is_rejected() {
        let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
        assert_eq!(
            arena.aos_alloc_raw(8, 0, 1),
            Err(ArenaError::InvalidAlignment { align: 0 })
        );
        assert_eq!(
            arena.aos_alloc_raw(8, 3, 1),
            Err(ArenaError::InvalidAlignment { align: 3 })
        );
        assert_eq!(
            arena.aos_alloc_raw(8, 16, 1),
            Err(ArenaError::InvalidAlignment { align: 16 })
        );
    }

    #[test]
    fn oversized_list_length_is_rejected_without_side_effects() {
        let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
        let too_long = (u32::MAX as usize)
            .checked_add(1)
            .expect("test platform can represent u32::MAX + 1");

        assert_eq!(
            arena.aos_alloc_list(too_long),
            Err(ArenaError::SizeOverflow)
        );
        assert!(arena.is_empty());
    }

    #[test]
    fn impossible_chunk_allocation_is_reported_without_side_effects() {
        let oversized = (isize::MAX as usize)
            .checked_add(1)
            .expect("test platform has addressable usize range beyond isize");
        let mut arena = BumpArena::with_initial_chunk_bytes(oversized).expect("arena creates");

        assert_eq!(
            arena.aos_alloc_raw(1, 1, 1),
            Err(ArenaError::AllocationFailed { bytes: oversized })
        );
        assert!(arena.is_empty());
    }

    #[test]
    fn zero_sized_raw_allocation_gets_one_word_handle() {
        let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
        let allocation = arena
            .aos_alloc_raw(0, 8, 1)
            .expect("zero-sized raw allocation succeeds");
        assert_eq!(allocation.requested_size, 0);
        assert_eq!(allocation.reserved_size, WORD_BYTES);
        assert_eq!(arena.stats().used_bytes, WORD_BYTES);
    }

    #[test]
    fn thread_local_arena_is_independent_per_worker() {
        ThreadLocalBumpArena::reset_current();
        let main_addr = ThreadLocalBumpArena::with_current(|arena| {
            arena
                .aos_alloc_raw(8, 8, 1)
                .expect("main allocation succeeds")
                .ptr
                .as_ptr() as usize
        });
        let main_stats = ThreadLocalBumpArena::with_current(|arena| arena.stats());

        let worker = std::thread::spawn(|| {
            ThreadLocalBumpArena::reset_current();
            let before = ThreadLocalBumpArena::with_current(|arena| arena.stats());
            let addr = ThreadLocalBumpArena::with_current(|arena| {
                arena
                    .aos_alloc_raw(8, 8, 2)
                    .expect("worker allocation succeeds")
                    .ptr
                    .as_ptr() as usize
            });
            let after = ThreadLocalBumpArena::with_current(|arena| arena.stats());
            ThreadLocalBumpArena::reset_current();
            (before, after, addr)
        })
        .join()
        .expect("worker thread joins");

        assert_eq!(main_stats.chunks, 1);
        assert_eq!(worker.0, ArenaStats::default());
        assert_eq!(worker.1.chunks, 1);
        assert_ne!(main_addr, worker.2);
        ThreadLocalBumpArena::reset_current();
    }
}
