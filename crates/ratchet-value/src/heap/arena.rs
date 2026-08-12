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

    /// Returns the number of chunks currently owned by the arena.
    ///
    /// Constant-time, unlike [`BumpArena::stats`], which walks every chunk;
    /// per-allocation staleness checks (the flat stores' membership-region
    /// refresh) must use this.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
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

    /// Rewinds to a region marker after the owning heap validated its suffix.
    ///
    /// This is the safe cross-crate handoff for runtimes that own the typed
    /// record table layered over the arena. The arena exposes only opaque
    /// pointer handles, so rewinding cannot itself dereference or alias a Rust
    /// reference. Callers remain responsible for invalidating their logical
    /// handles first; checked resolution must reject stale handles after the
    /// pop.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidRegionMark`] if `mark` cannot describe the
    /// arena's current allocation prefix.
    pub fn pop_caller_validated_region_to_mark(
        &mut self,
        mark: ArenaRegionMark,
    ) -> Result<ArenaRegionPopReport, ArenaError> {
        // SAFETY: `ArenaAllocation` exposes opaque pointer handles rather than
        // Rust references. The runtime calling this handoff owns and has
        // already invalidated its typed side table; any later pointer access
        // remains behind the resolver's independent live-membership checks.
        unsafe { self.pop_region_to_mark(mark) }
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
    pub(super) unsafe fn pop_region_to_mark(
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

    /// Structurally validates a region marker against the arena's current
    /// prefix without mutating anything.
    ///
    /// Crate-visible so the flat-object store can prove a marker acceptable
    /// *before* it drops the payloads above it: `FlatObjectStore::pop_region`
    /// must not reach the arena rewind with payload state half-destroyed.
    pub(crate) fn validate_region_mark(&self, mark: ArenaRegionMark) -> Result<(), ArenaError> {
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

mod reports;

pub use reports::{
    ArenaAllocation, ArenaMemoryAdviceReport, ArenaRegionMark, ArenaRegionPopReport, ArenaStats,
    HeapObjectKind,
};

#[cfg(test)]
mod tests;
