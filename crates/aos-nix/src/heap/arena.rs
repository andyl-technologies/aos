//! Tier-A one-shot bump arena.
//!
//! This is the safe Phase-1 allocator substrate for the tree-walk oracle. It
//! reserves aligned slots in owned chunks, returns opaque [`HeapObject`] handles,
//! and never frees individual allocations. The implementation deliberately avoids
//! raw memory writes until concrete heap object layouts exist.

use std::mem;

use thiserror::Error;

use crate::value::{HeapObject, Value};

const DEFAULT_CHUNK_BYTES: usize = 2 * 1024 * 1024;
const WORD_BYTES: usize = mem::size_of::<u64>();
const MAX_ALIGN: usize = mem::align_of::<u64>();
const OBJECT_HEADER_BYTES: usize = 2 * WORD_BYTES;
const THUNK_BYTES: usize = 3 * WORD_BYTES;
// Header plus u32 length, padded so the inline Value tail starts 8-byte aligned.
const LIST_ELEMENTS_OFFSET_BYTES: usize = OBJECT_HEADER_BYTES + WORD_BYTES;
const CONS_BYTES: usize = OBJECT_HEADER_BYTES + mem::size_of::<Value>() + WORD_BYTES;

/// The logical heap object kind requested through an allocation entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapObjectKind {
    /// A suspended thunk object.
    Thunk,
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
    /// Number of bytes reserved by all chunks.
    pub reserved_bytes: usize,
    /// Number of bytes consumed by allocations, including alignment padding and
    /// word rounding.
    pub used_bytes: usize,
}

/// A safe, never-free bump arena for one evaluator invocation.
#[derive(Debug)]
pub struct BumpArena {
    chunks: Vec<Chunk>,
    next_chunk_bytes: usize,
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
        })
    }

    /// Returns current chunk and byte accounting.
    pub fn stats(&self) -> ArenaStats {
        let mut stats = ArenaStats {
            chunks: self.chunks.len(),
            reserved_bytes: 0,
            used_bytes: 0,
        };
        for chunk in &self.chunks {
            stats.reserved_bytes += chunk.capacity_bytes();
            stats.used_bytes += chunk.cursor;
        }
        stats
    }

    /// Returns whether no allocation has been served yet.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
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
            self.next_chunk_bytes = next_chunk_bytes;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Chunk {
    words: Box<[u64]>,
    cursor: usize,
}

impl Chunk {
    fn new(bytes: usize) -> Result<Self, ArenaError> {
        let bytes = round_up(bytes, WORD_BYTES)?;
        let words = bytes
            .checked_div(WORD_BYTES)
            .ok_or(ArenaError::SizeOverflow)?;
        if words == 0 {
            return Err(ArenaError::InvalidChunkSize { chunk_bytes: bytes });
        }
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(words)
            .map_err(|_| ArenaError::AllocationFailed { bytes })?;
        storage.resize(words, 0u64);
        Ok(Self {
            words: storage.into_boxed_slice(),
            cursor: 0,
        })
    }

    fn capacity_bytes(&self) -> usize {
        self.words.len() * WORD_BYTES
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
        let base = self.words.as_mut_ptr().cast::<u8>();
        let ptr = std::ptr::NonNull::new(base.wrapping_add(start).cast::<HeapObject>())
            .ok_or(ArenaError::NullChunkPointer)?;
        self.cursor = end;
        Ok(ptr)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_arena_has_no_chunks() {
        let arena = BumpArena::new();
        assert!(arena.is_empty());
        assert_eq!(arena.stats(), ArenaStats::default());
    }

    #[test]
    fn custom_initial_chunk_size_is_word_rounded() {
        let mut arena = BumpArena::with_initial_chunk_bytes(9).expect("arena creates");
        let allocation = arena
            .aos_alloc_raw(1, 1, 7)
            .expect("raw allocation succeeds");
        assert_eq!(allocation.reserved_size, WORD_BYTES);
        assert_eq!(arena.stats().reserved_bytes, 16);
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
        assert_eq!(stats.used_bytes, 80);
    }

    #[test]
    fn entrypoint_layouts_are_stable() {
        let mut arena = BumpArena::with_initial_chunk_bytes(512).expect("arena creates");
        let thunk = arena.aos_alloc_thunk().expect("thunk allocates");
        assert_eq!(thunk.kind, HeapObjectKind::Thunk);
        assert_eq!(thunk.requested_size, THUNK_BYTES);

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
}
