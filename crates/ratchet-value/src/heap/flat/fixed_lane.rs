//! Headerless fixed-stride objects in the permanent shared flat arena.
//!
//! [`HeaderlessFlatLane`] is the narrow substrate for object populations whose
//! runtime tag and lane membership already provide the type witness that the
//! generic flat store obtains from its 24-byte header. It reserves lazy blocks
//! from [`SharedFlatStoreArena`]'s upward-growing permanent lane, placement
//! writes one payload at each fixed-stride slot, and keeps only block
//! descriptors rather than one registry entry per object.
//!
//! # Soundness structure
//!
//! A Candidate-C domain/index pair proves only that an address lies in the
//! shared reservation; it does not prove an object's type. Resolution therefore
//! checks that the address is an exact initialized slot in one of this lane's
//! own non-overlapping blocks before constructing a reference. The lane is not
//! cloneable, so exactly one owner drops every initialized payload. Its strong
//! arena handle keeps all blocks mapped until that drop pass completes.

use super::*;
use crate::heap::arena::HeapObjectKind;

/// Target byte size for one lazily reserved lane block.
const DEFAULT_BLOCK_BYTES: usize = 1 << 20;

/// One raw block owned exclusively by a [`HeaderlessFlatLane`].
#[derive(Debug)]
struct HeaderlessBlock {
    start: NonNull<HeapObject>,
    initialized: usize,
    capacity: usize,
}

/// One headerless payload allocation.
#[derive(Clone, Copy, Debug)]
pub struct HeaderlessFlatAllocation {
    /// Stable payload address, suitable for a runtime heap value.
    pub ptr: NonNull<HeapObject>,
    /// Logical per-slot allocation used by evaluator safepoint accounting.
    pub allocation: ArenaAllocation,
}

/// A permanent, headerless, fixed-stride object lane.
///
/// Blocks are reserved lazily from a shared arena and never rewound. The lane
/// stores one descriptor per block, not one entry per payload.
#[derive(Debug)]
pub struct HeaderlessFlatLane<T> {
    arena: SharedFlatStoreArena,
    kind: FlatObjectKind,
    blocks: Vec<HeaderlessBlock>,
    active_block: Option<usize>,
    len: usize,
    block_slots: usize,
    stride: usize,
    _payload: PhantomData<T>,
}

impl<T> HeaderlessFlatLane<T> {
    /// Creates an empty lane with approximately one MiB per lazy block.
    ///
    /// Zero-sized or over-aligned payloads are rejected by [`Self::alloc`].
    pub fn new(arena: SharedFlatStoreArena, kind: FlatObjectKind) -> Self {
        let stride = slot_stride::<T>().unwrap_or(MAX_ALIGN);
        let block_slots = (DEFAULT_BLOCK_BYTES / stride).max(1);
        Self {
            arena,
            kind,
            blocks: Vec::new(),
            active_block: None,
            len: 0,
            block_slots,
            stride,
            _payload: PhantomData,
        }
    }

    /// Creates an empty lane with an explicit number of slots per lazy block.
    ///
    /// This constructor is primarily useful for bounded experiments and tests;
    /// production callers should normally use [`Self::new`].
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `block_slots` is zero,
    /// [`ArenaError::InvalidAlignment`] for an over-aligned payload, or
    /// [`ArenaError::SizeOverflow`] for a zero-sized payload or overflowing
    /// block extent.
    pub fn with_block_slots(
        arena: SharedFlatStoreArena,
        kind: FlatObjectKind,
        block_slots: usize,
    ) -> Result<Self, ArenaError> {
        if block_slots == 0 {
            return Err(ArenaError::InvalidChunkSize { chunk_bytes: 0 });
        }
        let stride = slot_stride::<T>()?;
        stride
            .checked_mul(block_slots)
            .ok_or(ArenaError::SizeOverflow)?;
        Ok(Self {
            arena,
            kind,
            blocks: Vec::new(),
            active_block: None,
            len: 0,
            block_slots,
            stride,
            _payload: PhantomData,
        })
    }

    /// Allocates and initializes one payload in the lane.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::Arena`] when block storage cannot be
    /// reserved or the payload layout is unsupported, and
    /// [`FlatObjectError::RegistryAllocationFailed`] if the per-block
    /// descriptor vector cannot grow.
    pub fn alloc(&mut self, payload: T) -> Result<HeaderlessFlatAllocation, FlatObjectError> {
        let stride = slot_stride::<T>().map_err(FlatObjectError::Arena)?;
        debug_assert_eq!(stride, self.stride);
        let needs_block = match self.active_block.and_then(|index| self.blocks.get(index)) {
            Some(block) => block.initialized == block.capacity,
            None => true,
        };
        if needs_block {
            let requested_blocks = self.blocks.len().checked_add(1).ok_or(
                FlatObjectError::RegistryAllocationFailed {
                    entries: usize::MAX,
                },
            )?;
            self.blocks
                .try_reserve(1)
                .map_err(|_| FlatObjectError::RegistryAllocationFailed {
                    entries: requested_blocks,
                })?;
            let block_bytes = stride
                .checked_mul(self.block_slots)
                .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
            let allocation = self
                .arena
                .alloc_headerless_block_raw(block_bytes, mem::align_of::<T>(), self.kind)
                .map_err(FlatObjectError::Arena)?;
            #[cfg(feature = "hole_reuse_shadow_probe")]
            if self.arena.uses_reservation() {
                super::hole_reuse_shadow::note_candidate_c_allocation(
                    allocation.ptr.as_ptr() as usize,
                    allocation.reserved_size,
                    allocation.align,
                );
            }
            let block = HeaderlessBlock {
                start: allocation.ptr,
                initialized: 0,
                capacity: self.block_slots,
            };
            let insertion = self.blocks.partition_point(|existing| {
                (existing.start.as_ptr() as usize) < block.start.as_ptr() as usize
            });
            self.blocks.insert(insertion, block);
            self.active_block = Some(insertion);
        }

        let Some(block) = self
            .active_block
            .and_then(|index| self.blocks.get_mut(index))
        else {
            return Err(FlatObjectError::Arena(ArenaError::InternalMissingChunk));
        };
        let offset = block
            .initialized
            .checked_mul(stride)
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        let address = (block.start.as_ptr() as usize)
            .checked_add(offset)
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        let Some(ptr) = NonNull::new(address as *mut HeapObject) else {
            return Err(FlatObjectError::Arena(ArenaError::NullChunkPointer));
        };
        let new_len = self
            .len
            .checked_add(1)
            .ok_or(FlatObjectError::RegistryAllocationFailed {
                entries: usize::MAX,
            })?;
        // SAFETY: `block` is an exclusively owned raw reservation containing
        // `capacity` slots of `stride` bytes. `initialized < capacity`, the
        // computed slot is aligned for `T`, and no earlier allocation wrote
        // this slot. The lane never reissues or rewinds an initialized slot.
        unsafe { ptr.as_ptr().cast::<T>().write(payload) };
        block.initialized += 1;
        self.len = new_len;

        Ok(HeaderlessFlatAllocation {
            ptr,
            allocation: ArenaAllocation {
                ptr,
                kind: HeapObjectKind::Raw {
                    type_tag: self.kind as u32,
                },
                requested_size: mem::size_of::<T>(),
                reserved_size: stride,
                align: mem::align_of::<T>(),
            },
        })
    }

    /// Resolves an exact initialized lane address to its payload.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::UnknownAddress`] unless `ptr` is the start
    /// of an initialized slot owned by this lane.
    pub fn resolve(&self, ptr: NonNull<HeapObject>) -> Result<&T, FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        if !self.contains_address(address) {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        // SAFETY: `contains_address` proves `ptr` is exactly the start of an
        // initialized `T` slot in one of this lane's live blocks. Allocation
        // requires `&mut self`, so this shared borrow excludes mutation, and
        // the strong arena handle keeps the block mapped for the reference.
        Ok(unsafe { &*ptr.as_ptr().cast::<T>() })
    }

    /// Returns whether `ptr` is an exact initialized slot in this lane.
    pub fn contains(&self, ptr: NonNull<HeapObject>) -> bool {
        self.contains_address(ptr.as_ptr() as usize)
    }

    /// Returns the number of initialized payloads.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the lane contains no initialized payloads.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the currently reserved slot capacity.
    pub fn capacity(&self) -> usize {
        self.blocks
            .iter()
            .map(|block| block.capacity)
            .fold(0usize, usize::saturating_add)
    }

    /// Returns the number of raw blocks currently reserved by the lane.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Iterates the address and reserved byte size of every initialized slot.
    ///
    /// The regions remain valid only while this lane owns its arena. This
    /// diagnostic-oriented view does not expose payload references or permit
    /// mutation.
    pub fn initialized_regions(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.blocks.iter().flat_map(|block| {
            (0..block.initialized).map(|slot| {
                (
                    (block.start.as_ptr() as usize)
                        .saturating_add(slot.saturating_mul(self.stride)),
                    self.stride,
                )
            })
        })
    }

    #[inline]
    fn contains_address(&self, address: usize) -> bool {
        let Some(first) = self.blocks.first() else {
            return false;
        };
        if address < first.start.as_ptr() as usize {
            return false;
        }
        let Some(last) = self.blocks.last() else {
            return false;
        };
        let last_start = last.start.as_ptr() as usize;
        let Some(last_end) = last
            .initialized
            .checked_mul(self.stride)
            .and_then(|extent| last_start.checked_add(extent))
        else {
            return false;
        };
        if address >= last_end {
            return false;
        }
        let position = self
            .blocks
            .partition_point(|block| block.start.as_ptr() as usize <= address);
        let Some(block) = position
            .checked_sub(1)
            .and_then(|index| self.blocks.get(index))
        else {
            return false;
        };
        self.block_contains(block, address)
    }

    #[inline]
    fn block_contains(&self, block: &HeaderlessBlock, address: usize) -> bool {
        let start = block.start.as_ptr() as usize;
        let Some(delta) = address.checked_sub(start) else {
            return false;
        };
        delta % self.stride == 0 && delta / self.stride < block.initialized
    }
}

impl<T> Drop for HeaderlessFlatLane<T> {
    fn drop(&mut self) {
        for block in &self.blocks {
            for slot in 0..block.initialized {
                let offset = slot * self.stride;
                let address = block.start.as_ptr() as usize + offset;
                // SAFETY: each index below `initialized` was placement-written
                // exactly once as `T`, blocks never overlap, and this is the
                // sole non-cloneable lane owner's drop pass. The lane's arena
                // handle remains a live field until after this method returns.
                unsafe { std::ptr::drop_in_place(address as *mut T) };
            }
        }
    }
}

fn slot_stride<T>() -> Result<usize, ArenaError> {
    let size = mem::size_of::<T>();
    let align = mem::align_of::<T>();
    if size == 0 {
        return Err(ArenaError::SizeOverflow);
    }
    if align > MAX_ALIGN {
        return Err(ArenaError::InvalidAlignment { align });
    }
    size.checked_add(MAX_ALIGN - 1)
        .map(|size| size & !(MAX_ALIGN - 1))
        .ok_or(ArenaError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    #[derive(Debug)]
    struct DropPayload {
        value: u64,
        drops: Rc<Cell<usize>>,
    }

    impl Drop for DropPayload {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    fn offset_ptr(ptr: NonNull<HeapObject>, bytes: usize) -> NonNull<HeapObject> {
        NonNull::new((ptr.as_ptr() as usize + bytes) as *mut HeapObject)
            .expect("non-null arena offset")
    }

    #[test]
    fn resolves_only_exact_initialized_slots() {
        let arena = SharedFlatStoreArena::new();
        let mut lane = HeaderlessFlatLane::with_block_slots(arena, FlatObjectKind::ThunkHead, 2)
            .expect("valid lane");
        let first = lane.alloc([11u64, 12]).expect("first allocation");

        assert_eq!(
            *lane.resolve(first.ptr).expect("first slot resolves"),
            [11, 12]
        );
        assert!(!lane.contains(offset_ptr(first.ptr, 8)));
        assert!(!lane.contains(offset_ptr(first.ptr, lane.stride)));
    }

    #[test]
    fn interleaved_shared_allocations_do_not_widen_membership() {
        let arena = SharedFlatStoreArena::new();
        let mut lane =
            HeaderlessFlatLane::with_block_slots(arena.clone(), FlatObjectKind::ThunkHead, 1)
                .expect("valid lane");
        let first = lane.alloc(1u64).expect("first lane block");
        let mut strings =
            FlatObjectStore::with_shared_arena(arena, FlatKindSet::of(&[FlatObjectKind::String]));
        let foreign = strings
            .alloc(FlatObjectKind::String, 0, 0, 2u64)
            .expect("interleaved generic allocation");
        let second = lane.alloc(3u64).expect("second lane block");

        assert!(lane.contains(first.ptr));
        assert!(!lane.contains(foreign.ptr));
        assert!(lane.contains(second.ptr));
        assert_eq!(lane.block_count(), 2);
    }

    #[test]
    fn candidate_c_indices_round_trip_lane_addresses() {
        let arena = SharedFlatStoreArena::new();
        if !arena.uses_reservation() {
            return;
        }
        let mut lane = HeaderlessFlatLane::new(arena.clone(), FlatObjectKind::ThunkHead);
        let allocation = lane.alloc(7u64).expect("lane allocation");
        let index = arena
            .index_for_pointer(allocation.ptr)
            .expect("lane pointer belongs to reservation");
        assert_eq!(arena.pointer_for_index(index), Some(allocation.ptr));
    }

    #[test]
    fn drops_every_initialized_payload_once_across_blocks() {
        let drops = Rc::new(Cell::new(0));
        {
            let arena = SharedFlatStoreArena::new();
            let mut lane =
                HeaderlessFlatLane::with_block_slots(arena, FlatObjectKind::ThunkHead, 2)
                    .expect("valid lane");
            for value in 0..5 {
                lane.alloc(DropPayload {
                    value,
                    drops: Rc::clone(&drops),
                })
                .expect("payload allocation");
            }
            assert_eq!(lane.len(), 5);
            assert_eq!(lane.capacity(), 6);
            let last_start = lane.blocks.last().expect("last block").start;
            assert_eq!(
                lane.resolve(last_start)
                    .expect("last block starts initialized")
                    .value,
                4
            );
        }
        assert_eq!(drops.get(), 5);
    }

    #[test]
    fn chunked_compatibility_backing_supports_the_lane() {
        let arena = SharedFlatStoreArena::with_initial_chunk_bytes(128).expect("chunked arena");
        assert!(!arena.uses_reservation());
        let mut lane = HeaderlessFlatLane::with_block_slots(arena, FlatObjectKind::ThunkHead, 16)
            .expect("valid lane");
        let mut allocations = Vec::new();
        for value in 0..40 {
            allocations.push(lane.alloc(value).expect("chunked lane allocation"));
        }

        assert!(lane.block_count() >= 3);
        assert!(
            lane.blocks.windows(2).all(|pair| {
                (pair[0].start.as_ptr() as usize) < pair[1].start.as_ptr() as usize
            })
        );
        for (value, allocation) in allocations.into_iter().enumerate() {
            assert_eq!(
                *lane.resolve(allocation.ptr).expect("chunked resolve"),
                value
            );
        }
    }
}
