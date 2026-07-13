//! Candidate-C contiguous address-space reservation.
//!
//! Candidate C represents heap references as unsigned 32-bit byte offsets into
//! one 4 GiB virtual reservation. [`ReservedArena`] owns that reservation,
//! validates every pointer/index conversion against its used lanes, and bumps
//! from both ends. Permanent/shared objects grow upward from offset zero;
//! serial region-popped objects grow downward from the reservation end. The
//! mapping is read/write but demand paged, so reserving the index space does
//! not commit 4 GiB of resident memory.
//!
//! This module intentionally does not define concrete object layouts. It
//! returns opaque [`HeapObject`] handles so the flat-object store can adopt the
//! index space without exposing raw references or unchecked pointer decoding.

use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use thiserror::Error;

use super::reservation_registry::{
    ReservationRegistryError, register_reservation_base, unregister_reservation_base,
};
use crate::value::HeapObject;

/// Heap-image round-trip primitive for the Candidate-C address-free snapshot
/// (RFC-0007 doc 31 §1, stage 1). Adds `impl ReservedArena` methods that dump
/// the used lanes and reload them into a fresh mapping with the domain
/// preserved, gated to the variant carrier where compressed words are live.
#[cfg(feature = "candidate_c_value")]
mod image;

/// The virtual address-space size required by a full unsigned 32-bit offset.
pub const CANDIDATE_C_ADDRESS_SPACE_BYTES: u64 = 1_u64 << 32;
/// Maximum nonzero arena domain encodable beside kind and forced metadata.
pub const CANDIDATE_C_ARENA_DOMAIN_MAX: u32 = (1 << 23) - 1;
static NEXT_ARENA_DOMAIN: AtomicU32 = AtomicU32::new(1);

#[cfg(any(target_os = "android", target_os = "linux"))]
const MAP_ANONYMOUS_FLAG: libc::c_int = libc::MAP_ANONYMOUS;

#[cfg(not(any(target_os = "android", target_os = "linux")))]
const MAP_ANONYMOUS_FLAG: libc::c_int = libc::MAP_ANON;

/// A byte offset into a Candidate-C reservation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArenaIndex(u32);

impl ArenaIndex {
    /// Creates an arena index from its raw byte offset.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw byte offset from the reservation base.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// A process-unique identity for one Candidate-C reservation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArenaDomainId(u32);

impl ArenaDomainId {
    /// Decodes nonzero 23-bit domain metadata.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        if raw > 0 && raw <= CANDIDATE_C_ARENA_DOMAIN_MAX {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// Returns the nonzero 23-bit domain metadata.
    pub const fn raw(self) -> u32 {
        self.0
    }

    fn next() -> Result<Self, ReservedArenaError> {
        let raw = NEXT_ARENA_DOMAIN
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                (next <= CANDIDATE_C_ARENA_DOMAIN_MAX).then_some(next + 1)
            })
            .map_err(|_| ReservedArenaError::ArenaDomainExhausted)?;
        Ok(Self(raw))
    }
}

/// One allocation from a contiguous Candidate-C reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedArenaAllocation {
    /// The compressed byte-offset handle for the allocation.
    pub index: ArenaIndex,
    /// The opaque native pointer corresponding to `index`.
    pub ptr: NonNull<HeapObject>,
    /// The size requested by the caller.
    pub requested_size: usize,
    /// The nonzero allocation extent reserved after the aligned start.
    pub reserved_size: usize,
    /// The requested power-of-two alignment.
    pub align: usize,
}

/// Current accounting for a contiguous Candidate-C reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedArenaStats {
    /// Virtual bytes held by the reservation.
    pub virtual_reserved_bytes: usize,
    /// Bytes in both allocation lanes, including alignment padding.
    pub used_bytes: usize,
    /// Bytes consumed by the low, monotonically increasing lane.
    pub low_used_bytes: usize,
    /// Bytes consumed by the high, rewindable decreasing lane.
    pub high_used_bytes: usize,
    /// Bytes still available after the bump cursor.
    pub available_bytes: usize,
}

/// A LIFO marker in one contiguous Candidate-C reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedArenaMark {
    base_address: usize,
    cursor: usize,
}

/// A LIFO marker in the reservation's high, downward-growing lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedArenaHighMark {
    base_address: usize,
    cursor: usize,
}

impl ReservedArenaHighMark {
    /// Returns the high-lane cursor captured by the marker.
    pub const fn cursor(self) -> usize {
        self.cursor
    }
}

impl ReservedArenaMark {
    /// Returns the low-lane used-prefix length captured by the marker.
    pub const fn cursor(self) -> usize {
        self.cursor
    }
}

/// A single, bidirectionally allocated Candidate-C address space.
#[derive(Debug)]
pub struct ReservedArena {
    base: NonNull<u8>,
    domain_id: ArenaDomainId,
    capacity: usize,
    low_cursor: AtomicUsize,
    high_cursor: usize,
}

// SAFETY: The arena uniquely owns its anonymous mapping, which is not tied to
// the creating thread. Shared allocation claims disjoint ranges atomically;
// rewind requires exclusive `&mut` access, and moving the owner preserves the
// base address and mapping lifetime.
unsafe impl Send for ReservedArena {}

// SAFETY: Shared allocation mutates only the atomic cursor and returns a
// uniquely claimed opaque range. Checked pointer/index conversion and
// accounting do not mutate mapped bytes; rewind and unmapping require
// exclusive access or ownership.
unsafe impl Sync for ReservedArena {}

impl ReservedArena {
    /// Reserves the full 4 GiB Candidate-C virtual address space.
    ///
    /// The mapping is demand paged: untouched reservation pages do not become
    /// resident merely because the virtual range exists.
    ///
    /// # Errors
    ///
    /// Returns an error on non-64-bit targets, unsupported platforms, or when
    /// the operating system cannot create the anonymous mapping.
    pub fn new() -> Result<Self, ReservedArenaError> {
        let capacity = usize::try_from(CANDIDATE_C_ADDRESS_SPACE_BYTES)
            .map_err(|_| ReservedArenaError::UnsupportedPointerWidth)?;
        Self::with_capacity(capacity)
    }

    /// Reserves a contiguous test or variant address space of `capacity` bytes.
    ///
    /// Production Candidate C uses [`Self::new`]. Smaller capacities make
    /// boundary behavior testable without changing the offset codec.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or greater-than-4-GiB capacity, on non-64-bit
    /// targets or unsupported platforms, or when the operating system cannot
    /// create the anonymous mapping.
    #[cfg(unix)]
    pub fn with_capacity(capacity: usize) -> Result<Self, ReservedArenaError> {
        if usize::BITS < 64 {
            return Err(ReservedArenaError::UnsupportedPointerWidth);
        }
        validate_capacity(capacity)?;
        let domain_id = ArenaDomainId::next()?;
        let base = map_anonymous_reservation(capacity)?;
        // Publish `domain_id -> base` so a context-free holder of a compressed
        // `(domain, index)` word can reconstruct a native pointer without a heap
        // handle (see `reservation_registry`). This happens before the
        // reservation escapes and is withdrawn in `Drop` before the mapping is
        // released, so a published entry always names live memory.
        if let Err(error) = register_reservation_base(domain_id, base.as_ptr() as usize, capacity) {
            // SAFETY: `base`/`capacity` denote the mapping created above and no
            // reference into it exists yet, so releasing it here is sound.
            let _ = unsafe { libc::munmap(base.as_ptr().cast(), capacity) };
            return Err(ReservedArenaError::from(error));
        }
        Ok(Self {
            base,
            domain_id,
            capacity,
            low_cursor: AtomicUsize::new(0),
            high_cursor: capacity,
        })
    }

    /// Returns this reservation's process-unique compressed-word domain.
    pub const fn domain_id(&self) -> ArenaDomainId {
        self.domain_id
    }

    /// Reports that contiguous reservation is unavailable on non-Unix hosts.
    ///
    /// # Errors
    ///
    /// Always returns [`ReservedArenaError::UnsupportedPlatform`].
    #[cfg(not(unix))]
    pub fn with_capacity(_capacity: usize) -> Result<Self, ReservedArenaError> {
        Err(ReservedArenaError::UnsupportedPlatform)
    }

    /// Atomically allocates an aligned opaque range and returns both handles.
    ///
    /// Zero-sized requests consume one byte so every successful allocation has
    /// a unique index. Alignment is applied to the absolute mapped address,
    /// rather than assuming the operating-system page alignment is sufficient.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-power-of-two alignment, arithmetic overflow,
    /// or an allocation that exceeds the reservation or 32-bit offset space.
    pub fn alloc(
        &self,
        requested_size: usize,
        align: usize,
    ) -> Result<ReservedArenaAllocation, ReservedArenaError> {
        let (start, reserved_size) = loop {
            let cursor = self.low_cursor.load(Ordering::Relaxed);
            let (start, end, reserved_size) =
                self.plan_allocation(cursor, requested_size, align)?;
            if self
                .low_cursor
                .compare_exchange_weak(cursor, end, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break (start, reserved_size);
            }
        };
        self.allocation_at(start, requested_size, reserved_size, align)
    }

    /// Exclusively allocates an aligned range without an atomic cursor update.
    ///
    /// Serial owners that already have `&mut self` use this door to retain the
    /// same address/index contract without paying a compare-exchange per
    /// object. It plans and commits exactly the same cursor transition as
    /// [`Self::alloc`].
    ///
    /// # Errors
    ///
    /// Returns an error for a non-power-of-two alignment, arithmetic overflow,
    /// or an allocation that exceeds the reservation or 32-bit offset space.
    #[inline]
    pub fn alloc_exclusive(
        &mut self,
        requested_size: usize,
        align: usize,
    ) -> Result<ReservedArenaAllocation, ReservedArenaError> {
        let cursor = *self.low_cursor.get_mut();
        let base_address = self.base.as_ptr() as usize;
        let reserved_size = requested_size.max(1);
        let (start, end) = if align.is_power_of_two()
            && base_address & (align - 1) == 0
            && cursor & (align - 1) == 0
        {
            let end = cursor
                .checked_add(reserved_size)
                .ok_or(ReservedArenaError::SizeOverflow)?;
            if end > self.high_cursor || cursor > u32::MAX as usize {
                return Err(ReservedArenaError::OutOfSpace {
                    requested_size,
                    align,
                    available_bytes: self.high_cursor.saturating_sub(cursor),
                });
            }
            (cursor, end)
        } else {
            let (start, end, _) = self.plan_allocation(cursor, requested_size, align)?;
            (start, end)
        };
        let allocation = self.allocation_at(start, requested_size, reserved_size, align)?;
        *self.low_cursor.get_mut() = end;
        Ok(allocation)
    }

    /// Exclusively allocates from the high, downward-growing lane.
    ///
    /// The returned object start remains aligned while any alignment padding
    /// is charged to the high lane. This door requires exclusive access so a
    /// caller can pair allocations with [`Self::high_mark`] and rewind them
    /// independently of permanent low-lane allocations.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-power-of-two alignment, arithmetic overflow,
    /// or an allocation that would collide with the low lane.
    #[inline]
    pub fn alloc_exclusive_high(
        &mut self,
        requested_size: usize,
        align: usize,
    ) -> Result<ReservedArenaAllocation, ReservedArenaError> {
        if !align.is_power_of_two() {
            return Err(ReservedArenaError::InvalidAlignment { align });
        }
        let reserved_size = requested_size.max(1);
        let base_address = self.base.as_ptr() as usize;
        let unaligned_start = self
            .high_cursor
            .checked_sub(reserved_size)
            .ok_or(ReservedArenaError::SizeOverflow)?;
        let start_address = base_address
            .checked_add(unaligned_start)
            .ok_or(ReservedArenaError::SizeOverflow)?
            & !(align - 1);
        let start = start_address
            .checked_sub(base_address)
            .ok_or(ReservedArenaError::SizeOverflow)?;
        let low_cursor = *self.low_cursor.get_mut();
        if start < low_cursor || start > u32::MAX as usize {
            return Err(ReservedArenaError::OutOfSpace {
                requested_size,
                align,
                available_bytes: self.high_cursor.saturating_sub(low_cursor),
            });
        }
        let consumed_size = self.high_cursor - start;
        let allocation = self.allocation_at(start, requested_size, consumed_size, align)?;
        self.high_cursor = start;
        Ok(allocation)
    }

    #[inline]
    fn plan_allocation(
        &self,
        cursor: usize,
        requested_size: usize,
        align: usize,
    ) -> Result<(usize, usize, usize), ReservedArenaError> {
        if !align.is_power_of_two() {
            return Err(ReservedArenaError::InvalidAlignment { align });
        }
        let reserved_size = requested_size.max(1);
        let base_address = self.base.as_ptr() as usize;
        let cursor_address = base_address
            .checked_add(cursor)
            .ok_or(ReservedArenaError::SizeOverflow)?;
        let aligned_address = align_up(cursor_address, align)?;
        let start = aligned_address
            .checked_sub(base_address)
            .ok_or(ReservedArenaError::SizeOverflow)?;
        let end = start
            .checked_add(reserved_size)
            .ok_or(ReservedArenaError::SizeOverflow)?;
        if end > self.high_cursor || start > u32::MAX as usize {
            return Err(ReservedArenaError::OutOfSpace {
                requested_size,
                align,
                available_bytes: self.high_cursor.saturating_sub(cursor),
            });
        }
        Ok((start, end, reserved_size))
    }

    #[inline]
    fn allocation_at(
        &self,
        start: usize,
        requested_size: usize,
        reserved_size: usize,
        align: usize,
    ) -> Result<ReservedArenaAllocation, ReservedArenaError> {
        // SAFETY: `start < end <= capacity`, so the computed address remains
        // inside the live mapping (or at its first byte for a one-byte object).
        let address = unsafe { self.base.as_ptr().add(start) };
        let Some(ptr) = NonNull::new(address.cast::<HeapObject>()) else {
            return Err(ReservedArenaError::NullAllocationPointer);
        };
        Ok(ReservedArenaAllocation {
            index: ArenaIndex::new(start as u32),
            ptr,
            requested_size,
            reserved_size,
            align,
        })
    }

    /// Returns whether either allocation lane contains live bytes.
    pub(crate) fn has_allocations(&self) -> bool {
        self.low_cursor.load(Ordering::Acquire) != 0 || self.high_cursor != self.capacity
    }

    /// Returns the complete readable virtual mapping owned by the reservation.
    pub(crate) fn mapped_region(&self) -> Option<(usize, usize)> {
        let start = self.base.as_ptr() as usize;
        start.checked_add(self.capacity).map(|end| (start, end))
    }

    /// Converts an address in either used lane to its compressed byte offset.
    ///
    /// The address need not be an object boundary. Concrete object registries
    /// remain responsible for validating exact allocation starts and liveness.
    ///
    /// # Errors
    ///
    /// Returns an error when `ptr` is outside the mapping or lies in the free
    /// gap between the two lanes.
    pub fn index_for_pointer(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<ArenaIndex, ReservedArenaError> {
        let base_address = self.base.as_ptr() as usize;
        let address = ptr.as_ptr() as usize;
        let low_cursor = self.low_cursor.load(Ordering::Acquire);
        let Some(offset) = address.checked_sub(base_address) else {
            return Err(ReservedArenaError::PointerOutsideUsedLanes { address });
        };
        let in_low_lane = offset < low_cursor;
        let in_high_lane = offset >= self.high_cursor && offset < self.capacity;
        if (!in_low_lane && !in_high_lane) || offset > u32::MAX as usize {
            return Err(ReservedArenaError::PointerOutsideUsedLanes { address });
        }
        Ok(ArenaIndex::new(offset as u32))
    }

    /// Converts a compressed byte offset into an opaque native address.
    ///
    /// The index need not be an object boundary. Concrete object registries
    /// remain responsible for validating exact allocation starts and liveness.
    ///
    /// # Errors
    ///
    /// Returns an error when `index` lies in the free gap between the lanes.
    pub fn pointer_for_index(
        &self,
        index: ArenaIndex,
    ) -> Result<NonNull<HeapObject>, ReservedArenaError> {
        let offset = index.raw() as usize;
        let low_cursor = self.low_cursor.load(Ordering::Acquire);
        let in_low_lane = offset < low_cursor;
        let in_high_lane = offset >= self.high_cursor && offset < self.capacity;
        if !in_low_lane && !in_high_lane {
            return Err(ReservedArenaError::IndexOutsideUsedLanes {
                index: index.raw(),
                low_used_bytes: low_cursor,
                high_lane_start: self.high_cursor,
            });
        }
        // SAFETY: The used-lane check proves `offset < capacity`, so the
        // computed address is inside this arena's live mapping.
        let address = unsafe { self.base.as_ptr().add(offset) };
        NonNull::new(address.cast::<HeapObject>()).ok_or(ReservedArenaError::NullAllocationPointer)
    }

    /// Captures a LIFO marker for a caller-validated lexical region.
    pub fn mark(&self) -> ReservedArenaMark {
        ReservedArenaMark {
            base_address: self.base.as_ptr() as usize,
            cursor: self.low_cursor.load(Ordering::Acquire),
        }
    }

    /// Rewinds to a marker after the caller invalidates every later handle.
    ///
    /// This integer-only handoff creates no Rust references. The higher-level
    /// object owner must first prove that indices at or above the marker cannot
    /// be resolved again, matching the existing bump-arena region-pop contract.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker belongs to another reservation or lies
    /// beyond the current cursor.
    pub fn pop_caller_validated_to_mark(
        &mut self,
        mark: ReservedArenaMark,
    ) -> Result<usize, ReservedArenaError> {
        let cursor = self.low_cursor.get_mut();
        if mark.base_address != self.base.as_ptr() as usize || mark.cursor > *cursor {
            return Err(ReservedArenaError::InvalidMark);
        }
        let released = *cursor - mark.cursor;
        *cursor = mark.cursor;
        Ok(released)
    }

    /// Captures the current downward-growing lane position.
    pub fn high_mark(&self) -> ReservedArenaHighMark {
        ReservedArenaHighMark {
            base_address: self.base.as_ptr() as usize,
            cursor: self.high_cursor,
        }
    }

    /// Validates a high-lane marker without changing the reservation.
    ///
    /// # Errors
    ///
    /// Returns [`ReservedArenaError::InvalidMark`] for a cross-reservation
    /// marker or one outside the current high-lane allocation history.
    pub(crate) fn validate_high_mark(
        &self,
        mark: ReservedArenaHighMark,
    ) -> Result<(), ReservedArenaError> {
        let low_cursor = self.low_cursor.load(Ordering::Acquire);
        if mark.base_address != self.base.as_ptr() as usize
            || mark.cursor < self.high_cursor
            || mark.cursor > self.capacity
            || mark.cursor < low_cursor
        {
            return Err(ReservedArenaError::InvalidMark);
        }
        Ok(())
    }

    /// Rewinds the high lane after the caller invalidates every later handle.
    ///
    /// Low-lane allocations made after the marker remain live. The caller must
    /// drop and unregister every high-lane object below the marker first.
    ///
    /// # Errors
    ///
    /// Returns [`ReservedArenaError::InvalidMark`] when validation fails.
    pub fn pop_high_caller_validated_to_mark(
        &mut self,
        mark: ReservedArenaHighMark,
    ) -> Result<usize, ReservedArenaError> {
        self.validate_high_mark(mark)?;
        let released = mark.cursor - self.high_cursor;
        self.high_cursor = mark.cursor;
        Ok(released)
    }

    /// Returns current virtual-reservation and bump-prefix accounting.
    pub fn stats(&self) -> ReservedArenaStats {
        let low_used_bytes = self.low_cursor.load(Ordering::Acquire);
        let high_used_bytes = self.capacity - self.high_cursor;
        let used_bytes = low_used_bytes.saturating_add(high_used_bytes);
        ReservedArenaStats {
            virtual_reserved_bytes: self.capacity,
            used_bytes,
            low_used_bytes,
            high_used_bytes,
            available_bytes: self.high_cursor.saturating_sub(low_used_bytes),
        }
    }
}

#[cfg(unix)]
impl Drop for ReservedArena {
    fn drop(&mut self) {
        // Withdraw this reservation's base BEFORE unmapping, so the registry
        // never hands out a base that names freed memory. Domain ids never
        // repeat, so a later lookup for this domain returns `None` rather than a
        // stale or aliased base. This ordering upholds the values-must-not-
        // outlive-their-heap invariant at the registry seam.
        unregister_reservation_base(self.domain_id);
        // SAFETY: `base..base+capacity` is the exact still-owned mapping
        // returned by `mmap`; this type never splits or transfers that range.
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast(), self.capacity) };
    }
}

/// Maps `capacity` bytes of demand-paged, private, anonymous read/write memory.
///
/// This is the single mmap seam shared by the fresh reservation constructor
/// ([`ReservedArena::with_capacity`]) and the heap-image reload constructor
/// (`reservation::image`); centralizing it keeps the one `mmap` `unsafe` in a
/// single reviewed place. The returned range is owned exclusively by the caller,
/// which must eventually `munmap` exactly `[base, base + capacity)`.
///
/// # Errors
///
/// Returns [`ReservedArenaError::MappingFailed`] when the operating system
/// rejects the mapping, or [`ReservedArenaError::NullMapping`] on the
/// pathological null-but-successful return.
#[cfg(unix)]
pub(super) fn map_anonymous_reservation(
    capacity: usize,
) -> Result<NonNull<u8>, ReservedArenaError> {
    // SAFETY: The arguments request a private anonymous mapping, pass no file
    // descriptor, and `capacity` is nonzero and representable by `usize`. The
    // returned range is owned exclusively by the caller.
    let mapped = unsafe {
        libc::mmap(
            ptr::null_mut(),
            capacity,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | MAP_ANONYMOUS_FLAG,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(ReservedArenaError::MappingFailed {
            capacity,
            source: std::io::Error::last_os_error(),
        });
    }
    match NonNull::new(mapped.cast::<u8>()) {
        Some(base) => Ok(base),
        None => {
            // SAFETY: A null successful return still denotes the exact mapping
            // created above; release it before reporting the unsupported base.
            let _ = unsafe { libc::munmap(mapped, capacity) };
            Err(ReservedArenaError::NullMapping { capacity })
        }
    }
}

fn validate_capacity(capacity: usize) -> Result<(), ReservedArenaError> {
    if capacity == 0 {
        return Err(ReservedArenaError::InvalidCapacity { capacity });
    }
    if capacity as u128 > u128::from(CANDIDATE_C_ADDRESS_SPACE_BYTES) {
        return Err(ReservedArenaError::CapacityTooLarge { capacity });
    }
    Ok(())
}

fn align_up(value: usize, align: usize) -> Result<usize, ReservedArenaError> {
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(ReservedArenaError::SizeOverflow)
}

/// A contiguous Candidate-C reservation operation failed.
#[derive(Debug, Error)]
pub enum ReservedArenaError {
    /// Candidate C requires a 64-bit native address space.
    #[error("Candidate-C address reservation requires a 64-bit target")]
    UnsupportedPointerWidth,
    /// Anonymous virtual mappings are unavailable on this platform.
    #[error("Candidate-C address reservation is unsupported on this platform")]
    UnsupportedPlatform,
    /// The non-reusing compressed-word domain space was exhausted.
    #[error("Candidate-C arena domain identity space is exhausted")]
    ArenaDomainExhausted,
    /// A reservation cannot have zero capacity.
    #[error("reservation capacity must be nonzero, got {capacity}")]
    InvalidCapacity {
        /// The rejected capacity.
        capacity: usize,
    },
    /// A reservation exceeded the unsigned 32-bit offset space.
    #[error("reservation capacity {capacity} exceeds 4 GiB")]
    CapacityTooLarge {
        /// The rejected capacity.
        capacity: usize,
    },
    /// The operating system rejected the anonymous mapping.
    #[error("could not reserve {capacity} bytes of contiguous address space: {source}")]
    MappingFailed {
        /// The requested virtual size.
        capacity: usize,
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// The operating system unexpectedly returned a null successful mapping.
    #[error("anonymous mapping of {capacity} bytes returned null")]
    NullMapping {
        /// The requested virtual size.
        capacity: usize,
    },
    /// An allocation unexpectedly computed a null pointer.
    #[error("reservation allocation computed a null pointer")]
    NullAllocationPointer,
    /// An allocation alignment was not a nonzero power of two.
    #[error("reservation alignment {align} is not a nonzero power of two")]
    InvalidAlignment {
        /// The rejected alignment.
        align: usize,
    },
    /// Address or allocation-size arithmetic overflowed.
    #[error("reservation address arithmetic overflowed")]
    SizeOverflow,
    /// The requested allocation did not fit the remaining index space.
    #[error(
        "reservation cannot fit {requested_size} bytes at alignment {align}; {available_bytes} bytes remain"
    )]
    OutOfSpace {
        /// The caller-requested byte size.
        requested_size: usize,
        /// The caller-requested alignment.
        align: usize,
        /// Free bytes between the opposing allocation cursors.
        available_bytes: usize,
    },
    /// A pointer was outside both currently used allocation lanes.
    #[error("address 0x{address:x} is outside the reservation's used lanes")]
    PointerOutsideUsedLanes {
        /// The rejected native address.
        address: usize,
    },
    /// A compressed offset was outside both currently used allocation lanes.
    #[error(
        "arena index {index} is outside the low {low_used_bytes}-byte lane and high lane starting at {high_lane_start}"
    )]
    IndexOutsideUsedLanes {
        /// The rejected byte offset.
        index: u32,
        /// The low lane's current used-prefix length.
        low_used_bytes: usize,
        /// The high lane's current starting offset.
        high_lane_start: usize,
    },
    /// A rewind marker did not belong to the current live allocation lane.
    #[error("reservation marker does not belong to the current live allocation lane")]
    InvalidMark,
    /// The process-global reservation base table had no free slot for this
    /// reservation's domain.
    #[error(transparent)]
    DomainRegistry(#[from] ReservationRegistryError),
}

#[cfg(all(test, unix, target_pointer_width = "64"))]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn full_reservation_exposes_the_complete_u32_offset_space() {
        let arena = ReservedArena::new().expect("4 GiB virtual reservation is available");
        assert_eq!(
            arena.stats().virtual_reserved_bytes as u64,
            CANDIDATE_C_ADDRESS_SPACE_BYTES
        );
        let first = arena.alloc(8, 8).expect("first object fits");
        assert_eq!(first.index, ArenaIndex::new(0));
        assert_eq!(
            arena
                .pointer_for_index(first.index)
                .expect("index resolves"),
            first.ptr
        );
        assert_eq!(
            arena.index_for_pointer(first.ptr).expect("pointer encodes"),
            first.index
        );
    }

    #[test]
    fn live_reservations_receive_distinct_nonzero_domains() {
        let first = ReservedArena::with_capacity(4096).expect("first reservation maps");
        let second = ReservedArena::with_capacity(4096).expect("second reservation maps");

        assert_ne!(first.domain_id(), second.domain_id());
        assert!(first.domain_id().raw() > 0);
        assert!(first.domain_id().raw() <= CANDIDATE_C_ARENA_DOMAIN_MAX);
        assert_eq!(
            ArenaDomainId::from_raw(first.domain_id().raw()),
            Some(first.domain_id())
        );
        assert_eq!(ArenaDomainId::from_raw(0), None);
        assert_eq!(
            ArenaDomainId::from_raw(CANDIDATE_C_ARENA_DOMAIN_MAX + 1),
            None
        );
    }

    #[test]
    fn allocations_align_absolute_addresses_and_roundtrip_indices() {
        let arena = ReservedArena::with_capacity(4096).expect("small reservation maps");
        let first = arena.alloc(3, 1).expect("first object fits");
        let aligned = arena.alloc(16, 64).expect("aligned object fits");
        assert_eq!(aligned.ptr.as_ptr() as usize % 64, 0);
        assert!(aligned.index.raw() >= first.index.raw() + first.reserved_size as u32);
        assert_eq!(
            arena
                .pointer_for_index(aligned.index)
                .expect("index resolves"),
            aligned.ptr
        );
        assert_eq!(
            arena
                .index_for_pointer(aligned.ptr)
                .expect("pointer encodes"),
            aligned.index
        );
        assert!(matches!(
            arena.alloc(1, 3),
            Err(ReservedArenaError::InvalidAlignment { align: 3 })
        ));
    }

    #[test]
    fn exclusive_and_atomic_allocations_share_one_monotonic_cursor() {
        let mut arena = ReservedArena::with_capacity(4096).expect("small reservation maps");
        let exclusive = arena
            .alloc_exclusive(24, 8)
            .expect("exclusive allocation fits");
        let atomic = arena.alloc(24, 8).expect("atomic allocation fits");
        assert_ne!(exclusive.index, atomic.index);
        assert!(exclusive.index < atomic.index);
        assert_eq!(
            arena
                .index_for_pointer(exclusive.ptr)
                .expect("exclusive pointer encodes"),
            exclusive.index
        );
        assert_eq!(
            arena
                .index_for_pointer(atomic.ptr)
                .expect("atomic pointer encodes"),
            atomic.index
        );
        assert_eq!(arena.stats().used_bytes, 48);
    }

    #[test]
    fn bounds_checks_reject_exhaustion_and_unused_offsets() {
        let arena = ReservedArena::with_capacity(64).expect("small reservation maps");
        let allocation = arena.alloc(64, 1).expect("exact capacity fits");
        assert!(matches!(
            arena.alloc(1, 1),
            Err(ReservedArenaError::OutOfSpace { .. })
        ));
        assert!(matches!(
            arena.pointer_for_index(ArenaIndex::new(64)),
            Err(ReservedArenaError::IndexOutsideUsedLanes { .. })
        ));
        assert_eq!(
            arena
                .index_for_pointer(allocation.ptr)
                .expect("pointer encodes"),
            allocation.index
        );
        assert!(matches!(
            arena.index_for_pointer(NonNull::dangling()),
            Err(ReservedArenaError::PointerOutsideUsedLanes { .. })
        ));
    }

    #[test]
    fn low_and_high_lanes_share_indices_and_rewind_independently() {
        let mut arena = ReservedArena::with_capacity(4096).expect("small reservation maps");
        let low = arena.alloc_exclusive(24, 8).expect("low object fits");
        let mark = arena.high_mark();
        let high = arena.alloc_exclusive_high(40, 8).expect("high object fits");
        assert!(low.index < high.index);
        assert_eq!(
            arena
                .index_for_pointer(high.ptr)
                .expect("high pointer encodes"),
            high.index
        );
        assert_eq!(
            arena
                .pointer_for_index(high.index)
                .expect("high index resolves"),
            high.ptr
        );
        assert_eq!(arena.stats().low_used_bytes, 24);
        assert_eq!(arena.stats().high_used_bytes, 40);

        let later_low = arena.alloc_exclusive(8, 8).expect("later low object fits");
        assert_eq!(
            arena
                .pop_high_caller_validated_to_mark(mark)
                .expect("high marker remains valid across low allocation"),
            40
        );
        assert_eq!(
            arena
                .index_for_pointer(later_low.ptr)
                .expect("later low pointer encodes"),
            later_low.index
        );
        assert!(matches!(
            arena.index_for_pointer(high.ptr),
            Err(ReservedArenaError::PointerOutsideUsedLanes { .. })
        ));
        let replacement = arena
            .alloc_exclusive_high(40, 8)
            .expect("replacement high object fits");
        assert_eq!(replacement.index, high.index);
        assert_eq!(replacement.ptr, high.ptr);
    }

    #[test]
    fn opposing_lanes_reject_colliding_allocations() {
        let mut arena = ReservedArena::with_capacity(64).expect("small reservation maps");
        arena.alloc_exclusive(32, 8).expect("low half fits");
        arena
            .alloc_exclusive_high(24, 8)
            .expect("high portion fits");
        assert!(matches!(
            arena.alloc_exclusive(16, 8),
            Err(ReservedArenaError::OutOfSpace { .. })
        ));
        assert!(matches!(
            arena.alloc_exclusive_high(16, 8),
            Err(ReservedArenaError::OutOfSpace { .. })
        ));
    }

    #[test]
    fn caller_validated_rewind_reuses_the_same_index() {
        let mut arena = ReservedArena::with_capacity(4096).expect("small reservation maps");
        let _retained = arena.alloc(8, 8).expect("retained object fits");
        let mark = arena.mark();
        let temporary = arena.alloc(32, 16).expect("temporary object fits");
        assert!(
            arena
                .pop_caller_validated_to_mark(mark)
                .expect("mark is valid")
                >= 32
        );
        let replacement = arena.alloc(32, 16).expect("replacement fits");
        assert_eq!(replacement.index, temporary.index);
        assert_eq!(replacement.ptr, temporary.ptr);
    }

    #[test]
    fn reservation_owner_can_cross_worker_boundaries() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<ReservedArena>();
    }

    #[test]
    fn concurrent_allocations_claim_disjoint_aligned_offsets() {
        let arena =
            Arc::new(ReservedArena::with_capacity(1 << 20).expect("concurrent reservation maps"));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let arena = Arc::clone(&arena);
                thread::spawn(move || {
                    (0..128)
                        .map(|_| arena.alloc(24, 8).map(|allocation| allocation.index.raw()))
                        .collect::<Result<Vec<_>, _>>()
                })
            })
            .collect();
        let mut indices = Vec::new();
        for worker in workers {
            let claimed = worker
                .join()
                .expect("allocation worker joins")
                .expect("allocation worker succeeds");
            indices.extend(claimed);
        }
        indices.sort_unstable();
        indices.dedup();
        assert_eq!(indices.len(), 8 * 128);
        assert!(indices.iter().all(|index| index % 8 == 0));
        assert_eq!(arena.stats().used_bytes, 8 * 128 * 24);
    }
}
