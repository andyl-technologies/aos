//! Candidate-C contiguous address-space reservation.
//!
//! Candidate C represents heap references as unsigned 32-bit byte offsets into
//! one 4 GiB virtual reservation. [`ReservedArena`] owns that reservation,
//! validates every pointer/index conversion against its used prefix, and bumps
//! monotonically. The mapping is read/write but demand paged, so reserving the
//! index space does not commit 4 GiB of resident memory.
//!
//! This module intentionally does not define concrete object layouts. It
//! returns opaque [`HeapObject`] handles so the flat-object store can adopt the
//! index space without exposing raw references or unchecked pointer decoding.

use std::ptr::{self, NonNull};

use thiserror::Error;

use crate::value::HeapObject;

/// The virtual address-space size required by a full unsigned 32-bit offset.
pub const CANDIDATE_C_ADDRESS_SPACE_BYTES: u64 = 1_u64 << 32;

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
    /// Bytes in the bump allocator's used prefix, including alignment padding.
    pub used_bytes: usize,
    /// Bytes still available after the bump cursor.
    pub available_bytes: usize,
}

/// A LIFO marker in one contiguous Candidate-C reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedArenaMark {
    base_address: usize,
    cursor: usize,
}

impl ReservedArenaMark {
    /// Returns the used-prefix length captured by the marker.
    pub const fn cursor(self) -> usize {
        self.cursor
    }
}

/// A single, monotonically allocated Candidate-C address space.
#[derive(Debug)]
pub struct ReservedArena {
    base: NonNull<u8>,
    capacity: usize,
    cursor: usize,
}

// SAFETY: The arena uniquely owns its anonymous mapping, which is not tied to
// the creating thread. Allocation and rewind require exclusive `&mut` access,
// and moving the owner preserves the base address and mapping lifetime.
unsafe impl Send for ReservedArena {}

// SAFETY: Shared access exposes only accounting or checked opaque addresses;
// it cannot mutate the bump cursor or mapped bytes. Allocation, rewind, and
// unmapping require exclusive access or ownership.
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

        // SAFETY: The arguments request a private anonymous mapping, pass no
        // file descriptor, and `capacity` is nonzero and representable by
        // `usize`. The returned range is owned exclusively by this arena.
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
        let Some(base) = NonNull::new(mapped.cast::<u8>()) else {
            // SAFETY: A null successful return still denotes the exact mapping
            // created above; release it before reporting the unsupported base.
            let _ = unsafe { libc::munmap(mapped, capacity) };
            return Err(ReservedArenaError::NullMapping { capacity });
        };
        Ok(Self {
            base,
            capacity,
            cursor: 0,
        })
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

    /// Allocates an aligned opaque object range and returns both handle forms.
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
        &mut self,
        requested_size: usize,
        align: usize,
    ) -> Result<ReservedArenaAllocation, ReservedArenaError> {
        if !align.is_power_of_two() {
            return Err(ReservedArenaError::InvalidAlignment { align });
        }
        let reserved_size = requested_size.max(1);
        let base_address = self.base.as_ptr() as usize;
        let cursor_address = base_address
            .checked_add(self.cursor)
            .ok_or(ReservedArenaError::SizeOverflow)?;
        let aligned_address = align_up(cursor_address, align)?;
        let start = aligned_address
            .checked_sub(base_address)
            .ok_or(ReservedArenaError::SizeOverflow)?;
        let end = start
            .checked_add(reserved_size)
            .ok_or(ReservedArenaError::SizeOverflow)?;
        if end > self.capacity || start > u32::MAX as usize {
            return Err(ReservedArenaError::OutOfSpace {
                requested_size,
                align,
                available_bytes: self.capacity.saturating_sub(self.cursor),
            });
        }

        // SAFETY: `start < end <= capacity`, so the computed address remains
        // inside the live mapping (or at its first byte for a one-byte object).
        let address = unsafe { self.base.as_ptr().add(start) };
        let Some(ptr) = NonNull::new(address.cast::<HeapObject>()) else {
            return Err(ReservedArenaError::NullAllocationPointer);
        };
        self.cursor = end;
        Ok(ReservedArenaAllocation {
            index: ArenaIndex::new(start as u32),
            ptr,
            requested_size,
            reserved_size,
            align,
        })
    }

    /// Converts an address in the used prefix to its compressed byte offset.
    ///
    /// The address need not be an object boundary. Concrete object registries
    /// remain responsible for validating exact allocation starts and liveness.
    ///
    /// # Errors
    ///
    /// Returns an error when `ptr` is below the mapping base or outside the
    /// arena's current used prefix.
    pub fn index_for_pointer(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<ArenaIndex, ReservedArenaError> {
        let base_address = self.base.as_ptr() as usize;
        let address = ptr.as_ptr() as usize;
        let Some(offset) = address.checked_sub(base_address) else {
            return Err(ReservedArenaError::PointerOutsideUsedPrefix { address });
        };
        if offset >= self.cursor || offset > u32::MAX as usize {
            return Err(ReservedArenaError::PointerOutsideUsedPrefix { address });
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
    /// Returns an error when `index` lies outside the arena's current used
    /// prefix.
    pub fn pointer_for_index(
        &self,
        index: ArenaIndex,
    ) -> Result<NonNull<HeapObject>, ReservedArenaError> {
        let offset = index.raw() as usize;
        if offset >= self.cursor {
            return Err(ReservedArenaError::IndexOutsideUsedPrefix {
                index: index.raw(),
                used_bytes: self.cursor,
            });
        }
        // SAFETY: The used-prefix check proves `offset < cursor <= capacity`,
        // so the computed address is inside this arena's live mapping.
        let address = unsafe { self.base.as_ptr().add(offset) };
        NonNull::new(address.cast::<HeapObject>()).ok_or(ReservedArenaError::NullAllocationPointer)
    }

    /// Captures a LIFO marker for a caller-validated lexical region.
    pub fn mark(&self) -> ReservedArenaMark {
        ReservedArenaMark {
            base_address: self.base.as_ptr() as usize,
            cursor: self.cursor,
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
        if mark.base_address != self.base.as_ptr() as usize || mark.cursor > self.cursor {
            return Err(ReservedArenaError::InvalidMark);
        }
        let released = self.cursor - mark.cursor;
        self.cursor = mark.cursor;
        Ok(released)
    }

    /// Returns current virtual-reservation and bump-prefix accounting.
    pub fn stats(&self) -> ReservedArenaStats {
        ReservedArenaStats {
            virtual_reserved_bytes: self.capacity,
            used_bytes: self.cursor,
            available_bytes: self.capacity - self.cursor,
        }
    }
}

#[cfg(unix)]
impl Drop for ReservedArena {
    fn drop(&mut self) {
        // SAFETY: `base..base+capacity` is the exact still-owned mapping
        // returned by `mmap`; this type never splits or transfers that range.
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast(), self.capacity) };
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
        /// Bytes after the current cursor, before alignment padding.
        available_bytes: usize,
    },
    /// A pointer was not in the current used prefix.
    #[error("address 0x{address:x} is outside the reservation's used prefix")]
    PointerOutsideUsedPrefix {
        /// The rejected native address.
        address: usize,
    },
    /// A compressed offset was not in the current used prefix.
    #[error("arena index {index} is outside the {used_bytes}-byte used prefix")]
    IndexOutsideUsedPrefix {
        /// The rejected byte offset.
        index: u32,
        /// The current used-prefix length.
        used_bytes: usize,
    },
    /// A rewind marker did not belong to the current live prefix.
    #[error("reservation marker does not belong to the current live prefix")]
    InvalidMark,
}

#[cfg(all(test, unix, target_pointer_width = "64"))]
mod tests {
    use super::*;

    #[test]
    fn full_reservation_exposes_the_complete_u32_offset_space() {
        let mut arena = ReservedArena::new().expect("4 GiB virtual reservation is available");
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
    fn allocations_align_absolute_addresses_and_roundtrip_indices() {
        let mut arena = ReservedArena::with_capacity(4096).expect("small reservation maps");
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
    fn bounds_checks_reject_exhaustion_and_unused_offsets() {
        let mut arena = ReservedArena::with_capacity(64).expect("small reservation maps");
        let allocation = arena.alloc(64, 1).expect("exact capacity fits");
        assert!(matches!(
            arena.alloc(1, 1),
            Err(ReservedArenaError::OutOfSpace { .. })
        ));
        assert!(matches!(
            arena.pointer_for_index(ArenaIndex::new(64)),
            Err(ReservedArenaError::IndexOutsideUsedPrefix { .. })
        ));
        assert_eq!(
            arena
                .index_for_pointer(allocation.ptr)
                .expect("pointer encodes"),
            allocation.index
        );
        assert!(matches!(
            arena.index_for_pointer(NonNull::dangling()),
            Err(ReservedArenaError::PointerOutsideUsedPrefix { .. })
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
}
