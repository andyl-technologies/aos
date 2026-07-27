//! Virtually reserved, directly indexed storage for compact heap lanes.
//!
//! [`StableReservedLane`] owns one demand-paged virtual reservation and fills it
//! monotonically with one payload type. Growth never reallocates or copies
//! initialized payloads, while resolution is a checked base-plus-offset load
//! with no segment-directory indirection.
//!
//! Values published outside the lane use its separate logical domain. The
//! mapping's internal registered domain is never exposed, so context-free
//! pointer reconstruction fails closed and the owning heap must select the
//! correct typed lane first.

use std::marker::PhantomData;
use std::mem;
use std::ptr::NonNull;

use thiserror::Error;

use super::{ArenaDomainId, ReservedArena, ReservedArenaError};

/// An element index into one typed [`StableReservedLane`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StableLaneCoordinate(u32);

impl StableLaneCoordinate {
    /// Returns the encoded element index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Reconstructs an index for checked resolution by its owning typed lane.
    pub const fn from_u32(raw: u32) -> Self {
        Self(raw)
    }
}

/// A failure to configure or append to a [`StableReservedLane`].
#[derive(Debug, Error)]
pub enum StableLaneError {
    /// A lane must admit at least one payload.
    #[error("stable reserved lane capacity must be nonzero")]
    ZeroCapacity,
    /// Zero-sized values cannot receive distinct byte coordinates.
    #[error("stable reserved lanes do not support zero-sized payloads")]
    ZeroSizedPayload,
    /// The requested payload capacity overflowed addressable bytes.
    #[error("stable reserved lane capacity overflow for {elements} elements")]
    CapacityOverflow {
        /// Requested payload capacity.
        elements: usize,
    },
    /// The lane has initialized every admitted payload slot.
    #[error("stable reserved lane is full at {capacity} elements")]
    Full {
        /// Admitted payload capacity.
        capacity: usize,
    },
    /// A contiguous append does not fit the lane's remaining admitted slots.
    #[error(
        "stable reserved lane cannot append {requested} elements with {remaining} slots remaining"
    )]
    InsufficientCapacity {
        /// Requested contiguous payload count.
        requested: usize,
        /// Uninitialized admitted slots.
        remaining: usize,
    },
    /// A public contiguous range count exceeded `u32`.
    #[error("stable reserved lane range count {elements} exceeds u32")]
    RangeCountOverflow {
        /// Requested contiguous payload count.
        elements: usize,
    },
    /// The private virtual reservation could not be created or extended.
    #[error(transparent)]
    Reservation(#[from] ReservedArenaError),
    /// The reservation returned a non-contiguous coordinate.
    #[error("stable reserved lane allocation broke fixed-stride layout")]
    NonContiguousAllocation,
}

/// A fixed-capacity typed lane backed by a stable demand-paged reservation.
///
/// The lane destroys initialized payloads in coordinate order before unmapping
/// its reservation. Copyable packed streams can additionally use
/// [`Self::try_extend_contiguous`] for one-allocation range appends.
#[derive(Debug)]
pub struct StableReservedLane<T> {
    arena: ReservedArena,
    logical_domain: ArenaDomainId,
    first_offset: Option<usize>,
    base: NonNull<T>,
    len: usize,
    capacity: usize,
    mapped_bytes: usize,
    _payload: PhantomData<T>,
}

impl<T> StableReservedLane<T> {
    /// Reserves virtual capacity for exactly `capacity` payloads.
    ///
    /// Physical pages remain demand-paged until initialized. The mapping
    /// includes at most `align_of::<T>() - 1` leading padding bytes so the
    /// first payload can satisfy its alignment.
    ///
    /// # Errors
    ///
    /// Returns [`StableLaneError`] for zero capacity, zero-sized payloads,
    /// byte-count overflow, logical-domain exhaustion, unsupported mappings,
    /// or virtual reservation failure.
    pub fn with_capacity(capacity: usize) -> Result<Self, StableLaneError> {
        if capacity == 0 {
            return Err(StableLaneError::ZeroCapacity);
        }
        let size = mem::size_of::<T>();
        if size == 0 {
            return Err(StableLaneError::ZeroSizedPayload);
        }
        let mapped_bytes = capacity
            .checked_mul(size)
            .and_then(|bytes| bytes.checked_add(mem::align_of::<T>() - 1))
            .ok_or(StableLaneError::CapacityOverflow { elements: capacity })?;
        let arena = ReservedArena::with_capacity(mapped_bytes)?;
        let logical_domain = ArenaDomainId::allocate_logical()?;
        Ok(Self {
            arena,
            logical_domain,
            first_offset: None,
            base: NonNull::dangling(),
            len: 0,
            capacity,
            mapped_bytes,
            _payload: PhantomData,
        })
    }

    /// Appends one payload without reallocating prior storage.
    ///
    /// # Errors
    ///
    /// Returns [`StableLaneError::Full`] when the admitted capacity is
    /// exhausted, or another [`StableLaneError`] if the reservation cannot
    /// provide the expected fixed-stride coordinate.
    pub fn try_push(&mut self, value: T) -> Result<StableLaneCoordinate, StableLaneError> {
        if self.len == self.capacity {
            return Err(StableLaneError::Full {
                capacity: self.capacity,
            });
        }
        let coordinate =
            u32::try_from(self.len).map_err(|_| StableLaneError::CapacityOverflow {
                elements: self.capacity,
            })?;
        let allocation = self
            .arena
            .alloc_exclusive(mem::size_of::<T>(), mem::align_of::<T>())?;
        let raw = allocation.index.raw() as usize;
        let first = self.first_offset.unwrap_or(raw);
        let expected = self
            .len
            .checked_mul(mem::size_of::<T>())
            .and_then(|bytes| first.checked_add(bytes))
            .ok_or(StableLaneError::CapacityOverflow {
                elements: self.capacity,
            })?;
        if raw != expected {
            return Err(StableLaneError::NonContiguousAllocation);
        }
        // SAFETY: `allocation` is an aligned, exclusively claimed live range
        // large enough for `T`. This lane owns the reservation, never reuses a
        // coordinate, and its `Drop` pass destroys every initialized slot.
        unsafe { allocation.ptr.as_ptr().cast::<T>().write(value) };
        self.first_offset = Some(first);
        if self.len == 0 {
            self.base = allocation.ptr.cast::<T>();
        }
        self.len += 1;
        Ok(StableLaneCoordinate(coordinate))
    }

    /// Appends one copyable range as adjacent fixed-stride payloads.
    ///
    /// Empty ranges do not allocate and return `None`.
    ///
    /// # Errors
    ///
    /// Returns [`StableLaneError`] when the range does not fit, its coordinate
    /// or byte count cannot be represented, or the reservation cannot provide
    /// the expected fixed-stride range.
    pub fn try_extend_contiguous(
        &mut self,
        values: &[T],
    ) -> Result<Option<(StableLaneCoordinate, u32)>, StableLaneError>
    where
        T: Copy,
    {
        if values.is_empty() {
            return Ok(None);
        }
        let remaining = self.capacity.saturating_sub(self.len);
        if values.len() > remaining {
            return Err(StableLaneError::InsufficientCapacity {
                requested: values.len(),
                remaining,
            });
        }
        let count =
            u32::try_from(values.len()).map_err(|_| StableLaneError::RangeCountOverflow {
                elements: values.len(),
            })?;
        let coordinate =
            u32::try_from(self.len).map_err(|_| StableLaneError::CapacityOverflow {
                elements: self.capacity,
            })?;
        let byte_count = values.len().checked_mul(mem::size_of::<T>()).ok_or(
            StableLaneError::CapacityOverflow {
                elements: self.capacity,
            },
        )?;
        let next_len =
            self.len
                .checked_add(values.len())
                .ok_or(StableLaneError::CapacityOverflow {
                    elements: self.capacity,
                })?;
        let expected = self.first_offset.and_then(|first| {
            self.len
                .checked_mul(mem::size_of::<T>())?
                .checked_add(first)
        });
        let allocation = self
            .arena
            .alloc_exclusive(byte_count, mem::align_of::<T>())?;
        let raw = allocation.index.raw() as usize;
        if expected.is_some_and(|expected| raw != expected) {
            return Err(StableLaneError::NonContiguousAllocation);
        }
        // SAFETY: the allocation is aligned and exclusively claims
        // `values.len()` adjacent `T` slots. Safe borrowing prevents `values`
        // from aliasing this lane, and `T: Copy` has no drop obligation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                values.as_ptr(),
                allocation.ptr.as_ptr().cast::<T>(),
                values.len(),
            )
        };
        if self.len == 0 {
            self.first_offset = Some(raw);
            self.base = allocation.ptr.cast::<T>();
        }
        self.len = next_len;
        Ok(Some((StableLaneCoordinate(coordinate), count)))
    }

    /// Resolves a checked initialized coordinate.
    #[inline(always)]
    pub fn get(&self, coordinate: StableLaneCoordinate) -> Option<&T> {
        let address = self.address_for(coordinate)?;
        // SAFETY: `address_for` proves this is the aligned start of an
        // initialized `T` in this lane. Shared borrowing excludes mutation,
        // and the owned reservation keeps the address mapped.
        Some(unsafe { &*address.cast::<T>() })
    }

    /// Resolves a checked initialized coordinate for in-place mutation.
    #[inline(always)]
    pub fn get_mut(&mut self, coordinate: StableLaneCoordinate) -> Option<&mut T> {
        let address = self.address_for(coordinate)?;
        // SAFETY: `address_for` proves this is the aligned start of an
        // initialized `T` in this lane. Exclusive borrowing prevents aliases
        // through this safe API, and the owned reservation stays mapped.
        Some(unsafe { &mut *address.cast::<T>() })
    }

    /// Returns the logical domain that must accompany published coordinates.
    pub const fn domain(&self) -> ArenaDomainId {
        self.logical_domain
    }

    /// Returns the number of initialized payloads.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the lane contains no initialized payloads.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the admitted payload count.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns initialized payload bytes, excluding leading alignment padding.
    pub fn initialized_bytes(&self) -> Option<usize> {
        self.len.checked_mul(mem::size_of::<T>())
    }

    /// Returns virtually reserved bytes, including possible alignment padding.
    pub const fn virtual_reserved_bytes(&self) -> usize {
        self.mapped_bytes
    }

    #[inline(always)]
    fn address_for(&self, coordinate: StableLaneCoordinate) -> Option<*mut T> {
        let slot = coordinate.0 as usize;
        if slot >= self.len {
            return None;
        }
        // The fixed-capacity constructor and successful fixed-stride
        // allocations prove this initialized slot remains in the live mapping.
        Some(self.base.as_ptr().wrapping_add(slot))
    }
}

impl<T> Drop for StableReservedLane<T> {
    fn drop(&mut self) {
        for slot in 0..self.len {
            // SAFETY: every coordinate below `len` was initialized exactly
            // once as `T`, fixed-stride allocation prevents overlap, and this
            // exclusive drop pass is the lane's only destruction path.
            unsafe { std::ptr::drop_in_place(self.base.as_ptr().add(slot)) };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::hint::black_box;
    use std::rc::Rc;
    use std::time::Instant;

    use super::*;

    #[derive(Debug)]
    struct DropPayload(Rc<Cell<usize>>);

    impl Drop for DropPayload {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn coordinates_are_fixed_stride_and_resolve_exact_slots() {
        let mut lane = StableReservedLane::<u64>::with_capacity(3).expect("lane reservation");
        let first = lane.try_push(11).expect("first payload");
        let second = lane.try_push(22).expect("second payload");

        assert_eq!(second.as_u32() - first.as_u32(), 1);
        assert_eq!(lane.get(first), Some(&11));
        assert_eq!(lane.get(second), Some(&22));
        assert_eq!(lane.get(StableLaneCoordinate::from_u32(2)), None,);
    }

    #[test]
    fn payload_addresses_remain_stable() {
        let mut lane = StableReservedLane::<u64>::with_capacity(32_768).expect("lane reservation");
        let first = lane.try_push(41).expect("first payload");
        let address = lane.get(first).expect("first payload resolves") as *const u64;
        for value in 0..32_767 {
            lane.try_push(value).expect("later payload");
        }

        assert_eq!(lane.get(first), Some(&41));
        assert_eq!(
            lane.get(first).map(|value| value as *const u64),
            Some(address)
        );
    }

    #[test]
    fn capacity_is_enforced_without_mutation() {
        let mut lane = StableReservedLane::<u64>::with_capacity(1).expect("lane reservation");
        lane.try_push(1).expect("admitted payload");

        assert!(matches!(
            lane.try_push(2),
            Err(StableLaneError::Full { capacity: 1 })
        ));
        assert_eq!(lane.len(), 1);
    }

    #[test]
    fn contiguous_appends_preserve_adjacency_and_fail_before_writing() {
        let mut lane = StableReservedLane::<u64>::with_capacity(5).expect("lane reservation");
        let (start, count) = lane
            .try_extend_contiguous(&[10, 20, 30])
            .expect("range fits")
            .expect("range is nonempty");
        let following = lane.try_push(40).expect("following payload");

        assert_eq!(start.as_u32(), 0);
        assert_eq!(count, 3);
        assert_eq!(lane.get(StableLaneCoordinate::from_u32(0)), Some(&10));
        assert_eq!(lane.get(StableLaneCoordinate::from_u32(1)), Some(&20));
        assert_eq!(lane.get(StableLaneCoordinate::from_u32(2)), Some(&30));
        assert_eq!(lane.get(following), Some(&40));
        assert!(matches!(
            lane.try_extend_contiguous(&[50, 60]),
            Err(StableLaneError::InsufficientCapacity {
                requested: 2,
                remaining: 1,
            })
        ));
        assert_eq!(lane.len(), 4);
    }

    #[test]
    fn zero_capacity_and_zero_sized_payloads_are_rejected() {
        assert!(matches!(
            StableReservedLane::<u64>::with_capacity(0),
            Err(StableLaneError::ZeroCapacity)
        ));
        assert!(matches!(
            StableReservedLane::<()>::with_capacity(1),
            Err(StableLaneError::ZeroSizedPayload)
        ));
    }

    #[test]
    fn initialized_payloads_are_dropped_exactly_once() {
        let drops = Rc::new(Cell::new(0));
        {
            let mut lane =
                StableReservedLane::<DropPayload>::with_capacity(3).expect("lane reservation");
            for _ in 0..3 {
                lane.try_push(DropPayload(Rc::clone(&drops)))
                    .expect("payload fits");
            }
        }

        assert_eq!(drops.get(), 3);
    }

    #[test]
    #[ignore = "manual pinned-builder microbenchmark"]
    fn stable_reserved_read_overhead_probe() {
        const ELEMENTS: usize = 1 << 20;
        const READS: usize = 1 << 24;

        let direct = (0..ELEMENTS as u64).collect::<Vec<_>>();
        let mut stable =
            StableReservedLane::<u64>::with_capacity(ELEMENTS).expect("lane reservation");
        for value in 0..ELEMENTS as u64 {
            stable.try_push(value).expect("stable payload");
        }
        let element_mask = black_box(ELEMENTS - 1);

        let direct_start = Instant::now();
        let mut direct_state = 1u32;
        let mut direct_sum = 0u64;
        for _ in 0..READS {
            direct_state = direct_state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223);
            let index = direct_state as usize & element_mask;
            direct_sum = direct_sum
                .wrapping_add(*direct.get(index).expect("generated direct index resolves"));
        }
        black_box(direct_sum);
        let direct_elapsed = direct_start.elapsed();

        let stable_start = Instant::now();
        let mut stable_state = 1u32;
        let mut stable_sum = 0u64;
        for _ in 0..READS {
            stable_state = stable_state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223);
            let index = stable_state as usize & element_mask;
            stable_sum = stable_sum.wrapping_add(
                *stable
                    .get(StableLaneCoordinate::from_u32(index as u32))
                    .expect("generated coordinate resolves"),
            );
        }
        black_box(stable_sum);
        let stable_elapsed = stable_start.elapsed();

        assert_eq!(direct_sum, stable_sum);
        eprintln!(
            "stable-reserved-read-probe direct_ns={} stable_ns={} ratio={:.4}",
            direct_elapsed.as_nanos(),
            stable_elapsed.as_nanos(),
            stable_elapsed.as_secs_f64() / direct_elapsed.as_secs_f64()
        );
    }

    #[test]
    #[ignore = "manual pinned-builder microbenchmark"]
    fn stable_reserved_allocation_overhead_probe() {
        use super::super::flat::{FlatObjectKind, HeaderlessFlatLane, SharedFlatStoreArena};

        const ELEMENTS: usize = 1 << 20;
        const BLOCK_SLOTS: usize = 1 << 13;

        let arena = SharedFlatStoreArena::new();
        let mut headerless = HeaderlessFlatLane::<u64>::with_block_slots(
            arena,
            FlatObjectKind::ThunkHead,
            BLOCK_SLOTS,
        )
        .expect("headerless lane");
        let headerless_start = Instant::now();
        for value in 0..ELEMENTS as u64 {
            black_box(headerless.alloc(value).expect("headerless payload"));
        }
        let headerless_elapsed = headerless_start.elapsed();

        let mut stable =
            StableReservedLane::<u64>::with_capacity(ELEMENTS).expect("lane reservation");
        let stable_start = Instant::now();
        for value in 0..ELEMENTS as u64 {
            black_box(stable.try_push(value).expect("stable payload"));
        }
        let stable_elapsed = stable_start.elapsed();

        assert_eq!(headerless.len(), stable.len());
        eprintln!(
            "stable-reserved-allocation-probe headerless_ns={} stable_ns={} ratio={:.4}",
            headerless_elapsed.as_nanos(),
            stable_elapsed.as_nanos(),
            stable_elapsed.as_secs_f64() / headerless_elapsed.as_secs_f64()
        );
    }
}
