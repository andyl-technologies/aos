//! Headerless exact-capacity destinations for boxed scalar payloads.
//!
//! Boxed integers and floats occupy separate fixed-stride lanes:
//!
//! ```text
//! integer lane   i64 payload                         8 bytes
//! float lane     exact IEEE-754 payload bits         8 bytes
//! ```
//!
//! Direct `u32` coordinates replace per-object headers and pointer registries.
//! Float storage retains the complete bit pattern, including NaN payloads and
//! signed zero. [`PackedScalarLaneDirectBuilder`] reserves both vectors before
//! accepting values and rejects any append that exceeds the admitted logical
//! capacity. A finalized lane performs no allocation while resolving values.

use std::mem;

use thiserror::Error;

/// A direct fixed-stride coordinate in the packed integer lane.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PackedIntRef(u32);

impl PackedIntRef {
    /// Builds a direct coordinate for checked lane resolution.
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the fixed-record index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

/// A direct fixed-stride coordinate in the packed float lane.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PackedFloatRef(u32);

impl PackedFloatRef {
    /// Builds a direct coordinate for checked lane resolution.
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the fixed-record index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

/// Exact logical element counts admitted for one direct packed build.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackedScalarLaneCapacities {
    /// Boxed integer payloads.
    pub(crate) integers: usize,
    /// Boxed float payloads.
    pub(crate) floats: usize,
}

/// Exact per-vector bytes owned by a finalized packed scalar lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedScalarLaneBytes {
    /// Bytes occupied by the finalized lane's vector descriptors.
    pub(crate) control: usize,
    /// Bytes occupied by initialized or reserved integer payloads.
    pub(crate) integers: usize,
    /// Bytes occupied by initialized or reserved float payload bits.
    pub(crate) floats: usize,
}

impl PackedScalarLaneBytes {
    /// Returns the checked sum of every reported component.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError::ByteAccountingOverflow`] when the
    /// component byte counts cannot be summed in `usize`.
    pub(crate) fn total(self) -> Result<usize, PackedScalarLaneError> {
        self.control
            .checked_add(self.integers)
            .and_then(|total| total.checked_add(self.floats))
            .ok_or(PackedScalarLaneError::ByteAccountingOverflow)
    }
}

/// A finalized immutable boxed-scalar destination with no object registry.
#[derive(Debug, Default)]
pub(crate) struct PackedScalarLane {
    integers: Vec<i64>,
    float_bits: Vec<u64>,
}

impl PackedScalarLane {
    /// Returns the number of initialized boxed integers.
    pub(crate) fn integer_count(&self) -> usize {
        self.integers.len()
    }

    /// Returns the number of initialized boxed floats.
    pub(crate) fn float_count(&self) -> usize {
        self.float_bits.len()
    }

    /// Returns exact initialized bytes, including vector descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError::ByteAccountingOverflow`] when a vector
    /// length cannot be represented as a byte count.
    pub(crate) fn initialized_bytes(&self) -> Result<PackedScalarLaneBytes, PackedScalarLaneError> {
        scalar_bytes(self.integers.len(), self.float_bits.len())
    }

    /// Returns allocator-granted capacity bytes, including vector descriptors.
    ///
    /// This reports actual allocator capacities, which may exceed the logical
    /// counts requested through `Vec::try_reserve_exact`.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError::ByteAccountingOverflow`] when a vector
    /// capacity cannot be represented as a byte count.
    pub(crate) fn capacity_bytes(&self) -> Result<PackedScalarLaneBytes, PackedScalarLaneError> {
        scalar_bytes(self.integers.capacity(), self.float_bits.capacity())
    }

    /// Resolves one packed integer without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError::UnknownInteger`] when `reference` is
    /// stale or outside this generation's integer lane.
    pub(crate) fn integer(&self, reference: PackedIntRef) -> Result<i64, PackedScalarLaneError> {
        self.integers
            .get(reference.0 as usize)
            .copied()
            .ok_or(PackedScalarLaneError::UnknownInteger { index: reference.0 })
    }

    /// Resolves the exact bits of one packed float without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError::UnknownFloat`] when `reference` is
    /// stale or outside this generation's float lane.
    pub(crate) fn float_bits(
        &self,
        reference: PackedFloatRef,
    ) -> Result<u64, PackedScalarLaneError> {
        self.float_bits
            .get(reference.0 as usize)
            .copied()
            .ok_or(PackedScalarLaneError::UnknownFloat { index: reference.0 })
    }

    /// Resolves one packed float without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError::UnknownFloat`] when `reference` is
    /// stale or outside this generation's float lane.
    pub(crate) fn float(&self, reference: PackedFloatRef) -> Result<f64, PackedScalarLaneError> {
        self.float_bits(reference).map(f64::from_bits)
    }
}

/// A pre-reserved packed scalar builder that cannot grow logically.
#[derive(Debug)]
pub(crate) struct PackedScalarLaneDirectBuilder {
    lane: PackedScalarLane,
    admitted: PackedScalarLaneCapacities,
    admitted_capacity_bytes: PackedScalarLaneBytes,
}

impl PackedScalarLaneDirectBuilder {
    /// Reserves all integer and float storage before any payload is copied.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError`] when an admitted range exceeds direct
    /// coordinate width, a byte count overflows, or a reservation fails.
    pub(crate) fn try_new(
        admitted: PackedScalarLaneCapacities,
    ) -> Result<Self, PackedScalarLaneError> {
        check_direct_range(admitted.integers, "integer")?;
        check_direct_range(admitted.floats, "float")?;
        scalar_bytes(admitted.integers, admitted.floats)?;

        let mut lane = PackedScalarLane::default();
        reserve(&mut lane.integers, admitted.integers, "integer")?;
        reserve(&mut lane.float_bits, admitted.floats, "float")?;
        let admitted_capacity_bytes = lane.capacity_bytes()?;
        Ok(Self {
            lane,
            admitted,
            admitted_capacity_bytes,
        })
    }

    /// Appends one boxed integer and returns its direct coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError`] before mutation when logical admission
    /// is exhausted, the next index exceeds `u32`, or a reserved vector's
    /// allocator capacity changed unexpectedly.
    pub(crate) fn append_integer(
        &mut self,
        value: i64,
    ) -> Result<PackedIntRef, PackedScalarLaneError> {
        let index = self.lane.integers.len();
        check_append(index, self.admitted.integers, "integer")?;
        let index = checked_index(index, "integer")?;
        self.ensure_capacity_unchanged()?;
        self.lane.integers.push(value);
        Ok(PackedIntRef(index))
    }

    /// Appends one boxed float while preserving its complete bit pattern.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError`] before mutation when logical admission
    /// is exhausted, the next index exceeds `u32`, or a reserved vector's
    /// allocator capacity changed unexpectedly.
    pub(crate) fn append_float(
        &mut self,
        value: f64,
    ) -> Result<PackedFloatRef, PackedScalarLaneError> {
        self.append_float_bits(value.to_bits())
    }

    /// Appends exact boxed-float bits and returns their direct coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError`] before mutation when logical admission
    /// is exhausted, the next index exceeds `u32`, or a reserved vector's
    /// allocator capacity changed unexpectedly.
    pub(crate) fn append_float_bits(
        &mut self,
        bits: u64,
    ) -> Result<PackedFloatRef, PackedScalarLaneError> {
        let index = self.lane.float_bits.len();
        check_append(index, self.admitted.floats, "float")?;
        let index = checked_index(index, "float")?;
        self.ensure_capacity_unchanged()?;
        self.lane.float_bits.push(bits);
        Ok(PackedFloatRef(index))
    }

    /// Finalizes the lane after verifying that neither vector grew.
    ///
    /// # Errors
    ///
    /// Returns [`PackedScalarLaneError::CapacityChanged`] if allocator capacity
    /// differs from the complete pre-build reservation.
    pub(crate) fn finish(self) -> Result<PackedScalarLane, PackedScalarLaneError> {
        self.ensure_capacity_unchanged()?;
        Ok(self.lane)
    }

    fn ensure_capacity_unchanged(&self) -> Result<(), PackedScalarLaneError> {
        let actual = self.lane.capacity_bytes()?;
        if actual != self.admitted_capacity_bytes {
            return Err(PackedScalarLaneError::CapacityChanged {
                admitted: self.admitted_capacity_bytes.total()?,
                actual: actual.total()?,
            });
        }
        Ok(())
    }
}

fn scalar_bytes(
    integers: usize,
    floats: usize,
) -> Result<PackedScalarLaneBytes, PackedScalarLaneError> {
    Ok(PackedScalarLaneBytes {
        control: mem::size_of::<PackedScalarLane>(),
        integers: checked_bytes::<i64>(integers, "integer")?,
        floats: checked_bytes::<u64>(floats, "float")?,
    })
}

fn checked_bytes<T>(elements: usize, lane: &'static str) -> Result<usize, PackedScalarLaneError> {
    elements
        .checked_mul(mem::size_of::<T>())
        .ok_or(PackedScalarLaneError::ByteRangeOverflow { lane, elements })
}

fn check_direct_range(count: usize, lane: &'static str) -> Result<(), PackedScalarLaneError> {
    checked_range(0, count, lane).map(|_| ())
}

fn checked_range(
    start: usize,
    count: usize,
    lane: &'static str,
) -> Result<(u32, u32), PackedScalarLaneError> {
    let start = checked_index(start, lane)?;
    let count =
        u32::try_from(count).map_err(|_| PackedScalarLaneError::CountOverflow { lane, count })?;
    start
        .checked_add(count)
        .ok_or(PackedScalarLaneError::RangeOverflow { lane, start, count })?;
    Ok((start, count))
}

fn checked_index(index: usize, lane: &'static str) -> Result<u32, PackedScalarLaneError> {
    u32::try_from(index).map_err(|_| PackedScalarLaneError::IndexOverflow { lane, index })
}

fn check_append(
    initialized: usize,
    admitted: usize,
    lane: &'static str,
) -> Result<(), PackedScalarLaneError> {
    let attempted = initialized
        .checked_add(1)
        .ok_or(PackedScalarLaneError::RangeOverflow {
            lane,
            start: u32::MAX,
            count: 1,
        })?;
    if attempted > admitted {
        return Err(PackedScalarLaneError::CapacityExceeded {
            lane,
            admitted,
            attempted,
        });
    }
    Ok(())
}

fn reserve<T>(
    values: &mut Vec<T>,
    count: usize,
    lane: &'static str,
) -> Result<(), PackedScalarLaneError> {
    values
        .try_reserve_exact(count)
        .map_err(|_| PackedScalarLaneError::AllocationFailed { lane })
}

/// Packed scalar construction or resolution failed.
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum PackedScalarLaneError {
    /// A direct record coordinate exceeds `u32`.
    #[error("packed {lane} index {index} exceeds u32")]
    IndexOverflow {
        /// Affected packed lane.
        lane: &'static str,
        /// Rejected index.
        index: usize,
    },
    /// An admitted direct range count exceeds `u32`.
    #[error("packed {lane} count {count} exceeds u32")]
    CountOverflow {
        /// Affected packed lane.
        lane: &'static str,
        /// Rejected count.
        count: usize,
    },
    /// Direct coordinate arithmetic overflowed `u32`.
    #[error("packed {lane} range start={start} count={count} exceeds u32")]
    RangeOverflow {
        /// Affected packed lane.
        lane: &'static str,
        /// Rejected range start.
        start: u32,
        /// Rejected range count.
        count: u32,
    },
    /// Exact payload byte accounting overflowed `usize`.
    #[error("packed {lane} byte range for {elements} elements exceeds usize")]
    ByteRangeOverflow {
        /// Affected packed lane.
        lane: &'static str,
        /// Rejected element count.
        elements: usize,
    },
    /// The sum of exact component byte counts overflowed `usize`.
    #[error("packed scalar total byte accounting overflow")]
    ByteAccountingOverflow,
    /// A logical append exceeds its pre-admitted capacity.
    #[error("packed {lane} capacity exceeded: admitted {admitted}, attempted {attempted}")]
    CapacityExceeded {
        /// Affected packed lane.
        lane: &'static str,
        /// Pre-admitted logical capacity.
        admitted: usize,
        /// Attempted initialized count.
        attempted: usize,
    },
    /// A complete vector reservation failed.
    #[error("failed to reserve packed {lane} lane")]
    AllocationFailed {
        /// Affected packed lane.
        lane: &'static str,
    },
    /// A reserved vector changed allocator capacity.
    #[error("packed scalar capacity changed from {admitted} bytes to {actual} bytes")]
    CapacityChanged {
        /// Capacity bytes immediately after reservation.
        admitted: usize,
        /// Capacity bytes observed later.
        actual: usize,
    },
    /// An integer coordinate is stale or out of range.
    #[error("unknown packed integer coordinate {index}")]
    UnknownInteger {
        /// Rejected coordinate.
        index: u32,
    },
    /// A float coordinate is stale or out of range.
    #[error("unknown packed float coordinate {index}")]
    UnknownFloat {
        /// Rejected coordinate.
        index: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_capacity_build_never_grows_and_accounts_actual_layout() {
        let admitted = PackedScalarLaneCapacities {
            integers: 3,
            floats: 2,
        };
        let mut builder = PackedScalarLaneDirectBuilder::try_new(admitted).unwrap();
        let reserved = builder.admitted_capacity_bytes;
        builder.append_integer(i64::MIN).unwrap();
        builder.append_integer(0).unwrap();
        builder.append_integer(i64::MAX).unwrap();
        builder.append_float(-0.0).unwrap();
        builder.append_float_bits(0x7ff8_1234_5678_9abc).unwrap();
        let lane = builder.finish().unwrap();

        assert_eq!(lane.capacity_bytes().unwrap(), reserved);
        assert_eq!(lane.integer_count(), admitted.integers);
        assert_eq!(lane.float_count(), admitted.floats);
        let initialized = lane.initialized_bytes().unwrap();
        assert_eq!(initialized.control, mem::size_of::<PackedScalarLane>());
        assert_eq!(
            initialized.integers,
            admitted.integers * mem::size_of::<i64>()
        );
        assert_eq!(initialized.floats, admitted.floats * mem::size_of::<u64>());
        assert_eq!(
            initialized.total().unwrap(),
            mem::size_of::<PackedScalarLane>()
                + admitted.integers * mem::size_of::<i64>()
                + admitted.floats * mem::size_of::<u64>()
        );
    }

    #[test]
    fn allocation_free_resolution_preserves_all_scalar_bits() {
        let nan_bits = 0xfff8_1234_5678_9abc;
        let mut builder = PackedScalarLaneDirectBuilder::try_new(PackedScalarLaneCapacities {
            integers: 2,
            floats: 3,
        })
        .unwrap();
        let minimum = builder.append_integer(i64::MIN).unwrap();
        let maximum = builder.append_integer(i64::MAX).unwrap();
        let negative_zero = builder.append_float(-0.0).unwrap();
        let nan = builder.append_float_bits(nan_bits).unwrap();
        let infinity = builder.append_float(f64::INFINITY).unwrap();
        let lane = builder.finish().unwrap();

        assert_eq!(lane.integer(minimum).unwrap(), i64::MIN);
        assert_eq!(lane.integer(maximum).unwrap(), i64::MAX);
        assert_eq!(lane.float_bits(negative_zero).unwrap(), (-0.0f64).to_bits());
        assert_eq!(
            lane.float(negative_zero).unwrap().to_bits(),
            (-0.0f64).to_bits()
        );
        assert_eq!(lane.float_bits(nan).unwrap(), nan_bits);
        assert_eq!(lane.float(nan).unwrap().to_bits(), nan_bits);
        assert_eq!(lane.float(infinity).unwrap(), f64::INFINITY);
    }

    #[test]
    fn overfill_and_stale_coordinates_fail_before_mutation() {
        let mut builder = PackedScalarLaneDirectBuilder::try_new(PackedScalarLaneCapacities {
            integers: 1,
            floats: 1,
        })
        .unwrap();
        builder.append_integer(7).unwrap();
        builder.append_float(1.5).unwrap();
        let before = (
            builder.lane.integer_count(),
            builder.lane.float_count(),
            builder.lane.capacity_bytes().unwrap(),
        );

        assert_eq!(
            builder.append_integer(8).unwrap_err(),
            PackedScalarLaneError::CapacityExceeded {
                lane: "integer",
                admitted: 1,
                attempted: 2,
            }
        );
        assert_eq!(
            builder.append_float(2.5).unwrap_err(),
            PackedScalarLaneError::CapacityExceeded {
                lane: "float",
                admitted: 1,
                attempted: 2,
            }
        );
        assert_eq!(
            (
                builder.lane.integer_count(),
                builder.lane.float_count(),
                builder.lane.capacity_bytes().unwrap(),
            ),
            before
        );

        let lane = builder.finish().unwrap();
        assert_eq!(
            lane.integer(PackedIntRef::from_index(9)).unwrap_err(),
            PackedScalarLaneError::UnknownInteger { index: 9 }
        );
        assert_eq!(
            lane.float(PackedFloatRef::from_index(9)).unwrap_err(),
            PackedScalarLaneError::UnknownFloat { index: 9 }
        );
    }

    #[test]
    fn direct_coordinate_and_byte_ranges_are_checked() {
        assert_eq!(PackedIntRef::from_index(17).index(), 17);
        assert_eq!(PackedFloatRef::from_index(23).index(), 23);

        if usize::BITS > u32::BITS {
            let too_many = u32::MAX as usize + 1;
            assert_eq!(
                check_direct_range(too_many, "integer").unwrap_err(),
                PackedScalarLaneError::CountOverflow {
                    lane: "integer",
                    count: too_many,
                }
            );
        }

        assert_eq!(
            checked_range(u32::MAX as usize, 1, "float").unwrap_err(),
            PackedScalarLaneError::RangeOverflow {
                lane: "float",
                start: u32::MAX,
                count: 1,
            }
        );
        assert_eq!(
            checked_bytes::<u64>(usize::MAX, "float").unwrap_err(),
            PackedScalarLaneError::ByteRangeOverflow {
                lane: "float",
                elements: usize::MAX,
            }
        );
    }
}
