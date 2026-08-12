//! Growth-stable, epoch-owned storage for compact heap lanes.
//!
//! [`SegmentedLane`] keeps payload buffers in independently allocated segments,
//! so growing the segment directory never copies or temporarily duplicates
//! initialized payloads. A compact [`SegmentCoordinate`] divides its 32 bits
//! between a segment number and an in-segment slot:
//!
//! ```text
//! high bits: segment index | low bits: slot index
//! ```
//!
//! The split is chosen per payload type so an ordinary segment is at most
//! approximately 64 KiB. Contiguous payloads never cross a segment boundary;
//! payloads larger than an ordinary segment receive a dedicated segment.

use std::mem;

use thiserror::Error;

/// Target capacity in bytes for one ordinary payload segment.
pub const SEGMENTED_LANE_TARGET_BYTES: usize = 64 * 1024;

/// A compact coordinate into one typed [`SegmentedLane`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SegmentCoordinate(u32);

impl SegmentCoordinate {
    /// Returns the encoded coordinate word.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Reconstructs a coordinate from its encoded word.
    pub const fn from_u32(word: u32) -> Self {
        Self(word)
    }
}

/// A failure to configure or grow a [`SegmentedLane`].
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SegmentedLaneError {
    /// Zero-sized payloads cannot receive distinct heap coordinates.
    #[error("segmented lanes do not support zero-sized payloads")]
    ZeroSizedPayload,
    /// The segment directory could not reserve another descriptor.
    #[error("could not reserve descriptor for segment {segments}")]
    DirectoryAllocationFailed {
        /// Descriptor count requested from the directory.
        segments: usize,
    },
    /// A payload segment could not reserve its exact element capacity.
    #[error("could not reserve a payload segment containing {elements} elements")]
    SegmentAllocationFailed {
        /// Element capacity requested from the payload segment.
        elements: usize,
    },
    /// No unused segment number remains in the 32-bit coordinate.
    #[error("segment count {segments} exceeds the coordinate space with {local_bits} local bits")]
    CoordinateSpaceExhausted {
        /// Segment count that could not be represented.
        segments: usize,
        /// Low coordinate bits assigned to the in-segment slot.
        local_bits: u32,
    },
    /// The initialized element count overflowed `usize`.
    #[error("segmented lane element count overflow")]
    LengthOverflow,
    /// A requested contiguous range cannot be represented by its public count.
    #[error("contiguous payload count {elements} exceeds u32")]
    RangeCountOverflow {
        /// Requested contiguous element count.
        elements: usize,
    },
}

/// An epoch-owned typed lane whose initialized payloads never move during growth.
///
/// Ordinary segments have a power-of-two element capacity selected to stay at
/// or below [`SEGMENTED_LANE_TARGET_BYTES`]. The outer directory may move its
/// `Vec<T>` descriptors, but each descriptor continues to own the same payload
/// allocation.
#[derive(Debug)]
pub struct SegmentedLane<T> {
    segments: Vec<Vec<T>>,
    active_ordinary: Option<usize>,
    len: usize,
    local_bits: u32,
    ordinary_slots: usize,
}

impl<T> SegmentedLane<T> {
    /// Creates an empty lane for `T`.
    ///
    /// # Errors
    ///
    /// Returns [`SegmentedLaneError::ZeroSizedPayload`] when `T` is zero-sized.
    pub fn new() -> Result<Self, SegmentedLaneError> {
        let size = mem::size_of::<T>();
        if size == 0 {
            return Err(SegmentedLaneError::ZeroSizedPayload);
        }
        let target_slots = (SEGMENTED_LANE_TARGET_BYTES / size).max(1);
        let local_bits = usize::BITS - 1 - target_slots.leading_zeros();
        let ordinary_slots = 1usize << local_bits;
        Ok(Self {
            segments: Vec::new(),
            active_ordinary: None,
            len: 0,
            local_bits,
            ordinary_slots,
        })
    }

    /// Appends one payload and returns its stable coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`SegmentedLaneError`] when the segment directory, payload
    /// storage, coordinate space, or initialized element count cannot grow.
    pub fn try_push(&mut self, value: T) -> Result<SegmentCoordinate, SegmentedLaneError> {
        let segment_index = match self.active_ordinary {
            Some(index)
                if self
                    .segments
                    .get(index)
                    .is_some_and(|segment| segment.len() < self.ordinary_slots) =>
            {
                index
            }
            _ => self.push_empty_segment(self.ordinary_slots, true)?,
        };
        let segment_count = self.segments.len();
        let local = self.segments.get(segment_index).map(Vec::len).ok_or(
            SegmentedLaneError::CoordinateSpaceExhausted {
                segments: segment_count,
                local_bits: self.local_bits,
            },
        )?;
        let coordinate = self.encode(segment_index, local)?;
        let next_len = self
            .len
            .checked_add(1)
            .ok_or(SegmentedLaneError::LengthOverflow)?;
        let segment = self.segments.get_mut(segment_index).ok_or(
            SegmentedLaneError::CoordinateSpaceExhausted {
                segments: segment_count,
                local_bits: self.local_bits,
            },
        )?;
        segment.push(value);
        self.len = next_len;
        Ok(coordinate)
    }

    /// Appends a copyable payload range without crossing a segment boundary.
    ///
    /// Empty ranges are represented by no coordinate and do not allocate.
    /// A range larger than the ordinary segment capacity receives a dedicated
    /// oversized segment.
    ///
    /// # Errors
    ///
    /// Returns [`SegmentedLaneError`] when the directory, payload storage,
    /// coordinate space, public range count, or initialized length cannot grow.
    pub fn try_extend_contiguous(
        &mut self,
        values: &[T],
    ) -> Result<Option<(SegmentCoordinate, u32)>, SegmentedLaneError>
    where
        T: Copy,
    {
        if values.is_empty() {
            return Ok(None);
        }
        let count =
            u32::try_from(values.len()).map_err(|_| SegmentedLaneError::RangeCountOverflow {
                elements: values.len(),
            })?;
        let next_len = self
            .len
            .checked_add(values.len())
            .ok_or(SegmentedLaneError::LengthOverflow)?;
        let segment_index = match self.active_ordinary {
            Some(index)
                if values.len() <= self.ordinary_slots
                    && self.segments.get(index).is_some_and(|segment| {
                        self.ordinary_slots.saturating_sub(segment.len()) >= values.len()
                    }) =>
            {
                index
            }
            _ => {
                let capacity = self.ordinary_slots.max(values.len());
                self.push_empty_segment(capacity, values.len() <= self.ordinary_slots)?
            }
        };
        let segment_count = self.segments.len();
        let local = self.segments.get(segment_index).map(Vec::len).ok_or(
            SegmentedLaneError::CoordinateSpaceExhausted {
                segments: segment_count,
                local_bits: self.local_bits,
            },
        )?;
        let coordinate = self.encode(segment_index, local)?;
        let segment = self.segments.get_mut(segment_index).ok_or(
            SegmentedLaneError::CoordinateSpaceExhausted {
                segments: segment_count,
                local_bits: self.local_bits,
            },
        )?;
        for value in values {
            segment.push(*value);
        }
        self.len = next_len;
        Ok(Some((coordinate, count)))
    }

    /// Resolves one exact encoded slot.
    pub fn get(&self, coordinate: SegmentCoordinate) -> Option<&T> {
        let (segment, local) = self.decode(coordinate);
        self.segments.get(segment)?.get(local)
    }

    /// Resolves one contiguous range entirely within its owning segment.
    pub fn get_contiguous(&self, start: SegmentCoordinate, count: u32) -> Option<&[T]> {
        let (segment, local) = self.decode(start);
        let end = local.checked_add(count as usize)?;
        self.segments.get(segment)?.get(local..end)
    }

    /// Returns the number of initialized payload elements.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the lane contains no initialized payloads.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of independently allocated payload segments.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns the ordinary per-segment element capacity.
    pub const fn ordinary_slots(&self) -> usize {
        self.ordinary_slots
    }

    /// Returns the low coordinate bits assigned to an in-segment slot.
    pub const fn local_bits(&self) -> u32 {
        self.local_bits
    }

    /// Returns initialized payload bytes, excluding directory descriptors.
    pub fn initialized_bytes(&self) -> Option<usize> {
        self.len.checked_mul(mem::size_of::<T>())
    }

    /// Returns allocator-requested payload capacity bytes.
    pub fn capacity_bytes(&self) -> Option<usize> {
        self.segments.iter().try_fold(0usize, |total, segment| {
            segment
                .capacity()
                .checked_mul(mem::size_of::<T>())
                .and_then(|bytes| total.checked_add(bytes))
        })
    }

    fn push_empty_segment(
        &mut self,
        capacity: usize,
        make_active: bool,
    ) -> Result<usize, SegmentedLaneError> {
        let segment_index = self.segments.len();
        self.ensure_segment_encodable(segment_index)?;
        self.segments.try_reserve(1).map_err(|_| {
            SegmentedLaneError::DirectoryAllocationFailed {
                segments: segment_index.saturating_add(1),
            }
        })?;
        let mut segment = Vec::new();
        segment
            .try_reserve_exact(capacity)
            .map_err(|_| SegmentedLaneError::SegmentAllocationFailed { elements: capacity })?;
        self.segments.push(segment);
        if make_active {
            self.active_ordinary = Some(segment_index);
        }
        Ok(segment_index)
    }

    fn ensure_segment_encodable(&self, segment: usize) -> Result<(), SegmentedLaneError> {
        let maximum = (u32::MAX >> self.local_bits) as usize;
        if segment > maximum {
            return Err(SegmentedLaneError::CoordinateSpaceExhausted {
                segments: segment.saturating_add(1),
                local_bits: self.local_bits,
            });
        }
        Ok(())
    }

    fn encode(
        &self,
        segment: usize,
        local: usize,
    ) -> Result<SegmentCoordinate, SegmentedLaneError> {
        self.ensure_segment_encodable(segment)?;
        if local >= self.ordinary_slots {
            return Err(SegmentedLaneError::CoordinateSpaceExhausted {
                segments: segment.saturating_add(1),
                local_bits: self.local_bits,
            });
        }
        let segment =
            u32::try_from(segment).map_err(|_| SegmentedLaneError::CoordinateSpaceExhausted {
                segments: segment.saturating_add(1),
                local_bits: self.local_bits,
            })?;
        let local =
            u32::try_from(local).map_err(|_| SegmentedLaneError::CoordinateSpaceExhausted {
                segments: segment as usize + 1,
                local_bits: self.local_bits,
            })?;
        Ok(SegmentCoordinate((segment << self.local_bits) | local))
    }

    fn decode(&self, coordinate: SegmentCoordinate) -> (usize, usize) {
        let local_mask = (1u32 << self.local_bits) - 1;
        (
            (coordinate.0 >> self.local_bits) as usize,
            (coordinate.0 & local_mask) as usize,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::time::Instant;

    use super::*;

    #[test]
    fn chooses_power_of_two_segments_at_or_below_target_bytes() {
        let bytes = SegmentedLane::<u8>::new().expect("nonzero payload");
        let words = SegmentedLane::<u64>::new().expect("nonzero payload");
        let records = SegmentedLane::<[u64; 3]>::new().expect("nonzero payload");

        assert_eq!(bytes.ordinary_slots(), 65_536);
        assert_eq!(words.ordinary_slots(), 8_192);
        assert_eq!(records.ordinary_slots(), 2_048);
        assert!(records.ordinary_slots() * mem::size_of::<[u64; 3]>() <= 64 * 1024);
    }

    #[test]
    fn payload_addresses_remain_stable_when_the_directory_grows() {
        let mut lane = SegmentedLane::<u64>::new().expect("nonzero payload");
        let first = lane.try_push(41).expect("first payload");
        let address = lane.get(first).expect("first payload resolves") as *const u64;
        for value in 0..(lane.ordinary_slots() * 3) {
            lane.try_push(value as u64).expect("later payload");
        }

        assert_eq!(lane.get(first), Some(&41));
        assert_eq!(
            lane.get(first).map(|value| value as *const u64),
            Some(address)
        );
        assert_eq!(lane.segment_count(), 4);
    }

    #[test]
    fn contiguous_ranges_never_cross_segment_boundaries() {
        let mut lane = SegmentedLane::<u64>::new().expect("nonzero payload");
        let prefix = vec![3; lane.ordinary_slots() - 2];
        lane.try_extend_contiguous(&prefix)
            .expect("prefix allocation");
        let values = [11, 12, 13, 14];
        let (start, count) = lane
            .try_extend_contiguous(&values)
            .expect("range allocation")
            .expect("nonempty range");

        assert_eq!(lane.get_contiguous(start, count), Some(values.as_slice()));
        assert_eq!(lane.segment_count(), 2);
    }

    #[test]
    fn oversized_ranges_receive_dedicated_segments() {
        let mut lane = SegmentedLane::<u64>::new().expect("nonzero payload");
        let oversized = vec![7; lane.ordinary_slots() + 1];
        let (start, count) = lane
            .try_extend_contiguous(&oversized)
            .expect("oversized allocation")
            .expect("nonempty range");
        let following = lane.try_push(9).expect("ordinary allocation");

        assert_eq!(
            lane.get_contiguous(start, count),
            Some(oversized.as_slice())
        );
        assert_eq!(lane.get(following), Some(&9));
        assert_eq!(lane.segment_count(), 2);
    }

    #[test]
    fn empty_ranges_do_not_allocate() {
        let mut lane = SegmentedLane::<u64>::new().expect("nonzero payload");

        assert_eq!(lane.try_extend_contiguous(&[]), Ok(None));
        assert!(lane.is_empty());
        assert_eq!(lane.segment_count(), 0);
    }

    #[test]
    fn zero_sized_payloads_are_rejected() {
        assert!(matches!(
            SegmentedLane::<()>::new(),
            Err(SegmentedLaneError::ZeroSizedPayload)
        ));
    }

    #[test]
    #[ignore = "manual pinned-builder microbenchmark"]
    fn segmented_read_overhead_probe() {
        const ELEMENTS: usize = 1 << 20;
        const READS: usize = 1 << 24;

        let direct = (0..ELEMENTS as u64).collect::<Vec<_>>();
        let mut segmented = SegmentedLane::<u64>::new().expect("nonzero payload");
        for value in 0..ELEMENTS as u64 {
            segmented.try_push(value).expect("segmented payload");
        }

        let direct_start = Instant::now();
        let mut direct_state = 1u32;
        let mut direct_sum = 0u64;
        for _ in 0..READS {
            direct_state = direct_state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223);
            let index = direct_state as usize & (ELEMENTS - 1);
            direct_sum = direct_sum.wrapping_add(direct[index]);
        }
        black_box(direct_sum);
        let direct_elapsed = direct_start.elapsed();

        let segmented_start = Instant::now();
        let mut segmented_state = 1u32;
        let mut segmented_sum = 0u64;
        for _ in 0..READS {
            segmented_state = segmented_state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223);
            let coordinate = SegmentCoordinate::from_u32(segmented_state & (ELEMENTS as u32 - 1));
            segmented_sum = segmented_sum.wrapping_add(
                *segmented
                    .get(coordinate)
                    .expect("generated coordinate resolves"),
            );
        }
        black_box(segmented_sum);
        let segmented_elapsed = segmented_start.elapsed();

        assert_eq!(direct_sum, segmented_sum);
        eprintln!(
            "segmented-read-probe direct_ns={} segmented_ns={} ratio={:.4}",
            direct_elapsed.as_nanos(),
            segmented_elapsed.as_nanos(),
            segmented_elapsed.as_secs_f64() / direct_elapsed.as_secs_f64()
        );
    }
}
