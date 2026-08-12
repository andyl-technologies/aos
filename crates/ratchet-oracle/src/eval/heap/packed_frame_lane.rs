//! Registry-free packed frame destinations for future moving publication.
//!
//! A finalized lane contains only fixed-stride frame records and one contiguous
//! Candidate-C value lane:
//!
//! ```text
//! frame record
//!   parent:u32 | slot_start:u32 | slot_count:u32          12 bytes
//! slot lane
//!   exact Candidate-C compressed value word                8 bytes
//! ```
//!
//! [`PackedFrameLaneBuilder`] temporarily maps source identities to destination
//! coordinates so a shared source frame is emitted exactly once. Finalization
//! consumes and drops that map; [`PackedFrameLane`] retains no source identity,
//! forwarding, hash, or pointer registry.

use std::collections::HashMap;
use std::hash::Hash;
use std::mem;

use thiserror::Error;

use super::packed_thunk_lane::PackedValueWord;

const NO_PARENT: u32 = u32::MAX;

fn checked_frame_index(index: usize) -> Result<u32, PackedFrameLaneError> {
    let encoded =
        u32::try_from(index).map_err(|_| PackedFrameLaneError::FrameIndexOverflow { index })?;
    if encoded == NO_PARENT {
        return Err(PackedFrameLaneError::FrameIndexOverflow { index });
    }
    Ok(encoded)
}

fn checked_slot_range(start: usize, count: usize) -> Result<(u32, u32), PackedFrameLaneError> {
    let slot_start = u32::try_from(start)
        .map_err(|_| PackedFrameLaneError::SlotIndexOverflow { index: start })?;
    let slot_count =
        u32::try_from(count).map_err(|_| PackedFrameLaneError::SlotCountOverflow { count })?;
    slot_start
        .checked_add(slot_count)
        .ok_or(PackedFrameLaneError::SlotRangeOverflow {
            start: slot_start,
            count: slot_count,
        })?;
    Ok((slot_start, slot_count))
}

/// A direct fixed-stride coordinate in a packed frame lane.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PackedFrameRef(u32);

impl PackedFrameRef {
    /// Returns the frame-record index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

/// Exact initialized bytes owned by a finalized packed frame lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedFrameLaneBytes {
    /// Bytes occupied by initialized fixed-stride frame records.
    pub(crate) frames: usize,
    /// Bytes occupied by initialized Candidate-C value slots.
    pub(crate) slots: usize,
}

impl PackedFrameLaneBytes {
    /// Returns total initialized destination bytes.
    pub(crate) const fn total(self) -> usize {
        self.frames + self.slots
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackedFrameRecord {
    parent: u32,
    slot_start: u32,
    slot_count: u32,
}

impl PackedFrameRecord {
    const fn new(parent: Option<PackedFrameRef>, slot_start: u32, slot_count: u32) -> Self {
        Self {
            parent: match parent {
                Some(parent) => parent.0,
                None => NO_PARENT,
            },
            slot_start,
            slot_count,
        }
    }
}

/// A finalized registry-free frame and environment destination.
#[derive(Debug, Default)]
pub(crate) struct PackedFrameLane {
    frames: Vec<PackedFrameRecord>,
    slots: Vec<PackedValueWord>,
}

impl PackedFrameLane {
    /// Returns the number of finalized frame records.
    pub(crate) fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Returns the number of finalized value slots.
    pub(crate) fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Returns exact initialized destination bytes, excluding vector capacity.
    pub(crate) fn initialized_bytes(&self) -> PackedFrameLaneBytes {
        PackedFrameLaneBytes {
            frames: self.frames.len() * mem::size_of::<PackedFrameRecord>(),
            slots: self.slots.len() * mem::size_of::<PackedValueWord>(),
        }
    }

    /// Returns allocated vector-capacity bytes, excluding vector descriptors.
    ///
    /// Packed-heap projections use this conservative quantity so allocator
    /// growth above initialized length cannot consume the acceptance margin
    /// unnoticed.
    pub(crate) fn capacity_bytes(&self) -> PackedFrameLaneBytes {
        PackedFrameLaneBytes {
            frames: self.frames.capacity() * mem::size_of::<PackedFrameRecord>(),
            slots: self.slots.capacity() * mem::size_of::<PackedValueWord>(),
        }
    }

    /// Returns one frame's parent coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedFrameLaneError`] for a stale frame coordinate or a
    /// malformed parent coordinate.
    pub(crate) fn parent(
        &self,
        frame: PackedFrameRef,
    ) -> Result<Option<PackedFrameRef>, PackedFrameLaneError> {
        let record = self.record(frame)?;
        if record.parent == NO_PARENT {
            return Ok(None);
        }
        if (record.parent as usize) >= self.frames.len() {
            return Err(PackedFrameLaneError::MalformedParent {
                frame: frame.0,
                parent: record.parent,
            });
        }
        Ok(Some(PackedFrameRef(record.parent)))
    }

    /// Returns one frame's complete contiguous value-slot slice.
    ///
    /// # Errors
    ///
    /// Returns [`PackedFrameLaneError`] for a stale frame coordinate or a
    /// malformed stored slot range.
    pub(crate) fn slots(
        &self,
        frame: PackedFrameRef,
    ) -> Result<&[PackedValueWord], PackedFrameLaneError> {
        let record = self.record(frame)?;
        let start = record.slot_start as usize;
        let count = record.slot_count as usize;
        let end = start
            .checked_add(count)
            .ok_or(PackedFrameLaneError::MalformedSlotRange {
                frame: frame.0,
                start: record.slot_start,
                count: record.slot_count,
            })?;
        self.slots
            .get(start..end)
            .ok_or(PackedFrameLaneError::MalformedSlotRange {
                frame: frame.0,
                start: record.slot_start,
                count: record.slot_count,
            })
    }

    /// Returns one value slot by direct frame-local index.
    ///
    /// # Errors
    ///
    /// Returns [`PackedFrameLaneError`] for a stale frame, malformed stored
    /// range, or out-of-range frame-local slot.
    pub(crate) fn get(
        &self,
        frame: PackedFrameRef,
        slot: u32,
    ) -> Result<PackedValueWord, PackedFrameLaneError> {
        self.slots(frame)?
            .get(slot as usize)
            .copied()
            .ok_or(PackedFrameLaneError::SlotOutOfRange {
                frame: frame.0,
                slot,
            })
    }

    /// Traverses a frame and its parents toward the root.
    ///
    /// Each frame coordinate is passed to `visit` before its parent. The lane
    /// rejects invalid parents and cycles instead of looping.
    ///
    /// # Errors
    ///
    /// Returns [`PackedFrameLaneError`] for a stale starting coordinate,
    /// malformed parent coordinate, or parent cycle.
    pub(crate) fn traverse(
        &self,
        start: PackedFrameRef,
        mut visit: impl FnMut(PackedFrameRef),
    ) -> Result<(), PackedFrameLaneError> {
        let mut current = Some(start);
        let mut traversed = 0usize;
        while let Some(frame) = current {
            if traversed >= self.frames.len() {
                return Err(PackedFrameLaneError::ParentCycle { frame: frame.0 });
            }
            self.record(frame)?;
            visit(frame);
            traversed += 1;
            current = self.parent(frame)?;
        }
        Ok(())
    }

    fn record(&self, frame: PackedFrameRef) -> Result<PackedFrameRecord, PackedFrameLaneError> {
        self.frames
            .get(frame.0 as usize)
            .copied()
            .ok_or(PackedFrameLaneError::UnknownFrame { index: frame.0 })
    }
}

/// Exact logical element counts admitted for a direct packed frame build.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackedFrameLaneCapacities {
    /// Frame records.
    pub(crate) frames: usize,
    /// Candidate-C value slots across all frames.
    pub(crate) slots: usize,
}

/// A pre-reserved, source-map-free packed frame builder.
///
/// The caller assigns frame coordinates by append order and supplies already
/// translated parent coordinates. This is the moving collector's direct door:
/// it retains no source identities and never grows a lane after construction.
#[derive(Debug)]
pub(crate) struct PackedFrameLaneDirectBuilder {
    lane: PackedFrameLane,
    admitted: PackedFrameLaneCapacities,
    admitted_capacity_bytes: PackedFrameLaneBytes,
}

impl PackedFrameLaneDirectBuilder {
    /// Reserves every frame and slot admitted for this build.
    ///
    /// # Errors
    ///
    /// Returns [`PackedFrameLaneError`] if the admitted counts do not fit the
    /// direct coordinate format or either complete reservation fails.
    pub(crate) fn try_new(
        admitted: PackedFrameLaneCapacities,
    ) -> Result<Self, PackedFrameLaneError> {
        if admitted.frames > u32::MAX as usize {
            return Err(PackedFrameLaneError::FrameIndexOverflow {
                index: admitted.frames.saturating_sub(1),
            });
        }
        checked_slot_range(0, admitted.slots)?;
        let mut lane = PackedFrameLane::default();
        lane.frames
            .try_reserve_exact(admitted.frames)
            .map_err(|_| PackedFrameLaneError::AllocationFailed {
                lane: "frame-record",
            })?;
        lane.slots
            .try_reserve_exact(admitted.slots)
            .map_err(|_| PackedFrameLaneError::AllocationFailed { lane: "value-slot" })?;
        let admitted_capacity_bytes = lane.capacity_bytes();
        Ok(Self {
            lane,
            admitted,
            admitted_capacity_bytes,
        })
    }

    /// Appends one caller-preassigned frame coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedFrameLaneError`] before mutation when the frame or slot
    /// admission is exhausted, the parent is not already initialized, or the
    /// direct coordinate range overflows.
    pub(crate) fn append(
        &mut self,
        parent: Option<PackedFrameRef>,
        slots: &[PackedValueWord],
    ) -> Result<PackedFrameRef, PackedFrameLaneError> {
        let attempted_frames = self.lane.frames.len().saturating_add(1);
        if attempted_frames > self.admitted.frames {
            return Err(PackedFrameLaneError::CapacityExceeded {
                lane: "frame-record",
                admitted: self.admitted.frames,
                attempted: attempted_frames,
            });
        }
        let attempted_slots = self.lane.slots.len().checked_add(slots.len()).ok_or(
            PackedFrameLaneError::SlotRangeOverflow {
                start: u32::MAX,
                count: u32::MAX,
            },
        )?;
        if attempted_slots > self.admitted.slots {
            return Err(PackedFrameLaneError::CapacityExceeded {
                lane: "value-slot",
                admitted: self.admitted.slots,
                attempted: attempted_slots,
            });
        }
        if let Some(parent) = parent
            && (parent.0 as usize) >= self.lane.frames.len()
        {
            return Err(PackedFrameLaneError::UnknownParent { index: parent.0 });
        }
        let frame_index = checked_frame_index(self.lane.frames.len())?;
        let (slot_start, slot_count) = checked_slot_range(self.lane.slots.len(), slots.len())?;
        self.ensure_capacity_unchanged()?;
        self.lane.slots.extend_from_slice(slots);
        self.lane
            .frames
            .push(PackedFrameRecord::new(parent, slot_start, slot_count));
        self.ensure_capacity_unchanged()?;
        Ok(PackedFrameRef(frame_index))
    }

    /// Returns initialized bytes accumulated so far.
    pub(crate) fn initialized_bytes(&self) -> PackedFrameLaneBytes {
        self.lane.initialized_bytes()
    }

    /// Returns the allocator-granted capacity fixed at construction.
    pub(crate) fn capacity_bytes(&self) -> PackedFrameLaneBytes {
        self.lane.capacity_bytes()
    }

    /// Finalizes the lane without requiring every admitted slot to be filled.
    ///
    /// # Errors
    ///
    /// Returns [`PackedFrameLaneError`] if a backing vector's capacity changed
    /// after admission.
    pub(crate) fn finish(self) -> Result<PackedFrameLane, PackedFrameLaneError> {
        self.ensure_capacity_unchanged()?;
        Ok(self.lane)
    }

    fn ensure_capacity_unchanged(&self) -> Result<(), PackedFrameLaneError> {
        let actual = self.lane.capacity_bytes();
        if actual != self.admitted_capacity_bytes {
            return Err(PackedFrameLaneError::CapacityChanged {
                admitted: self.admitted_capacity_bytes.total(),
                actual: actual.total(),
            });
        }
        Ok(())
    }
}

/// A temporary source-identity deduplicating builder.
#[derive(Debug)]
pub(crate) struct PackedFrameLaneBuilder<SourceId> {
    lane: PackedFrameLane,
    source_frames: HashMap<SourceId, PackedFrameRef>,
}

impl<SourceId> Default for PackedFrameLaneBuilder<SourceId> {
    fn default() -> Self {
        Self {
            lane: PackedFrameLane::default(),
            source_frames: HashMap::new(),
        }
    }
}

impl<SourceId> PackedFrameLaneBuilder<SourceId>
where
    SourceId: Eq + Hash,
{
    /// Creates an empty temporary frame builder.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Interns one source frame into the packed destination.
    ///
    /// Repeated `source` identities return the first coordinate without
    /// appending another record or slot range. A parent must already have been
    /// interned, making every successfully built parent chain acyclic.
    ///
    /// # Errors
    ///
    /// Returns [`PackedFrameLaneError`] when a parent is stale, an index or
    /// range does not fit in `u32`, or destination storage cannot be reserved.
    pub(crate) fn intern(
        &mut self,
        source: SourceId,
        parent: Option<PackedFrameRef>,
        slots: &[PackedValueWord],
    ) -> Result<PackedFrameRef, PackedFrameLaneError> {
        if let Some(existing) = self.source_frames.get(&source).copied() {
            return Ok(existing);
        }
        if let Some(parent) = parent {
            if (parent.0 as usize) >= self.lane.frames.len() {
                return Err(PackedFrameLaneError::UnknownParent { index: parent.0 });
            }
        }

        let frame_index = checked_frame_index(self.lane.frames.len())?;
        let (slot_start, slot_count) = checked_slot_range(self.lane.slots.len(), slots.len())?;
        let slot_end = slot_start + slot_count;
        let expected_end = self.lane.slots.len().checked_add(slots.len()).ok_or(
            PackedFrameLaneError::SlotRangeOverflow {
                start: slot_start,
                count: slot_count,
            },
        )?;
        if slot_end as usize != expected_end {
            return Err(PackedFrameLaneError::SlotRangeOverflow {
                start: slot_start,
                count: slot_count,
            });
        }

        self.source_frames
            .try_reserve(1)
            .map_err(|_| PackedFrameLaneError::AllocationFailed {
                lane: "source-frame-dedup",
            })?;
        self.lane.frames.try_reserve_exact(1).map_err(|_| {
            PackedFrameLaneError::AllocationFailed {
                lane: "frame-record",
            }
        })?;
        self.lane
            .slots
            .try_reserve_exact(slots.len())
            .map_err(|_| PackedFrameLaneError::AllocationFailed { lane: "value-slot" })?;

        let reference = PackedFrameRef(frame_index);
        self.lane.slots.extend_from_slice(slots);
        self.lane
            .frames
            .push(PackedFrameRecord::new(parent, slot_start, slot_count));
        self.source_frames.insert(source, reference);
        Ok(reference)
    }

    /// Drops temporary source identity state and returns the finalized lane.
    pub(crate) fn finish(self) -> PackedFrameLane {
        let Self {
            lane,
            source_frames,
        } = self;
        drop(source_frames);
        lane
    }
}

/// A checked packed frame allocation or lookup failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum PackedFrameLaneError {
    /// A frame record index no longer fits in `u32`.
    #[error("packed frame index {index} does not fit in u32")]
    FrameIndexOverflow {
        /// The rejected vector index.
        index: usize,
    },
    /// A value-slot start no longer fits in `u32`.
    #[error("packed frame slot index {index} does not fit in u32")]
    SlotIndexOverflow {
        /// The rejected vector index.
        index: usize,
    },
    /// A frame-local value-slot count no longer fits in `u32`.
    #[error("packed frame slot count {count} does not fit in u32")]
    SlotCountOverflow {
        /// The rejected count.
        count: usize,
    },
    /// A value-slot range exceeds the direct 32-bit coordinate space.
    #[error("packed frame slot range start={start} count={count} overflows u32")]
    SlotRangeOverflow {
        /// The range start.
        start: u32,
        /// The range length.
        count: u32,
    },
    /// Safe destination storage could not grow.
    #[error("packed frame destination could not reserve {lane} storage")]
    AllocationFailed {
        /// The destination lane that failed.
        lane: &'static str,
    },
    /// An append exceeded a caller-admitted logical lane count.
    #[error("packed {lane} capacity {admitted} rejects length {attempted}")]
    CapacityExceeded {
        /// The affected lane.
        lane: &'static str,
        /// The exact admitted element count.
        admitted: usize,
        /// The length the rejected append would have produced.
        attempted: usize,
    },
    /// A pre-reserved lane grew after admission.
    #[error("packed frame capacity changed from {admitted} bytes to {actual} bytes")]
    CapacityChanged {
        /// Capacity measured immediately after pre-reservation.
        admitted: usize,
        /// Capacity observed after an append or at finalization.
        actual: usize,
    },
    /// An intern request names a parent not yet present in the builder.
    #[error("packed frame parent index {index} is not initialized")]
    UnknownParent {
        /// The rejected direct parent index.
        index: u32,
    },
    /// A direct frame coordinate lies outside the initialized lane.
    #[error("packed frame index {index} is not initialized")]
    UnknownFrame {
        /// The rejected direct frame index.
        index: u32,
    },
    /// A stored parent coordinate lies outside the finalized lane.
    #[error("packed frame {frame} contains malformed parent {parent}")]
    MalformedParent {
        /// The frame containing the bad parent.
        frame: u32,
        /// The rejected parent coordinate.
        parent: u32,
    },
    /// A finalized parent chain contains a cycle.
    #[error("packed frame parent chain cycles at frame {frame}")]
    ParentCycle {
        /// A frame revisited after at least the lane's frame count.
        frame: u32,
    },
    /// A stored frame slot range lies outside the finalized slot lane.
    #[error("packed frame {frame} contains malformed slot range start={start} count={count}")]
    MalformedSlotRange {
        /// The frame containing the bad range.
        frame: u32,
        /// The stored slot start.
        start: u32,
        /// The stored slot count.
        count: u32,
    },
    /// A frame-local slot coordinate lies outside that frame.
    #[error("packed frame {frame} has no local slot {slot}")]
    SlotOutOfRange {
        /// The addressed frame.
        frame: u32,
        /// The rejected frame-local slot coordinate.
        slot: u32,
    },
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::heap::{ArenaDomainId, ArenaIndex};
    use crate::value::ValueTag;
    use crate::value::compressed::CompressedValueWord;

    fn packed(word: CompressedValueWord) -> PackedValueWord {
        PackedValueWord::new(word)
    }

    fn int(value: i32) -> PackedValueWord {
        packed(CompressedValueWord::inline_int(i64::from(value)).unwrap())
    }

    #[test]
    fn exact_layout_and_byte_accounting_match_contract() {
        assert_eq!(mem::size_of::<PackedFrameRef>(), 4);
        assert_eq!(mem::size_of::<PackedFrameRecord>(), 12);
        assert_eq!(mem::align_of::<PackedFrameRecord>(), 4);
        assert_eq!(mem::size_of::<PackedValueWord>(), 8);
        assert_eq!(mem::size_of::<PackedFrameLane>(), 48);

        let mut builder = PackedFrameLaneBuilder::new();
        let root = builder.intern(1_u64, None, &[]).unwrap();
        let child = builder
            .intern(2_u64, Some(root), &[int(1), int(2), int(3)])
            .unwrap();
        let lane = builder.finish();
        assert_eq!(lane.frame_count(), 2);
        assert_eq!(lane.slot_count(), 3);
        assert_eq!(
            lane.initialized_bytes(),
            PackedFrameLaneBytes {
                frames: 24,
                slots: 24
            }
        );
        assert_eq!(lane.initialized_bytes().total(), 48);
        let capacity = lane.capacity_bytes();
        assert!(capacity.frames >= 24);
        assert!(capacity.slots >= 24);
        assert!(capacity.total() >= 48);
        assert_eq!(lane.parent(child), Ok(Some(root)));
    }

    #[test]
    fn direct_builder_exact_fill_and_underfill_preserve_capacity() {
        let admitted = PackedFrameLaneCapacities {
            frames: 2,
            slots: 3,
        };
        let mut builder = PackedFrameLaneDirectBuilder::try_new(admitted).unwrap();
        let capacity = builder.capacity_bytes();
        let _root = builder.append(None, &[int(1)]).unwrap();
        assert_eq!(
            builder.initialized_bytes(),
            PackedFrameLaneBytes {
                frames: 12,
                slots: 8,
            }
        );
        assert_eq!(builder.capacity_bytes(), capacity);
        let lane = builder.finish().unwrap();
        assert_eq!(lane.frame_count(), 1);
        assert_eq!(lane.capacity_bytes(), capacity);

        let mut exact = PackedFrameLaneDirectBuilder::try_new(admitted).unwrap();
        let exact_capacity = exact.capacity_bytes();
        let root = exact.append(None, &[int(1)]).unwrap();
        let child = exact.append(Some(root), &[int(2), int(3)]).unwrap();
        let lane = exact.finish().unwrap();
        assert_eq!(lane.initialized_bytes().total(), 48);
        assert_eq!(lane.capacity_bytes(), exact_capacity);
        assert_eq!(lane.parent(child), Ok(Some(root)));
    }

    #[test]
    fn direct_builder_rejects_overfill_before_growth() {
        let mut builder = PackedFrameLaneDirectBuilder::try_new(PackedFrameLaneCapacities {
            frames: 1,
            slots: 1,
        })
        .unwrap();
        let capacity = builder.capacity_bytes();
        builder.append(None, &[int(1)]).unwrap();
        let initialized = builder.initialized_bytes();
        assert_eq!(
            builder.append(None, &[]),
            Err(PackedFrameLaneError::CapacityExceeded {
                lane: "frame-record",
                admitted: 1,
                attempted: 2,
            })
        );
        assert_eq!(builder.initialized_bytes(), initialized);
        assert_eq!(builder.capacity_bytes(), capacity);

        let mut slots = PackedFrameLaneDirectBuilder::try_new(PackedFrameLaneCapacities {
            frames: 1,
            slots: 1,
        })
        .unwrap();
        let slots_capacity = slots.capacity_bytes();
        assert_eq!(
            slots.append(None, &[int(1), int(2)]),
            Err(PackedFrameLaneError::CapacityExceeded {
                lane: "value-slot",
                admitted: 1,
                attempted: 2,
            })
        );
        assert_eq!(slots.initialized_bytes().total(), 0);
        assert_eq!(slots.capacity_bytes(), slots_capacity);
    }

    #[test]
    fn shared_parent_chains_and_source_identity_are_preserved() {
        let mut builder = PackedFrameLaneBuilder::new();
        let root = builder.intern("root", None, &[int(1)]).unwrap();
        let left = builder.intern("left", Some(root), &[int(2)]).unwrap();
        let right = builder.intern("right", Some(root), &[int(3)]).unwrap();
        assert_eq!(
            builder.intern("left", Some(right), &[int(99)]).unwrap(),
            left
        );
        let lane = builder.finish();

        let mut left_chain = Vec::new();
        lane.traverse(left, |frame| left_chain.push(frame)).unwrap();
        assert_eq!(left_chain, vec![left, root]);
        let mut right_chain = Vec::new();
        lane.traverse(right, |frame| right_chain.push(frame))
            .unwrap();
        assert_eq!(right_chain, vec![right, root]);
        assert_eq!(lane.frame_count(), 3);
        assert_eq!(lane.slot_count(), 3);
    }

    #[test]
    fn empty_and_multi_slot_frames_support_direct_get() {
        let mut builder = PackedFrameLaneBuilder::new();
        let empty = builder.intern(1_u8, None, &[]).unwrap();
        let full = builder
            .intern(2_u8, Some(empty), &[int(10), int(20), int(30)])
            .unwrap();
        let lane = builder.finish();
        assert_eq!(lane.slots(empty), Ok([].as_slice()));
        assert_eq!(lane.slots(full), Ok([int(10), int(20), int(30)].as_slice()));
        assert_eq!(lane.get(full, 1), Ok(int(20)));
        assert_eq!(
            lane.get(full, 3),
            Err(PackedFrameLaneError::SlotOutOfRange {
                frame: full.index(),
                slot: 3
            })
        );
    }

    #[test]
    fn every_candidate_c_value_kind_round_trips_in_slots() {
        let domain = ArenaDomainId::from_raw((1 << 23) - 1).unwrap();
        let mut values = vec![
            packed(CompressedValueWord::inline_int(i64::from(i32::MIN)).unwrap()),
            packed(CompressedValueWord::boxed_int(
                domain,
                ArenaIndex::new(u32::MAX - 1),
            )),
            packed(CompressedValueWord::boxed_float(
                domain,
                ArenaIndex::new(u32::MAX),
            )),
            packed(CompressedValueWord::boolean(false)),
            packed(CompressedValueWord::boolean(true)),
            packed(CompressedValueWord::null()),
        ];
        for (offset, tag) in [
            ValueTag::String,
            ValueTag::Path,
            ValueTag::List,
            ValueTag::Attrs,
            ValueTag::Lambda,
            ValueTag::Primop,
            ValueTag::External,
            ValueTag::Thunk,
        ]
        .into_iter()
        .enumerate()
        {
            values.push(packed(
                CompressedValueWord::heap(domain, tag, ArenaIndex::new(offset as u32)).unwrap(),
            ));
        }
        values.push(packed(
            CompressedValueWord::heap(domain, ValueTag::Thunk, ArenaIndex::new(u32::MAX))
                .unwrap()
                .with_forced_bit()
                .unwrap(),
        ));

        let mut builder = PackedFrameLaneBuilder::new();
        let frame = builder.intern(1_u8, None, &values).unwrap();
        let lane = builder.finish();
        assert_eq!(lane.slots(frame), Ok(values.as_slice()));
        for (index, expected) in values.into_iter().enumerate() {
            assert_eq!(lane.get(frame, index as u32), Ok(expected));
        }
    }

    #[test]
    fn stale_and_malformed_coordinates_fail_closed() {
        let mut builder = PackedFrameLaneBuilder::new();
        assert_eq!(
            builder.intern(1_u8, Some(PackedFrameRef(7)), &[]),
            Err(PackedFrameLaneError::UnknownParent { index: 7 })
        );
        let valid = builder.intern(2_u8, None, &[int(1)]).unwrap();
        let mut lane = builder.finish();
        assert_eq!(
            lane.parent(PackedFrameRef(u32::MAX - 1)),
            Err(PackedFrameLaneError::UnknownFrame {
                index: u32::MAX - 1
            })
        );

        lane.frames[valid.0 as usize].parent = 9;
        assert_eq!(
            lane.parent(valid),
            Err(PackedFrameLaneError::MalformedParent {
                frame: valid.0,
                parent: 9
            })
        );
        lane.frames[valid.0 as usize].parent = valid.0;
        assert_eq!(
            lane.traverse(valid, |_| {}),
            Err(PackedFrameLaneError::ParentCycle { frame: valid.0 })
        );
        lane.frames[valid.0 as usize].parent = NO_PARENT;
        lane.frames[valid.0 as usize].slot_start = u32::MAX;
        assert_eq!(
            lane.slots(valid),
            Err(PackedFrameLaneError::MalformedSlotRange {
                frame: valid.0,
                start: u32::MAX,
                count: 1
            })
        );
    }

    #[test]
    fn direct_coordinate_checks_reject_reserved_and_overflowing_ranges() {
        assert_eq!(
            checked_frame_index(u32::MAX as usize),
            Err(PackedFrameLaneError::FrameIndexOverflow {
                index: u32::MAX as usize
            })
        );
        assert_eq!(
            checked_slot_range((u32::MAX - 1) as usize, 2),
            Err(PackedFrameLaneError::SlotRangeOverflow {
                start: u32::MAX - 1,
                count: 2
            })
        );
    }

    #[derive(Debug)]
    struct DroppingSourceId {
        id: u32,
        drops: Arc<AtomicUsize>,
    }

    impl PartialEq for DroppingSourceId {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl Eq for DroppingSourceId {}

    impl Hash for DroppingSourceId {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }

    impl Drop for DroppingSourceId {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn finish_drops_temporary_source_builder_state() {
        let drops = Arc::new(AtomicUsize::new(0));
        let source = DroppingSourceId {
            id: 1,
            drops: Arc::clone(&drops),
        };
        let mut builder = PackedFrameLaneBuilder::new();
        let frame = builder.intern(source, None, &[int(7)]).unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let lane = builder.finish();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(lane.get(frame, 0), Ok(int(7)));
    }
}
