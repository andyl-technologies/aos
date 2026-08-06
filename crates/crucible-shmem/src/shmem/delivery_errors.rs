//! Deterministic frame-delivery ordering and ABI error types.

use super::*;

/// The deterministic order key for frames visible to one consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameDeliveryKey {
    /// The consumer icount at which the frame becomes visible.
    pub delivery_icount: u64,
    /// The producer node id.
    pub src_node: u32,
    /// The per-producer sequence number.
    pub seq: u32,
}

/// Returns all currently deliverable frames in deterministic visibility order.
#[must_use]
pub fn deliverable_frames_at(
    frames: &[FrameEntry],
    consumer_current_icount: u64,
) -> Vec<&FrameEntry> {
    let mut deliverable = frames
        .iter()
        .filter(|frame| frame.is_deliverable_at(consumer_current_icount))
        .collect::<Vec<_>>();

    deliverable.sort_by_key(|frame| frame.delivery_key());

    deliverable
}

/// An advance authorization bounded by the lookahead gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvanceCeiling {
    pub(super) current_icount: u64,
    pub(super) max_advance_icount: u64,
}

impl AdvanceCeiling {
    /// Returns the consumer icount observed before authorization.
    #[must_use]
    pub fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns the scheduler-authorized maximum icount the consumer may reach.
    #[must_use]
    pub fn max_advance_icount(&self) -> u64 {
        self.max_advance_icount
    }
}

/// Authorizes a max-advance ceiling under the conservative lookahead gate.
///
/// When `earliest_possible_delivery_icount` is present, the returned ceiling is
/// strictly before that icount. The scheduler must publish a fresh
/// authorization once the input group is present and deliverable.
///
/// # Errors
///
/// Returns [`LookaheadGateError::CeilingBeforeCurrent`] when `max_advance_icount`
/// is behind `current_icount`, and
/// [`LookaheadGateError::AdvanceReachesPossibleDelivery`] when the requested
/// ceiling would reach or pass an input that could become visible.
pub fn authorize_advance_ceiling(
    current_icount: u64,
    max_advance_icount: u64,
    earliest_possible_delivery_icount: Option<u64>,
) -> Result<AdvanceCeiling, LookaheadGateError> {
    if max_advance_icount < current_icount {
        return Err(LookaheadGateError::CeilingBeforeCurrent {
            current_icount,
            max_advance_icount,
        });
    }

    if let Some(earliest_possible_delivery_icount) = earliest_possible_delivery_icount
        && max_advance_icount >= earliest_possible_delivery_icount
    {
        return Err(LookaheadGateError::AdvanceReachesPossibleDelivery {
            max_advance_icount,
            earliest_possible_delivery_icount,
        });
    }

    Ok(AdvanceCeiling {
        current_icount,
        max_advance_icount,
    })
}

/// Verifies that a newly enqueued frame has not already missed its delivery.
///
/// A frame at the consumer's exact current boundary remains admissible. The
/// consumer is quiescent while the scheduler publishes the frame, and the next
/// drain makes that frame visible without advancing the consumer.
///
/// # Errors
///
/// Returns [`LookaheadGateError::DeliveryAlreadyPassed`] when the consumer has
/// advanced past the frame's delivery icount.
pub fn validate_frame_delivery_is_future(
    frame: &FrameEntry,
    consumer_current_icount: u64,
) -> Result<(), LookaheadGateError> {
    if frame.delivery_icount < consumer_current_icount {
        Err(LookaheadGateError::DeliveryAlreadyPassed {
            consumer_current_icount,
            frame: frame.delivery_key(),
        })
    } else {
        Ok(())
    }
}

/// A validation error for shared-memory frame entries.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FrameEntryError {
    /// The advertised payload length does not fit in [`MAX_FRAME_DATA`].
    #[error("frame payload length {len} exceeds capacity {capacity}")]
    PayloadLengthExceedsCapacity {
        /// The requested or advertised payload length.
        len: usize,
        /// The configured frame payload capacity.
        capacity: usize,
    },
}

/// A validation error for plugin-to-host coverage entries.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoverageEntryError {
    /// The translated block length is zero.
    #[error("coverage block length {block_len} must be nonzero")]
    InvalidBlockLength {
        /// Rejected block length.
        block_len: u32,
    },
    /// The fixed coverage-map index is outside the ABI queue cardinality.
    #[error("coverage map index {map_index} is outside {map_entries} entries")]
    MapIndexOutOfRange {
        /// Rejected map index.
        map_index: u64,
        /// ABI-fixed map cardinality.
        map_entries: u32,
    },
    /// Forward-compatibility bytes in a shared entry were nonzero.
    #[error("coverage entry contains nonzero reserved bytes")]
    NonzeroReservedBytes,
}

/// A validation error for plugin-to-host white-box marker entries.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WhiteboxMarkerEntryError {
    /// The marker body does not fit in the fixed entry payload.
    #[error("white-box marker payload length {len} exceeds capacity {capacity}")]
    PayloadLengthExceedsCapacity {
        /// Requested or advertised marker payload length.
        len: usize,
        /// ABI-fixed marker payload capacity.
        capacity: usize,
    },
    /// Bytes after the advertised marker body were not zero.
    #[error("white-box marker entry contains nonzero payload-tail bytes")]
    NonzeroPayloadTail,
    /// Forward-compatibility bytes in a shared entry were nonzero.
    #[error("white-box marker entry contains nonzero reserved bytes")]
    NonzeroReservedBytes,
}

/// An error produced while validating a mapped setup region header.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionSetupValidationError {
    /// The mapped length is too small to contain a shared-memory header.
    #[error("setup region length {region_len} is smaller than header size {minimum_len}")]
    RegionTooSmall {
        /// The rejected `Setup.region_len`.
        region_len: u64,
        /// The minimum mappable length required for the header.
        minimum_len: u64,
    },
    /// The region header magic is not [`REGION_MAGIC`].
    #[error("setup region magic {actual:#x} does not match expected {expected:#x}")]
    InvalidMagic {
        /// Magic value read from the mapped header.
        actual: u64,
        /// Required magic value.
        expected: u64,
    },
    /// The region header ABI version is not [`ABI_VERSION`].
    #[error("setup region ABI version {actual} does not match expected {expected}")]
    AbiVersionMismatch {
        /// ABI version read from the mapped header.
        actual: u32,
        /// ABI version compiled into this crate.
        expected: u32,
    },
    /// The header's region size does not match the control-protocol setup length.
    #[error(
        "setup region length {setup_region_len} does not match header region_size {header_region_size}"
    )]
    RegionLengthMismatch {
        /// Length from the control-protocol `Setup` frame.
        setup_region_len: u64,
        /// Length read from the mapped region header.
        header_region_size: u64,
    },
    /// The directed-ring count cannot represent any valid VM-node count.
    #[error("setup region ring count {ring_count} is not a positive multiple of {rings_per_vm}")]
    InvalidRingCount {
        /// Ring count read from the mapped region header.
        ring_count: u32,
        /// Required directed-ring count per VM node.
        rings_per_vm: u32,
    },
    /// The header geometry cannot be recomputed by the current layout model.
    #[error("setup region layout is invalid")]
    InvalidLayout {
        /// Underlying layout-model error.
        source: RegionLayoutError,
    },
    /// The header node count does not match the fixed ABI slot array.
    #[error("setup region node count {actual} does not match expected {expected}")]
    InvalidNodeCount {
        /// Node count read from the mapped region header.
        actual: u32,
        /// Required physical node count.
        expected: u32,
    },
    /// The header ring-header offset does not match the recomputed layout.
    #[error("setup region ring header offset {actual} does not match expected {expected}")]
    InvalidRingHeaderOffset {
        /// Offset read from the mapped region header.
        actual: u64,
        /// Required offset from the recomputed layout.
        expected: u64,
    },
    /// The header frame-entry offset does not match the recomputed layout.
    #[error("setup region ring data offset {actual} does not match expected {expected}")]
    InvalidRingDataOffset {
        /// Offset read from the mapped region header.
        actual: u64,
        /// Required offset from the recomputed layout.
        expected: u64,
    },
    /// The header frame-entry stride does not match the ABI entry size.
    #[error("setup region entry stride {actual} does not match expected {expected}")]
    InvalidEntryStride {
        /// Stride read from the mapped region header.
        actual: u64,
        /// Required frame-entry stride.
        expected: u64,
    },
    /// The recomputed layout size does not match the control-protocol setup length.
    #[error(
        "setup region length {setup_region_len} does not match computed layout size {layout_region_size}"
    )]
    LayoutRegionLengthMismatch {
        /// Length from the control-protocol `Setup` frame.
        setup_region_len: u64,
        /// Length recomputed from the header geometry.
        layout_region_size: u64,
    },
    /// The layout recomputation overflowed.
    #[error("setup region geometry overflowed during validation")]
    GeometryOverflow,
}

/// An error produced while validating or allocating a shared-memory region.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionLayoutError {
    /// The crate was compiled for a target outside the pinned ABI layout target.
    #[error("shared-memory layout target {actual} is unsupported; expected {expected}")]
    UnsupportedTarget {
        /// The target triple required by the ABI.
        expected: &'static str,
        /// The target class observed at compile time.
        actual: &'static str,
    },
    /// The requested logical VM count cannot fit beside reserved executor slots.
    #[error("requested {requested} VM nodes exceeds maximum {max}")]
    TooManyVmNodes {
        /// The requested logical VM node count.
        requested: u32,
        /// The maximum logical VM node count.
        max: u32,
    },
    /// The per-ring queue capacity was zero or not a power of two.
    #[error("queue capacity {capacity} is not a nonzero power of two")]
    InvalidQueueCapacity {
        /// The rejected per-ring capacity.
        capacity: u32,
    },
    /// The fixed icount shift cannot be represented in `u64` conversions.
    #[error("icount shift {shift_bits} cannot be represented as u64")]
    InvalidIcountShift {
        /// The rejected shift value.
        shift_bits: u32,
    },
    /// The computed region byte geometry overflowed an integer.
    #[error("computed shared-memory region geometry overflowed")]
    GeometryOverflow,
}

/// An error produced while serializing an initialized region for setup handoff.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionSerializationError {
    /// The region size cannot fit in a process-local byte vector.
    #[error("shared-memory region size {region_size} cannot fit in usize")]
    RegionSizeTooLarge {
        /// Computed region size in bytes.
        region_size: u64,
    },
    /// A segment offset overflowed while serializing the region.
    #[error("shared-memory {segment} index {index} offset overflowed")]
    SegmentOffsetOverflow {
        /// Segment kind being serialized.
        segment: &'static str,
        /// Segment index within its array.
        index: usize,
    },
    /// A segment would extend beyond the computed region length.
    #[error(
        "shared-memory {segment} index {index} at byte {offset} with length {len} extends past region length {region_len}"
    )]
    SegmentOutOfBounds {
        /// Segment kind being serialized.
        segment: &'static str,
        /// Segment index within its array.
        index: usize,
        /// Computed byte offset.
        offset: usize,
        /// Segment length in bytes.
        len: usize,
        /// Total region length in bytes.
        region_len: usize,
    },
}

/// An error produced by SPSC ring operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SpscRingError {
    /// The backing entry slice is empty or not power-of-two sized.
    #[error("SPSC ring capacity {capacity} is not a nonzero power of two")]
    InvalidCapacity {
        /// The invalid backing entry count.
        capacity: usize,
    },
    /// The ring cannot accept another frame.
    #[error("SPSC ring is full at capacity {capacity}")]
    QueueFull {
        /// The ring capacity in frame entries.
        capacity: u64,
    },
    /// The live entry count exceeds the configured capacity.
    #[error(
        "SPSC ring indices are corrupt: read_idx={read_idx} write_idx={write_idx} capacity={capacity}"
    )]
    CorruptIndices {
        /// The consumer-owned read index.
        read_idx: u64,
        /// The producer-owned write index.
        write_idx: u64,
        /// The ring capacity in frame entries.
        capacity: u64,
    },
    /// A guest-introspection entry failed its fixed-layout validation.
    #[error("SPSC guest-introspection entry is malformed")]
    InvalidGuestIntrospectionEntry {
        /// Entry validation failure.
        #[source]
        source: GuestIntrospectionEntryError,
    },
    /// A directional guest-introspection publication sequence is discontinuous.
    #[error("SPSC guest-introspection sequence mismatch: expected {expected}, actual {actual}")]
    GuestIntrospectionSequenceMismatch {
        /// Next sequence required by the consumer.
        expected: u64,
        /// Sequence observed in the shared entry.
        actual: u64,
    },
    /// A quiescent snapshot cannot fit in the target ring.
    #[error("SPSC snapshot length {len} exceeds ring capacity {capacity}")]
    SnapshotTooLarge {
        /// The number of frames in the snapshot.
        len: usize,
        /// The ring capacity in frame entries.
        capacity: u64,
    },
    /// A frame in the ring or snapshot advertises an impossible payload length.
    #[error("SPSC frame payload length {len} exceeds capacity {capacity}")]
    InvalidFrameLength {
        /// The invalid frame payload length.
        len: usize,
        /// The maximum payload capacity in bytes.
        capacity: usize,
    },
    /// The snapshot frame count cannot fit in the canonical byte encoding.
    #[error("SPSC snapshot length {len} cannot be encoded as u64")]
    SnapshotLengthOverflow {
        /// The number of frames in the snapshot.
        len: usize,
    },
    /// The encoded snapshot frame count cannot fit in this target's memory size.
    #[error("SPSC snapshot frame count {count} cannot fit in usize")]
    SnapshotFrameCountOverflow {
        /// The rejected encoded frame count.
        count: u64,
    },
    /// The canonical snapshot byte stream ended before the declared field.
    #[error(
        "SPSC snapshot decode truncated at byte {offset}: needed {needed} bytes, available {available}"
    )]
    SnapshotDecodeTruncated {
        /// The byte offset where the decoder needed more input.
        offset: usize,
        /// The number of bytes needed for the current field.
        needed: usize,
        /// The bytes remaining in the input.
        available: usize,
    },
    /// The canonical snapshot byte stream contained bytes after declared frames.
    #[error("SPSC snapshot decode left {available} trailing bytes at byte {offset}")]
    SnapshotDecodeTrailingBytes {
        /// The byte offset where declared frames ended.
        offset: usize,
        /// The number of bytes left after declared frames.
        available: usize,
    },
}

/// A lookahead-gate validation error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LookaheadGateError {
    /// A scheduler attempted to publish a ceiling behind the consumer.
    #[error("max advance icount {max_advance_icount} is before current icount {current_icount}")]
    CeilingBeforeCurrent {
        /// The consumer icount observed before authorization.
        current_icount: u64,
        /// The requested maximum advance icount.
        max_advance_icount: u64,
    },
    /// A scheduler attempted to let a node reach an input's possible delivery.
    #[error(
        "max advance icount {max_advance_icount} reaches possible delivery icount {earliest_possible_delivery_icount}"
    )]
    AdvanceReachesPossibleDelivery {
        /// The requested maximum advance icount.
        max_advance_icount: u64,
        /// The earliest icount at which an input could become visible.
        earliest_possible_delivery_icount: u64,
    },
    /// A frame was enqueued after the consumer passed its delivery icount.
    #[error("frame {frame:?} delivery icount is behind consumer icount {consumer_current_icount}")]
    DeliveryAlreadyPassed {
        /// The consumer icount observed when the frame was enqueued.
        consumer_current_icount: u64,
        /// The late frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
}

pub(super) fn validated_capacity<T>(entries: &[T]) -> Result<u64, SpscRingError> {
    if entries.is_empty() || !entries.len().is_power_of_two() {
        return Err(SpscRingError::InvalidCapacity {
            capacity: entries.len(),
        });
    }
    Ok(entries.len() as u64)
}

pub(super) fn live_count(
    read_idx: u64,
    write_idx: u64,
    capacity: u64,
) -> Result<u64, SpscRingError> {
    let live = write_idx
        .checked_sub(read_idx)
        .ok_or(SpscRingError::CorruptIndices {
            read_idx,
            write_idx,
            capacity,
        })?;
    if live > capacity {
        Err(SpscRingError::CorruptIndices {
            read_idx,
            write_idx,
            capacity,
        })
    } else {
        Ok(live)
    }
}

/// An error produced by the per-node advance-ceiling slot.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NodeSlotError {
    /// A process requested an invalid fixed icount shift.
    #[error("icount shift {shift_bits} cannot be represented as u64")]
    InvalidShift {
        /// The rejected shift value.
        shift_bits: u8,
    },
    /// The virtual-time nanosecond view overflowed `u64`.
    #[error("icount {icount} shifted by {shift_bits} bits overflows virtual nanoseconds")]
    VirtualTimeOverflow {
        /// The icount being converted.
        icount: u64,
        /// The fixed shift value.
        shift_bits: u8,
    },
    /// A scheduler attempted to publish a ceiling behind the node's current icount.
    #[error(
        "max advance icount {max_advance_icount} is before published current icount {current_icount}"
    )]
    CeilingBeforePublishedCurrent {
        /// The node's published current icount.
        current_icount: u64,
        /// The rejected maximum advance icount.
        max_advance_icount: u64,
    },
    /// A node attempted to advance past the scheduler-published ceiling.
    #[error("node attempted to advance to icount {next_icount} past ceiling {max_advance_icount}")]
    NodeAdvancePastCeiling {
        /// The icount the node attempted to reach.
        next_icount: u64,
        /// The scheduler-published ceiling.
        max_advance_icount: u64,
    },
    /// A node published an idle wake behind its current icount.
    #[error("idle wake icount {idle_wake_icount} is before current icount {current_icount}")]
    IdleWakeBeforeCurrent {
        /// The node's current icount.
        current_icount: u64,
        /// The rejected idle wake icount.
        idle_wake_icount: u64,
    },
    /// A non-private futex wake failed after `wake_signal` was incremented.
    #[error("non-private futex wake failed after incrementing wake_signal: {source}")]
    FutexWake {
        /// The futex syscall failure.
        source: FutexError,
    },
}
