//! `crucible-shmem` owns the shared-memory ABI.
//!
//! Spec index: RFC-0010 files 13.
//!
//! This L1 crate is the single source of truth for the `#[repr(C)]` region
//! layout, per-node clocks, status words, and SPSC frame queues described by
//! its indexed RFC-0010 file. It is an unsafe-boundary crate because future
//! implementations map shared memory and expose layout-checked accessors.
//!
//! Module map: the crate root owns the initial frame-entry layout and
//! delivery-icount contract; future modules will split region headers, node
//! clocks, status words, and SPSC frame queues.
//!
//! Unsafe boundary discipline: mmap, pointer, and atomic details stay private;
//! public callers use safe typed region accessors and safe SPSC push/pop
//! wrappers that uphold alignment, lifetime, and ordering invariants.
//!
//! Frame-entry wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     delivery_icount
//! 8       4     src_node
//! 12      4     seq
//! 16      2     len
//! 18      6     padding
//! 24      N     payload bytes
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use thiserror::Error;

/// The maximum frame payload carried by a shared-memory [`FrameEntry`].
///
/// This RFC-fixed value is sector-aligned, leaves room for a 4 KiB block
/// response plus protocol headroom, and still fits in [`FrameEntry::len`].
pub const MAX_FRAME_DATA: usize = 4608;

const FRAME_ENTRY_DATA_OFFSET: usize = 24;
const _: () = assert!(MAX_FRAME_DATA <= u16::MAX as usize);

/// A shared-memory frame whose delivery time is carried in band.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FrameEntry {
    /// The consumer icount at which the frame becomes visible.
    pub delivery_icount: u64,
    /// The producer node id.
    pub src_node: u32,
    /// The per-producer sequence number.
    pub seq: u32,
    /// The number of valid bytes in [`FrameEntry::data`].
    pub len: u16,
    _pad: [u8; 6],
    /// The fixed-capacity frame payload buffer.
    pub data: [u8; MAX_FRAME_DATA],
}

const _: () = assert!(core::mem::offset_of!(FrameEntry, delivery_icount) == 0);
const _: () = assert!(core::mem::offset_of!(FrameEntry, src_node) == 8);
const _: () = assert!(core::mem::offset_of!(FrameEntry, seq) == 12);
const _: () = assert!(core::mem::offset_of!(FrameEntry, len) == 16);
const _: () = assert!(core::mem::offset_of!(FrameEntry, data) == FRAME_ENTRY_DATA_OFFSET);
const _: () =
    assert!(core::mem::size_of::<FrameEntry>() == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);
const _: () = assert!(core::mem::align_of::<FrameEntry>() == 8);

impl FrameEntry {
    /// Builds a frame entry with an in-band delivery icount.
    ///
    /// # Errors
    ///
    /// Returns [`FrameEntryError::PayloadLengthExceedsCapacity`] when `payload`
    /// is too large for [`MAX_FRAME_DATA`].
    pub fn new(
        delivery_icount: u64,
        src_node: u32,
        seq: u32,
        payload: &[u8],
    ) -> Result<Self, FrameEntryError> {
        if payload.len() > MAX_FRAME_DATA {
            return Err(FrameEntryError::PayloadLengthExceedsCapacity {
                len: payload.len(),
                capacity: MAX_FRAME_DATA,
            });
        }

        let mut data = [0; MAX_FRAME_DATA];
        data[..payload.len()].copy_from_slice(payload);

        Ok(Self {
            delivery_icount,
            src_node,
            seq,
            len: payload.len() as u16,
            _pad: [0; 6],
            data,
        })
    }

    /// Returns `true` when this frame is visible at `consumer_current_icount`.
    #[must_use]
    pub fn is_deliverable_at(&self, consumer_current_icount: u64) -> bool {
        self.delivery_icount <= consumer_current_icount
    }

    /// Returns the deterministic per-consumer delivery-order key.
    #[must_use]
    pub fn delivery_key(&self) -> FrameDeliveryKey {
        FrameDeliveryKey {
            delivery_icount: self.delivery_icount,
            src_node: self.src_node,
            seq: self.seq,
        }
    }

    /// Returns the valid payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FrameEntryError::PayloadLengthExceedsCapacity`] when a frame
    /// read from shared memory advertises a length greater than
    /// [`MAX_FRAME_DATA`].
    pub fn payload(&self) -> Result<&[u8], FrameEntryError> {
        let len = usize::from(self.len);
        if len > MAX_FRAME_DATA {
            Err(FrameEntryError::PayloadLengthExceedsCapacity {
                len,
                capacity: MAX_FRAME_DATA,
            })
        } else {
            Ok(&self.data[..len])
        }
    }
}

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
    current_icount: u64,
    max_advance_icount: u64,
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

    if let Some(earliest_possible_delivery_icount) = earliest_possible_delivery_icount {
        if max_advance_icount >= earliest_possible_delivery_icount {
            return Err(LookaheadGateError::AdvanceReachesPossibleDelivery {
                max_advance_icount,
                earliest_possible_delivery_icount,
            });
        }
    }

    Ok(AdvanceCeiling {
        current_icount,
        max_advance_icount,
    })
}

/// Verifies that a newly enqueued frame has not already missed its delivery.
///
/// # Errors
///
/// Returns [`LookaheadGateError::DeliveryAlreadyPassed`] when the consumer has
/// already reached or passed the frame's delivery icount.
pub fn validate_frame_delivery_is_future(
    frame: &FrameEntry,
    consumer_current_icount: u64,
) -> Result<(), LookaheadGateError> {
    if frame.delivery_icount <= consumer_current_icount {
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
    /// A frame was enqueued after the consumer reached its delivery icount.
    #[error(
        "frame {frame:?} delivery icount is not in the future of consumer icount {consumer_current_icount}"
    )]
    DeliveryAlreadyPassed {
        /// The consumer icount observed when the frame was enqueued.
        consumer_current_icount: u64,
        /// The late frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
}
