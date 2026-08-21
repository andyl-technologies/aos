//! Frame delivery ordering, lookahead authorization, and entry errors.

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
    pub(crate) current_icount: u64,
    pub(crate) max_advance_icount: u64,
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

/// A validation error for the consumer-owned frame delivery state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FrameDeliveryStateError {
    /// The shared byte carries a state unknown to this ABI version.
    #[error("frame delivery state {state} is not recognized")]
    UnknownState {
        /// The rejected shared-memory state byte.
        state: u8,
    },
}
