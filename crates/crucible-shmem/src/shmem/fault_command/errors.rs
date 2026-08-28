//! Fault ABI validation and transport errors.

use super::*;

/// Byte-level fault ABI validation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FaultAbiError {
    /// The command or result header has the wrong exact byte length.
    #[error("fault ABI header length mismatch")]
    HeaderLength,
    /// The ABI or semantic version is unsupported.
    #[error("fault ABI version mismatch")]
    Version,
    /// A command kind tag is not registered.
    #[error("unknown fault command kind {0}")]
    UnknownCommandKind(u16),
    /// A result status tag is not registered.
    #[error("unknown fault result status {0}")]
    UnknownResultStatus(u16),
    /// A boundary phase tag is not registered.
    #[error("unknown fault boundary phase {0}")]
    UnknownBoundaryPhase(u16),
    /// Unsupported command flag bits are set.
    #[error("unsupported fault command flags")]
    Flags,
    /// A sequence or capability version is zero.
    #[error("invalid fault ABI sequence")]
    Sequence,
    /// The target coordinate exceeds its authorization ceiling.
    #[error("invalid fault ABI coordinate")]
    Coordinate,
    /// Reserved bytes are nonzero.
    #[error("fault ABI reserved bytes are nonzero")]
    ReservedNonzero,
    /// A payload exceeds its compiled hard limit.
    #[error("fault ABI payload exceeds the hard limit")]
    PayloadLimit,
    /// A payload offset and length escape the supplied arena.
    #[error("fault ABI payload bounds are invalid")]
    PayloadBounds,
    /// A payload digest does not authenticate the selected bytes.
    #[error("fault ABI payload digest mismatch")]
    PayloadDigest,
    /// Applied/rejected result fields contradict the status.
    #[error("fault ABI result invariants are invalid")]
    ResultInvariant,
    /// A capability row or manifest violates its canonical contract.
    #[error("fault ABI capability invariant is invalid")]
    CapabilityInvariant,
}

/// Shared-memory fault command transport failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FaultTransportError {
    /// The reversible hot-fork barrier rejects a new producer publication.
    #[error("fault transport producer admission is held for hot fork")]
    ProducerBarrierHeld,
    /// The command/result ring capacity is invalid for the ABI.
    #[error("fault transport ring capacity {capacity} is invalid")]
    InvalidRingCapacity {
        /// Invalid entry count.
        capacity: usize,
    },
    /// The payload arena capacity is zero or exceeds the ABI hard bound.
    #[error("fault payload arena capacity {capacity} is invalid")]
    InvalidArenaCapacity {
        /// Invalid byte capacity.
        capacity: usize,
    },
    /// The command/result ring cannot accept another entry.
    #[error("fault command/result ring is full at capacity {capacity}")]
    RingFull {
        /// Fixed entry capacity.
        capacity: u64,
    },
    /// The payload arena cannot accept one contiguous reservation.
    #[error("fault payload arena has {available} bytes available, need {requested}")]
    PayloadArenaFull {
        /// Requested payload plus any required wrap padding.
        requested: u64,
        /// Currently free bytes.
        available: u64,
    },
    /// One payload cannot fit under the configured or hard limit.
    #[error("fault payload length {len} exceeds the arena or ABI limit")]
    PayloadTooLarge {
        /// Rejected payload length.
        len: usize,
    },
    /// The consumer could not allocate the owned payload before releasing it.
    #[error("fault payload allocation failed for {requested} bytes")]
    PayloadAllocationFailed {
        /// Exact payload byte count requested from the allocator.
        requested: usize,
    },
    /// A caller-supplied payload buffer cannot hold the published result.
    #[error("fault payload buffer capacity {capacity} is smaller than {requested} bytes")]
    PayloadBufferTooSmall {
        /// Already-owned buffer capacity.
        capacity: usize,
        /// Exact published payload byte count.
        requested: usize,
    },
    /// Producer and consumer indices describe more live entries than capacity.
    #[error("fault ring indices are corrupt: read={read} write={write} capacity={capacity}")]
    CorruptRingIndices {
        /// Consumer-owned index.
        read: u64,
        /// Producer-owned index.
        write: u64,
        /// Fixed entry capacity.
        capacity: u64,
    },
    /// Producer and consumer byte cursors describe impossible live storage.
    #[error("fault arena cursors are corrupt: read={read} write={write} capacity={capacity}")]
    CorruptArenaCursors {
        /// Consumer-owned cursor.
        read: u64,
        /// Producer-owned cursor.
        write: u64,
        /// Fixed byte capacity.
        capacity: u64,
    },
    /// Slot-owned reservation framing disagrees with the arena state.
    #[error("fault payload reservation framing is corrupt")]
    CorruptReservation,
    /// An offset, cursor, or length calculation overflowed.
    #[error("fault transport arithmetic overflow")]
    ArithmeticOverflow,
    /// The command envelope violates the byte-level ABI.
    #[error(transparent)]
    Abi(FaultAbiError),
}
