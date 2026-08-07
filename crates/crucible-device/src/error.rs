//! Error taxonomy for the uniform I/O sub-node model.
//!
//! This module owns [`DeviceError`], the single `thiserror` enum every fallible
//! sub-node operation returns. It models the deterministic failure modes of the
//! request/response lifecycle (clock conversion overflow, monotonicity
//! violations, full-ring backpressure that cannot make progress) so that no I/O
//! path ever panics or depends on host state to decide an outcome.

use crucible_shmem::{FrameEntryError, FutexError, NodeSlotError, SpscRingError};

use crate::block::codec::BlockCodecError;
use crate::ninep::codec::NinepCodecError;

/// A deterministic failure of an I/O sub-node operation.
///
/// Every variant is a pure function of the sub-node's owned state and the
/// requested operation; none depends on host wall-clock, host scheduling, or
/// host filesystem ordering. Sub-node code propagates these with `?` rather than
/// panicking so that a malformed request or an exhausted clock range fails
/// loudly and reproducibly.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceError {
    /// An explorer-supplied draw vector does not match the active fault table.
    #[error("invalid injected network draw vector: {message}")]
    InvalidInjectedDraws {
        /// The deterministic shape mismatch.
        message: String,
    },

    /// The icount-to-nanosecond conversion (or its inverse) failed.
    ///
    /// Wraps the [`NodeSlotError`] raised by `crucible-shmem`'s fixed-shift
    /// virtual-time map: an out-of-range `shift_bits`, or an icount whose
    /// nanosecond view overflows `u64`.
    #[error("virtual-time conversion failed: {source}")]
    Clock {
        /// The underlying virtual-time conversion failure.
        source: NodeSlotError,
    },

    /// A target nanosecond instant has no representable icount under the shift.
    ///
    /// Raised by the nanosecond-to-icount ceil map ([TIME-4]) when the smallest
    /// icount whose virtual nanosecond view is at or above the target would
    /// overflow `u64`.
    #[error("target {target_ns} ns has no representable icount at shift {shift_bits}")]
    IcountOverflow {
        /// The nanosecond instant that could not be mapped to an icount.
        target_ns: u64,
        /// The fixed virtual-time shift in bits.
        shift_bits: u8,
    },

    /// A modeled latency pushed a completion past the representable ns range.
    ///
    /// Raised when `virtual_ns(request_icount) + latency` overflows `u64`
    /// nanoseconds before the ceil map runs.
    #[error("completion nanoseconds overflowed: vt({request_icount}) + {latency_ns} ns")]
    CompletionOverflow {
        /// The requester icount whose virtual nanoseconds form the base.
        request_icount: u64,
        /// The modeled latency added to the base, in nanoseconds.
        latency_ns: u64,
    },

    /// A device returned additional completions without a primary completion.
    #[error("computed response contains duplicates but no primary completion")]
    InvalidComputedResponse,

    /// The canonical completion-order sequence exhausted its wire width.
    #[error("response ordering sequence exhausted at {sequence}")]
    ResponseSequenceOverflow {
        /// Last representable sequence value that could not be advanced.
        sequence: u32,
    },

    /// A resolved block directive is malformed or disagrees with its request.
    #[error("invalid resolved block fault directive: {reason}")]
    InvalidBlockFaultDirective {
        /// Stable validation failure.
        reason: &'static str,
    },

    /// Signal-driven execution required a directive for this exact request.
    #[error("missing resolved block fault directive for request {request_id}")]
    MissingBlockFaultDirective {
        /// Guest request identity.
        request_id: u32,
    },

    /// The scheduler attempted to pass an unresolved staged storage boundary.
    #[error(
        "cannot advance storage to {requested_nanos}ns past unresolved fault opportunity at {ready_nanos}ns"
    )]
    UnresolvedBlockFaultOpportunity {
        /// Exact coordinate whose decision is still absent.
        ready_nanos: u64,
        /// Rejected requested advance coordinate.
        requested_nanos: u64,
    },

    /// Two unresolved directives attempted to own one request identity.
    #[error("duplicate resolved block fault directive for request {request_id}")]
    DuplicateBlockFaultDirective {
        /// Guest request identity.
        request_id: u32,
    },

    /// A duplicate completion reached a device without a bound live transport.
    #[error(
        "block request {request_id} requires duplicate-completion transport handling before COMPUTE"
    )]
    BlockDuplicateTransportUnavailable {
        /// Guest request whose resolved directive requires transport handling.
        request_id: u32,
    },

    /// Checkpointed block fault state reached a compiled hard ceiling.
    #[error("block fault state `{field}` reached hard limit {hard}")]
    BlockFaultStateLimit {
        /// Bounded state collection.
        field: &'static str,
        /// Compiled hard ceiling.
        hard: usize,
    },

    /// The exact volatile cache cannot admit another selected write.
    #[error(
        "block volatile cache has {available_bytes} bytes available, request needs {requested_bytes}"
    )]
    BlockCacheFull {
        /// Bytes requested by the write fragment.
        requested_bytes: u64,
        /// Remaining configured capacity.
        available_bytes: u64,
    },

    /// An integrated storage-service queue reached its configured request depth.
    #[error("block storage-service queue for contributor {contributor:?} is full at depth {depth}")]
    BlockServiceQueueFull {
        /// Contributor whose independently constrained queue is full.
        contributor: [u8; 32],
        /// Exact configured active-plus-pending request limit.
        depth: u32,
    },

    /// The scheduler asked the clock to move backward.
    ///
    /// The virtual clock is monotonic and advanced only by the scheduler; a
    /// limit below the current icount is a contract violation, not a wait.
    #[error("clock cannot move backward: limit {limit_icount} is before current {current_icount}")]
    ClockRegression {
        /// The sub-node's current icount.
        current_icount: u64,
        /// The rejected limit the scheduler attempted to advance to.
        limit_icount: u64,
    },

    /// A computed completion would land in the consumer's past.
    ///
    /// The fail-loud guard of RFC §15.1.1: a response whose `delivery_icount` is
    /// strictly below the sub-node's current icount can never be delivered at
    /// its exact icount and would corrupt the global `delivery_icount` order
    /// ([IO-31], [IO-34]). The sub-node MUST fail loudly here rather than
    /// enqueue a past-dated response.
    #[error(
        "computed delivery icount {delivery_icount} is in the consumer's past (current {current_icount})"
    )]
    DeliveryInPast {
        /// The computed delivery icount that lands in the past.
        delivery_icount: u64,
        /// The sub-node's current icount at COMPUTE time.
        current_icount: u64,
    },

    /// A read or write range extends past the device length.
    ///
    /// The block sub-node rejects an out-of-bounds range rather than silently
    /// truncating or extending it ([IO-6]). It is surfaced in band as an
    /// error-status response when a request is served, and out of band (this
    /// error) when the overlay API is called directly.
    #[error("range [{offset}, {offset}+{len}) extends past device length {device_len}")]
    OutOfRange {
        /// The byte offset of the rejected range.
        offset: u64,
        /// The byte length of the rejected range.
        len: u64,
        /// The device length the range exceeded.
        device_len: u64,
    },

    /// A restore was handed a base image whose hash differs from the snapshot's.
    ///
    /// The block snapshot never carries the base image bytes ([TEMP-9]); restore
    /// re-supplies the content-addressed base and verifies its BLAKE3 hash
    /// matches the recorded `base_hash` ([IO-11]). A mismatch means the wrong
    /// parent World was supplied.
    #[error("restore base hash mismatch")]
    BaseMismatch {
        /// The BLAKE3 hash the snapshot recorded for its base.
        expected: [u8; 32],
        /// The BLAKE3 hash of the base image supplied to restore.
        found: [u8; 32],
    },

    /// A block wire message failed to decode at the device boundary.
    ///
    /// Hostile request bytes are answered in band with an error-status response
    /// rather than this error ([IO-8]); this variant surfaces only when the
    /// device's own re-encoded response fails to decode, which indicates an
    /// internal encoding bug, not external input.
    #[error("block wire codec error: {0}")]
    Codec(#[from] BlockCodecError),

    /// A 9p wire message failed to encode at the device boundary.
    ///
    /// Hostile request bytes are answered in band with an `Rlerror` response
    /// rather than this error ([IO-17], [IO-18]); this variant surfaces only when
    /// the device's own re-encoded response fails to encode (for example a
    /// `readdir` payload that overflows the negotiated `msize`), which indicates
    /// an internal encoding bug, not external input.
    #[error("9p wire codec error: {0}")]
    NinepCodec(#[from] NinepCodecError),

    /// A shared-memory frame entry could not carry or expose its payload.
    ///
    /// This is a deterministic transport-boundary failure: either a device
    /// response is larger than the fixed [`crucible_shmem::FrameEntry`] payload
    /// capacity, or a frame read from a ring advertises an invalid payload length.
    #[error("shared-memory frame entry error: {source}")]
    FrameEntry {
        /// The underlying frame-entry validation failure.
        source: FrameEntryError,
    },

    /// A shared-memory SPSC ring operation failed.
    ///
    /// Non-full failures indicate corrupt indices or an invalid backing slice.
    /// Full-ring backpressure is handled by the lifecycle bridge when it can
    /// preserve the pending frame in flight; direct conversions surface the
    /// same deterministic ring error here.
    #[error("shared-memory SPSC ring error: {source}")]
    ShmemRing {
        /// The underlying ring operation failure.
        source: SpscRingError,
    },

    /// A wake tied to a shared-memory ring transition failed.
    ///
    /// The ring transition is deterministic and already happened; this variant
    /// fails loudly when the cross-process futex wake syscall itself reports an
    /// unexpected error.
    #[error("shared-memory wake failed: {source}")]
    ShmemWake {
        /// The underlying non-private futex wake failure.
        source: FutexError,
    },

    /// A network link's base latency is not strictly positive.
    ///
    /// RFC §15.4.2 / [IO-33]: a link's base latency MUST be strictly positive and
    /// at or above the configured minimum link-latency floor, because the base
    /// latency is exactly what supplies the conservative lookahead bound to the
    /// scheduler ([SCHED-6], [SCHED-20]). A zero-latency link would give a peer
    /// zero lookahead and collapse the system to single-instruction lockstep, so
    /// it is rejected at construction rather than silently accepted. The floor
    /// itself must also be strictly positive for the same reason.
    #[error(
        "link base latency {base_latency_ns} ns is below the strictly-positive floor {floor_ns} ns"
    )]
    LinkLatencyBelowFloor {
        /// The rejected base latency in virtual nanoseconds.
        base_latency_ns: u64,
        /// The strictly-positive minimum link-latency floor in virtual nanoseconds.
        floor_ns: u64,
    },

    /// A reorder/jitter shift would deliver a frame into the consumer's past.
    ///
    /// The fail-loud path of RFC §15.4.2 / [IO-34]: a reorder fault is a
    /// per-frame seeded delivery-icount shift that may move one frame's delivery
    /// past another's, but every resulting `delivery_icount` MUST stay within the
    /// consumer's future at the instant the frame is enqueued ([SHM-35]). A
    /// modeled shift that would land at or before the consumer's current frontier
    /// can never be delivered at its exact icount; rather than silently deliver
    /// late, the link either clamps to a deliverable future icount (the
    /// caller-selected policy) or fails loudly with this error via the divergence
    /// path ([INV-10]).
    #[error(
        "reorder/jitter shift moved frame delivery to icount {delivery_icount}, in the consumer's past (frontier {consumer_frontier})"
    )]
    DeliveryReorderedIntoPast {
        /// The computed delivery icount that lands at or before the frontier.
        delivery_icount: u64,
        /// The consumer's current frontier icount at enqueue time.
        consumer_frontier: u64,
    },

    /// A backpressured ring is full and cannot accept the producer's frame.
    ///
    /// This is the deterministic block-and-wait signal of [IO-32]: the producer
    /// blocks at its current boundary until the consumer frees a slot. It is
    /// never a drop — the caller retries after the consumer drains. It is also
    /// reused as the capacity-shape rejection for a non-power-of-two ring size.
    #[error("ring is full at capacity {capacity}; producer must block until space frees")]
    RingFull {
        /// The fixed ring capacity in entries.
        capacity: u64,
    },

    /// A scheduler bridge attempted to submit a request to the wrong device kind.
    ///
    /// This is a wiring error at the typed sub-node boundary: a block request must
    /// be submitted only to a block sub-node, and a 9p frame only to a 9p
    /// sub-node. The error is deterministic and fails loudly before any response
    /// can be computed or enqueued.
    #[error("wrong I/O sub-node kind: expected {expected}, found {actual}")]
    WrongDeviceKind {
        /// The device kind the request path requires.
        expected: &'static str,
        /// The concrete device kind held by the sub-node.
        actual: &'static str,
    },
}

impl From<NodeSlotError> for DeviceError {
    fn from(source: NodeSlotError) -> Self {
        DeviceError::Clock { source }
    }
}

impl From<FrameEntryError> for DeviceError {
    fn from(source: FrameEntryError) -> Self {
        DeviceError::FrameEntry { source }
    }
}

impl From<SpscRingError> for DeviceError {
    fn from(source: SpscRingError) -> Self {
        DeviceError::ShmemRing { source }
    }
}

impl From<FutexError> for DeviceError {
    fn from(source: FutexError) -> Self {
        DeviceError::ShmemWake { source }
    }
}
