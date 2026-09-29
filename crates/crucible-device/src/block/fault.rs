//! Exact block durability and resolved fault directives.
//!
//! The signal evaluator lives above `crucible-device`. Before a live request is
//! consumed it installs one fully resolved directive here. This layer applies
//! that directive to real block bytes, volatile cache state, durable state, and
//! the real response transported through the shared-memory ring. It performs no
//! signal evaluation and gives no semantic meaning to opaque policy names.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeviceError;
use crate::request::{AdditionalCompletion, ComputedResponse, Response, ResponseStatus};

use super::codec::{
    BlockErrorCode, BlockOp, BlockRequest, BlockRequestIdentity, BlockResponse, BlockStatus,
    BlockTransportPending, BlockTransportRequestIds, BlockTransportReset, BlockTransportResolved,
    BlockTransportUnadmitted, BlockTransportUndelivered,
};
use super::flash::{BlockFlashMutationOutcome, BlockFlashState, ResolvedBlockFlashRule};
use super::media::{BlockMediaState, ResolvedBlockMediaRule};
use super::overlay::{BaseImage, CowOverlay};
use super::persistence::{
    BlockPersistenceGraph, BlockWriteFragmentId, ResolvedBlockPersistenceTransform,
};
use super::service::{
    BlockServiceCompletion, BlockServiceJob, BlockServiceState, ResolvedBlockServiceRule,
};

mod checkpoint_codec;
mod directive_validation;
mod durability_config;
mod helpers;

use helpers::*;
pub(in crate::block) use helpers::{keyed_discard_bytes, request_in_capacity};
#[macro_use]
mod observation_effects;
mod state_admission;
pub use state_admission::BlockExecutionServiceSummary;
mod observation_revision;
mod state_execution;

pub use checkpoint_codec::{BlockFaultStateCodecError, MAX_BLOCK_FAULT_STATE_BYTES};

/// Hard maximum directives waiting for their exact request.
pub const HARD_PENDING_BLOCK_FAULT_DIRECTIVES: usize = 1_048_576;
/// Hard aggregate heap bytes retained by pending resolved directives.
pub const HARD_PENDING_BLOCK_FAULT_BYTES: u64 = 268_435_456;
/// Hard maximum volatile cache entries.
pub const HARD_BLOCK_CACHE_ENTRIES: usize = 4_194_304;
/// Hard maximum controller-accepted write entries.
pub const HARD_BLOCK_CONTROLLER_ENTRIES: usize = 4_194_304;
/// Hard aggregate bytes waiting in the direct-to-media persistence queue.
pub const HARD_BLOCK_MEDIA_QUEUE_BYTES: u64 = 137_438_953_472;
/// Hard maximum bytes in either configured volatile storage layer.
pub const HARD_BLOCK_VOLATILE_LAYER_BYTES: u64 = 68_719_476_736;
/// Hard maximum retained historical versions.
pub const HARD_BLOCK_RETAINED_VERSIONS: usize = 4_194_304;
/// Hard maximum exact spans in one resolved write directive.
pub const HARD_BLOCK_WRITE_SPANS: usize = 65_536;
/// Hard maximum duplicate completions from one operation.
pub const HARD_BLOCK_DUPLICATE_COMPLETIONS: usize = 256;
/// Hard maximum stalled completions retained across checkpoints.
pub const HARD_BLOCK_RETAINED_COMPLETIONS: usize = 1_048_576;
/// Hard maximum resolved media-persistence directives and retained outcomes.
pub const HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS: usize = 1_048_576;
/// Hard maximum controller epochs whose queued-request reset policy is retained.
pub const HARD_BLOCK_RETIRED_TRANSPORT_EPOCHS: usize = 65_536;
/// Hard maximum old-epoch request identities authorized for one preserved retry.
pub const HARD_BLOCK_RETRY_PRESERVE_AUTHORIZATIONS: usize = 1_048_576;
/// Hard maximum canonical dirty ranges awaiting array-member rebuild.
pub const HARD_BLOCK_ARRAY_DIRTY_RANGES: usize = 4_194_304;
/// Hard aggregate exact bytes retained for array-member rebuild.
pub const HARD_BLOCK_ARRAY_DIRTY_BYTES: u64 = 137_438_953_472;

/// One checkpointed logical range absent from an array member.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockArrayDirtyRange {
    /// Stable array member ordinal.
    pub member_ordinal: u16,
    /// First physical member byte requiring repair.
    pub start_byte: u64,
    /// Exact replacement bytes required on the member.
    pub bytes: Vec<u8>,
    /// Monotone logical mutation generation carried through rebuild races.
    pub generation: u64,
    /// Coordinate at which this range first became dirty.
    pub dirty_ticks: u64,
}

/// Checkpointed array rebuild scheduling continuation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockArrayRebuildCursor {
    /// Next stable rebuild-opportunity sequence.
    pub next_sequence: u64,
    /// Completion coordinate of the last charged rebuild chunk.
    pub available_ticks: Option<u64>,
    /// Earliest coordinate at which another rebuild chunk can complete.
    pub next_ready_ticks: Option<u64>,
    /// Member bound to the scheduled deadline.
    pub scheduled_member: Option<u16>,
    /// Physical range start bound to the scheduled deadline.
    pub scheduled_start_byte: Option<u64>,
    /// Dirty generation bound to the scheduled deadline.
    pub scheduled_generation: Option<u64>,
}

/// One authenticated array rebuild chunk ready for host evaluation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockArrayRebuildOpportunity {
    /// Stable rebuild sequence.
    pub sequence: u64,
    /// Target member ordinal.
    pub member_ordinal: u16,
    /// Physical member offset.
    pub start_byte: u64,
    /// Exact replacement bytes.
    pub bytes: Vec<u8>,
    /// Dirty generation used to reject a stale repair racing a newer write.
    pub generation: u64,
    /// Modeled completion coordinate.
    pub ready_ticks: u64,
}

/// Reset policy retained for requests already published under an older epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BlockRetiredTransportEpoch {
    queued: BlockTransportPending,
    failure_result: BlockErrorCode,
}

/// Availability presented by the block controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockFaultAvailability {
    /// Reads and writes are admitted.
    Online,
    /// No operation is admitted.
    Offline,
    /// Reads are admitted and writes fail.
    ReadOnly,
    /// Operations remain admitted under explicit per-request directives.
    Degraded,
}

/// Durability reached before an ordinary successful completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockCompletionDurability {
    /// The write may complete after controller acceptance.
    ControllerAccepted,
    /// The write may complete after admission to volatile cache.
    VolatileCacheAccepted,
    /// The write completes only after durable persistence.
    Durable,
}

/// Guest-visible readback after a successful discard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockDiscardSemantics {
    /// Discarded bytes deterministically read as zero.
    DeterministicZero,
    /// Discard leaves the prior logical bytes visible.
    ReadsOldData,
    /// Discard installs deterministic device/request-keyed bytes for replay.
    UndefinedKeyed,
}

/// Immutable durability bounds for one block device.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockDurabilityConfig {
    /// Guest-visible device length without an active capacity effect.
    pub length_bytes: u64,
    /// Smallest independently applied write fragment.
    pub atomic_write_bytes: u32,
    /// Maximum admitted request bytes.
    pub maximum_request_bytes: u64,
    /// Required discard alignment, or zero when discard is unsupported.
    pub discard_granularity_bytes: u32,
    /// Exact readback contract for successful discard.
    pub discard_semantics: BlockDiscardSemantics,
    /// Maximum exact volatile-cache bytes.
    pub volatile_cache_bytes: u64,
    /// Maximum volatile-cache entries.
    pub cache_entries: u32,
    /// Maximum bytes accepted by the controller but not yet admitted to cache/media.
    pub controller_buffer_bytes: u64,
    /// Maximum controller-accepted write entries.
    pub controller_entries: u32,
    /// Maximum live persistence dependency edges for this device.
    pub persistence_dependencies: u32,
    /// Maximum retained versions.
    pub retained_versions: u32,
    /// Normal successful-completion durability.
    pub completion_durability: BlockCompletionDurability,
}

/// One exact half-open request-relative byte span.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct BlockFaultByteSpan {
    /// First selected byte relative to the request.
    pub start: u64,
    /// Positive selected length.
    pub length: u64,
}

impl BlockFaultByteSpan {
    fn end(self) -> Option<u64> {
        self.start.checked_add(self.length)
    }
}

/// Exact data returned instead of the ordinary read result.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockFaultReadTransform {
    /// XORs a nonempty mask over one request-relative range.
    Xor {
        /// First transformed byte.
        offset: u64,
        /// Nonempty mask bytes applied once, without repetition.
        mask: Vec<u8>,
    },
    /// Replaces the complete read with already-resolved stale/misdirected bytes.
    Replace {
        /// Exact replacement bytes, equal in length to the read.
        bytes: Vec<u8>,
    },
}

/// Exact physical treatment of one admitted write.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockFaultWriteDisposition {
    /// Applies every byte at the addressed range.
    Apply,
    /// Applies no byte while preserving the separately declared guest status.
    Lost,
    /// Applies only the canonical non-overlapping request-relative spans.
    Torn {
        /// Exact selected spans.
        spans: Vec<BlockFaultByteSpan>,
    },
    /// Applies the complete bytes at another device/range.
    Misdirected {
        /// Authoritative destination selected during World resolution.
        destination: BlockFaultMisdirectionDestination,
        /// Replacement range start.
        destination_offset: u64,
    },
    /// Applies the declared prefix/subset produced by a flash program failure.
    ProgramFailure {
        /// Exact selected spans.
        spans: Vec<BlockFaultByteSpan>,
    },
}

/// Resolved device destination for a misdirected write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockFaultMisdirectionDestination {
    /// Redirects within the attached source device.
    AttachedDevice,
    /// Redirects to another authoritative device identified by target hash.
    ExternalDevice([u8; 32]),
}

/// Exact cross-device durability acknowledgement required before source delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockExternalDurabilityDependency {
    /// Content identity of the authoritative destination block device.
    pub destination_device: [u8; 32],
    /// Destination's configured acknowledgement stage for the redirected write.
    pub required_durability: BlockCompletionDurability,
    /// Destination cache sequence that must be included in that stage's frontier.
    pub required_frontier: u64,
}

/// Exact flush result and internal durability treatment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockFaultFlushDisposition {
    /// Persists the captured cache frontier before completing.
    Honest,
    /// Returns an error without changing durability.
    Error(BlockFaultResult),
    /// Returns success without advancing the actual durable frontier.
    Lie,
    /// Retains the completion until a later recovery event.
    Stall,
}

/// Deterministic volatile-cache victim order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockFaultCacheEviction {
    /// Selects the lowest admission sequence.
    Fifo,
    /// Selects the least recently accessed entry, then admission sequence.
    Lru,
    /// Selects the lowest pending writeback sequence.
    WritebackSequence,
}

/// Treatment of a dirty entry selected for cache eviction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockFaultDirtyEviction {
    /// Persists the selected entry before reclaiming it.
    Persist,
    /// Rejects the admitting write with its validated block error result.
    Fail(BlockFaultResult),
}

/// Protocol-neutral modeled result retained in block error evidence.
pub type BlockFaultResult = BlockErrorCode;

enum BlockWriteOutcome {
    Applied(u64),
    Rejected(BlockFaultResult),
}

/// Fully resolved volatile-cache behavior for one admitted write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockCachePolicy {
    /// Effective byte capacity, bounded by the device contract.
    pub capacity_bytes: u64,
    /// Deterministic victim selection.
    pub eviction: BlockFaultCacheEviction,
    /// Dirty victim treatment.
    pub dirty_eviction: BlockFaultDirtyEviction,
    /// Whether entries admitted by this policy survive ordinary power loss.
    pub power_loss_protected: bool,
}

/// Event that resolves a retained completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockRetainedRelease {
    /// Modeled recovery occurred before timeout.
    Recovery {
        /// Exact virtual coordinate of the recovery event.
        event_ticks: u64,
        /// Event evaluation sequence within `event_ticks`.
        event_sequence: u64,
    },
    /// The modeled timeout coordinate was reached first.
    Timeout,
}

/// Result of applying one eligible retained-completion release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockRetainedReleaseOutcome {
    /// Recovery started required persistence and the completion remains retained.
    PendingPersistence,
    /// The selected response was reserved for delivery.
    Released,
}

/// One fully resolved guest-transport treatment of an additional completion.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ResolvedBlockDuplicateCompletion {
    /// Sends the original response; the guest ignores it after the first.
    Ignore {
        /// Cumulative delay from the primary completion, in nanoseconds.
        gap_nanos: u64,
    },
    /// Sends an explicit protocol-error completion for the original request.
    ProtocolError {
        /// Cumulative delay from the primary completion, in nanoseconds.
        gap_nanos: u64,
        /// Fully encoded block-layer error result.
        response: BlockResponse,
    },
    /// Sends the original response and requires the guest transport to reset.
    Reset {
        /// Cumulative delay from the primary completion, in nanoseconds.
        gap_nanos: u64,
        /// Complete controller transition executed by this first duplicate.
        transition: ResolvedBlockControllerTransition,
    },
}

/// Guest transport policy expanded into one or more duplicate completions.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockDuplicatePolicy {
    /// The guest transport ignores every completion after the primary.
    Ignore,
    /// Every duplicate carries this matching typed protocol error.
    ProtocolError(BlockResponse),
    /// The first duplicate executes this complete live controller transition.
    Reset(ResolvedBlockControllerTransition),
}

/// Treatment of requests arriving while a controller transition is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransitionUnadmitted {
    /// Rejects the request with the transition's typed failure.
    Reject,
    /// Holds admission until the exact recovery boundary.
    WaitForRecovery,
}

/// Treatment of queued or executing requests at the transition boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransitionPending {
    /// Completes the request with the transition's typed failure.
    Fail,
    /// Reissues the request with its existing identity.
    RetryPreserveId,
    /// Reissues the request with a newly allocated post-transition identity.
    RetryNewId,
}

/// Treatment of resolved requests at the transition boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransitionResolved {
    /// Preserves the resolved result.
    Complete,
    /// Replaces the result with the transition's typed failure.
    Fail,
    /// Reissues the request with its existing identity.
    RetryPreserveId,
    /// Reissues the request with a newly allocated post-transition identity.
    RetryNewId,
}

/// Treatment of completed but guest-undelivered requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransitionUndelivered {
    /// Preserves and later delivers the completion.
    Complete,
    /// Replaces the completion with the transition's typed failure.
    Fail,
    /// Reissues the request with its existing identity.
    RetryPreserveId,
    /// Reissues the request with a newly allocated post-transition identity.
    RetryNewId,
    /// Discards the completion.
    DropCompletion,
}

/// Retention of volatile device state across a controller transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransitionState {
    /// Preserves the complete state.
    Preserve,
    /// Loses the complete state.
    Lose,
}

/// Namespace and path discovery behavior after recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransitionTopology {
    /// Preserves the current topology generation.
    Preserve,
    /// Re-enumerates the declared namespaces and paths.
    ReenumerateDeclared,
}

/// Fully resolved live block-controller reset policy.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockControllerTransition {
    /// Typed result used by every stage configured to fail.
    pub failure_result: BlockFaultResult,
    /// Treatment of requests arriving during recovery.
    pub unadmitted: BlockTransitionUnadmitted,
    /// Treatment of admitted queued requests.
    pub queued: BlockTransitionPending,
    /// Treatment of executing requests.
    pub executing: BlockTransitionPending,
    /// Treatment of resolved requests.
    pub resolved: BlockTransitionResolved,
    /// Treatment of completed but guest-undelivered requests.
    pub completed_undelivered: BlockTransitionUndelivered,
    /// Controller write-buffer retention.
    pub controller_buffer: BlockTransitionState,
    /// Volatile write-cache retention.
    pub volatile_cache: BlockTransitionState,
    /// Post-reset request-ID allocation.
    pub request_ids: BlockTransportRequestIds,
    /// Duplicate-suppression history retention.
    pub duplicate_history: BlockTransitionState,
    /// Post-reset namespace/path behavior.
    pub topology: BlockTransitionTopology,
    /// Exact recovery duration in virtual nanoseconds.
    pub recovery_nanos: u64,
}

impl ResolvedBlockControllerTransition {
    /// Converts this policy into the exact guest transport reset for `current_epoch`.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when advancing to a
    /// new transport epoch would overflow `u64`.
    pub fn transport_reset(&self, current_epoch: u64) -> Result<BlockTransportReset, DeviceError> {
        let next_epoch = match self.request_ids {
            BlockTransportRequestIds::PreserveMonotonic => current_epoch,
            BlockTransportRequestIds::NewEpochFromZero => {
                current_epoch
                    .checked_add(1)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "block transport epoch overflow",
                    })?
            }
        };
        Ok(BlockTransportReset {
            next_epoch,
            recovery_nanos: self.recovery_nanos,
            request_ids: self.request_ids,
            reenumerate_declared: matches!(
                self.topology,
                BlockTransitionTopology::ReenumerateDeclared
            ),
            preserve_duplicate_history: matches!(
                self.duplicate_history,
                BlockTransitionState::Preserve
            ),
            failure_result: self.failure_result,
            unadmitted: match self.unadmitted {
                BlockTransitionUnadmitted::Reject => BlockTransportUnadmitted::Reject,
                BlockTransitionUnadmitted::WaitForRecovery => {
                    BlockTransportUnadmitted::WaitForRecovery
                }
            },
            queued: transport_pending(self.queued),
            executing: transport_pending(self.executing),
            resolved: match self.resolved {
                BlockTransitionResolved::Complete => BlockTransportResolved::Complete,
                BlockTransitionResolved::Fail => BlockTransportResolved::Fail,
                BlockTransitionResolved::RetryPreserveId => BlockTransportResolved::RetryPreserveId,
                BlockTransitionResolved::RetryNewId => BlockTransportResolved::RetryNewId,
            },
            completed_undelivered: match self.completed_undelivered {
                BlockTransitionUndelivered::Complete => BlockTransportUndelivered::Complete,
                BlockTransitionUndelivered::Fail => BlockTransportUndelivered::Fail,
                BlockTransitionUndelivered::RetryPreserveId => {
                    BlockTransportUndelivered::RetryPreserveId
                }
                BlockTransitionUndelivered::RetryNewId => BlockTransportUndelivered::RetryNewId,
                BlockTransitionUndelivered::DropCompletion => {
                    BlockTransportUndelivered::DropCompletion
                }
            },
            preserve_controller_buffer: matches!(
                self.controller_buffer,
                BlockTransitionState::Preserve
            ),
            preserve_volatile_cache: matches!(self.volatile_cache, BlockTransitionState::Preserve),
        })
    }
}

impl ResolvedBlockDuplicateCompletion {
    const fn gap_nanos(&self) -> u64 {
        match self {
            Self::Ignore { gap_nanos }
            | Self::ProtocolError { gap_nanos, .. }
            | Self::Reset { gap_nanos, .. } => *gap_nanos,
        }
    }
}

/// One fully resolved directive consumed by exactly one block request.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockFaultDirective {
    /// Transport generation containing the exact request.
    pub request_epoch: u64,
    /// Adapter-owned monotone opportunity sequence for queue identity.
    pub request_sequence: u64,
    /// Expected wire operation; prevents directive/request aliasing.
    pub operation: BlockOp,
    /// Expected range start.
    pub offset: u64,
    /// Expected range length.
    pub count: u32,
    /// Expected BLAKE3 digest of the complete encoded request.
    pub request_digest: [u8; 32],
    /// Effective controller availability.
    pub availability: BlockFaultAvailability,
    /// Effective guest-visible capacity.
    pub reported_capacity_bytes: u64,
    /// Terminal result forced before data or durability mutation.
    pub error_result: Option<BlockFaultResult>,
    /// Dynamic service, latency, stall, and reorder delay.
    pub additional_latency_nanos: u64,
    /// Canonically device-ordered external durable frontiers that must all be
    /// acknowledged before this request's completion may be delivered.
    pub external_durability_dependencies: Vec<BlockExternalDurabilityDependency>,
    /// Canonically contributor-ordered service rules sampled at admission.
    pub service_rules: Vec<ResolvedBlockServiceRule>,
    /// Exact virtual coordinate at which this request resolves in the adapter.
    pub execution_ticks: u64,
    /// Whether the primary completion remains retained after COMPUTE.
    pub retain_completion: bool,
    /// Typed error returned if a retained operation times out.
    pub retention_timeout_response: Option<BlockResponse>,
    /// Exact simulation-tick deadline for the retained completion.
    pub retention_timeout_ticks: Option<u64>,
    /// Optional content identity of the signal event that releases recovery.
    pub retention_recovery_event: Option<[u8; 32]>,
    /// Boundary after which the subscribed recovery event may release completion.
    pub retention_recovery_after_ticks: Option<u64>,
    /// Evaluation sequence after which a same-coordinate recovery may release.
    pub retention_recovery_after_sequence: Option<u64>,
    /// Canonically gap-ordered duplicate transport outcomes.
    pub duplicate_completions: Vec<ResolvedBlockDuplicateCompletion>,
    /// Ordered read transformations.
    pub read_transforms: Vec<BlockFaultReadTransform>,
    /// Stateful physical-media overlays evaluated at the real media opportunity.
    pub media_rules: Vec<ResolvedBlockMediaRule>,
    /// Write persistence disposition.
    pub write_disposition: BlockFaultWriteDisposition,
    /// Flush disposition.
    pub flush_disposition: BlockFaultFlushDisposition,
    /// Exact volatile-cache behavior, when the write enters that layer.
    pub cache_policy: Option<ResolvedBlockCachePolicy>,
    /// Persistence-DAG transformations resolved for this write.
    pub persistence_transforms: Vec<ResolvedBlockPersistenceTransform>,
    /// Physical flash rules active at this read or frozen for write persistence.
    pub persistence_media_rules: Vec<ResolvedBlockFlashRule>,
    /// Exact virtual coordinate at which persistence admission occurs.
    pub persistence_admitted_ticks: u64,
}

/// Stable identity of one write fragment ready to enter physical media.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockPersistenceOpportunity {
    /// Global durability sequence.
    pub sequence: u64,
    /// Original guest request identity.
    pub request_id: u32,
    /// First durability sequence assigned to the complete logical operation.
    pub operation_sequence: u64,
    /// Physical operation performed by this fragment.
    pub operation: BlockOp,
    /// Digest of the original guest wire request.
    pub request_digest: [u8; 32],
    /// Absolute destination byte offset.
    pub offset: u64,
    /// Exact fragment byte count.
    pub count: u32,
    /// BLAKE3 digest of the exact intended fragment bytes.
    pub intended_digest: [u8; 32],
    /// Earliest virtual coordinate at which persistence may execute.
    pub ready_ticks: u64,
}

/// Exact physical-media policy resolved for one persistence opportunity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockPersistenceMediaDirective {
    /// Opportunity identity authenticated before mutation.
    pub opportunity: BlockPersistenceOpportunity,
    /// Canonically contributor-ordered flash rules active at this opportunity.
    pub flash_rules: Vec<ResolvedBlockFlashRule>,
}

/// Replay evidence for one completed physical-media persistence opportunity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockPersistenceMediaOutcome {
    /// Opportunity identity that was consumed.
    pub opportunity: BlockPersistenceOpportunity,
    /// Exact virtual coordinate at which the physical mutation executed.
    pub executed_ticks: u64,
    /// Exact program or erase spans applied to durable media.
    pub applied_spans: Vec<BlockFaultByteSpan>,
    /// Whether a flash program or erase rule reported failure after partial application.
    pub media_failed: bool,
    /// Digest of the bytes actually programmed or erased, including an empty application.
    pub applied_digest: [u8; 32],
}

/// One storage completion in the device's exact causal generation order.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockStorageOutcome {
    /// One contributor completed integrated service before subsequent effects.
    Service(BlockServiceCompletion),
    /// One physical-media persistence mutation completed.
    Persistence(BlockPersistenceMediaOutcome),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum BlockStorageOutcomeRef {
    Service(usize),
    Persistence(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BlockServicePendingRequest {
    request: BlockRequest,
    request_icount: u64,
    directive: ResolvedBlockFaultDirective,
    remaining_contributors: BTreeSet<[u8; 32]>,
    finished_ticks: u64,
}

/// Exact request-stage opportunity exposed after integrated queue service.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockExecutionOpportunity {
    /// Adapter-owned request sequence shared by every request phase.
    pub request_sequence: u64,
    /// Original request retained byte-for-byte through queue service.
    pub request: BlockRequest,
    /// Original requester coordinate.
    pub request_icount: u64,
    /// Digest of the complete immutable request wire payload.
    pub wire_digest: [u8; 32],
    /// Exact virtual coordinate at which resolve/persist effects are sampled.
    pub ready_ticks: u64,
    /// Admission and queue-phase decision retained through integrated service.
    ///
    /// The production resolver extends this exact directive at resolve/persist
    /// time, so no process-local side table is required for checkpoint/restore.
    pub admission: ResolvedBlockFaultDirective,
}

/// Exact resolve/persist decision authenticated to one live request opportunity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockExecutionDirective {
    /// Complete opportunity identity observed before signal evaluation.
    pub opportunity: BlockExecutionOpportunity,
    /// Resolved request mutation for that exact coordinate.
    pub directive: ResolvedBlockFaultDirective,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BlockExecutionPendingRequest {
    opportunity: BlockExecutionOpportunity,
    execution: Option<ResolvedBlockFaultDirective>,
}

/// Exact mutation-frontier opportunity for one resolved storage request.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockRequestPersistenceOpportunity {
    /// Adapter-owned request sequence shared by every request phase.
    pub request_sequence: u64,
    /// Original request retained byte-for-byte until mutation authorization.
    pub request: BlockRequest,
    /// Original requester coordinate.
    pub request_icount: u64,
    /// Exact virtual coordinate at which persist effects are sampled.
    pub ready_ticks: u64,
    /// Digest of the complete immutable request wire payload.
    pub wire_digest: [u8; 32],
    /// Complete admit/queue/resolve decision awaiting persist contributions.
    pub resolved: ResolvedBlockFaultDirective,
}

/// Exact persist decision authenticated to one live mutation opportunity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockRequestPersistenceDirective {
    /// Complete opportunity identity observed before signal evaluation.
    pub opportunity: BlockRequestPersistenceOpportunity,
    /// Fully composed request directive for that exact mutation coordinate.
    pub directive: ResolvedBlockFaultDirective,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BlockRequestPersistencePending {
    opportunity: BlockRequestPersistenceOpportunity,
    persistence: Option<ResolvedBlockFaultDirective>,
}

/// Exact guest-completion opportunity exposed only after request mutation and
/// every mandatory durability frontier have completed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockDeliveryOpportunity {
    /// Adapter-owned request sequence shared by every request phase.
    pub request_sequence: u64,
    /// Original request retained byte-for-byte through mutation.
    pub request: BlockRequest,
    /// Original requester coordinate.
    pub request_icount: u64,
    /// Earliest virtual coordinate at which the completion may be published.
    pub ready_ticks: u64,
    /// Digest of the complete immutable request wire payload.
    pub wire_digest: [u8; 32],
    /// Exact response produced by the storage mutation.
    pub response: BlockResponse,
    /// Complete admit/queue/resolve/persist decision awaiting delivery effects.
    pub resolved: ResolvedBlockFaultDirective,
    /// Exclusive durability frontier required before successful publication.
    pub required_durable_frontier: Option<u64>,
}

/// Exact delivery decision authenticated to one computed completion.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockDeliveryDirective {
    /// Complete opportunity identity observed before signal evaluation.
    pub opportunity: BlockDeliveryOpportunity,
    /// Fully composed directive for that exact completion.
    pub directive: ResolvedBlockFaultDirective,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BlockDeliveryPending {
    opportunity: BlockDeliveryOpportunity,
    delivery: Option<ResolvedBlockFaultDirective>,
}

/// One request released by integrated storage service and ready for scheduling.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct BlockDeferredResponse {
    /// Exact coordinate at which all service contributors released the request.
    pub finished_ticks: u64,
    /// Original request, retained byte-for-byte while queued.
    pub request: BlockRequest,
    /// Original requester coordinate retained for overflow diagnostics.
    pub request_icount: u64,
    /// Fully computed response after real device mutation at the release boundary.
    pub computed: ComputedResponse,
}

/// One admitted volatile write fragment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockVolatileEntry {
    /// Monotone cache admission sequence.
    pub sequence: u64,
    /// Original request ID.
    pub request_id: u32,
    /// Immutable physical-media identity shared by every request fragment.
    pub media_identity: BlockMediaOperationIdentity,
    /// Destination range start.
    pub offset: u64,
    /// Exact admitted bytes.
    pub bytes: Vec<u8>,
    /// Modeled access-order sequence used only by LRU selection.
    pub last_access_sequence: u64,
    /// Whether ordinary power-loss selection must preserve this entry.
    pub power_loss_protected: bool,
}

/// One write accepted by the controller but not yet admitted to media cache.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockControllerEntry {
    /// Monotone write sequence shared with cache and durable frontiers.
    pub sequence: u64,
    /// Original request ID.
    pub request_id: u32,
    /// Immutable physical-media identity shared by every request fragment.
    pub media_identity: BlockMediaOperationIdentity,
    /// Destination range start.
    pub offset: u64,
    /// Exact accepted bytes.
    pub bytes: Vec<u8>,
}

/// Immutable identity of one logical operation entering physical media.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockMediaOperationIdentity {
    /// Write or discard operation interpreted at persistence.
    pub operation: BlockOp,
    /// First durability sequence assigned to the complete logical operation.
    pub operation_sequence: u64,
    /// Digest of the original guest wire request.
    pub request_digest: [u8; 32],
    /// Original complete request range start.
    pub request_offset: u64,
    /// Original complete request byte count.
    pub request_count: u32,
}

/// One retained prior range version.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockRetainedVersion {
    /// Monotone version identity.
    pub sequence: u64,
    /// Range start.
    pub offset: u64,
    /// Prior exact bytes.
    pub bytes: Vec<u8>,
}

/// One protocol-valid completion retained by a stall until recovery or timeout.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockRetainedCompletion {
    /// Original epoch-scoped request identity.
    pub identity: BlockRequestIdentity,
    /// Complete uniform wire response released on recovery.
    pub recovery_response: Response,
    /// Complete uniform wire response released on timeout.
    pub timeout_response: Response,
    /// Original request coordinate retained for replay evidence.
    pub request_icount: u64,
    /// Dynamic delay in exact ticks selected before completion was retained.
    pub additional_latency_ticks: u64,
    /// Exact simulation-tick deadline that releases the timeout response.
    pub timeout_ticks: u64,
    /// Optional content identity of the signal event that releases recovery.
    pub recovery_event: Option<[u8; 32]>,
    /// Boundary after which the subscribed recovery event may release completion.
    pub recovery_after_ticks: Option<u64>,
    /// Evaluation sequence after which a same-coordinate recovery may release.
    pub recovery_after_sequence: Option<u64>,
    /// Exclusive captured write frontier persisted before recovered flush success.
    pub persist_through_on_recovery: Option<u64>,
}

/// Checkpointed durability, cache, version, and directive state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockFaultState {
    observation_revision: std::num::NonZeroU64,
    // Runtime nesting is never persisted as an observation or Source proof.
    #[serde(skip)]
    observation_mutation_active: bool,
    #[serde(skip)]
    observation_external_effect: bool,
    #[serde(skip)]
    observation_changed: bool,
    config: BlockDurabilityConfig,
    transport_epoch: Option<u64>,
    retired_transport_epochs: BTreeMap<u64, BlockRetiredTransportEpoch>,
    retry_preserve_authorizations: BTreeSet<BlockRequestIdentity>,
    recovery_until_ticks: Option<u64>,
    execution_required: bool,
    pending: BTreeMap<BlockRequestIdentity, ResolvedBlockFaultDirective>,
    pending_bytes: u64,
    service: BlockServiceState,
    service_pending: BTreeMap<u64, BlockServicePendingRequest>,
    service_pending_bytes: u64,
    service_outcomes: Vec<BlockServiceCompletion>,
    storage_outcome_order: Vec<BlockStorageOutcomeRef>,
    execution_opportunities_required: bool,
    execution_pending: BTreeMap<u64, BlockExecutionPendingRequest>,
    execution_pending_bytes: u64,
    request_persistence_pending: BTreeMap<u64, BlockRequestPersistencePending>,
    request_persistence_pending_bytes: u64,
    delivery_pending: BTreeMap<u64, BlockDeliveryPending>,
    delivery_pending_bytes: u64,
    controller: BTreeMap<u64, BlockControllerEntry>,
    controller_bytes: u64,
    media_queue: BTreeMap<u64, BlockControllerEntry>,
    media_queue_bytes: u64,
    volatile: BTreeMap<u64, BlockVolatileEntry>,
    volatile_bytes: u64,
    retained: BTreeMap<u64, BlockRetainedVersion>,
    media: BlockMediaState,
    flash: BlockFlashState,
    persistence_execution_required: bool,
    pending_persistence_media: BTreeMap<u64, ResolvedBlockPersistenceMediaDirective>,
    persistence_media_outcomes: Vec<BlockPersistenceMediaOutcome>,
    persistence: BlockPersistenceGraph,
    pending_barrier_frontier: Option<u64>,
    pending_honest_flush_frontier: Option<u64>,
    next_cache_sequence: u64,
    next_cache_access_sequence: u64,
    next_version_sequence: u64,
    first_lost_sequence: Option<u64>,
    actual_durable_frontier: u64,
    reported_durable_frontier: u64,
    retained_completions: BTreeMap<BlockRequestIdentity, BlockRetainedCompletion>,
    array_dirty_ranges: BTreeMap<(u16, u64), BlockArrayDirtyRange>,
    array_rebuild: BlockArrayRebuildCursor,
}

#[cfg(test)]
#[path = "fault/codec_tests.rs"]
mod codec_tests;

#[cfg(test)]
#[path = "fault_tests.rs"]
mod tests;
