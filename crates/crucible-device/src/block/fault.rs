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

mod state_admission;
mod state_execution;

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

/// Reset policy retained for requests already published under an older epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockRetiredTransportEpoch {
    queued: BlockTransportPending,
    failure_result: BlockErrorCode,
}

/// Availability presented by the block controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockCompletionDurability {
    /// The write may complete after controller acceptance.
    ControllerAccepted,
    /// The write may complete after admission to volatile cache.
    VolatileCacheAccepted,
    /// The write completes only after durable persistence.
    Durable,
}

/// Guest-visible readback after a successful discard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockDiscardSemantics {
    /// Discarded bytes deterministically read as zero.
    DeterministicZero,
    /// Discard leaves the prior logical bytes visible.
    ReadsOldData,
    /// Discard installs deterministic device/request-keyed bytes for replay.
    UndefinedKeyed,
}

/// Immutable durability bounds for one block device.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl BlockDurabilityConfig {
    /// Builds the fault-free write-through contract for a device.
    #[must_use]
    pub fn write_through(length_bytes: u64) -> Self {
        Self {
            length_bytes,
            atomic_write_bytes: 1,
            maximum_request_bytes: length_bytes.max(1),
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 0,
            cache_entries: 0,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: super::persistence::HARD_BLOCK_PERSISTENCE_EDGES as u32,
            retained_versions: 1,
            completion_durability: BlockCompletionDurability::Durable,
        }
    }

    /// Validates geometry and hard resource bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when a bound is zero,
    /// inconsistent with device length, or exceeds a compiled hard ceiling.
    pub fn validate(&self) -> Result<(), DeviceError> {
        let cache_entries = usize::try_from(self.cache_entries).unwrap_or(usize::MAX);
        let controller_entries = usize::try_from(self.controller_entries).unwrap_or(usize::MAX);
        let retained_versions = usize::try_from(self.retained_versions).unwrap_or(usize::MAX);
        let persistence_dependencies =
            usize::try_from(self.persistence_dependencies).unwrap_or(usize::MAX);
        if self.atomic_write_bytes == 0
            || self.maximum_request_bytes == 0
            || (self.length_bytes > 0 && self.maximum_request_bytes > self.length_bytes)
            || (self.discard_granularity_bytes != 0
                && !self.discard_granularity_bytes.is_power_of_two())
            || cache_entries > HARD_BLOCK_CACHE_ENTRIES
            || controller_entries > HARD_BLOCK_CONTROLLER_ENTRIES
            || persistence_dependencies > super::persistence::HARD_BLOCK_PERSISTENCE_EDGES
            || persistence_dependencies == 0
            || self.volatile_cache_bytes > HARD_BLOCK_VOLATILE_LAYER_BYTES
            || self.controller_buffer_bytes > HARD_BLOCK_VOLATILE_LAYER_BYTES
            || retained_versions == 0
            || retained_versions > HARD_BLOCK_RETAINED_VERSIONS
            || (self.volatile_cache_bytes == 0) != (self.cache_entries == 0)
            || (self.controller_buffer_bytes == 0) != (self.controller_entries == 0)
            || (self.completion_durability == BlockCompletionDurability::VolatileCacheAccepted
                && self.volatile_cache_bytes == 0)
            || (self.completion_durability == BlockCompletionDurability::ControllerAccepted
                && self.controller_buffer_bytes == 0)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "invalid block durability configuration",
            });
        }
        Ok(())
    }
}

/// One exact half-open request-relative byte span.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockFaultMisdirectionDestination {
    /// Redirects within the attached source device.
    AttachedDevice,
    /// Redirects to another authoritative device identified by target hash.
    ExternalDevice([u8; 32]),
}

/// Exact cross-device durability acknowledgement required before source delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockExternalDurabilityDependency {
    /// Content identity of the authoritative destination block device.
    pub destination_device: [u8; 32],
    /// Destination's configured acknowledgement stage for the redirected write.
    pub required_durability: BlockCompletionDurability,
    /// Destination cache sequence that must be included in that stage's frontier.
    pub required_frontier: u64,
}

/// Exact flush result and internal durability treatment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockFaultCacheEviction {
    /// Selects the lowest admission sequence.
    Fifo,
    /// Selects the least recently accessed entry, then admission sequence.
    Lru,
    /// Selects the lowest pending writeback sequence.
    WritebackSequence,
}

/// Treatment of a dirty entry selected for cache eviction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRetainedRelease {
    /// Modeled recovery occurred before timeout.
    Recovery {
        /// Exact virtual coordinate of the recovery event.
        event_nanos: u64,
        /// Event evaluation sequence within `event_nanos`.
        event_sequence: u64,
    },
    /// The modeled timeout coordinate was reached first.
    Timeout,
}

/// Result of applying one eligible retained-completion release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRetainedReleaseOutcome {
    /// Recovery started required persistence and the completion remains retained.
    PendingPersistence,
    /// The selected response was reserved for delivery.
    Released,
}

/// One fully resolved guest-transport treatment of an additional completion.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockDuplicatePolicy {
    /// The guest transport ignores every completion after the primary.
    Ignore,
    /// Every duplicate carries this matching typed protocol error.
    ProtocolError(BlockResponse),
    /// The first duplicate executes this complete live controller transition.
    Reset(ResolvedBlockControllerTransition),
}

/// Treatment of requests arriving while a controller transition is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransitionUnadmitted {
    /// Rejects the request with the transition's typed failure.
    Reject,
    /// Holds admission until the exact recovery boundary.
    WaitForRecovery,
}

/// Treatment of queued or executing requests at the transition boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransitionPending {
    /// Completes the request with the transition's typed failure.
    Fail,
    /// Reissues the request with its existing identity.
    RetryPreserveId,
    /// Reissues the request with a newly allocated post-transition identity.
    RetryNewId,
}

/// Treatment of resolved requests at the transition boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransitionState {
    /// Preserves the complete state.
    Preserve,
    /// Loses the complete state.
    Lose,
}

/// Namespace and path discovery behavior after recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransitionTopology {
    /// Preserves the current topology generation.
    Preserve,
    /// Re-enumerates the declared namespaces and paths.
    ReenumerateDeclared,
}

/// Fully resolved live block-controller reset policy.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Durable frontier on an externally redirected destination that must be
    /// acknowledged before this request's completion may be delivered.
    pub external_durability_dependency: Option<BlockExternalDurabilityDependency>,
    /// Canonically contributor-ordered service rules sampled at admission.
    pub service_rules: Vec<ResolvedBlockServiceRule>,
    /// Exact virtual coordinate at which this request resolves in the adapter.
    pub execution_nanos: u64,
    /// Whether the primary completion remains retained after COMPUTE.
    pub retain_completion: bool,
    /// Typed error returned if a retained operation times out.
    pub retention_timeout_response: Option<BlockResponse>,
    /// Exact virtual-nanosecond deadline for the retained completion.
    pub retention_timeout_nanos: Option<u64>,
    /// Optional content identity of the signal event that releases recovery.
    pub retention_recovery_event: Option<[u8; 32]>,
    /// Boundary after which the subscribed recovery event may release completion.
    pub retention_recovery_after_nanos: Option<u64>,
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
    pub persistence_admitted_nanos: u64,
}

/// Stable identity of one write fragment ready to enter physical media.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub ready_nanos: u64,
}

/// Exact physical-media policy resolved for one persistence opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBlockPersistenceMediaDirective {
    /// Opportunity identity authenticated before mutation.
    pub opportunity: BlockPersistenceOpportunity,
    /// Canonically contributor-ordered flash rules active at this opportunity.
    pub flash_rules: Vec<ResolvedBlockFlashRule>,
}

/// Replay evidence for one completed physical-media persistence opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPersistenceMediaOutcome {
    /// Opportunity identity that was consumed.
    pub opportunity: BlockPersistenceOpportunity,
    /// Exact virtual coordinate at which the physical mutation executed.
    pub executed_nanos: u64,
    /// Exact program or erase spans applied to durable media.
    pub applied_spans: Vec<BlockFaultByteSpan>,
    /// Whether a flash program or erase rule reported failure after partial application.
    pub media_failed: bool,
    /// Digest of the bytes actually programmed or erased, including an empty application.
    pub applied_digest: [u8; 32],
}

/// One storage completion in the device's exact causal generation order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockStorageOutcome {
    /// One contributor completed integrated service before subsequent effects.
    Service(BlockServiceCompletion),
    /// One physical-media persistence mutation completed.
    Persistence(BlockPersistenceMediaOutcome),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockStorageOutcomeRef {
    Service(usize),
    Persistence(usize),
}

impl ResolvedBlockFaultDirective {
    /// Builds the exact fault-free directive for `request`.
    #[must_use]
    pub fn fault_free(request: &BlockRequest, capacity: u64) -> Self {
        Self {
            request_epoch: request.epoch,
            request_sequence: u64::from(request.request_id),
            operation: request.op,
            offset: request.offset,
            count: request.count,
            request_digest: request_digest(request),
            availability: BlockFaultAvailability::Online,
            reported_capacity_bytes: capacity,
            error_result: None,
            additional_latency_nanos: 0,
            external_durability_dependency: None,
            service_rules: Vec::new(),
            execution_nanos: 0,
            retain_completion: false,
            retention_timeout_response: None,
            retention_timeout_nanos: None,
            retention_recovery_event: None,
            retention_recovery_after_nanos: None,
            retention_recovery_after_sequence: None,
            duplicate_completions: Vec::new(),
            read_transforms: Vec::new(),
            media_rules: Vec::new(),
            write_disposition: BlockFaultWriteDisposition::Apply,
            flush_disposition: BlockFaultFlushDisposition::Honest,
            cache_policy: None,
            persistence_transforms: Vec::new(),
            persistence_media_rules: Vec::new(),
            persistence_admitted_nanos: 0,
        }
    }

    /// Expands an authored adjacent-completion gap into canonical primary-relative delays.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the copy count exceeds the hard bound, the
    /// gap is zero, multiplication overflows, or a protocol-error response does
    /// not match this directive's request identity and error status.
    pub fn configure_duplicate_completions(
        &mut self,
        request_id: u32,
        copies: u32,
        adjacent_gap_nanos: u64,
        policy: BlockDuplicatePolicy,
    ) -> Result<(), DeviceError> {
        let mut resolved = self.clone();
        resolved.duplicate_completions.clear();
        resolved.append_duplicate_completions(request_id, copies, adjacent_gap_nanos, policy)?;
        self.duplicate_completions = resolved.duplicate_completions;
        Ok(())
    }

    /// Appends duplicate outcomes after the current last primary-relative delay.
    ///
    /// The mutation is transactional: validation and all checked delay
    /// arithmetic complete before this directive is changed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the combined copy count exceeds the hard
    /// bound, the adjacent gap is zero, delay arithmetic overflows, or a
    /// protocol-error response does not match this directive's request.
    pub fn append_duplicate_completions(
        &mut self,
        request_id: u32,
        copies: u32,
        adjacent_gap_nanos: u64,
        policy: BlockDuplicatePolicy,
    ) -> Result<(), DeviceError> {
        let copies =
            usize::try_from(copies).map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate copy count does not fit memory",
            })?;
        if copies == 0
            || self
                .duplicate_completions
                .len()
                .checked_add(copies)
                .is_none_or(|total| total > HARD_BLOCK_DUPLICATE_COMPLETIONS)
            || adjacent_gap_nanos == 0
            || matches!(
                &policy,
                BlockDuplicatePolicy::ProtocolError(response)
                    if response.request_id != request_id
                        || response.status != BlockStatus::Error
            )
            || matches!(&policy, BlockDuplicatePolicy::Reset(transition) if transition.recovery_nanos == 0)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate completion policy is invalid",
            });
        }
        let base_gap_nanos = self
            .duplicate_completions
            .last()
            .map_or(0, ResolvedBlockDuplicateCompletion::gap_nanos);
        let mut resolved = Vec::with_capacity(copies);
        for index in 0..copies {
            let multiplier = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate completion index overflow",
                })?;
            let gap_nanos = adjacent_gap_nanos
                .checked_mul(multiplier)
                .and_then(|gap| base_gap_nanos.checked_add(gap))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate completion delay overflow",
                })?;
            resolved.push(match &policy {
                BlockDuplicatePolicy::Ignore => {
                    ResolvedBlockDuplicateCompletion::Ignore { gap_nanos }
                }
                BlockDuplicatePolicy::ProtocolError(response) => {
                    ResolvedBlockDuplicateCompletion::ProtocolError {
                        gap_nanos,
                        response: response.clone(),
                    }
                }
                BlockDuplicatePolicy::Reset(transition) if index == 0 => {
                    ResolvedBlockDuplicateCompletion::Reset {
                        gap_nanos,
                        transition: transition.clone(),
                    }
                }
                BlockDuplicatePolicy::Reset(_) => {
                    ResolvedBlockDuplicateCompletion::Ignore { gap_nanos }
                }
            });
        }
        self.duplicate_completions.extend(resolved);
        Ok(())
    }

    fn validate_for(
        &self,
        request: &BlockRequest,
        config: &BlockDurabilityConfig,
    ) -> Result<(), DeviceError> {
        let device_length = config.length_bytes;
        self.validate_static(request.request_id, config)?;
        if self.request_epoch != request.epoch
            || self.operation != request.op
            || self.offset != request.offset
            || self.count != request.count
            || self.request_digest != request_digest(request)
            || (self.reported_capacity_bytes == 0 && device_length != 0)
            || self.reported_capacity_bytes > device_length
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "directive does not match the block request",
            });
        }
        Ok(())
    }

    fn validate_static(
        &self,
        request_id: u32,
        config: &BlockDurabilityConfig,
    ) -> Result<(), DeviceError> {
        if (self.reported_capacity_bytes == 0 && config.length_bytes != 0)
            || self.reported_capacity_bytes > config.length_bytes
            || self.duplicate_completions.len() > HARD_BLOCK_DUPLICATE_COMPLETIONS
            || self.read_transforms.len() > HARD_BLOCK_WRITE_SPANS
            || self.media_rules.len() > HARD_BLOCK_WRITE_SPANS
            || self.persistence_transforms.len() > HARD_BLOCK_WRITE_SPANS
            || self.persistence_media_rules.len() > super::flash::HARD_BLOCK_FLASH_RULES
            || self.service_rules.len() > super::service::HARD_BLOCK_SERVICE_RULES
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "directive violates static block bounds",
            });
        }
        if self
            .service_rules
            .windows(2)
            .any(|pair| pair[0].contributor >= pair[1].contributor)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "storage service rules are not in canonical contributor order",
            });
        }
        for rule in &self.service_rules {
            rule.validate()?;
        }
        if self.retain_completion && !self.duplicate_completions.is_empty() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "a retained completion cannot also emit duplicates",
            });
        }
        if self.retain_completion
            != self
                .retention_timeout_response
                .as_ref()
                .is_some_and(|response| {
                    response.request_id == request_id && response.status == BlockStatus::Error
                })
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "retained completion lacks its matching typed timeout response",
            });
        }
        if self.retain_completion != self.retention_timeout_nanos.is_some()
            || self
                .retention_timeout_nanos
                .is_some_and(|deadline| deadline <= self.execution_nanos)
            || !self.retain_completion && self.retention_recovery_event.is_some()
            || self.retention_recovery_event.is_some()
                != self.retention_recovery_after_nanos.is_some()
            || self.retention_recovery_event.is_some()
                != self.retention_recovery_after_sequence.is_some()
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "retained completion lacks a future timeout or has a stray recovery event",
            });
        }
        if self
            .retention_timeout_response
            .as_ref()
            .is_some_and(|response| !block_response_fits_transport(response))
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "retained timeout response exceeds the block transport frame",
            });
        }
        if !self
            .duplicate_completions
            .windows(2)
            .all(|pair| pair[0].gap_nanos() < pair[1].gap_nanos())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate completion gaps are not in strict canonical order",
            });
        }
        for duplicate in &self.duplicate_completions {
            if let ResolvedBlockDuplicateCompletion::ProtocolError { response, .. } = duplicate
                && (response.request_id != request_id
                    || response.epoch != self.request_epoch
                    || response.status != BlockStatus::Error
                    || !block_response_fits_transport(response))
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate protocol error is invalid for the request transport",
                });
            }
        }
        if self.operation != BlockOp::Read && !self.read_transforms.is_empty() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "read transforms require a read request",
            });
        }
        if self.operation != BlockOp::Write
            && self.operation != BlockOp::Discard
            && self.write_disposition != BlockFaultWriteDisposition::Apply
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "write dispositions require a write request",
            });
        }
        if self.external_durability_dependency.is_some()
            && (self.operation != BlockOp::Write
                || self.write_disposition != BlockFaultWriteDisposition::Lost)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external durability dependency requires a committed external write",
            });
        }
        if self.operation == BlockOp::Discard
            && self.write_disposition != BlockFaultWriteDisposition::Apply
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "discard does not accept write-disposition transformations",
            });
        }
        if !matches!(self.operation, BlockOp::Write | BlockOp::Discard)
            && self.cache_policy.is_some()
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile-cache admission requires a write request",
            });
        }
        if (!matches!(self.operation, BlockOp::Write | BlockOp::Discard)
            && !self.persistence_transforms.is_empty())
            || (!matches!(
                self.operation,
                BlockOp::Read | BlockOp::Write | BlockOp::Discard
            ) && !self.persistence_media_rules.is_empty())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persistence transformations require a write request",
            });
        }
        if !self.persistence_transforms.is_empty() {
            if self.persistence_admitted_nanos != self.execution_nanos {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "persistence admission coordinate differs from request execution",
                });
            }
            BlockPersistenceGraph::validate_transforms(
                &self.persistence_transforms,
                self.persistence_admitted_nanos,
            )?;
        }
        if self
            .persistence_media_rules
            .windows(2)
            .any(|pair| pair[0].contributor >= pair[1].contributor)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persistence flash rules are not in canonical contributor order",
            });
        }
        for rule in &self.persistence_media_rules {
            rule.validate(config.length_bytes)?;
        }
        if self.cache_policy.is_some_and(|policy| {
            policy.capacity_bytes == 0
                || policy.capacity_bytes > config.volatile_cache_bytes
                || config.cache_entries == 0
        }) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile-cache policy exceeds the device contract",
            });
        }
        if self.operation != BlockOp::Flush
            && !matches!(self.flush_disposition, BlockFaultFlushDisposition::Honest)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "flush dispositions require a flush request",
            });
        }
        if matches!(self.flush_disposition, BlockFaultFlushDisposition::Stall)
            && !self.retain_completion
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "a stalled flush must retain its completion",
            });
        }
        validate_write_disposition(
            &self.write_disposition,
            self.offset,
            u64::from(self.count),
            u64::from(config.atomic_write_bytes),
            false,
        )?;
        for transform in &self.read_transforms {
            match transform {
                BlockFaultReadTransform::Xor { offset, mask } => {
                    if mask.is_empty()
                        || offset
                            .checked_add(u64::try_from(mask.len()).unwrap_or(u64::MAX))
                            .is_none_or(|end| end > u64::from(self.count))
                    {
                        return Err(DeviceError::InvalidBlockFaultDirective {
                            reason: "read XOR transform exceeds the declared response",
                        });
                    }
                }
                BlockFaultReadTransform::Replace { bytes }
                    if bytes.len() != usize::try_from(self.count).unwrap_or(usize::MAX) =>
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "replacement transform length differs from the declared response",
                    });
                }
                BlockFaultReadTransform::Replace { .. } => {}
            }
        }
        let mut media_contributors = BTreeSet::new();
        for rule in &self.media_rules {
            rule.validate(config.length_bytes)?;
            if !media_contributors.insert(rule.contributor) {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "media contributor is repeated in one directive",
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockServicePendingRequest {
    request: BlockRequest,
    request_icount: u64,
    directive: ResolvedBlockFaultDirective,
    remaining_contributors: BTreeSet<[u8; 32]>,
    finished_nanos: u64,
}

/// Exact request-stage opportunity exposed after integrated queue service.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub ready_nanos: u64,
    /// Admission and queue-phase decision retained through integrated service.
    ///
    /// The production resolver extends this exact directive at resolve/persist
    /// time, so no process-local side table is required for checkpoint/restore.
    pub admission: ResolvedBlockFaultDirective,
}

/// Exact resolve/persist decision authenticated to one live request opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBlockExecutionDirective {
    /// Complete opportunity identity observed before signal evaluation.
    pub opportunity: BlockExecutionOpportunity,
    /// Resolved request mutation for that exact coordinate.
    pub directive: ResolvedBlockFaultDirective,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockExecutionPendingRequest {
    opportunity: BlockExecutionOpportunity,
    execution: Option<ResolvedBlockFaultDirective>,
}

/// Exact mutation-frontier opportunity for one resolved storage request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequestPersistenceOpportunity {
    /// Adapter-owned request sequence shared by every request phase.
    pub request_sequence: u64,
    /// Original request retained byte-for-byte until mutation authorization.
    pub request: BlockRequest,
    /// Original requester coordinate.
    pub request_icount: u64,
    /// Exact virtual coordinate at which persist effects are sampled.
    pub ready_nanos: u64,
    /// Digest of the complete immutable request wire payload.
    pub wire_digest: [u8; 32],
    /// Complete admit/queue/resolve decision awaiting persist contributions.
    pub resolved: ResolvedBlockFaultDirective,
}

/// Exact persist decision authenticated to one live mutation opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBlockRequestPersistenceDirective {
    /// Complete opportunity identity observed before signal evaluation.
    pub opportunity: BlockRequestPersistenceOpportunity,
    /// Fully composed request directive for that exact mutation coordinate.
    pub directive: ResolvedBlockFaultDirective,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockRequestPersistencePending {
    opportunity: BlockRequestPersistenceOpportunity,
    persistence: Option<ResolvedBlockFaultDirective>,
}

/// Exact guest-completion opportunity exposed only after request mutation and
/// every mandatory durability frontier have completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDeliveryOpportunity {
    /// Adapter-owned request sequence shared by every request phase.
    pub request_sequence: u64,
    /// Original request retained byte-for-byte through mutation.
    pub request: BlockRequest,
    /// Original requester coordinate.
    pub request_icount: u64,
    /// Earliest virtual coordinate at which the completion may be published.
    pub ready_nanos: u64,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBlockDeliveryDirective {
    /// Complete opportunity identity observed before signal evaluation.
    pub opportunity: BlockDeliveryOpportunity,
    /// Fully composed directive for that exact completion.
    pub directive: ResolvedBlockFaultDirective,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockDeliveryPending {
    opportunity: BlockDeliveryOpportunity,
    delivery: Option<ResolvedBlockFaultDirective>,
}

/// One request released by integrated storage service and ready for scheduling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BlockDeferredResponse {
    /// Exact coordinate at which all service contributors released the request.
    pub finished_nanos: u64,
    /// Original request, retained byte-for-byte while queued.
    pub request: BlockRequest,
    /// Original requester coordinate retained for overflow diagnostics.
    pub request_icount: u64,
    /// Fully computed response after real device mutation at the release boundary.
    pub computed: ComputedResponse,
}

/// One admitted volatile write fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRetainedVersion {
    /// Monotone version identity.
    pub sequence: u64,
    /// Range start.
    pub offset: u64,
    /// Prior exact bytes.
    pub bytes: Vec<u8>,
}

/// One protocol-valid completion retained by a stall until recovery or timeout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRetainedCompletion {
    /// Original epoch-scoped request identity.
    pub identity: BlockRequestIdentity,
    /// Complete uniform wire response released on recovery.
    pub recovery_response: Response,
    /// Complete uniform wire response released on timeout.
    pub timeout_response: Response,
    /// Original request coordinate retained for replay evidence.
    pub request_icount: u64,
    /// Dynamic delay selected before the completion was retained.
    pub additional_latency_nanos: u64,
    /// Exact virtual-nanosecond deadline that releases the timeout response.
    pub timeout_nanos: u64,
    /// Optional content identity of the signal event that releases recovery.
    pub recovery_event: Option<[u8; 32]>,
    /// Boundary after which the subscribed recovery event may release completion.
    pub recovery_after_nanos: Option<u64>,
    /// Evaluation sequence after which a same-coordinate recovery may release.
    pub recovery_after_sequence: Option<u64>,
    /// Exclusive captured write frontier persisted before recovered flush success.
    pub persist_through_on_recovery: Option<u64>,
}

/// Checkpointed durability, cache, version, and directive state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFaultState {
    config: BlockDurabilityConfig,
    icount_shift: u8,
    transport_epoch: Option<u64>,
    retired_transport_epochs: BTreeMap<u64, BlockRetiredTransportEpoch>,
    retry_preserve_authorizations: BTreeSet<BlockRequestIdentity>,
    recovery_until_nanos: Option<u64>,
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
}

fn transport_pending_response(
    identity: BlockRequestIdentity,
    policy: BlockTransportPending,
    failure: BlockErrorCode,
) -> Result<Response, DeviceError> {
    let response = match policy {
        BlockTransportPending::Fail => BlockResponse::error_for(identity, failure),
        BlockTransportPending::RetryPreserveId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryPreserveId)
        }
        BlockTransportPending::RetryNewId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryNewId)
        }
    };
    block_response_to_uniform(&response)
}

fn transport_resolved_response(
    identity: BlockRequestIdentity,
    policy: BlockTransportResolved,
    failure: BlockErrorCode,
) -> Result<Response, DeviceError> {
    let response = match policy {
        BlockTransportResolved::Complete => {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "completed reset policy cannot replace a resolved request",
            });
        }
        BlockTransportResolved::Fail => BlockResponse::error_for(identity, failure),
        BlockTransportResolved::RetryPreserveId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryPreserveId)
        }
        BlockTransportResolved::RetryNewId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryNewId)
        }
    };
    block_response_to_uniform(&response)
}

fn transport_undelivered_response(
    identity: BlockRequestIdentity,
    policy: BlockTransportUndelivered,
    failure: BlockErrorCode,
) -> Result<Response, DeviceError> {
    let response = match policy {
        BlockTransportUndelivered::Complete => {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "completed reset policy cannot replace an undelivered request",
            });
        }
        BlockTransportUndelivered::Fail => BlockResponse::error_for(identity, failure),
        BlockTransportUndelivered::RetryPreserveId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryPreserveId)
        }
        BlockTransportUndelivered::RetryNewId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryNewId)
        }
        BlockTransportUndelivered::DropCompletion => {
            BlockResponse::reset_disposition(identity, BlockStatus::DropCompletion)
        }
    };
    block_response_to_uniform(&response)
}

const fn transport_pending(policy: BlockTransitionPending) -> BlockTransportPending {
    match policy {
        BlockTransitionPending::Fail => BlockTransportPending::Fail,
        BlockTransitionPending::RetryPreserveId => BlockTransportPending::RetryPreserveId,
        BlockTransitionPending::RetryNewId => BlockTransportPending::RetryNewId,
    }
}

fn request_in_capacity(request: &BlockRequest, capacity: u64) -> bool {
    match request.op {
        BlockOp::Read | BlockOp::Write | BlockOp::Discard => request
            .offset
            .checked_add(u64::from(request.count))
            .is_some_and(|end| end <= capacity),
        BlockOp::Flush | BlockOp::GetLength => true,
    }
}

fn block_admission_error(
    request: &BlockRequest,
    directive: &ResolvedBlockFaultDirective,
    config: &BlockDurabilityConfig,
) -> Option<BlockErrorCode> {
    (directive.availability == BlockFaultAvailability::Offline)
        .then_some(BlockErrorCode::Offline)
        .or_else(|| {
            (directive.availability == BlockFaultAvailability::ReadOnly
                && matches!(request.op, BlockOp::Write | BlockOp::Discard))
            .then_some(BlockErrorCode::ReadOnly)
        })
        .or_else(|| {
            (!request_in_capacity(request, directive.reported_capacity_bytes)
                || u64::from(request.count) > config.maximum_request_bytes
                || (request.op == BlockOp::Read
                    && usize::try_from(request.count).unwrap_or(usize::MAX)
                        > super::device::MAX_READ_BYTES))
                .then_some(BlockErrorCode::InvalidRange)
        })
}

fn validate_state_range(offset: u64, length: usize, device_length: u64) -> Result<(), DeviceError> {
    let length =
        u64::try_from(length).map_err(|_error| DeviceError::InvalidBlockFaultDirective {
            reason: "restored block state range length overflow",
        })?;
    if offset
        .checked_add(length)
        .is_some_and(|end| end <= device_length)
    {
        Ok(())
    } else {
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "restored block state range exceeds the device",
        })
    }
}

fn validate_media_entry(
    identity: BlockMediaOperationIdentity,
    fragment_sequence: u64,
    offset: u64,
    length: usize,
    device_length: u64,
) -> Result<(), DeviceError> {
    if !matches!(identity.operation, BlockOp::Write | BlockOp::Discard) {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "restored media entry has an invalid physical operation",
        });
    }
    let request_end = identity
        .request_offset
        .checked_add(u64::from(identity.request_count));
    let fragment_end = offset.checked_add(u64::try_from(length).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "restored media entry length overflow",
        }
    })?);
    if identity.request_count == 0
        || identity.operation_sequence > fragment_sequence
        || request_end.is_none_or(|end| end > device_length)
        || fragment_end
            .is_none_or(|end| offset < identity.request_offset || end > request_end.unwrap_or(0))
    {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "restored media entry differs from its original request",
        });
    }
    Ok(())
}

fn entry_contributes_visible(
    sequence: u64,
    overlap_start: u64,
    overlap_end: u64,
    visible: &BTreeMap<u64, (u64, Vec<u8>)>,
) -> bool {
    let mut uncovered = vec![(overlap_start, overlap_end)];
    for (_newer_sequence, (offset, bytes)) in visible.range((sequence + 1)..) {
        let newer_end = offset.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let mut next = Vec::new();
        for (start, end) in uncovered {
            if newer_end <= start || *offset >= end {
                next.push((start, end));
                continue;
            }
            if start < *offset {
                next.push((start, (*offset).min(end)));
            }
            if newer_end < end {
                next.push((newer_end.max(start), end));
            }
        }
        uncovered = next;
        if uncovered.is_empty() {
            return false;
        }
    }
    true
}

fn directive_owned_bytes(directive: &ResolvedBlockFaultDirective) -> Result<u64, DeviceError> {
    let mut total = 0_u64;
    for transform in &directive.read_transforms {
        let bytes = match transform {
            BlockFaultReadTransform::Xor { mask, .. } => mask.len(),
            BlockFaultReadTransform::Replace { bytes } => bytes.len(),
        };
        total = total
            .checked_add(u64::try_from(bytes).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "pending read transform length overflow",
                }
            })?)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "pending directive byte count overflow",
            })?;
    }
    for duplicate in &directive.duplicate_completions {
        if let ResolvedBlockDuplicateCompletion::ProtocolError { response, .. } = duplicate {
            total = total
                .checked_add(u64::try_from(response.data.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "pending duplicate response length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte count overflow",
                })?;
        }
    }
    for rule in &directive.media_rules {
        total = total
            .checked_add(
                u64::try_from(
                    rule.operations
                        .len()
                        .saturating_mul(std::mem::size_of::<BlockOp>()),
                )
                .map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                    reason: "pending media operation-set length overflow",
                })?,
            )
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "pending directive byte count overflow",
            })?;
    }
    for rule in &directive.service_rules {
        for class in &rule.classes {
            total = total
                .checked_add(u64::try_from(class.operations.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "pending service operation-set length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte count overflow",
                })?;
        }
    }
    total = total
        .checked_add(
            u64::try_from(
                directive
                    .persistence_media_rules
                    .len()
                    .saturating_mul(std::mem::size_of::<ResolvedBlockFlashRule>()),
            )
            .map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                reason: "pending flash rule byte count overflow",
            })?,
        )
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "pending directive byte count overflow",
        })?;
    if let Some(response) = &directive.retention_timeout_response {
        total = total
            .checked_add(u64::try_from(response.data.len()).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "pending timeout response length overflow",
                }
            })?)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "pending directive byte count overflow",
            })?;
    }
    Ok(total)
}

fn service_pending_owned_bytes(pending: &BlockServicePendingRequest) -> Result<u64, DeviceError> {
    u64::try_from(pending.request.data.len())
        .map_err(|_error| DeviceError::InvalidBlockFaultDirective {
            reason: "queued service request length overflow",
        })?
        .checked_add(directive_owned_bytes(&pending.directive)?)
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "queued service request byte count overflow",
        })
}

fn execution_pending_owned_bytes(
    pending: &BlockExecutionPendingRequest,
) -> Result<u64, DeviceError> {
    let request = u64::try_from(pending.opportunity.request.data.len()).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "execution-pending request length overflow",
        }
    })?;
    let admission = directive_owned_bytes(&pending.opportunity.admission)?;
    let execution = pending
        .execution
        .as_ref()
        .map(directive_owned_bytes)
        .transpose()?
        .unwrap_or(0);
    request
        .checked_add(admission)
        .and_then(|bytes| bytes.checked_add(execution))
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "execution-pending request byte count overflow",
        })
}

fn request_persistence_pending_owned_bytes(
    pending: &BlockRequestPersistencePending,
) -> Result<u64, DeviceError> {
    let request = u64::try_from(pending.opportunity.request.data.len()).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "request-persistence payload length overflow",
        }
    })?;
    let resolved = directive_owned_bytes(&pending.opportunity.resolved)?;
    let persistence = pending
        .persistence
        .as_ref()
        .map(directive_owned_bytes)
        .transpose()?
        .unwrap_or(0);
    request
        .checked_add(resolved)
        .and_then(|bytes| bytes.checked_add(persistence))
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "request-persistence byte count overflow",
        })
}

fn delivery_pending_owned_bytes(pending: &BlockDeliveryPending) -> Result<u64, DeviceError> {
    let request = u64::try_from(pending.opportunity.request.data.len()).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "delivery-pending request length overflow",
        }
    })?;
    let response = u64::try_from(pending.opportunity.response.data.len()).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "delivery-pending response length overflow",
        }
    })?;
    let resolved = directive_owned_bytes(&pending.opportunity.resolved)?;
    let delivery = pending
        .delivery
        .as_ref()
        .map(directive_owned_bytes)
        .transpose()?
        .unwrap_or(0);
    request
        .checked_add(response)
        .and_then(|bytes| bytes.checked_add(resolved))
        .and_then(|bytes| bytes.checked_add(delivery))
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "delivery-pending byte count overflow",
        })
}

fn block_response_fits_transport(response: &BlockResponse) -> bool {
    response
        .encode()
        .is_ok_and(|encoded| encoded.len() <= crucible_shmem::MAX_FRAME_DATA)
}

fn validate_write_disposition(
    disposition: &BlockFaultWriteDisposition,
    request_offset: u64,
    request_length: u64,
    atomic_write_bytes: u64,
    allow_subatomic: bool,
) -> Result<(), DeviceError> {
    if let BlockFaultWriteDisposition::Misdirected {
        destination_offset, ..
    } = disposition
        && !allow_subatomic
        && destination_offset % atomic_write_bytes != request_offset % atomic_write_bytes
    {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "misdirected write changes atomic-fragment alignment",
        });
    }
    let spans = match disposition {
        BlockFaultWriteDisposition::Torn { spans }
        | BlockFaultWriteDisposition::ProgramFailure { spans } => spans,
        BlockFaultWriteDisposition::Apply
        | BlockFaultWriteDisposition::Lost
        | BlockFaultWriteDisposition::Misdirected { .. } => return Ok(()),
    };
    if spans.len() > HARD_BLOCK_WRITE_SPANS || spans.is_empty() {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "invalid resolved write span count",
        });
    }
    let mut prior_end = 0;
    let boundaries =
        canonical_atomic_boundaries(request_offset, request_length, atomic_write_bytes)?;
    for span in spans {
        let Some(end) = span.end() else {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "resolved write span overflow",
            });
        };
        if span.length == 0 || span.start < prior_end || end > request_length {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "resolved write spans overlap or exceed request",
            });
        }
        if !allow_subatomic
            && (boundaries.binary_search(&span.start).is_err()
                || boundaries.binary_search(&end).is_err())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "resolved write span splits an atomic-write fragment",
            });
        }
        prior_end = end;
    }
    Ok(())
}

fn canonical_atomic_boundaries(
    request_offset: u64,
    request_length: u64,
    atomic_write_bytes: u64,
) -> Result<Vec<u64>, DeviceError> {
    if atomic_write_bytes == 0 {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "atomic-write size is zero",
        });
    }
    let mut boundaries = vec![0];
    let request_end = request_offset.checked_add(request_length).ok_or(
        DeviceError::InvalidBlockFaultDirective {
            reason: "request range overflow while splitting atomic writes",
        },
    )?;
    let mut absolute = request_offset;
    while absolute < request_end {
        let remainder = absolute % atomic_write_bytes;
        let step = if remainder == 0 {
            atomic_write_bytes
        } else {
            atomic_write_bytes - remainder
        };
        absolute = absolute.saturating_add(step).min(request_end);
        boundaries.push(absolute - request_offset);
    }
    Ok(boundaries)
}

fn canonical_atomic_spans(
    request_offset: u64,
    request_length: u64,
    atomic_write_bytes: u64,
) -> Result<Vec<BlockFaultByteSpan>, DeviceError> {
    let boundaries =
        canonical_atomic_boundaries(request_offset, request_length, atomic_write_bytes)?;
    Ok(boundaries
        .windows(2)
        .map(|pair| BlockFaultByteSpan {
            start: pair[0],
            length: pair[1] - pair[0],
        })
        .collect())
}

fn apply_read_transforms(
    bytes: &mut Vec<u8>,
    transforms: &[BlockFaultReadTransform],
) -> Result<(), DeviceError> {
    for transform in transforms {
        match transform {
            BlockFaultReadTransform::Xor { offset, mask } => {
                let start = usize::try_from(*offset).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "read transform offset does not fit memory",
                    }
                })?;
                let end = start.checked_add(mask.len()).ok_or(
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "read transform range overflow",
                    },
                )?;
                let selected =
                    bytes
                        .get_mut(start..end)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "read transform exceeds response",
                        })?;
                if mask.is_empty() {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "read transform mask is empty",
                    });
                }
                for (byte, mask) in selected.iter_mut().zip(mask) {
                    *byte ^= *mask;
                }
            }
            BlockFaultReadTransform::Replace { bytes: replacement } => {
                if replacement.len() != bytes.len() {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "replacement read length differs",
                    });
                }
                bytes.clone_from(replacement);
            }
        }
    }
    Ok(())
}

fn request_digest(request: &BlockRequest) -> [u8; 32] {
    match request.encode() {
        Ok(bytes) => *blake3::hash(&bytes).as_bytes(),
        Err(_) => [0; 32],
    }
}

fn keyed_discard_bytes(base_hash: [u8; 32], request: &BlockRequest, count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count);
    let mut block = 0_u64;
    while bytes.len() < count {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.block-discard-undefined.v1\0");
        hasher.update(&base_hash);
        hasher.update(&request.request_id.to_be_bytes());
        hasher.update(&request.offset.to_be_bytes());
        hasher.update(&request.count.to_be_bytes());
        hasher.update(&block.to_be_bytes());
        let digest = hasher.finalize();
        let remaining = count - bytes.len();
        bytes.extend_from_slice(&digest.as_bytes()[..remaining.min(digest.as_bytes().len())]);
        block = block.saturating_add(1);
    }
    bytes
}

fn block_response_to_uniform(response: &BlockResponse) -> Result<Response, DeviceError> {
    if !block_response_fits_transport(response) {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "block response exceeds the block transport frame",
        });
    }
    let status = if response.status == BlockStatus::Ok {
        ResponseStatus::Ok
    } else {
        ResponseStatus::Error
    };
    Ok(Response::new(
        response.request_id,
        status,
        response.encode().map_err(DeviceError::Codec)?,
    ))
}

#[cfg(test)]
#[path = "fault_tests.rs"]
mod tests;
