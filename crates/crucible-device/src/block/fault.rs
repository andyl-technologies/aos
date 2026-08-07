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
    /// Applies the complete bytes at another range on this device.
    Misdirected {
        /// Replacement range start.
        destination_offset: u64,
    },
    /// Applies the declared prefix/subset produced by a flash program failure.
    ProgramFailure {
        /// Exact selected spans.
        spans: Vec<BlockFaultByteSpan>,
    },
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
    Recovery,
    /// The modeled timeout coordinate was reached first.
    Timeout,
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
            service_rules: Vec::new(),
            execution_nanos: 0,
            retain_completion: false,
            retention_timeout_response: None,
            retention_timeout_nanos: None,
            retention_recovery_event: None,
            retention_recovery_after_nanos: None,
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
    /// Exclusive virtual-nanosecond deadline that releases the timeout response.
    pub timeout_nanos: u64,
    /// Optional content identity of the signal event that releases recovery.
    pub recovery_event: Option<[u8; 32]>,
    /// Boundary after which the subscribed recovery event may release completion.
    pub recovery_after_nanos: Option<u64>,
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

impl BlockFaultState {
    /// Creates fault-free write-through state for a device.
    #[must_use]
    pub fn write_through(length_bytes: u64) -> Self {
        Self {
            config: BlockDurabilityConfig::write_through(length_bytes),
            icount_shift: 0,
            transport_epoch: None,
            retired_transport_epochs: BTreeMap::new(),
            retry_preserve_authorizations: BTreeSet::new(),
            recovery_until_nanos: None,
            execution_required: false,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            service: BlockServiceState::default(),
            service_pending: BTreeMap::new(),
            service_pending_bytes: 0,
            service_outcomes: Vec::new(),
            storage_outcome_order: Vec::new(),
            execution_opportunities_required: false,
            execution_pending: BTreeMap::new(),
            execution_pending_bytes: 0,
            request_persistence_pending: BTreeMap::new(),
            request_persistence_pending_bytes: 0,
            delivery_pending: BTreeMap::new(),
            delivery_pending_bytes: 0,
            controller: BTreeMap::new(),
            controller_bytes: 0,
            media_queue: BTreeMap::new(),
            media_queue_bytes: 0,
            volatile: BTreeMap::new(),
            volatile_bytes: 0,
            retained: BTreeMap::new(),
            media: BlockMediaState::default(),
            flash: BlockFlashState::default(),
            persistence_execution_required: false,
            pending_persistence_media: BTreeMap::new(),
            persistence_media_outcomes: Vec::new(),
            persistence: BlockPersistenceGraph::new(),
            pending_barrier_frontier: None,
            pending_honest_flush_frontier: None,
            next_cache_sequence: 0,
            next_cache_access_sequence: 0,
            next_version_sequence: 0,
            first_lost_sequence: None,
            actual_durable_frontier: 0,
            reported_durable_frontier: 0,
            retained_completions: BTreeMap::new(),
        }
    }

    /// Reports whether accepted storage mutation remains outside durable media.
    ///
    /// This excludes request-phase and delivery queues: callers can combine it
    /// with transport quiescence to identify a checkpoint boundary at which the
    /// guest-visible operation has completed but controller, cache, or media
    /// work must still survive in the host continuation.
    #[must_use]
    pub fn has_pending_durability_continuation(&self) -> bool {
        !self.controller.is_empty()
            || !self.media_queue.is_empty()
            || !self.volatile.is_empty()
            || !self.pending_persistence_media.is_empty()
            || self.pending_barrier_frontier.is_some()
            || self.pending_honest_flush_frontier.is_some()
    }

    /// Creates a validated fault-free write-through state.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when `config` violates geometry or hard bounds.
    pub fn new(config: BlockDurabilityConfig) -> Result<Self, DeviceError> {
        config.validate()?;
        let persistence = BlockPersistenceGraph::with_edge_limit(
            usize::try_from(config.persistence_dependencies).unwrap_or(usize::MAX),
        )?;
        Ok(Self {
            config,
            icount_shift: 0,
            transport_epoch: None,
            retired_transport_epochs: BTreeMap::new(),
            retry_preserve_authorizations: BTreeSet::new(),
            recovery_until_nanos: None,
            execution_required: false,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            service: BlockServiceState::default(),
            service_pending: BTreeMap::new(),
            service_pending_bytes: 0,
            service_outcomes: Vec::new(),
            storage_outcome_order: Vec::new(),
            execution_opportunities_required: false,
            execution_pending: BTreeMap::new(),
            execution_pending_bytes: 0,
            request_persistence_pending: BTreeMap::new(),
            request_persistence_pending_bytes: 0,
            delivery_pending: BTreeMap::new(),
            delivery_pending_bytes: 0,
            controller: BTreeMap::new(),
            controller_bytes: 0,
            media_queue: BTreeMap::new(),
            media_queue_bytes: 0,
            volatile: BTreeMap::new(),
            volatile_bytes: 0,
            retained: BTreeMap::new(),
            media: BlockMediaState::default(),
            flash: BlockFlashState::default(),
            persistence_execution_required: false,
            pending_persistence_media: BTreeMap::new(),
            persistence_media_outcomes: Vec::new(),
            persistence,
            pending_barrier_frontier: None,
            pending_honest_flush_frontier: None,
            next_cache_sequence: 0,
            next_cache_access_sequence: 0,
            next_version_sequence: 0,
            first_lost_sequence: None,
            actual_durable_frontier: 0,
            reported_durable_frontier: 0,
            retained_completions: BTreeMap::new(),
        })
    }

    /// Enables or disables the fail-closed requirement for exact directives.
    pub fn require_directives(&mut self, required: bool) {
        self.execution_required = required;
    }

    /// Binds request arrival coordinates to the device's virtual-time scale.
    pub(super) fn set_icount_shift(&mut self, shift_bits: u8) {
        debug_assert!(shift_bits < 64);
        self.icount_shift = shift_bits;
    }

    /// Enables fail-closed resolve/persist opportunities after queue service.
    pub fn require_execution_opportunities(&mut self, required: bool) {
        self.execution_opportunities_required = required;
    }

    /// Returns the first request ready for resolve/persist phase evaluation.
    #[must_use]
    pub fn next_execution_opportunity(&self, now_nanos: u64) -> Option<BlockExecutionOpportunity> {
        self.execution_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_nanos <= now_nanos && pending.execution.is_none()
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_nanos,
                    pending.opportunity.request_sequence,
                )
            })
            .map(|pending| pending.opportunity.clone())
    }

    /// Installs the complete resolve/persist directive for one ready request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, the directive
    /// aliases another request, queue service is repeated, or a decision was
    /// already installed.
    pub fn install_execution_directive(
        &mut self,
        resolved: ResolvedBlockExecutionDirective,
    ) -> Result<(), DeviceError> {
        let request_sequence = resolved.opportunity.request_sequence;
        let directive = resolved.directive;
        let pending = self.execution_pending.get(&request_sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "execution directive has no ready request opportunity",
            },
        )?;
        directive.validate_for(&pending.opportunity.request, &self.config)?;
        if resolved.opportunity != pending.opportunity
            || directive.request_sequence != request_sequence
            || pending.execution.is_some()
            || !directive.service_rules.is_empty()
            || directive.execution_nanos != pending.opportunity.ready_nanos
            || (!directive.persistence_transforms.is_empty()
                && directive.persistence_admitted_nanos != pending.opportunity.ready_nanos)
            || directive.availability != pending.opportunity.admission.availability
            || directive.reported_capacity_bytes
                != pending.opportunity.admission.reported_capacity_bytes
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "execution directive identity or phase is invalid",
            });
        }
        let mut next = self.clone();
        let next_pending = next.execution_pending.get_mut(&request_sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "execution opportunity disappeared",
            },
        )?;
        next_pending.execution = Some(directive);
        let bytes = next
            .execution_pending
            .values()
            .try_fold(0_u64, |total, pending| {
                total
                    .checked_add(execution_pending_owned_bytes(pending)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "execution-pending byte accounting overflow",
                    })
            })?;
        if bytes > HARD_PENDING_BLOCK_FAULT_BYTES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_execution_pending_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            });
        }
        next.execution_pending_bytes = bytes;
        *self = next;
        Ok(())
    }

    /// Returns the first resolved write/discard/flush awaiting persist evaluation.
    #[must_use]
    pub fn next_request_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockRequestPersistenceOpportunity> {
        self.request_persistence_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_nanos <= now_nanos && pending.persistence.is_none()
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_nanos,
                    pending.opportunity.request_sequence,
                )
            })
            .map(|pending| pending.opportunity.clone())
    }

    /// Installs the complete persist decision for one exact mutation opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, repeated, or the
    /// directive alters fields already fixed by admit/queue/resolve.
    pub fn install_request_persistence_directive(
        &mut self,
        resolved: ResolvedBlockRequestPersistenceDirective,
    ) -> Result<(), DeviceError> {
        let sequence = resolved.opportunity.request_sequence;
        let directive = resolved.directive;
        let pending = self.request_persistence_pending.get(&sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "persist directive has no ready request opportunity",
            },
        )?;
        directive.validate_for(&pending.opportunity.request, &self.config)?;
        let prior = &pending.opportunity.resolved;
        if resolved.opportunity != pending.opportunity
            || pending.persistence.is_some()
            || directive.request_sequence != sequence
            || directive.execution_nanos != pending.opportunity.ready_nanos
            || !directive.service_rules.is_empty()
            || directive.availability != prior.availability
            || directive.reported_capacity_bytes != prior.reported_capacity_bytes
            || directive.error_result != prior.error_result
            || directive.additional_latency_nanos != prior.additional_latency_nanos
            || directive.retain_completion != prior.retain_completion
            || directive.retention_timeout_response != prior.retention_timeout_response
            || directive.retention_timeout_nanos != prior.retention_timeout_nanos
            || directive.retention_recovery_event != prior.retention_recovery_event
            || directive.retention_recovery_after_nanos != prior.retention_recovery_after_nanos
            || directive.duplicate_completions != prior.duplicate_completions
            || directive.read_transforms != prior.read_transforms
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persist directive identity or earlier phases differ",
            });
        }
        let mut next = self.clone();
        let next_pending = next.request_persistence_pending.get_mut(&sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "request-persistence opportunity disappeared",
            },
        )?;
        next_pending.persistence = Some(directive);
        next.request_persistence_pending_bytes = next
            .request_persistence_pending
            .values()
            .try_fold(0_u64, |total, pending| {
                total
                    .checked_add(request_persistence_pending_owned_bytes(pending)?)
                    .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
                    .ok_or(DeviceError::BlockFaultStateLimit {
                        field: "block_request_persistence_pending_bytes",
                        hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                    })
            })?;
        *self = next;
        Ok(())
    }

    /// Returns the first computed completion ready for deliver-phase evaluation.
    #[must_use]
    pub fn next_delivery_opportunity(&self, now_nanos: u64) -> Option<BlockDeliveryOpportunity> {
        self.delivery_pending
            .values()
            .filter(|pending| {
                pending.opportunity.ready_nanos <= now_nanos
                    && pending.delivery.is_none()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| self.actual_durable_frontier >= frontier)
            })
            .min_by_key(|pending| {
                (
                    pending.opportunity.ready_nanos,
                    pending.opportunity.request_sequence,
                )
            })
            .map(|pending| pending.opportunity.clone())
    }

    /// Installs the complete deliver-phase decision for one computed completion.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, repeated, or the
    /// directive changes fields fixed by an earlier request phase.
    pub fn install_delivery_directive(
        &mut self,
        resolved: ResolvedBlockDeliveryDirective,
    ) -> Result<(), DeviceError> {
        let sequence = resolved.opportunity.request_sequence;
        let directive = resolved.directive;
        let pending = self.delivery_pending.get(&sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "delivery directive has no computed completion opportunity",
            },
        )?;
        directive.validate_for(&pending.opportunity.request, &self.config)?;
        let prior = &pending.opportunity.resolved;
        if resolved.opportunity != pending.opportunity
            || pending.delivery.is_some()
            || directive.request_sequence != sequence
            || directive.execution_nanos != prior.execution_nanos
            || !directive.service_rules.is_empty()
            || directive.availability != prior.availability
            || directive.reported_capacity_bytes != prior.reported_capacity_bytes
            || directive.error_result != prior.error_result
            || directive.retain_completion != prior.retain_completion
            || directive.retention_timeout_response != prior.retention_timeout_response
            || directive.retention_timeout_nanos != prior.retention_timeout_nanos
            || directive.retention_recovery_event != prior.retention_recovery_event
            || directive.retention_recovery_after_nanos != prior.retention_recovery_after_nanos
            || directive.read_transforms != prior.read_transforms
            || directive.media_rules != prior.media_rules
            || directive.write_disposition != prior.write_disposition
            || directive.flush_disposition != prior.flush_disposition
            || directive.cache_policy != prior.cache_policy
            || directive.persistence_transforms != prior.persistence_transforms
            || directive.persistence_media_rules != prior.persistence_media_rules
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "delivery directive identity or earlier phases differ",
            });
        }
        let mut next = self.clone();
        let next_pending = next.delivery_pending.get_mut(&sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "delivery opportunity disappeared",
            },
        )?;
        next_pending.delivery = Some(directive);
        next.delivery_pending_bytes =
            next.delivery_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(delivery_pending_owned_bytes(pending)?)
                        .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
                        .ok_or(DeviceError::BlockFaultStateLimit {
                            field: "block_delivery_pending_bytes",
                            hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES)
                                .unwrap_or(usize::MAX),
                        })
                })?;
        *self = next;
        Ok(())
    }

    /// Returns whether no request, mutation, or sequence has entered this state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.transport_epoch.is_none()
            && self.retired_transport_epochs.is_empty()
            && self.retry_preserve_authorizations.is_empty()
            && self.recovery_until_nanos.is_none()
            && self.pending.is_empty()
            && self.pending_bytes == 0
            && self.service.continuations().is_empty()
            && self.service_pending.is_empty()
            && self.service_pending_bytes == 0
            && self.service_outcomes.is_empty()
            && self.storage_outcome_order.is_empty()
            && self.execution_pending.is_empty()
            && self.execution_pending_bytes == 0
            && self.request_persistence_pending.is_empty()
            && self.request_persistence_pending_bytes == 0
            && self.delivery_pending.is_empty()
            && self.delivery_pending_bytes == 0
            && self.controller.is_empty()
            && self.controller_bytes == 0
            && self.media_queue.is_empty()
            && self.media_queue_bytes == 0
            && self.volatile.is_empty()
            && self.volatile_bytes == 0
            && self.retained.is_empty()
            && self.media.rules().is_empty()
            && self.flash.continuations().is_empty()
            && self.pending_persistence_media.is_empty()
            && self.persistence_media_outcomes.is_empty()
            && self.persistence.nodes().is_empty()
            && self.pending_barrier_frontier.is_none()
            && self.pending_honest_flush_frontier.is_none()
            && self.retained_completions.is_empty()
            && self.next_cache_sequence == 0
            && self.next_cache_access_sequence == 0
            && self.next_version_sequence == 0
            && self.first_lost_sequence.is_none()
            && self.actual_durable_frontier == 0
            && self.reported_durable_frontier == 0
    }

    /// Returns the epoch authenticated by the live block transport, if any.
    #[must_use]
    pub const fn transport_epoch(&self) -> Option<u64> {
        self.transport_epoch
    }

    /// Returns the exclusive virtual-nanosecond recovery deadline, if active.
    #[must_use]
    pub const fn recovery_until_nanos(&self) -> Option<u64> {
        self.recovery_until_nanos
    }

    /// Validates all checkpointed storage-state invariants against a device.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for geometry mismatch, accounting drift,
    /// out-of-range entries, exhausted bounds, or malformed retained responses.
    pub fn validate_restore(&self, device_length: u64) -> Result<(), DeviceError> {
        self.config.validate()?;
        self.media.validate_restore(device_length)?;
        self.flash.validate_restore(device_length)?;
        self.service.validate_restore()?;
        if self.config.length_bytes != device_length
            || self.pending.len() > HARD_PENDING_BLOCK_FAULT_DIRECTIVES
            || self.retired_transport_epochs.len() > HARD_BLOCK_RETIRED_TRANSPORT_EPOCHS
            || self.retry_preserve_authorizations.len() > HARD_BLOCK_RETRY_PRESERVE_AUTHORIZATIONS
            || self.pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.service_pending.len() > super::service::HARD_BLOCK_SERVICE_JOBS
            || self.service_pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.service_outcomes.len() > super::service::HARD_BLOCK_SERVICE_JOBS
            || self.storage_outcome_order.len()
                > super::service::HARD_BLOCK_SERVICE_JOBS
                    .saturating_add(HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS)
            || self.execution_pending.len() > super::service::HARD_BLOCK_SERVICE_JOBS
            || self.execution_pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.request_persistence_pending.len() > super::service::HARD_BLOCK_SERVICE_JOBS
            || self.request_persistence_pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.delivery_pending.len() > super::service::HARD_BLOCK_SERVICE_JOBS
            || self.delivery_pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.volatile.len() > HARD_BLOCK_CACHE_ENTRIES
            || self.controller.len() > HARD_BLOCK_CONTROLLER_ENTRIES
            || self.media_queue.len() > HARD_BLOCK_CONTROLLER_ENTRIES
            || self.media_queue_bytes > HARD_BLOCK_MEDIA_QUEUE_BYTES
            || self.retained.len() > HARD_BLOCK_RETAINED_VERSIONS
            || self.retained_completions.len() > HARD_BLOCK_RETAINED_COMPLETIONS
            || self.pending_persistence_media.len() > HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS
            || self.persistence_media_outcomes.len() > HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS
            || self.volatile.len()
                > usize::try_from(self.config.cache_entries).unwrap_or(usize::MAX)
            || self.controller.len()
                > usize::try_from(self.config.controller_entries).unwrap_or(usize::MAX)
            || self.retained.len()
                > usize::try_from(self.config.retained_versions).unwrap_or(usize::MAX)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored block fault state violates configured bounds",
            });
        }
        if let Some(transport_epoch) = self.transport_epoch {
            if self
                .retired_transport_epochs
                .keys()
                .any(|epoch| *epoch >= transport_epoch)
                || self.retry_preserve_authorizations.iter().any(|identity| {
                    identity.epoch >= transport_epoch
                        || !self.retired_transport_epochs.contains_key(&identity.epoch)
                        || self.retired_transport_epochs[&identity.epoch].queued
                            != BlockTransportPending::RetryPreserveId
                })
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored retired block transport state is inconsistent",
                });
            }
        } else if !self.retired_transport_epochs.is_empty()
            || !self.retry_preserve_authorizations.is_empty()
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored retired block transport state has no live epoch",
            });
        }
        if self.storage_outcome_order.len()
            != self
                .service_outcomes
                .len()
                .saturating_add(self.persistence_media_outcomes.len())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored storage outcome order does not cover every outcome",
            });
        }
        let mut seen_service = vec![false; self.service_outcomes.len()];
        let mut seen_persistence = vec![false; self.persistence_media_outcomes.len()];
        for outcome in &self.storage_outcome_order {
            let seen = match *outcome {
                BlockStorageOutcomeRef::Service(index) => seen_service.get_mut(index),
                BlockStorageOutcomeRef::Persistence(index) => seen_persistence.get_mut(index),
            }
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "restored storage outcome order contains an invalid index",
            })?;
            if std::mem::replace(seen, true) {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored storage outcome order contains a duplicate index",
                });
            }
        }
        let pending_bytes = self.pending.values().try_fold(0_u64, |total, directive| {
            total.checked_add(directive_owned_bytes(directive)?).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "restored pending directive byte accounting overflow",
                },
            )
        })?;
        if pending_bytes != self.pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored pending directive byte accounting differs",
            });
        }
        for (identity, directive) in &self.pending {
            directive.validate_static(identity.request_id, &self.config)?;
            if directive.request_epoch != identity.epoch {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored pending directive epoch differs from its key",
                });
            }
        }
        for (sequence, pending) in &self.service_pending {
            pending
                .directive
                .validate_for(&pending.request, &self.config)?;
            if *sequence != pending.directive.request_sequence
                || pending.directive.service_rules.is_empty()
                || pending.remaining_contributors.is_empty()
                || pending.remaining_contributors.iter().any(|contributor| {
                    !pending
                        .directive
                        .service_rules
                        .iter()
                        .any(|rule| rule.contributor == *contributor)
                })
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored queued storage service request is invalid",
                });
            }
        }
        let service_pending_bytes =
            self.service_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(service_pending_owned_bytes(pending)?)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "restored service-pending byte accounting overflow",
                        })
                })?;
        if service_pending_bytes != self.service_pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored service-pending byte accounting differs",
            });
        }
        let execution_pending_bytes =
            self.execution_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(execution_pending_owned_bytes(pending)?)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "restored execution-pending byte accounting overflow",
                        })
                })?;
        if execution_pending_bytes != self.execution_pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored execution-pending byte accounting differs",
            });
        }
        let request_persistence_pending_bytes = self
            .request_persistence_pending
            .values()
            .try_fold(0_u64, |total, pending| {
                total
                    .checked_add(request_persistence_pending_owned_bytes(pending)?)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored request-persistence byte accounting overflow",
                    })
            })?;
        if request_persistence_pending_bytes != self.request_persistence_pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored request-persistence byte accounting differs",
            });
        }
        let delivery_pending_bytes =
            self.delivery_pending
                .values()
                .try_fold(0_u64, |total, pending| {
                    total
                        .checked_add(delivery_pending_owned_bytes(pending)?)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "restored delivery-pending byte accounting overflow",
                        })
                })?;
        if delivery_pending_bytes != self.delivery_pending_bytes {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored delivery-pending byte accounting differs",
            });
        }
        for (sequence, pending) in &self.execution_pending {
            pending
                .opportunity
                .admission
                .validate_for(&pending.opportunity.request, &self.config)?;
            if *sequence != pending.opportunity.request_sequence
                || pending.opportunity.admission.request_sequence != *sequence
                || !pending.opportunity.admission.service_rules.is_empty()
                || pending.opportunity.admission.execution_nanos != pending.opportunity.ready_nanos
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored request execution opportunity is invalid",
                });
            }
            if let Some(execution) = &pending.execution {
                execution.validate_for(&pending.opportunity.request, &self.config)?;
                if execution.request_sequence != *sequence
                    || !execution.service_rules.is_empty()
                    || execution.execution_nanos != pending.opportunity.ready_nanos
                    || execution.availability != pending.opportunity.admission.availability
                    || execution.reported_capacity_bytes
                        != pending.opportunity.admission.reported_capacity_bytes
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored request execution decision is invalid",
                    });
                }
            }
        }
        for (sequence, pending) in &self.request_persistence_pending {
            let opportunity = &pending.opportunity;
            opportunity
                .resolved
                .validate_for(&opportunity.request, &self.config)?;
            if *sequence != opportunity.request_sequence
                || opportunity.resolved.request_sequence != *sequence
                || opportunity.resolved.execution_nanos != opportunity.ready_nanos
                || !matches!(
                    opportunity.request.op,
                    BlockOp::Write | BlockOp::Discard | BlockOp::Flush
                )
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored request-persistence opportunity is invalid",
                });
            }
            if let Some(persistence) = &pending.persistence {
                persistence.validate_for(&opportunity.request, &self.config)?;
                if persistence.request_sequence != *sequence
                    || persistence.execution_nanos != opportunity.ready_nanos
                    || persistence.availability != opportunity.resolved.availability
                    || persistence.reported_capacity_bytes
                        != opportunity.resolved.reported_capacity_bytes
                    || persistence.error_result != opportunity.resolved.error_result
                    || persistence.read_transforms != opportunity.resolved.read_transforms
                    || persistence.retain_completion != opportunity.resolved.retain_completion
                    || persistence.retention_timeout_response
                        != opportunity.resolved.retention_timeout_response
                    || persistence.retention_timeout_nanos
                        != opportunity.resolved.retention_timeout_nanos
                    || persistence.retention_recovery_event
                        != opportunity.resolved.retention_recovery_event
                    || persistence.retention_recovery_after_nanos
                        != opportunity.resolved.retention_recovery_after_nanos
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored request-persistence decision is invalid",
                    });
                }
            }
        }
        for (sequence, pending) in &self.delivery_pending {
            let opportunity = &pending.opportunity;
            opportunity
                .resolved
                .validate_for(&opportunity.request, &self.config)?;
            if *sequence != opportunity.request_sequence
                || opportunity.resolved.request_sequence != *sequence
                || opportunity.wire_digest != opportunity.resolved.request_digest
                || opportunity.response.request_id != opportunity.request.request_id
                || !block_response_fits_transport(&opportunity.response)
                || opportunity
                    .required_durable_frontier
                    .is_some_and(|frontier| frontier > self.next_cache_sequence)
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored delivery opportunity is invalid",
                });
            }
            if let Some(delivery) = &pending.delivery {
                delivery.validate_for(&opportunity.request, &self.config)?;
                if delivery.request_sequence != *sequence
                    || delivery.execution_nanos != opportunity.resolved.execution_nanos
                    || delivery.availability != opportunity.resolved.availability
                    || delivery.reported_capacity_bytes
                        != opportunity.resolved.reported_capacity_bytes
                    || delivery.error_result != opportunity.resolved.error_result
                    || delivery.read_transforms != opportunity.resolved.read_transforms
                    || delivery.write_disposition != opportunity.resolved.write_disposition
                    || delivery.flush_disposition != opportunity.resolved.flush_disposition
                    || delivery.cache_policy != opportunity.resolved.cache_policy
                    || delivery.persistence_transforms
                        != opportunity.resolved.persistence_transforms
                    || delivery.persistence_media_rules
                        != opportunity.resolved.persistence_media_rules
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored delivery decision changes an earlier phase",
                    });
                }
            }
        }
        let expected_service_jobs = self
            .service_pending
            .iter()
            .flat_map(|(sequence, pending)| {
                pending
                    .remaining_contributors
                    .iter()
                    .map(|contributor| (*contributor, *sequence))
            })
            .collect::<BTreeSet<_>>();
        if self
            .service
            .live_job_keys()
            .into_iter()
            .collect::<BTreeSet<_>>()
            != expected_service_jobs
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored service queue differs from request contributor joins",
            });
        }
        let service_sequences = self
            .service_pending
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let execution_sequences = self
            .execution_pending
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let persistence_sequences = self
            .request_persistence_pending
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let delivery_sequences = self
            .delivery_pending
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let installed_sequences = self
            .pending
            .values()
            .map(|directive| directive.request_sequence)
            .collect::<BTreeSet<_>>();
        if installed_sequences.len() != self.pending.len()
            || !service_sequences.is_disjoint(&execution_sequences)
            || !service_sequences.is_disjoint(&installed_sequences)
            || !execution_sequences.is_disjoint(&installed_sequences)
            || !service_sequences.is_disjoint(&persistence_sequences)
            || !service_sequences.is_disjoint(&delivery_sequences)
            || !execution_sequences.is_disjoint(&persistence_sequences)
            || !execution_sequences.is_disjoint(&delivery_sequences)
            || !persistence_sequences.is_disjoint(&delivery_sequences)
            || !persistence_sequences.is_disjoint(&installed_sequences)
            || !delivery_sequences.is_disjoint(&installed_sequences)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored request sequence occupies multiple execution stages",
            });
        }
        let volatile_bytes = self.volatile.values().try_fold(0_u64, |total, entry| {
            validate_state_range(entry.offset, entry.bytes.len(), device_length)?;
            validate_media_entry(
                entry.media_identity,
                entry.sequence,
                entry.offset,
                entry.bytes.len(),
                device_length,
            )?;
            total
                .checked_add(u64::try_from(entry.bytes.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "restored volatile entry length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored volatile byte accounting overflow",
                })
        })?;
        let controller_bytes = self.controller.values().try_fold(0_u64, |total, entry| {
            validate_state_range(entry.offset, entry.bytes.len(), device_length)?;
            validate_media_entry(
                entry.media_identity,
                entry.sequence,
                entry.offset,
                entry.bytes.len(),
                device_length,
            )?;
            total
                .checked_add(u64::try_from(entry.bytes.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "restored controller entry length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored controller byte accounting overflow",
                })
        })?;
        let media_queue_bytes = self.media_queue.values().try_fold(0_u64, |total, entry| {
            validate_state_range(entry.offset, entry.bytes.len(), device_length)?;
            validate_media_entry(
                entry.media_identity,
                entry.sequence,
                entry.offset,
                entry.bytes.len(),
                device_length,
            )?;
            total
                .checked_add(u64::try_from(entry.bytes.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "restored media-queue entry length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored media-queue byte accounting overflow",
                })
        })?;
        if volatile_bytes != self.volatile_bytes
            || controller_bytes != self.controller_bytes
            || media_queue_bytes != self.media_queue_bytes
            || volatile_bytes > self.config.volatile_cache_bytes
            || controller_bytes > self.config.controller_buffer_bytes
            || self.volatile.iter().any(|(sequence, entry)| {
                *sequence != entry.sequence || *sequence >= self.next_cache_sequence
            })
            || self.retained.iter().any(|(sequence, version)| {
                *sequence != version.sequence
                    || *sequence >= self.next_version_sequence
                    || validate_state_range(version.offset, version.bytes.len(), device_length)
                        .is_err()
            })
            || self.controller.iter().any(|(sequence, entry)| {
                *sequence != entry.sequence || *sequence >= self.next_cache_sequence
            })
            || self.media_queue.iter().any(|(sequence, entry)| {
                *sequence != entry.sequence || *sequence >= self.next_cache_sequence
            })
            || self
                .volatile
                .values()
                .any(|entry| entry.last_access_sequence >= self.next_cache_access_sequence)
            || self
                .first_lost_sequence
                .is_some_and(|sequence| sequence >= self.next_cache_sequence)
            || self.actual_durable_frontier > self.next_cache_sequence
            || self.reported_durable_frontier > self.next_cache_sequence
            || self
                .pending_barrier_frontier
                .is_some_and(|frontier| frontier > self.next_cache_sequence)
            || self
                .pending_honest_flush_frontier
                .is_some_and(|frontier| frontier > self.next_cache_sequence)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored block fault state has invalid accounting or sequence",
            });
        }
        self.persistence.validate()?;
        if self.persistence.edge_limit()
            != usize::try_from(self.config.persistence_dependencies).unwrap_or(usize::MAX)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored persistence graph uses a different configured edge bound",
            });
        }
        let layer_sequences = self
            .controller
            .keys()
            .chain(self.media_queue.keys())
            .chain(self.volatile.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        if layer_sequences
            != self
                .persistence
                .nodes()
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored persistence graph differs from pending storage layers",
            });
        }
        let live_discard_operations = self
            .controller
            .values()
            .map(|entry| entry.media_identity)
            .chain(self.media_queue.values().map(|entry| entry.media_identity))
            .chain(self.volatile.values().map(|entry| entry.media_identity))
            .filter_map(|identity| {
                (identity.operation == BlockOp::Discard).then_some(identity.operation_sequence)
            })
            .collect::<BTreeSet<_>>();
        if self.flash.continuations().values().any(|continuation| {
            continuation
                .erase_decisions
                .keys()
                .any(|(operation, _block)| !live_discard_operations.contains(operation))
        }) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored flash erase decision has no live discard operation",
            });
        }
        let expected_durable_frontier = self
            .controller
            .keys()
            .next()
            .copied()
            .into_iter()
            .chain(self.volatile.keys().next().copied())
            .chain(self.media_queue.keys().next().copied())
            .chain(self.first_lost_sequence)
            .min()
            .unwrap_or(self.next_cache_sequence);
        if self.actual_durable_frontier != expected_durable_frontier {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored actual durable frontier differs from exact pending state",
            });
        }
        for (identity, completion) in &self.retained_completions {
            if *identity != completion.identity
                || completion.recovery_response.request_id != identity.request_id
                || completion.timeout_response.request_id != identity.request_id
                || completion
                    .persist_through_on_recovery
                    .is_some_and(|frontier| frontier > self.next_cache_sequence)
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored retained completion is malformed",
                });
            }
            for response in [&completion.recovery_response, &completion.timeout_response] {
                if response.payload.len() > crucible_shmem::MAX_FRAME_DATA {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored retained completion exceeds the block transport frame",
                    });
                }
                let decoded =
                    BlockResponse::decode(&response.payload).map_err(DeviceError::Codec)?;
                if decoded.identity() != *identity
                    || (decoded.status == BlockStatus::Ok)
                        != (response.status == ResponseStatus::Ok)
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored retained completion payload differs from its envelope",
                    });
                }
            }
        }
        for (sequence, directive) in &self.pending_persistence_media {
            if *sequence != directive.opportunity.sequence {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "restored persistence-media directive key differs",
                });
            }
            self.validate_persistence_media_directive(directive)?;
        }
        Ok(())
    }

    /// Enables fail-closed resolution at each physical persistence opportunity.
    pub fn require_persistence_media_directives(&mut self, required: bool) {
        self.persistence_execution_required = required;
    }

    /// Returns the first ready physical persistence opportunity in canonical order.
    #[must_use]
    pub fn next_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockPersistenceOpportunity> {
        self.media_queue
            .keys()
            .filter(|sequence| self.persistence.is_ready_at(**sequence, now_nanos))
            .filter(|sequence| !self.pending_persistence_media.contains_key(sequence))
            .filter_map(|sequence| {
                self.persistence
                    .writeback_key(*sequence)
                    .map(|key| (key, *sequence))
            })
            .min_by_key(|(key, _sequence)| *key)
            .and_then(|(_key, sequence)| self.persistence_opportunity(sequence))
    }

    /// Installs the exact media directive for one ready persistence opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for stale/mismatched opportunity identity,
    /// duplicate installation, invalid flash rules, or bounded-state exhaustion.
    pub fn install_persistence_media_directive(
        &mut self,
        directive: ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), DeviceError> {
        self.validate_persistence_media_directive(&directive)?;
        if self.pending_persistence_media.len() == HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_persistence_media",
                hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
            });
        }
        let sequence = directive.opportunity.sequence;
        if self.pending_persistence_media.contains_key(&sequence) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate persistence-media directive",
            });
        }
        let mut next = self.clone();
        next.flash
            .register_rules(self.config.length_bytes, &directive.flash_rules)?;
        next.pending_persistence_media.insert(sequence, directive);
        *self = next;
        Ok(())
    }

    /// Returns checkpointed sparse flash counters and changed-cell state.
    #[must_use]
    pub const fn flash_state(&self) -> &BlockFlashState {
        &self.flash
    }

    /// Drains completed persistence-media evidence after durable event recording.
    pub fn drain_persistence_media_outcomes(&mut self) -> Vec<BlockPersistenceMediaOutcome> {
        self.storage_outcome_order
            .retain(|outcome| matches!(outcome, BlockStorageOutcomeRef::Service(_)));
        std::mem::take(&mut self.persistence_media_outcomes)
    }

    /// Borrows completed physical-media outcomes without acknowledging them.
    #[must_use]
    pub fn persistence_media_outcomes(&self) -> &[BlockPersistenceMediaOutcome] {
        &self.persistence_media_outcomes
    }

    /// Returns every pending storage outcome in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when checkpointed outcome-order state contains
    /// an invalid reference.
    pub fn storage_outcomes(&self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        self.storage_outcome_order
            .iter()
            .map(|outcome| match *outcome {
                BlockStorageOutcomeRef::Service(index) => self
                    .service_outcomes
                    .get(index)
                    .copied()
                    .map(BlockStorageOutcome::Service),
                BlockStorageOutcomeRef::Persistence(index) => self
                    .persistence_media_outcomes
                    .get(index)
                    .cloned()
                    .map(BlockStorageOutcome::Persistence),
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "storage outcome order contains an invalid index",
            })
    }

    /// Drains every storage outcome in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] without mutation when checkpointed outcome-order
    /// state contains an invalid reference.
    pub fn drain_storage_outcomes(&mut self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        let outcomes = self.storage_outcomes()?;
        self.storage_outcome_order.clear();
        self.service_outcomes.clear();
        self.persistence_media_outcomes.clear();
        Ok(outcomes)
    }

    /// Installs one directive, keyed by the exact guest request ID.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate IDs or a hard pending-state limit.
    pub fn install(
        &mut self,
        identity: BlockRequestIdentity,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        directive.validate_static(identity.request_id, &self.config)?;
        if directive.request_epoch != identity.epoch {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block fault directive epoch differs from its installation identity",
            });
        }
        if self.pending.len() == HARD_PENDING_BLOCK_FAULT_DIRECTIVES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_directives",
                hard: HARD_PENDING_BLOCK_FAULT_DIRECTIVES,
            });
        }
        if self.pending.contains_key(&identity) {
            return Err(DeviceError::DuplicateBlockFaultDirective {
                request_id: identity.request_id,
            });
        }
        let bytes = directive_owned_bytes(&directive)?;
        let next_bytes =
            self.pending_bytes
                .checked_add(bytes)
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "pending_directive_bytes",
                    hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                })?;
        if next_bytes > HARD_PENDING_BLOCK_FAULT_BYTES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_directive_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            });
        }
        self.pending.insert(identity, directive);
        self.pending_bytes = next_bytes;
        Ok(())
    }

    /// Returns the immutable durability configuration.
    #[must_use]
    pub const fn config(&self) -> &BlockDurabilityConfig {
        &self.config
    }

    /// Returns volatile entries in cache sequence order.
    #[must_use]
    pub const fn volatile_entries(&self) -> &BTreeMap<u64, BlockVolatileEntry> {
        &self.volatile
    }

    /// Returns canonical cache-loss candidates for the requested protection scope.
    ///
    /// When `include_protected` is false, entries admitted under a
    /// power-loss-protected policy are excluded. A protection-failure impulse
    /// passes true and receives every live sequence.
    #[must_use]
    pub fn volatile_loss_candidates(&self, include_protected: bool) -> Vec<u64> {
        self.volatile
            .iter()
            .filter_map(|(sequence, entry)| {
                (include_protected || !entry.power_loss_protected).then_some(*sequence)
            })
            .collect()
    }

    /// Returns the canonical digest of the complete live volatile-cache entry set.
    #[must_use]
    pub fn volatile_entries_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.block-volatile-entry-set.v2\0");
        for (sequence, entry) in &self.volatile {
            hasher.update(&sequence.to_be_bytes());
            hasher.update(&entry.request_id.to_be_bytes());
            hasher.update(&[entry.media_identity.operation.to_wire()]);
            hasher.update(&entry.media_identity.operation_sequence.to_be_bytes());
            hasher.update(&entry.media_identity.request_digest);
            hasher.update(&entry.media_identity.request_offset.to_be_bytes());
            hasher.update(&entry.media_identity.request_count.to_be_bytes());
            hasher.update(&entry.offset.to_be_bytes());
            hasher.update(
                &u64::try_from(entry.bytes.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            hasher.update(blake3::hash(&entry.bytes).as_bytes());
            hasher.update(&entry.last_access_sequence.to_be_bytes());
            hasher.update(&[u8::from(entry.power_loss_protected)]);
        }
        *hasher.finalize().as_bytes()
    }

    /// Returns controller-accepted writes in global sequence order.
    #[must_use]
    pub const fn controller_entries(&self) -> &BTreeMap<u64, BlockControllerEntry> {
        &self.controller
    }

    /// Returns writes admitted to the durable-media service queue.
    #[must_use]
    pub const fn media_queue_entries(&self) -> &BTreeMap<u64, BlockControllerEntry> {
        &self.media_queue
    }

    /// Returns the complete live persistence dependency graph.
    #[must_use]
    pub const fn persistence_graph(&self) -> &BlockPersistenceGraph {
        &self.persistence
    }

    /// Drains persistence graph mutations after canonical event recording.
    pub fn drain_persistence_transformation_evidence(
        &mut self,
    ) -> Vec<super::persistence::BlockPersistenceTransformationEvidence> {
        self.persistence.drain_transformation_evidence()
    }

    /// Returns retained versions in version sequence order.
    #[must_use]
    pub const fn retained_versions(&self) -> &BTreeMap<u64, BlockRetainedVersion> {
        &self.retained
    }

    /// Returns checkpointed media overlays and activation counters.
    #[must_use]
    pub const fn media_state(&self) -> &BlockMediaState {
        &self.media
    }

    /// Returns completions waiting for an explicit recovery or timeout event.
    #[must_use]
    pub const fn retained_completions(
        &self,
    ) -> &BTreeMap<BlockRequestIdentity, BlockRetainedCompletion> {
        &self.retained_completions
    }

    /// Returns one retained completion without consuming it.
    #[must_use]
    pub fn retained_completion(
        &self,
        identity: BlockRequestIdentity,
    ) -> Option<&BlockRetainedCompletion> {
        self.retained_completions.get(&identity)
    }

    /// Returns retained requests whose timeout is due in canonical identity order.
    #[must_use]
    pub fn retained_timeouts_due(&self, now_nanos: u64) -> Vec<BlockRequestIdentity> {
        self.retained_completions
            .iter()
            .filter_map(|(identity, completion)| {
                (completion.timeout_nanos <= now_nanos).then_some(*identity)
            })
            .collect()
    }

    /// Returns retained requests subscribed to one recovery event identity.
    #[must_use]
    pub fn retained_recoveries_for(
        &self,
        event: [u8; 32],
        event_nanos: u64,
    ) -> Vec<BlockRequestIdentity> {
        self.retained_completions
            .iter()
            .filter_map(|(identity, completion)| {
                (completion.recovery_event == Some(event)
                    && completion
                        .recovery_after_nanos
                        .is_some_and(|after| event_nanos > after))
                .then_some(*identity)
            })
            .collect()
    }

    /// Returns the earliest retained-completion timeout coordinate.
    #[must_use]
    pub fn next_retained_timeout_nanos(&self) -> Option<u64> {
        self.retained_completions
            .values()
            .map(|completion| completion.timeout_nanos)
            .min()
    }

    /// Resolves a retained completion and applies its recovery-only durability.
    ///
    /// Callers must execute this method on cloned state and commit the clone
    /// only after the response scheduler accepts the returned response.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the request is not retained or persistence
    /// of the captured flush frontier fails.
    pub(super) fn resolve_retained_completion(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        identity: BlockRequestIdentity,
        release: BlockRetainedRelease,
        now_nanos: u64,
    ) -> Result<Response, DeviceError> {
        let completion = self.retained_completions.get(&identity).cloned().ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "storage completion is not retained",
            },
        )?;
        let response = match release {
            BlockRetainedRelease::Recovery => {
                if let Some(frontier) = completion.persist_through_on_recovery {
                    let wait = self.persist_through(base, durable, frontier, now_nanos)?;
                    if wait != 0 {
                        return Err(DeviceError::InvalidBlockFaultDirective {
                            reason: "flush recovery precedes its persistence deadline",
                        });
                    }
                    self.reported_durable_frontier = self.actual_durable_frontier;
                }
                completion.recovery_response
            }
            BlockRetainedRelease::Timeout => completion.timeout_response,
        };
        self.retained_completions.remove(&identity);
        Ok(response)
    }

    /// Returns the actual durable write/cache frontier.
    #[must_use]
    pub const fn actual_durable_frontier(&self) -> u64 {
        self.actual_durable_frontier
    }

    /// Returns the frontier most recently reported durable to the guest.
    #[must_use]
    pub const fn reported_durable_frontier(&self) -> u64 {
        self.reported_durable_frontier
    }

    /// Drops exact volatile entries selected by cache sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a selected sequence is not currently live.
    pub fn lose_volatile(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        let selected = sequences.iter().copied().collect::<BTreeSet<_>>();
        if selected.len() != sequences.len()
            || selected
                .iter()
                .any(|sequence| !self.volatile.contains_key(sequence))
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile loss selection is not an exact live subset",
            });
        }
        let mut next = self.clone();
        for sequence in selected {
            if let Some(entry) = next.volatile.remove(&sequence) {
                next.persistence.commit_lost(sequence)?;
                next.first_lost_sequence = Some(
                    next.first_lost_sequence
                        .map_or(sequence, |existing| existing.min(sequence)),
                );
                next.volatile_bytes = next
                    .volatile_bytes
                    .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "volatile byte accounting underflow",
                    })?;
            }
        }
        next.recompute_actual_durable_frontier();
        *self = next;
        Ok(())
    }

    /// Drops exact controller-accepted entries selected by global sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a selected sequence is not currently in the
    /// controller-accepted layer.
    pub fn lose_controller(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        let selected = sequences.iter().copied().collect::<BTreeSet<_>>();
        if selected.len() != sequences.len()
            || selected
                .iter()
                .any(|sequence| !self.controller.contains_key(sequence))
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "controller loss selection is not an exact live subset",
            });
        }
        let mut next = self.clone();
        for sequence in selected {
            if let Some(entry) = next.controller.remove(&sequence) {
                next.persistence.commit_lost(sequence)?;
                next.first_lost_sequence = Some(
                    next.first_lost_sequence
                        .map_or(sequence, |existing| existing.min(sequence)),
                );
                next.controller_bytes = next
                    .controller_bytes
                    .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "controller byte accounting underflow",
                    })?;
            }
        }
        next.recompute_actual_durable_frontier();
        *self = next;
        Ok(())
    }

    /// Applies the host-side portion of a delivered controller reset.
    ///
    /// The caller must invoke this only after the corresponding reset response
    /// has crossed the delivery boundary. Requests removed from a host-owned
    /// lifecycle stage receive one explicit terminal or retry disposition; the
    /// returned responses are ordered by request sequence within each lifecycle
    /// stage and by the stage order queued, executing, resolved, then completed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a generated response cannot be encoded or if
    /// losing controller/cache state violates persistence accounting.
    pub(super) fn apply_transport_reset(
        &mut self,
        reset: BlockTransportReset,
        delivered_nanos: u64,
    ) -> Result<Vec<Response>, DeviceError> {
        let mut next = self.clone();
        let mut responses = Vec::new();

        let current_epoch = next.transport_epoch.unwrap_or(reset.next_epoch);
        match reset.request_ids {
            BlockTransportRequestIds::PreserveMonotonic if reset.next_epoch != current_epoch => {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "preserved block transport reset changed epoch",
                });
            }
            BlockTransportRequestIds::NewEpochFromZero
                if current_epoch.checked_add(1) != Some(reset.next_epoch) =>
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "block transport reset did not advance exactly one epoch",
                });
            }
            _ => {}
        }
        if reset.request_ids == BlockTransportRequestIds::NewEpochFromZero {
            if next.retired_transport_epochs.len() == HARD_BLOCK_RETIRED_TRANSPORT_EPOCHS {
                return Err(DeviceError::BlockFaultStateLimit {
                    field: "retired_transport_epochs",
                    hard: HARD_BLOCK_RETIRED_TRANSPORT_EPOCHS,
                });
            }
            if next
                .retired_transport_epochs
                .insert(
                    current_epoch,
                    BlockRetiredTransportEpoch {
                        queued: reset.queued,
                        failure_result: reset.failure_result,
                    },
                )
                .is_some()
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "block transport epoch was retired twice",
                });
            }
        }
        next.transport_epoch = Some(reset.next_epoch);
        next.recovery_until_nanos = Some(delivered_nanos.checked_add(reset.recovery_nanos).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "block transport recovery deadline overflow",
            },
        )?);

        let pending = std::mem::take(&mut next.pending);
        next.pending_bytes = 0;
        for (identity, _directive) in pending {
            responses.push(transport_pending_response(
                identity,
                reset.queued,
                reset.failure_result,
            )?);
        }

        let queued = std::mem::take(&mut next.service_pending);
        next.service_pending_bytes = 0;
        next.service = BlockServiceState::default();
        for pending in queued.into_values() {
            responses.push(transport_pending_response(
                pending.request.identity(),
                reset.queued,
                reset.failure_result,
            )?);
        }

        let executing = std::mem::take(&mut next.execution_pending);
        next.execution_pending_bytes = 0;
        for pending in executing.into_values() {
            responses.push(transport_pending_response(
                pending.opportunity.request.identity(),
                reset.executing,
                reset.failure_result,
            )?);
        }

        if reset.resolved != BlockTransportResolved::Complete {
            let persistence = std::mem::take(&mut next.request_persistence_pending);
            next.request_persistence_pending_bytes = 0;
            for pending in persistence.into_values() {
                responses.push(transport_resolved_response(
                    pending.opportunity.request.identity(),
                    reset.resolved,
                    reset.failure_result,
                )?);
            }

            let delivery = std::mem::take(&mut next.delivery_pending);
            next.delivery_pending_bytes = 0;
            for pending in delivery.into_values() {
                responses.push(transport_resolved_response(
                    pending.opportunity.request.identity(),
                    reset.resolved,
                    reset.failure_result,
                )?);
            }
        } else {
            for pending in next.delivery_pending.values_mut() {
                pending.opportunity.required_durable_frontier = None;
            }
        }

        if reset.completed_undelivered != BlockTransportUndelivered::Complete {
            let retained = std::mem::take(&mut next.retained_completions);
            for completion in retained.into_values() {
                let original = BlockResponse::decode(&completion.recovery_response.payload)
                    .map_err(DeviceError::Codec)?;
                responses.push(transport_undelivered_response(
                    original.identity(),
                    reset.completed_undelivered,
                    reset.failure_result,
                )?);
            }
        }

        if !reset.preserve_controller_buffer {
            let sequences = next.controller.keys().copied().collect::<Vec<_>>();
            next.lose_controller(&sequences)?;
        }
        if !reset.preserve_volatile_cache {
            let sequences = next.volatile.keys().copied().collect::<Vec<_>>();
            next.lose_volatile(&sequences)?;
        }

        *self = next;
        Ok(responses)
    }

    /// Returns the earliest exact integrated-service release coordinate.
    #[must_use]
    pub(super) fn next_service_completion_nanos(&self) -> Option<u64> {
        self.service.next_completion_nanos()
    }

    /// Returns the earliest request resolve/persist opportunity coordinate.
    #[must_use]
    pub(super) fn next_execution_deadline_nanos(&self) -> Option<u64> {
        self.execution_pending
            .values()
            .filter(|pending| pending.execution.is_none())
            .map(|pending| pending.opportunity.ready_nanos)
            .min()
    }

    /// Returns the earliest request mutation awaiting a persist decision.
    #[must_use]
    pub(super) fn next_request_persistence_deadline_nanos(&self) -> Option<u64> {
        self.request_persistence_pending
            .values()
            .filter(|pending| pending.persistence.is_none())
            .map(|pending| pending.opportunity.ready_nanos)
            .min()
    }

    /// Returns the earliest completion awaiting an exact delivery decision.
    #[must_use]
    pub(super) fn next_delivery_deadline_nanos(&self) -> Option<u64> {
        self.delivery_pending
            .values()
            .filter(|pending| {
                pending.delivery.is_none()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| self.actual_durable_frontier >= frontier)
            })
            .map(|pending| pending.opportunity.ready_nanos)
            .min()
    }

    /// Returns the earliest dependency-ready physical persistence boundary.
    #[must_use]
    pub(super) fn next_persistence_deadline_nanos(&self) -> Option<u64> {
        self.media_queue
            .keys()
            .filter(|sequence| self.persistence.is_ready_at(**sequence, u64::MAX))
            .filter_map(|sequence| self.persistence.deadline_nanos(*sequence))
            .min()
    }

    /// Drains contributor-level service evidence in canonical completion order.
    pub fn drain_service_outcomes(&mut self) -> Vec<BlockServiceCompletion> {
        self.storage_outcome_order
            .retain(|outcome| matches!(outcome, BlockStorageOutcomeRef::Persistence(_)));
        std::mem::take(&mut self.service_outcomes)
    }

    /// Borrows integrated-service completion evidence without acknowledging it.
    #[must_use]
    pub fn service_outcomes(&self) -> &[BlockServiceCompletion] {
        &self.service_outcomes
    }

    fn defer_execution(
        &mut self,
        request: &BlockRequest,
        request_icount: u64,
        ready_nanos: u64,
        mut admission: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        if self
            .execution_pending
            .contains_key(&admission.request_sequence)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "request execution sequence is repeated",
            });
        }
        if self.execution_pending.len() == super::service::HARD_BLOCK_SERVICE_JOBS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_execution_pending",
                hard: super::service::HARD_BLOCK_SERVICE_JOBS,
            });
        }
        if let Some(removed) = self.pending.remove(&request.identity()) {
            self.pending_bytes = self
                .pending_bytes
                .checked_sub(directive_owned_bytes(&removed)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte accounting underflow",
                })?;
        }
        admission.service_rules.clear();
        let sequence = admission.request_sequence;
        let pending = BlockExecutionPendingRequest {
            opportunity: BlockExecutionOpportunity {
                request_sequence: sequence,
                request: request.clone(),
                request_icount,
                wire_digest: admission.request_digest,
                ready_nanos,
                admission,
            },
            execution: None,
        };
        self.execution_pending_bytes = self
            .execution_pending_bytes
            .checked_add(execution_pending_owned_bytes(&pending)?)
            .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
            .ok_or(DeviceError::BlockFaultStateLimit {
                field: "block_execution_pending_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            })?;
        self.execution_pending.insert(sequence, pending);
        Ok(())
    }

    /// Executes every ready request whose resolve/persist decision is installed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when a decision is malformed, execution fails,
    /// or the resulting completion cannot be represented exactly.
    pub(super) fn resume_execution_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let ready = next
            .execution_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_nanos <= now_nanos && pending.execution.is_some())
                    .then_some((pending.opportunity.ready_nanos, *sequence))
            })
            .collect::<BTreeSet<_>>();
        for (ready_nanos, sequence) in ready {
            let pending = next.execution_pending.remove(&sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready execution request disappeared",
                },
            )?;
            next.execution_pending_bytes = next
                .execution_pending_bytes
                .checked_sub(execution_pending_owned_bytes(&pending)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "execution-pending byte accounting underflow",
                })?;
            let directive = pending
                .execution
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "ready execution request lost its decision",
                })?;
            if matches!(
                pending.opportunity.request.op,
                BlockOp::Write | BlockOp::Discard | BlockOp::Flush
            ) && block_admission_error(&pending.opportunity.request, &directive, &next.config)
                .is_none()
                && directive.error_result.is_none()
            {
                next.defer_request_persistence(
                    pending.opportunity.request,
                    pending.opportunity.request_icount,
                    ready_nanos,
                    directive,
                )?;
                continue;
            }
            next.execute_to_delivery(
                base,
                &mut next_durable,
                &pending.opportunity.request,
                pending.opportunity.request_icount,
                directive,
                ready_nanos,
            )?;
        }
        if !next.persistence_execution_required {
            next.persist_due(base, &mut next_durable, now_nanos)?;
        }
        *self = next;
        *durable = next_durable;
        Ok(Vec::new())
    }

    fn defer_request_persistence(
        &mut self,
        request: BlockRequest,
        request_icount: u64,
        ready_nanos: u64,
        resolved: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        let sequence = resolved.request_sequence;
        if self.request_persistence_pending.contains_key(&sequence) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "request persistence sequence is repeated",
            });
        }
        if self.request_persistence_pending.len() == super::service::HARD_BLOCK_SERVICE_JOBS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_request_persistence_pending",
                hard: super::service::HARD_BLOCK_SERVICE_JOBS,
            });
        }
        let pending = BlockRequestPersistencePending {
            opportunity: BlockRequestPersistenceOpportunity {
                request_sequence: sequence,
                wire_digest: resolved.request_digest,
                request,
                request_icount,
                ready_nanos,
                resolved,
            },
            persistence: None,
        };
        self.request_persistence_pending_bytes = self
            .request_persistence_pending_bytes
            .checked_add(request_persistence_pending_owned_bytes(&pending)?)
            .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
            .ok_or(DeviceError::BlockFaultStateLimit {
                field: "block_request_persistence_pending_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            })?;
        self.request_persistence_pending.insert(sequence, pending);
        Ok(())
    }

    /// Executes every request whose exact persist decision is installed and ready.
    pub(super) fn resume_request_persistence_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let ready = next
            .request_persistence_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_nanos <= now_nanos && pending.persistence.is_some())
                    .then_some((pending.opportunity.ready_nanos, *sequence))
            })
            .collect::<BTreeSet<_>>();
        for (ready_nanos, sequence) in ready {
            let pending = next.request_persistence_pending.remove(&sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready request-persistence opportunity disappeared",
                },
            )?;
            next.request_persistence_pending_bytes = next
                .request_persistence_pending_bytes
                .checked_sub(request_persistence_pending_owned_bytes(&pending)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "request-persistence byte accounting underflow",
                })?;
            let directive = pending
                .persistence
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "ready request-persistence opportunity lost its decision",
                })?;
            next.execute_to_delivery(
                base,
                &mut next_durable,
                &pending.opportunity.request,
                pending.opportunity.request_icount,
                directive,
                ready_nanos,
            )?;
        }
        *self = next;
        *durable = next_durable;
        Ok(Vec::new())
    }

    fn execute_to_delivery(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
        directive: ResolvedBlockFaultDirective,
        mutation_nanos: u64,
    ) -> Result<(), DeviceError> {
        if self
            .delivery_pending
            .contains_key(&directive.request_sequence)
            || self.delivery_pending.len() == super::service::HARD_BLOCK_SERVICE_JOBS
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_delivery_pending",
                hard: super::service::HARD_BLOCK_SERVICE_JOBS,
            });
        }
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let (response, mut persistence_wait_nanos) =
            next.execute_wire(base, &mut next_durable, request, &directive)?;
        if response.status == BlockStatus::Ok
            && matches!(request.op, BlockOp::Write | BlockOp::Discard)
            && next.config.completion_durability == BlockCompletionDurability::Durable
        {
            persistence_wait_nanos = persistence_wait_nanos.max(next.persist_through(
                base,
                &mut next_durable,
                next.next_cache_sequence,
                mutation_nanos,
            )?);
        }
        let ready_nanos = mutation_nanos.checked_add(persistence_wait_nanos).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "storage mutation and persistence wait overflow",
            },
        )?;
        let required_durable_frontier = (response.status == BlockStatus::Ok)
            .then(|| match request.op {
                BlockOp::Write | BlockOp::Discard
                    if next.config.completion_durability == BlockCompletionDurability::Durable =>
                {
                    matches!(
                        directive.write_disposition,
                        BlockFaultWriteDisposition::Apply
                            | BlockFaultWriteDisposition::Misdirected { .. }
                    )
                    .then_some(next.next_cache_sequence)
                }
                BlockOp::Flush
                    if matches!(
                        directive.flush_disposition,
                        BlockFaultFlushDisposition::Honest
                    ) =>
                {
                    Some(next.next_cache_sequence)
                }
                _ => None,
            })
            .flatten();
        let pending = BlockDeliveryPending {
            opportunity: BlockDeliveryOpportunity {
                request_sequence: directive.request_sequence,
                request: request.clone(),
                request_icount,
                ready_nanos,
                wire_digest: directive.request_digest,
                response,
                resolved: directive,
                required_durable_frontier,
            },
            delivery: None,
        };
        next.delivery_pending_bytes = next
            .delivery_pending_bytes
            .checked_add(delivery_pending_owned_bytes(&pending)?)
            .filter(|bytes| *bytes <= HARD_PENDING_BLOCK_FAULT_BYTES)
            .ok_or(DeviceError::BlockFaultStateLimit {
                field: "block_delivery_pending_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            })?;
        next.delivery_pending
            .insert(pending.opportunity.request_sequence, pending);
        *self = next;
        *durable = next_durable;
        Ok(())
    }

    /// Releases every computed completion with an installed deliver decision.
    pub(super) fn resume_delivery_to(
        &mut self,
        now_nanos: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let ready = next
            .delivery_pending
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.opportunity.ready_nanos <= now_nanos
                    && pending.delivery.is_some()
                    && pending
                        .opportunity
                        .required_durable_frontier
                        .is_none_or(|frontier| next.actual_durable_frontier >= frontier))
                .then_some((pending.opportunity.ready_nanos, *sequence))
            })
            .collect::<BTreeSet<_>>();
        let mut released = Vec::with_capacity(ready.len());
        for (ready_nanos, sequence) in ready {
            let pending = next.delivery_pending.remove(&sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready delivery opportunity disappeared",
                },
            )?;
            next.delivery_pending_bytes = next
                .delivery_pending_bytes
                .checked_sub(delivery_pending_owned_bytes(&pending)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "delivery-pending byte accounting underflow",
                })?;
            let directive = pending
                .delivery
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "ready delivery opportunity lost its decision",
                })?;
            let computed = next.finish_computed_response(
                &pending.opportunity.request,
                pending.opportunity.request_icount,
                pending.opportunity.response,
                0,
                &directive,
            )?;
            released.push(BlockDeferredResponse {
                finished_nanos: ready_nanos,
                request: pending.opportunity.request,
                request_icount: pending.opportunity.request_icount,
                computed,
            });
        }
        *self = next;
        Ok(released)
    }

    /// Advances service and executes every request released by all constraints.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when service state is malformed, persistence at
    /// an intervening boundary fails, or released device execution fails.
    pub(super) fn advance_service_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let outcomes = next.service.advance_to(now_nanos)?;
        if next
            .service_outcomes
            .len()
            .checked_add(outcomes.len())
            .is_none_or(|count| count > super::service::HARD_BLOCK_SERVICE_JOBS)
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "block_service_outcomes",
                hard: super::service::HARD_BLOCK_SERVICE_JOBS,
            });
        }
        let mut ready = BTreeMap::<(u64, u64), u64>::new();
        for outcome in &outcomes {
            let pending = next.service_pending.get_mut(&outcome.sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "service completion has no queued block request",
                },
            )?;
            if !pending.remaining_contributors.remove(&outcome.contributor) {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "service contributor completed a request twice",
                });
            }
            pending.finished_nanos = pending.finished_nanos.max(outcome.finished_nanos);
            if pending.remaining_contributors.is_empty() {
                ready.insert(
                    (pending.finished_nanos, pending.directive.request_sequence),
                    outcome.sequence,
                );
            }
        }
        let first_outcome = next.service_outcomes.len();
        let outcome_end =
            first_outcome
                .checked_add(outcomes.len())
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "block_service_outcomes",
                    hard: super::service::HARD_BLOCK_SERVICE_JOBS,
                })?;
        for index in first_outcome..outcome_end {
            next.storage_outcome_order
                .push(BlockStorageOutcomeRef::Service(index));
        }
        next.service_outcomes.extend(outcomes);
        let mut released = Vec::with_capacity(ready.len());
        for ((finished_nanos, _request_sequence), sequence) in ready {
            next.persist_due(base, &mut next_durable, finished_nanos)?;
            let mut pending = next.service_pending.remove(&sequence).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "ready service request disappeared",
                },
            )?;
            next.service_pending_bytes = next
                .service_pending_bytes
                .checked_sub(service_pending_owned_bytes(&pending)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "service-pending byte accounting underflow",
                })?;
            pending.directive.service_rules.clear();
            pending.directive.execution_nanos = finished_nanos;
            if !pending.directive.persistence_transforms.is_empty() {
                pending.directive.persistence_admitted_nanos = finished_nanos;
            }
            if next.execution_opportunities_required {
                next.defer_execution(
                    &pending.request,
                    pending.request_icount,
                    finished_nanos,
                    pending.directive,
                )?;
            } else {
                let computed = next.execute_immediate(
                    base,
                    &mut next_durable,
                    &pending.request,
                    pending.request_icount,
                    pending.directive,
                )?;
                released.push(BlockDeferredResponse {
                    finished_nanos,
                    request: pending.request,
                    request_icount: pending.request_icount,
                    computed,
                });
            }
        }
        next.persist_due(base, &mut next_durable, now_nanos)?;
        *self = next;
        *durable = next_durable;
        Ok(released)
    }

    pub(super) fn execute(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
    ) -> Result<ComputedResponse, DeviceError> {
        let identity = request.identity();
        let preserved_retry = self.retry_preserve_authorizations.contains(&identity);
        match self.transport_epoch {
            Some(epoch) if epoch != request.epoch && !preserved_retry => {
                return self
                    .dispose_retired_transport_request_if_needed(identity)?
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "stale block request did not produce a reset disposition",
                    })
                    .map(|primary| ComputedResponse {
                        primary: Some(primary),
                        additional: Vec::new(),
                        additional_latency_nanos: 0,
                    });
            }
            None => self.transport_epoch = Some(request.epoch),
            Some(_) => {}
        }
        let mut directive = match self.pending.get(&identity) {
            Some(directive) => directive.clone(),
            None if self.execution_required => {
                return Err(DeviceError::MissingBlockFaultDirective {
                    request_id: request.request_id,
                });
            }
            None => ResolvedBlockFaultDirective::fault_free(request, self.config.length_bytes),
        };
        directive.validate_for(request, &self.config)?;
        let arrival_nanos =
            crucible_shmem::icount_to_virtual_ns(request_icount, self.icount_shift)?;
        if self
            .recovery_until_nanos
            .is_some_and(|deadline| arrival_nanos < deadline)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block request crossed the host boundary during controller recovery",
            });
        }
        if self
            .recovery_until_nanos
            .is_some_and(|deadline| arrival_nanos >= deadline)
        {
            self.recovery_until_nanos = None;
        }
        if directive.retain_completion
            && self.retained_completions.contains_key(&request.identity())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "request identity already owns a retained completion",
            });
        }
        if directive.retain_completion
            && self.retained_completions.len() == HARD_BLOCK_RETAINED_COMPLETIONS
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "retained_completions",
                hard: HARD_BLOCK_RETAINED_COMPLETIONS,
            });
        }
        if !directive.service_rules.is_empty()
            && block_admission_error(request, &directive, &self.config).is_none()
        {
            if self
                .service_pending
                .values()
                .any(|pending| pending.request.request_id == request.request_id)
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "request identity is already queued for storage service",
                });
            }
            let admitted_nanos = directive.execution_nanos;
            let service_job = BlockServiceJob {
                sequence: directive.request_sequence,
                operation: request.op,
                bytes: u64::from(request.count),
                admitted_nanos,
            };
            let mut admitted_service = self.service.clone();
            match admitted_service.admit(service_job, &directive.service_rules) {
                Ok(()) => {}
                Err(DeviceError::BlockServiceQueueFull { .. }) => {
                    directive.service_rules.clear();
                    directive.error_result = Some(BlockFaultResult::Busy);
                }
                Err(error) => return Err(error),
            }
            if directive.service_rules.is_empty() {
                // Queue capacity is a modeled request rejection. Fall through
                // to consume the directive and return the stable Busy result.
            } else {
                let mut next = self.clone();
                if let Some(removed) = next.pending.remove(&identity) {
                    next.pending_bytes = next
                        .pending_bytes
                        .checked_sub(directive_owned_bytes(&removed)?)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "pending directive byte accounting underflow",
                        })?;
                }
                next.service = admitted_service;
                let remaining_contributors = directive
                    .service_rules
                    .iter()
                    .map(|rule| rule.contributor)
                    .collect();
                let pending = BlockServicePendingRequest {
                    request: request.clone(),
                    request_icount,
                    directive,
                    remaining_contributors,
                    finished_nanos: admitted_nanos,
                };
                let owned_bytes = service_pending_owned_bytes(&pending)?;
                next.service_pending_bytes = next
                    .service_pending_bytes
                    .checked_add(owned_bytes)
                    .filter(|total| *total <= HARD_PENDING_BLOCK_FAULT_BYTES)
                    .ok_or(DeviceError::BlockFaultStateLimit {
                        field: "block_service_pending_bytes",
                        hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                    })?;
                if next
                    .service_pending
                    .insert(pending.directive.request_sequence, pending)
                    .is_some()
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "storage service request sequence is repeated",
                    });
                }
                if preserved_retry {
                    let removed = next.retry_preserve_authorizations.remove(&identity);
                    debug_assert!(removed, "accepted preserved retry had authorization");
                }
                *self = next;
                return Ok(ComputedResponse {
                    primary: None,
                    additional: Vec::new(),
                    additional_latency_nanos: 0,
                });
            }
        }
        if self.execution_opportunities_required
            && block_admission_error(request, &directive, &self.config).is_none()
        {
            let mut next = self.clone();
            next.defer_execution(
                request,
                request_icount,
                directive.execution_nanos,
                directive,
            )?;
            if preserved_retry {
                let removed = next.retry_preserve_authorizations.remove(&identity);
                debug_assert!(removed, "accepted preserved retry had authorization");
            }
            *self = next;
            return Ok(ComputedResponse {
                primary: None,
                additional: Vec::new(),
                additional_latency_nanos: 0,
            });
        }
        let computed = self.execute_immediate(base, durable, request, request_icount, directive)?;
        if preserved_retry {
            let removed = self.retry_preserve_authorizations.remove(&identity);
            debug_assert!(removed, "accepted preserved retry had authorization");
        }
        Ok(computed)
    }

    pub(super) fn dispose_retired_transport_request_if_needed(
        &mut self,
        identity: BlockRequestIdentity,
    ) -> Result<Option<Response>, DeviceError> {
        if self.transport_epoch.is_none()
            || self.transport_epoch == Some(identity.epoch)
            || self.retry_preserve_authorizations.contains(&identity)
        {
            return Ok(None);
        }
        let policy = self
            .retired_transport_epochs
            .get(&identity.epoch)
            .copied()
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "block request epoch has no retained reset policy",
            })?;
        if policy.queued == BlockTransportPending::RetryPreserveId
            && self.retry_preserve_authorizations.len() == HARD_BLOCK_RETRY_PRESERVE_AUTHORIZATIONS
        {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "retry_preserve_authorizations",
                hard: HARD_BLOCK_RETRY_PRESERVE_AUTHORIZATIONS,
            });
        }

        let mut next = self.clone();
        if let Some(removed) = next.pending.remove(&identity) {
            next.pending_bytes = next
                .pending_bytes
                .checked_sub(directive_owned_bytes(&removed)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte accounting underflow",
                })?;
        }
        if policy.queued == BlockTransportPending::RetryPreserveId
            && !next.retry_preserve_authorizations.insert(identity)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block request already has a preserved-retry authorization",
            });
        }
        let response = transport_pending_response(identity, policy.queued, policy.failure_result)?;
        *self = next;
        Ok(Some(response))
    }

    fn execute_immediate(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<ComputedResponse, DeviceError> {
        let mut next = self.clone();
        if let Some(removed) = next.pending.remove(&request.identity()) {
            next.pending_bytes = next
                .pending_bytes
                .checked_sub(directive_owned_bytes(&removed)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte accounting underflow",
                })?;
        }
        let mut next_durable = durable.clone();
        let (response, persistence_wait_nanos) =
            next.execute_wire(base, &mut next_durable, request, &directive)?;
        let computed = next.finish_computed_response(
            request,
            request_icount,
            response,
            persistence_wait_nanos,
            &directive,
        )?;
        *self = next;
        *durable = next_durable;
        Ok(computed)
    }

    fn finish_computed_response(
        &mut self,
        request: &BlockRequest,
        request_icount: u64,
        response: BlockResponse,
        persistence_wait_nanos: u64,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<ComputedResponse, DeviceError> {
        let additional_latency_nanos = directive
            .additional_latency_nanos
            .checked_add(persistence_wait_nanos)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "storage persistence and completion latency overflow",
            })?;
        let encoded = response.encode().map_err(DeviceError::Codec)?;
        let status = if response.status == BlockStatus::Ok {
            ResponseStatus::Ok
        } else {
            ResponseStatus::Error
        };
        let primary = Response::new(request.request_id, status, encoded);
        if directive.retain_completion {
            self.retained_completions.insert(
                request.identity(),
                BlockRetainedCompletion {
                    identity: request.identity(),
                    recovery_response: primary.clone(),
                    timeout_response: block_response_to_uniform(
                        directive.retention_timeout_response.as_ref().ok_or(
                            DeviceError::InvalidBlockFaultDirective {
                                reason: "retained completion lost its timeout response",
                            },
                        )?,
                    )?,
                    request_icount,
                    additional_latency_nanos,
                    timeout_nanos: directive.retention_timeout_nanos.ok_or(
                        DeviceError::InvalidBlockFaultDirective {
                            reason: "retained completion lost its timeout coordinate",
                        },
                    )?,
                    recovery_event: directive.retention_recovery_event,
                    recovery_after_nanos: directive.retention_recovery_after_nanos,
                    persist_through_on_recovery: (request.op == BlockOp::Flush
                        && matches!(
                            directive.flush_disposition,
                            BlockFaultFlushDisposition::Stall
                        ))
                    .then_some(self.next_cache_sequence),
                },
            );
        }
        let additional = directive
            .duplicate_completions
            .iter()
            .map(|duplicate| {
                let (gap_nanos, response) = match duplicate {
                    ResolvedBlockDuplicateCompletion::Ignore { gap_nanos } => (
                        *gap_nanos,
                        block_response_to_uniform(&BlockResponse::ignored_duplicate(
                            request.identity(),
                        ))?,
                    ),
                    ResolvedBlockDuplicateCompletion::ProtocolError {
                        gap_nanos,
                        response,
                    } => (
                        *gap_nanos,
                        block_response_to_uniform(&BlockResponse::duplicate_protocol_error(
                            response,
                        ))?,
                    ),
                    ResolvedBlockDuplicateCompletion::Reset {
                        gap_nanos,
                        transition,
                    } => {
                        let next_epoch = match transition.request_ids {
                            BlockTransportRequestIds::PreserveMonotonic => request.epoch,
                            BlockTransportRequestIds::NewEpochFromZero => request
                                .epoch
                                .checked_add(1)
                                .ok_or(DeviceError::InvalidBlockFaultDirective {
                                    reason: "block transport epoch overflow",
                                })?,
                        };
                        (
                            *gap_nanos,
                            block_response_to_uniform(&BlockResponse::transport_reset(
                                request.identity(),
                                BlockTransportReset {
                                    next_epoch,
                                    recovery_nanos: transition.recovery_nanos,
                                    request_ids: transition.request_ids,
                                    reenumerate_declared: matches!(
                                        transition.topology,
                                        BlockTransitionTopology::ReenumerateDeclared
                                    ),
                                    preserve_duplicate_history: matches!(
                                        transition.duplicate_history,
                                        BlockTransitionState::Preserve
                                    ),
                                    failure_result: transition.failure_result,
                                    unadmitted: match transition.unadmitted {
                                        BlockTransitionUnadmitted::Reject => {
                                            BlockTransportUnadmitted::Reject
                                        }
                                        BlockTransitionUnadmitted::WaitForRecovery => {
                                            BlockTransportUnadmitted::WaitForRecovery
                                        }
                                    },
                                    queued: transport_pending(transition.queued),
                                    executing: transport_pending(transition.executing),
                                    resolved: match transition.resolved {
                                        BlockTransitionResolved::Complete => {
                                            BlockTransportResolved::Complete
                                        }
                                        BlockTransitionResolved::Fail => {
                                            BlockTransportResolved::Fail
                                        }
                                        BlockTransitionResolved::RetryPreserveId => {
                                            BlockTransportResolved::RetryPreserveId
                                        }
                                        BlockTransitionResolved::RetryNewId => {
                                            BlockTransportResolved::RetryNewId
                                        }
                                    },
                                    completed_undelivered: match transition.completed_undelivered {
                                        BlockTransitionUndelivered::Complete => {
                                            BlockTransportUndelivered::Complete
                                        }
                                        BlockTransitionUndelivered::Fail => {
                                            BlockTransportUndelivered::Fail
                                        }
                                        BlockTransitionUndelivered::RetryPreserveId => {
                                            BlockTransportUndelivered::RetryPreserveId
                                        }
                                        BlockTransitionUndelivered::RetryNewId => {
                                            BlockTransportUndelivered::RetryNewId
                                        }
                                        BlockTransitionUndelivered::DropCompletion => {
                                            BlockTransportUndelivered::DropCompletion
                                        }
                                    },
                                    preserve_controller_buffer: matches!(
                                        transition.controller_buffer,
                                        BlockTransitionState::Preserve
                                    ),
                                    preserve_volatile_cache: matches!(
                                        transition.volatile_cache,
                                        BlockTransitionState::Preserve
                                    ),
                                },
                            ))?,
                        )
                    }
                };
                Ok(AdditionalCompletion {
                    gap_nanos,
                    response,
                })
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        Ok(ComputedResponse {
            primary: (!directive.retain_completion).then_some(primary),
            additional,
            additional_latency_nanos,
        })
    }

    /// Applies one externally misdirected write without fabricating a guest request.
    ///
    /// The destination uses its own geometry and normal durability policy. The
    /// multi-device owner is responsible for executing this method on cloned
    /// source/destination devices and committing both together.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for destination range, atomicity, cache, retained
    /// version, or durable-overlay failures.
    pub(super) fn apply_external_write(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request_id: u32,
        destination_offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), DeviceError> {
        let request = BlockRequest::write(request_id, destination_offset, bytes);
        let directive = ResolvedBlockFaultDirective::fault_free(&request, self.config.length_bytes);
        directive.validate_for(&request, &self.config)?;
        if u64::from(request.count) > self.config.maximum_request_bytes
            || !request_in_capacity(&request, self.config.length_bytes)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external write exceeds destination capacity or request geometry",
            });
        }
        match self.apply_write(base, durable, &request, &directive)? {
            BlockWriteOutcome::Applied(_persistence_wait_nanos) => Ok(()),
            BlockWriteOutcome::Rejected(_) => Err(DeviceError::BlockCacheFull {
                requested_bytes: u64::from(request.count),
                available_bytes: self
                    .config
                    .volatile_cache_bytes
                    .saturating_sub(self.volatile_bytes),
            }),
        }
    }

    fn execute_wire(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<(BlockResponse, u64), DeviceError> {
        let admission_error = block_admission_error(request, directive, &self.config);
        let media_error = if admission_error.is_none() && directive.error_result.is_none() {
            self.media.apply(
                request,
                directive.execution_nanos,
                self.config.length_bytes,
                &directive.media_rules,
            )?
        } else {
            None
        };
        let error = admission_error.or(directive.error_result).or(media_error);
        if let Some(error) = error {
            return Ok((BlockResponse::error_for(request.identity(), error), 0));
        }
        match request.op {
            BlockOp::Read => {
                let mut bytes =
                    self.read_visible(base, durable, request.offset, request.count, true)?;
                if !directive.persistence_media_rules.is_empty() {
                    self.flash.read(
                        request,
                        directive.execution_nanos,
                        self.config.length_bytes,
                        &directive.persistence_media_rules,
                        &mut bytes,
                    )?;
                }
                self.flash
                    .apply_persistent_read(request.offset, &mut bytes)?;
                apply_read_transforms(&mut bytes, &directive.read_transforms)?;
                Ok((BlockResponse::ok_for(request.identity(), bytes), 0))
            }
            BlockOp::Write => match self.apply_write(base, durable, request, directive)? {
                BlockWriteOutcome::Applied(wait) => {
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), wait))
                }
                BlockWriteOutcome::Rejected(result) => {
                    Ok((BlockResponse::error_for(request.identity(), result), 0))
                }
            },
            BlockOp::Discard => self.apply_discard(base, durable, request, directive),
            BlockOp::Flush => match directive.flush_disposition {
                BlockFaultFlushDisposition::Honest => {
                    let frontier = self.next_cache_sequence;
                    let wait = self.persist_all(base, durable, directive.execution_nanos)?;
                    if wait == 0 {
                        self.reported_durable_frontier = self.actual_durable_frontier;
                    } else {
                        self.pending_barrier_frontier = Some(
                            self.pending_barrier_frontier
                                .map_or(frontier, |existing| existing.max(frontier)),
                        );
                        self.pending_honest_flush_frontier = Some(
                            self.pending_honest_flush_frontier
                                .map_or(frontier, |existing| existing.max(frontier)),
                        );
                    }
                    if self.actual_durable_frontier >= frontier {
                        self.pending_barrier_frontier = None;
                    }
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), wait))
                }
                BlockFaultFlushDisposition::Error(error) => {
                    Ok((BlockResponse::error_for(request.identity(), error), 0))
                }
                BlockFaultFlushDisposition::Lie => {
                    let frontier = self.next_cache_sequence;
                    self.reported_durable_frontier = frontier;
                    self.pending_barrier_frontier = Some(
                        self.pending_barrier_frontier
                            .map_or(frontier, |existing| existing.max(frontier)),
                    );
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), 0))
                }
                BlockFaultFlushDisposition::Stall => {
                    let frontier = self.next_cache_sequence;
                    self.pending_barrier_frontier = Some(
                        self.pending_barrier_frontier
                            .map_or(frontier, |existing| existing.max(frontier)),
                    );
                    Ok((BlockResponse::ok_for(request.identity(), Vec::new()), 0))
                }
            },
            BlockOp::GetLength => Ok((
                BlockResponse::ok_for(
                    request.identity(),
                    directive.reported_capacity_bytes.to_le_bytes().to_vec(),
                ),
                0,
            )),
        }
    }

    fn apply_discard(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<(BlockResponse, u64), DeviceError> {
        let granularity = u64::from(self.config.discard_granularity_bytes);
        if granularity == 0
            || request.count == 0
            || !request.offset.is_multiple_of(granularity)
            || !u64::from(request.count).is_multiple_of(granularity)
        {
            return Ok((
                BlockResponse::error_for(request.identity(), BlockErrorCode::InvalidRange),
                0,
            ));
        }
        if self.config.discard_semantics == BlockDiscardSemantics::ReadsOldData
            && directive.persistence_media_rules.is_empty()
        {
            return Ok((BlockResponse::ok_for(request.identity(), Vec::new()), 0));
        }
        let count = usize::try_from(request.count).map_err(|_error| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "discard range does not fit memory",
            }
        })?;
        let bytes = if !directive.persistence_media_rules.is_empty() {
            vec![0xff; count]
        } else {
            match self.config.discard_semantics {
                BlockDiscardSemantics::DeterministicZero => vec![0; count],
                BlockDiscardSemantics::ReadsOldData => Vec::new(),
                BlockDiscardSemantics::UndefinedKeyed => {
                    keyed_discard_bytes(base.hash(), request, count)
                }
            }
        };
        let mut write = request.clone();
        write.data = bytes;
        match self.apply_write(base, durable, &write, directive)? {
            BlockWriteOutcome::Applied(wait) => {
                Ok((BlockResponse::ok_for(request.identity(), Vec::new()), wait))
            }
            BlockWriteOutcome::Rejected(result) => {
                Ok((BlockResponse::error_for(request.identity(), result), 0))
            }
        }
    }

    fn read_visible(
        &mut self,
        base: &BaseImage,
        durable: &CowOverlay,
        offset: u64,
        count: u32,
        record_cache_access: bool,
    ) -> Result<Vec<u8>, DeviceError> {
        let mut bytes = durable.read(base, offset, u64::from(count))?;
        let end = offset.checked_add(u64::from(count)).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "read range overflow",
            },
        )?;
        let visible = self
            .controller
            .iter()
            .map(|(sequence, entry)| (*sequence, (entry.offset, entry.bytes.as_slice())))
            .chain(
                self.volatile
                    .iter()
                    .map(|(sequence, entry)| (*sequence, (entry.offset, entry.bytes.as_slice()))),
            )
            .chain(
                self.media_queue
                    .iter()
                    .map(|(sequence, entry)| (*sequence, (entry.offset, entry.bytes.as_slice()))),
            )
            .map(|(sequence, (entry_offset, entry_bytes))| {
                (sequence, (entry_offset, entry_bytes.to_vec()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut accessed = Vec::new();
        for (sequence, (entry_offset, entry_bytes)) in &visible {
            let entry_end = entry_offset
                .checked_add(u64::try_from(entry_bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "volatile entry range overflow",
                })?;
            let overlap_start = offset.max(*entry_offset);
            let overlap_end = end.min(entry_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let destination = usize::try_from(overlap_start - offset).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "read overlap does not fit memory",
                }
            })?;
            let source = usize::try_from(overlap_start - *entry_offset).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "cache overlap does not fit memory",
                }
            })?;
            let length = usize::try_from(overlap_end - overlap_start).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "cache overlap length does not fit memory",
                }
            })?;
            bytes[destination..destination + length]
                .copy_from_slice(&entry_bytes[source..source + length]);
            if record_cache_access
                && self.volatile.contains_key(sequence)
                && entry_contributes_visible(*sequence, overlap_start, overlap_end, &visible)
            {
                accessed.push(*sequence);
            }
        }
        for sequence in accessed {
            let access_sequence = self.next_cache_access_sequence;
            self.next_cache_access_sequence = self
                .next_cache_access_sequence
                .checked_add(1)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "cache access sequence overflow",
                })?;
            if let Some(entry) = self.volatile.get_mut(&sequence) {
                entry.last_access_sequence = access_sequence;
            }
        }
        Ok(bytes)
    }

    fn apply_write(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<BlockWriteOutcome, DeviceError> {
        let intended_spans = canonical_atomic_spans(
            request.offset,
            u64::from(request.count),
            u64::from(self.config.atomic_write_bytes),
        )?;
        let (destination, spans) = match &directive.write_disposition {
            BlockFaultWriteDisposition::Apply => (request.offset, intended_spans.clone()),
            BlockFaultWriteDisposition::Lost => (request.offset, Vec::new()),
            BlockFaultWriteDisposition::Torn { spans }
            | BlockFaultWriteDisposition::ProgramFailure { spans } => {
                (request.offset, spans.clone())
            }
            BlockFaultWriteDisposition::Misdirected { destination_offset } => {
                (*destination_offset, intended_spans.clone())
            }
        };
        let mut resolved = Vec::with_capacity(spans.len());
        let mut admitted_bytes = 0_u64;
        for (fragment_index, span) in intended_spans.iter().enumerate() {
            if !spans.iter().any(|selected| {
                selected.start <= span.start
                    && selected
                        .end()
                        .zip(span.end())
                        .is_some_and(|(selected_end, fragment_end)| selected_end >= fragment_end)
            }) {
                continue;
            }
            let start = usize::try_from(span.start).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write span does not fit memory",
                }
            })?;
            let end = usize::try_from(span.end().unwrap_or(u64::MAX)).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write span end does not fit memory",
                }
            })?;
            let offset = destination.checked_add(span.start).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write destination overflow",
                },
            )?;
            let bytes =
                request
                    .data
                    .get(start..end)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "write span exceeds request data",
                    })?;
            let byte_count = u64::try_from(bytes.len()).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write span length does not fit the device geometry",
                }
            })?;
            let range_end =
                offset
                    .checked_add(byte_count)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "write destination range overflow",
                    })?;
            if range_end > self.config.length_bytes {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "write destination exceeds the physical device",
                });
            }
            admitted_bytes = admitted_bytes.checked_add(byte_count).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write admission byte count overflow",
                },
            )?;
            resolved.push((fragment_index, offset, bytes));
        }

        let controller = directive.cache_policy.is_none()
            && self.config.completion_durability == BlockCompletionDurability::ControllerAccepted;
        let cache = directive.cache_policy.is_some()
            || self.config.completion_durability
                == BlockCompletionDurability::VolatileCacheAccepted;
        if controller {
            let available_entries = usize::try_from(self.config.controller_entries)
                .unwrap_or(usize::MAX)
                .saturating_sub(self.controller.len());
            let available_bytes = self
                .config
                .controller_buffer_bytes
                .saturating_sub(self.controller_bytes);
            if resolved.len() > available_entries || admitted_bytes > available_bytes {
                return Ok(BlockWriteOutcome::Rejected(BlockFaultResult::Busy));
            }
        } else if cache {
            let rejection = match directive.cache_policy {
                Some(policy) => self.prepare_cache_admission(
                    base,
                    durable,
                    resolved.len(),
                    admitted_bytes,
                    policy,
                    directive.execution_nanos,
                )?,
                None => {
                    let available_entries = usize::try_from(self.config.cache_entries)
                        .unwrap_or(usize::MAX)
                        .saturating_sub(self.volatile.len());
                    if resolved.len() <= available_entries
                        && admitted_bytes
                            <= self
                                .config
                                .volatile_cache_bytes
                                .saturating_sub(self.volatile_bytes)
                    {
                        None
                    } else {
                        Some(BlockFaultResult::Busy)
                    }
                }
            };
            if let Some(result) = rejection {
                return Ok(BlockWriteOutcome::Rejected(result));
            }
        }
        let sequence_count = u64::try_from(intended_spans.len()).map_err(|_error| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "intended write fragment count does not fit the sequence space",
            }
        })?;
        let first_sequence = self.next_cache_sequence;
        let media_identity = BlockMediaOperationIdentity {
            operation: request.op,
            operation_sequence: first_sequence,
            request_digest: directive.request_digest,
            request_offset: request.offset,
            request_count: request.count,
        };
        self.next_cache_sequence = self.next_cache_sequence.checked_add(sequence_count).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "write durability sequence overflow",
            },
        )?;
        let version_count = u64::try_from(resolved.len()).map_err(|_error| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "retained version count does not fit the sequence space",
            }
        })?;
        self.next_version_sequence
            .checked_add(version_count)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "retained version sequence overflow",
            })?;
        let applied_fragments = resolved
            .iter()
            .map(|(fragment_index, _, _)| *fragment_index)
            .collect::<BTreeSet<_>>();
        for fragment_index in 0..intended_spans.len() {
            if !applied_fragments.contains(&fragment_index) {
                let sequence = first_sequence
                    .checked_add(u64::try_from(fragment_index).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "lost write fragment sequence overflow",
                    })?;
                self.first_lost_sequence = Some(
                    self.first_lost_sequence
                        .map_or(sequence, |existing| existing.min(sequence)),
                );
            }
        }

        let persistence_fragments = resolved
            .iter()
            .map(|(fragment_index, offset, bytes)| {
                let sequence = first_sequence
                    .checked_add(u64::try_from(*fragment_index).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "persistence fragment sequence overflow",
                    })?;
                Ok((
                    sequence,
                    BlockWriteFragmentId {
                        request_id: request.request_id,
                        fragment_index: u32::try_from(*fragment_index).map_err(|_error| {
                            DeviceError::InvalidBlockFaultDirective {
                                reason: "persistence fragment index exceeds u32",
                            }
                        })?,
                        start: *offset,
                        length: u64::try_from(bytes.len()).map_err(|_error| {
                            DeviceError::InvalidBlockFaultDirective {
                                reason: "persistence fragment length overflow",
                            }
                        })?,
                    },
                ))
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        self.persistence.admit_request_with_barrier(
            &persistence_fragments,
            directive.persistence_admitted_nanos,
            &directive.persistence_transforms,
            self.pending_barrier_frontier,
        )?;
        if !directive.persistence_media_rules.is_empty() {
            self.flash
                .register_rules(self.config.length_bytes, &directive.persistence_media_rules)?;
            let next_count = self
                .pending_persistence_media
                .len()
                .checked_add(resolved.len())
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "pending_persistence_media",
                    hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
                })?;
            if next_count > HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS {
                return Err(DeviceError::BlockFaultStateLimit {
                    field: "pending_persistence_media",
                    hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
                });
            }
            for (fragment_index, offset, bytes) in &resolved {
                let sequence = first_sequence
                    .checked_add(u64::try_from(*fragment_index).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "persistence-media sequence overflow",
                    })?;
                self.pending_persistence_media.insert(
                    sequence,
                    ResolvedBlockPersistenceMediaDirective {
                        opportunity: BlockPersistenceOpportunity {
                            sequence,
                            request_id: request.request_id,
                            operation_sequence: media_identity.operation_sequence,
                            operation: media_identity.operation,
                            request_digest: media_identity.request_digest,
                            offset: *offset,
                            count: u32::try_from(bytes.len()).map_err(|_error| {
                                DeviceError::InvalidBlockFaultDirective {
                                    reason: "persistence-media fragment exceeds request width",
                                }
                            })?,
                            intended_digest: *blake3::hash(bytes).as_bytes(),
                            ready_nanos: self.persistence.deadline_nanos(sequence).unwrap_or(0),
                        },
                        flash_rules: directive.persistence_media_rules.clone(),
                    },
                );
            }
        }

        for (fragment_index, offset, bytes) in resolved {
            let sequence = first_sequence
                .checked_add(u64::try_from(fragment_index).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "applied write fragment sequence overflow",
                })?;
            self.retain_prior(
                base,
                durable,
                offset,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            )?;
            if controller {
                self.controller_write(
                    sequence,
                    request.request_id,
                    media_identity,
                    offset,
                    bytes.to_vec(),
                )?;
            } else if cache {
                self.cache_write(
                    sequence,
                    request.request_id,
                    media_identity,
                    offset,
                    bytes.to_vec(),
                    directive
                        .cache_policy
                        .is_some_and(|policy| policy.power_loss_protected),
                )?;
            } else {
                self.media_queue_write(
                    sequence,
                    request.request_id,
                    media_identity,
                    offset,
                    bytes.to_vec(),
                )?;
            }
        }
        let persistence_wait_nanos = if !cache && !controller {
            self.persist_through(
                base,
                durable,
                self.next_cache_sequence,
                directive.execution_nanos,
            )?
        } else {
            0
        };
        self.recompute_actual_durable_frontier();
        if !cache && !controller {
            self.reported_durable_frontier = self.actual_durable_frontier;
        }
        Ok(BlockWriteOutcome::Applied(persistence_wait_nanos))
    }

    fn retain_prior(
        &mut self,
        base: &BaseImage,
        durable: &CowOverlay,
        offset: u64,
        length: u64,
    ) -> Result<(), DeviceError> {
        if self.retained.len()
            == usize::try_from(self.config.retained_versions).unwrap_or(usize::MAX)
        {
            let oldest = self.retained.keys().next().copied().ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "retained-version accounting is empty at capacity",
                },
            )?;
            self.retained.remove(&oldest);
        }
        let bytes = self.read_visible(
            base,
            durable,
            offset,
            u32::try_from(length).map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                reason: "retained range exceeds request width",
            })?,
            false,
        )?;
        let sequence = self.next_version_sequence;
        self.next_version_sequence = self.next_version_sequence.checked_add(1).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "retained version sequence overflow",
            },
        )?;
        self.retained.insert(
            sequence,
            BlockRetainedVersion {
                sequence,
                offset,
                bytes,
            },
        );
        Ok(())
    }

    fn cache_write(
        &mut self,
        sequence: u64,
        request_id: u32,
        media_identity: BlockMediaOperationIdentity,
        offset: u64,
        bytes: Vec<u8>,
        power_loss_protected: bool,
    ) -> Result<(), DeviceError> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let next_bytes = self.volatile_bytes.checked_add(length).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "volatile byte count overflow",
            },
        )?;
        if self.volatile.len() == usize::try_from(self.config.cache_entries).unwrap_or(usize::MAX)
            || next_bytes > self.config.volatile_cache_bytes
        {
            return Err(DeviceError::BlockCacheFull {
                requested_bytes: length,
                available_bytes: self
                    .config
                    .volatile_cache_bytes
                    .saturating_sub(self.volatile_bytes),
            });
        }
        let access_sequence = self.next_cache_access_sequence;
        self.next_cache_access_sequence = self.next_cache_access_sequence.checked_add(1).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "cache access sequence overflow",
            },
        )?;
        self.volatile.insert(
            sequence,
            BlockVolatileEntry {
                sequence,
                request_id,
                media_identity,
                offset,
                bytes,
                last_access_sequence: access_sequence,
                power_loss_protected,
            },
        );
        self.volatile_bytes = next_bytes;
        Ok(())
    }

    fn prepare_cache_admission(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        incoming_entries: usize,
        incoming_bytes: u64,
        policy: ResolvedBlockCachePolicy,
        now_nanos: u64,
    ) -> Result<Option<BlockFaultResult>, DeviceError> {
        let mut next = self.clone();
        let mut next_durable = durable.clone();
        let rejection = next.prepare_cache_admission_staged(
            base,
            &mut next_durable,
            incoming_entries,
            incoming_bytes,
            policy,
            now_nanos,
        )?;
        if rejection.is_none() {
            *self = next;
            *durable = next_durable;
        }
        Ok(rejection)
    }

    fn prepare_cache_admission_staged(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        incoming_entries: usize,
        incoming_bytes: u64,
        policy: ResolvedBlockCachePolicy,
        now_nanos: u64,
    ) -> Result<Option<BlockFaultResult>, DeviceError> {
        let entry_capacity = usize::try_from(self.config.cache_entries).unwrap_or(usize::MAX);
        if incoming_entries > entry_capacity || incoming_bytes > policy.capacity_bytes {
            return Ok(Some(BlockFaultResult::Busy));
        }
        while self
            .volatile
            .len()
            .checked_add(incoming_entries)
            .is_none_or(|entries| entries > entry_capacity)
            || self
                .volatile_bytes
                .checked_add(incoming_bytes)
                .is_none_or(|bytes| bytes > policy.capacity_bytes)
        {
            if let BlockFaultDirtyEviction::Fail(result) = policy.dirty_eviction {
                return Ok(Some(result));
            }
            let Some(victim) = (match policy.eviction {
                BlockFaultCacheEviction::Fifo => self
                    .volatile
                    .values()
                    .filter(|entry| self.persistence.is_ready(entry.sequence))
                    .min_by_key(|entry| entry.sequence)
                    .map(|entry| entry.sequence),
                BlockFaultCacheEviction::Lru => self
                    .volatile
                    .values()
                    .filter(|entry| self.persistence.is_ready(entry.sequence))
                    .min_by_key(|entry| (entry.last_access_sequence, entry.sequence))
                    .map(|entry| entry.sequence),
                BlockFaultCacheEviction::WritebackSequence => self
                    .volatile
                    .keys()
                    .filter(|sequence| self.persistence.is_ready(**sequence))
                    .filter_map(|sequence| {
                        self.persistence
                            .writeback_key(*sequence)
                            .map(|key| (key, *sequence))
                    })
                    .min_by_key(|(key, _sequence)| *key)
                    .map(|(_key, sequence)| sequence),
            }) else {
                return Ok(Some(BlockFaultResult::Busy));
            };
            self.schedule_volatile_persistence(victim)?;
        }
        if !self.persistence_execution_required {
            self.persist_due(base, durable, now_nanos)?;
        }
        Ok(None)
    }

    fn schedule_volatile_persistence(&mut self, sequence: u64) -> Result<(), DeviceError> {
        let entry = self.volatile.get(&sequence).cloned().ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "cache eviction selected an absent volatile fragment",
            },
        )?;
        self.media_queue_write(
            entry.sequence,
            entry.request_id,
            entry.media_identity,
            entry.offset,
            entry.bytes.clone(),
        )?;
        let removed =
            self.volatile
                .remove(&sequence)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "cache eviction fragment disappeared",
                })?;
        self.volatile_bytes = self
            .volatile_bytes
            .checked_sub(u64::try_from(removed.bytes.len()).unwrap_or(u64::MAX))
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile byte accounting underflow during persistence scheduling",
            })?;
        Ok(())
    }

    pub(super) fn persist_due(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<(), DeviceError> {
        loop {
            let sequence = self
                .media_queue
                .keys()
                .filter(|sequence| self.persistence.is_ready_at(**sequence, now_nanos))
                .filter(|sequence| {
                    !self.persistence_execution_required
                        || self.pending_persistence_media.contains_key(sequence)
                })
                .filter_map(|sequence| {
                    self.persistence
                        .writeback_key(*sequence)
                        .map(|key| (key, *sequence))
                })
                .min_by_key(|(key, _sequence)| *key)
                .map(|(_key, sequence)| sequence);
            let Some(sequence) = sequence else {
                break;
            };
            self.persist_sequence(base, durable, sequence, now_nanos)?;
        }
        self.recompute_actual_durable_frontier();
        if self
            .pending_honest_flush_frontier
            .is_some_and(|frontier| self.actual_durable_frontier >= frontier)
        {
            self.reported_durable_frontier = self.actual_durable_frontier;
            self.pending_honest_flush_frontier = None;
        }
        Ok(())
    }

    fn controller_write(
        &mut self,
        sequence: u64,
        request_id: u32,
        media_identity: BlockMediaOperationIdentity,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), DeviceError> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.controller_bytes = self.controller_bytes.checked_add(length).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "controller byte count overflow",
            },
        )?;
        self.controller.insert(
            sequence,
            BlockControllerEntry {
                sequence,
                request_id,
                media_identity,
                offset,
                bytes,
            },
        );
        Ok(())
    }

    fn media_queue_write(
        &mut self,
        sequence: u64,
        request_id: u32,
        media_identity: BlockMediaOperationIdentity,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), DeviceError> {
        if self.media_queue.contains_key(&sequence) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "media-queue sequence is already present",
            });
        }
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let next_bytes = self.media_queue_bytes.checked_add(length).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "media-queue byte count overflow",
            },
        )?;
        if next_bytes > HARD_BLOCK_MEDIA_QUEUE_BYTES {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "media-queue byte count exceeds its hard bound",
            });
        }
        self.media_queue_bytes = next_bytes;
        self.media_queue.insert(
            sequence,
            BlockControllerEntry {
                sequence,
                request_id,
                media_identity,
                offset,
                bytes,
            },
        );
        Ok(())
    }

    fn persist_all(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_nanos: u64,
    ) -> Result<u64, DeviceError> {
        self.persist_through(base, durable, self.next_cache_sequence, now_nanos)
    }

    fn persist_through(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        frontier: u64,
        now_nanos: u64,
    ) -> Result<u64, DeviceError> {
        if frontier > self.next_cache_sequence {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "flush persistence frontier exceeds issued storage sequence",
            });
        }
        let controller = self
            .controller
            .keys()
            .copied()
            .filter(|sequence| *sequence < frontier)
            .collect::<Vec<_>>();
        for sequence in controller {
            self.schedule_controller_persistence(sequence)?;
        }
        let volatile = self
            .volatile
            .keys()
            .copied()
            .filter(|sequence| *sequence < frontier)
            .collect::<Vec<_>>();
        for sequence in volatile {
            self.schedule_volatile_persistence(sequence)?;
        }
        if !self.persistence_execution_required {
            self.persist_due(base, durable, now_nanos)?;
        }
        let wait = self
            .media_queue
            .keys()
            .copied()
            .filter(|sequence| *sequence < frontier)
            .filter_map(|sequence| self.persistence.deadline_nanos(sequence))
            .map(|deadline| deadline.saturating_sub(now_nanos))
            .max()
            .unwrap_or(0);
        self.recompute_actual_durable_frontier();
        Ok(wait)
    }

    fn schedule_controller_persistence(&mut self, sequence: u64) -> Result<(), DeviceError> {
        let entry = self.controller.get(&sequence).cloned().ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "persistence selected an absent controller fragment",
            },
        )?;
        self.media_queue_write(
            entry.sequence,
            entry.request_id,
            entry.media_identity,
            entry.offset,
            entry.bytes.clone(),
        )?;
        let removed =
            self.controller
                .remove(&sequence)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "controller persistence fragment disappeared",
                })?;
        self.controller_bytes = self
            .controller_bytes
            .checked_sub(u64::try_from(removed.bytes.len()).unwrap_or(u64::MAX))
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "controller byte accounting underflow during persistence scheduling",
            })?;
        Ok(())
    }

    fn persist_sequence(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        sequence: u64,
        now_nanos: u64,
    ) -> Result<(), DeviceError> {
        let (request_id, media_identity, offset, bytes) =
            if let Some(entry) = self.controller.get(&sequence) {
                (
                    entry.request_id,
                    entry.media_identity,
                    entry.offset,
                    entry.bytes.clone(),
                )
            } else if let Some(entry) = self.media_queue.get(&sequence) {
                (
                    entry.request_id,
                    entry.media_identity,
                    entry.offset,
                    entry.bytes.clone(),
                )
            } else if let Some(entry) = self.volatile.get(&sequence) {
                (
                    entry.request_id,
                    entry.media_identity,
                    entry.offset,
                    entry.bytes.clone(),
                )
            } else {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "ready persistence fragment has no owning storage layer",
                });
            };
        let opportunity = self.persistence_opportunity(sequence).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "persistence opportunity disappeared",
            },
        )?;
        let directive = self.pending_persistence_media.remove(&sequence);
        if self.persistence_execution_required && directive.is_none() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "missing resolved persistence-media directive",
            });
        }
        let flash = directive.map_or(
            Ok(BlockFlashMutationOutcome {
                spans: vec![BlockFaultByteSpan {
                    start: 0,
                    length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                }],
                failed: false,
            }),
            |directive| {
                let contributors = directive
                    .flash_rules
                    .iter()
                    .map(|rule| rule.contributor)
                    .collect::<Vec<_>>();
                match media_identity.operation {
                    BlockOp::Write => {
                        let request = BlockRequest::write(request_id, offset, bytes.clone());
                        self.flash.program_registered(
                            &request,
                            now_nanos,
                            self.config.length_bytes,
                            &contributors,
                        )
                    }
                    BlockOp::Discard => self.flash.erase_fragment_registered(
                        media_identity.operation_sequence,
                        media_identity.request_offset,
                        media_identity.request_count,
                        offset,
                        &bytes,
                        now_nanos,
                        self.config.length_bytes,
                        &contributors,
                    ),
                    _ => Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "physical persistence operation is not write or discard",
                    }),
                }
            },
        )?;
        let mut programmed = Vec::new();
        for span in &flash.spans {
            let start = usize::try_from(span.start).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "flash program span start does not fit memory",
                }
            })?;
            let end = usize::try_from(span.end().unwrap_or(u64::MAX)).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "flash program span end does not fit memory",
                }
            })?;
            let selected =
                bytes
                    .get(start..end)
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "flash program span exceeds persistence fragment",
                    })?;
            durable.write(base, offset.saturating_add(span.start), selected)?;
            programmed.extend_from_slice(selected);
        }
        self.persistence.commit_persisted(sequence)?;
        if let Some(entry) = self.controller.remove(&sequence) {
            self.controller_bytes = self
                .controller_bytes
                .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "controller byte accounting underflow during persistence",
                })?;
        } else if let Some(entry) = self.media_queue.remove(&sequence) {
            self.media_queue_bytes = self
                .media_queue_bytes
                .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "media-queue byte accounting underflow during persistence",
                })?;
        } else if let Some(entry) = self.volatile.remove(&sequence) {
            self.volatile_bytes = self
                .volatile_bytes
                .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "volatile byte accounting underflow during persistence",
                })?;
        } else {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persisted fragment disappeared from its storage layer",
            });
        }
        if self.persistence_media_outcomes.len() == HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "persistence_media_outcomes",
                hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
            });
        }
        let outcome_index = self.persistence_media_outcomes.len();
        self.persistence_media_outcomes
            .push(BlockPersistenceMediaOutcome {
                opportunity,
                executed_nanos: now_nanos,
                applied_spans: flash.spans,
                media_failed: flash.failed,
                applied_digest: *blake3::hash(&programmed).as_bytes(),
            });
        self.storage_outcome_order
            .push(BlockStorageOutcomeRef::Persistence(outcome_index));
        self.recompute_actual_durable_frontier();
        Ok(())
    }

    fn persistence_opportunity(&self, sequence: u64) -> Option<BlockPersistenceOpportunity> {
        let entry = self
            .controller
            .get(&sequence)
            .map(|entry| {
                (
                    entry.request_id,
                    entry.media_identity,
                    entry.offset,
                    entry.bytes.as_slice(),
                )
            })
            .or_else(|| {
                self.media_queue.get(&sequence).map(|entry| {
                    (
                        entry.request_id,
                        entry.media_identity,
                        entry.offset,
                        entry.bytes.as_slice(),
                    )
                })
            })
            .or_else(|| {
                self.volatile.get(&sequence).map(|entry| {
                    (
                        entry.request_id,
                        entry.media_identity,
                        entry.offset,
                        entry.bytes.as_slice(),
                    )
                })
            })?;
        Some(BlockPersistenceOpportunity {
            sequence,
            request_id: entry.0,
            operation_sequence: entry.1.operation_sequence,
            operation: entry.1.operation,
            request_digest: entry.1.request_digest,
            offset: entry.2,
            count: u32::try_from(entry.3.len()).ok()?,
            intended_digest: *blake3::hash(entry.3).as_bytes(),
            ready_nanos: self.persistence.deadline_nanos(sequence).unwrap_or(0),
        })
    }

    fn validate_persistence_media_directive(
        &self,
        directive: &ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), DeviceError> {
        if self
            .persistence_opportunity(directive.opportunity.sequence)
            .as_ref()
            != Some(&directive.opportunity)
            || directive
                .flash_rules
                .windows(2)
                .any(|pair| pair[0].contributor >= pair[1].contributor)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "persistence-media directive does not match its live opportunity",
            });
        }
        for rule in &directive.flash_rules {
            rule.validate(self.config.length_bytes)?;
        }
        Ok(())
    }

    fn recompute_actual_durable_frontier(&mut self) {
        self.actual_durable_frontier = self
            .controller
            .keys()
            .next()
            .copied()
            .into_iter()
            .chain(self.volatile.keys().next().copied())
            .chain(self.media_queue.keys().next().copied())
            .chain(self.first_lost_sequence)
            .min()
            .unwrap_or(self.next_cache_sequence);
        if self.pending_barrier_frontier.is_some_and(|frontier| {
            !self
                .persistence
                .nodes()
                .keys()
                .any(|sequence| *sequence < frontier)
        }) {
            self.pending_barrier_frontier = None;
        }
    }
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
    if let BlockFaultWriteDisposition::Misdirected { destination_offset } = disposition
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
mod tests {
    use super::*;

    fn state(durability: BlockCompletionDurability) -> BlockFaultState {
        BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 1,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 64,
            cache_entries: 64,
            controller_buffer_bytes: 64,
            controller_entries: 64,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: durability,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"))
    }

    fn reset_transition() -> ResolvedBlockControllerTransition {
        ResolvedBlockControllerTransition {
            failure_result: BlockFaultResult::Offline,
            unadmitted: BlockTransitionUnadmitted::Reject,
            queued: BlockTransitionPending::Fail,
            executing: BlockTransitionPending::RetryPreserveId,
            resolved: BlockTransitionResolved::Complete,
            completed_undelivered: BlockTransitionUndelivered::Complete,
            controller_buffer: BlockTransitionState::Preserve,
            volatile_cache: BlockTransitionState::Preserve,
            request_ids: BlockTransportRequestIds::NewEpochFromZero,
            duplicate_history: BlockTransitionState::Lose,
            topology: BlockTransitionTopology::ReenumerateDeclared,
            recovery_nanos: 50,
        }
    }

    fn response(
        state: &mut BlockFaultState,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        mutate: impl FnOnce(&mut ResolvedBlockFaultDirective),
    ) -> BlockResponse {
        let mut directive = ResolvedBlockFaultDirective::fault_free(request, base.len());
        mutate(&mut directive);
        state
            .install(request.identity(), directive)
            .unwrap_or_else(|error| panic!("directive installs: {error}"));
        let computed = state
            .execute(base, durable, request, 0)
            .unwrap_or_else(|error| panic!("request executes: {error}"));
        let primary = computed
            .primary
            .unwrap_or_else(|| panic!("test request unexpectedly retained"));
        BlockResponse::decode(&primary.payload)
            .unwrap_or_else(|error| panic!("response decodes: {error}"))
    }

    fn read(
        state: &mut BlockFaultState,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request_id: u32,
        offset: u64,
        count: u32,
    ) -> Vec<u8> {
        response(
            state,
            base,
            durable,
            &BlockRequest::read(request_id, offset, count),
            |_| {},
        )
        .data
    }

    #[test]
    fn latent_media_failure_changes_future_real_request_results() {
        let base = BaseImage::new(vec![0x5a; 32]);
        let mut durable = CowOverlay::new();
        let mut state = state(BlockCompletionDurability::Durable);
        let rule = ResolvedBlockMediaRule {
            contributor: [0x31; 32],
            start: 8,
            length: 8,
            state: crate::block::BlockMediaRangeState::Latent,
            operations: vec![BlockOp::Read],
            count_threshold: Some(2),
            time_threshold_nanos: None,
        };

        let first = BlockRequest::read(40, 8, 4);
        let first_response = response(&mut state, &base, &mut durable, &first, |directive| {
            directive.media_rules.push(rule.clone());
        });
        assert_eq!(first_response.status, BlockStatus::Ok);

        let second = BlockRequest::read(41, 8, 4);
        let second_response = response(&mut state, &base, &mut durable, &second, |directive| {
            directive.media_rules.push(rule);
        });
        assert_eq!(second_response.status, BlockStatus::Error);
        assert_eq!(
            second_response.error_code(),
            Ok(BlockErrorCode::MediumError)
        );
        assert_eq!(state.media_state().rules()[&[0x31; 32]].access_count, 2);
    }

    fn discard_state(semantics: BlockDiscardSemantics) -> BlockFaultState {
        BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 1,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 4,
            discard_semantics: semantics,
            volatile_cache_bytes: 0,
            cache_entries: 0,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::Durable,
        })
        .unwrap_or_else(|error| panic!("valid discard state: {error}"))
    }

    #[test]
    fn discard_readback_contracts_mutate_real_future_reads() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let discard = BlockRequest::discard(50, 8, 4);

        let mut zero_state = discard_state(BlockDiscardSemantics::DeterministicZero);
        let mut zero_durable = CowOverlay::new();
        assert_eq!(
            response(&mut zero_state, &base, &mut zero_durable, &discard, |_| {}).status,
            BlockStatus::Ok
        );
        assert_eq!(
            read(&mut zero_state, &base, &mut zero_durable, 51, 8, 4),
            vec![0; 4]
        );

        let mut old_state = discard_state(BlockDiscardSemantics::ReadsOldData);
        let mut old_durable = CowOverlay::new();
        response(&mut old_state, &base, &mut old_durable, &discard, |_| {});
        assert_eq!(
            read(&mut old_state, &base, &mut old_durable, 51, 8, 4),
            b"ijkl"
        );

        let mut first_state = discard_state(BlockDiscardSemantics::UndefinedKeyed);
        let mut first_durable = CowOverlay::new();
        response(
            &mut first_state,
            &base,
            &mut first_durable,
            &discard,
            |_| {},
        );
        let first = read(&mut first_state, &base, &mut first_durable, 51, 8, 4);
        let mut replay_state = discard_state(BlockDiscardSemantics::UndefinedKeyed);
        let mut replay_durable = CowOverlay::new();
        response(
            &mut replay_state,
            &base,
            &mut replay_durable,
            &discard,
            |_| {},
        );
        assert_eq!(
            read(&mut replay_state, &base, &mut replay_durable, 51, 8, 4),
            first
        );
        assert_ne!(first, b"ijkl");
    }

    #[test]
    fn discard_rejects_unsupported_or_misaligned_ranges_without_mutation() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut configured = discard_state(BlockDiscardSemantics::DeterministicZero);
        let mut durable = CowOverlay::new();
        let before = durable.clone();
        let request = BlockRequest::discard(60, 2, 4);
        let result = response(&mut configured, &base, &mut durable, &request, |_| {});
        assert_eq!(result.error_code(), Ok(BlockErrorCode::InvalidRange));
        assert_eq!(durable, before);

        let mut unsupported = state(BlockCompletionDurability::Durable);
        let request = BlockRequest::discard(61, 4, 4);
        let result = response(&mut unsupported, &base, &mut durable, &request, |_| {});
        assert_eq!(result.error_code(), Ok(BlockErrorCode::InvalidRange));
        assert_eq!(durable, before);
    }

    #[test]
    fn lost_torn_and_misdirected_writes_mutate_exact_bytes() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = state(BlockCompletionDurability::Durable);

        let lost = BlockRequest::write(1, 0, b"XXXXXXXX".to_vec());
        response(&mut state, &base, &mut durable, &lost, |directive| {
            directive.write_disposition = BlockFaultWriteDisposition::Lost;
        });
        assert_eq!(read(&mut state, &base, &mut durable, 2, 0, 8), b"abcdefgh");

        let torn = BlockRequest::write(3, 0, b"12345678".to_vec());
        response(&mut state, &base, &mut durable, &torn, |directive| {
            directive.write_disposition = BlockFaultWriteDisposition::Torn {
                spans: vec![
                    BlockFaultByteSpan {
                        start: 0,
                        length: 2,
                    },
                    BlockFaultByteSpan {
                        start: 4,
                        length: 2,
                    },
                ],
            };
        });
        assert_eq!(read(&mut state, &base, &mut durable, 4, 0, 8), b"12cd56gh");

        let misdirected = BlockRequest::write(5, 0, b"WXYZ".to_vec());
        response(&mut state, &base, &mut durable, &misdirected, |directive| {
            directive.write_disposition = BlockFaultWriteDisposition::Misdirected {
                destination_offset: 8,
            };
        });
        assert_eq!(read(&mut state, &base, &mut durable, 6, 8, 4), b"WXYZ");
    }

    #[test]
    fn acknowledged_lost_and_torn_fragments_permanently_bound_durability() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut main_state = state(BlockCompletionDurability::Durable);
        response(
            &mut main_state,
            &base,
            &mut durable,
            &BlockRequest::write(1, 0, b"GOOD".to_vec()),
            |_| {},
        );
        assert_eq!(main_state.actual_durable_frontier(), 4);
        response(
            &mut main_state,
            &base,
            &mut durable,
            &BlockRequest::write(2, 4, b"NO".to_vec()),
            |directive| directive.write_disposition = BlockFaultWriteDisposition::Lost,
        );
        response(
            &mut main_state,
            &base,
            &mut durable,
            &BlockRequest::flush(3),
            |_| {},
        );
        assert_eq!(main_state.next_cache_sequence, 6);
        assert_eq!(main_state.first_lost_sequence, Some(4));
        assert_eq!(main_state.actual_durable_frontier(), 4);
        assert_eq!(main_state.reported_durable_frontier(), 4);

        let mut torn_state = state(BlockCompletionDurability::Durable);
        let mut torn_durable = CowOverlay::new();
        response(
            &mut torn_state,
            &base,
            &mut torn_durable,
            &BlockRequest::write(4, 0, b"WXYZ".to_vec()),
            |directive| {
                directive.write_disposition = BlockFaultWriteDisposition::Torn {
                    spans: vec![
                        BlockFaultByteSpan {
                            start: 0,
                            length: 1,
                        },
                        BlockFaultByteSpan {
                            start: 2,
                            length: 1,
                        },
                    ],
                };
            },
        );
        assert_eq!(torn_state.next_cache_sequence, 4);
        assert_eq!(torn_state.first_lost_sequence, Some(1));
        assert_eq!(torn_state.actual_durable_frontier(), 1);
        assert_eq!(torn_state.reported_durable_frontier(), 1);
    }

    #[test]
    fn volatile_cache_flush_lie_loss_and_honest_flush_track_both_frontiers() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);
        let write = BlockRequest::write(1, 0, b"CACHE".to_vec());
        response(&mut state, &base, &mut durable, &write, |_| {});
        assert_eq!(read(&mut state, &base, &mut durable, 2, 0, 5), b"CACHE");
        assert_eq!(durable.read(&base, 0, 5).unwrap_or_default(), b"abcde");

        let lie = BlockRequest::flush(3);
        response(&mut state, &base, &mut durable, &lie, |directive| {
            directive.flush_disposition = BlockFaultFlushDisposition::Lie;
        });
        assert_eq!(state.actual_durable_frontier(), 0);
        assert_eq!(state.reported_durable_frontier(), 5);

        state
            .lose_volatile(&[0, 1, 2, 3, 4])
            .unwrap_or_else(|error| panic!("live cache entry is lost: {error}"));
        assert_eq!(read(&mut state, &base, &mut durable, 4, 0, 5), b"abcde");

        let second = BlockRequest::write(5, 0, b"SOLID".to_vec());
        response(&mut state, &base, &mut durable, &second, |_| {});
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::flush(6),
            |_| {},
        );
        assert!(state.volatile_entries().is_empty());
        // A lost sequence is a permanent hole in the exact durability
        // frontier, even after later writes are honestly flushed.
        assert_eq!(state.actual_durable_frontier(), 0);
        assert_eq!(state.reported_durable_frontier(), 0);
        assert_eq!(durable.read(&base, 0, 5).unwrap_or_default(), b"SOLID");
    }

    #[test]
    fn controller_accepted_writes_remain_a_distinct_durability_layer() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = state(BlockCompletionDurability::ControllerAccepted);
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(1, 4, b"CTRL".to_vec()),
            |_| {},
        );
        assert_eq!(state.controller_entries().len(), 4);
        assert!(state.volatile_entries().is_empty());
        assert_eq!(durable.read(&base, 4, 4).unwrap_or_default(), b"efgh");
        assert_eq!(read(&mut state, &base, &mut durable, 2, 4, 4), b"CTRL");

        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::flush(3),
            |_| {},
        );
        assert!(state.controller_entries().is_empty());
        assert!(state.volatile_entries().is_empty());
        assert_eq!(durable.read(&base, 4, 4).unwrap_or_default(), b"CTRL");
        assert_eq!(state.actual_durable_frontier(), 4);
        assert_eq!(state.reported_durable_frontier(), 4);
    }

    #[test]
    fn read_transforms_and_stalled_completion_are_checkpointable() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);
        let read_request = BlockRequest::read(1, 0, 4);
        let transformed = response(
            &mut state,
            &base,
            &mut durable,
            &read_request,
            |directive| {
                directive
                    .read_transforms
                    .push(BlockFaultReadTransform::Xor {
                        offset: 1,
                        mask: vec![0xff, 0x01],
                    });
            },
        );
        assert_eq!(transformed.data, vec![b'a', b'b' ^ 0xff, b'c' ^ 0x01, b'd']);

        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(2, 8, b"held".to_vec()),
            |_| {},
        );
        let flush = BlockRequest::flush(3);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&flush, base.len());
        directive.flush_disposition = BlockFaultFlushDisposition::Stall;
        directive.retain_completion = true;
        directive.retention_timeout_response = Some(BlockResponse::error(
            flush.request_id,
            BlockErrorCode::Timeout,
        ));
        directive.retention_timeout_nanos = Some(100);
        directive.retention_recovery_event = Some([7; 32]);
        directive.retention_recovery_after_nanos = Some(0);
        state
            .install(flush.identity(), directive)
            .unwrap_or_else(|error| panic!("directive installs: {error}"));
        let computed = state
            .execute(&base, &mut durable, &flush, 0)
            .unwrap_or_else(|error| panic!("flush executes: {error}"));
        assert!(computed.primary.is_none());
        assert_eq!(state.reported_durable_frontier(), 0);
        let checkpoint = state.clone();
        assert_eq!(
            checkpoint.retained_completions(),
            state.retained_completions()
        );
        assert_eq!(
            checkpoint
                .retained_completion(flush.identity())
                .map(|held| held.identity.request_id),
            Some(flush.request_id)
        );
        assert!(state.retained_timeouts_due(99).is_empty());
        assert_eq!(state.retained_timeouts_due(100), vec![flush.identity()]);
        assert!(state.retained_recoveries_for([7; 32], 0).is_empty());
        assert_eq!(
            state.retained_recoveries_for([7; 32], 50),
            vec![flush.identity()]
        );
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(4, 12, b"later".to_vec()),
            |_| {},
        );
        let released = state
            .resolve_retained_completion(
                &base,
                &mut durable,
                flush.identity(),
                BlockRetainedRelease::Recovery,
                0,
            )
            .unwrap_or_else(|error| panic!("retained completion recovers: {error}"));
        let released = BlockResponse::decode(&released.payload)
            .unwrap_or_else(|error| panic!("released response decodes: {error}"));
        assert_eq!(released.status, BlockStatus::Ok);
        assert_eq!(state.reported_durable_frontier(), 4);
        assert_eq!(state.actual_durable_frontier(), 4);
        assert_eq!(state.volatile_entries().len(), 5);
        assert_eq!(durable.read(&base, 8, 4).unwrap_or_default(), b"held");
        assert_eq!(durable.read(&base, 12, 5).unwrap_or_default(), b"mnopq");
    }

    #[test]
    fn stalled_flush_timeout_does_not_persist_or_report_cached_writes() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(1, 8, b"held".to_vec()),
            |_| {},
        );
        let flush = BlockRequest::flush(2);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&flush, base.len());
        directive.flush_disposition = BlockFaultFlushDisposition::Stall;
        directive.retain_completion = true;
        directive.retention_timeout_response = Some(BlockResponse::error(
            flush.request_id,
            BlockErrorCode::Timeout,
        ));
        directive.retention_timeout_nanos = Some(100);
        state
            .install(flush.identity(), directive)
            .unwrap_or_else(|error| panic!("directive installs: {error}"));
        let computed = state
            .execute(&base, &mut durable, &flush, 99)
            .unwrap_or_else(|error| panic!("flush executes: {error}"));
        assert!(computed.primary.is_none());
        let retained = state
            .retained_completion(flush.identity())
            .unwrap_or_else(|| panic!("completion is retained"));
        assert_eq!(retained.request_icount, 99);
        assert_eq!(retained.persist_through_on_recovery, Some(4));

        let released = state
            .resolve_retained_completion(
                &base,
                &mut durable,
                flush.identity(),
                BlockRetainedRelease::Timeout,
                0,
            )
            .unwrap_or_else(|error| panic!("retained completion times out: {error}"));
        let released = BlockResponse::decode(&released.payload)
            .unwrap_or_else(|error| panic!("released response decodes: {error}"));
        assert_eq!(released.status, BlockStatus::Error);
        assert_eq!(state.reported_durable_frontier(), 0);
        assert_eq!(state.actual_durable_frontier(), 0);
        assert_eq!(state.volatile_entries().len(), 4);
        assert_eq!(durable.read(&base, 8, 4).unwrap_or_default(), b"ijkl");
    }

    #[test]
    fn cache_admission_failure_is_transactional() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 1,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 3,
            cache_entries: 1,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 1024,
            retained_versions: 2,
            completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        let request = BlockRequest::write(1, 0, b"four".to_vec());
        let directive = ResolvedBlockFaultDirective::fault_free(&request, base.len());
        state
            .install(request.identity(), directive)
            .unwrap_or_else(|error| panic!("directive installs: {error}"));
        let before_durable = durable.clone();
        let computed = state
            .execute(&base, &mut durable, &request, 0)
            .unwrap_or_else(|error| panic!("write returns a guest-visible error: {error}"));
        let response = computed
            .primary
            .and_then(|response| BlockResponse::decode(&response.payload).ok())
            .unwrap_or_else(|| panic!("write produces one decodable response"));
        assert_eq!(response.status, BlockStatus::Error);
        assert!(state.volatile_entries().is_empty());
        assert_eq!(durable, before_durable);
    }

    #[test]
    fn pending_durability_continuation_tracks_acknowledged_cache_write() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = state(BlockCompletionDurability::VolatileCacheAccepted);

        assert!(!state.has_pending_durability_continuation());
        let write = BlockRequest::write(1, 8, b"cache".to_vec());
        let completed = response(&mut state, &base, &mut durable, &write, |_| {});
        assert_eq!(completed.status, BlockStatus::Ok);
        assert!(state.has_pending_durability_continuation());
        assert_eq!(durable.read(&base, 8, 5).unwrap_or_default(), b"ijklm");

        let flush = BlockRequest::flush(2);
        let completed = response(&mut state, &base, &mut durable, &flush, |_| {});
        assert_eq!(completed.status, BlockStatus::Ok);
        assert!(!state.has_pending_durability_continuation());
        assert_eq!(durable.read(&base, 8, 5).unwrap_or_default(), b"cache");
    }

    #[test]
    fn cache_rejection_rolls_back_partially_schedulable_evictions() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 8,
            cache_entries: 2,
            controller_buffer_bytes: 4,
            controller_entries: 1,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::ControllerAccepted,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(1, 0, b"aaaa".to_vec()),
            |_| {},
        );
        let cache = ResolvedBlockCachePolicy {
            capacity_bytes: 8,
            eviction: BlockFaultCacheEviction::Fifo,
            dirty_eviction: BlockFaultDirtyEviction::Persist,
            power_loss_protected: false,
        };
        for (request_id, offset) in [(2, 0), (3, 8)] {
            response(
                &mut state,
                &base,
                &mut durable,
                &BlockRequest::write(request_id, offset, vec![b'x'; 4]),
                |directive| directive.cache_policy = Some(cache),
            );
        }
        let before_state = state.clone();
        let before_durable = durable.clone();
        let rejected = response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(4, 16, vec![b'y'; 8]),
            |directive| directive.cache_policy = Some(cache),
        );

        assert_eq!(rejected.error_code(), Ok(BlockFaultResult::Busy));
        assert_eq!(state, before_state);
        assert_eq!(durable, before_durable);
    }

    #[test]
    fn cache_policy_persists_fifo_victims_before_admission() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 8,
            cache_entries: 2,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::Durable,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        let policy = ResolvedBlockCachePolicy {
            capacity_bytes: 8,
            eviction: BlockFaultCacheEviction::Fifo,
            dirty_eviction: BlockFaultDirtyEviction::Persist,
            power_loss_protected: false,
        };
        for (request_id, offset, bytes) in [(1, 0, b"aaaa"), (2, 4, b"bbbb"), (3, 8, b"cccc")] {
            response(
                &mut state,
                &base,
                &mut durable,
                &BlockRequest::write(request_id, offset, bytes.to_vec()),
                |directive| directive.cache_policy = Some(policy),
            );
        }
        assert_eq!(state.volatile_entries().len(), 2);
        assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"aaaa");
        assert_eq!(durable.read(&base, 4, 4).unwrap_or_default(), b"efgh");
        assert_eq!(
            read(&mut state, &base, &mut durable, 4, 0, 12),
            b"aaaabbbbcccc"
        );
    }

    #[test]
    fn cache_dirty_eviction_preserves_the_authored_typed_failure() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 4,
            cache_entries: 1,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::Durable,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        let persist = ResolvedBlockCachePolicy {
            capacity_bytes: 4,
            eviction: BlockFaultCacheEviction::Fifo,
            dirty_eviction: BlockFaultDirtyEviction::Persist,
            power_loss_protected: false,
        };
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(1, 0, b"aaaa".to_vec()),
            |directive| directive.cache_policy = Some(persist),
        );
        let failed = response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(2, 4, b"bbbb".to_vec()),
            |directive| {
                directive.cache_policy = Some(ResolvedBlockCachePolicy {
                    dirty_eviction: BlockFaultDirtyEviction::Fail(BlockFaultResult::NoSpace),
                    ..persist
                });
            },
        );
        assert_eq!(failed.status, BlockStatus::Error);
        assert_eq!(failed.error_code(), Ok(BlockFaultResult::NoSpace));
        assert_eq!(state.volatile_entries().len(), 1);
        assert_eq!(read(&mut state, &base, &mut durable, 3, 0, 8), b"aaaaefgh");
    }

    #[test]
    fn cache_policy_lru_reads_change_the_exact_victim() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 8,
            cache_entries: 2,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::Durable,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        let policy = ResolvedBlockCachePolicy {
            capacity_bytes: 8,
            eviction: BlockFaultCacheEviction::Lru,
            dirty_eviction: BlockFaultDirtyEviction::Persist,
            power_loss_protected: false,
        };
        for (request_id, offset, bytes) in [(1, 0, b"aaaa"), (2, 4, b"bbbb")] {
            response(
                &mut state,
                &base,
                &mut durable,
                &BlockRequest::write(request_id, offset, bytes.to_vec()),
                |directive| directive.cache_policy = Some(policy),
            );
        }
        assert_eq!(read(&mut state, &base, &mut durable, 3, 0, 4), b"aaaa");
        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(4, 8, b"cccc".to_vec()),
            |directive| directive.cache_policy = Some(policy),
        );
        assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"abcd");
        assert_eq!(durable.read(&base, 4, 4).unwrap_or_default(), b"bbbb");
        assert_eq!(
            read(&mut state, &base, &mut durable, 5, 0, 12),
            b"aaaabbbbcccc"
        );
    }

    #[test]
    fn cache_lru_tracks_visible_bytes_and_preserves_overlap_dependencies() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 10,
            cache_entries: 3,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::Durable,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        let policy = ResolvedBlockCachePolicy {
            capacity_bytes: 6,
            eviction: BlockFaultCacheEviction::Lru,
            dirty_eviction: BlockFaultDirtyEviction::Persist,
            power_loss_protected: false,
        };
        for (request_id, offset, bytes) in [(1, 0, b"aaaa".as_slice()), (2, 0, b"BB".as_slice())] {
            response(
                &mut state,
                &base,
                &mut durable,
                &BlockRequest::write(request_id, offset, bytes.to_vec()),
                |directive| directive.cache_policy = Some(policy),
            );
        }
        let old_access = state.volatile_entries()[&0].last_access_sequence;
        let new_access = state.volatile_entries()[&1].last_access_sequence;
        assert_eq!(read(&mut state, &base, &mut durable, 3, 2, 2), b"aa");
        assert!(state.volatile_entries()[&0].last_access_sequence > old_access);
        assert_eq!(
            state.volatile_entries()[&1].last_access_sequence,
            new_access
        );

        response(
            &mut state,
            &base,
            &mut durable,
            &BlockRequest::write(4, 8, b"cccc".to_vec()),
            |directive| directive.cache_policy = Some(policy),
        );
        assert!(!state.volatile_entries().contains_key(&0));
        assert!(state.volatile_entries().contains_key(&1));
        assert_eq!(read(&mut state, &base, &mut durable, 5, 0, 4), b"BBaa");
    }

    #[test]
    fn cache_loss_candidates_distinguish_power_loss_from_protection_failure() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 8,
            cache_entries: 2,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::Durable,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        for (request_id, offset, protected) in [(1, 0, false), (2, 4, true)] {
            response(
                &mut state,
                &base,
                &mut durable,
                &BlockRequest::write(request_id, offset, vec![b'x'; 4]),
                |directive| {
                    directive.cache_policy = Some(ResolvedBlockCachePolicy {
                        capacity_bytes: 8,
                        eviction: BlockFaultCacheEviction::Fifo,
                        dirty_eviction: BlockFaultDirtyEviction::Persist,
                        power_loss_protected: protected,
                    });
                },
            );
        }
        assert_eq!(state.volatile_loss_candidates(false), vec![0]);
        assert_eq!(state.volatile_loss_candidates(true), vec![0, 1]);
        let ordinary_loss = state.volatile_loss_candidates(false);
        state
            .lose_volatile(&ordinary_loss)
            .unwrap_or_else(|error| panic!("ordinary power-loss subset is live: {error}"));
        assert_eq!(state.volatile_loss_candidates(true), vec![1]);
    }

    #[test]
    fn persistence_delay_defers_durable_bytes_and_flush_truth_until_due() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let mut state = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 8,
            cache_entries: 2,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 1024,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        let write = BlockRequest::write(1, 0, b"zzzz".to_vec());
        let mut directive = ResolvedBlockFaultDirective::fault_free(&write, base.len());
        directive.execution_nanos = 10;
        directive.persistence_admitted_nanos = 10;
        directive.cache_policy = Some(ResolvedBlockCachePolicy {
            capacity_bytes: 8,
            eviction: BlockFaultCacheEviction::WritebackSequence,
            dirty_eviction: BlockFaultDirtyEviction::Persist,
            power_loss_protected: false,
        });
        directive
            .persistence_transforms
            .push(ResolvedBlockPersistenceTransform {
                contributor: [7; 32],
                ordering_group: [6; 32],
                ordering: crate::block::BlockPersistenceOrdering::Preserve,
                delay_nanos: 100,
                preserve_barriers: true,
            });
        state
            .install(write.identity(), directive)
            .unwrap_or_else(|error| panic!("write directive: {error}"));
        state
            .execute(&base, &mut durable, &write, 10)
            .unwrap_or_else(|error| panic!("cached write: {error}"));

        let flush = BlockRequest::flush(2);
        let mut flush_directive = ResolvedBlockFaultDirective::fault_free(&flush, base.len());
        flush_directive.execution_nanos = 20;
        state
            .install(flush.identity(), flush_directive)
            .unwrap_or_else(|error| panic!("flush directive: {error}"));
        let computed = state
            .execute(&base, &mut durable, &flush, 20)
            .unwrap_or_else(|error| panic!("delayed flush: {error}"));
        assert_eq!(computed.additional_latency_nanos, 90);
        assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"abcd");
        assert_eq!(state.reported_durable_frontier(), 0);
        assert!(state.media_queue_entries().contains_key(&0));

        state
            .persist_due(&base, &mut durable, 109)
            .unwrap_or_else(|error| panic!("pre-deadline service: {error}"));
        assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"abcd");
        state
            .persist_due(&base, &mut durable, 110)
            .unwrap_or_else(|error| panic!("deadline service: {error}"));
        assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"zzzz");
        assert_eq!(state.reported_durable_frontier(), 1);
        assert!(state.media_queue_entries().is_empty());
    }

    #[test]
    fn duplicate_directive_rejection_preserves_the_original() {
        let request = BlockRequest::read(7, 0, 4);
        let mut state = state(BlockCompletionDurability::Durable);
        let original = ResolvedBlockFaultDirective::fault_free(&request, 32);
        let mut replacement = original.clone();
        replacement.error_result = Some(BlockFaultResult::IoError);
        state
            .install(request.identity(), original.clone())
            .unwrap_or_else(|error| panic!("first directive installs: {error}"));
        assert_eq!(
            state.install(request.identity(), replacement),
            Err(DeviceError::DuplicateBlockFaultDirective {
                request_id: request.request_id
            })
        );
        assert_eq!(state.pending.get(&request.identity()), Some(&original));
    }

    #[test]
    fn duplicate_resolution_uses_checked_primary_relative_delays() {
        let request = BlockRequest::read(7, 0, 4);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
        directive
            .configure_duplicate_completions(
                request.request_id,
                3,
                11,
                BlockDuplicatePolicy::Ignore,
            )
            .unwrap_or_else(|error| panic!("duplicate policy resolves: {error}"));
        assert_eq!(
            directive
                .duplicate_completions
                .iter()
                .map(ResolvedBlockDuplicateCompletion::gap_nanos)
                .collect::<Vec<_>>(),
            vec![11, 22, 33]
        );
        directive
            .append_duplicate_completions(request.request_id, 2, 7, BlockDuplicatePolicy::Ignore)
            .unwrap_or_else(|error| panic!("duplicate contribution appends: {error}"));
        assert_eq!(
            directive
                .duplicate_completions
                .iter()
                .map(ResolvedBlockDuplicateCompletion::gap_nanos)
                .collect::<Vec<_>>(),
            vec![11, 22, 33, 40, 47]
        );
        let before = directive.duplicate_completions.clone();
        assert!(
            directive
                .append_duplicate_completions(
                    request.request_id,
                    2,
                    u64::MAX,
                    BlockDuplicatePolicy::Ignore,
                )
                .is_err()
        );
        assert_eq!(directive.duplicate_completions, before);
    }

    #[test]
    fn duplicate_reset_encodes_the_exact_live_transport_transition() {
        let request = BlockRequest::write(7, 0, b"data".to_vec());
        let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
        directive
            .configure_duplicate_completions(
                request.request_id,
                1,
                11,
                BlockDuplicatePolicy::Reset(reset_transition()),
            )
            .unwrap_or_else(|error| panic!("duplicate policy resolves: {error}"));
        let mut state = state(BlockCompletionDurability::Durable);
        state
            .install(request.identity(), directive)
            .unwrap_or_else(|error| panic!("reset directive installs: {error}"));
        let computed = state
            .execute(
                &BaseImage::new(vec![0; 32]),
                &mut CowOverlay::new(),
                &request,
                0,
            )
            .unwrap_or_else(|error| panic!("reset request executes: {error}"));
        assert_eq!(computed.additional.len(), 1);
        let reset = BlockResponse::decode(&computed.additional[0].response.payload)
            .unwrap_or_else(|error| panic!("reset response decodes: {error}"))
            .transport_reset_directive()
            .unwrap_or_else(|error| panic!("reset payload decodes: {error}"));
        assert_eq!(reset.next_epoch, 1);
        assert_eq!(reset.recovery_nanos, 50);
        assert!(reset.reenumerate_declared);
        assert!(!reset.preserve_duplicate_history);
    }

    #[test]
    fn duplicate_ignore_and_protocol_error_produce_exact_additional_completions() {
        let base = BaseImage::new(b"abcdefghijklmnopqrstuvwxyz012345".to_vec());
        let mut durable = CowOverlay::new();
        let request = BlockRequest::read(7, 0, 4);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
        directive
            .configure_duplicate_completions(
                request.request_id,
                1,
                11,
                BlockDuplicatePolicy::Ignore,
            )
            .unwrap_or_else(|error| panic!("ignore policy resolves: {error}"));
        let mut state = state(BlockCompletionDurability::Durable);
        state
            .install(request.identity(), directive)
            .unwrap_or_else(|error| panic!("ignore directive installs: {error}"));
        let computed = state
            .execute(&base, &mut durable, &request, 0)
            .unwrap_or_else(|error| panic!("ignore directive executes: {error}"));
        let primary = computed
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("primary response should exist"));
        assert_eq!(computed.additional.len(), 1);
        assert_eq!(computed.additional[0].gap_nanos, 11);
        let ignored = BlockResponse::decode(&computed.additional[0].response.payload)
            .unwrap_or_else(|error| panic!("ignored duplicate should decode: {error}"));
        assert_eq!(ignored.status, BlockStatus::DuplicateIgnored);
        assert_eq!(ignored.identity(), request.identity());
        assert!(ignored.data.is_empty());
        assert_ne!(&computed.additional[0].response, primary);

        let request = BlockRequest::read(8, 0, 4);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
        directive
            .configure_duplicate_completions(
                request.request_id,
                1,
                17,
                BlockDuplicatePolicy::ProtocolError(BlockResponse::error(
                    request.request_id,
                    BlockErrorCode::IoError,
                )),
            )
            .unwrap_or_else(|error| panic!("protocol-error policy resolves: {error}"));
        state
            .install(request.identity(), directive)
            .unwrap_or_else(|error| panic!("protocol-error directive installs: {error}"));
        let computed = state
            .execute(&base, &mut durable, &request, 0)
            .unwrap_or_else(|error| panic!("protocol-error directive executes: {error}"));
        assert_eq!(computed.additional.len(), 1);
        assert_eq!(computed.additional[0].gap_nanos, 17);
        let protocol_error = BlockResponse::decode(&computed.additional[0].response.payload)
            .unwrap_or_else(|error| panic!("duplicate protocol error should decode: {error}"));
        assert_eq!(protocol_error.status, BlockStatus::DuplicateProtocolError);
        assert_eq!(
            computed.additional[0].response.status,
            ResponseStatus::Error
        );
    }

    #[test]
    fn timeout_and_duplicate_responses_must_fit_one_transport_frame() {
        let request = BlockRequest::flush(9);
        let oversized = BlockResponse {
            status: BlockStatus::Error,
            epoch: request.epoch,
            request_id: request.request_id,
            data: vec![0; crucible_shmem::MAX_FRAME_DATA],
        };
        let mut retained = ResolvedBlockFaultDirective::fault_free(&request, 32);
        retained.flush_disposition = BlockFaultFlushDisposition::Stall;
        retained.retain_completion = true;
        retained.retention_timeout_response = Some(oversized.clone());
        assert!(matches!(
            state(BlockCompletionDurability::Durable).install(request.identity(), retained),
            Err(DeviceError::InvalidBlockFaultDirective { .. })
        ));

        let read = BlockRequest::read(10, 0, 1);
        let mut duplicate = ResolvedBlockFaultDirective::fault_free(&read, 32);
        duplicate
            .configure_duplicate_completions(
                read.request_id,
                1,
                1,
                BlockDuplicatePolicy::ProtocolError(BlockResponse {
                    request_id: read.request_id,
                    ..oversized
                }),
            )
            .unwrap_or_else(|error| panic!("duplicate policy resolves before install: {error}"));
        assert!(matches!(
            state(BlockCompletionDurability::Durable).install(read.identity(), duplicate),
            Err(DeviceError::InvalidBlockFaultDirective { .. })
        ));
    }

    #[test]
    fn persistence_opportunity_applies_checkpointed_partial_flash_program() {
        let base = BaseImage::new(vec![0; 32]);
        let mut durable = CowOverlay::new();
        let mut storage = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 32,
            cache_entries: 8,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 32,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
        })
        .unwrap_or_else(|error| panic!("flash test state should build: {error}"));
        let write = BlockRequest::write(41, 0, vec![0xaa; 4]);
        let directive = ResolvedBlockFaultDirective::fault_free(&write, 32);
        storage
            .install(write.identity(), directive)
            .unwrap_or_else(|error| panic!("write directive should install: {error}"));
        storage
            .execute(&base, &mut durable, &write, 0)
            .unwrap_or_else(|error| panic!("cached write should execute: {error}"));
        storage
            .schedule_volatile_persistence(0)
            .unwrap_or_else(|error| panic!("write should enter media queue: {error}"));
        storage.require_persistence_media_directives(true);
        let opportunity = storage
            .next_persistence_opportunity(0)
            .unwrap_or_else(|| panic!("persistence opportunity should be ready"));
        let flash_rule = ResolvedBlockFlashRule {
            contributor: [3; 32],
            choice_key: [4; 32],
            erase_block_bytes: 8,
            program_page_bytes: 4,
            endurance_cycles: 10,
            retention: super::super::flash::ResolvedBlockFlashRetention {
                minimum_age_nanos: 1,
                wear_age_nanos: 0,
                bit_probability_millionths: 0,
                maximum_changed_bits: 1,
            },
            read_disturb: super::super::flash::ResolvedBlockFlashReadDisturb {
                read_threshold: 10,
                neighbor_pages: 1,
                bit_probability_millionths: 0,
                maximum_changed_bits: 1,
            },
            program_erase: super::super::flash::ResolvedBlockFlashProgramErase {
                program_probability_millionths: 1_000_000,
                erase_probability_millionths: 0,
                worn_probability_millionths: 0,
                partial_program: true,
                partial_erase: false,
            },
        };
        storage
            .install_persistence_media_directive(ResolvedBlockPersistenceMediaDirective {
                opportunity: opportunity.clone(),
                flash_rules: vec![flash_rule],
            })
            .unwrap_or_else(|error| panic!("flash directive should install: {error}"));
        storage
            .validate_restore(32)
            .unwrap_or_else(|error| panic!("pre-persist checkpoint should validate: {error}"));
        storage
            .persist_due(&base, &mut durable, 0)
            .unwrap_or_else(|error| panic!("flash persistence should execute: {error}"));
        let outcomes = storage.drain_persistence_media_outcomes();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].opportunity, opportunity);
        assert!(outcomes[0].media_failed);
        assert_eq!(outcomes[0].applied_spans.len(), 1);
        let programmed = outcomes[0].applied_spans[0].length as usize;
        let materialized = durable.materialize(&base);
        assert_eq!(&materialized[..programmed], &vec![0xaa; programmed]);
        assert_eq!(&materialized[programmed..4], &vec![0; 4 - programmed]);
    }

    #[test]
    fn flash_discard_applies_one_request_wide_partial_erase() {
        let base = BaseImage::new(vec![0xaa; 16]);
        let mut durable = CowOverlay::new();
        let mut storage = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 16,
            atomic_write_bytes: 4,
            maximum_request_bytes: 16,
            discard_granularity_bytes: 4,
            discard_semantics: BlockDiscardSemantics::ReadsOldData,
            volatile_cache_bytes: 16,
            cache_entries: 4,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 16,
            retained_versions: 4,
            completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
        })
        .unwrap_or_else(|error| panic!("flash discard state should build: {error}"));
        let discard = BlockRequest::discard(42, 0, 8);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&discard, 16);
        directive.persistence_media_rules = vec![ResolvedBlockFlashRule {
            contributor: [7; 32],
            choice_key: [8; 32],
            erase_block_bytes: 8,
            program_page_bytes: 4,
            endurance_cycles: 10,
            retention: super::super::flash::ResolvedBlockFlashRetention {
                minimum_age_nanos: 1,
                wear_age_nanos: 0,
                bit_probability_millionths: 0,
                maximum_changed_bits: 1,
            },
            read_disturb: super::super::flash::ResolvedBlockFlashReadDisturb {
                read_threshold: 10,
                neighbor_pages: 1,
                bit_probability_millionths: 0,
                maximum_changed_bits: 1,
            },
            program_erase: super::super::flash::ResolvedBlockFlashProgramErase {
                program_probability_millionths: 0,
                erase_probability_millionths: 1_000_000,
                worn_probability_millionths: 0,
                partial_program: false,
                partial_erase: true,
            },
        }];
        storage
            .install(discard.identity(), directive)
            .unwrap_or_else(|error| panic!("discard directive should install: {error}"));
        storage
            .execute(&base, &mut durable, &discard, 0)
            .unwrap_or_else(|error| panic!("discard should enter the volatile cache: {error}"));
        storage
            .schedule_volatile_persistence(0)
            .unwrap_or_else(|error| panic!("first fragment should enter media: {error}"));
        storage
            .schedule_volatile_persistence(1)
            .unwrap_or_else(|error| panic!("second fragment should enter media: {error}"));
        storage
            .validate_restore(16)
            .unwrap_or_else(|error| panic!("queued discard checkpoint should validate: {error}"));
        storage
            .persist_due(&base, &mut durable, 0)
            .unwrap_or_else(|error| panic!("flash erase should persist: {error}"));

        let outcomes = storage.drain_persistence_media_outcomes();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|outcome| outcome.media_failed));
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.opportunity.operation == BlockOp::Discard)
        );
        let erased = outcomes
            .iter()
            .flat_map(|outcome| &outcome.applied_spans)
            .map(|span| span.length)
            .sum::<u64>();
        assert!((1..=8).contains(&erased));
        let materialized = durable.materialize(&base);
        assert_eq!(
            &materialized[..usize::try_from(erased).unwrap_or(0)],
            &vec![0xff; usize::try_from(erased).unwrap_or(0)]
        );
        assert_eq!(
            &materialized[usize::try_from(erased).unwrap_or(0)..8],
            &vec![0xaa; 8 - usize::try_from(erased).unwrap_or(0)]
        );
        let continuation = &storage.flash_state().continuations()[&[7; 32]];
        assert_eq!(continuation.erase_blocks[&0].erase_count, 1);
        assert!(continuation.erase_decisions.is_empty());
    }

    #[test]
    fn flash_retention_changes_survive_effect_deactivation_and_restore() {
        let base = BaseImage::new(vec![0; 32]);
        let mut durable = CowOverlay::new();
        let mut storage = state(BlockCompletionDurability::Durable);
        let read = BlockRequest::read(52, 0, 4);
        let mut active = ResolvedBlockFaultDirective::fault_free(&read, 32);
        active.execution_nanos = 10;
        active.persistence_media_rules = vec![ResolvedBlockFlashRule {
            contributor: [5; 32],
            choice_key: [6; 32],
            erase_block_bytes: 8,
            program_page_bytes: 4,
            endurance_cycles: 10,
            retention: super::super::flash::ResolvedBlockFlashRetention {
                minimum_age_nanos: 1,
                wear_age_nanos: 0,
                bit_probability_millionths: 1_000_000,
                maximum_changed_bits: 1,
            },
            read_disturb: super::super::flash::ResolvedBlockFlashReadDisturb {
                read_threshold: 100,
                neighbor_pages: 1,
                bit_probability_millionths: 0,
                maximum_changed_bits: 1,
            },
            program_erase: super::super::flash::ResolvedBlockFlashProgramErase {
                program_probability_millionths: 0,
                erase_probability_millionths: 0,
                worn_probability_millionths: 0,
                partial_program: false,
                partial_erase: false,
            },
        }];
        storage
            .install(read.identity(), active)
            .unwrap_or_else(|error| panic!("active flash read should install: {error}"));
        let changed = storage
            .execute(&base, &mut durable, &read, 0)
            .unwrap_or_else(|error| panic!("active flash read should execute: {error}"));
        let changed = BlockResponse::decode(
            &changed
                .primary
                .unwrap_or_else(|| panic!("read should complete"))
                .payload,
        )
        .unwrap_or_else(|error| panic!("read response should decode: {error}"));
        assert_ne!(changed.data, vec![0; 4]);

        storage
            .validate_restore(32)
            .unwrap_or_else(|error| panic!("flash continuation should restore: {error}"));
        let inactive_read = BlockRequest::read(53, 0, 4);
        storage
            .install(
                inactive_read.identity(),
                ResolvedBlockFaultDirective::fault_free(&inactive_read, 32),
            )
            .unwrap_or_else(|error| panic!("inactive read should install: {error}"));
        let persisted = storage
            .execute(&base, &mut durable, &inactive_read, 0)
            .unwrap_or_else(|error| panic!("inactive read should execute: {error}"));
        let persisted = BlockResponse::decode(
            &persisted
                .primary
                .unwrap_or_else(|| panic!("read should complete"))
                .payload,
        )
        .unwrap_or_else(|error| panic!("read response should decode: {error}"));
        assert_eq!(persisted.data, changed.data);
    }

    #[test]
    fn staged_execution_does_not_mutate_before_the_exact_decision() {
        let base = BaseImage::new(vec![0; 32]);
        let mut durable = CowOverlay::new();
        let mut storage = state(BlockCompletionDurability::Durable);
        storage.require_execution_opportunities(true);
        let request = BlockRequest::write(61, 4, b"stage".to_vec());
        let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
        admission.request_sequence = 900;
        admission.execution_nanos = 17;
        storage
            .install(request.identity(), admission)
            .unwrap_or_else(|error| panic!("admission directive should install: {error}"));

        let computed = storage
            .execute(&base, &mut durable, &request, 3)
            .unwrap_or_else(|error| panic!("request should enter staged execution: {error}"));
        assert!(computed.primary.is_none());
        assert_eq!(durable.read(&base, 4, 5).unwrap_or_default(), vec![0; 5]);
        assert!(storage.next_execution_opportunity(16).is_none());
        let opportunity = storage
            .next_execution_opportunity(17)
            .unwrap_or_else(|| panic!("exact execution opportunity should be visible"));
        assert_eq!(opportunity.request_sequence, 900);
        assert_eq!(opportunity.request, request);
        assert_eq!(opportunity.request_icount, 3);
        assert_eq!(opportunity.ready_nanos, 17);
        storage
            .validate_restore(32)
            .unwrap_or_else(|error| panic!("pre-decision checkpoint should validate: {error}"));

        let mut execution = ResolvedBlockFaultDirective::fault_free(&request, 32);
        execution.request_sequence = 900;
        execution.execution_nanos = 18;
        assert!(matches!(
            storage.install_execution_directive(ResolvedBlockExecutionDirective {
                opportunity: opportunity.clone(),
                directive: execution.clone(),
            }),
            Err(DeviceError::InvalidBlockFaultDirective { .. })
        ));
        execution.execution_nanos = 17;
        storage
            .install_execution_directive(ResolvedBlockExecutionDirective {
                opportunity,
                directive: execution,
            })
            .unwrap_or_else(|error| panic!("execution directive should install: {error}"));
        storage
            .validate_restore(32)
            .unwrap_or_else(|error| panic!("post-decision checkpoint should validate: {error}"));
        assert!(
            storage
                .resume_execution_to(&base, &mut durable, 16)
                .unwrap_or_else(|error| panic!("early resume should succeed: {error}"))
                .is_empty()
        );
        let released = storage
            .resume_execution_to(&base, &mut durable, 17)
            .unwrap_or_else(|error| panic!("exact resume should succeed: {error}"));
        assert!(released.is_empty());
        let persistence = storage
            .next_request_persistence_opportunity(17)
            .unwrap_or_else(|| panic!("persist opportunity should be visible"));
        let mut persisted = persistence.resolved.clone();
        persisted.execution_nanos = 17;
        storage
            .install_request_persistence_directive(ResolvedBlockRequestPersistenceDirective {
                opportunity: persistence,
                directive: persisted,
            })
            .unwrap_or_else(|error| panic!("persist directive should install: {error}"));
        let released = storage
            .resume_request_persistence_to(&base, &mut durable, 17)
            .unwrap_or_else(|error| panic!("persist resume should succeed: {error}"));
        assert!(released.is_empty());
        let delivery = storage
            .next_delivery_opportunity(17)
            .unwrap_or_else(|| panic!("delivery opportunity should be visible"));
        let delivered = delivery.resolved.clone();
        storage
            .install_delivery_directive(ResolvedBlockDeliveryDirective {
                opportunity: delivery,
                directive: delivered,
            })
            .unwrap_or_else(|error| panic!("delivery directive should install: {error}"));
        let released = storage
            .resume_delivery_to(17)
            .unwrap_or_else(|error| panic!("delivery resume should succeed: {error}"));
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].finished_nanos, 17);
        assert_eq!(durable.read(&base, 4, 5).unwrap_or_default(), b"stage");
        assert!(storage.next_execution_opportunity(u64::MAX).is_none());
    }

    #[test]
    fn durable_delivery_waits_for_the_exact_physical_media_decision() {
        let base = BaseImage::new(vec![0; 32]);
        let mut durable = CowOverlay::new();
        let mut storage = state(BlockCompletionDurability::Durable);
        storage.require_execution_opportunities(true);
        storage.require_persistence_media_directives(true);
        let request = BlockRequest::write(63, 0, b"sync".to_vec());
        let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
        admission.request_sequence = 902;
        admission.execution_nanos = 17;
        storage
            .install(request.identity(), admission)
            .unwrap_or_else(|error| panic!("admission directive should install: {error}"));
        storage
            .execute(&base, &mut durable, &request, 3)
            .unwrap_or_else(|error| panic!("request should enter staged execution: {error}"));

        let execution = storage
            .next_execution_opportunity(17)
            .unwrap_or_else(|| panic!("execution opportunity should be visible"));
        storage
            .install_execution_directive(ResolvedBlockExecutionDirective {
                directive: execution.admission.clone(),
                opportunity: execution,
            })
            .unwrap_or_else(|error| panic!("execution directive should install: {error}"));
        storage
            .resume_execution_to(&base, &mut durable, 17)
            .unwrap_or_else(|error| panic!("execution should reach persistence: {error}"));

        let persistence = storage
            .next_request_persistence_opportunity(17)
            .unwrap_or_else(|| panic!("request persistence should be visible"));
        let mut persisted = persistence.resolved.clone();
        persisted.persistence_admitted_nanos = 17;
        persisted.cache_policy = Some(ResolvedBlockCachePolicy {
            capacity_bytes: 64,
            eviction: BlockFaultCacheEviction::WritebackSequence,
            dirty_eviction: BlockFaultDirtyEviction::Persist,
            power_loss_protected: false,
        });
        persisted
            .persistence_transforms
            .push(ResolvedBlockPersistenceTransform {
                contributor: [7; 32],
                ordering_group: [6; 32],
                ordering: crate::block::BlockPersistenceOrdering::Preserve,
                delay_nanos: 100,
                preserve_barriers: true,
            });
        storage
            .install_request_persistence_directive(ResolvedBlockRequestPersistenceDirective {
                opportunity: persistence,
                directive: persisted,
            })
            .unwrap_or_else(|error| panic!("request persistence should install: {error}"));
        storage
            .resume_request_persistence_to(&base, &mut durable, 17)
            .unwrap_or_else(|error| panic!("request mutation should execute: {error}"));

        assert!(storage.next_delivery_opportunity(u64::MAX).is_none());
        assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), vec![0; 4]);
        storage
            .validate_restore(32)
            .unwrap_or_else(|error| panic!("pre-media checkpoint should validate: {error}"));
        let mut media_count = 0;
        while let Some(media) = storage.next_persistence_opportunity(117) {
            storage
                .install_persistence_media_directive(ResolvedBlockPersistenceMediaDirective {
                    opportunity: media,
                    flash_rules: Vec::new(),
                })
                .unwrap_or_else(|error| panic!("physical persistence should install: {error}"));
            storage
                .persist_due(&base, &mut durable, 117)
                .unwrap_or_else(|error| panic!("physical persistence should execute: {error}"));
            media_count += 1;
        }
        assert_eq!(media_count, 4);

        let delivery = storage
            .next_delivery_opportunity(117)
            .unwrap_or_else(|| panic!("delivery should follow actual durability"));
        storage
            .install_delivery_directive(ResolvedBlockDeliveryDirective {
                directive: delivery.resolved.clone(),
                opportunity: delivery,
            })
            .unwrap_or_else(|error| panic!("delivery directive should install: {error}"));
        let released = storage
            .resume_delivery_to(117)
            .unwrap_or_else(|error| panic!("durable completion should publish: {error}"));
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].finished_nanos, 117);
        assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), b"sync");
    }

    #[test]
    fn queue_service_release_creates_the_execution_opportunity() {
        let base = BaseImage::new(vec![0; 32]);
        let mut durable = CowOverlay::new();
        let mut storage = state(BlockCompletionDurability::Durable);
        storage.require_execution_opportunities(true);
        let request = BlockRequest::write(62, 0, b"work".to_vec());
        let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
        admission.request_sequence = 901;
        admission.execution_nanos = 10;
        admission.service_rules = vec![ResolvedBlockServiceRule {
            contributor: [7; 32],
            bytes_per_second: 4,
            iops: None,
            queue_depth: 1,
            discipline: super::super::service::BlockServiceDiscipline::Fifo,
            classes: Vec::new(),
            rebuild_shares_service: false,
        }];
        storage
            .install(request.identity(), admission)
            .unwrap_or_else(|error| panic!("service directive should install: {error}"));
        let queued = storage
            .execute(&base, &mut durable, &request, 1)
            .unwrap_or_else(|error| panic!("request should queue: {error}"));
        assert!(queued.primary.is_none());
        assert!(storage.next_execution_opportunity(u64::MAX).is_none());

        let finished = 1_000_000_010;
        assert!(
            storage
                .advance_service_to(&base, &mut durable, finished - 1)
                .unwrap_or_else(|error| panic!("early service advance should succeed: {error}"))
                .is_empty()
        );
        assert!(storage.next_execution_opportunity(finished - 1).is_none());
        assert!(
            storage
                .advance_service_to(&base, &mut durable, finished)
                .unwrap_or_else(|error| panic!("service release should succeed: {error}"))
                .is_empty()
        );
        let opportunity = storage
            .next_execution_opportunity(finished)
            .unwrap_or_else(|| panic!("released request should expose execution"));
        assert_eq!(opportunity.request_sequence, 901);
        assert_eq!(opportunity.ready_nanos, finished);
        assert_eq!(durable.read(&base, 0, 4).unwrap_or_default(), vec![0; 4]);
        storage
            .validate_restore(32)
            .unwrap_or_else(|error| panic!("service-release checkpoint should validate: {error}"));
    }

    #[test]
    fn service_evidence_precedes_same_nanos_persistence_it_triggers() {
        let base = BaseImage::new(vec![0; 32]);
        let mut durable = CowOverlay::new();
        let mut storage = BlockFaultState::new(BlockDurabilityConfig {
            length_bytes: 32,
            atomic_write_bytes: 4,
            maximum_request_bytes: 32,
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 32,
            cache_entries: 8,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: 32,
            retained_versions: 8,
            completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
        })
        .unwrap_or_else(|error| panic!("ordered-outcome state should build: {error}"));
        let cached = BlockRequest::write(70, 0, b"data".to_vec());
        storage
            .install(
                cached.identity(),
                ResolvedBlockFaultDirective::fault_free(&cached, 32),
            )
            .unwrap_or_else(|error| panic!("cached write should install: {error}"));
        storage
            .execute(&base, &mut durable, &cached, 0)
            .unwrap_or_else(|error| panic!("cached write should execute: {error}"));
        let finished = 1_000_000_010;

        let serviced = BlockRequest::read(71, 0, 4);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&serviced, 32);
        directive.execution_nanos = 10;
        directive.service_rules = vec![ResolvedBlockServiceRule {
            contributor: [9; 32],
            bytes_per_second: 4,
            iops: None,
            queue_depth: 1,
            discipline: super::super::service::BlockServiceDiscipline::Fifo,
            classes: Vec::new(),
            rebuild_shares_service: false,
        }];
        storage
            .install(serviced.identity(), directive)
            .unwrap_or_else(|error| panic!("serviced read should install: {error}"));
        storage
            .execute(&base, &mut durable, &serviced, 0)
            .unwrap_or_else(|error| panic!("serviced read should queue: {error}"));
        storage
            .schedule_volatile_persistence(0)
            .unwrap_or_else(|error| panic!("cached write should schedule: {error}"));
        storage
            .advance_service_to(&base, &mut durable, finished)
            .unwrap_or_else(|error| panic!("service and persistence should execute: {error}"));

        let outcomes = storage
            .storage_outcomes()
            .unwrap_or_else(|error| panic!("outcomes should remain ordered: {error}"));
        assert!(matches!(
            outcomes.as_slice(),
            [
                BlockStorageOutcome::Service(BlockServiceCompletion {
                    finished_nanos: service_nanos,
                    ..
                }),
                BlockStorageOutcome::Persistence(BlockPersistenceMediaOutcome {
                    executed_nanos: persistence_nanos,
                    ..
                })
            ] if service_nanos == persistence_nanos && *service_nanos == finished
        ));
    }
}
