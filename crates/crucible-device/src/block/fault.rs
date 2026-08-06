//! Exact block durability and resolved fault directives.
//!
//! The signal evaluator lives above `crucible-device`. Before a live request is
//! consumed it installs one fully resolved directive here. This layer applies
//! that directive to real block bytes, volatile cache state, durable state, and
//! the real response transported through the shared-memory ring. It performs no
//! signal evaluation and gives no semantic meaning to opaque policy names.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeviceError;
use crate::request::{ComputedResponse, Response, ResponseStatus};

use super::codec::{BlockOp, BlockRequest, BlockResponse, BlockStatus};
use super::overlay::{BaseImage, CowOverlay};

/// Hard maximum directives waiting for their exact request.
pub const HARD_PENDING_BLOCK_FAULT_DIRECTIVES: usize = 1_048_576;
/// Hard aggregate heap bytes retained by pending resolved directives.
pub const HARD_PENDING_BLOCK_FAULT_BYTES: u64 = 268_435_456;
/// Hard maximum volatile cache entries.
pub const HARD_BLOCK_CACHE_ENTRIES: usize = 4_194_304;
/// Hard maximum controller-accepted write entries.
pub const HARD_BLOCK_CONTROLLER_ENTRIES: usize = 4_194_304;
/// Hard maximum retained historical versions.
pub const HARD_BLOCK_RETAINED_VERSIONS: usize = 4_194_304;
/// Hard maximum exact spans in one resolved write directive.
pub const HARD_BLOCK_WRITE_SPANS: usize = 65_536;
/// Hard maximum duplicate completions from one operation.
pub const HARD_BLOCK_DUPLICATE_COMPLETIONS: usize = 256;
/// Hard maximum stalled completions retained across checkpoints.
pub const HARD_BLOCK_RETAINED_COMPLETIONS: usize = 1_048_576;

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

/// Immutable durability bounds for one block device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDurabilityConfig {
    /// Guest-visible device length without an active capacity effect.
    pub length_bytes: u64,
    /// Smallest independently applied write fragment.
    pub atomic_write_bytes: u32,
    /// Maximum admitted request bytes.
    pub maximum_request_bytes: u64,
    /// Maximum exact volatile-cache bytes.
    pub volatile_cache_bytes: u64,
    /// Maximum volatile-cache entries.
    pub cache_entries: u32,
    /// Maximum bytes accepted by the controller but not yet admitted to cache/media.
    pub controller_buffer_bytes: u64,
    /// Maximum controller-accepted write entries.
    pub controller_entries: u32,
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
            volatile_cache_bytes: 0,
            cache_entries: 0,
            controller_buffer_bytes: 0,
            controller_entries: 0,
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
        if self.atomic_write_bytes == 0
            || self.maximum_request_bytes == 0
            || (self.length_bytes > 0 && self.maximum_request_bytes > self.length_bytes)
            || cache_entries > HARD_BLOCK_CACHE_ENTRIES
            || controller_entries > HARD_BLOCK_CONTROLLER_ENTRIES
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
    Error,
    /// Returns success without advancing the actual durable frontier.
    Lie,
    /// Retains the completion until a later recovery event.
    Stall,
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
    },
}

/// Guest transport policy expanded into one or more duplicate completions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockDuplicatePolicy {
    /// The guest transport ignores every completion after the primary.
    Ignore,
    /// Every duplicate carries this matching typed protocol error.
    ProtocolError(BlockResponse),
    /// The first duplicate requires a live guest transport reset.
    Reset,
}

impl ResolvedBlockDuplicateCompletion {
    const fn gap_nanos(&self) -> u64 {
        match self {
            Self::Ignore { gap_nanos }
            | Self::ProtocolError { gap_nanos, .. }
            | Self::Reset { gap_nanos } => *gap_nanos,
        }
    }
}

/// One fully resolved directive consumed by exactly one block request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBlockFaultDirective {
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
    pub force_error: bool,
    /// Dynamic service, latency, stall, and reorder delay.
    pub additional_latency_nanos: u64,
    /// Whether the primary completion remains retained after COMPUTE.
    pub retain_completion: bool,
    /// Typed error returned if a retained operation times out.
    pub retention_timeout_response: Option<BlockResponse>,
    /// Canonically gap-ordered duplicate transport outcomes.
    pub duplicate_completions: Vec<ResolvedBlockDuplicateCompletion>,
    /// Ordered read transformations.
    pub read_transforms: Vec<BlockFaultReadTransform>,
    /// Write persistence disposition.
    pub write_disposition: BlockFaultWriteDisposition,
    /// Flush disposition.
    pub flush_disposition: BlockFaultFlushDisposition,
    /// Whether an admitted write enters volatile cache instead of durable media.
    pub use_volatile_cache: bool,
    /// Whether exact spans may split the declared atomic-write fragments.
    pub allow_subatomic_mutation: bool,
}

impl ResolvedBlockFaultDirective {
    /// Builds the exact fault-free directive for `request`.
    #[must_use]
    pub fn fault_free(request: &BlockRequest, capacity: u64) -> Self {
        Self {
            operation: request.op,
            offset: request.offset,
            count: request.count,
            request_digest: request_digest(request),
            availability: BlockFaultAvailability::Online,
            reported_capacity_bytes: capacity,
            force_error: false,
            additional_latency_nanos: 0,
            retain_completion: false,
            retention_timeout_response: None,
            duplicate_completions: Vec::new(),
            read_transforms: Vec::new(),
            write_disposition: BlockFaultWriteDisposition::Apply,
            flush_disposition: BlockFaultFlushDisposition::Honest,
            use_volatile_cache: false,
            allow_subatomic_mutation: false,
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
        let copies =
            usize::try_from(copies).map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate copy count does not fit memory",
            })?;
        if copies == 0
            || copies > HARD_BLOCK_DUPLICATE_COMPLETIONS
            || adjacent_gap_nanos == 0
            || matches!(
                &policy,
                BlockDuplicatePolicy::ProtocolError(response)
                    if response.request_id != request_id
                        || response.status != BlockStatus::Error
            )
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate completion policy is invalid",
            });
        }
        let mut resolved = Vec::with_capacity(copies);
        for index in 0..copies {
            let multiplier = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate completion index overflow",
                })?;
            let gap_nanos = adjacent_gap_nanos.checked_mul(multiplier).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate completion delay overflow",
                },
            )?;
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
                BlockDuplicatePolicy::Reset => {
                    ResolvedBlockDuplicateCompletion::Reset { gap_nanos }
                }
            });
        }
        self.duplicate_completions = resolved;
        Ok(())
    }

    fn validate_for(
        &self,
        request: &BlockRequest,
        config: &BlockDurabilityConfig,
    ) -> Result<(), DeviceError> {
        let device_length = config.length_bytes;
        self.validate_static(request.request_id, config)?;
        if self.operation != request.op
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
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "directive violates static block bounds",
            });
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
                    || response.status != BlockStatus::Error
                    || !block_response_fits_transport(response))
            {
                return Err(DeviceError::InvalidBlockFaultDirective {
                    reason: "duplicate protocol error is invalid for the request transport",
                });
            }
        }
        if !self.duplicate_completions.is_empty() {
            return Err(DeviceError::BlockDuplicateTransportUnavailable { request_id });
        }
        if self.operation != BlockOp::Read && !self.read_transforms.is_empty() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "read transforms require a read request",
            });
        }
        if self.operation != BlockOp::Write
            && self.write_disposition != BlockFaultWriteDisposition::Apply
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "write dispositions require a write request",
            });
        }
        if self.operation != BlockOp::Write && self.use_volatile_cache {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "volatile-cache admission requires a write request",
            });
        }
        if self.operation != BlockOp::Flush
            && self.flush_disposition != BlockFaultFlushDisposition::Honest
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "flush dispositions require a flush request",
            });
        }
        if self.flush_disposition == BlockFaultFlushDisposition::Stall && !self.retain_completion {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "a stalled flush must retain its completion",
            });
        }
        validate_write_disposition(
            &self.write_disposition,
            self.offset,
            u64::from(self.count),
            u64::from(config.atomic_write_bytes),
            self.allow_subatomic_mutation,
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
        Ok(())
    }
}

/// One admitted volatile write fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockVolatileEntry {
    /// Monotone cache admission sequence.
    pub sequence: u64,
    /// Original request ID.
    pub request_id: u32,
    /// Destination range start.
    pub offset: u64,
    /// Exact admitted bytes.
    pub bytes: Vec<u8>,
}

/// One write accepted by the controller but not yet admitted to media cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockControllerEntry {
    /// Monotone write sequence shared with cache and durable frontiers.
    pub sequence: u64,
    /// Original request ID.
    pub request_id: u32,
    /// Destination range start.
    pub offset: u64,
    /// Exact accepted bytes.
    pub bytes: Vec<u8>,
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
    /// Original request identity.
    pub request_id: u32,
    /// Complete uniform wire response released on recovery.
    pub recovery_response: Response,
    /// Complete uniform wire response released on timeout.
    pub timeout_response: Response,
    /// Original request coordinate retained for replay evidence.
    pub request_icount: u64,
    /// Dynamic delay selected before the completion was retained.
    pub additional_latency_nanos: u64,
    /// Exclusive captured write frontier persisted before recovered flush success.
    pub persist_through_on_recovery: Option<u64>,
}

/// Checkpointed durability, cache, version, and directive state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFaultState {
    config: BlockDurabilityConfig,
    execution_required: bool,
    pending: BTreeMap<u32, ResolvedBlockFaultDirective>,
    pending_bytes: u64,
    controller: BTreeMap<u64, BlockControllerEntry>,
    controller_bytes: u64,
    volatile: BTreeMap<u64, BlockVolatileEntry>,
    volatile_bytes: u64,
    retained: BTreeMap<u64, BlockRetainedVersion>,
    next_cache_sequence: u64,
    next_version_sequence: u64,
    actual_durable_frontier: u64,
    reported_durable_frontier: u64,
    retained_completions: BTreeMap<u32, BlockRetainedCompletion>,
}

impl BlockFaultState {
    /// Creates fault-free write-through state for a device.
    #[must_use]
    pub fn write_through(length_bytes: u64) -> Self {
        Self {
            config: BlockDurabilityConfig::write_through(length_bytes),
            execution_required: false,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            controller: BTreeMap::new(),
            controller_bytes: 0,
            volatile: BTreeMap::new(),
            volatile_bytes: 0,
            retained: BTreeMap::new(),
            next_cache_sequence: 0,
            next_version_sequence: 0,
            actual_durable_frontier: 0,
            reported_durable_frontier: 0,
            retained_completions: BTreeMap::new(),
        }
    }

    /// Creates a validated fault-free write-through state.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when `config` violates geometry or hard bounds.
    pub fn new(config: BlockDurabilityConfig) -> Result<Self, DeviceError> {
        config.validate()?;
        Ok(Self {
            config,
            execution_required: false,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            controller: BTreeMap::new(),
            controller_bytes: 0,
            volatile: BTreeMap::new(),
            volatile_bytes: 0,
            retained: BTreeMap::new(),
            next_cache_sequence: 0,
            next_version_sequence: 0,
            actual_durable_frontier: 0,
            reported_durable_frontier: 0,
            retained_completions: BTreeMap::new(),
        })
    }

    /// Enables or disables the fail-closed requirement for exact directives.
    pub fn require_directives(&mut self, required: bool) {
        self.execution_required = required;
    }

    /// Returns whether no request, mutation, or sequence has entered this state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.pending.is_empty()
            && self.pending_bytes == 0
            && self.controller.is_empty()
            && self.controller_bytes == 0
            && self.volatile.is_empty()
            && self.volatile_bytes == 0
            && self.retained.is_empty()
            && self.retained_completions.is_empty()
            && self.next_cache_sequence == 0
            && self.next_version_sequence == 0
            && self.actual_durable_frontier == 0
            && self.reported_durable_frontier == 0
    }

    /// Validates all checkpointed storage-state invariants against a device.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for geometry mismatch, accounting drift,
    /// out-of-range entries, exhausted bounds, or malformed retained responses.
    pub fn validate_restore(&self, device_length: u64) -> Result<(), DeviceError> {
        self.config.validate()?;
        if self.config.length_bytes != device_length
            || self.pending.len() > HARD_PENDING_BLOCK_FAULT_DIRECTIVES
            || self.pending_bytes > HARD_PENDING_BLOCK_FAULT_BYTES
            || self.volatile.len() > HARD_BLOCK_CACHE_ENTRIES
            || self.controller.len() > HARD_BLOCK_CONTROLLER_ENTRIES
            || self.retained.len() > HARD_BLOCK_RETAINED_VERSIONS
            || self.retained_completions.len() > HARD_BLOCK_RETAINED_COMPLETIONS
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
        for (request_id, directive) in &self.pending {
            directive.validate_static(*request_id, &self.config)?;
        }
        let volatile_bytes = self.volatile.values().try_fold(0_u64, |total, entry| {
            validate_state_range(entry.offset, entry.bytes.len(), device_length)?;
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
        if volatile_bytes != self.volatile_bytes
            || controller_bytes != self.controller_bytes
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
            || self.actual_durable_frontier > self.next_cache_sequence
            || self.reported_durable_frontier > self.next_cache_sequence
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored block fault state has invalid accounting or sequence",
            });
        }
        for (request_id, completion) in &self.retained_completions {
            if *request_id != completion.request_id
                || completion.recovery_response.request_id != *request_id
                || completion.timeout_response.request_id != *request_id
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
                if decoded.request_id != *request_id
                    || (decoded.status == BlockStatus::Ok)
                        != (response.status == ResponseStatus::Ok)
                {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "restored retained completion payload differs from its envelope",
                    });
                }
            }
        }
        Ok(())
    }

    /// Installs one directive, keyed by the exact guest request ID.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate IDs or a hard pending-state limit.
    pub fn install(
        &mut self,
        request_id: u32,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        directive.validate_static(request_id, &self.config)?;
        if self.pending.len() == HARD_PENDING_BLOCK_FAULT_DIRECTIVES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_directives",
                hard: HARD_PENDING_BLOCK_FAULT_DIRECTIVES,
            });
        }
        if self.pending.contains_key(&request_id) {
            return Err(DeviceError::DuplicateBlockFaultDirective { request_id });
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
        self.pending.insert(request_id, directive);
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

    /// Returns controller-accepted writes in global sequence order.
    #[must_use]
    pub const fn controller_entries(&self) -> &BTreeMap<u64, BlockControllerEntry> {
        &self.controller
    }

    /// Returns retained versions in version sequence order.
    #[must_use]
    pub const fn retained_versions(&self) -> &BTreeMap<u64, BlockRetainedVersion> {
        &self.retained
    }

    /// Returns completions waiting for an explicit recovery or timeout event.
    #[must_use]
    pub const fn retained_completions(&self) -> &BTreeMap<u32, BlockRetainedCompletion> {
        &self.retained_completions
    }

    /// Returns one retained completion without consuming it.
    #[must_use]
    pub fn retained_completion(&self, request_id: u32) -> Option<&BlockRetainedCompletion> {
        self.retained_completions.get(&request_id)
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
        request_id: u32,
        release: BlockRetainedRelease,
    ) -> Result<Response, DeviceError> {
        let completion = self.retained_completions.get(&request_id).cloned().ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "storage completion is not retained",
            },
        )?;
        let response = match release {
            BlockRetainedRelease::Recovery => {
                if let Some(frontier) = completion.persist_through_on_recovery {
                    self.persist_through(base, durable, frontier)?;
                    self.reported_durable_frontier = frontier;
                }
                completion.recovery_response
            }
            BlockRetainedRelease::Timeout => completion.timeout_response,
        };
        self.retained_completions.remove(&request_id);
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
        for sequence in selected {
            if let Some(entry) = self.volatile.remove(&sequence) {
                self.volatile_bytes = self
                    .volatile_bytes
                    .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "volatile byte accounting underflow",
                    })?;
            }
        }
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
        for sequence in selected {
            if let Some(entry) = self.controller.remove(&sequence) {
                self.controller_bytes = self
                    .controller_bytes
                    .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "controller byte accounting underflow",
                    })?;
            }
        }
        Ok(())
    }

    pub(super) fn execute(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
    ) -> Result<ComputedResponse, DeviceError> {
        let directive = match self.pending.get(&request.request_id) {
            Some(directive) => directive.clone(),
            None if self.execution_required => {
                return Err(DeviceError::MissingBlockFaultDirective {
                    request_id: request.request_id,
                });
            }
            None => ResolvedBlockFaultDirective::fault_free(request, self.config.length_bytes),
        };
        directive.validate_for(request, &self.config)?;
        if !directive.duplicate_completions.is_empty() {
            return Err(DeviceError::BlockDuplicateTransportUnavailable {
                request_id: request.request_id,
            });
        }
        if directive.retain_completion
            && self.retained_completions.contains_key(&request.request_id)
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
        let mut next = self.clone();
        if let Some(removed) = next.pending.remove(&request.request_id) {
            next.pending_bytes = next
                .pending_bytes
                .checked_sub(directive_owned_bytes(&removed)?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte accounting underflow",
                })?;
        }
        let mut next_durable = durable.clone();
        let response = next.execute_wire(base, &mut next_durable, request, &directive)?;
        let encoded = response.encode().map_err(DeviceError::Codec)?;
        let status = if response.status == BlockStatus::Ok {
            ResponseStatus::Ok
        } else {
            ResponseStatus::Error
        };
        let primary = Response::new(request.request_id, status, encoded);
        if directive.retain_completion {
            next.retained_completions.insert(
                request.request_id,
                BlockRetainedCompletion {
                    request_id: request.request_id,
                    recovery_response: primary.clone(),
                    timeout_response: block_response_to_uniform(
                        directive.retention_timeout_response.as_ref().ok_or(
                            DeviceError::InvalidBlockFaultDirective {
                                reason: "retained completion lost its timeout response",
                            },
                        )?,
                    )?,
                    request_icount,
                    additional_latency_nanos: directive.additional_latency_nanos,
                    persist_through_on_recovery: (request.op == BlockOp::Flush
                        && directive.flush_disposition == BlockFaultFlushDisposition::Stall)
                        .then_some(next.next_cache_sequence),
                },
            );
        }
        let computed = ComputedResponse {
            primary: (!directive.retain_completion).then_some(primary),
            additional: Vec::new(),
            additional_latency_nanos: directive.additional_latency_nanos,
        };
        *self = next;
        *durable = next_durable;
        Ok(computed)
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
        self.apply_write(base, durable, &request, &directive)
    }

    fn execute_wire(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<BlockResponse, DeviceError> {
        if directive.force_error
            || directive.availability == BlockFaultAvailability::Offline
            || (directive.availability == BlockFaultAvailability::ReadOnly
                && request.op == BlockOp::Write)
            || !request_in_capacity(request, directive.reported_capacity_bytes)
            || u64::from(request.count) > self.config.maximum_request_bytes
            || (request.op == BlockOp::Read
                && usize::try_from(request.count).unwrap_or(usize::MAX)
                    > super::device::MAX_READ_BYTES)
        {
            return Ok(BlockResponse::error(request.request_id));
        }
        match request.op {
            BlockOp::Read => {
                let mut bytes = self.read_visible(base, durable, request.offset, request.count)?;
                apply_read_transforms(&mut bytes, &directive.read_transforms)?;
                Ok(BlockResponse::ok(request.request_id, bytes))
            }
            BlockOp::Write => {
                self.apply_write(base, durable, request, directive)?;
                Ok(BlockResponse::ok(request.request_id, Vec::new()))
            }
            BlockOp::Flush => match directive.flush_disposition {
                BlockFaultFlushDisposition::Honest => {
                    self.persist_all(base, durable)?;
                    self.reported_durable_frontier = self.actual_durable_frontier;
                    Ok(BlockResponse::ok(request.request_id, Vec::new()))
                }
                BlockFaultFlushDisposition::Error => Ok(BlockResponse::error(request.request_id)),
                BlockFaultFlushDisposition::Lie => {
                    self.reported_durable_frontier = self.next_cache_sequence;
                    Ok(BlockResponse::ok(request.request_id, Vec::new()))
                }
                BlockFaultFlushDisposition::Stall => {
                    Ok(BlockResponse::ok(request.request_id, Vec::new()))
                }
            },
            BlockOp::GetLength => Ok(BlockResponse::ok(
                request.request_id,
                directive.reported_capacity_bytes.to_le_bytes().to_vec(),
            )),
        }
    }

    fn read_visible(
        &self,
        base: &BaseImage,
        durable: &CowOverlay,
        offset: u64,
        count: u32,
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
            .collect::<BTreeMap<_, _>>();
        for (_sequence, (entry_offset, entry_bytes)) in visible {
            let entry_end = entry_offset
                .checked_add(u64::try_from(entry_bytes.len()).unwrap_or(u64::MAX))
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "volatile entry range overflow",
                })?;
            let overlap_start = offset.max(entry_offset);
            let overlap_end = end.min(entry_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let destination = usize::try_from(overlap_start - offset).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "read overlap does not fit memory",
                }
            })?;
            let source = usize::try_from(overlap_start - entry_offset).map_err(|_error| {
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
        }
        Ok(bytes)
    }

    fn apply_write(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        directive: &ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        let (destination, spans) = match &directive.write_disposition {
            BlockFaultWriteDisposition::Apply => (
                request.offset,
                canonical_atomic_spans(
                    request.offset,
                    u64::from(request.count),
                    u64::from(self.config.atomic_write_bytes),
                )?,
            ),
            BlockFaultWriteDisposition::Lost => return Ok(()),
            BlockFaultWriteDisposition::Torn { spans }
            | BlockFaultWriteDisposition::ProgramFailure { spans } => {
                (request.offset, spans.clone())
            }
            BlockFaultWriteDisposition::Misdirected { destination_offset } => (
                *destination_offset,
                canonical_atomic_spans(
                    request.offset,
                    u64::from(request.count),
                    u64::from(self.config.atomic_write_bytes),
                )?,
            ),
        };
        let mut resolved = Vec::with_capacity(spans.len());
        let mut admitted_bytes = 0_u64;
        for span in spans {
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
            resolved.push((offset, bytes));
        }

        let controller = !directive.use_volatile_cache
            && self.config.completion_durability == BlockCompletionDurability::ControllerAccepted;
        let cache = directive.use_volatile_cache
            || self.config.completion_durability
                == BlockCompletionDurability::VolatileCacheAccepted;
        if controller || cache {
            let (entry_limit, occupied_entries, byte_limit, occupied_bytes) = if controller {
                (
                    self.config.controller_entries,
                    self.controller.len(),
                    self.config.controller_buffer_bytes,
                    self.controller_bytes,
                )
            } else {
                (
                    self.config.cache_entries,
                    self.volatile.len(),
                    self.config.volatile_cache_bytes,
                    self.volatile_bytes,
                )
            };
            let available_entries = usize::try_from(entry_limit)
                .unwrap_or(usize::MAX)
                .saturating_sub(occupied_entries);
            let available_bytes = byte_limit.saturating_sub(occupied_bytes);
            if resolved.len() > available_entries || admitted_bytes > available_bytes {
                return Err(DeviceError::BlockCacheFull {
                    requested_bytes: admitted_bytes,
                    available_bytes,
                });
            }
            let sequence_count = u64::try_from(resolved.len()).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "write fragment count does not fit the sequence space",
                }
            })?;
            self.next_cache_sequence.checked_add(sequence_count).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "cache sequence overflow",
                },
            )?;
        }
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
        if !cache && !controller {
            self.next_cache_sequence.checked_add(version_count).ok_or(
                DeviceError::InvalidBlockFaultDirective {
                    reason: "durable sequence overflow",
                },
            )?;
        }

        for (offset, bytes) in resolved {
            self.retain_prior(
                base,
                durable,
                offset,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            )?;
            if controller {
                self.controller_write(request.request_id, offset, bytes.to_vec())?;
            } else if cache {
                self.cache_write(request.request_id, offset, bytes.to_vec())?;
            } else {
                durable.write(base, offset, bytes)?;
                self.next_cache_sequence = self.next_cache_sequence.checked_add(1).ok_or(
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "durable sequence overflow",
                    },
                )?;
                self.actual_durable_frontier = self.next_cache_sequence;
                self.reported_durable_frontier = self.actual_durable_frontier;
            }
        }
        Ok(())
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
        request_id: u32,
        offset: u64,
        bytes: Vec<u8>,
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
        let sequence = self.next_cache_sequence;
        self.next_cache_sequence = self.next_cache_sequence.checked_add(1).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "cache sequence overflow",
            },
        )?;
        self.volatile.insert(
            sequence,
            BlockVolatileEntry {
                sequence,
                request_id,
                offset,
                bytes,
            },
        );
        self.volatile_bytes = next_bytes;
        Ok(())
    }

    fn controller_write(
        &mut self,
        request_id: u32,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(), DeviceError> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let sequence = self.next_cache_sequence;
        self.next_cache_sequence = self.next_cache_sequence.checked_add(1).ok_or(
            DeviceError::InvalidBlockFaultDirective {
                reason: "controller sequence overflow",
            },
        )?;
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
    ) -> Result<(), DeviceError> {
        self.persist_through(base, durable, self.next_cache_sequence)
    }

    fn persist_through(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        frontier: u64,
    ) -> Result<(), DeviceError> {
        if frontier > self.next_cache_sequence {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "flush persistence frontier exceeds issued storage sequence",
            });
        }
        let controller_sequences = self
            .controller
            .range(..frontier)
            .map(|(sequence, _entry)| *sequence)
            .collect::<Vec<_>>();
        let volatile_sequences = self
            .volatile
            .range(..frontier)
            .map(|(sequence, _entry)| *sequence)
            .collect::<Vec<_>>();
        let mut writes = controller_sequences
            .iter()
            .filter_map(|sequence| {
                self.controller
                    .get(sequence)
                    .map(|entry| (*sequence, entry.offset, entry.bytes.clone()))
            })
            .chain(volatile_sequences.iter().filter_map(|sequence| {
                self.volatile
                    .get(sequence)
                    .map(|entry| (*sequence, entry.offset, entry.bytes.clone()))
            }))
            .collect::<Vec<_>>();
        writes.sort_by_key(|(sequence, _offset, _bytes)| *sequence);
        for (_sequence, offset, bytes) in &writes {
            durable.write(base, *offset, bytes)?;
        }
        for sequence in controller_sequences {
            if let Some(entry) = self.controller.remove(&sequence) {
                self.controller_bytes = self
                    .controller_bytes
                    .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "controller byte accounting underflow during persistence",
                    })?;
            }
        }
        for sequence in volatile_sequences {
            if let Some(entry) = self.volatile.remove(&sequence) {
                self.volatile_bytes = self
                    .volatile_bytes
                    .checked_sub(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or(DeviceError::InvalidBlockFaultDirective {
                        reason: "volatile byte accounting underflow during persistence",
                    })?;
            }
        }
        self.actual_durable_frontier = self.actual_durable_frontier.max(frontier);
        Ok(())
    }
}

fn request_in_capacity(request: &BlockRequest, capacity: u64) -> bool {
    match request.op {
        BlockOp::Read | BlockOp::Write => request
            .offset
            .checked_add(u64::from(request.count))
            .is_some_and(|end| end <= capacity),
        BlockOp::Flush | BlockOp::GetLength => true,
    }
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
            && (!boundaries.binary_search(&span.start).is_ok()
                || !boundaries.binary_search(&end).is_ok())
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
            volatile_cache_bytes: 64,
            cache_entries: 64,
            controller_buffer_bytes: 64,
            controller_entries: 64,
            retained_versions: 8,
            completion_durability: durability,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"))
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
            .install(request.request_id, directive)
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
        assert_eq!(state.actual_durable_frontier(), 10);
        assert_eq!(state.reported_durable_frontier(), 10);
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
        directive.retention_timeout_response = Some(BlockResponse::error(flush.request_id));
        state
            .install(flush.request_id, directive)
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
                .retained_completion(flush.request_id)
                .map(|held| held.request_id),
            Some(flush.request_id)
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
                flush.request_id,
                BlockRetainedRelease::Recovery,
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
        directive.retention_timeout_response = Some(BlockResponse::error(flush.request_id));
        state
            .install(flush.request_id, directive)
            .unwrap_or_else(|error| panic!("directive installs: {error}"));
        let computed = state
            .execute(&base, &mut durable, &flush, 99)
            .unwrap_or_else(|error| panic!("flush executes: {error}"));
        assert!(computed.primary.is_none());
        let retained = state
            .retained_completion(flush.request_id)
            .unwrap_or_else(|| panic!("completion is retained"));
        assert_eq!(retained.request_icount, 99);
        assert_eq!(retained.persist_through_on_recovery, Some(4));

        let released = state
            .resolve_retained_completion(
                &base,
                &mut durable,
                flush.request_id,
                BlockRetainedRelease::Timeout,
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
            volatile_cache_bytes: 3,
            cache_entries: 1,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            retained_versions: 2,
            completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
        })
        .unwrap_or_else(|error| panic!("valid test state: {error}"));
        let request = BlockRequest::write(1, 0, b"four".to_vec());
        let directive = ResolvedBlockFaultDirective::fault_free(&request, base.len());
        state
            .install(request.request_id, directive)
            .unwrap_or_else(|error| panic!("directive installs: {error}"));
        let before_state = state.clone();
        let before_durable = durable.clone();
        assert!(matches!(
            state.execute(&base, &mut durable, &request, 0),
            Err(DeviceError::BlockCacheFull { .. })
        ));
        assert_eq!(state, before_state);
        assert_eq!(durable, before_durable);
    }

    #[test]
    fn duplicate_directive_rejection_preserves_the_original() {
        let request = BlockRequest::read(7, 0, 4);
        let mut state = state(BlockCompletionDurability::Durable);
        let original = ResolvedBlockFaultDirective::fault_free(&request, 32);
        let mut replacement = original.clone();
        replacement.force_error = true;
        state
            .install(request.request_id, original.clone())
            .unwrap_or_else(|error| panic!("first directive installs: {error}"));
        assert_eq!(
            state.install(request.request_id, replacement),
            Err(DeviceError::DuplicateBlockFaultDirective {
                request_id: request.request_id
            })
        );
        assert_eq!(state.pending.get(&request.request_id), Some(&original));
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
        let before = directive.duplicate_completions.clone();
        assert!(
            directive
                .configure_duplicate_completions(
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
    fn duplicate_install_fails_before_a_request_can_enter_without_live_transport() {
        let request = BlockRequest::write(7, 0, b"data".to_vec());
        let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 32);
        directive
            .configure_duplicate_completions(request.request_id, 1, 11, BlockDuplicatePolicy::Reset)
            .unwrap_or_else(|error| panic!("duplicate policy resolves: {error}"));
        let mut state = state(BlockCompletionDurability::Durable);
        let before_state = state.clone();

        assert_eq!(
            state.install(request.request_id, directive),
            Err(DeviceError::BlockDuplicateTransportUnavailable {
                request_id: request.request_id,
            })
        );
        assert_eq!(state, before_state);
    }

    #[test]
    fn timeout_and_duplicate_responses_must_fit_one_transport_frame() {
        let request = BlockRequest::flush(9);
        let oversized = BlockResponse {
            status: BlockStatus::Error,
            request_id: request.request_id,
            data: vec![0; crucible_shmem::MAX_FRAME_DATA],
        };
        let mut retained = ResolvedBlockFaultDirective::fault_free(&request, 32);
        retained.flush_disposition = BlockFaultFlushDisposition::Stall;
        retained.retain_completion = true;
        retained.retention_timeout_response = Some(oversized.clone());
        assert!(matches!(
            state(BlockCompletionDurability::Durable).install(request.request_id, retained),
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
            state(BlockCompletionDurability::Durable).install(read.request_id, duplicate),
            Err(DeviceError::InvalidBlockFaultDirective { .. })
        ));
    }
}
