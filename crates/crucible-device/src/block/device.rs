//! The block sub-node: an [`IoSubNode`] over a base image and CoW overlay.
//!
//! This module owns [`BlockDevice`], which implements the COMPUTE half of the
//! uniform lifecycle for block I/O. It decodes a [`BlockRequest`] from the
//! request payload, serves it against the [`BaseImage`] + [`CowOverlay`]
//! ([IO-5], [IO-6]), and re-encodes a [`BlockResponse`] as the response payload.
//! The deterministic completion time is supplied by [`BlockLatency`] and applied
//! by the [`IoCore`] the device composes ([IO-10], [IO-22]).
//!
//! It also owns [`BlockSnapshot`], the device half of a `MaterializedState`
//! contribution: the overlay delta (dirty pages only), the device RNG position
//! cursor, the active fault table, the in-flight responses, the base hash, and
//! the device length — **never** the base image bytes ([IO-11], [TEMP-9]).
//! [`BlockDevice::restore`]
//! stacks the delta over a parent overlay and re-arms the in-flight queue, and
//! [`BlockDevice::materialize`] hands off a standalone raw image ([IO-12]).
//!
//! ```text
//! request payload  = BlockRequest::encode()   (rides the SLOT_BLK_IO ring)
//! compute(req):
//!   decode -> serve over overlay/base -> BlockResponse
//!   malformed bytes / out-of-range    -> error-status BlockResponse (never panic)
//! response payload = BlockResponse::encode()
//! delivery_icount  = ceil(vt(request_icount) + BlockLatency::latency_ns)
//! ```

use crucible_shmem::{FrameEntry, NodeSlot, RingHeader, icount_to_virtual_ns};

use crate::error::DeviceError;
use crate::request::{ComputedResponse, LatencyModel, Request, Response, ResponseStatus};
use crate::subnode::{IoCore, IoSubNode, ShmemDeliveryResult, ShmemInboxProcess};

use super::codec::{
    BlockErrorCode, BlockOp, BlockRequest, BlockRequestIdentity, BlockResponse, RESPONSE_HEADER_LEN,
};
use super::codec::{BlockStatus, BlockTransportReset, BlockTransportUndelivered};
use super::fault::keyed_discard_bytes;
use super::fault::{
    BlockCompletionDurability, BlockDeliveryOpportunity, BlockDiscardSemantics,
    BlockDurabilityConfig, BlockExecutionOpportunity, BlockFaultState,
    BlockPersistenceMediaOutcome, BlockPersistenceOpportunity, BlockRequestPersistenceOpportunity,
    BlockRetainedRelease, BlockRetainedReleaseOutcome, BlockStorageOutcome,
    ResolvedBlockControllerTransition, ResolvedBlockDeliveryDirective,
    ResolvedBlockExecutionDirective, ResolvedBlockFaultDirective,
    ResolvedBlockPersistenceMediaDirective, ResolvedBlockRequestPersistenceDirective,
};
use super::overlay::{BaseImage, CowOverlay};
use super::service::BlockServiceCompletion;

mod snapshot;
pub use snapshot::{BlockSnapshot, BlockSnapshotCodecError};

/// The largest read payload that fits one shmem frame alongside its header.
///
/// A [`BlockResponse`] rides a single SPSC frame whose data field is
/// [`crucible_shmem::MAX_FRAME_DATA`] bytes ([SHM-13]); the read payload must
/// leave room for the fixed [`RESPONSE_HEADER_LEN`]-byte response header. A read
/// whose `count` exceeds this is rejected with an error status ([IO-8]) rather
/// than emitting an un-transportable frame. The bound is derived from the
/// `crucible-shmem` constant, never hardcoded, so it tracks the ABI.
pub const MAX_READ_BYTES: usize = crucible_shmem::MAX_FRAME_DATA - RESPONSE_HEADER_LEN;

/// The deterministic completion-latency model for the block device.
///
/// Latency is `base_op_ns(op) + per_byte_ns * count` — a pure function of the
/// operation and the byte count and the device's configured parameters, with no
/// host-timing term ([IO-10], [IO-22]). The per-op floors let read, write, and
/// flush differ. All arithmetic saturates so an adversarial `count` cannot
/// panic; no floating point is used ([IO-24]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockLatency {
    /// Fixed latency floor for a read, in virtual nanoseconds.
    pub read_base_ns: u64,
    /// Fixed latency floor for a write, in virtual nanoseconds.
    pub write_base_ns: u64,
    /// Fixed latency for a flush, in virtual nanoseconds.
    pub flush_ns: u64,
    /// Fixed latency for a get-length, in virtual nanoseconds.
    pub get_length_ns: u64,
    /// Per-byte transfer cost added to a read or write, in virtual nanoseconds.
    pub per_byte_ns: u64,
}

impl BlockLatency {
    /// Creates a latency model from explicit per-op and per-byte parameters.
    #[must_use]
    pub fn new(
        read_base_ns: u64,
        write_base_ns: u64,
        flush_ns: u64,
        get_length_ns: u64,
        per_byte_ns: u64,
    ) -> Self {
        Self {
            read_base_ns,
            write_base_ns,
            flush_ns,
            get_length_ns,
            per_byte_ns,
        }
    }

    /// Returns the modeled latency for an operation and byte count.
    ///
    /// Saturating throughout so a hostile `count` yields `u64::MAX` rather than
    /// overflowing.
    #[must_use]
    pub fn latency_for(&self, op: BlockOp, count: u32) -> u64 {
        let variable = self.per_byte_ns.saturating_mul(u64::from(count));
        match op {
            BlockOp::Read => self.read_base_ns.saturating_add(variable),
            BlockOp::Write => self.write_base_ns.saturating_add(variable),
            BlockOp::Flush => self.flush_ns,
            BlockOp::GetLength => self.get_length_ns,
            BlockOp::Discard => self.write_base_ns.saturating_add(variable),
        }
    }
}

impl Default for BlockLatency {
    /// A modest default model: read/write floors with a small per-byte cost.
    fn default() -> Self {
        Self {
            read_base_ns: 1_000,
            write_base_ns: 1_500,
            flush_ns: 500,
            get_length_ns: 100,
            per_byte_ns: 1,
        }
    }
}

impl LatencyModel for BlockLatency {
    /// Derives latency from the encoded [`BlockRequest`] in the payload.
    ///
    /// A request payload that fails to decode is modeled with the read floor so
    /// the error response still completes at a deterministic, host-independent
    /// icount; the byte count for that case is zero.
    fn latency_ns(&self, request: &Request) -> u64 {
        match BlockRequest::decode(&request.payload) {
            Ok(decoded) => self.latency_for(decoded.op, decoded.count),
            Err(_) => self.read_base_ns,
        }
    }
}

/// A block device sub-node over a read-only base image and a CoW overlay.
///
/// Composes an [`IoCore`] (clock, rings, in-flight queue) with the device state
/// (base image, overlay, latency model, and exact storage continuation). Drive it with
/// [`IoCore`]'s lifecycle methods reached through [`BlockDevice::core_mut`], or
/// the convenience wrappers [`BlockDevice::submit`] / [`BlockDevice::advance_to`]
/// / [`BlockDevice::next_response`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDevice {
    core: IoCore,
    base: BaseImage,
    overlay: CowOverlay,
    storage_faults: BlockFaultState,
    latency: BlockLatency,
}

struct PreparedBlockTransportReset {
    storage_faults: BlockFaultState,
    inflight: Vec<crate::inflight::PendingResponse>,
    immediate: Vec<Response>,
}

/// Atomically installs a persist-phase write redirected to another device.
///
/// The destination receives the exact request bytes through its own admitted
/// geometry and durability state. The source retains the sole guest completion
/// and executes the request as a locally lost write after both cloned device
/// states commit together. Its completion carries an exact destination
/// durability dependency so the guest cannot observe success before that
/// frontier is acknowledged.
///
/// # Errors
///
/// Returns [`DeviceError`] if the directive is not an external misdirected
/// write for `destination_device`, either staged mutation fails, or the source
/// persistence opportunity is stale. Neither device changes on error.
pub fn install_cross_device_misdirected_persistence(
    source: &mut BlockDevice,
    destination: &mut BlockDevice,
    mut resolved: ResolvedBlockRequestPersistenceDirective,
    destination_device: [u8; 32],
) -> Result<super::fault::BlockExternalDurabilityDependency, DeviceError> {
    let destination_offset = match resolved.directive.write_disposition {
        super::fault::BlockFaultWriteDisposition::Misdirected {
            destination: super::fault::BlockFaultMisdirectionDestination::ExternalDevice(device),
            destination_offset,
        } if device == destination_device => destination_offset,
        _ => {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "cross-device persistence requires its exact external destination",
            });
        }
    };
    if resolved.opportunity.request.op != BlockOp::Write {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "cross-device persistence requires a write request",
        });
    }
    let mut next_source = source.clone();
    let mut next_destination = destination.clone();
    let (destination_durability, destination_frontier) =
        next_destination.storage_faults.apply_external_write(
            &next_destination.base,
            &mut next_destination.overlay,
            resolved.opportunity.request.request_id,
            resolved.directive.request_sequence,
            resolved.opportunity.ready_nanos,
            destination_offset,
            resolved.opportunity.request.data.clone(),
        )?;
    resolved.directive.write_disposition = super::fault::BlockFaultWriteDisposition::Lost;
    let dependency = super::fault::BlockExternalDurabilityDependency {
        destination_device,
        required_durability: destination_durability,
        required_frontier: destination_frontier,
    };
    resolved.directive.external_durability_dependencies = vec![dependency];
    next_source.install_storage_request_persistence_directive(resolved)?;
    *source = next_source;
    *destination = next_destination;
    Ok(dependency)
}

impl BlockDevice {
    /// Applies one exact logical write from a multi-device storage frontend.
    ///
    /// The destination uses its own geometry, cache, persistence graph, and
    /// completion-durability policy. This method does not schedule a guest
    /// response; the logical frontend remains the sole response owner.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the range or request geometry is invalid,
    /// the destination cannot admit the bytes, or durability mutation fails.
    pub fn apply_storage_external_write(
        &mut self,
        request_id: u32,
        request_sequence: u64,
        admitted_nanos: u64,
        destination_offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        self.storage_faults.apply_external_write(
            &self.base,
            &mut self.overlay,
            request_id,
            request_sequence,
            admitted_nanos,
            destination_offset,
            bytes,
        )
    }

    /// Applies one exact write, discard, or flush from a multi-device frontend.
    ///
    /// The request executes against this device's real cache and durability
    /// continuation but creates no guest completion. The returned dependency
    /// frontier lets the logical frontend delay its sole completion until this
    /// member reaches the required durability stage.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the request is a read or length query, its
    /// range is invalid, or the member cannot admit the requested mutation.
    pub fn apply_storage_external_mutation(
        &mut self,
        request_sequence: u64,
        admitted_nanos: u64,
        request: BlockRequest,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        self.storage_faults.apply_external_mutation(
            &self.base,
            &mut self.overlay,
            request_sequence,
            admitted_nanos,
            request,
        )
    }

    /// Records logical ranges that an array write could not place on members.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the range is invalid or bounded dirty-range
    /// continuation is exhausted.
    pub fn record_storage_array_dirty_range(
        &mut self,
        member: u16,
        start_byte: u64,
        bytes: Vec<u8>,
        dirty_nanos: u64,
    ) -> Result<(), DeviceError> {
        let mut next = self.storage_faults.clone();
        next.record_array_dirty_range(member, start_byte, bytes, dirty_nanos)?;
        self.storage_faults = next;
        Ok(())
    }

    /// Schedules or returns the next exact array rebuild chunk.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid service parameters or overflow.
    pub fn next_storage_array_rebuild_opportunity(
        &mut self,
        now_nanos: u64,
        chunk_bytes: u64,
        bytes_per_second: u64,
        operations_per_second: Option<u64>,
    ) -> Result<Option<super::fault::BlockArrayRebuildOpportunity>, DeviceError> {
        let mut next = self.storage_faults.clone();
        let opportunity = next.next_array_rebuild_opportunity(
            now_nanos,
            chunk_bytes,
            bytes_per_second,
            operations_per_second,
        )?;
        self.storage_faults = next;
        Ok(opportunity)
    }

    /// Acknowledges one exact array rebuild chunk after member commit.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale or no longer
    /// matches the checkpointed dirty bytes.
    pub fn complete_storage_array_rebuild(
        &mut self,
        opportunity: &super::fault::BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.storage_faults.complete_array_rebuild(opportunity)
    }

    /// Retires a failed rebuild attempt while retaining its exact dirty bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale or no longer
    /// matches the checkpointed scheduler continuation.
    pub fn defer_storage_array_rebuild(
        &mut self,
        opportunity: &super::fault::BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.storage_faults.defer_array_rebuild(opportunity)
    }

    /// Pauses a rebuild whose member or path is currently unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale or no longer
    /// matches the checkpointed scheduler continuation.
    pub fn pause_storage_array_rebuild(
        &mut self,
        now_nanos: u64,
        opportunity: &super::fault::BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.storage_faults
            .pause_array_rebuild(now_nanos, opportunity)
    }

    /// Resolves the logical bytes produced by a successful external discard.
    ///
    /// `None` means the declared discard semantics preserve the old data.
    /// Undefined data is deterministic and keyed exactly like a local discard.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] unless `request` is a valid, aligned discard in
    /// this device's declared capacity.
    pub fn storage_array_discard_replacement(
        &self,
        request: &BlockRequest,
    ) -> Result<Option<Vec<u8>>, DeviceError> {
        let granularity = u64::from(self.storage_faults.config().discard_granularity_bytes);
        if request.op != BlockOp::Discard
            || granularity == 0
            || request.count == 0
            || !request.offset.is_multiple_of(granularity)
            || !u64::from(request.count).is_multiple_of(granularity)
            || !super::fault::request_in_capacity(request, self.length())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external array discard is unsupported, unaligned, or out of range",
            });
        }
        let count = usize::try_from(request.count).map_err(|_| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "external array discard range does not fit memory",
            }
        })?;
        Ok(match self.storage_faults.config().discard_semantics {
            BlockDiscardSemantics::DeterministicZero => Some(vec![0; count]),
            BlockDiscardSemantics::ReadsOldData => None,
            BlockDiscardSemantics::UndefinedKeyed => {
                Some(keyed_discard_bytes(self.base.hash(), request, count))
            }
        })
    }

    /// Inspects exact currently visible bytes for an externally misdirected read.
    ///
    /// This controller-side inspection does not alter cache replacement state.
    /// The guest request remains owned by its attached device; this method only
    /// supplies the explicitly selected replacement bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the range exceeds the device or cannot be
    /// represented by its admitted storage geometry.
    pub fn inspect_storage_visible(
        &mut self,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, DeviceError> {
        self.storage_faults
            .read_visible(&self.base, &self.overlay, offset, count, false)
    }

    /// Builds a block device over `base` with the given core and latency model.
    ///
    /// The base image is held read-only and never mutated ([IO-5]); the overlay
    /// starts empty so every read falls through to the base.
    #[must_use]
    pub fn new(core: IoCore, base: BaseImage, latency: BlockLatency) -> Self {
        let mut storage_faults = BlockFaultState::write_through(base.len());
        storage_faults.set_icount_shift(core.shift_bits());
        Self {
            core,
            base,
            overlay: CowOverlay::new(),
            storage_faults,
            latency,
        }
    }

    /// Returns the device length in bytes (the base image size, [IO-6]).
    #[must_use]
    pub fn length(&self) -> u64 {
        self.base.len()
    }

    /// Returns the BLAKE3 content hash of the read-only base image.
    #[must_use]
    pub fn base_hash(&self) -> [u8; 32] {
        self.base.hash()
    }

    /// Returns a shared reference to the composed [`IoCore`].
    #[must_use]
    pub fn core(&self) -> &IoCore {
        &self.core
    }

    /// Returns a mutable reference to the composed [`IoCore`].
    ///
    /// Use this to reach the full uniform lifecycle (`enqueue_request`,
    /// `process_inbox`, `advance_to`, `pop_response`, `next_exact_local_event`)
    /// when the convenience wrappers are not enough.
    pub fn core_mut(&mut self) -> &mut IoCore {
        &mut self.core
    }

    /// Returns the deterministic completion-latency model.
    #[must_use]
    pub const fn latency_model(&self) -> &BlockLatency {
        &self.latency
    }

    /// Replaces the deterministic latency model for future request admissions.
    ///
    /// Responses already in flight retain their computed delivery coordinates;
    /// the replacement applies when subsequent requests are admitted. The active
    /// model is included in [`Self::snapshot`] and therefore survives restore.
    pub fn set_latency_model(&mut self, latency: BlockLatency) {
        self.latency = latency;
    }

    /// Returns a read-only view of the copy-on-write overlay.
    #[must_use]
    pub fn overlay(&self) -> &CowOverlay {
        &self.overlay
    }

    /// Returns checkpointed durability and resolved fault state.
    #[must_use]
    pub const fn storage_fault_state(&self) -> &BlockFaultState {
        &self.storage_faults
    }

    /// Restores an exact trusted storage-fault state during host transaction rollback.
    pub fn restore_storage_fault_state(&mut self, state: BlockFaultState) {
        self.storage_faults = state;
    }

    /// Replaces durability configuration before request execution begins.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the configuration is invalid or does not
    /// describe the exact bound base image.
    pub fn configure_storage_faults(
        &mut self,
        config: BlockDurabilityConfig,
        require_directives: bool,
    ) -> Result<(), DeviceError> {
        if config.length_bytes != self.base.len()
            || !self.storage_faults.is_pristine()
            || self.overlay.page_count() != 0
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "storage durability must be configured before device mutation",
            });
        }
        let mut state = BlockFaultState::new(config)?;
        state.set_icount_shift(self.core.shift_bits());
        state.require_directives(require_directives);
        self.storage_faults = state;
        Ok(())
    }

    /// Enables fail-closed staged resolve/persist opportunities.
    ///
    /// This must be selected before any request or storage mutation enters the
    /// device so checkpoints never mix direct and staged request semantics.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] unless the block and durability state are pristine.
    pub fn require_storage_execution_opportunities(&mut self) -> Result<(), DeviceError> {
        if !self.storage_faults.is_pristine() || self.overlay.page_count() != 0 {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "staged storage execution must be configured before device mutation",
            });
        }
        self.storage_faults.require_execution_opportunities(true);
        Ok(())
    }

    /// Enables fail-closed physical-media opportunities before device mutation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] unless the block and durability state are pristine.
    pub fn require_storage_persistence_media_opportunities(&mut self) -> Result<(), DeviceError> {
        if !self.storage_faults.is_pristine() || self.overlay.page_count() != 0 {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "staged physical persistence must be configured before device mutation",
            });
        }
        self.storage_faults
            .require_persistence_media_directives(true);
        Ok(())
    }

    /// Installs one fully resolved directive for an exact pending request ID.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate identity or bounded-state failure.
    pub fn install_storage_fault_directive(
        &mut self,
        identity: BlockRequestIdentity,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults.install(identity, directive)
    }

    /// Returns the first request ready for resolve/persist evaluation.
    #[must_use]
    pub fn next_storage_execution_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockExecutionOpportunity> {
        self.storage_faults.next_execution_opportunity(now_nanos)
    }

    /// Installs one complete resolve/persist decision for a staged request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the decision does not authenticate the live
    /// opportunity, repeats queue service, or violates storage bounds.
    pub fn install_storage_execution_directive(
        &mut self,
        directive: ResolvedBlockExecutionDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults.install_execution_directive(directive)
    }

    /// Returns the next write/discard/flush ready for persist-phase evaluation.
    #[must_use]
    pub fn next_storage_request_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockRequestPersistenceOpportunity> {
        self.storage_faults
            .next_request_persistence_opportunity(now_nanos)
    }

    /// Installs one exact persist-phase decision for a staged request mutation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the decision is stale, repeated, malformed,
    /// or changes an earlier phase.
    pub fn install_storage_request_persistence_directive(
        &mut self,
        directive: ResolvedBlockRequestPersistenceDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults
            .install_request_persistence_directive(directive)
    }

    /// Returns the next computed completion ready for deliver-phase evaluation.
    #[must_use]
    pub fn next_storage_delivery_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockDeliveryOpportunity> {
        self.storage_faults.next_delivery_opportunity(now_nanos)
    }

    /// Installs one exact deliver-phase decision for a computed completion.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the decision is stale, repeated, malformed,
    /// or changes an earlier phase.
    pub fn install_storage_delivery_directive(
        &mut self,
        directive: ResolvedBlockDeliveryDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults.install_delivery_directive(directive)
    }

    /// Returns the next physical persistence opportunity ready at `now_nanos`.
    #[must_use]
    pub fn next_storage_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockPersistenceOpportunity> {
        self.storage_faults.next_persistence_opportunity(now_nanos)
    }

    /// Installs one exact resolved physical-media directive.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the directive does not authenticate the
    /// live persistence opportunity, repeats an installed decision, or exceeds
    /// flash/persistence state bounds.
    pub fn install_storage_persistence_media_directive(
        &mut self,
        directive: ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults
            .install_persistence_media_directive(directive)
    }

    /// Drains completed physical-media outcomes for event recording.
    pub fn drain_storage_persistence_media_outcomes(
        &mut self,
    ) -> Vec<BlockPersistenceMediaOutcome> {
        self.storage_faults.drain_persistence_media_outcomes()
    }

    /// Borrows completed physical-media outcomes without acknowledging them.
    #[must_use]
    pub fn storage_persistence_media_outcomes(&self) -> &[BlockPersistenceMediaOutcome] {
        self.storage_faults.persistence_media_outcomes()
    }

    /// Drains integrated-service completion evidence in canonical order.
    pub fn drain_storage_service_outcomes(&mut self) -> Vec<BlockServiceCompletion> {
        self.storage_faults.drain_service_outcomes()
    }

    /// Borrows integrated-service completion evidence without acknowledging it.
    #[must_use]
    pub fn storage_service_outcomes(&self) -> &[BlockServiceCompletion] {
        self.storage_faults.service_outcomes()
    }

    /// Returns all pending storage outcomes in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when checkpointed outcome-order state is invalid.
    pub fn storage_outcomes(&self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        self.storage_faults.storage_outcomes()
    }

    /// Drains all storage outcomes in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] without mutation when checkpointed outcome-order
    /// state is invalid.
    pub fn drain_storage_outcomes(&mut self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        self.storage_faults.drain_storage_outcomes()
    }

    /// Returns the earliest response, service, or persistence event coordinate.
    pub fn next_exact_local_event(&self) -> Option<u64> {
        let service = self
            .storage_faults
            .next_service_completion_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let persistence = self
            .storage_faults
            .next_persistence_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let execution = self
            .storage_faults
            .next_execution_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let request_persistence = self
            .storage_faults
            .next_request_persistence_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let delivery = self
            .storage_faults
            .next_delivery_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let retained_timeout = self
            .storage_faults
            .next_retained_timeout_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let array_rebuild = self
            .storage_faults
            .next_array_rebuild_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        self.core
            .next_exact_local_event()
            .into_iter()
            .chain(service)
            .chain(execution)
            .chain(request_persistence)
            .chain(delivery)
            .chain(persistence)
            .chain(retained_timeout)
            .chain(array_rebuild)
            .min()
    }

    /// Drops exact volatile-cache entries selected by their global sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when any selected sequence is absent or repeated.
    pub fn lose_storage_volatile(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        self.storage_faults.lose_volatile(sequences)
    }

    /// Drops exact controller-buffer entries selected by their global sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when any selected sequence is absent or repeated.
    pub fn lose_storage_controller(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        self.storage_faults.lose_controller(sequences)
    }

    /// Applies an asynchronous controller transition at an authorized host boundary.
    ///
    /// Unlike a duplicate-completion reset, this transition is not caused by
    /// delivery of one distinguished guest response. It atomically updates the
    /// complete host-owned request lifecycle and rewrites every already-resolved
    /// but undelivered response according to the declared transition policy.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if the recovery coordinate is outside QEMU's
    /// virtual-clock range, an epoch cannot advance, a lifecycle disposition
    /// cannot be encoded, or the resulting responses exceed device bounds.
    pub fn apply_storage_controller_transition(
        &mut self,
        transition: &ResolvedBlockControllerTransition,
        boundary_nanos: u64,
    ) -> Result<(), DeviceError> {
        let qemu_virtual_limit = i64::MAX as u64;
        if boundary_nanos > qemu_virtual_limit
            || transition.recovery_nanos > qemu_virtual_limit
            || boundary_nanos
                .checked_add(transition.recovery_nanos)
                .is_none_or(|deadline| deadline > qemu_virtual_limit)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block transport recovery exceeds QEMU virtual-clock range",
            });
        }
        let current_epoch = self.storage_faults.transport_epoch().unwrap_or(0);
        let reset = transition.transport_reset(current_epoch)?;
        let mut next_faults = self.storage_faults.clone();
        let immediate = next_faults.apply_transport_reset(reset, boundary_nanos)?;
        let mut next_core = self.core.clone();
        next_core.check_response_sequence_capacity(immediate.len())?;
        let mut inflight = next_core.take_inflight_from_snapshot();
        if reset.completed_undelivered != BlockTransportUndelivered::Complete {
            for pending in &mut inflight {
                let response =
                    BlockResponse::decode(&pending.response.payload).map_err(DeviceError::Codec)?;
                if matches!(response.status, BlockStatus::Ok | BlockStatus::Error) {
                    let replacement = match reset.completed_undelivered {
                        BlockTransportUndelivered::Complete => response,
                        BlockTransportUndelivered::Fail => {
                            BlockResponse::error_for(response.identity(), reset.failure_result)
                        }
                        BlockTransportUndelivered::RetryPreserveId => {
                            BlockResponse::reset_disposition(
                                response.identity(),
                                BlockStatus::RetryPreserveId,
                            )
                        }
                        BlockTransportUndelivered::RetryNewId => BlockResponse::reset_disposition(
                            response.identity(),
                            BlockStatus::RetryNewId,
                        ),
                        BlockTransportUndelivered::DropCompletion => {
                            BlockResponse::reset_disposition(
                                response.identity(),
                                BlockStatus::DropCompletion,
                            )
                        }
                    };
                    pending.response = block_response_to_uniform_device(&replacement)?;
                }
            }
        }
        next_core.replace_inflight(inflight);
        for response in immediate {
            next_core.schedule_response_now(response)?;
        }
        self.storage_faults = next_faults;
        self.core = next_core;
        Ok(())
    }

    /// Releases a stalled storage completion at the current scheduler icount.
    ///
    /// The response remains retained if the delivery core cannot reserve its
    /// canonical ordering sequence, so retrying cannot lose the completion.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when `identity` is
    /// not retained, or propagates the delivery core's scheduling error.
    pub fn release_storage_completion(
        &mut self,
        identity: super::codec::BlockRequestIdentity,
        release: BlockRetainedRelease,
    ) -> Result<BlockRetainedReleaseOutcome, DeviceError> {
        let outcomes = self.release_storage_completions(&[(identity, release)])?;
        outcomes
            .into_iter()
            .next()
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "single retained-completion release produced no outcome",
            })
    }

    /// Atomically releases retained storage completions at the current icount.
    ///
    /// Every durability mutation and response reservation is applied to a clone
    /// of the complete device. The device changes only after all releases have
    /// succeeded, so a full response queue or invalid identity cannot expose a
    /// prefix of the requested batch.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when any identity is absent, a recovery cannot
    /// satisfy its durability frontier, or any response cannot be scheduled.
    pub fn release_storage_completions(
        &mut self,
        releases: &[(super::codec::BlockRequestIdentity, BlockRetainedRelease)],
    ) -> Result<Vec<BlockRetainedReleaseOutcome>, DeviceError> {
        let mut next = self.clone();
        let now_nanos = icount_to_virtual_ns(next.core.current_icount(), next.core.shift_bits())?;
        let mut outcomes = Vec::with_capacity(releases.len());
        for (identity, release) in releases {
            let response = next.storage_faults.resolve_retained_completion(
                &next.base,
                &mut next.overlay,
                *identity,
                *release,
                now_nanos,
            )?;
            match response {
                Some(response) => {
                    next.core.schedule_response_now(response)?;
                    outcomes.push(BlockRetainedReleaseOutcome::Released);
                }
                None => outcomes.push(BlockRetainedReleaseOutcome::PendingPersistence),
            }
        }
        *self = next;
        Ok(outcomes)
    }

    /// Predicts retained-completion release outcomes without changing the device.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::release_storage_completions`].
    pub fn preview_storage_completion_releases(
        &self,
        releases: &[(super::codec::BlockRequestIdentity, BlockRetainedRelease)],
    ) -> Result<Vec<BlockRetainedReleaseOutcome>, DeviceError> {
        let mut preview = self.clone();
        preview.release_storage_completions(releases)
    }

    /// Returns a read-only view of the base image.
    #[must_use]
    pub fn base(&self) -> &BaseImage {
        &self.base
    }

    /// Enqueues an encoded request and COMPUTEs it immediately.
    ///
    /// This is the ARRIVE+COMPUTE convenience path for the in-process double
    /// ([IO-27]): the wire bytes of `request` are wrapped into the uniform
    /// [`Request`] at `request_icount`, enqueued, and COMPUTEd, fixing the
    /// response's `delivery_icount`. The response stays in flight until
    /// [`BlockDevice::advance_to`] reaches that icount.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Codec`] when `request` cannot be encoded (a write
    /// payload exceeding the `u32` wire `count` field), [`DeviceError::RingFull`]
    /// when the inbound ring is full (the producer must drain and retry,
    /// [IO-32]), or any error [`IoCore::process_inbox`] raises
    /// (clock/overflow/past-delivery guards).
    pub fn submit(
        &mut self,
        request_icount: u64,
        request: &BlockRequest,
    ) -> Result<(), DeviceError> {
        let mut next_faults = self.storage_faults.clone();
        if let Some(response) =
            next_faults.dispose_retired_transport_request_if_needed(request.identity())?
        {
            let mut next_core = self.core.clone();
            next_core.schedule_response_now(response)?;
            self.storage_faults = next_faults;
            self.core = next_core;
            return Ok(());
        }
        self.advance_storage_service_before_admission(request_icount)?;
        let wire = request.encode().map_err(DeviceError::Codec)?;
        let uniform = Request::new(request_icount, request.request_id, wire);
        self.core
            .enqueue_request(uniform)
            .map_err(|rejected| DeviceError::RingFull {
                capacity: rejected.capacity,
            })?;
        // Borrow split: process_inbox needs `&mut self.core` and `&mut device`
        // simultaneously, so serve through a detached server view.
        Self::process_pending(
            &mut self.core,
            &self.base,
            &mut self.overlay,
            &mut self.storage_faults,
            &self.latency,
        )
    }

    /// Drains raw block request frames from a shared-memory inbox ring.
    ///
    /// Each dequeued frame is converted to the uniform [`Request`] payload,
    /// COMPUTEd through the block server, and inserted into the in-flight queue.
    /// The VM producer slot is woken as each request-ring entry is freed, so a
    /// producer blocked on a full `(vm slot -> SLOT_BLK_IO)` ring can retry
    /// without dropping or reordering the request ([IO-32]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for corrupt ring state, invalid frame payload
    /// length, wake failure, or any block COMPUTE/delivery-time error.
    pub fn process_shmem_inbox(
        &mut self,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError> {
        let mut result = ShmemInboxProcess {
            processed: 0,
            request_kinds: Vec::new(),
            first_request_icount: None,
            producer_wakes: Vec::new(),
        };
        loop {
            let one = self.process_one_shmem_request(inbox, inbox_entries, producer_slot)?;
            if one.processed == 0 {
                break;
            }
            result.processed += one.processed;
            result.request_kinds.extend(one.request_kinds);
            if result.first_request_icount.is_none() {
                result.first_request_icount = one.first_request_icount;
            }
            result.producer_wakes.extend(one.producer_wakes);
        }
        Ok(result)
    }

    /// Drains and COMPUTEs at most one raw shared-memory block request.
    ///
    /// This is the worker-dispatch counterpart to
    /// [`BlockDevice::process_shmem_inbox`]: callers can pin the head request's
    /// completion coordinate before dispatch, then consume precisely that
    /// request on the worker.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`BlockDevice::process_shmem_inbox`].
    pub fn process_one_shmem_request(
        &mut self,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError> {
        if let Some(frame) = inbox.peek(inbox_entries)? {
            let payload = frame.payload()?;
            let request_kind = payload.first().copied();
            let request = BlockRequest::decode(payload).map_err(DeviceError::Codec)?;
            let mut next_faults = self.storage_faults.clone();
            if let Some(response) =
                next_faults.dispose_retired_transport_request_if_needed(request.identity())?
            {
                let mut next_core = self.core.clone();
                next_core.schedule_response_now(response)?;
                let committed = inbox
                    .dequeue(inbox_entries)?
                    .ok_or(DeviceError::InvalidComputedResponse)?;
                if committed != frame {
                    return Err(DeviceError::InvalidComputedResponse);
                }
                let wake = producer_slot.wake_for_device_io_release()?;
                self.storage_faults = next_faults;
                self.core = next_core;
                return Ok(ShmemInboxProcess {
                    processed: 1,
                    request_kinds: vec![request_kind],
                    first_request_icount: Some(frame.delivery_icount),
                    producer_wakes: vec![wake],
                });
            }
            self.advance_storage_service_before_admission(frame.delivery_icount)?;
        }
        let mut node = BlockServer {
            base: &self.base,
            overlay: &mut self.overlay,
            storage_faults: &mut self.storage_faults,
            latency: &self.latency,
        };
        self.core
            .process_one_shmem_request(&mut node, inbox, inbox_entries, producer_slot)
    }

    fn advance_storage_service_before_admission(
        &mut self,
        request_icount: u64,
    ) -> Result<(), DeviceError> {
        let now_nanos = icount_to_virtual_ns(request_icount, self.core.shift_bits())?;
        self.reject_advance_past_unresolved_execution(now_nanos)?;
        let mut next_faults = self.storage_faults.clone();
        let mut next_overlay = self.overlay.clone();
        let mut next_core = self.core.clone();
        let mut released =
            next_faults.advance_service_to(&self.base, &mut next_overlay, now_nanos)?;
        released.extend(next_faults.resume_execution_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_request_persistence_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_delivery_to(now_nanos)?);
        for released in released {
            let latency_nanos = self
                .latency
                .latency_for(released.request.op, released.request.count);
            let base_completion_nanos = released.finished_nanos.checked_add(latency_nanos).ok_or(
                DeviceError::CompletionOverflow {
                    request_icount: released.request_icount,
                    latency_ns: latency_nanos,
                },
            )?;
            next_core
                .schedule_computed_response_at_nanos(base_completion_nanos, released.computed)?;
        }
        self.storage_faults = next_faults;
        self.overlay = next_overlay;
        self.core = next_core;
        Ok(())
    }

    fn prepare_transport_reset(
        core: &IoCore,
        storage_faults: &BlockFaultState,
        event: &crate::inflight::PendingResponse,
        reset: BlockTransportReset,
        delivered_icount: u64,
    ) -> Result<PreparedBlockTransportReset, DeviceError> {
        let mut next_faults = storage_faults.clone();
        let delivered_nanos = icount_to_virtual_ns(delivered_icount, core.shift_bits())?;
        let qemu_virtual_limit = i64::MAX as u64;
        if delivered_nanos > qemu_virtual_limit
            || reset.recovery_nanos > qemu_virtual_limit
            || delivered_nanos
                .checked_add(reset.recovery_nanos)
                .is_none_or(|deadline| deadline > qemu_virtual_limit)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block transport recovery exceeds QEMU virtual-clock range",
            });
        }
        let immediate = next_faults.apply_transport_reset(reset, delivered_nanos)?;
        core.check_response_sequence_capacity(immediate.len())?;

        let mut inflight = Vec::with_capacity(core.inflight_len().saturating_sub(1));
        for mut pending in core.take_inflight_from_snapshot() {
            if pending.key == event.key {
                continue;
            }
            if pending.key > event.key {
                let response =
                    BlockResponse::decode(&pending.response.payload).map_err(DeviceError::Codec)?;
                if matches!(response.status, BlockStatus::Ok | BlockStatus::Error)
                    && reset.completed_undelivered != BlockTransportUndelivered::Complete
                {
                    let replacement = match reset.completed_undelivered {
                        BlockTransportUndelivered::Complete => response,
                        BlockTransportUndelivered::Fail => {
                            BlockResponse::error_for(response.identity(), reset.failure_result)
                        }
                        BlockTransportUndelivered::RetryPreserveId => {
                            BlockResponse::reset_disposition(
                                response.identity(),
                                BlockStatus::RetryPreserveId,
                            )
                        }
                        BlockTransportUndelivered::RetryNewId => BlockResponse::reset_disposition(
                            response.identity(),
                            BlockStatus::RetryNewId,
                        ),
                        BlockTransportUndelivered::DropCompletion => {
                            BlockResponse::reset_disposition(
                                response.identity(),
                                BlockStatus::DropCompletion,
                            )
                        }
                    };
                    pending.response = block_response_to_uniform_device(&replacement)?;
                }
            }
            inflight.push(pending);
        }
        Ok(PreparedBlockTransportReset {
            storage_faults: next_faults,
            inflight,
            immediate,
        })
    }

    fn commit_transport_reset(
        core: &mut IoCore,
        storage_faults: &mut BlockFaultState,
        prepared: PreparedBlockTransportReset,
    ) -> Result<(), DeviceError> {
        let _discarded = core.take_inflight();
        core.replace_inflight(prepared.inflight);
        *storage_faults = prepared.storage_faults;
        for response in prepared.immediate {
            core.schedule_response_now(response)?;
        }
        Ok(())
    }

    fn deliver_local_with_resets(
        core: &mut IoCore,
        storage_faults: &mut BlockFaultState,
        limit: u64,
    ) -> Result<usize, DeviceError> {
        let mut delivered = 0;
        while let Some(head) = core.next_pending_response().cloned() {
            if head.delivery_icount() > limit {
                break;
            }
            let publish_at = head.delivery_icount().max(core.current_icount());
            let decoded =
                BlockResponse::decode(&head.response.payload).map_err(DeviceError::Codec)?;
            let prepared = if decoded.status == BlockStatus::TransportReset {
                let reset = decoded
                    .transport_reset_directive()
                    .map_err(DeviceError::Codec)?;
                Some(Self::prepare_transport_reset(
                    core,
                    storage_faults,
                    &head,
                    reset,
                    publish_at,
                )?)
            } else {
                None
            };
            if core.deliver_one(publish_at)?.is_none() {
                break;
            }
            delivered += 1;
            if let Some(prepared) = prepared {
                Self::commit_transport_reset(core, storage_faults, prepared)?;
            }
        }
        if core.current_icount() < limit {
            let _ = core.deliver_one(limit)?;
        }
        Ok(delivered)
    }

    fn deliver_shmem_with_resets(
        core: &mut IoCore,
        storage_faults: &mut BlockFaultState,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, DeviceError> {
        let mut delivered = 0;
        let mut consumer_wake = None;
        while let Some(head) = core.next_pending_response().cloned() {
            if head.delivery_icount() > limit {
                break;
            }
            let publish_at = head.delivery_icount().max(core.current_icount());
            let decoded =
                BlockResponse::decode(&head.response.payload).map_err(DeviceError::Codec)?;
            let prepared = if decoded.status == BlockStatus::TransportReset {
                let reset = decoded
                    .transport_reset_directive()
                    .map_err(DeviceError::Codec)?;
                Some(Self::prepare_transport_reset(
                    core,
                    storage_faults,
                    &head,
                    reset,
                    publish_at,
                )?)
            } else {
                None
            };
            let published =
                core.deliver_one_shmem(publish_at, outbox, outbox_entries, consumer_slot);
            let Some(_published) = (match published {
                Ok(published) => published,
                Err(error) => {
                    if delivered != 0 {
                        let _ = consumer_slot.wake_for_frame_delivery()?;
                    }
                    return Err(error);
                }
            }) else {
                break;
            };
            delivered += 1;
            if let Some(prepared) = prepared {
                Self::commit_transport_reset(core, storage_faults, prepared)?;
            }
        }
        if core.current_icount() < limit {
            let published = core.deliver_one_shmem(limit, outbox, outbox_entries, consumer_slot)?;
            if let Some(_response) = published {
                delivered += 1;
            }
        }
        if delivered != 0 {
            consumer_wake = Some(consumer_slot.wake_for_frame_delivery()?);
        }
        Ok(ShmemDeliveryResult {
            delivered,
            consumer_wake,
        })
    }

    /// Advances the clock to `limit` and DELIVERs every due response ([IO-2]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount.
    pub fn advance_to(&mut self, limit: u64) -> Result<usize, DeviceError> {
        let now_nanos = icount_to_virtual_ns(limit, self.core.shift_bits())?;
        self.reject_advance_past_unresolved_execution(now_nanos)?;
        let mut next_faults = self.storage_faults.clone();
        let mut next_overlay = self.overlay.clone();
        let mut next_core = self.core.clone();
        let mut released =
            next_faults.advance_service_to(&self.base, &mut next_overlay, now_nanos)?;
        released.extend(next_faults.resume_execution_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_request_persistence_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_delivery_to(now_nanos)?);
        for released in released {
            let base_completion_nanos = released
                .finished_nanos
                .checked_add(
                    self.latency
                        .latency_for(released.request.op, released.request.count),
                )
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: released.request_icount,
                    latency_ns: self
                        .latency
                        .latency_for(released.request.op, released.request.count),
                })?;
            next_core
                .schedule_computed_response_at_nanos(base_completion_nanos, released.computed)?;
        }
        let delivered = Self::deliver_local_with_resets(&mut next_core, &mut next_faults, limit)?;
        self.storage_faults = next_faults;
        self.overlay = next_overlay;
        self.core = next_core;
        Ok(delivered)
    }

    /// Advances the clock and publishes due block responses to a shmem ring.
    ///
    /// Responses are emitted as raw `BlockResponse` payload frames on the
    /// `(SLOT_BLK_IO -> vm slot)` ring. If the ring fills, undelivered responses
    /// remain in flight at their original `delivery_icount`; when at least one
    /// response is published, the VM consumer slot is woken.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for clock regression, oversized response frames,
    /// corrupt ring state, or wake failure.
    pub fn advance_to_shmem(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, DeviceError> {
        let now_nanos = icount_to_virtual_ns(limit, self.core.shift_bits())?;
        self.reject_advance_past_unresolved_execution(now_nanos)?;
        let mut next_faults = self.storage_faults.clone();
        let mut next_overlay = self.overlay.clone();
        let mut next_core = self.core.clone();
        let mut released =
            next_faults.advance_service_to(&self.base, &mut next_overlay, now_nanos)?;
        released.extend(next_faults.resume_execution_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_request_persistence_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_delivery_to(now_nanos)?);
        for released in released {
            let latency_nanos = self
                .latency
                .latency_for(released.request.op, released.request.count);
            let base_completion_nanos = released.finished_nanos.checked_add(latency_nanos).ok_or(
                DeviceError::CompletionOverflow {
                    request_icount: released.request_icount,
                    latency_ns: latency_nanos,
                },
            )?;
            next_core
                .schedule_computed_response_at_nanos(base_completion_nanos, released.computed)?;
        }
        self.storage_faults = next_faults;
        self.overlay = next_overlay;
        self.core = next_core;
        Self::deliver_shmem_with_resets(
            &mut self.core,
            &mut self.storage_faults,
            limit,
            outbox,
            outbox_entries,
            consumer_slot,
        )
    }

    fn reject_advance_past_unresolved_execution(
        &self,
        requested_nanos: u64,
    ) -> Result<(), DeviceError> {
        if let Some(ready_nanos) = self.storage_faults.next_execution_deadline_nanos()
            && ready_nanos < requested_nanos
        {
            return Err(DeviceError::UnresolvedBlockFaultOpportunity {
                ready_nanos,
                requested_nanos,
            });
        }
        if let Some(ready_nanos) = self
            .storage_faults
            .next_request_persistence_deadline_nanos()
            && ready_nanos < requested_nanos
        {
            return Err(DeviceError::UnresolvedBlockFaultOpportunity {
                ready_nanos,
                requested_nanos,
            });
        }
        if let Some(ready_nanos) = self.storage_faults.next_delivery_deadline_nanos()
            && ready_nanos < requested_nanos
        {
            return Err(DeviceError::UnresolvedBlockFaultOpportunity {
                ready_nanos,
                requested_nanos,
            });
        }
        Ok(())
    }

    /// Pops the next delivered response, decoding it from wire bytes.
    ///
    /// Returns `None` when no response has been made visible yet. The returned
    /// value is the decoded [`BlockResponse`]. A decode failure is surfaced as
    /// an error rather than silently dropped.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Codec`] when a delivered response payload fails to
    /// decode. For responses this device itself produced this cannot occur; it
    /// can surface only if the outbound ring was restored from an untrusted
    /// snapshot whose bytes were not produced by this codec.
    pub fn next_response(&mut self) -> Result<Option<BlockResponse>, DeviceError> {
        match self.core.pop_response() {
            Some(pending) => {
                let decoded =
                    BlockResponse::decode(&pending.response.payload).map_err(DeviceError::Codec)?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }

    /// COMPUTEs every pending inbox request through the block server view.
    ///
    /// Factored out so [`BlockDevice::submit`] can satisfy the borrow checker:
    /// `IoCore::process_inbox` takes the core mutably and an [`IoSubNode`]
    /// mutably, and the device cannot hand `&mut self` to both. The detached
    /// [`BlockServer`] borrows only the device sub-fields the COMPUTE step needs.
    ///
    /// # Errors
    ///
    /// Propagates any [`DeviceError`] from [`IoCore::process_inbox`].
    fn process_pending(
        core: &mut IoCore,
        base: &BaseImage,
        overlay: &mut CowOverlay,
        storage_faults: &mut BlockFaultState,
        latency: &BlockLatency,
    ) -> Result<(), DeviceError> {
        let mut server = BlockServer {
            base,
            overlay,
            storage_faults,
            latency,
        };
        core.process_inbox(&mut server)
    }

    /// Snapshots the device half of a `MaterializedState` ([IO-11], [IO-23]).
    ///
    /// Captures the overlay **delta** (only pages dirtied since the last
    /// checkpoint boundary), the **dirty page set itself** (so a mid-epoch
    /// snapshot/restore preserves which pages still owe the next checkpoint a
    /// delta, [IO-7]), the device RNG cursor, the active fault table, the latency model
    /// parameters (part of the `World`, [IO-10]), the in-flight responses with
    /// their delivery icounts, the base hash, and the device length — **never**
    /// the base image bytes ([TEMP-9]). The dirty set is *not* cleared here;
    /// call [`BlockDevice::checkpoint_boundary`] after taking the delta to begin
    /// a disjoint successor delta.
    #[must_use]
    pub fn snapshot(&self) -> BlockSnapshot {
        BlockSnapshot {
            core: self.core.snapshot(),
            base_hash: self.base.hash(),
            device_length: self.base.len(),
            overlay_delta: self.overlay.dirty_delta(),
            full_pages: self.overlay.all_pages().clone(),
            dirty: self.overlay.dirty_pages().clone(),
            storage_faults: self.storage_faults.clone(),
            latency: self.latency,
        }
    }

    /// Clears the overlay dirty set at a checkpoint boundary ([IO-7]).
    ///
    /// Call this *after* [`BlockDevice::snapshot`] captures the delta so the next
    /// snapshot captures only pages dirtied afterward, giving successive
    /// checkpoints disjoint deltas.
    pub fn checkpoint_boundary(&mut self) {
        self.overlay.clear_dirty();
    }

    /// Restores a device from a snapshot stacked over a parent overlay.
    ///
    /// The parent overlay (the materialized state up to the snapshot's parent) is
    /// passed in `parent`; the snapshot's delta is stacked on top, the **dirty
    /// page set** is restored verbatim (so the next checkpoint emits the same
    /// delta an uninterrupted run would, [IO-7]), the RNG position and the
    /// snapshot's **latency model** are restored (the latency params are part of
    /// the `World`, [IO-10]), and the in-flight responses are re-armed via the
    /// core snapshot ([IO-11]). The base image is supplied separately (it is
    /// content-addressed and shared, never carried in the snapshot, [TEMP-9]);
    /// the restore verifies its hash matches.
    ///
    /// The restored state is byte-identical to an uninterrupted run ([IO-11],
    /// [IO-22], [IO-28]): the same dirty bookkeeping, the same completion model,
    /// and the same in-flight queue, so post-restore `delivery_icount`s and
    /// payloads match exactly.
    ///
    /// Pass `parent = None` to restore a self-contained snapshot whose captured
    /// `full_pages` already hold the complete overlay (the common in-process case
    /// where there is no separate parent chain).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::BaseMismatch`] when `base`'s hash differs from the
    /// snapshot's `base_hash`, and any [`DeviceError`] [`IoCore::restore`] raises.
    pub fn restore(
        snapshot: &BlockSnapshot,
        base: BaseImage,
        parent: Option<&CowOverlay>,
    ) -> Result<Self, DeviceError> {
        if base.hash() != snapshot.base_hash {
            return Err(DeviceError::BaseMismatch {
                expected: snapshot.base_hash,
                found: base.hash(),
            });
        }
        snapshot
            .storage_faults
            .validate_restore(snapshot.device_length)?;
        if snapshot.device_length != base.len() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "snapshot storage length differs from the base image",
            });
        }
        let core = IoCore::restore(&snapshot.core)?;
        let overlay = match parent {
            Some(parent) => {
                let mut overlay = parent.clone();
                overlay.apply_delta(&snapshot.overlay_delta);
                // Restore the dirty set the snapshot captured ([IO-7]); the
                // applied delta is not implicitly clean, and clearing it here
                // would lose pages the next checkpoint still owes.
                overlay.set_dirty(snapshot.dirty.clone());
                overlay
            }
            None => CowOverlay::from_parts(snapshot.full_pages.clone(), snapshot.dirty.clone()),
        };
        Ok(Self {
            core,
            base,
            overlay,
            storage_faults: snapshot.storage_faults.clone(),
            // Restore the snapshot's latency model so post-restore completion
            // icounts match an uninterrupted run ([IO-10], [IO-22]); never
            // substitute the default, which would silently diverge.
            latency: snapshot.latency,
        })
    }

    /// Replaces this device with an authenticated snapshot over its current base image.
    ///
    /// This is the process-independent restore seam used by an already-instantiated
    /// scheduler: the immutable base remains owned by the admitted `World`, while
    /// every mutable core, overlay, durability, fault, and latency field comes from
    /// `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`BlockDevice::restore`] if the snapshot does
    /// not match the admitted base image or contains invalid device state.
    pub fn restore_snapshot(&mut self, snapshot: &BlockSnapshot) -> Result<(), DeviceError> {
        let restored = Self::restore(snapshot, self.base.clone(), None)?;
        *self = restored;
        Ok(())
    }

    /// Restores while overriding the latency model from the `World`.
    ///
    /// Like [`BlockDevice::restore`] but takes the `latency` model explicitly.
    /// Plain [`BlockDevice::restore`] already restores the snapshot's recorded
    /// latency faithfully; use this only when the caller authoritatively re-binds
    /// the latency parameters from the live `World` ([IO-10]).
    ///
    /// # Errors
    ///
    /// Same as [`BlockDevice::restore`].
    pub fn restore_with_latency(
        snapshot: &BlockSnapshot,
        base: BaseImage,
        parent: Option<&CowOverlay>,
        latency: BlockLatency,
    ) -> Result<Self, DeviceError> {
        let mut device = Self::restore(snapshot, base, parent)?;
        device.latency = latency;
        Ok(device)
    }

    /// Materializes the full current disk image: base with overlay applied.
    ///
    /// The hand-off for the real-time QEMU path ([IO-12]): a standalone raw image
    /// QEMU can mount. The base image is **not** mutated ([INV-5]); a fresh `Vec`
    /// is produced.
    #[must_use]
    pub fn materialize(&self) -> Vec<u8> {
        self.overlay.materialize(&self.base)
    }
}

fn block_response_to_uniform_device(response: &BlockResponse) -> Result<Response, DeviceError> {
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

fn ceil_nanos_to_valid_icount(target_nanos: u64, shift_bits: u8) -> u64 {
    debug_assert!(shift_bits < 64);
    if shift_bits == 0 {
        return target_nanos;
    }
    let quotient = target_nanos >> shift_bits;
    let mask = (1_u64 << shift_bits) - 1;
    quotient + u64::from(target_nanos & mask != 0)
}

/// The detached COMPUTE view a [`BlockDevice`] hands to [`IoCore::process_inbox`].
///
/// Borrows only the device fields the COMPUTE step touches (base, overlay,
/// latency), sidestepping the `&mut self`-to-both-args borrow conflict. It is
/// the concrete [`IoSubNode`]: every request is decoded, served against the
/// overlay/base, and re-encoded — out-of-range and malformed requests become
/// error-status responses, never panics ([IO-6], [IO-8]).
struct BlockServer<'a> {
    base: &'a BaseImage,
    overlay: &'a mut CowOverlay,
    storage_faults: &'a mut BlockFaultState,
    latency: &'a BlockLatency,
}

impl<'a> IoSubNode for BlockServer<'a> {
    type Latency = BlockLatency;
    type ComputeCheckpoint = (CowOverlay, BlockFaultState);

    fn latency_model(&self) -> &Self::Latency {
        self.latency
    }

    fn compute_checkpoint(&self) -> Self::ComputeCheckpoint {
        (self.overlay.clone(), self.storage_faults.clone())
    }

    fn restore_compute_checkpoint(&mut self, checkpoint: Self::ComputeCheckpoint) {
        *self.overlay = checkpoint.0;
        *self.storage_faults = checkpoint.1;
    }

    fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
        // Decode the wire request from the opaque payload. Hostile bytes yield an
        // error-status response keyed to the uniform request id ([IO-8]); the
        // device never panics or reads out of bounds.
        match BlockRequest::decode(&request.payload) {
            Ok(decoded) => self.storage_faults.execute(
                self.base,
                self.overlay,
                &decoded,
                request.request_icount,
            ),
            Err(_) => {
                let wire = BlockResponse::error(request.request_id, BlockErrorCode::IoError);
                let encoded = wire.encode().map_err(DeviceError::Codec)?;
                Ok(ComputedResponse::primary(Response::new(
                    request.request_id,
                    ResponseStatus::Error,
                    encoded,
                )))
            }
        }
    }
}
