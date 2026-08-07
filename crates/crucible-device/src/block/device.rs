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

use crate::clock::ceil_ns_to_icount;
use crate::error::DeviceError;
use crate::fault::{DeviceRng, IoFaultOutcome, IoFaults};
use crate::request::{ComputedResponse, LatencyModel, Request, Response, ResponseStatus};
use crate::subnode::{IoCore, IoSubNode, ShmemDeliveryResult, ShmemInboxProcess};

use super::codec::{BlockErrorCode, BlockOp, BlockRequest, BlockResponse, RESPONSE_HEADER_LEN};
use super::fault::{
    BlockDurabilityConfig, BlockFaultState, BlockPersistenceMediaOutcome,
    BlockPersistenceOpportunity, BlockRetainedRelease, ResolvedBlockFaultDirective,
    ResolvedBlockPersistenceMediaDirective,
};
use super::overlay::{BaseImage, CowOverlay};

mod snapshot;
pub use snapshot::BlockSnapshot;

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
/// (base image, overlay, latency model, fault table, RNG cursor). Drive it with
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
    /// The active I/O fault table applied to completions ([IO-25], [IO-26]).
    faults: IoFaults,
    /// The per-device RNG stream cursor (draws consumed so far, [IO-23]).
    ///
    /// Advanced by [`BlockDevice::resolve_response`] as the seeded per-device RNG
    /// draws each completion's faults; captured in the snapshot and re-derived on
    /// restore via [`BlockDevice::rng`] so a fork resumes the same draw sequence.
    rng_position: u64,
}

/// Atomically submits a write whose bytes are redirected to another block device.
///
/// The source produces the sole guest completion and remains unchanged; the
/// destination applies the bytes through its own controller/cache/durable
/// layers. Both complete device states are staged first and commit together.
///
/// # Errors
///
/// Returns [`DeviceError`] for a non-write request, a directive whose local
/// destination differs from `destination_offset`, any destination mutation
/// failure, or any source directive/COMPUTE/scheduling failure. On error neither
/// device changes.
pub fn submit_cross_device_misdirected_write(
    source: &mut BlockDevice,
    destination: &mut BlockDevice,
    request_icount: u64,
    request: &BlockRequest,
    mut directive: ResolvedBlockFaultDirective,
    destination_offset: u64,
) -> Result<(), DeviceError> {
    if request.op != BlockOp::Write
        || directive.write_disposition
            != (super::fault::BlockFaultWriteDisposition::Misdirected { destination_offset })
    {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "cross-device misdirection requires its exact write destination",
        });
    }
    let mut next_source = source.clone();
    let mut next_destination = destination.clone();
    next_destination.storage_faults.apply_external_write(
        &next_destination.base,
        &mut next_destination.overlay,
        request.request_id,
        destination_offset,
        request.data.clone(),
    )?;
    directive.write_disposition = super::fault::BlockFaultWriteDisposition::Lost;
    next_source.install_storage_fault_directive(request.request_id, directive)?;
    next_source.submit(request_icount, request)?;
    *source = next_source;
    *destination = next_destination;
    Ok(())
}

impl BlockDevice {
    /// Builds a block device over `base` with the given core and latency model.
    ///
    /// The base image is held read-only and never mutated ([IO-5]); the overlay
    /// starts empty so every read falls through to the base.
    #[must_use]
    pub fn new(core: IoCore, base: BaseImage, latency: BlockLatency) -> Self {
        let storage_faults = BlockFaultState::write_through(base.len());
        Self {
            core,
            base,
            overlay: CowOverlay::new(),
            storage_faults,
            latency,
            faults: IoFaults::none(),
            rng_position: 0,
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
        state.require_directives(require_directives);
        self.storage_faults = state;
        Ok(())
    }

    /// Installs one fully resolved directive for an exact pending request ID.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate identity or bounded-state failure.
    pub fn install_storage_fault_directive(
        &mut self,
        request_id: u32,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults.install(request_id, directive)
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

    /// Releases a stalled storage completion at the current scheduler icount.
    ///
    /// The response remains retained if the delivery core cannot reserve its
    /// canonical ordering sequence, so retrying cannot lose the completion.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when `request_id` is
    /// not retained, or propagates the delivery core's scheduling error.
    pub fn release_storage_completion(
        &mut self,
        request_id: u32,
        release: BlockRetainedRelease,
    ) -> Result<(), DeviceError> {
        let mut next_faults = self.storage_faults.clone();
        let mut next_overlay = self.overlay.clone();
        let now_nanos = icount_to_virtual_ns(self.core.current_icount(), self.core.shift_bits())?;
        let response = next_faults.resolve_retained_completion(
            &self.base,
            &mut next_overlay,
            request_id,
            release,
            now_nanos,
        )?;
        self.core.schedule_response_now(response)?;
        self.storage_faults = next_faults;
        self.overlay = next_overlay;
        Ok(())
    }

    /// Returns a read-only view of the base image.
    #[must_use]
    pub fn base(&self) -> &BaseImage {
        &self.base
    }

    /// Returns the device RNG stream cursor (draws consumed so far, [IO-23]).
    #[must_use]
    pub fn rng_position(&self) -> u64 {
        self.rng_position
    }

    /// Returns a read-only view of the active I/O fault table ([IO-26]).
    #[must_use]
    pub fn faults(&self) -> &IoFaults {
        &self.faults
    }

    /// Activates an I/O fault table for subsequent completions ([IO-25], [IO-26]).
    ///
    /// The block device applies exactly the same fault taxonomy as the network
    /// link: latency/jitter/reorder/bandwidth shift the response delivery icount,
    /// loss turns the response into an error status, duplicate emits a second
    /// response, and corrupt flips seeded bits in the read payload. The active set
    /// is part of the device's `MaterializedState` contribution, so a fork resumes
    /// with identical fault behavior ([IO-26]).
    pub fn set_faults(&mut self, faults: IoFaults) {
        self.faults = faults;
    }

    /// Builds a seeded RNG positioned at this device's captured cursor ([IO-23]).
    ///
    /// Forks the device stream by name-hash from the engine's decision-RNG
    /// `root_seed` in `domain` for `name` ([DET-25]) and resumes it at the
    /// captured cursor, so the returned RNG's next draw is byte-identical to the
    /// uninterrupted run's. The caller supplies the engine root seed and the
    /// device's stable stream domain and name (the engine owns the name-hash).
    #[must_use]
    pub fn rng(&self, root_seed: u64, domain: &str, name: &str) -> DeviceRng {
        DeviceRng::restore(root_seed, domain, name, self.rng_position)
    }

    /// Resolves a modeled completion through the active fault table ([IO-25]).
    ///
    /// Applies the uniform I/O fault taxonomy to a modeled
    /// `(delivery_icount, status, payload)` triple — the response
    /// [`BlockDevice::submit`]'s COMPUTE step would deliver — drawing every
    /// probabilistic choice from `rng` in the fixed model order and advancing the
    /// device RNG cursor to match ([IO-21], [IO-23]). The returned
    /// [`IoFaultOutcome`] carries the perturbed primary response, an optional
    /// duplicate, and which faults fired. Nanosecond shifts are converted to
    /// icounts with the device's fixed clock shift, so the result is a pure
    /// function of the inputs, the table, and the RNG position ([IO-22], [IO-24]).
    pub fn resolve_response(
        &mut self,
        primary_icount: u64,
        status: ResponseStatus,
        payload: Vec<u8>,
        rng: &mut DeviceRng,
    ) -> IoFaultOutcome {
        let shift_bits = self.core.shift_bits();
        let outcome = self
            .faults
            .resolve(primary_icount, status, payload, rng, |ns| {
                ceil_ns_to_icount(ns, shift_bits).unwrap_or(u64::MAX)
            });
        self.rng_position = rng.position();
        outcome
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
        let mut node = BlockServer {
            base: &self.base,
            overlay: &mut self.overlay,
            storage_faults: &mut self.storage_faults,
            latency: &self.latency,
        };
        self.core
            .process_shmem_inbox(&mut node, inbox, inbox_entries, producer_slot)
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
        let mut node = BlockServer {
            base: &self.base,
            overlay: &mut self.overlay,
            storage_faults: &mut self.storage_faults,
            latency: &self.latency,
        };
        self.core
            .process_one_shmem_request(&mut node, inbox, inbox_entries, producer_slot)
    }

    /// Advances the clock to `limit` and DELIVERs every due response ([IO-2]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount.
    pub fn advance_to(&mut self, limit: u64) -> Result<usize, DeviceError> {
        let now_nanos = icount_to_virtual_ns(limit, self.core.shift_bits())?;
        let mut next_faults = self.storage_faults.clone();
        let mut next_overlay = self.overlay.clone();
        next_faults.persist_due(&self.base, &mut next_overlay, now_nanos)?;
        let delivered = self.core.advance_to(limit)?;
        self.storage_faults = next_faults;
        self.overlay = next_overlay;
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
        self.core
            .advance_to_shmem(limit, outbox, outbox_entries, consumer_slot)
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
            faults: self.faults.clone(),
            rng_position: self.rng_position,
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
            // Restore the active fault table so post-restore completions are
            // perturbed identically ([IO-26]); omitting it would silently diverge.
            faults: snapshot.faults.clone(),
            rng_position: snapshot.rng_position,
        })
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
