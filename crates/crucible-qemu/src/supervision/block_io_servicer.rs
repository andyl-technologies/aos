//! Host block-I/O servicer for a live QEMU node's `SLOT_BLK_IO` rings.
//!
//! A live guest with a `crucible-shmem` virtio-blk device issues real block
//! reads and writes (the kernel's partition probe alone issues reads). The
//! `crucible-shmem` QEMU driver places each request as a [`FrameEntry`] on the
//! VM-to-device `SLOT_BLK_IO` ring, and the guest blocks until the matching
//! response frame appears on the device-to-VM ring. Nothing services that ring
//! by default, so the guest stalls on its first block request -- the gap this
//! runtime closes.
//!
//! [`QemuLiveBlockIoServicer`] maps the shared-memory region read-write (an
//! independent `MAP_SHARED` view of the same descriptor the node's channel maps)
//! and composes a deterministic [`BlockDevice`] over a fixed [`BaseImage`]. Each
//! [`QemuLiveBlockIoServicer::service`] call drains newly arrived request frames,
//! COMPUTEs each into an ordered in-flight response at its exact
//! `delivery_icount` (`ceil(vt(request_icount) + BlockLatency)`), then DELIVERs
//! every response whose `delivery_icount` is at or below the supplied guest
//! icount onto the response ring.
//!
//! ```text
//! service(guest_icount):
//!   ring pair = region.node_directed_ring_pair_mut(vm, vm->BLK, BLK->vm)
//!   process_shmem_inbox(request ring)  -> COMPUTE responses into in-flight queue
//!   advance_to_shmem(guest_icount, response ring) -> DELIVER due responses
//!   report { processed, delivered, next_completion_icount }
//! ```
//!
//! The host never invents a completion time: `delivery_icount` is a pure function
//! of the request icount, the modeled latency, and the fixed icount shift, so the
//! serviced I/O stays icount-deterministic. [`QemuLiveBlockIoServiceStep`]
//! exposes the device's next completion icount, which is the exact device horizon
//! a time-owning plugin must advance to before a blocked guest can complete.
//!
//! # Determinism invariant
//!
//! Servicing is a pure function of the observed guest icount. The host poll
//! cadence may change *when* [`QemuLiveBlockIoServicer::service`] runs and *how
//! many* frames it batches per call, but never *which* requests are processed,
//! their COMPUTE result, their order, or their `delivery_icount`: requests are
//! drained in SPSC FIFO order and delivered by the `(delivery_icount, src, seq)`
//! total order, gated on the passed-in guest icount rather than any host clock.
//! Two runs of the same guest therefore observe the identical processed sequence
//! and identical delivery icounts regardless of poll jitter.
//!
//! # Mapping discipline
//!
//! Unlike the observer-only [`crate::QemuLiveHostIoRuntime`], this servicer is a
//! participant: it holds an independent writable mapping. That writable authority
//! is deliberately confined to the `SLOT_BLK_IO` ring pair reached through
//! [`node_directed_ring_pair_mut`](MappedSetupRegion::node_directed_ring_pair_mut)
//! -- the request-ring read cursor, the response-ring frames, and the guest slot's
//! atomic wake word (the SPSC producer/consumer wakes). It never writes the guest
//! node slot's observed fields (current icount, fingerprint, idle state); those
//! stay the read-only province of the runtime, so the block servicer cannot
//! perturb the state the determinism gates observe.

use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crucible::model::ContentHash;
use crucible_device::block::{
    BlockDurabilityConfig, BlockExecutionOpportunity, BlockFaultState,
    BlockPersistenceMediaOutcome, BlockPersistenceOpportunity, BlockRetainedRelease,
    BlockServiceCompletion, ResolvedBlockExecutionDirective, ResolvedBlockFaultDirective,
    ResolvedBlockPersistenceMediaDirective,
};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, BlockSnapshot, DeviceError, IoCore, Request,
};
use crucible_shmem::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    NodeSlotSnapshot, RegionHeaderSnapshot, SLOT_BLK_IO, STATUS_DONE, SetupRegionMapError,
    SpscRingSnapshot, mmap_setup_region,
};
use thiserror::Error;

/// In-flight request-queue capacity for the servicer's I/O core.
const SERVICER_INBOX_CAPACITY: u64 = 16;
/// In-flight response-queue capacity for the servicer's I/O core.
const SERVICER_OUTBOX_CAPACITY: u64 = 16;

/// A production host servicer for one live node's `SLOT_BLK_IO` rings.
pub struct QemuLiveBlockIoServicer {
    region: MappedSetupRegion,
    device: BlockDevice,
    vm_slot: u32,
    frames_processed: usize,
    frames_delivered: usize,
}

/// Complete host block-device continuation paired with a QEMU/shared-memory checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoServicerCheckpoint {
    execution_binding: ContentHash,
    storage_device: Option<ContentHash>,
    region_header: RegionHeaderSnapshot,
    vm_slot: u32,
    size_bytes: u64,
    device: BlockSnapshot,
    requests: SpscRingSnapshot,
    responses: SpscRingSnapshot,
    frames_processed: usize,
    frames_delivered: usize,
}

impl QemuLiveBlockIoServicerCheckpoint {
    /// Records the scenario storage target owned by the host work pool.
    pub(crate) fn set_storage_device(&mut self, storage_device: Option<ContentHash>) {
        self.storage_device = storage_device;
    }

    /// Returns the scenario storage target restored with this continuation.
    pub(crate) const fn storage_device(&self) -> Option<ContentHash> {
        self.storage_device
    }
}

impl QemuLiveBlockIoServicer {
    /// Maps `shmem_fd` read-write and binds a deterministic block device to `vm_slot`.
    ///
    /// The `icount_shift` must equal the guest's launch-profile icount shift so
    /// the device's `delivery_icount` arithmetic lands in the same virtual-time
    /// domain as the guest. `size_bytes` sizes a deterministic base image whose
    /// byte `i` is `(i % 251) as u8`, so a read of any sector is reproducible
    /// without consulting any host file.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::MapRegion`] when the shared-memory
    /// region cannot be mapped, or [`QemuLiveBlockIoServicerError::Device`] when
    /// the I/O core rejects the shift or ring capacities.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
        size_bytes: u64,
    ) -> Result<Self, QemuLiveBlockIoServicerError> {
        let region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveBlockIoServicerError::MapRegion { source })?;
        let core = IoCore::new(
            icount_shift,
            SLOT_BLK_IO as u32,
            SERVICER_INBOX_CAPACITY,
            SERVICER_OUTBOX_CAPACITY,
        )
        .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let base = BaseImage::new(deterministic_base_image(size_bytes));
        let device = BlockDevice::new(core, base, BlockLatency::default());
        Ok(Self {
            region,
            device,
            vm_slot,
            frames_processed: 0,
            frames_delivered: 0,
        })
    }

    /// Restores a block-device continuation onto the checkpoint-paired region.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::MapRegion`] when the region cannot
    /// be mapped or [`QemuLiveBlockIoServicerError::Device`] when the device
    /// snapshot is malformed or its deterministic base identity differs.
    pub fn restore_from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        expected_execution_binding: ContentHash,
        checkpoint: QemuLiveBlockIoServicerCheckpoint,
    ) -> Result<Self, QemuLiveBlockIoServicerError> {
        if checkpoint.execution_binding != expected_execution_binding {
            return Err(QemuLiveBlockIoServicerError::CheckpointBindingMismatch);
        }
        if region_len != checkpoint.region_header.region_size {
            return Err(QemuLiveBlockIoServicerError::CheckpointRegionMismatch);
        }
        let mut region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveBlockIoServicerError::MapRegion { source })?;
        if !same_region_layout(region.header_snapshot(), checkpoint.region_header) {
            return Err(QemuLiveBlockIoServicerError::CheckpointRegionMismatch);
        }
        let base = BaseImage::new(deterministic_base_image(checkpoint.size_bytes));
        let device = BlockDevice::restore(&checkpoint.device, base, None)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let pair = region
            .node_directed_ring_pair_mut(
                checkpoint.vm_slot,
                checkpoint.vm_slot,
                SLOT_BLK_IO as u32,
                SLOT_BLK_IO as u32,
                checkpoint.vm_slot,
            )
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?;
        let request_depth = pair
            .first
            .header
            .live_len(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let response_depth = pair
            .second
            .header
            .live_len(pair.second.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        if request_depth != 0 || response_depth != 0 {
            return Err(QemuLiveBlockIoServicerError::RestoreRegionNotEmpty {
                request_depth,
                response_depth,
            });
        }
        pair.first
            .header
            .restore(pair.first.entries, &checkpoint.requests)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        pair.second
            .header
            .restore(pair.second.entries, &checkpoint.responses)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        pair.node_slot
            .store_device_completion_deadline_icount(device.next_exact_local_event().unwrap_or(0));
        Ok(Self {
            region,
            device,
            vm_slot: checkpoint.vm_slot,
            frames_processed: checkpoint.frames_processed,
            frames_delivered: checkpoint.frames_delivered,
        })
    }

    /// Captures the complete device and quiesced ring state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::RegionAccess`] when the block
    /// rings cannot be borrowed or [`QemuLiveBlockIoServicerError::Device`]
    /// when either ring cannot be snapshotted exactly.
    pub fn checkpoint(
        &mut self,
        execution_binding: ContentHash,
    ) -> Result<QemuLiveBlockIoServicerCheckpoint, QemuLiveBlockIoServicerError> {
        let pair = self
            .region
            .node_directed_ring_pair_mut(
                self.vm_slot,
                self.vm_slot,
                SLOT_BLK_IO as u32,
                SLOT_BLK_IO as u32,
                self.vm_slot,
            )
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?;
        if pair.node_slot.snapshot().status != STATUS_DONE {
            return Err(QemuLiveBlockIoServicerError::CheckpointNotQuiescent);
        }
        let requests = pair
            .first
            .header
            .snapshot(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let responses = pair
            .second
            .header
            .snapshot(pair.second.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        Ok(QemuLiveBlockIoServicerCheckpoint {
            execution_binding,
            storage_device: None,
            region_header: self.region.header_snapshot(),
            vm_slot: self.vm_slot,
            size_bytes: self.device.length(),
            device: self.device.snapshot(),
            requests,
            responses,
            frames_processed: self.frames_processed,
            frames_delivered: self.frames_delivered,
        })
    }

    /// Drains newly arrived requests and delivers responses due at `guest_icount`.
    ///
    /// COMPUTEs every request frame on the VM-to-device ring into an ordered
    /// in-flight response, then publishes every in-flight response whose
    /// `delivery_icount` is at or below `guest_icount` onto the device-to-VM ring
    /// (waking the guest slot when at least one is published).
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::RegionAccess`] when the mapped
    /// `SLOT_BLK_IO` rings cannot be borrowed, or
    /// [`QemuLiveBlockIoServicerError::Device`] when request COMPUTE, delivery, or
    /// ring publication fails.
    pub fn service(
        &mut self,
        guest_icount: u64,
    ) -> Result<QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicerError> {
        let Self {
            region,
            device,
            vm_slot,
            frames_processed,
            frames_delivered,
        } = self;
        let vm_slot = *vm_slot;
        let blk_slot = SLOT_BLK_IO as u32;

        let pair = region
            .node_directed_ring_pair_mut(vm_slot, vm_slot, blk_slot, blk_slot, vm_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?;
        let MappedNodeRingPairMut {
            node_slot,
            first,
            second,
        } = pair;
        let MappedDirectedRingMut {
            header: request_header,
            entries: request_entries,
            ..
        } = first;
        let MappedDirectedRingMut {
            header: response_header,
            entries: response_entries,
            ..
        } = second;

        let inbox = device
            .process_one_shmem_request(request_header, request_entries, node_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let write_frames_processed = inbox
            .request_kinds
            .iter()
            .filter(|kind| **kind == Some(1))
            .count();
        *frames_processed += inbox.processed;
        let computed_completion_icount = (inbox.processed > 0)
            .then(|| device.next_exact_local_event())
            .flatten();

        let delivery = device
            .advance_to_shmem(guest_icount, response_header, response_entries, node_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        *frames_delivered += delivery.delivered;

        // Publish the next device-completion deadline to the guest node slot so a
        // time-owning plugin whose guest is blocked on device I/O can idle-jump to
        // it. Zero when nothing is in flight (the pending completion was just
        // delivered), which retracts any stale deadline.
        let next_completion_icount = device.next_exact_local_event();
        node_slot.store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));

        Ok(QemuLiveBlockIoServiceStep {
            processed: inbox.processed,
            write_frames_processed,
            delivered: delivery.delivered,
            first_request_icount: inbox.first_request_icount,
            computed_completion_icount,
            next_completion_icount,
        })
    }

    /// Installs the fully resolved directive for the currently pinned request.
    ///
    /// The owner must resolve the directive from the exact request returned by
    /// [`Self::pin_next_request_completion`] and install it before calling
    /// [`Self::service`]. Installation is transactional and cannot dequeue the
    /// shared-memory request.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the directive is
    /// malformed, duplicated, exceeds a hard state bound, or requests a live
    /// transport capability that is not yet bound.
    pub fn install_storage_fault_directive(
        &mut self,
        request_id: u32,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .install_storage_fault_directive(request_id, directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Replaces the pristine write-through state with admitted World durability.
    ///
    /// `require_directives` must be true for a signal-driven production device;
    /// the false setting is reserved for explicitly fault-free servicing runs.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the configuration is
    /// malformed, differs from the base-image length, or device state is no
    /// longer pristine.
    pub fn configure_storage_faults(
        &mut self,
        config: BlockDurabilityConfig,
        require_directives: bool,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .configure_storage_faults(config, require_directives)
            .and_then(|()| {
                if require_directives {
                    self.device.require_storage_execution_opportunities()?;
                    self.device
                        .require_storage_persistence_media_opportunities()?;
                }
                Ok(())
            })
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the first request ready for resolve/persist evaluation.
    #[must_use]
    pub fn next_storage_execution_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockExecutionOpportunity> {
        self.device.next_storage_execution_opportunity(now_nanos)
    }

    /// Installs the complete resolve/persist decision for one staged request.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the directive is
    /// stale, repeated, malformed, or belongs to another request.
    pub fn install_storage_execution_directive(
        &mut self,
        directive: ResolvedBlockExecutionDirective,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .install_storage_execution_directive(directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the complete deterministic storage-fault continuation.
    #[must_use]
    pub fn storage_fault_state(&self) -> &BlockFaultState {
        self.device.storage_fault_state()
    }

    /// Returns the next physical persistence opportunity ready at `now_nanos`.
    #[must_use]
    pub fn next_storage_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockPersistenceOpportunity> {
        self.device.next_storage_persistence_opportunity(now_nanos)
    }

    /// Installs a resolved directive for one exact physical-media opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the directive is
    /// stale, malformed, duplicated, or exceeds a hard state bound.
    pub fn install_storage_persistence_media_directive(
        &mut self,
        directive: ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .install_storage_persistence_media_directive(directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Drains completed physical-media outcomes for durable event recording.
    pub fn drain_storage_persistence_media_outcomes(
        &mut self,
    ) -> Vec<BlockPersistenceMediaOutcome> {
        self.device.drain_storage_persistence_media_outcomes()
    }

    /// Drains integrated storage-service evidence for durable event recording.
    pub fn drain_storage_service_outcomes(&mut self) -> Vec<BlockServiceCompletion> {
        self.device.drain_storage_service_outcomes()
    }

    /// Drops exact volatile-cache entries at a scheduler-authorized boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the selection is
    /// not an exact subset of the currently live volatile-cache entries.
    pub fn lose_storage_volatile(
        &mut self,
        sequences: &[u64],
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .lose_storage_volatile(sequences)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Drops exact controller-buffer entries at a scheduler-authorized boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the selection is
    /// not an exact subset of the currently live controller-buffer entries.
    pub fn lose_storage_controller(
        &mut self,
        sequences: &[u64],
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .lose_storage_controller(sequences)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Releases one retained storage completion as recovery or timeout.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the request is not
    /// retained or its response cannot be scheduled at the current boundary.
    pub fn release_storage_completion(
        &mut self,
        request_id: u32,
        release: BlockRetainedRelease,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .release_storage_completion(request_id, release)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Pins the head request's completion coordinate without COMPUTE or dequeue.
    ///
    /// The method observes at most the SPSC head, computes its completion icount
    /// from the in-band request icount and the device latency model, and
    /// publishes the earliest pending completion to the VM slot before any host
    /// worker receives the request. Repeated calls for the same head are
    /// idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::RegionAccess`] when the mapped
    /// rings cannot be borrowed, or [`QemuLiveBlockIoServicerError::Device`] for
    /// malformed frame payloads, completion arithmetic failure, or a completion
    /// coordinate already in the device core's past.
    pub fn pin_next_request_completion(
        &mut self,
    ) -> Result<QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoServicerError> {
        let Self {
            region,
            device,
            vm_slot,
            frames_processed,
            ..
        } = self;
        let request_sequence = u64::try_from(*frames_processed)
            .map_err(|_error| QemuLiveBlockIoServicerError::RequestSequenceOverflow)?;
        let vm_slot = *vm_slot;
        let blk_slot = SLOT_BLK_IO as u32;
        let pair = region
            .node_directed_ring_pair_mut(vm_slot, vm_slot, blk_slot, blk_slot, vm_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?;
        let node_slot = pair.node_slot;
        let request = pair
            .first
            .header
            .peek(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;

        let observed = request
            .map(|frame| {
                let payload = frame.payload().map_err(DeviceError::from)?;
                let decoded = BlockRequest::decode(payload).ok();
                let request_id = decoded.as_ref().map_or(0, |request| request.request_id);
                let request = Request::new(frame.delivery_icount, request_id, payload.to_vec());
                let completion_icount = device
                    .core()
                    .compute_delivery_icount(&request, device.latency_model())?;
                if completion_icount < device.core().current_icount() {
                    return Err(DeviceError::DeliveryInPast {
                        delivery_icount: completion_icount,
                        current_icount: device.core().current_icount(),
                    });
                }
                Ok(QemuLiveBlockIoObservedRequest {
                    request_sequence,
                    request_icount: frame.delivery_icount,
                    completion_icount,
                    request: decoded,
                    wire_digest: *blake3::hash(payload).as_bytes(),
                })
            })
            .transpose()
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;

        let next_completion_icount = device
            .next_exact_local_event()
            .into_iter()
            .chain(observed.as_ref().map(|request| request.completion_icount))
            .min();
        node_slot.store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));
        Ok(QemuLiveBlockIoHostWorkPin {
            observed,
            next_completion_icount,
        })
    }

    /// Returns the cumulative number of request frames processed so far.
    #[must_use]
    pub const fn frames_processed(&self) -> usize {
        self.frames_processed
    }

    /// Returns the cumulative number of response frames delivered so far.
    #[must_use]
    pub const fn frames_delivered(&self) -> usize {
        self.frames_delivered
    }

    /// Returns the device's next completion icount, when a response is in flight.
    ///
    /// This is the exact device horizon: a blocked guest cannot complete its
    /// request until virtual time reaches this icount, so a time-owning plugin
    /// must advance to it before the response can be delivered.
    #[must_use]
    pub fn next_completion_icount(&self) -> Option<u64> {
        self.device.next_exact_local_event()
    }

    /// Reads the guest VM node slot's published state from the servicer's mapping.
    ///
    /// A caller driving the guest can read `current_icount`, `device_io_active`,
    /// and `idle_wake_icount` here to observe whether the guest is progressing or
    /// blocked on device I/O, without a second mapping of the region.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::RegionAccess`] when the guest node
    /// slot cannot be borrowed from the mapped region.
    pub fn vm_node_snapshot(&self) -> Result<NodeSlotSnapshot, QemuLiveBlockIoServicerError> {
        Ok(self
            .region
            .node_slot(self.vm_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?
            .snapshot())
    }
}

/// The per-call outcome of one [`QemuLiveBlockIoServicer::service`] step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoServiceStep {
    /// Request frames drained and COMPUTEd this call.
    pub processed: usize,
    /// Write request frames drained and COMPUTEd this call.
    pub write_frames_processed: usize,
    /// Response frames published to the response ring this call.
    pub delivered: usize,
    /// Submit icount carried by the request COMPUTEd this call.
    pub first_request_icount: Option<u64>,
    /// Completion icount pinned for the request COMPUTEd this call.
    pub computed_completion_icount: Option<u64>,
    /// The device's next completion icount after this call, when one is pending.
    pub next_completion_icount: Option<u64>,
}

/// A request observed before its device-side host work is dispatched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoObservedRequest {
    /// Adapter-owned monotone sequence of this exact request.
    pub request_sequence: u64,
    /// Icount carried by the request at observation time.
    pub request_icount: u64,
    /// Fault-free baseline completion used as a pre-dispatch wake horizon.
    ///
    /// A resolved storage directive may replace this provisional coordinate
    /// after admission; it is never reported as that request's final completion.
    pub completion_icount: u64,
    /// Exact decoded request, absent only for a malformed guest frame.
    pub request: Option<BlockRequest>,
    /// BLAKE3 digest of the complete immutable request wire bytes.
    pub wire_digest: [u8; 32],
}

/// The pinned state returned before one block host-work dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoHostWorkPin {
    /// Newly observed head request, when the inbound ring was nonempty.
    pub observed: Option<QemuLiveBlockIoObservedRequest>,
    /// Earliest safe wake horizon across observed and already-computed work.
    pub next_completion_icount: Option<u64>,
}

/// A shared diagnostic sink for one live block-I/O servicing run.
///
/// The block-servicing poll loop lives inside the [`crate::QemuLiveHostIoRuntime`]
/// that is moved into the node, so a run cannot read the servicer back out
/// afterward. Instead the runtime writes each observation here and the runner
/// holds a clone (via [`BlockIoDiagnostics::shared`]), reading the accumulated
/// evidence once the advance returns. All fields are updated from the single
/// advance-driving thread; the atomics exist only so the sink is `Sync` enough to
/// live behind the node's boxed runtime.
#[derive(Debug, Default)]
pub struct BlockIoDiagnostics {
    frames_processed: AtomicUsize,
    write_frames_processed: AtomicUsize,
    frames_delivered: AtomicUsize,
    service_calls: AtomicUsize,
    first_request_seen: AtomicBool,
    first_request_icount: AtomicU64,
    first_completion_horizon: AtomicU64,
    last_current_icount: AtomicU64,
    max_current_icount: AtomicU64,
    last_device_io_active: AtomicBool,
    last_idle_wake_icount: AtomicU64,
}

impl BlockIoDiagnostics {
    /// Creates an empty diagnostic sink wrapped for sharing across the boundary.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records one servicing observation from the runtime poll loop.
    ///
    /// `current_icount`, `device_io_active`, and `idle_wake_icount` are the guest
    /// slot's published state at the poll; `serviced` is the servicing outcome.
    pub(crate) fn record(
        &self,
        current_icount: u64,
        device_io_active: bool,
        idle_wake_icount: u64,
        serviced: &QemuLiveBlockIoServiceStep,
    ) {
        self.service_calls.fetch_add(1, Ordering::Relaxed);
        if serviced.processed > 0 {
            self.frames_processed
                .fetch_add(serviced.processed, Ordering::Relaxed);
            if !self.first_request_seen.swap(true, Ordering::Relaxed) {
                self.first_request_icount.store(
                    serviced.first_request_icount.unwrap_or(current_icount),
                    Ordering::Relaxed,
                );
                self.first_completion_horizon.store(
                    serviced.computed_completion_icount.unwrap_or(0),
                    Ordering::Relaxed,
                );
            }
        }
        if serviced.write_frames_processed > 0 {
            self.write_frames_processed
                .fetch_add(serviced.write_frames_processed, Ordering::Relaxed);
        }
        if serviced.delivered > 0 {
            self.frames_delivered
                .fetch_add(serviced.delivered, Ordering::Relaxed);
        }
        self.observe_slot(current_icount, device_io_active, idle_wake_icount);
    }

    /// Records the latest guest-slot state independently of a servicing call.
    ///
    /// A response delivery can be the final operation the host servicer needs
    /// to perform. The guest clears `device_io_active` only after consuming
    /// that response, so sampling slot state solely when servicing would retain
    /// the pre-consumption value forever. The drive loop calls this on every
    /// poll so terminal progress evidence describes the guest after delivery,
    /// without adding no-op device service calls.
    pub(crate) fn observe_slot(
        &self,
        current_icount: u64,
        device_io_active: bool,
        idle_wake_icount: u64,
    ) {
        self.last_current_icount
            .store(current_icount, Ordering::Relaxed);
        self.max_current_icount
            .fetch_max(current_icount, Ordering::Relaxed);
        self.last_device_io_active
            .store(device_io_active, Ordering::Relaxed);
        self.last_idle_wake_icount
            .store(idle_wake_icount, Ordering::Relaxed);
    }

    /// Returns a plain-value snapshot of the accumulated observations.
    #[must_use]
    pub fn snapshot(&self) -> BlockIoDiagnosticsSnapshot {
        let saw_request = self.first_request_seen.load(Ordering::Relaxed);
        BlockIoDiagnosticsSnapshot {
            frames_processed: self.frames_processed.load(Ordering::Relaxed),
            write_frames_processed: self.write_frames_processed.load(Ordering::Relaxed),
            frames_delivered: self.frames_delivered.load(Ordering::Relaxed),
            service_calls: self.service_calls.load(Ordering::Relaxed),
            first_request_icount: saw_request
                .then(|| self.first_request_icount.load(Ordering::Relaxed)),
            first_completion_horizon: saw_request.then_some(()).and_then(|()| {
                let horizon = self.first_completion_horizon.load(Ordering::Relaxed);
                (horizon != 0).then_some(horizon)
            }),
            last_current_icount: self.last_current_icount.load(Ordering::Relaxed),
            max_current_icount: self.max_current_icount.load(Ordering::Relaxed),
            last_device_io_active: self.last_device_io_active.load(Ordering::Relaxed),
            last_idle_wake_icount: self.last_idle_wake_icount.load(Ordering::Relaxed),
        }
    }
}

/// A plain-value snapshot of the [`BlockIoDiagnostics`] accumulated for a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockIoDiagnosticsSnapshot {
    /// Total request frames drained and COMPUTEd across the run.
    pub frames_processed: usize,
    /// Total write request frames drained and COMPUTEd across the run.
    pub write_frames_processed: usize,
    /// Total response frames published to the response ring across the run.
    pub frames_delivered: usize,
    /// Number of poll-loop servicing calls made across the run.
    pub service_calls: usize,
    /// Guest icount observed when the first request frame was processed.
    pub first_request_icount: Option<u64>,
    /// Device completion horizon computed for the first processed request.
    pub first_completion_horizon: Option<u64>,
    /// Guest icount observed at the final poll.
    pub last_current_icount: u64,
    /// Highest guest icount observed across the run.
    pub max_current_icount: u64,
    /// Whether the guest slot last advertised active device I/O.
    pub last_device_io_active: bool,
    /// The guest slot's last published idle-wake icount.
    pub last_idle_wake_icount: u64,
}

impl BlockIoDiagnosticsSnapshot {
    /// Compares deterministic block traffic, excluding host poll sample points.
    pub(crate) fn deterministic_observation_eq(&self, other: &Self) -> bool {
        self.frames_processed == other.frames_processed
            && self.write_frames_processed == other.write_frames_processed
            && self.frames_delivered == other.frames_delivered
            && self.first_request_icount == other.first_request_icount
            && self.first_completion_horizon == other.first_completion_horizon
            && self.last_device_io_active == other.last_device_io_active
    }
}

/// Builds the deterministic base-image bytes for a device of `size_bytes`.
fn deterministic_base_image(size_bytes: u64) -> Vec<u8> {
    let len = usize::try_from(size_bytes).unwrap_or(usize::MAX);
    (0..len).map(|index| (index % 251) as u8).collect()
}

fn same_region_layout(left: RegionHeaderSnapshot, right: RegionHeaderSnapshot) -> bool {
    left.magic == right.magic
        && left.abi_version == right.abi_version
        && left.node_count == right.node_count
        && left.queue_capacity == right.queue_capacity
        && left.ring_count == right.ring_count
        && left.ring_hdr_off == right.ring_hdr_off
        && left.ring_data_off == right.ring_data_off
        && left.entry_stride == right.entry_stride
        && left.region_size == right.region_size
        && left.icount_shift == right.icount_shift
        && left.fault_payload_arena_bytes == right.fault_payload_arena_bytes
}

/// Error returned by the live block-I/O servicer.
#[derive(Debug, Error)]
pub enum QemuLiveBlockIoServicerError {
    /// The adapter request sequence no longer fits its stable wire width.
    #[error("block-I/O request sequence exhausted")]
    RequestSequenceOverflow,
    /// The checkpoint belongs to a different QEMU execution checkpoint.
    #[error("block-I/O checkpoint does not match the QEMU execution binding")]
    CheckpointBindingMismatch,
    /// The restore region's ABI geometry differs from the captured region.
    #[error("block-I/O checkpoint does not match the shared-memory region layout")]
    CheckpointRegionMismatch,
    /// The shared-memory region could not be mapped read-write.
    #[error("map block-I/O shared-memory region failed: {source}")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// The mapped `SLOT_BLK_IO` rings could not be borrowed.
    #[error("access SLOT_BLK_IO rings failed: {source}")]
    RegionAccess {
        /// Underlying mapped-region access error.
        source: MappedSetupRegionAccessError,
    },
    /// The block device rejected a servicing operation.
    #[error("block device servicing failed: {source}")]
    Device {
        /// Underlying device error.
        source: DeviceError,
    },
    /// A checkpoint was attempted while the guest was not at a published boundary.
    #[error("block-I/O checkpoint requires a quiesced guest boundary")]
    CheckpointNotQuiescent,
    /// Restore would overwrite live frames in the new shared-memory region.
    #[error(
        "block-I/O restore region is not empty (requests={request_depth}, responses={response_depth})"
    )]
    RestoreRegionNotEmpty {
        /// Live guest-to-device frames.
        request_depth: u64,
        /// Live device-to-guest frames.
        response_depth: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_base_image_is_reproducible_and_sized() {
        let first = deterministic_base_image(512);
        let second = deterministic_base_image(512);
        assert_eq!(first.len(), 512);
        assert_eq!(first, second);
        assert_eq!(first[0], 0);
        assert_eq!(first[251], 0);
        assert_eq!(first[250], 250);
    }

    #[test]
    fn deterministic_diagnostics_ignore_host_poll_cadence() {
        let first = BlockIoDiagnosticsSnapshot {
            frames_processed: 1,
            write_frames_processed: 1,
            frames_delivered: 1,
            service_calls: 17,
            first_request_icount: Some(0),
            first_completion_horizon: Some(1512),
            last_current_icount: 12_000_000,
            max_current_icount: 12_000_000,
            last_device_io_active: false,
            last_idle_wake_icount: 1,
        };
        let second = BlockIoDiagnosticsSnapshot {
            service_calls: 29,
            ..first
        };

        assert_ne!(first, second);
        assert!(first.deterministic_observation_eq(&second));
    }

    #[test]
    fn terminal_slot_observation_replaces_pre_consumption_device_state() {
        let diagnostics = BlockIoDiagnostics::default();
        diagnostics.record(
            10,
            true,
            20,
            &QemuLiveBlockIoServiceStep {
                processed: 1,
                write_frames_processed: 1,
                delivered: 1,
                first_request_icount: Some(10),
                computed_completion_icount: Some(20),
                next_completion_icount: None,
            },
        );

        diagnostics.observe_slot(30, false, 30);

        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.service_calls, 1);
        assert_eq!(snapshot.last_current_icount, 30);
        assert_eq!(snapshot.max_current_icount, 30);
        assert!(!snapshot.last_device_io_active);
        assert_eq!(snapshot.last_idle_wake_icount, 30);
    }
}
