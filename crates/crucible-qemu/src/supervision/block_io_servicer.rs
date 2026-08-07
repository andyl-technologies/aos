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

use crucible::ContentHash;
use crucible_device::block::{
    BlockDeliveryOpportunity, BlockDurabilityConfig, BlockExecutionOpportunity, BlockFaultState,
    BlockPersistenceMediaOutcome, BlockPersistenceOpportunity, BlockRequestPersistenceOpportunity,
    BlockRetainedRelease, BlockServiceCompletion, BlockStorageOutcome,
    ResolvedBlockDeliveryDirective, ResolvedBlockExecutionDirective, ResolvedBlockFaultDirective,
    ResolvedBlockPersistenceMediaDirective, ResolvedBlockRequestPersistenceDirective,
};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, BlockRequestIdentity, DeviceError, IoCore,
    Request,
};
use crucible_shmem::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    NodeSlotSnapshot, RegionHeaderSnapshot, SLOT_BLK_IO, STATUS_IDLE, SetupRegionMapError,
    icount_to_virtual_ns, mmap_setup_region,
};
use thiserror::Error;

use crate::QemuLiveBlockIoServicerCheckpoint;

/// In-flight request-queue capacity for the servicer's I/O core.
const SERVICER_INBOX_CAPACITY: u64 = 16;
/// In-flight response-queue capacity for the servicer's I/O core.
const SERVICER_OUTBOX_CAPACITY: u64 = 16;
/// Hard settle bound for pre-scheduler block initialization.
const INITIALIZATION_SETTLE_STEPS: usize = 4_096;

/// A production host servicer for one live node's `SLOT_BLK_IO` rings.
pub struct QemuLiveBlockIoServicer {
    region: MappedSetupRegion,
    device: BlockDevice,
    vm_slot: u32,
    frames_processed: usize,
    frames_delivered: usize,
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
        Self::from_shmem_fd_with_base(
            shmem_fd,
            region_len,
            vm_slot,
            icount_shift,
            BaseImage::new(deterministic_base_image(size_bytes)),
        )
    }

    /// Maps the live block transport over one content-authenticated base image.
    ///
    /// This is the production constructor for World-declared storage. The base
    /// bytes are retained read-only by [`BlockDevice`]; all guest mutation lands
    /// in its checkpointed copy-on-write overlay.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::MapRegion`] when shared memory
    /// cannot be mapped, or [`QemuLiveBlockIoServicerError::Device`] when the
    /// deterministic I/O core rejects its clock or queue configuration.
    pub fn from_shmem_fd_with_base(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
        base: BaseImage,
    ) -> Result<Self, QemuLiveBlockIoServicerError> {
        Self::from_shmem_fd_with_base_and_latency(
            shmem_fd,
            region_len,
            vm_slot,
            icount_shift,
            base,
            BlockLatency::default(),
        )
    }

    /// Maps the live block transport with an explicit deterministic latency model.
    ///
    /// This constructor is used when a World's storage realization declares
    /// device timing rather than accepting [`BlockLatency::default`]. The model
    /// is part of the block-device snapshot, so an in-flight completion retains
    /// its timing across exact capture and restore.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::MapRegion`] when shared memory
    /// cannot be mapped, or [`QemuLiveBlockIoServicerError::Device`] when the
    /// deterministic I/O core rejects its clock or queue configuration.
    pub fn from_shmem_fd_with_base_and_latency(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
        base: BaseImage,
        latency: BlockLatency,
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
        let device = BlockDevice::new(core, base, latency);
        Ok(Self {
            region,
            device,
            vm_slot,
            frames_processed: 0,
            frames_delivered: 0,
        })
    }

    /// Replaces the deterministic latency model for future block admissions.
    ///
    /// This is the production activation seam for a model that must take effect
    /// after fault-free firmware discovery. Any response already in flight keeps
    /// its previously computed delivery coordinate.
    pub fn set_latency_model(&mut self, latency: BlockLatency) {
        self.device.set_latency_model(latency);
    }

    /// Restores a block-device continuation onto the checkpoint-paired region.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::MapRegion`] when the region cannot
    /// be mapped or [`QemuLiveBlockIoServicerError::Device`] when the device
    /// snapshot is malformed or its deterministic base identity differs.
    pub fn restore_from_shmem_fd_with_base(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        expected_execution_binding: ContentHash,
        checkpoint: QemuLiveBlockIoServicerCheckpoint,
        base: BaseImage,
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
        if base.len() != checkpoint.size_bytes {
            return Err(QemuLiveBlockIoServicerError::CheckpointBindingMismatch);
        }
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
        let node = pair.node_slot.snapshot();
        if node.status != STATUS_IDLE || node.device_io_active != 0 {
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

    /// Atomically restores a paired device and ring continuation in place.
    ///
    /// The target device is reconstructed and both ring snapshots are validated
    /// before live device state changes. If the second ring unexpectedly rejects
    /// restoration, the first ring is rolled back to its exact prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the execution binding, region layout, base image,
    /// guest boundary, device snapshot, or either ring snapshot does not match.
    pub fn restore_checkpoint(
        &mut self,
        expected_execution_binding: ContentHash,
        checkpoint: &QemuLiveBlockIoServicerCheckpoint,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.validate_checkpoint(expected_execution_binding, checkpoint)?;
        let staged_device =
            BlockDevice::restore(&checkpoint.device, self.device.base().clone(), None)
                .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
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
        let prior_requests = pair
            .first
            .header
            .snapshot(pair.first.entries)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        pair.first
            .header
            .restore(pair.first.entries, &checkpoint.requests)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        if let Err(source) = pair
            .second
            .header
            .restore(pair.second.entries, &checkpoint.responses)
        {
            pair.first
                .header
                .restore(pair.first.entries, &prior_requests)
                .map_err(DeviceError::from)
                .map_err(|rollback| QemuLiveBlockIoServicerError::Device { source: rollback })?;
            return Err(QemuLiveBlockIoServicerError::Device {
                source: DeviceError::from(source),
            });
        }
        pair.node_slot.store_device_completion_deadline_icount(
            staged_device.next_exact_local_event().unwrap_or(0),
        );
        self.device = staged_device;
        self.frames_processed = checkpoint.frames_processed;
        self.frames_delivered = checkpoint.frames_delivered;
        Ok(())
    }

    /// Validates an in-place restore without changing live continuation state.
    ///
    /// This is the prepare half of a paired host/QEMU restore transaction. A
    /// successful return proves that the execution identity, shared-memory
    /// geometry, current quiescent boundary, ring snapshots, and block-device
    /// snapshot can all be restored before QMP is allowed to load VMState.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::restore_checkpoint`]
    /// without modifying either shared-memory ring or the live device.
    pub fn validate_checkpoint(
        &mut self,
        expected_execution_binding: ContentHash,
        checkpoint: &QemuLiveBlockIoServicerCheckpoint,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        if checkpoint.execution_binding != expected_execution_binding {
            return Err(QemuLiveBlockIoServicerError::CheckpointBindingMismatch);
        }
        if checkpoint.region_header.region_size != self.region.header_snapshot().region_size
            || !same_region_layout(self.region.header_snapshot(), checkpoint.region_header)
            || checkpoint.vm_slot != self.vm_slot
            || checkpoint.size_bytes != self.device.length()
        {
            return Err(QemuLiveBlockIoServicerError::CheckpointRegionMismatch);
        }
        checkpoint
            .requests
            .canonical_bytes()
            .and_then(|_| checkpoint.responses.canonical_bytes())
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let _staged_device =
            BlockDevice::restore(&checkpoint.device, self.device.base().clone(), None)
                .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
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
        let node = pair.node_slot.snapshot();
        if node.status != STATUS_IDLE || node.device_io_active != 0 {
            return Err(QemuLiveBlockIoServicerError::CheckpointNotQuiescent);
        }
        Ok(())
    }

    /// Reports whether a quiescent guest transport has pending host durability.
    ///
    /// A true result means both shared-memory rings and every request/response
    /// queue are empty, while an accepted controller, cache, or media mutation
    /// remains in the checkpointed storage state. This is the savevm-safe
    /// boundary: QEMU has no block coroutine for `bdrv_drain_all_begin()` to
    /// wait on, but exact restore still has real Apache-side work to preserve.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError`] when either mapped ring cannot
    /// be snapshotted consistently.
    pub fn has_pending_work(&mut self) -> Result<bool, QemuLiveBlockIoServicerError> {
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
        let device = self.device.snapshot();
        let transport_quiescent = requests.frames.is_empty()
            && responses.frames.is_empty()
            && device.core.inbox.is_empty()
            && device.core.inflight.is_empty()
            && device.core.outbox.is_empty();
        Ok(transport_quiescent && device.storage_faults.has_pending_durability_continuation())
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
        let intake = self.process_one_storage_request()?;
        let delivery = self.advance_storage_to(guest_icount)?;
        Ok(QemuLiveBlockIoServiceStep {
            processed: intake.processed,
            write_frames_processed: intake.write_frames_processed,
            delivered: delivery.delivered,
            first_request_icount: intake.first_request_icount,
            computed_completion_icount: intake.computed_completion_icount,
            next_completion_icount: delivery.next_completion_icount,
        })
    }

    /// Services pre-ready guest discovery with explicit fault-free decisions.
    ///
    /// QEMU performs virtio block discovery before the scheduler admits the
    /// scenario's first fault coordinate. This method drives the same staged
    /// opportunity machinery as production, but installs explicit fault-free
    /// decisions because signal time has not started. It must never be called
    /// after the live coordinator is installed.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError`] for malformed initialization
    /// traffic, stage/clock failures, or failure to settle within the hard bound.
    pub fn service_fault_free_initialization(
        &mut self,
        guest_icount: u64,
    ) -> Result<QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicerError> {
        let now_nanos = icount_to_virtual_ns(guest_icount, self.device.core().shift_bits())
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let mut aggregate = QemuLiveBlockIoServiceStep::default();
        for _ in 0..INITIALIZATION_SETTLE_STEPS {
            let pin = self.pin_next_request_completion()?;
            if let Some(observed) = pin.observed {
                let request = observed
                    .request
                    .ok_or(QemuLiveBlockIoServicerError::MalformedInitializationRequest)?;
                let mut directive = ResolvedBlockFaultDirective::fault_free(
                    &request,
                    self.device.storage_fault_state().config().length_bytes,
                );
                directive.request_sequence = observed.request_sequence;
                directive.execution_nanos =
                    icount_to_virtual_ns(observed.request_icount, self.device.core().shift_bits())
                        .map_err(DeviceError::from)
                        .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
                self.install_storage_fault_directive(request.identity(), directive)?;
            }

            let intake = self.process_one_storage_request()?;
            aggregate.absorb_intake(intake)?;
            let mut installed = false;
            while let Some(opportunity) = self.next_storage_execution_opportunity(now_nanos) {
                let mut directive = opportunity.admission.clone();
                directive.execution_nanos = opportunity.ready_nanos;
                self.install_storage_execution_directive(ResolvedBlockExecutionDirective {
                    opportunity,
                    directive,
                })?;
                installed = true;
            }
            while let Some(opportunity) =
                self.next_storage_request_persistence_opportunity(now_nanos)
            {
                let mut directive = opportunity.resolved.clone();
                directive.execution_nanos = opportunity.ready_nanos;
                self.install_storage_request_persistence_directive(
                    ResolvedBlockRequestPersistenceDirective {
                        opportunity,
                        directive,
                    },
                )?;
                installed = true;
            }
            while let Some(opportunity) = self.next_storage_persistence_opportunity(now_nanos) {
                self.install_storage_persistence_media_directive(
                    ResolvedBlockPersistenceMediaDirective {
                        opportunity,
                        flash_rules: Vec::new(),
                    },
                )?;
                installed = true;
            }
            while let Some(opportunity) = self.next_storage_delivery_opportunity(now_nanos) {
                let directive = opportunity.resolved.clone();
                self.install_storage_delivery_directive(ResolvedBlockDeliveryDirective {
                    opportunity,
                    directive,
                })?;
                installed = true;
            }
            let delivery = self.advance_storage_to(guest_icount)?;
            aggregate.absorb_delivery(delivery)?;
            if intake.processed == 0 && !installed && delivery.delivered == 0 {
                return Ok(aggregate);
            }
        }
        Err(QemuLiveBlockIoServicerError::InitializationDidNotSettle)
    }

    /// Consumes at most one directive-authorized request without advancing time.
    ///
    /// Separating intake from [`Self::advance_storage_to`] gives the production
    /// coordinator an exact seam at which to evaluate resolve/persist phases
    /// after queue release and before any device mutation becomes visible.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::RegionAccess`] for an inaccessible
    /// ring pair or [`QemuLiveBlockIoServicerError::Device`] when request intake
    /// is malformed or lacks its required admission directive.
    pub fn process_one_storage_request(
        &mut self,
    ) -> Result<QemuLiveBlockIoIntakeStep, QemuLiveBlockIoServicerError> {
        let Self {
            region,
            device,
            vm_slot,
            frames_processed,
            ..
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
        let _ = second;

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

        let next_completion_icount = device.next_exact_local_event();
        node_slot.store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));
        Ok(QemuLiveBlockIoIntakeStep {
            processed: inbox.processed,
            write_frames_processed,
            first_request_icount: inbox.first_request_icount,
            computed_completion_icount,
            next_completion_icount,
        })
    }

    /// Advances deterministic storage state and publishes responses due at `guest_icount`.
    ///
    /// The production coordinator calls this only after installing every exact
    /// opportunity decision ready at or before the requested coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::RegionAccess`] for an inaccessible
    /// response ring or [`QemuLiveBlockIoServicerError::Device`] when time
    /// regresses, an opportunity remains unresolved, or publication fails.
    pub fn advance_storage_to(
        &mut self,
        guest_icount: u64,
    ) -> Result<QemuLiveBlockIoDeliveryStep, QemuLiveBlockIoServicerError> {
        let Self {
            region,
            device,
            vm_slot,
            frames_delivered,
            ..
        } = self;
        let vm_slot = *vm_slot;
        let blk_slot = SLOT_BLK_IO as u32;
        let pair = region
            .node_directed_ring_pair_mut(vm_slot, vm_slot, blk_slot, blk_slot, vm_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?;
        let delivery = device
            .advance_to_shmem(
                guest_icount,
                pair.second.header,
                pair.second.entries,
                pair.node_slot,
            )
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        *frames_delivered += delivery.delivered;
        let next_completion_icount = device.next_exact_local_event();
        pair.node_slot
            .store_device_completion_deadline_icount(next_completion_icount.unwrap_or(0));
        Ok(QemuLiveBlockIoDeliveryStep {
            delivered: delivery.delivered,
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
        identity: BlockRequestIdentity,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .install_storage_fault_directive(identity, directive)
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

    /// Returns the next resolved request awaiting persist-phase evaluation.
    #[must_use]
    pub fn next_storage_request_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockRequestPersistenceOpportunity> {
        self.device
            .next_storage_request_persistence_opportunity(now_nanos)
    }

    /// Installs the complete persist decision for one exact request mutation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the decision is
    /// stale, repeated, malformed, or changes an earlier phase.
    pub fn install_storage_request_persistence_directive(
        &mut self,
        directive: ResolvedBlockRequestPersistenceDirective,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .install_storage_request_persistence_directive(directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the next computed completion ready for deliver-phase evaluation.
    #[must_use]
    pub fn next_storage_delivery_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockDeliveryOpportunity> {
        self.device.next_storage_delivery_opportunity(now_nanos)
    }

    /// Installs one exact deliver-phase decision for a computed completion.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when the decision is
    /// stale, repeated, malformed, or changes an earlier phase.
    pub fn install_storage_delivery_directive(
        &mut self,
        directive: ResolvedBlockDeliveryDirective,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .install_storage_delivery_directive(directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the complete deterministic storage-fault continuation.
    #[must_use]
    pub fn storage_fault_state(&self) -> &BlockFaultState {
        self.device.storage_fault_state()
    }

    /// Restores an exact state captured before an uncommitted host transaction.
    pub(crate) fn restore_storage_fault_state(&mut self, state: BlockFaultState) {
        self.device.restore_storage_fault_state(state);
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

    /// Borrows completed physical-media outcomes without acknowledging them.
    #[must_use]
    pub fn storage_persistence_media_outcomes(&self) -> &[BlockPersistenceMediaOutcome] {
        self.device.storage_persistence_media_outcomes()
    }

    /// Drains integrated storage-service evidence for durable event recording.
    pub fn drain_storage_service_outcomes(&mut self) -> Vec<BlockServiceCompletion> {
        self.device.drain_storage_service_outcomes()
    }

    /// Borrows integrated storage-service evidence without acknowledging it.
    #[must_use]
    pub fn storage_service_outcomes(&self) -> &[BlockServiceCompletion] {
        self.device.storage_service_outcomes()
    }

    /// Returns all pending storage outcomes in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] when checkpointed
    /// outcome-order state is invalid.
    pub fn storage_outcomes(
        &self,
    ) -> Result<Vec<BlockStorageOutcome>, QemuLiveBlockIoServicerError> {
        self.device
            .storage_outcomes()
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Drains all storage outcomes in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] without mutation when
    /// checkpointed outcome-order state is invalid.
    pub fn drain_storage_outcomes(
        &mut self,
    ) -> Result<Vec<BlockStorageOutcome>, QemuLiveBlockIoServicerError> {
        self.device
            .drain_storage_outcomes()
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
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
        identity: BlockRequestIdentity,
        release: BlockRetainedRelease,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .release_storage_completion(identity, release)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Atomically releases a batch of retained storage completions.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::Device`] without changing the
    /// device when any release or response reservation fails.
    pub fn release_storage_completions(
        &mut self,
        releases: &[(BlockRequestIdentity, BlockRetainedRelease)],
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device
            .release_storage_completions(releases)
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

impl Default for QemuLiveBlockIoServiceStep {
    fn default() -> Self {
        Self {
            processed: 0,
            write_frames_processed: 0,
            delivered: 0,
            first_request_icount: None,
            computed_completion_icount: None,
            next_completion_icount: None,
        }
    }
}

impl QemuLiveBlockIoServiceStep {
    fn absorb_intake(
        &mut self,
        intake: QemuLiveBlockIoIntakeStep,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.processed = self
            .processed
            .checked_add(intake.processed)
            .ok_or(QemuLiveBlockIoServicerError::ServiceAccountingOverflow)?;
        self.write_frames_processed = self
            .write_frames_processed
            .checked_add(intake.write_frames_processed)
            .ok_or(QemuLiveBlockIoServicerError::ServiceAccountingOverflow)?;
        self.first_request_icount = self.first_request_icount.or(intake.first_request_icount);
        self.computed_completion_icount = self
            .computed_completion_icount
            .or(intake.computed_completion_icount);
        self.next_completion_icount = intake.next_completion_icount;
        Ok(())
    }

    fn absorb_delivery(
        &mut self,
        delivery: QemuLiveBlockIoDeliveryStep,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.delivered = self
            .delivered
            .checked_add(delivery.delivered)
            .ok_or(QemuLiveBlockIoServicerError::ServiceAccountingOverflow)?;
        self.next_completion_icount = delivery.next_completion_icount;
        Ok(())
    }
}

/// Request-intake half of one staged block servicing pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoIntakeStep {
    /// Request frames consumed in this pass (zero or one).
    pub processed: usize,
    /// Consumed write frames (zero or one).
    pub write_frames_processed: usize,
    /// Submit icount carried by the consumed request.
    pub first_request_icount: Option<u64>,
    /// Provisional exact local event after intake.
    pub computed_completion_icount: Option<u64>,
    /// Earliest exact local event after intake.
    pub next_completion_icount: Option<u64>,
}

/// Delivery half of one staged block servicing pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoDeliveryStep {
    /// Responses published to the guest ring.
    pub delivered: usize,
    /// Earliest exact local event remaining after delivery.
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
    /// Pre-ready block discovery carried a malformed request frame.
    #[error("pre-ready block discovery carried a malformed request")]
    MalformedInitializationRequest,
    /// Pre-ready staged storage work exceeded its deterministic settle bound.
    #[error("pre-ready block discovery did not settle within the hard step bound")]
    InitializationDidNotSettle,
    /// Per-pass diagnostic accounting exceeded the host integer width.
    #[error("block-I/O service accounting overflowed")]
    ServiceAccountingOverflow,
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
    /// A checkpoint was attempted without a plugin-acknowledged coordinated pause.
    #[error("block-I/O checkpoint requires a plugin-acknowledged coordinated pause")]
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
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::fd::AsFd;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use crucible_shmem::{RegionAllocation, RegionConfig, authorize_advance_ceiling};

    use super::*;

    #[cfg(unix)]
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    fn checkpoint_fixture() -> (fs::File, u64, QemuLiveBlockIoServicer) {
        checkpoint_fixture_with_latency(BlockLatency::default())
    }

    #[cfg(unix)]
    fn checkpoint_fixture_with_latency(
        latency: BlockLatency,
    ) -> (fs::File, u64, QemuLiveBlockIoServicer) {
        let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))
            .unwrap_or_else(|error| panic!("allocate test region: {error}"));
        let slot = allocation
            .node_slot(0)
            .unwrap_or_else(|| panic!("test region must contain slot zero"));
        let ceiling = authorize_advance_ceiling(0, 0, None)
            .unwrap_or_else(|error| panic!("authorize test boundary: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("publish test ceiling: {error}"));
        slot.publish_reached_icount(0, 0)
            .unwrap_or_else(|error| panic!("publish test boundary: {error}"));
        allocation
            .header()
            .request_pause([slot])
            .unwrap_or_else(|error| panic!("request test checkpoint pause: {error}"));
        slot.publish_pause_quiesced(0, 0, 0)
            .unwrap_or_else(|error| panic!("publish test checkpoint pause: {error}"));
        let layout = allocation.layout();
        let bytes = allocation
            .setup_region_bytes()
            .unwrap_or_else(|error| panic!("serialize test region: {error}"));
        let mut path = std::env::temp_dir();
        path.push(format!(
            "crucible-block-servicer-checkpoint-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|error| panic!("create test region: {error}"));
        fs::remove_file(&path).unwrap_or_else(|error| panic!("unlink test region: {error}"));
        file.set_len(layout.region_size)
            .unwrap_or_else(|error| panic!("size test region: {error}"));
        file.write_all(&bytes)
            .unwrap_or_else(|error| panic!("write test region: {error}"));
        let servicer = QemuLiveBlockIoServicer::from_shmem_fd_with_base_and_latency(
            file.as_fd(),
            layout.region_size,
            0,
            0,
            BaseImage::new(deterministic_base_image(4096)),
            latency,
        )
        .unwrap_or_else(|error| panic!("map test servicer: {error}"));
        (file, layout.region_size, servicer)
    }

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

    #[cfg(unix)]
    #[test]
    fn explicit_latency_is_retained_in_exact_checkpoint_state() {
        let latency = BlockLatency::new(50_000_000, 60_000_000, 700, 300, 4);
        let (_file, _region_len, mut servicer) = checkpoint_fixture_with_latency(latency);
        let checkpoint = servicer
            .checkpoint(ContentHash::from_bytes(b"explicit-block-latency"))
            .unwrap_or_else(|error| panic!("capture timed block checkpoint: {error}"));

        assert_eq!(checkpoint.device.latency, latency);
    }

    #[cfg(unix)]
    #[test]
    fn latency_replacement_is_retained_in_exact_checkpoint_state() {
        let replacement = BlockLatency::new(70_000_000, 80_000_000, 900, 400, 8);
        let (_file, _region_len, mut servicer) = checkpoint_fixture();
        servicer.set_latency_model(replacement);
        let checkpoint = servicer
            .checkpoint(ContentHash::from_bytes(b"replacement-block-latency"))
            .unwrap_or_else(|error| panic!("capture replacement block checkpoint: {error}"));

        assert_eq!(checkpoint.device.latency, replacement);
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

    #[cfg(unix)]
    #[test]
    fn in_place_checkpoint_restore_reinstates_exact_device_and_ring_state() {
        let (_file, _region_len, mut servicer) = checkpoint_fixture();
        let binding = ContentHash::from_bytes(b"execution-checkpoint-a");
        let mut cached = BlockDurabilityConfig::write_through(4096);
        cached.atomic_write_bytes = 512;
        cached.volatile_cache_bytes = 4096;
        cached.cache_entries = 16;
        cached.retained_versions = 16;
        cached.completion_durability =
            crucible_device::block::BlockCompletionDurability::VolatileCacheAccepted;
        servicer
            .configure_storage_faults(cached, true)
            .unwrap_or_else(|error| panic!("configure storage: {error}"));
        servicer.frames_processed = 7;
        servicer.frames_delivered = 5;
        let checkpoint = servicer
            .checkpoint(binding)
            .unwrap_or_else(|error| panic!("capture block checkpoint: {error}"));

        servicer
            .configure_storage_faults(BlockDurabilityConfig::write_through(4096), false)
            .unwrap_or_else(|error| panic!("mutate storage configuration: {error}"));
        servicer.frames_processed = 99;
        servicer.frames_delivered = 88;
        servicer
            .restore_checkpoint(binding, &checkpoint)
            .unwrap_or_else(|error| panic!("restore block checkpoint: {error}"));

        let restored = servicer
            .checkpoint(binding)
            .unwrap_or_else(|error| panic!("recapture restored checkpoint: {error}"));
        assert_eq!(restored, checkpoint);
    }

    #[cfg(unix)]
    #[test]
    fn rejected_in_place_restore_preserves_exact_live_continuation() {
        let (_file, _region_len, mut servicer) = checkpoint_fixture();
        let binding = ContentHash::from_bytes(b"execution-checkpoint-a");
        let checkpoint = servicer
            .checkpoint(binding)
            .unwrap_or_else(|error| panic!("capture block checkpoint: {error}"));
        let before = checkpoint.clone();

        let error = servicer
            .restore_checkpoint(
                ContentHash::from_bytes(b"execution-checkpoint-b"),
                &checkpoint,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            QemuLiveBlockIoServicerError::CheckpointBindingMismatch
        ));
        let after = servicer
            .checkpoint(binding)
            .unwrap_or_else(|error| panic!("capture state after rejected restore: {error}"));
        assert_eq!(after, before);
    }
}
