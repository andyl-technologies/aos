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

use std::fs::File;
use std::io::Write;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crucible::ContentHash;
use crucible_device::block::BlockFaultWriteDisposition;
use crucible_device::block::{
    BlockArrayDirtyRange, BlockDeliveryOpportunity, BlockDurabilityConfig,
    BlockExecutionOpportunity, BlockExternalDurabilityDependency, BlockFaultState,
    BlockPersistenceMediaOutcome, BlockPersistenceOpportunity, BlockRequestPersistenceOpportunity,
    BlockRetainedRelease, BlockRetainedReleaseOutcome, BlockServiceCompletion, BlockStorageOutcome,
    ResolvedBlockControllerTransition, ResolvedBlockDeliveryDirective,
    ResolvedBlockExecutionDirective, ResolvedBlockFaultDirective, ResolvedBlockMediaRule,
    ResolvedBlockPersistenceMediaDirective, ResolvedBlockRequestPersistenceDirective,
    install_cross_device_misdirected_persistence,
};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, BlockRequestIdentity, DeviceError, IoCore,
    Request,
};
use crucible_shmem::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    NodeSlotSnapshot, RegionHeaderSnapshot, SLOT_BLK_IO, STATUS_IDLE, STATUS_RUNNING,
    SetupRegionMapError, icount_to_virtual_ns, mmap_setup_region,
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
    device: QemuSharedBlockDevice,
    vm_slot: u32,
    frames_processed: usize,
    frames_delivered: usize,
}

/// Shared ownership of one authoritative live block-device continuation.
///
/// Servicers retain ring ownership while the lifecycle uses this handle to
/// stage atomic transactions spanning two independently owned block devices.
#[derive(Clone)]
pub struct QemuSharedBlockDevice {
    inner: Arc<QemuSharedBlockDeviceInner>,
}

struct QemuSharedBlockDeviceInner {
    device: Mutex<BlockDevice>,
    notification: Mutex<QemuBlockDeviceNotification>,
}

struct QemuBlockDeviceNotification {
    region: MappedSetupRegion,
    vm_slot: u32,
    wake: Option<Arc<File>>,
}

impl QemuSharedBlockDevice {
    fn new(device: BlockDevice, notification_region: MappedSetupRegion, vm_slot: u32) -> Self {
        Self {
            inner: Arc::new(QemuSharedBlockDeviceInner {
                device: Mutex::new(device),
                notification: Mutex::new(QemuBlockDeviceNotification {
                    region: notification_region,
                    vm_slot,
                    wake: None,
                }),
            }),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, BlockDevice>, QemuLiveBlockIoServicerError> {
        self.inner
            .device
            .lock()
            .map_err(|_| QemuLiveBlockIoServicerError::DeviceLockPoisoned)
    }

    pub(crate) fn attach_notification_wake(
        &self,
        wake: Arc<File>,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        let mut notification = self
            .inner
            .notification
            .lock()
            .map_err(|_| QemuLiveBlockIoServicerError::NotificationLockPoisoned)?;
        if notification.wake.is_some() {
            return Err(QemuLiveBlockIoServicerError::NotificationWakeAlreadyAttached);
        }
        notification.wake = Some(wake);
        Ok(())
    }

    /// Returns whether two handles own the same authoritative device.
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Inspects exact controller-visible bytes without changing cache policy state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when the
    /// authoritative device lock is poisoned, or
    /// [`QemuLiveBlockIoServicerError::Device`] when the range is invalid.
    pub fn inspect_storage_visible(
        &self,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, QemuLiveBlockIoServicerError> {
        self.lock()?
            .inspect_storage_visible(offset, count)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the authoritative guest-visible device length.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when the
    /// authoritative device lock is poisoned.
    pub fn storage_length(&self) -> Result<u64, QemuLiveBlockIoServicerError> {
        Ok(self.lock()?.length())
    }

    /// Resolves the logical bytes produced by this device's discard contract.
    ///
    /// # Errors
    ///
    /// Returns a lock error or the authoritative device's range/alignment error.
    pub fn storage_array_discard_replacement(
        &self,
        request: &BlockRequest,
    ) -> Result<Option<Vec<u8>>, QemuLiveBlockIoServicerError> {
        self.lock()?
            .storage_array_discard_replacement(request)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Schedules or returns this logical device's next array rebuild chunk.
    ///
    /// # Errors
    ///
    /// Returns a lock error or an invalid rebuild-service error.
    pub fn next_storage_array_rebuild_opportunity(
        &self,
        now_nanos: u64,
        chunk_bytes: u64,
        bytes_per_second: u64,
        operations_per_second: Option<u64>,
    ) -> Result<
        Option<crucible_device::block::BlockArrayRebuildOpportunity>,
        QemuLiveBlockIoServicerError,
    > {
        self.lock()?
            .next_storage_array_rebuild_opportunity(
                now_nanos,
                chunk_bytes,
                bytes_per_second,
                operations_per_second,
            )
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Retires one evaluated failed rebuild attempt while preserving its bytes.
    ///
    /// # Errors
    ///
    /// Returns a lock error or a stale rebuild-opportunity error.
    pub fn defer_storage_array_rebuild(
        &self,
        opportunity: &crucible_device::block::BlockArrayRebuildOpportunity,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.lock()?
            .defer_storage_array_rebuild(opportunity)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Pauses one scheduled rebuild while its member or path is unavailable.
    ///
    /// # Errors
    ///
    /// Returns a lock error or a stale rebuild-opportunity error.
    pub fn pause_storage_array_rebuild(
        &self,
        now_nanos: u64,
        opportunity: &crucible_device::block::BlockArrayRebuildOpportunity,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.lock()?
            .pause_storage_array_rebuild(now_nanos, opportunity)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Atomically writes one evaluated rebuild chunk to its member and retires it.
    ///
    /// # Errors
    ///
    /// Returns identity, lock, notification, member-mutation, or stale-cursor
    /// errors without committing either device.
    pub fn install_storage_array_rebuild(
        &self,
        source_id: ContentHash,
        destination: &Self,
        destination_id: ContentHash,
        opportunity: &crucible_device::block::BlockArrayRebuildOpportunity,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        if source_id == destination_id || self.ptr_eq(destination) {
            return Err(QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch);
        }
        let mut handles = [
            (source_id, self.clone()),
            (destination_id, destination.clone()),
        ];
        handles.sort_by_key(|(id, _)| *id);
        let mut devices = handles
            .iter()
            .map(|(_, handle)| handle.lock())
            .collect::<Result<Vec<_>, _>>()?;
        let prior = devices
            .iter()
            .map(|device| (*device).clone())
            .collect::<Vec<_>>();
        let mut staged = prior.clone();
        let source_index = usize::from(handles[0].0 != source_id);
        let destination_index = 1 - source_index;
        let prior_deadline = prior[destination_index].next_exact_local_event();
        staged[destination_index]
            .apply_storage_external_mutation(
                opportunity.sequence,
                opportunity.ready_nanos,
                BlockRequest::write(
                    u32::try_from(opportunity.sequence).unwrap_or(u32::MAX),
                    opportunity.start_byte,
                    opportunity.bytes.clone(),
                ),
            )
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        staged[source_index]
            .complete_storage_array_rebuild(opportunity)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let deadline = staged[destination_index].next_exact_local_event();
        for (device, next) in devices.iter_mut().zip(staged) {
            **device = next;
        }
        if let Err(error) = destination.publish_remote_mutation(deadline, prior_deadline) {
            for (device, before) in devices.iter_mut().zip(prior) {
                **device = before;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Returns the destination's actual durable cache frontier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when the
    /// authoritative device lock is poisoned.
    pub fn actual_durable_frontier(&self) -> Result<u64, QemuLiveBlockIoServicerError> {
        Ok(self.lock()?.storage_fault_state().actual_durable_frontier())
    }

    /// Returns the aggregate number of pending storage operations.
    ///
    /// # Errors
    ///
    /// Returns a lock or device-state error when the count cannot be read.
    pub fn pending_operation_count(&self) -> Result<u64, QemuLiveBlockIoServicerError> {
        self.pending_operation_usage()
            .map(|(operations, _bytes)| operations)
    }

    /// Returns the aggregate pending count and largest retained request extent.
    ///
    /// # Errors
    ///
    /// Returns a lock or device-state error when the usage cannot be read.
    pub fn pending_operation_usage(&self) -> Result<(u64, u64), QemuLiveBlockIoServicerError> {
        self.lock()?
            .storage_fault_state()
            .pending_operation_usage()
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the number and digest of live volatile-cache entries.
    ///
    /// This observation does not alter replacement order or any durability
    /// frontier, so production evidence collection cannot perturb execution.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when the
    /// authoritative device lock is poisoned.
    pub fn volatile_cache_evidence(
        &self,
    ) -> Result<(usize, [u8; 32]), QemuLiveBlockIoServicerError> {
        let device = self.lock()?;
        let state = device.storage_fault_state();
        Ok((
            state.volatile_entries().len(),
            state.volatile_entries_digest(),
        ))
    }

    /// Applies one asynchronous controller transition to the live device.
    ///
    /// The complete device is staged before commit. Publication of a changed
    /// completion horizon wakes the owning runtime; if publication fails, the
    /// exact pre-transition device state is restored.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when the
    /// authoritative device lock is poisoned, a notification error when the
    /// owning runtime cannot be awakened, or
    /// [`QemuLiveBlockIoServicerError::Device`] when the transition is invalid.
    pub fn apply_storage_boundary_mutations(
        &self,
        volatile_sequences: &[u64],
        controller_transitions: &[(ResolvedBlockControllerTransition, u64)],
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        let mut device = self.lock()?;
        let prior = device.clone();
        let prior_deadline = prior.next_exact_local_event();
        device
            .lose_storage_volatile(volatile_sequences)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        for (transition, boundary_nanos) in controller_transitions {
            device
                .apply_storage_controller_transition(transition, *boundary_nanos)
                .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        }
        let deadline = device.next_exact_local_event();
        if let Err(error) = self.publish_remote_mutation(deadline, prior_deadline) {
            *device = prior;
            return Err(error);
        }
        Ok(())
    }

    /// Returns whether this device has acknowledged an external dependency at
    /// its configured controller, volatile-cache, or durable-media stage.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when the
    /// authoritative device lock is poisoned.
    pub fn satisfies_external_durability(
        &self,
        dependency: BlockExternalDurabilityDependency,
    ) -> Result<bool, QemuLiveBlockIoServicerError> {
        self.lock().map(|device| {
            device
                .storage_fault_state()
                .completion_frontier(dependency.required_durability)
                >= dependency.required_frontier
        })
    }

    /// Atomically installs one persist-phase write redirected to another device.
    ///
    /// Locks are acquired in canonical content-hash order. The underlying
    /// transaction clones both complete devices and commits neither unless the
    /// destination mutation, deadline publication, and runtime wake all succeed.
    /// The returned dependency gates source completion on the destination's
    /// configured normal completion frontier, while the destination is scheduled
    /// at the source persistence opportunity's exact virtual-time coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when either
    /// device lock is poisoned, or [`QemuLiveBlockIoServicerError::Device`]
    /// when the transaction does not exactly match the resolved destination or
    /// either device rejects its staged transition.
    pub fn install_cross_device_misdirected_persistence(
        &self,
        source_id: ContentHash,
        destination: &Self,
        destination_id: ContentHash,
        resolved: ResolvedBlockRequestPersistenceDirective,
    ) -> Result<BlockExternalDurabilityDependency, QemuLiveBlockIoServicerError> {
        if source_id == destination_id || self.ptr_eq(destination) {
            return Err(QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch);
        }
        let remote_boundary = resolved.opportunity.ready_nanos;
        let dependency = if source_id < destination_id {
            let mut source_device = self.lock()?;
            let mut destination_device = destination.lock()?;
            let prior_source = source_device.clone();
            let prior_destination = destination_device.clone();
            let prior_deadline = prior_destination.next_exact_local_event();
            let dependency = match install_cross_device_misdirected_persistence(
                &mut source_device,
                &mut destination_device,
                resolved,
                destination_id.bytes,
            ) {
                Ok(dependency) => dependency,
                Err(source) => return Err(QemuLiveBlockIoServicerError::Device { source }),
            };
            let deadline = destination_device
                .next_exact_local_event()
                .or(Some(remote_boundary));
            if let Err(error) = destination.publish_remote_mutation(deadline, prior_deadline) {
                *source_device = prior_source;
                *destination_device = prior_destination;
                return Err(error);
            }
            dependency
        } else {
            let mut destination_device = destination.lock()?;
            let mut source_device = self.lock()?;
            let prior_source = source_device.clone();
            let prior_destination = destination_device.clone();
            let prior_deadline = prior_destination.next_exact_local_event();
            let dependency = match install_cross_device_misdirected_persistence(
                &mut source_device,
                &mut destination_device,
                resolved,
                destination_id.bytes,
            ) {
                Ok(dependency) => dependency,
                Err(source) => return Err(QemuLiveBlockIoServicerError::Device { source }),
            };
            let deadline = destination_device
                .next_exact_local_event()
                .or(Some(remote_boundary));
            if let Err(error) = destination.publish_remote_mutation(deadline, prior_deadline) {
                *source_device = prior_source;
                *destination_device = prior_destination;
                return Err(error);
            }
            dependency
        };
        Ok(dependency)
    }

    /// Atomically applies one logical array mutation across an ordered device set.
    ///
    /// `destinations` contains `(device identity, handle, ordered requests)` and
    /// must be in unique identity order. A destination's requests must all have
    /// the logical operation and strictly increasing offsets, except that flush
    /// has exactly one zero-range request. Every complete device is cloned while
    /// all locks are held; the logical source and all destinations commit only
    /// after every destination accepts its exact mutation. Runtime notifications
    /// are then published for every changed destination. A notification failure
    /// restores every device and republishes the prior horizons.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch`]
    /// for aliases or noncanonical destination order, a lock/notification error
    /// for host ownership failures, or [`QemuLiveBlockIoServicerError::Device`]
    /// when any real block device rejects the transaction.
    pub fn install_multi_device_mutation(
        &self,
        source_id: ContentHash,
        destinations: &[(ContentHash, QemuSharedBlockDevice, Vec<BlockRequest>)],
        dirty_writes: &[BlockArrayDirtyRange],
        mut resolved: ResolvedBlockRequestPersistenceDirective,
    ) -> Result<Vec<BlockExternalDurabilityDependency>, QemuLiveBlockIoServicerError> {
        if destinations.is_empty()
            || destinations.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || destinations
                .iter()
                .any(|(id, handle, _)| *id == source_id || self.ptr_eq(handle))
            || destinations
                .iter()
                .enumerate()
                .any(|(index, (_, handle, _))| {
                    destinations[index + 1..]
                        .iter()
                        .any(|(_, other, _)| handle.ptr_eq(other))
                })
        {
            return Err(QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch);
        }
        let remote_boundary = resolved.opportunity.ready_nanos;
        let mut handles = Vec::with_capacity(destinations.len() + 1);
        handles.push((source_id, self.clone()));
        handles.extend(
            destinations
                .iter()
                .map(|(id, handle, _)| (*id, handle.clone())),
        );
        handles.sort_by_key(|(id, _)| *id);
        let mut devices = handles
            .iter()
            .map(|(_, handle)| handle.lock())
            .collect::<Result<Vec<_>, _>>()?;
        let prior = devices
            .iter()
            .map(|device| (*device).clone())
            .collect::<Vec<_>>();
        let mut staged = prior.clone();
        let prior_deadlines = prior
            .iter()
            .map(BlockDevice::next_exact_local_event)
            .collect::<Vec<_>>();
        let source_index = handles
            .binary_search_by_key(&source_id, |(id, _)| *id)
            .map_err(|_| QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch)?;
        if dirty_writes.windows(2).any(|pair| {
            (pair[0].member_ordinal, pair[0].start_byte)
                >= (pair[1].member_ordinal, pair[1].start_byte)
        }) {
            return Err(QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch);
        }
        let mut dependencies = Vec::with_capacity(destinations.len());
        for (destination_id, _, requests) in destinations {
            let destination_index = handles
                .binary_search_by_key(destination_id, |(id, _)| *id)
                .map_err(|_| QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch)?;
            let logical_op = resolved.opportunity.request.op;
            if requests.is_empty()
                || requests.iter().any(|request| {
                    request.op != logical_op
                        && !(logical_op == crucible_device::block::BlockOp::Discard
                            && request.op == crucible_device::block::BlockOp::Write)
                })
                || (resolved.opportunity.request.op == crucible_device::block::BlockOp::Flush
                    && requests.len() != 1)
                || (resolved.opportunity.request.op != crucible_device::block::BlockOp::Flush
                    && requests
                        .windows(2)
                        .any(|pair| pair[0].offset >= pair[1].offset))
            {
                return Err(QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch);
            }
            let mut required_durability = None;
            let mut required_frontier = 0_u64;
            for request in requests {
                let (durability, frontier) = staged[destination_index]
                    .apply_storage_external_mutation(
                        resolved.directive.request_sequence,
                        resolved.opportunity.ready_nanos,
                        request.clone(),
                    )
                    .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
                required_durability = Some(durability);
                required_frontier = required_frontier.max(frontier);
            }
            dependencies.push(BlockExternalDurabilityDependency {
                destination_device: destination_id.bytes,
                required_durability: required_durability
                    .ok_or(QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch)?,
                required_frontier,
            });
        }
        match resolved.opportunity.request.op {
            crucible_device::block::BlockOp::Write | crucible_device::block::BlockOp::Discard => {
                resolved.directive.write_disposition = BlockFaultWriteDisposition::Lost;
            }
            crucible_device::block::BlockOp::Flush => {
                resolved.directive.flush_disposition =
                    crucible_device::block::BlockFaultFlushDisposition::Lie;
            }
            crucible_device::block::BlockOp::Read | crucible_device::block::BlockOp::GetLength => {
                return Err(QemuLiveBlockIoServicerError::CrossDeviceIdentityMismatch);
            }
        }
        resolved.directive.external_durability_dependencies = dependencies.clone();
        for dirty in dirty_writes {
            staged[source_index]
                .record_storage_array_dirty_range(
                    dirty.member_ordinal,
                    dirty.start_byte,
                    dirty.bytes.clone(),
                    resolved.opportunity.ready_nanos,
                )
                .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        }
        staged[source_index]
            .install_storage_request_persistence_directive(resolved)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let deadlines = staged
            .iter()
            .enumerate()
            .map(|(index, device)| {
                device
                    .next_exact_local_event()
                    .or_else(|| (index != source_index).then_some(remote_boundary))
            })
            .collect::<Vec<_>>();
        for (device, next) in devices.iter_mut().zip(staged) {
            **device = next;
        }
        for (index, (_, handle)) in handles.iter().enumerate() {
            if index == source_index {
                continue;
            }
            if let Err(error) =
                handle.publish_remote_mutation(deadlines[index], prior_deadlines[index])
            {
                for (device, before) in devices.iter_mut().zip(prior.iter()) {
                    **device = before.clone();
                }
                for (rollback_index, (_, rollback_handle)) in handles.iter().enumerate() {
                    if rollback_index != source_index {
                        let _ = rollback_handle.publish_remote_mutation(
                            prior_deadlines[rollback_index],
                            deadlines[rollback_index],
                        );
                    }
                }
                return Err(error);
            }
        }
        Ok(dependencies)
    }

    fn publish_remote_mutation(
        &self,
        deadline: Option<u64>,
        rollback_deadline: Option<u64>,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        let notification = self
            .inner
            .notification
            .lock()
            .map_err(|_| QemuLiveBlockIoServicerError::NotificationLockPoisoned)?;
        let wake = notification
            .wake
            .clone()
            .ok_or(QemuLiveBlockIoServicerError::NotificationWakeMissing)?;
        let slot = notification
            .region
            .node_slot(notification.vm_slot)
            .map_err(|source| QemuLiveBlockIoServicerError::RegionAccess { source })?;
        slot.store_device_completion_deadline_icount(deadline.unwrap_or(0));
        if let Err(source) = slot.wake_for_frame_delivery() {
            slot.store_device_completion_deadline_icount(rollback_deadline.unwrap_or(0));
            return Err(QemuLiveBlockIoServicerError::Device {
                source: DeviceError::from(source),
            });
        }
        let mut wake = wake.as_ref();
        if let Err(source) = wake.write_all(&1_u64.to_ne_bytes()) {
            slot.store_device_completion_deadline_icount(rollback_deadline.unwrap_or(0));
            return Err(QemuLiveBlockIoServicerError::NotificationWake { source });
        }
        Ok(())
    }
}

impl QemuLiveBlockIoServicer {
    /// Returns a handle to this servicer's authoritative block device.
    #[must_use]
    pub fn shared_device(&self) -> QemuSharedBlockDevice {
        self.device.clone()
    }

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
        let notification_region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveBlockIoServicerError::MapRegion { source })?;
        let core = IoCore::new(
            icount_shift,
            SLOT_BLK_IO as u32,
            SERVICER_INBOX_CAPACITY,
            SERVICER_OUTBOX_CAPACITY,
        )
        .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let device = QemuSharedBlockDevice::new(
            BlockDevice::new(core, base, latency),
            notification_region,
            vm_slot,
        );
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
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn set_latency_model(
        &mut self,
        latency: BlockLatency,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device.lock()?.set_latency_model(latency);
        Ok(())
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
        let notification_region = mmap_setup_region(shmem_fd, region_len)
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
            device: QemuSharedBlockDevice::new(device, notification_region, checkpoint.vm_slot),
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
        let pause_requested = self.region.header_snapshot().pause_requested != 0;
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
        if !checkpoint_boundary_is_quiescent(node.status, node.device_io_active, pause_requested) {
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
        let device = self.device.lock()?;
        Ok(QemuLiveBlockIoServicerCheckpoint {
            execution_binding,
            storage_device: None,
            region_header: self.region.header_snapshot(),
            vm_slot: self.vm_slot,
            size_bytes: device.length(),
            device: device.snapshot(),
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
        let base = self.device.lock()?.base().clone();
        let staged_device = BlockDevice::restore(&checkpoint.device, base, None)
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
        *self.device.lock()? = staged_device;
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
        let device = self.device.lock()?;
        if checkpoint.region_header.region_size != self.region.header_snapshot().region_size
            || !same_region_layout(self.region.header_snapshot(), checkpoint.region_header)
            || checkpoint.vm_slot != self.vm_slot
            || checkpoint.size_bytes != device.length()
        {
            return Err(QemuLiveBlockIoServicerError::CheckpointRegionMismatch);
        }
        checkpoint
            .requests
            .canonical_bytes()
            .and_then(|_| checkpoint.responses.canonical_bytes())
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let _staged_device = BlockDevice::restore(&checkpoint.device, device.base().clone(), None)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        drop(device);
        let pause_requested = self.region.header_snapshot().pause_requested != 0;
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
        if !checkpoint_boundary_is_quiescent(node.status, node.device_io_active, pause_requested) {
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
        let device = self.device.lock()?.snapshot();
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
        let shift_bits = self.device.lock()?.core().shift_bits();
        let now_nanos = icount_to_virtual_ns(guest_icount, shift_bits)
            .map_err(DeviceError::from)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
        let mut aggregate = QemuLiveBlockIoServiceStep::default();
        for _ in 0..INITIALIZATION_SETTLE_STEPS {
            let pin = self.pin_next_request_completion()?;
            if let Some(observed) = pin.observed {
                let request = observed
                    .request
                    .ok_or(QemuLiveBlockIoServicerError::MalformedInitializationRequest)?;
                let length_bytes = self
                    .device
                    .lock()?
                    .storage_fault_state()
                    .config()
                    .length_bytes;
                let mut directive = ResolvedBlockFaultDirective::fault_free(&request, length_bytes);
                directive.request_sequence = observed.request_sequence;
                directive.execution_nanos =
                    icount_to_virtual_ns(observed.request_icount, shift_bits)
                        .map_err(DeviceError::from)
                        .map_err(|source| QemuLiveBlockIoServicerError::Device { source })?;
                self.install_storage_fault_directive(request.identity(), directive)?;
            }

            let intake = self.process_one_storage_request()?;
            aggregate.absorb_intake(intake)?;
            let mut installed = false;
            while let Some(opportunity) = self.next_storage_execution_opportunity(now_nanos)? {
                let mut directive = opportunity.admission.clone();
                directive.execution_nanos = opportunity.ready_nanos;
                self.install_storage_execution_directive(ResolvedBlockExecutionDirective {
                    opportunity,
                    directive,
                })?;
                installed = true;
            }
            while let Some(opportunity) =
                self.next_storage_request_persistence_opportunity(now_nanos)?
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
            while let Some(opportunity) = self.next_storage_persistence_opportunity(now_nanos)? {
                self.install_storage_persistence_media_directive(
                    ResolvedBlockPersistenceMediaDirective {
                        opportunity,
                        flash_rules: Vec::new(),
                    },
                )?;
                installed = true;
            }
            while let Some(opportunity) = self.next_storage_delivery_opportunity(now_nanos)? {
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
            ..
        } = pair;
        let MappedDirectedRingMut {
            header: request_header,
            entries: request_entries,
            ..
        } = first;
        let _ = second;
        let mut device = device.lock()?;

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
        let mut device = device.lock()?;
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
            .lock()?
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
        let mut device = self.device.lock()?;
        device
            .configure_storage_faults(config, require_directives)
            .and_then(|()| {
                if require_directives {
                    device.require_storage_execution_opportunities()?;
                    device.require_storage_persistence_media_opportunities()?;
                }
                Ok(())
            })
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the first request ready for resolve/persist evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn next_storage_execution_opportunity(
        &self,
        now_nanos: u64,
    ) -> Result<Option<BlockExecutionOpportunity>, QemuLiveBlockIoServicerError> {
        Ok(self
            .device
            .lock()?
            .next_storage_execution_opportunity(now_nanos))
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
            .lock()?
            .install_storage_execution_directive(directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the next resolved request awaiting persist-phase evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn next_storage_request_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Result<Option<BlockRequestPersistenceOpportunity>, QemuLiveBlockIoServicerError> {
        Ok(self
            .device
            .lock()?
            .next_storage_request_persistence_opportunity(now_nanos))
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
            .lock()?
            .install_storage_request_persistence_directive(directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the next computed completion ready for deliver-phase evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn next_storage_delivery_opportunity(
        &self,
        now_nanos: u64,
    ) -> Result<Option<BlockDeliveryOpportunity>, QemuLiveBlockIoServicerError> {
        Ok(self
            .device
            .lock()?
            .next_storage_delivery_opportunity(now_nanos))
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
            .lock()?
            .install_storage_delivery_directive(directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns the complete deterministic storage-fault continuation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn storage_fault_state(&self) -> Result<BlockFaultState, QemuLiveBlockIoServicerError> {
        Ok(self.device.lock()?.storage_fault_state().clone())
    }

    /// Returns the aggregate number of pending operations in the authoritative device.
    ///
    /// # Errors
    ///
    /// Returns an error when the device lock is poisoned or its retained
    /// operation count cannot be represented.
    pub fn storage_pending_operation_count(&self) -> Result<u64, QemuLiveBlockIoServicerError> {
        self.storage_pending_operation_usage()
            .map(|(operations, _bytes)| operations)
    }

    /// Returns the aggregate pending count and largest retained request extent.
    ///
    /// # Errors
    ///
    /// Returns an error when the device lock is poisoned or its retained usage
    /// cannot be represented.
    pub fn storage_pending_operation_usage(
        &self,
    ) -> Result<(u64, u64), QemuLiveBlockIoServicerError> {
        self.device
            .lock()?
            .storage_fault_state()
            .pending_operation_usage()
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Returns current media intervals and prospective new rule ownership.
    ///
    /// # Errors
    ///
    /// Returns an error when the device lock is poisoned or either count cannot
    /// be represented.
    pub fn storage_media_rule_usage(
        &self,
        rules: &[ResolvedBlockMediaRule],
    ) -> Result<(u64, u64), QemuLiveBlockIoServicerError> {
        self.device
            .lock()?
            .storage_fault_state()
            .media_rule_usage(rules)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Restores an exact state captured before an uncommitted host transaction.
    pub(crate) fn restore_storage_fault_state(
        &mut self,
        state: BlockFaultState,
    ) -> Result<(), QemuLiveBlockIoServicerError> {
        self.device.lock()?.restore_storage_fault_state(state);
        Ok(())
    }

    /// Returns the next physical persistence opportunity ready at `now_nanos`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn next_storage_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Result<Option<BlockPersistenceOpportunity>, QemuLiveBlockIoServicerError> {
        Ok(self
            .device
            .lock()?
            .next_storage_persistence_opportunity(now_nanos))
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
            .lock()?
            .install_storage_persistence_media_directive(directive)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Drains completed physical-media outcomes for durable event recording.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn drain_storage_persistence_media_outcomes(
        &mut self,
    ) -> Result<Vec<BlockPersistenceMediaOutcome>, QemuLiveBlockIoServicerError> {
        Ok(self
            .device
            .lock()?
            .drain_storage_persistence_media_outcomes())
    }

    /// Borrows completed physical-media outcomes without acknowledging them.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn storage_persistence_media_outcomes(
        &self,
    ) -> Result<Vec<BlockPersistenceMediaOutcome>, QemuLiveBlockIoServicerError> {
        Ok(self
            .device
            .lock()?
            .storage_persistence_media_outcomes()
            .to_vec())
    }

    /// Drains integrated storage-service evidence for durable event recording.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn drain_storage_service_outcomes(
        &mut self,
    ) -> Result<Vec<BlockServiceCompletion>, QemuLiveBlockIoServicerError> {
        Ok(self.device.lock()?.drain_storage_service_outcomes())
    }

    /// Borrows integrated storage-service evidence without acknowledging it.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn storage_service_outcomes(
        &self,
    ) -> Result<Vec<BlockServiceCompletion>, QemuLiveBlockIoServicerError> {
        Ok(self.device.lock()?.storage_service_outcomes().to_vec())
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
            .lock()?
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
            .lock()?
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
            .lock()?
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
            .lock()?
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
    ) -> Result<BlockRetainedReleaseOutcome, QemuLiveBlockIoServicerError> {
        self.device
            .lock()?
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
    ) -> Result<Vec<BlockRetainedReleaseOutcome>, QemuLiveBlockIoServicerError> {
        self.device
            .lock()?
            .release_storage_completions(releases)
            .map_err(|source| QemuLiveBlockIoServicerError::Device { source })
    }

    /// Predicts a retained-completion release batch without changing the device.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::release_storage_completions`].
    pub fn preview_storage_completion_releases(
        &self,
        releases: &[(BlockRequestIdentity, BlockRetainedRelease)],
    ) -> Result<Vec<BlockRetainedReleaseOutcome>, QemuLiveBlockIoServicerError> {
        self.device
            .lock()?
            .preview_storage_completion_releases(releases)
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
        let device = device.lock()?;

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
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockIoServicerError::DeviceLockPoisoned`] when another
    /// thread panicked while holding the authoritative device lock.
    pub fn next_completion_icount(&self) -> Result<Option<u64>, QemuLiveBlockIoServicerError> {
        Ok(self.device.lock()?.next_exact_local_event())
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

fn checkpoint_boundary_is_quiescent(
    status: u8,
    device_io_active: u8,
    pause_requested: bool,
) -> bool {
    device_io_active == 0
        && (status == STATUS_IDLE || (status == STATUS_RUNNING && pause_requested))
}

/// Error returned by the live block-I/O servicer.
#[derive(Debug, Error)]
pub enum QemuLiveBlockIoServicerError {
    /// Another thread panicked while mutating the authoritative block device.
    #[error("authoritative block-device lock is poisoned")]
    DeviceLockPoisoned,
    /// Another thread panicked while publishing a remote device mutation.
    #[error("block-device notification lock is poisoned")]
    NotificationLockPoisoned,
    /// A runtime wake was attached to the same authoritative device twice.
    #[error("block-device remote-mutation wake channel is already attached")]
    NotificationWakeAlreadyAttached,
    /// A remotely addressable device was exposed before its runtime wake was attached.
    #[error("block-device remote-mutation wake channel is not attached")]
    NotificationWakeMissing,
    /// The destination runtime could not be awakened after a remote mutation.
    #[error("wake destination block runtime after remote mutation failed: {source}")]
    NotificationWake {
        /// Underlying eventfd write error.
        source: std::io::Error,
    },
    /// A cross-device operation named one device twice or aliased its handles.
    #[error("cross-device block transaction does not identify two distinct devices")]
    CrossDeviceIdentityMismatch,
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
#[path = "block_io_servicer_tests.rs"]
mod tests;
