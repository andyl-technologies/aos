//! Bounded host-worker dispatch for live device-side work.
//!
//! [`QemuLiveBlockHostWorkPool`] separates request observation from the block
//! device's host-side COMPUTE step:
//!
//! ```text
//! owner:  observe ring head -> compute + publish completion icount -> dispatch
//! worker: dequeue exactly that head -> COMPUTE -> return result
//! owner:  deliver only when guest_icount >= the already-pinned coordinate
//! ```
//!
//! The pin round trip is intentionally synchronous and cheap. The worker does
//! not receive the COMPUTE command until the completion coordinate has been
//! derived from virtual-time inputs and published to the node slot. Host delay
//! can therefore change only how long the guest is stalled at that coordinate,
//! never the coordinate itself.

use std::os::fd::{AsFd, BorrowedFd};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use thiserror::Error;

use crucible::model::{ContentHash, ResolvedBindingAction, ResolvedFaultTarget};
use crucible_device::block::{
    BaseImage, BlockDurabilityConfig, BlockExecutionOpportunity, BlockFaultState,
    BlockPersistenceMediaOutcome, BlockPersistenceOpportunity, BlockRequestIdentity,
    BlockRequestPersistenceOpportunity, BlockRetainedRelease, BlockServiceCompletion,
    ResolvedBlockExecutionDirective, ResolvedBlockFaultDirective,
    ResolvedBlockPersistenceMediaDirective,
};

use super::block_io_servicer::{
    QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer,
    QemuLiveBlockIoServicerError,
};
use crate::{
    QemuLiveBlockIoServicerCheckpoint, ResolvedVolatileCacheLoss, StorageFaultResolutionContext,
    StorageFaultResolutionError, VolatileCacheLossReplay, resolve_volatile_cache_loss,
};

/// Capacity of the owner-to-worker command queue.
///
/// One outstanding command is sufficient because a device's SPSC request order
/// is itself serial. Different live devices may each own one pool and overlap on
/// distinct host workers.
const COMMAND_QUEUE_CAPACITY: usize = 1;

/// Host-only delay applied before one worker COMPUTE step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QemuDeviceHostWorkDelay {
    /// Starts the host work as soon as the worker receives it.
    #[default]
    None,
    /// Delays host work by wall time without changing virtual time.
    Wall(Duration),
}

impl QemuDeviceHostWorkDelay {
    fn apply(self) {
        if let Self::Wall(delay) = self
            && !delay.is_zero()
        {
            thread::sleep(delay);
        }
    }
}

/// A one-worker bounded pool for a live block device.
///
/// The worker owns the mutable block device and its writable shared-memory
/// mapping. The owner thread performs a pin command synchronously, then may
/// dispatch one COMPUTE command and continue driving the guest while it runs.
pub struct QemuLiveBlockHostWorkPool {
    commands: SyncSender<WorkerCommand>,
    replies: Receiver<WorkerReply>,
    worker: Option<JoinHandle<()>>,
    work_in_flight: bool,
    pinned: Option<QemuLiveBlockIoHostWorkPin>,
    in_flight_pin: Option<QemuLiveBlockIoHostWorkPin>,
    in_flight_storage_fault: bool,
    storage_device: Option<ContentHash>,
}

/// Atomic storage opportunities and outcomes observed on the owning worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockStorageEvents {
    /// Next request ready for exact resolve/persist phase evaluation.
    pub execution_opportunity: Option<BlockExecutionOpportunity>,
    /// Next resolved request ready for exact persist-phase evaluation.
    pub request_persistence_opportunity: Option<BlockRequestPersistenceOpportunity>,
    /// Next physical-media decision opportunity ready at the requested coordinate.
    pub persistence_opportunity: Option<BlockPersistenceOpportunity>,
    /// Completed physical-media mutations drained exactly once.
    pub persistence_outcomes: Vec<BlockPersistenceMediaOutcome>,
    /// Completed service contributions drained exactly once.
    pub service_outcomes: Vec<BlockServiceCompletion>,
}

impl QemuLiveBlockHostWorkPool {
    /// Starts a worker and constructs its live block servicer on that worker.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveBlockHostWorkPoolError::CloneShmemFd`] when the shared
    /// memory descriptor cannot be cloned,
    /// [`QemuLiveBlockHostWorkPoolError::SpawnWorker`] when the host thread
    /// cannot be created, or [`QemuLiveBlockHostWorkPoolError::Servicer`] when
    /// the worker cannot map or initialize the block servicer.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
        size_bytes: u64,
    ) -> Result<Self, QemuLiveBlockHostWorkPoolError> {
        Self::from_shmem_fd_with_optional_storage_config(
            shmem_fd,
            region_len,
            vm_slot,
            icount_shift,
            size_bytes,
            None,
        )
    }

    /// Starts a worker with exact admitted storage durability and mandatory directives.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_shmem_fd`], including a servicer
    /// error when `config` is malformed or differs from `size_bytes`.
    pub fn from_shmem_fd_with_storage_config(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
        size_bytes: u64,
        storage_device: ContentHash,
        config: BlockDurabilityConfig,
    ) -> Result<Self, QemuLiveBlockHostWorkPoolError> {
        Self::from_shmem_fd_with_optional_storage_config(
            shmem_fd,
            region_len,
            vm_slot,
            icount_shift,
            size_bytes,
            Some((storage_device, config)),
        )
    }

    fn from_shmem_fd_with_optional_storage_config(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
        icount_shift: u8,
        size_bytes: u64,
        storage_config: Option<(ContentHash, BlockDurabilityConfig)>,
    ) -> Result<Self, QemuLiveBlockHostWorkPoolError> {
        let storage_device = storage_config.as_ref().map(|(device, _config)| *device);
        let owned_fd = shmem_fd
            .try_clone_to_owned()
            .map_err(|source| QemuLiveBlockHostWorkPoolError::CloneShmemFd { source })?;
        let (commands, command_rx) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
        let (reply_tx, replies) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(String::from("crucible-block-host-work"))
            .spawn(move || {
                let servicer = QemuLiveBlockIoServicer::from_shmem_fd(
                    owned_fd.as_fd(),
                    region_len,
                    vm_slot,
                    icount_shift,
                    size_bytes,
                )
                .and_then(|mut servicer| {
                    if let Some((_device, config)) = storage_config {
                        servicer.configure_storage_faults(config, true)?;
                    }
                    Ok(servicer)
                });
                match servicer {
                    Ok(servicer) => {
                        let _ = ready_tx.send(Ok(()));
                        worker_loop(servicer, &command_rx, &reply_tx);
                    }
                    Err(source) => {
                        let _ = ready_tx.send(Err(source));
                    }
                }
            })
            .map_err(|source| QemuLiveBlockHostWorkPoolError::SpawnWorker { source })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                replies,
                worker: Some(worker),
                work_in_flight: false,
                pinned: None,
                in_flight_pin: None,
                in_flight_storage_fault: false,
                storage_device,
            }),
            Ok(Err(source)) => {
                let _ = worker.join();
                Err(QemuLiveBlockHostWorkPoolError::Servicer { source })
            }
            Err(_) => {
                let _ = worker.join();
                Err(QemuLiveBlockHostWorkPoolError::WorkerDisconnected)
            }
        }
    }

    /// Restores a worker-owned device continuation onto its paired region.
    ///
    /// # Errors
    ///
    /// Returns the same descriptor, thread, and servicer errors as
    /// [`Self::from_shmem_fd`].
    pub fn restore_from_shmem_fd_with_base(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        expected_execution_binding: ContentHash,
        checkpoint: QemuLiveBlockIoServicerCheckpoint,
        base: BaseImage,
    ) -> Result<Self, QemuLiveBlockHostWorkPoolError> {
        let storage_device = checkpoint.storage_device();
        let owned_fd = shmem_fd
            .try_clone_to_owned()
            .map_err(|source| QemuLiveBlockHostWorkPoolError::CloneShmemFd { source })?;
        let (commands, command_rx) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
        let (reply_tx, replies) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(String::from("crucible-block-host-work"))
            .spawn(move || {
                let servicer = QemuLiveBlockIoServicer::restore_from_shmem_fd_with_base(
                    owned_fd.as_fd(),
                    region_len,
                    expected_execution_binding,
                    checkpoint,
                    base,
                );
                match servicer {
                    Ok(servicer) => {
                        let _ = ready_tx.send(Ok(()));
                        worker_loop(servicer, &command_rx, &reply_tx);
                    }
                    Err(source) => {
                        let _ = ready_tx.send(Err(source));
                    }
                }
            })
            .map_err(|source| QemuLiveBlockHostWorkPoolError::SpawnWorker { source })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                replies,
                worker: Some(worker),
                work_in_flight: false,
                pinned: None,
                in_flight_pin: None,
                in_flight_storage_fault: false,
                storage_device,
            }),
            Ok(Err(source)) => {
                let _ = worker.join();
                Err(QemuLiveBlockHostWorkPoolError::Servicer { source })
            }
            Err(_) => {
                let _ = worker.join();
                Err(QemuLiveBlockHostWorkPoolError::WorkerDisconnected)
            }
        }
    }

    /// Observes and pins the next request before host work dispatch.
    ///
    /// This call waits only for the worker to peek the ring head, compute the
    /// deterministic completion coordinate, and publish that coordinate. It does
    /// not dequeue or COMPUTE the request.
    ///
    /// # Errors
    ///
    /// Returns an error when work is already in flight, the worker disconnects,
    /// the worker protocol is violated, or the servicer cannot pin the request.
    pub fn pin_next_request_completion(
        &mut self,
    ) -> Result<QemuLiveBlockIoHostWorkPin, QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        self.commands
            .send(WorkerCommand::Pin)
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        let reply = self
            .replies
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        match reply {
            WorkerReply::Pinned(result) => {
                let pin =
                    result.map_err(|source| QemuLiveBlockHostWorkPoolError::Servicer { source })?;
                self.pinned = Some(pin.clone());
                Ok(pin)
            }
            WorkerReply::Serviced(_)
            | WorkerReply::Checkpoint(_)
            | WorkerReply::Mutated(_)
            | WorkerReply::StorageState(_)
            | WorkerReply::StorageEvents(_)
            | WorkerReply::VolatileLoss(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "pin reply",
            }),
        }
    }

    /// Dispatches one COMPUTE/delivery pass after a successful pin.
    ///
    /// `guest_icount` is the owner's current virtual-time observation. A delayed
    /// worker may finish after the guest reaches the pinned completion; a later
    /// pass then publishes the response while the guest remains stalled at that
    /// same coordinate.
    ///
    /// # Errors
    ///
    /// Returns an error when no pin precedes the dispatch, work is already in
    /// flight, or the worker disconnects.
    pub fn dispatch(
        &mut self,
        guest_icount: u64,
        delay: QemuDeviceHostWorkDelay,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        self.dispatch_with_storage_fault(guest_icount, delay, None)
    }

    /// Dispatches one pass with an exact directive resolved from the prior pin.
    ///
    /// The optional pair must name the request returned by
    /// [`Self::pin_next_request_completion`]. The worker installs it before
    /// dequeuing the shared-memory head, so installation failure leaves the
    /// request available for exact retry.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::dispatch`].
    pub fn dispatch_with_storage_fault(
        &mut self,
        guest_icount: u64,
        delay: QemuDeviceHostWorkDelay,
        directive: Option<(BlockRequestIdentity, ResolvedBlockFaultDirective)>,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        let pin = self
            .pinned
            .as_ref()
            .ok_or(QemuLiveBlockHostWorkPoolError::DispatchWithoutPin)?;
        validate_pinned_directive(pin, directive.as_ref())?;
        let has_storage_fault = directive.is_some();
        let pin = self
            .pinned
            .take()
            .ok_or(QemuLiveBlockHostWorkPoolError::DispatchWithoutPin)?;
        self.commands
            .send(WorkerCommand::Service {
                guest_icount,
                delay,
                directive,
            })
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        self.work_in_flight = true;
        self.in_flight_pin = Some(pin);
        self.in_flight_storage_fault = has_storage_fault;
        Ok(())
    }

    /// Polls for completion of the outstanding worker pass.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker disconnects, violates the protocol, or
    /// the block servicer fails.
    pub fn try_complete(
        &mut self,
    ) -> Result<Option<QemuLiveBlockIoServiceStep>, QemuLiveBlockHostWorkPoolError> {
        if !self.work_in_flight {
            return Ok(None);
        }
        match self.replies.try_recv() {
            Ok(WorkerReply::Serviced(result)) => {
                self.work_in_flight = false;
                let pin = self.in_flight_pin.take();
                let preserve_baseline_completion = !self.in_flight_storage_fault;
                self.in_flight_storage_fault = false;
                result
                    .map(|mut serviced| {
                        if let Some(observed) = pin
                            .and_then(|pinned| pinned.observed)
                            .filter(|_observed| preserve_baseline_completion)
                        {
                            serviced.first_request_icount = Some(observed.request_icount);
                            serviced.computed_completion_icount = Some(observed.completion_icount);
                        }
                        Some(serviced)
                    })
                    .map_err(|source| QemuLiveBlockHostWorkPoolError::Servicer { source })
            }
            Ok(WorkerReply::Pinned(_))
            | Ok(WorkerReply::Checkpoint(_))
            | Ok(WorkerReply::Mutated(_))
            | Ok(WorkerReply::StorageState(_))
            | Ok(WorkerReply::StorageEvents(_))
            | Ok(WorkerReply::VolatileLoss(_)) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "service reply",
            }),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                Err(QemuLiveBlockHostWorkPoolError::WorkerDisconnected)
            }
        }
    }

    /// Returns whether a COMPUTE/delivery pass is currently running.
    #[must_use]
    pub const fn work_in_flight(&self) -> bool {
        self.work_in_flight
    }

    /// Captures the complete worker-owned block-device continuation.
    ///
    /// # Errors
    ///
    /// Returns an error while work is in flight, when a request pin has not yet
    /// been dispatched, or when the worker disconnects or violates its protocol.
    pub fn checkpoint(
        &mut self,
        execution_binding: ContentHash,
    ) -> Result<QemuLiveBlockIoServicerCheckpoint, QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        if self
            .pinned
            .as_ref()
            .is_some_and(|pin| pin.observed.is_some())
        {
            return Err(QemuLiveBlockHostWorkPoolError::CheckpointWithPinnedRequest);
        }
        self.pinned = None;
        self.commands
            .send(WorkerCommand::Checkpoint { execution_binding })
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        match self
            .replies
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?
        {
            WorkerReply::Checkpoint(result) => (*result)
                .map(|mut checkpoint| {
                    checkpoint.set_storage_device(self.storage_device);
                    checkpoint
                })
                .map_err(|source| QemuLiveBlockHostWorkPoolError::Servicer { source }),
            WorkerReply::Pinned(_)
            | WorkerReply::Serviced(_)
            | WorkerReply::Mutated(_)
            | WorkerReply::StorageState(_)
            | WorkerReply::StorageEvents(_)
            | WorkerReply::VolatileLoss(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "checkpoint reply",
            }),
        }
    }

    /// Reads the complete worker-owned deterministic storage-fault state.
    ///
    /// # Errors
    ///
    /// Returns an error while work or a nonempty request pin is outstanding,
    /// or when the worker disconnects or violates its protocol.
    pub fn storage_fault_state(
        &mut self,
    ) -> Result<BlockFaultState, QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        if self
            .pinned
            .as_ref()
            .is_some_and(|pin| pin.observed.is_some())
        {
            return Err(QemuLiveBlockHostWorkPoolError::MutationWithPinnedRequest);
        }
        self.pinned = None;
        self.commands
            .send(WorkerCommand::InspectStorageState)
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        match self
            .replies
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?
        {
            WorkerReply::StorageState(result) => {
                result.map_err(|source| QemuLiveBlockHostWorkPoolError::Servicer { source })
            }
            WorkerReply::Pinned(_)
            | WorkerReply::Serviced(_)
            | WorkerReply::Checkpoint(_)
            | WorkerReply::Mutated(_)
            | WorkerReply::StorageEvents(_)
            | WorkerReply::VolatileLoss(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "storage-state reply",
            }),
        }
    }

    /// Atomically observes the next persistence opportunity and drains evidence.
    ///
    /// # Errors
    ///
    /// Returns an error while work or a nonempty pin is outstanding, or when
    /// the worker disconnects or violates its protocol.
    pub fn storage_events(
        &mut self,
        now_nanos: u64,
    ) -> Result<QemuLiveBlockStorageEvents, QemuLiveBlockHostWorkPoolError> {
        self.require_storage_device_bound()?;
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        if self
            .pinned
            .as_ref()
            .is_some_and(|pin| pin.observed.is_some())
        {
            return Err(QemuLiveBlockHostWorkPoolError::MutationWithPinnedRequest);
        }
        self.pinned = None;
        self.commands
            .send(WorkerCommand::StorageEvents { now_nanos })
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        match self
            .replies
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?
        {
            WorkerReply::StorageEvents(result) => {
                result.map_err(|source| QemuLiveBlockHostWorkPoolError::Servicer { source })
            }
            _ => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "storage-events reply",
            }),
        }
    }

    /// Installs the exact decision for one live physical-media opportunity.
    ///
    /// # Errors
    ///
    /// Returns the same worker-state, protocol, and device errors as other
    /// storage mutations.
    pub fn install_storage_persistence_media_directive(
        &mut self,
        directive: ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        self.require_storage_device_bound()?;
        self.mutate(StorageMutation::InstallPersistenceMedia(directive))
    }

    /// Installs the complete resolve/persist decision for one staged request.
    ///
    /// # Errors
    ///
    /// Returns the same worker-state, protocol, and device errors as other
    /// storage mutations.
    pub fn install_storage_execution_directive(
        &mut self,
        directive: ResolvedBlockExecutionDirective,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        self.require_storage_device_bound()?;
        self.mutate(StorageMutation::InstallExecution(directive))
    }

    /// Drops exact volatile-cache entries on the worker-owned live device.
    ///
    /// # Errors
    ///
    /// Returns an error while work or a nonempty request pin is outstanding,
    /// when the worker disconnects or violates its protocol, or when the
    /// servicer rejects the exact sequence selection.
    pub fn lose_storage_volatile(
        &mut self,
        sequences: Vec<u64>,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        self.require_storage_device_bound()?;
        self.mutate(StorageMutation::LoseVolatile(sequences))
    }

    /// Atomically resolves and applies one signal-driven cache-loss impulse.
    ///
    /// The worker computes eligibility, the replay entry-set digest, keyed
    /// selection, and mutation against one uninterrupted device state. No
    /// request service or other mutation can interleave between observation
    /// and loss.
    ///
    /// # Errors
    ///
    /// Returns an error while work or a nonempty request pin is outstanding,
    /// when the action cannot resolve exactly, when mutation fails, or when the
    /// worker disconnects or violates its protocol.
    pub fn resolve_and_lose_storage_volatile(
        &mut self,
        target: ResolvedFaultTarget,
        context: StorageFaultResolutionContext,
        action: ResolvedBindingAction,
        replay: VolatileCacheLossReplay,
    ) -> Result<ResolvedVolatileCacheLoss, QemuLiveBlockHostWorkPoolError> {
        self.require_storage_target(&target)?;
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        if self
            .pinned
            .as_ref()
            .is_some_and(|pin| pin.observed.is_some())
        {
            return Err(QemuLiveBlockHostWorkPoolError::MutationWithPinnedRequest);
        }
        self.pinned = None;
        self.commands
            .send(WorkerCommand::ResolveVolatileLoss {
                target,
                context,
                action: Box::new(action),
                replay,
            })
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        match self
            .replies
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?
        {
            WorkerReply::VolatileLoss(result) => match result {
                Ok(resolved) => Ok(resolved),
                Err(VolatileLossWorkerError::Resolution(source)) => {
                    Err(QemuLiveBlockHostWorkPoolError::StorageResolution { source })
                }
                Err(VolatileLossWorkerError::Servicer(source)) => {
                    Err(QemuLiveBlockHostWorkPoolError::Servicer { source })
                }
            },
            WorkerReply::Pinned(_)
            | WorkerReply::Serviced(_)
            | WorkerReply::Checkpoint(_)
            | WorkerReply::Mutated(_)
            | WorkerReply::StorageState(_)
            | WorkerReply::StorageEvents(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "volatile-cache loss reply",
            }),
        }
    }

    /// Drops exact controller-buffer entries on the worker-owned live device.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::lose_storage_volatile`].
    pub fn lose_storage_controller(
        &mut self,
        sequences: Vec<u64>,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        self.require_storage_device_bound()?;
        self.mutate(StorageMutation::LoseController(sequences))
    }

    /// Releases one retained completion on the worker-owned live device.
    ///
    /// # Errors
    ///
    /// Returns the same worker-state and protocol errors as
    /// [`Self::lose_storage_volatile`], or a servicer error when the request is
    /// not retained or its response cannot be scheduled.
    pub fn release_storage_completion(
        &mut self,
        identity: BlockRequestIdentity,
        release: BlockRetainedRelease,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        self.require_storage_device_bound()?;
        self.mutate(StorageMutation::ReleaseCompletion { identity, release })
    }

    fn mutate(&mut self, mutation: StorageMutation) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        if self
            .pinned
            .as_ref()
            .is_some_and(|pin| pin.observed.is_some())
        {
            return Err(QemuLiveBlockHostWorkPoolError::MutationWithPinnedRequest);
        }
        self.pinned = None;
        self.commands
            .send(WorkerCommand::Mutate(mutation))
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        match self
            .replies
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?
        {
            WorkerReply::Mutated(result) => {
                result.map_err(|source| QemuLiveBlockHostWorkPoolError::Servicer { source })
            }
            WorkerReply::Pinned(_)
            | WorkerReply::Serviced(_)
            | WorkerReply::Checkpoint(_)
            | WorkerReply::StorageState(_)
            | WorkerReply::StorageEvents(_)
            | WorkerReply::VolatileLoss(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "storage mutation reply",
            }),
        }
    }

    fn require_storage_device_bound(&self) -> Result<ContentHash, QemuLiveBlockHostWorkPoolError> {
        self.storage_device
            .ok_or(QemuLiveBlockHostWorkPoolError::StorageDeviceUnbound)
    }

    fn require_storage_target(
        &self,
        target: &ResolvedFaultTarget,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        let actual = self.require_storage_device_bound()?;
        let selected = match target {
            ResolvedFaultTarget::BlockDevice { device }
            | ResolvedFaultTarget::BlockRange { device, .. } => *device,
            _ => return Err(QemuLiveBlockHostWorkPoolError::StorageTargetKind),
        };
        if selected != actual {
            return Err(QemuLiveBlockHostWorkPoolError::StorageTargetMismatch {
                expected: actual,
                actual: selected,
            });
        }
        Ok(())
    }
}

fn validate_pinned_directive(
    pin: &QemuLiveBlockIoHostWorkPin,
    directive: Option<&(BlockRequestIdentity, ResolvedBlockFaultDirective)>,
) -> Result<(), QemuLiveBlockHostWorkPoolError> {
    let Some((identity, directive)) = directive else {
        return Ok(());
    };
    let observed = pin
        .observed
        .as_ref()
        .ok_or(QemuLiveBlockHostWorkPoolError::DirectiveWithoutRequest)?;
    let request = observed
        .request
        .as_ref()
        .ok_or(QemuLiveBlockHostWorkPoolError::MalformedPinnedRequest)?;
    if request.identity() != *identity
        || directive.operation != request.op
        || directive.offset != request.offset
        || directive.count != request.count
        || directive.request_digest != observed.wire_digest
    {
        return Err(QemuLiveBlockHostWorkPoolError::DirectivePinMismatch {
            pinned_request_id: request.request_id,
            directive_request_id: identity.request_id,
        });
    }
    Ok(())
}

impl Drop for QemuLiveBlockHostWorkPool {
    fn drop(&mut self) {
        let _ = self.commands.send(WorkerCommand::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

enum WorkerCommand {
    Pin,
    Checkpoint {
        execution_binding: ContentHash,
    },
    Service {
        guest_icount: u64,
        delay: QemuDeviceHostWorkDelay,
        directive: Option<(BlockRequestIdentity, ResolvedBlockFaultDirective)>,
    },
    Mutate(StorageMutation),
    InspectStorageState,
    StorageEvents {
        now_nanos: u64,
    },
    ResolveVolatileLoss {
        target: ResolvedFaultTarget,
        context: StorageFaultResolutionContext,
        action: Box<ResolvedBindingAction>,
        replay: VolatileCacheLossReplay,
    },
    Shutdown,
}

enum StorageMutation {
    LoseVolatile(Vec<u64>),
    LoseController(Vec<u64>),
    InstallPersistenceMedia(ResolvedBlockPersistenceMediaDirective),
    InstallExecution(ResolvedBlockExecutionDirective),
    ReleaseCompletion {
        identity: BlockRequestIdentity,
        release: BlockRetainedRelease,
    },
}

enum WorkerReply {
    Pinned(Result<QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoServicerError>),
    Serviced(Result<QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicerError>),
    Checkpoint(Box<Result<QemuLiveBlockIoServicerCheckpoint, QemuLiveBlockIoServicerError>>),
    Mutated(Result<(), QemuLiveBlockIoServicerError>),
    StorageState(Result<BlockFaultState, QemuLiveBlockIoServicerError>),
    StorageEvents(Result<QemuLiveBlockStorageEvents, QemuLiveBlockIoServicerError>),
    VolatileLoss(Result<ResolvedVolatileCacheLoss, VolatileLossWorkerError>),
}

enum VolatileLossWorkerError {
    Resolution(StorageFaultResolutionError),
    Servicer(QemuLiveBlockIoServicerError),
}

fn worker_loop(
    mut servicer: QemuLiveBlockIoServicer,
    commands: &Receiver<WorkerCommand>,
    replies: &SyncSender<WorkerReply>,
) {
    while let Ok(command) = commands.recv() {
        let reply = match command {
            WorkerCommand::Pin => WorkerReply::Pinned(servicer.pin_next_request_completion()),
            WorkerCommand::Checkpoint { execution_binding } => {
                WorkerReply::Checkpoint(Box::new(servicer.checkpoint(execution_binding)))
            }
            WorkerCommand::Service {
                guest_icount,
                delay,
                directive,
            } => {
                delay.apply();
                let result = directive
                    .map_or(Ok(()), |(request_id, directive)| {
                        servicer.install_storage_fault_directive(request_id, directive)
                    })
                    .and_then(|()| servicer.service(guest_icount));
                WorkerReply::Serviced(result)
            }
            WorkerCommand::Mutate(mutation) => WorkerReply::Mutated(match mutation {
                StorageMutation::LoseVolatile(sequences) => {
                    servicer.lose_storage_volatile(&sequences)
                }
                StorageMutation::LoseController(sequences) => {
                    servicer.lose_storage_controller(&sequences)
                }
                StorageMutation::InstallPersistenceMedia(directive) => {
                    servicer.install_storage_persistence_media_directive(directive)
                }
                StorageMutation::InstallExecution(directive) => {
                    servicer.install_storage_execution_directive(directive)
                }
                StorageMutation::ReleaseCompletion { identity, release } => servicer
                    .release_storage_completion(identity, release)
                    .map(|_| ()),
            }),
            WorkerCommand::InspectStorageState => {
                WorkerReply::StorageState(servicer.storage_fault_state())
            }
            WorkerCommand::StorageEvents { now_nanos } => WorkerReply::StorageEvents((|| {
                Ok(QemuLiveBlockStorageEvents {
                    execution_opportunity: servicer
                        .next_storage_execution_opportunity(now_nanos)?,
                    request_persistence_opportunity: servicer
                        .next_storage_request_persistence_opportunity(now_nanos)?,
                    persistence_opportunity: servicer
                        .next_storage_persistence_opportunity(now_nanos)?,
                    persistence_outcomes: servicer.drain_storage_persistence_media_outcomes()?,
                    service_outcomes: servicer.drain_storage_service_outcomes()?,
                })
            })(
            )),
            WorkerCommand::ResolveVolatileLoss {
                target,
                context,
                action,
                replay,
            } => WorkerReply::VolatileLoss(
                servicer
                    .storage_fault_state()
                    .map_err(VolatileLossWorkerError::Servicer)
                    .and_then(|state| {
                        resolve_volatile_cache_loss(&target, &state, context, &action, replay)
                            .map_err(VolatileLossWorkerError::Resolution)
                    })
                    .and_then(|resolved| {
                        servicer
                            .lose_storage_volatile(&resolved.selected_sequences)
                            .map_err(VolatileLossWorkerError::Servicer)?;
                        Ok(resolved)
                    }),
            ),
            WorkerCommand::Shutdown => break,
        };
        if replies.send(reply).is_err() {
            break;
        }
    }
}

/// Error raised by [`QemuLiveBlockHostWorkPool`].
#[derive(Debug, Error)]
pub enum QemuLiveBlockHostWorkPoolError {
    /// The shared-memory descriptor could not be cloned for the worker.
    #[error("clone shared-memory descriptor for block host worker failed: {source}")]
    CloneShmemFd {
        /// Underlying descriptor error.
        source: std::io::Error,
    },
    /// The host worker thread could not be created.
    #[error("spawn block host worker failed: {source}")]
    SpawnWorker {
        /// Underlying thread creation error.
        source: std::io::Error,
    },
    /// The worker-side live servicer failed.
    #[error("block host worker servicer failed: {source}")]
    Servicer {
        /// Underlying live-servicer error.
        source: QemuLiveBlockIoServicerError,
    },
    /// A signal-driven storage action failed exact resolution.
    #[error("resolve signal-driven storage fault failed: {source}")]
    StorageResolution {
        /// Exact resolver failure.
        source: StorageFaultResolutionError,
    },
    /// The worker was not constructed with an exact live storage-device identity.
    #[error("signal-driven storage mutation requires a device-bound worker")]
    StorageDeviceUnbound,
    /// The selected target is not a block device or block range.
    #[error("signal-driven storage mutation selected a non-block target")]
    StorageTargetKind,
    /// The selected block target belongs to another live device worker.
    #[error("storage target device mismatch: worker {expected:?}, selected {actual:?}")]
    StorageTargetMismatch {
        /// Device hash bound when the worker was constructed.
        expected: ContentHash,
        /// Device hash supplied by the resolved action.
        actual: ContentHash,
    },
    /// The worker channel closed unexpectedly.
    #[error("block host worker disconnected")]
    WorkerDisconnected,
    /// A second command was attempted while work was already running.
    #[error("block host work is already in flight")]
    WorkAlreadyInFlight,
    /// COMPUTE was dispatched without first pinning the request coordinate.
    #[error("block host work dispatch requires a preceding completion pin")]
    DispatchWithoutPin,
    /// A checkpoint was requested after pinning but before dispatching the request.
    #[error("block host work cannot checkpoint with an undispatched pinned request")]
    CheckpointWithPinnedRequest,
    /// A live mutation was requested after observing a nonempty ring head.
    #[error("block host work cannot mutate storage state with an undispatched pinned request")]
    MutationWithPinnedRequest,
    /// A directive was supplied while the pinned ring head was empty.
    #[error("a storage fault directive requires a pinned block request")]
    DirectiveWithoutRequest,
    /// The pinned frame could not be decoded as a block request.
    #[error("a storage fault directive cannot target a malformed pinned block request")]
    MalformedPinnedRequest,
    /// The directive identity or geometry differs from the exact pinned request.
    #[error(
        "storage fault directive request {directive_request_id} does not match pinned request {pinned_request_id}"
    )]
    DirectivePinMismatch {
        /// Request ID decoded from the pinned frame.
        pinned_request_id: u32,
        /// Request ID supplied with the directive.
        directive_request_id: u32,
    },
    /// The worker returned a reply for a different command phase.
    #[error("block host worker protocol violation: expected {expected}")]
    Protocol {
        /// Reply phase the owner expected.
        expected: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use crucible_device::block::BlockRequest;

    use super::*;

    fn pin(request: BlockRequest) -> QemuLiveBlockIoHostWorkPin {
        let wire = request
            .encode()
            .unwrap_or_else(|error| panic!("test request should encode: {error}"));
        QemuLiveBlockIoHostWorkPin {
            observed: Some(
                super::super::block_io_servicer::QemuLiveBlockIoObservedRequest {
                    request_sequence: 0,
                    request_icount: 10,
                    completion_icount: 20,
                    request: Some(request),
                    wire_digest: *blake3::hash(&wire).as_bytes(),
                },
            ),
            next_completion_icount: Some(20),
        }
    }

    #[test]
    fn exact_directive_matches_pinned_request() {
        let request = BlockRequest::read(7, 512, 512);
        let directive = ResolvedBlockFaultDirective::fault_free(&request, 4096);
        validate_pinned_directive(
            &pin(request),
            Some(&(BlockRequestIdentity::new(0, 7), directive)),
        )
        .unwrap_or_else(|error| panic!("exact directive should match: {error}"));
    }

    #[test]
    fn mismatched_directive_is_rejected_before_dispatch() {
        let request = BlockRequest::read(7, 512, 512);
        let other = BlockRequest::read(8, 512, 512);
        let directive = ResolvedBlockFaultDirective::fault_free(&other, 4096);
        let error = match validate_pinned_directive(
            &pin(request),
            Some(&(BlockRequestIdentity::new(0, 8), directive)),
        ) {
            Ok(()) => panic!("request alias must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            QemuLiveBlockHostWorkPoolError::DirectivePinMismatch {
                pinned_request_id: 7,
                directive_request_id: 8,
            }
        ));
    }
}
