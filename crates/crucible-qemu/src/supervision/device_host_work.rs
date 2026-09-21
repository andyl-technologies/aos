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
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crucible::model::ContentHash;
use crucible_device::block::{
    BaseImage, BlockDurabilityConfig, BlockFaultState, BlockRequestIdentity, BlockRetainedRelease,
    ResolvedBlockExecutionDirective, ResolvedBlockFaultDirective,
    ResolvedBlockPersistenceMediaDirective,
};

use super::block_io_servicer::{
    QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer,
    QemuLiveBlockIoServicerError,
};
use super::host_io_runtime::QemuBlockFaultCoordinator;
use crate::{QemuAsyncDriverRuntimeError, QemuLiveBlockIoServicerCheckpoint};

mod worker;
pub use worker::QemuLiveBlockHostWorkPoolError;
use worker::{StorageMutation, WorkerCommand, WorkerReply, worker_loop};

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
    published_deadline: Option<u64>,
    in_flight_storage_fault: bool,
    storage_device: Option<ContentHash>,
    shared_device: crate::QemuSharedBlockDevice,
}

impl QemuLiveBlockHostWorkPool {
    /// Starts the production worker around an already configured servicer.
    ///
    /// # Errors
    ///
    /// Returns an error when the host worker cannot be spawned or acknowledge
    /// ownership of the servicer.
    pub(crate) fn from_servicer(
        servicer: QemuLiveBlockIoServicer,
    ) -> Result<(Self, Arc<Mutex<QemuLiveBlockIoServicer>>), QemuLiveBlockHostWorkPoolError> {
        let shared_device = servicer.shared_device();
        let servicer = Arc::new(Mutex::new(servicer));
        let worker_servicer = Arc::clone(&servicer);
        let (commands, command_rx) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
        let (reply_tx, replies) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(String::from("crucible-block-host-work"))
            .spawn(move || {
                let _ = ready_tx.send(());
                worker_loop(worker_servicer, &command_rx, &reply_tx);
            })
            .map_err(|source| QemuLiveBlockHostWorkPoolError::SpawnWorker { source })?;
        ready_rx
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        Ok((
            Self {
                commands,
                replies,
                worker: Some(worker),
                work_in_flight: false,
                pinned: None,
                in_flight_pin: None,
                published_deadline: None,
                in_flight_storage_fault: false,
                storage_device: None,
                shared_device,
            },
            servicer,
        ))
    }

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
                        let shared_device = servicer.shared_device();
                        let _ = ready_tx.send(Ok(shared_device));
                        worker_loop(Arc::new(Mutex::new(servicer)), &command_rx, &reply_tx);
                    }
                    Err(source) => {
                        let _ = ready_tx.send(Err(source));
                    }
                }
            })
            .map_err(|source| QemuLiveBlockHostWorkPoolError::SpawnWorker { source })?;
        match ready_rx.recv() {
            Ok(Ok(shared_device)) => Ok(Self {
                commands,
                replies,
                worker: Some(worker),
                work_in_flight: false,
                pinned: None,
                in_flight_pin: None,
                published_deadline: None,
                in_flight_storage_fault: false,
                storage_device,
                shared_device,
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
                        let shared_device = servicer.shared_device();
                        let _ = ready_tx.send(Ok(shared_device));
                        worker_loop(Arc::new(Mutex::new(servicer)), &command_rx, &reply_tx);
                    }
                    Err(source) => {
                        let _ = ready_tx.send(Err(source));
                    }
                }
            })
            .map_err(|source| QemuLiveBlockHostWorkPoolError::SpawnWorker { source })?;
        match ready_rx.recv() {
            Ok(Ok(shared_device)) => Ok(Self {
                commands,
                replies,
                worker: Some(worker),
                work_in_flight: false,
                pinned: None,
                in_flight_pin: None,
                published_deadline: None,
                in_flight_storage_fault: false,
                storage_device,
                shared_device,
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
                self.published_deadline = pin.next_completion_icount;
                self.pinned = Some(pin.clone());
                Ok(pin)
            }
            WorkerReply::Serviced(_)
            | WorkerReply::Checkpoint(_)
            | WorkerReply::Mutated(_)
            | WorkerReply::StorageState(_)
            | WorkerReply::Coordinated(_)
            | WorkerReply::Coordination(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
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
    fn dispatch_with_storage_fault(
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
                directive: Box::new(directive),
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
                        self.published_deadline = serviced.next_completion_icount;
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
            Ok(WorkerReply::Coordinated(result)) => {
                self.work_in_flight = false;
                self.in_flight_pin = None;
                result
                    .map(|serviced| {
                        self.published_deadline = serviced.next_completion_icount;
                        Some(serviced)
                    })
                    .map_err(|source| QemuLiveBlockHostWorkPoolError::Coordinator { source })
            }
            Ok(WorkerReply::Pinned(_))
            | Ok(WorkerReply::Checkpoint(_))
            | Ok(WorkerReply::Mutated(_))
            | Ok(WorkerReply::StorageState(_))
            | Ok(WorkerReply::Coordination(_)) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
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

    /// Installs the production fault coordinator on the worker that owns the device.
    ///
    /// # Errors
    ///
    /// Returns an error when work is active, a coordinator is already installed,
    /// or the worker disconnects.
    pub(crate) fn install_fault_coordinator(
        &mut self,
        coordinator: Box<dyn QemuBlockFaultCoordinator>,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        self.commands
            .send(WorkerCommand::InstallCoordinator(coordinator))
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        match self
            .replies
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?
        {
            WorkerReply::Coordination(result) => {
                result.map_err(|source| QemuLiveBlockHostWorkPoolError::Coordinator { source })
            }
            _ => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "coordinator installation reply",
            }),
        }
    }

    /// Dispatches one complete coordinator-owned service pass without waiting.
    ///
    /// # Errors
    ///
    /// Returns an error when another pass is active or the worker disconnects.
    pub(crate) fn dispatch_coordinated(
        &mut self,
        guest_icount: u64,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        let pin = self
            .pinned
            .take()
            .ok_or(QemuLiveBlockHostWorkPoolError::DispatchWithoutPin)?;
        self.commands
            .send(WorkerCommand::CoordinatedService { guest_icount })
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        self.work_in_flight = true;
        self.in_flight_pin = Some(pin);
        Ok(())
    }

    /// Returns the exact deadline published before the active worker pass.
    ///
    /// The value is cached from the synchronous pin and the most recently
    /// completed service pass, so reading it never waits for host device work.
    #[must_use]
    pub const fn published_completion_deadline(&self) -> Option<u64> {
        self.published_deadline
    }

    /// Applies exact boundary actions on the worker-owned device and coordinator.
    ///
    /// # Errors
    ///
    /// Returns an error when work is active, no coordinator is installed, or
    /// either participant rejects the action.
    pub fn apply_boundary_actions(
        &mut self,
        coordinate: crucible::model::FaultCoordinate,
        evaluation_sequence: u64,
        actions: Vec<crucible::model::ResolvedBindingAction>,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        self.commands
            .send(WorkerCommand::ApplyBoundaryActions {
                coordinate,
                evaluation_sequence,
                actions,
            })
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?;
        match self
            .replies
            .recv()
            .map_err(|_| QemuLiveBlockHostWorkPoolError::WorkerDisconnected)?
        {
            WorkerReply::Coordination(result) => {
                result.map_err(|source| QemuLiveBlockHostWorkPoolError::Coordinator { source })
            }
            _ => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "boundary action reply",
            }),
        }
    }

    /// Returns a clone of the authoritative shared block-device handle.
    #[must_use]
    pub fn shared_device(&self) -> crate::QemuSharedBlockDevice {
        self.shared_device.clone()
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
            | WorkerReply::Coordinated(_)
            | WorkerReply::Coordination(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
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
            | WorkerReply::Coordinated(_)
            | WorkerReply::Coordination(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "storage-state reply",
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
        self.mutate(StorageMutation::InstallExecution(Box::new(directive)))
    }

    /// Drops exact controller-buffer entries on the worker-owned live device.
    ///
    /// # Errors
    ///
    /// Returns an error when no storage device is bound, worker state forbids
    /// mutation, the worker disconnects, the reply violates the protocol, or
    /// the live device rejects the mutation.
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
    /// Returns an error when no storage device is bound, worker state forbids
    /// mutation, the worker disconnects, the reply violates the protocol, or
    /// the request is not retained or its response cannot be scheduled.
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
            .send(WorkerCommand::Mutate(Box::new(mutation)))
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
            | WorkerReply::Coordinated(_)
            | WorkerReply::Coordination(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
                expected: "storage mutation reply",
            }),
        }
    }

    fn require_storage_device_bound(&self) -> Result<ContentHash, QemuLiveBlockHostWorkPoolError> {
        self.storage_device
            .ok_or(QemuLiveBlockHostWorkPoolError::StorageDeviceUnbound)
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

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsFd;
    use std::time::Duration;

    use crucible_device::block::BlockRequest;
    use crucible_shmem::{FrameEntry, RegionAllocation, RegionConfig, SLOT_BLK_IO};

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

    fn region_with_request(
        request: &BlockRequest,
    ) -> Result<(File, u64), Box<dyn std::error::Error>> {
        let mut allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))?;
        let frame = FrameEntry::new(10, 0, 0, &request.encode()?)?;
        allocation.enqueue_directed_frame(0, SLOT_BLK_IO as u32, &frame)?;
        let layout = allocation.layout();
        let bytes = allocation.setup_region_bytes()?;
        let mut region = tempfile::tempfile()?;
        region.set_len(layout.region_size)?;
        region.write_all(&bytes)?;

        Ok((region, layout.region_size))
    }

    fn worker_with_request(
        request: &BlockRequest,
    ) -> Result<(QemuLiveBlockHostWorkPool, File), Box<dyn std::error::Error>> {
        let (region, region_size) = region_with_request(request)?;
        let worker =
            QemuLiveBlockHostWorkPool::from_shmem_fd(region.as_fd(), region_size, 0, 0, 4096)?;
        Ok((worker, region))
    }

    fn servicer_with_request(
        request: &BlockRequest,
    ) -> Result<(QemuLiveBlockIoServicer, File), Box<dyn std::error::Error>> {
        let (region, region_size) = region_with_request(request)?;
        let servicer =
            QemuLiveBlockIoServicer::from_shmem_fd(region.as_fd(), region_size, 0, 0, 4096)?;
        Ok((servicer, region))
    }

    fn wait_for_completion(
        worker: &mut QemuLiveBlockHostWorkPool,
    ) -> Result<QemuLiveBlockIoServiceStep, Box<dyn std::error::Error>> {
        for _ in 0..2_000 {
            if let Some(step) = worker.try_complete()? {
                return Ok(step);
            }
            thread::sleep(Duration::from_millis(1));
        }
        Err("block host worker did not complete within the test bound".into())
    }

    fn complete_worker_request(
        worker: &mut QemuLiveBlockHostWorkPool,
        delay: QemuDeviceHostWorkDelay,
        completion_icount: u64,
    ) -> Result<[QemuLiveBlockIoServiceStep; 2], Box<dyn std::error::Error>> {
        worker.dispatch(10, delay)?;
        let compute = wait_for_completion(worker)?;

        let delivery_pin = worker.pin_next_request_completion()?;
        assert!(delivery_pin.observed.is_none());
        assert_eq!(delivery_pin.next_completion_icount, Some(completion_icount));
        worker.dispatch(completion_icount, QemuDeviceHostWorkDelay::None)?;
        let delivery = wait_for_completion(worker)?;
        Ok([compute, delivery])
    }

    fn complete_region_bytes(region: &mut File) -> Result<Vec<u8>, std::io::Error> {
        let mut bytes = Vec::new();
        region.seek(SeekFrom::Start(0))?;
        region.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    #[test]
    fn synchronous_host_wins_and_guest_wins_preserve_completion_and_canonical_log()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = BlockRequest::read(7, 512, 512);
        let execution_binding = ContentHash::from_bytes(b"device-host-work-overlap");

        let (mut synchronous, mut synchronous_region) = servicer_with_request(&request)?;
        let synchronous_compute = synchronous.service(10)?;
        let completion_icount = synchronous_compute
            .computed_completion_icount
            .ok_or("synchronous service did not compute a completion coordinate")?;
        let synchronous_log = [synchronous_compute, synchronous.service(completion_icount)?];
        let synchronous_checkpoint = synchronous.checkpoint(execution_binding)?;
        let synchronous_bytes = complete_region_bytes(&mut synchronous_region)?;

        let (mut host_wins, mut host_wins_region) = worker_with_request(&request)?;
        let host_pin = host_wins.pin_next_request_completion()?;
        assert_eq!(host_pin.next_completion_icount, Some(completion_icount));
        let host_wins_log = complete_worker_request(
            &mut host_wins,
            QemuDeviceHostWorkDelay::None,
            completion_icount,
        )?;
        let host_wins_checkpoint = host_wins.checkpoint(execution_binding)?;
        let host_wins_bytes = complete_region_bytes(&mut host_wins_region)?;

        let (mut guest_wins, mut guest_wins_region) = worker_with_request(&request)?;
        let guest_pin = guest_wins.pin_next_request_completion()?;
        let guest_observed_horizon = guest_wins.published_completion_deadline();
        assert_eq!(guest_pin, host_pin);
        assert_eq!(guest_observed_horizon, guest_pin.next_completion_icount);
        let guest_wins_log = complete_worker_request(
            &mut guest_wins,
            QemuDeviceHostWorkDelay::Wall(Duration::from_millis(100)),
            completion_icount,
        )?;
        assert_eq!(guest_wins.published_completion_deadline(), None);
        let guest_wins_checkpoint = guest_wins.checkpoint(execution_binding)?;
        let guest_wins_bytes = complete_region_bytes(&mut guest_wins_region)?;

        assert_eq!(host_wins_log, synchronous_log);
        assert_eq!(guest_wins_log, synchronous_log);
        assert_eq!(host_wins_checkpoint, synchronous_checkpoint);
        assert_eq!(guest_wins_checkpoint, synchronous_checkpoint);
        assert_eq!(host_wins_bytes, synchronous_bytes);
        assert_eq!(guest_wins_bytes, synchronous_bytes);
        Ok(())
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
