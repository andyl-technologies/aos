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

use crucible_device::block::ResolvedBlockFaultDirective;

use super::block_io_servicer::{
    QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer,
    QemuLiveBlockIoServicerError,
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
            WorkerReply::Serviced(_) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
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
        directive: Option<(u32, ResolvedBlockFaultDirective)>,
    ) -> Result<(), QemuLiveBlockHostWorkPoolError> {
        if self.work_in_flight {
            return Err(QemuLiveBlockHostWorkPoolError::WorkAlreadyInFlight);
        }
        let pin = self
            .pinned
            .as_ref()
            .ok_or(QemuLiveBlockHostWorkPoolError::DispatchWithoutPin)?;
        validate_pinned_directive(pin, directive.as_ref())?;
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
                result
                    .map(|mut serviced| {
                        if let Some(observed) = pin.and_then(|pinned| pinned.observed) {
                            serviced.first_request_icount = Some(observed.request_icount);
                            serviced.computed_completion_icount = Some(observed.completion_icount);
                        }
                        Some(serviced)
                    })
                    .map_err(|source| QemuLiveBlockHostWorkPoolError::Servicer { source })
            }
            Ok(WorkerReply::Pinned(_)) => Err(QemuLiveBlockHostWorkPoolError::Protocol {
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
}

fn validate_pinned_directive(
    pin: &QemuLiveBlockIoHostWorkPin,
    directive: Option<&(u32, ResolvedBlockFaultDirective)>,
) -> Result<(), QemuLiveBlockHostWorkPoolError> {
    let Some((request_id, directive)) = directive else {
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
    if request.request_id != *request_id
        || directive.operation != request.op
        || directive.offset != request.offset
        || directive.count != request.count
        || directive.request_digest != observed.wire_digest
    {
        return Err(QemuLiveBlockHostWorkPoolError::DirectivePinMismatch {
            pinned_request_id: request.request_id,
            directive_request_id: *request_id,
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
    Service {
        guest_icount: u64,
        delay: QemuDeviceHostWorkDelay,
        directive: Option<(u32, ResolvedBlockFaultDirective)>,
    },
    Shutdown,
}

enum WorkerReply {
    Pinned(Result<QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoServicerError>),
    Serviced(Result<QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicerError>),
}

fn worker_loop(
    mut servicer: QemuLiveBlockIoServicer,
    commands: &Receiver<WorkerCommand>,
    replies: &SyncSender<WorkerReply>,
) {
    while let Ok(command) = commands.recv() {
        let reply = match command {
            WorkerCommand::Pin => WorkerReply::Pinned(servicer.pin_next_request_completion()),
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
    /// The worker channel closed unexpectedly.
    #[error("block host worker disconnected")]
    WorkerDisconnected,
    /// A second command was attempted while work was already running.
    #[error("block host work is already in flight")]
    WorkAlreadyInFlight,
    /// COMPUTE was dispatched without first pinning the request coordinate.
    #[error("block host work dispatch requires a preceding completion pin")]
    DispatchWithoutPin,
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
        validate_pinned_directive(&pin(request), Some(&(7, directive)))
            .unwrap_or_else(|error| panic!("exact directive should match: {error}"));
    }

    #[test]
    fn mismatched_directive_is_rejected_before_dispatch() {
        let request = BlockRequest::read(7, 512, 512);
        let other = BlockRequest::read(8, 512, 512);
        let directive = ResolvedBlockFaultDirective::fault_free(&other, 4096);
        let error = validate_pinned_directive(&pin(request), Some(&(8, directive)))
            .expect_err("request alias must fail closed");
        assert!(matches!(
            error,
            QemuLiveBlockHostWorkPoolError::DirectivePinMismatch {
                pinned_request_id: 7,
                directive_request_id: 8,
            }
        ));
    }
}
