//! Owner-worker command protocol for live block host work.

use super::*;
use thiserror::Error;

pub(super) enum WorkerCommand {
    Pin,
    Checkpoint {
        execution_binding: ContentHash,
    },
    Service {
        guest_icount: u64,
        delay: QemuDeviceHostWorkDelay,
        directive: Box<Option<(BlockRequestIdentity, ResolvedBlockFaultDirective)>>,
    },
    CoordinatedService {
        guest_icount: u64,
    },
    InstallCoordinator(Box<dyn QemuBlockFaultCoordinator>),
    ApplyBoundaryActions {
        coordinate: crucible::model::FaultCoordinate,
        evaluation_sequence: u64,
        actions: Vec<crucible::model::ResolvedBindingAction>,
    },
    Mutate(Box<StorageMutation>),
    InspectStorageState,
    Shutdown,
}

pub(super) enum StorageMutation {
    LoseController(Vec<u64>),
    InstallPersistenceMedia(ResolvedBlockPersistenceMediaDirective),
    InstallExecution(Box<ResolvedBlockExecutionDirective>),
    ReleaseCompletion {
        identity: BlockRequestIdentity,
        release: BlockRetainedRelease,
    },
}

pub(super) enum WorkerReply {
    Pinned(Result<QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoServicerError>),
    Serviced(Result<QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicerError>),
    Checkpoint(Box<Result<QemuLiveBlockIoServicerCheckpoint, QemuLiveBlockIoServicerError>>),
    Mutated(Result<(), QemuLiveBlockIoServicerError>),
    StorageState(Box<Result<BlockFaultState, QemuLiveBlockIoServicerError>>),
    Coordinated(Result<QemuLiveBlockIoServiceStep, QemuAsyncDriverRuntimeError>),
    Coordination(Result<(), QemuAsyncDriverRuntimeError>),
}

pub(super) fn worker_loop(
    servicer: Arc<Mutex<QemuLiveBlockIoServicer>>,
    commands: &Receiver<WorkerCommand>,
    replies: &SyncSender<WorkerReply>,
) {
    let mut coordinator: Option<Box<dyn QemuBlockFaultCoordinator>> = None;
    while let Ok(command) = commands.recv() {
        let mut servicer = match servicer.lock() {
            Ok(servicer) => servicer,
            Err(poisoned) => poisoned.into_inner(),
        };
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
                let result = (*directive)
                    .map_or(Ok(()), |(request_id, directive)| {
                        servicer.install_storage_fault_directive(request_id, directive)
                    })
                    .and_then(|()| servicer.service(guest_icount));
                WorkerReply::Serviced(result)
            }
            WorkerCommand::CoordinatedService { guest_icount } => {
                WorkerReply::Coordinated(coordinator.as_mut().map_or_else(
                    || {
                        Err(QemuAsyncDriverRuntimeError::new(
                            "service block host work",
                            "block host worker has no fault coordinator",
                        ))
                    },
                    |coordinator| coordinator.service_block_io(&mut servicer, guest_icount),
                ))
            }
            WorkerCommand::InstallCoordinator(installed) => {
                WorkerReply::Coordination(if coordinator.is_some() {
                    Err(QemuAsyncDriverRuntimeError::new(
                        "install block host-work coordinator",
                        "block host worker already has a fault coordinator",
                    ))
                } else {
                    coordinator = Some(installed);
                    Ok(())
                })
            }
            WorkerCommand::ApplyBoundaryActions {
                coordinate,
                evaluation_sequence,
                actions,
            } => WorkerReply::Coordination(match coordinator.as_mut() {
                Some(coordinator) => coordinator.apply_boundary_actions(
                    &mut servicer,
                    coordinate,
                    evaluation_sequence,
                    &actions,
                ),
                None => Err(QemuAsyncDriverRuntimeError::new(
                    "apply block host-work boundary actions",
                    "block host worker has no fault coordinator",
                )),
            }),
            WorkerCommand::Mutate(mutation) => WorkerReply::Mutated(match *mutation {
                StorageMutation::LoseController(sequences) => {
                    servicer.lose_storage_controller(&sequences)
                }
                StorageMutation::InstallPersistenceMedia(directive) => {
                    servicer.install_storage_persistence_media_directive(directive)
                }
                StorageMutation::InstallExecution(directive) => {
                    servicer.install_storage_execution_directive(*directive)
                }
                StorageMutation::ReleaseCompletion { identity, release } => servicer
                    .release_storage_completion(identity, release)
                    .map(|_| ()),
            }),
            WorkerCommand::InspectStorageState => {
                WorkerReply::StorageState(Box::new(servicer.storage_fault_state()))
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
    /// The worker-owned production fault coordinator rejected an operation.
    #[error("block host worker coordinator failed: {source}")]
    Coordinator {
        /// Exact coordinator failure.
        source: QemuAsyncDriverRuntimeError,
    },
    /// The worker was not constructed with an exact live storage-device identity.
    #[error("signal-driven storage mutation requires a device-bound worker")]
    StorageDeviceUnbound,
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
