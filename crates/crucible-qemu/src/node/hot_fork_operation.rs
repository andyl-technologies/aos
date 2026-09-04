//! Linear node ownership for one retained-template hot fork.
//!
//! QMP command rejection is safe only before `fork(2)`. Once command delivery
//! becomes ambiguous, or QEMU reports a parent-disposition failure after
//! creating the child, the source node retains every staged descriptor and is
//! quarantined as one process authority. A successful transaction alone moves
//! the branch-private child QMP endpoint into the returned launch token.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use thiserror::Error;

use super::*;

/// Exact QMP command failure classification across the process-creation boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuHotForkCommandError {
    /// QEMU explicitly rejected the complete basis before creating a child.
    #[error("QEMU rejected the retained-template fork before process creation: {source}")]
    Rejected {
        /// Exact typed channel failure.
        source: QemuNodeChannelError,
    },
    /// The exchange failed after child creation may have occurred.
    #[error("retained-template fork outcome is indeterminate: {source}")]
    Indeterminate {
        /// Exact typed channel failure.
        source: QemuNodeChannelError,
    },
}

/// Exact process-generation basis that a hot-fork child owner must retain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildProcessBasis {
    source_process_id: u32,
    child_process_id: u32,
    request: crate::QmpHotForkRequest,
}

impl QemuHotForkChildProcessBasis {
    /// Returns the source template process identifier.
    #[must_use]
    pub const fn source_process_id(self) -> u32 {
        self.source_process_id
    }

    /// Returns the positive child process identifier reported by QEMU.
    #[must_use]
    pub const fn child_process_id(self) -> u32 {
        self.child_process_id
    }

    /// Returns the exact generation request echoed by the source parent.
    #[must_use]
    pub const fn request(self) -> crate::QmpHotForkRequest {
        self.request
    }
}

/// Process owner that authenticates and retains one successful hot-fork child.
pub trait QemuHotForkChildProcessOwner {
    /// Nonduplicable authority retained in the successful launch token.
    type Authority;

    /// Authenticates and retains the exact child process generation.
    ///
    /// Implementations must validate the child against their attempt-owned
    /// process namespace and preserve kill/reap authority on every error.
    /// Returning success transfers one nonduplicable authority into the launch
    /// token; returning an error must not leave an unowned child.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the reported child cannot be bound
    /// to the exact source attempt or retained for terminal cleanup.
    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError>;
}

/// Linear branch-private host continuation paired with one hot-fork child.
///
/// The continuation owns the host halves of the replacement plugin control and
/// wake endpoints, a descriptor for the exact private ring mapping, and a clone
/// of every scheduler-owned shared-memory cursor and pending value. It retains
/// the same scheduler-owned send-authorization capability so topology changes remain
/// globally authoritative. The source node retains its independent template
/// continuation. Host-device continuation cloning remains a separate operation
/// because writable block and filesystem roots require fresh branch-local
/// backing rather than descriptor duplication.
#[must_use = "the child host continuation must remain owned through child teardown"]
pub struct QemuHotForkPluginHostContinuation {
    endpoint: QemuHotForkPluginHostEndpoint,
    ring_descriptor: OwnedFd,
    ring: QemuHotForkPrivateRingStageProof,
    endpoint_stage: QemuHotForkPluginEndpointStageProof,
    shmem_hot_path: Box<dyn QemuShmemHotPathChannel>,
}

impl std::fmt::Debug for QemuHotForkPluginHostContinuation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkPluginHostContinuation")
            .field("endpoint", &self.endpoint)
            .field("ring", &self.ring)
            .field("endpoint_stage", &self.endpoint_stage)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkPluginHostContinuation {
    /// Returns the exact source template generation paired with this continuation.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.endpoint.template_generation()
    }

    /// Returns the exact child-private ring generation.
    #[must_use]
    pub const fn private_ring_generation(&self) -> u64 {
        self.endpoint.private_ring_generation()
    }

    /// Returns the authenticated private setup-region identity.
    #[must_use]
    pub fn ring_identity(&self) -> crucible_shmem::SetupRegionBackingIdentity {
        self.ring.backing_identity()
    }

    /// Borrows the descriptor retained for branch-local host-I/O reconstruction.
    #[must_use]
    pub fn shmem_as_fd(&self) -> BorrowedFd<'_> {
        self.ring_descriptor.as_fd()
    }

    /// Borrows the private plugin wake eventfd.
    #[must_use]
    pub fn wake_as_fd(&self) -> BorrowedFd<'_> {
        self.endpoint.wake_as_fd()
    }

    /// Borrows the private plugin control channel.
    #[must_use]
    pub fn plugin_control_mut(&mut self) -> &mut dyn QemuPluginIpcControlChannel {
        &mut self.endpoint
    }

    /// Borrows the cloned scheduler-side shared-memory continuation.
    #[must_use]
    pub fn shmem_hot_path_mut(&mut self) -> &mut dyn QemuShmemHotPathChannel {
        self.shmem_hot_path.as_mut()
    }
}

/// Linear successful parent result, process authority, and private child endpoint.
#[derive(Debug)]
#[must_use = "the forked child endpoint must be authenticated or transferred to quarantine"]
pub struct QemuHotForkChildLaunch<A> {
    parent_state: crate::QmpHotForkState,
    child_process_id: u32,
    process_authority: A,
    child_qmp: QemuHotForkChildQmpHostEndpoint,
    host_continuation: QemuHotForkPluginHostContinuation,
}

impl<A> QemuHotForkChildLaunch<A> {
    /// Returns the exact parent-process result and request echo.
    #[must_use]
    pub const fn parent_state(&self) -> crate::QmpHotForkState {
        self.parent_state
    }

    /// Returns the positive child process identifier reported by the parent.
    #[must_use]
    pub const fn child_process_id(&self) -> u32 {
        self.child_process_id
    }

    /// Returns the retained child process authority.
    #[must_use]
    pub const fn process_authority(&self) -> &A {
        &self.process_authority
    }

    /// Returns the retained child-QMP endpoint basis without consuming it.
    #[must_use]
    pub const fn child_qmp(&self) -> &QemuHotForkChildQmpHostEndpoint {
        &self.child_qmp
    }

    /// Returns the exact branch-private host continuation.
    pub const fn host_continuation(&self) -> &QemuHotForkPluginHostContinuation {
        &self.host_continuation
    }

    /// Separates the exact parent result from the linear private child endpoint.
    pub fn into_parts(
        self,
    ) -> (
        crate::QmpHotForkState,
        A,
        QemuHotForkChildQmpHostEndpoint,
        QemuHotForkPluginHostContinuation,
    ) {
        (
            self.parent_state,
            self.process_authority,
            self.child_qmp,
            self.host_continuation,
        )
    }
}

/// Failure to transfer one exact retained-template fork into child ownership.
#[derive(Debug, Error)]
pub enum QemuHotForkLaunchError {
    /// A local invariant or explicit QMP rejection proved that no child exists.
    #[error("retained-template fork was rejected before process creation: {source}")]
    Rejected {
        /// Exact local or QMP failure.
        source: QemuNodeChannelError,
    },
    /// Command completion is ambiguous and the complete source node is quarantined.
    #[error("retained-template fork outcome is indeterminate: {source}")]
    Indeterminate {
        /// Exact QMP exchange failure.
        source: QemuNodeChannelError,
    },
    /// QEMU created a child but could not restore the parent transaction.
    #[error(
        "retained-template fork created child {child_pid}, but parent disposition failed with {parent_status}"
    )]
    ParentDispositionFailed {
        /// Positive child PID retained in the authenticated parent response.
        child_pid: i64,
        /// Negative parent disposition status.
        parent_status: i64,
    },
    /// QEMU created a child but the host endpoint could not move into its launch token.
    #[error("forked child endpoint transfer failed: {source}")]
    EndpointTransfer {
        /// Exact authenticated parent response.
        parent_state: Box<crate::QmpHotForkState>,
        /// Endpoint ownership failure.
        source: QemuNodeChannelError,
    },
    /// The child endpoint was retained but its process generation was not.
    #[error("forked child process retention failed: {source}")]
    ProcessRetention {
        /// Exact authenticated parent response.
        parent_state: Box<crate::QmpHotForkState>,
        /// Process-owner authentication or retention failure.
        source: QemuNodeChannelError,
    },
}

impl QemuNode {
    /// Queries the source QEMU's exact parent-owned process record.
    ///
    /// This remains available for a quarantined source after an indeterminate
    /// fork exchange so a recovery owner can discover whether the requested
    /// generation produced a child and whether QEMU has reaped it.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the generation is unknown, the
    /// parent channel is unavailable, or the response violates the exact
    /// retained-state contract.
    pub fn query_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, QemuNodeChannelError> {
        self.channels
            .qmp_machine_control
            .query_hot_fork_child_process(generation)
    }

    /// Releases the source QEMU's exact process record after child reap.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] while the child is running, when the
    /// generation is unknown, when the parent channel is unavailable, or when
    /// the response violates the exact released-state contract.
    pub fn release_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, QemuNodeChannelError> {
        self.channels
            .qmp_machine_control
            .release_hot_fork_child_process(generation)
    }

    /// Forks a prepared template and transfers its private child-QMP endpoint.
    ///
    /// The caller supplies the request derived from the exact prepared template
    /// and sealed child-QMP reports. QEMU revalidates all request generations on
    /// its source main loop. An explicit pre-fork rejection leaves this node and
    /// its endpoint reusable. Every post-fork or ambiguous failure quarantines
    /// this node with all staged ownership still retained. A successful result
    /// moves the endpoint exactly once into [`QemuHotForkChildLaunch`].
    ///
    /// The returned positive PID is not by itself process ownership. Before
    /// connecting the endpoint or admitting guest work, the daemon must bind
    /// that exact process generation to its attempt-owned cgroup and reap
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkLaunchError::Rejected`] when no child was created.
    /// All other variants leave this node quarantined because a child exists or
    /// may exist.
    pub fn fork_hot_fork_template<O>(
        &mut self,
        request: crate::QmpHotForkRequest,
        process_owner: &mut O,
    ) -> Result<QemuHotForkChildLaunch<O::Authority>, QemuHotForkLaunchError>
    where
        O: QemuHotForkChildProcessOwner,
    {
        if self.lifecycle_state != QemuNodeLifecycleState::Running {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "hot fork requires a running source node",
                ),
            });
        }
        let stage =
            self.hot_fork_child_qmp_stage()
                .ok_or_else(|| QemuHotForkLaunchError::Rejected {
                    source: QemuNodeChannelError::new(
                        "fork retained hot-fork template",
                        "source node retains no child QMP stage",
                    ),
                })?;
        if stage.state() != QemuHotForkChildQmpStageState::Installed || !stage.resource_plan_bound()
        {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "child QMP endpoint is not installed in a sealed resource plan",
                ),
            });
        }
        let process_contract = self
            .hot_fork_child_process_contract_stage()
            .ok_or_else(|| QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "source node retains no target child process contract",
                ),
            })?;
        if process_contract.consumed()
            || process_contract.generation() != request.child_process_contract_generation()
            || process_contract.template_generation() != request.template_generation()
        {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "target child process contract does not match the fork request",
                ),
            });
        }

        let ring =
            self.hot_fork_private_ring_stage()
                .ok_or_else(|| QemuHotForkLaunchError::Rejected {
                    source: QemuNodeChannelError::new(
                        "fork retained hot-fork template",
                        "source node retains no private-ring stage",
                    ),
                })?;
        let endpoint_stage = self.hot_fork_plugin_endpoint_stage().ok_or_else(|| {
            QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "source node retains no plugin host-endpoint stage",
                ),
            }
        })?;
        if ring.state() != QemuHotForkPrivateRingStageState::Installed
            || endpoint_stage.state() != QemuHotForkPluginEndpointStageState::Installed
            || endpoint_stage.template_generation() != request.template_generation()
            || endpoint_stage.private_ring_generation() != request.private_ring_generation()
        {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "plugin host continuation does not match the exact fork request",
                ),
            });
        }
        if !self
            .hot_fork_plugin_endpoint_stage
            .as_ref()
            .is_some_and(QemuHotForkPluginEndpointStage::host_endpoint_available)
        {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "branch-private plugin host endpoint was already transferred",
                ),
            });
        }
        let mapping = match self.hot_fork_private_ring_stage.as_ref() {
            Some(QemuHotForkPrivateRingStage::Installed(mapping)) => mapping,
            Some(QemuHotForkPrivateRingStage::TransferUncertain(_)) | None => {
                return Err(QemuHotForkLaunchError::Rejected {
                    source: QemuNodeChannelError::new(
                        "fork retained hot-fork template",
                        "private-ring ownership is not installed exactly",
                    ),
                });
            }
        };
        let ring_descriptor = mapping
            .clone_descriptor()
            .map_err(|source| QemuHotForkLaunchError::Rejected { source })?;
        let shmem_hot_path = self
            .channels
            .shmem_hot_path
            .clone_hot_fork_host_continuation(mapping)
            .map_err(|source| QemuHotForkLaunchError::Rejected { source })?;

        let parent_state = match self.channels.qmp_machine_control.hot_fork(request) {
            Ok(state) => state,
            Err(QemuHotForkCommandError::Rejected { source }) => {
                return Err(QemuHotForkLaunchError::Rejected { source });
            }
            Err(QemuHotForkCommandError::Indeterminate { source }) => {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                return Err(QemuHotForkLaunchError::Indeterminate { source });
            }
        };
        if let Some(process_contract) = self.hot_fork_child_process_contract_stage.as_mut() {
            process_contract.mark_consumed();
        }
        if parent_state.outcome() == crate::QmpHotForkOutcome::ParentDispositionFailed {
            self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
            return Err(QemuHotForkLaunchError::ParentDispositionFailed {
                child_pid: parent_state.child_pid(),
                parent_status: parent_state.parent_status(),
            });
        }

        let host_endpoint = self
            .hot_fork_plugin_endpoint_stage
            .as_mut()
            .ok_or_else(|| QemuHotForkLaunchError::EndpointTransfer {
                parent_state: Box::new(parent_state),
                source: QemuNodeChannelError::new(
                    "take hot-fork plugin host endpoint",
                    "plugin endpoint stage disappeared after child creation",
                ),
            })?
            .take_host_endpoint()
            .map_err(|source| {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                QemuHotForkLaunchError::EndpointTransfer {
                    parent_state: Box::new(parent_state),
                    source,
                }
            })?;
        let child_qmp = self
            .take_hot_fork_child_qmp_host_endpoint()
            .map_err(|source| {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                QemuHotForkLaunchError::EndpointTransfer {
                    parent_state: Box::new(parent_state),
                    source,
                }
            })?;
        let child_process_id = u32::try_from(parent_state.child_pid()).map_err(|_source| {
            self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
            QemuHotForkLaunchError::ProcessRetention {
                parent_state: Box::new(parent_state),
                source: QemuNodeChannelError::new(
                    "retain forked child process",
                    "QEMU returned a child process identifier outside the Linux PID range",
                ),
            }
        })?;
        let basis = QemuHotForkChildProcessBasis {
            source_process_id: self.process_id(),
            child_process_id,
            request: parent_state.request(),
        };
        let process_authority = process_owner
            .retain_hot_fork_child(basis)
            .map_err(|source| {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                QemuHotForkLaunchError::ProcessRetention {
                    parent_state: Box::new(parent_state),
                    source,
                }
            })?;
        let host_continuation = QemuHotForkPluginHostContinuation {
            endpoint: host_endpoint,
            ring_descriptor,
            ring,
            endpoint_stage,
            shmem_hot_path,
        };
        Ok(QemuHotForkChildLaunch {
            parent_state,
            child_process_id,
            process_authority,
            child_qmp,
            host_continuation,
        })
    }
}
