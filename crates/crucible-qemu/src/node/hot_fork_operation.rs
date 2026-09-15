//! Linear node ownership for one retained-template hot fork.
//!
//! QMP command rejection is safe only before `fork(2)`. Once command delivery
//! becomes ambiguous, or QEMU reports a parent-disposition failure after
//! creating the child, the source node retains every staged descriptor and is
//! quarantined as one process authority. A successful transaction alone moves
//! the branch-private child QMP endpoint and sole diagnostics reader into the
//! returned launch token.

use std::os::fd::OwnedFd;
use thiserror::Error;

use super::*;
use crate::console_observation::QemuConsoleObservationSpool;

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
/// of every scheduler-owned shared-memory cursor and pending value. It also owns
/// the reconstructed host block, 9p, and accelerator continuation over that
/// private ring. It retains the same scheduler-owned send-authorization
/// capability so topology changes remain globally authoritative. The source
/// node retains its independent template continuation.
#[must_use = "the child host continuation must remain owned through child teardown"]
pub struct QemuHotForkHostContinuation {
    pub(super) request: crate::QmpHotForkRequest,
    pub(super) endpoint: QemuHotForkPluginHostEndpoint,
    pub(super) ring_descriptor: OwnedFd,
    pub(super) ring: QemuHotForkPrivateRingStageProof,
    pub(super) endpoint_stage: QemuHotForkPluginEndpointStageProof,
    pub(super) shmem_hot_path: Box<dyn QemuShmemHotPathChannel>,
    pub(super) host_io_binding: crucible::model::ContentHash,
    pub(super) host_io_runtime: Box<dyn QemuHostIoRuntime>,
    pub(super) console_spool: Option<QemuConsoleObservationSpool>,
    pub(super) node_state: QemuHotForkNodeStateContinuation,
    pub(super) checkpoint_cancellation: OwnedFd,
}

impl std::fmt::Debug for QemuHotForkHostContinuation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkHostContinuation")
            .field("endpoint", &self.endpoint)
            .field("ring", &self.ring)
            .field("endpoint_stage", &self.endpoint_stage)
            .field("host_io_binding", &self.host_io_binding)
            .finish_non_exhaustive()
    }
}

/// Linear successful parent result, process authority, and private child channels.
#[derive(Debug)]
#[must_use = "the forked child authorities must be reconciled or transferred to quarantine"]
pub struct QemuHotForkChildLaunch<A> {
    parent_state: crate::QmpHotForkState,
    child_process_id: u32,
    pub(super) process_authority: A,
    pub(super) child_qmp: QemuHotForkChildQmpHostEndpoint,
    diagnostics: QemuHotForkChildDiagnosticConsumer,
    pub(super) host_continuation: QemuHotForkHostContinuation,
    child_files: Vec<crate::QmpHotForkChildFile>,
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

    /// Returns the exact root selectors and destination inode identities
    /// consumed by this successful fork.
    #[must_use]
    pub fn child_files(&self) -> &[crate::QmpHotForkChildFile] {
        &self.child_files
    }

    /// Returns the exact branch-private diagnostics consumer.
    pub const fn diagnostics(&self) -> &QemuHotForkChildDiagnosticConsumer {
        &self.diagnostics
    }

    pub(super) fn diagnostics_mut(&mut self) -> &mut QemuHotForkChildDiagnosticConsumer {
        &mut self.diagnostics
    }

    /// Separates the exact parent result from all linear child authorities.
    pub fn into_parts(
        self,
    ) -> (
        crate::QmpHotForkState,
        A,
        QemuHotForkChildQmpHostEndpoint,
        QemuHotForkChildDiagnosticConsumer,
        QemuHotForkHostContinuation,
    ) {
        (
            self.parent_state,
            self.process_authority,
            self.child_qmp,
            self.diagnostics,
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

fn hot_fork_host_io_binding(
    request: crate::QmpHotForkRequest,
    ring: crucible_shmem::SetupRegionBackingIdentity,
) -> crucible::model::ContentHash {
    let material = format!(
        "template={};private-ring={};diagnostic={};qmp={};console={};monitor={};plugin-endpoint={};plugin-barrier={};rcu-barrier={};async-worker-barrier={};block-barrier={};parent-process={};child-process={};child-contract={};child-files={};ring-device={};ring-inode={};ring-length={}",
        request.template_generation(),
        request.private_ring_generation(),
        request.diagnostic_generation(),
        request.qmp_generation(),
        request.console_generation(),
        request.monitor_generation(),
        request.plugin_endpoint_generation(),
        request.plugin_barrier_generation(),
        request.rcu_barrier_generation(),
        request.async_worker_barrier_generation(),
        request.block_barrier_generation(),
        request.parent_process_generation(),
        request.child_process_generation(),
        request.child_process_contract_generation(),
        request.child_files_generation(),
        ring.device(),
        ring.inode(),
        ring.length(),
    );
    crucible::model::ContentHash::from_canonical_material(
        "crucible.qemu.hot-fork-host-io-continuation.v3",
        &material,
    )
}

struct QemuHotForkRetainedState {
    template: crate::QmpHotForkTemplateState,
    private_ring: crate::QmpHotForkPrivateRingState,
    diagnostics: crate::QmpHotForkChildDiagnosticState,
    child_qmp: crate::QmpHotForkChildQmpState,
    child_console: crate::QmpHotForkChildConsoleState,
    process_contract: crate::QmpHotForkChildProcessContractState,
    child_files: crate::QmpHotForkChildFilesState,
}

fn hot_fork_request_basis_mismatch(message: impl Into<String>) -> QemuNodeChannelError {
    QemuNodeChannelError::new("derive retained hot-fork request", message)
}

#[path = "hot_fork_operation/node.rs"]
mod node;
