//! Linear node ownership for one retained-template hot fork.
//!
//! QMP command rejection is safe only before `fork(2)`. Once command delivery
//! becomes ambiguous, or QEMU reports a parent-disposition failure after
//! creating the child, the source node retains every staged descriptor and is
//! quarantined as one process authority. A successful transaction alone moves
//! the branch-private child QMP endpoint and sole diagnostics reader into the
//! returned launch token.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
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

impl QemuHotForkHostContinuation {
    /// Returns the exact source template generation paired with this continuation.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.endpoint.template_generation()
    }

    /// Returns the exact QMP fork request binding every child continuation.
    #[must_use]
    pub const fn request(&self) -> crate::QmpHotForkRequest {
        self.request
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

    /// Returns the exact fork/ring identity binding the host-I/O clone.
    #[must_use]
    pub const fn host_io_binding(&self) -> crucible::model::ContentHash {
        self.host_io_binding
    }

    /// Returns the exact scheduler-owned node state cloned at the fork boundary.
    #[must_use]
    pub const fn node_state(&self) -> &QemuHotForkNodeStateContinuation {
        &self.node_state
    }

    /// Borrows the branch-private host-device continuation.
    #[must_use]
    pub fn host_io_runtime_mut(&mut self) -> &mut dyn QemuHostIoRuntime {
        self.host_io_runtime.as_mut()
    }

    /// Returns whether the branch-private console spool remains transferable.
    #[must_use]
    pub const fn console_observation_available(&self) -> bool {
        self.console_spool.is_some()
    }

    /// Attaches this continuation's boundary spool to its assembled child node.
    ///
    /// The host-I/O runtime retained by this continuation owns the matching
    /// branch-private console reader. The child publishes those bytes only at
    /// completed scheduler boundaries for `node`. The spool is linear: one
    /// continuation can attach it to exactly one child node.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] if this continuation already transferred
    /// its spool or the supplied child already owns a console observation.
    pub fn attach_console_observation(
        &mut self,
        child: &mut QemuNode,
        node: NodeId,
    ) -> Result<(), QemuNodeChannelError> {
        if child.console_observation.is_some() {
            return Err(QemuNodeChannelError::new(
                "attach hot-fork child console observation",
                "child node already owns a console observation",
            ));
        }
        let spool = self.console_spool.take().ok_or_else(|| {
            QemuNodeChannelError::new(
                "attach hot-fork child console observation",
                "child console observation was already transferred",
            )
        })?;
        child.console_observation = Some(QemuConsoleObservation { node, spool });
        Ok(())
    }
}

/// Backward-compatible name for the plugin portion's original continuation type.
pub type QemuHotForkPluginHostContinuation = QemuHotForkHostContinuation;

/// Linear successful parent result, process authority, and private child channels.
#[derive(Debug)]
#[must_use = "the forked child authorities must be reconciled or transferred to quarantine"]
pub struct QemuHotForkChildLaunch<A> {
    parent_state: crate::QmpHotForkState,
    child_process_id: u32,
    process_authority: A,
    child_qmp: QemuHotForkChildQmpHostEndpoint,
    diagnostics: QemuHotForkChildDiagnosticConsumer,
    host_continuation: QemuHotForkHostContinuation,
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

    /// Returns the retained child process authority.
    #[must_use]
    pub const fn process_authority(&self) -> &A {
        &self.process_authority
    }

    /// Returns the exact root selectors and destination inode identities
    /// consumed by this successful fork.
    #[must_use]
    pub fn child_files(&self) -> &[crate::QmpHotForkChildFile] {
        &self.child_files
    }

    /// Returns the retained child-QMP endpoint basis without consuming it.
    #[must_use]
    pub const fn child_qmp(&self) -> &QemuHotForkChildQmpHostEndpoint {
        &self.child_qmp
    }

    /// Returns the exact branch-private diagnostics consumer.
    pub const fn diagnostics(&self) -> &QemuHotForkChildDiagnosticConsumer {
        &self.diagnostics
    }

    /// Returns the exact branch-private host continuation.
    pub const fn host_continuation(&self) -> &QemuHotForkHostContinuation {
        &self.host_continuation
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
        "template={};private-ring={};diagnostic={};qmp={};console={};monitor={};plugin-endpoint={};plugin-barrier={};rcu-barrier={};bh-timer-barrier={};block-barrier={};parent-process={};child-process={};child-contract={};child-files={};ring-device={};ring-inode={};ring-length={}",
        request.template_generation(),
        request.private_ring_generation(),
        request.diagnostic_generation(),
        request.qmp_generation(),
        request.console_generation(),
        request.monitor_generation(),
        request.plugin_endpoint_generation(),
        request.plugin_barrier_generation(),
        request.rcu_barrier_generation(),
        request.bh_timer_barrier_generation(),
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

impl QemuNode {
    fn derive_hot_fork_request(
        &mut self,
    ) -> Result<crate::QmpHotForkRequest, QemuNodeChannelError> {
        if self.lifecycle_state != QemuNodeLifecycleState::Running {
            return Err(hot_fork_request_basis_mismatch(
                "hot-fork request derivation requires a running source node",
            ));
        }

        let retained = QemuHotForkRetainedState {
            template: self
                .channels
                .qmp_machine_control
                .query_hot_fork_template()?,
            private_ring: self
                .channels
                .qmp_machine_control
                .query_hot_fork_private_rings()?,
            diagnostics: self
                .channels
                .qmp_machine_control
                .query_hot_fork_child_diagnostics()?,
            child_qmp: self
                .channels
                .qmp_machine_control
                .query_hot_fork_child_qmp()?,
            child_console: self
                .channels
                .qmp_machine_control
                .query_hot_fork_child_console()?,
            process_contract: self
                .channels
                .qmp_machine_control
                .query_hot_fork_child_process_contract()?,
            child_files: self
                .channels
                .qmp_machine_control
                .query_hot_fork_child_files()?,
        };
        let confirmed_template = self
            .channels
            .qmp_machine_control
            .query_hot_fork_template()?;
        if confirmed_template != retained.template {
            return Err(hot_fork_request_basis_mismatch(
                "retained template changed while its fork request was derived",
            ));
        }

        let request = crate::QmpHotForkRequest::from_prepared_template(
            &retained.template,
            &retained.child_qmp,
            &retained.child_console,
            &retained.process_contract,
            &retained.child_files,
        )
        .map_err(|source| hot_fork_request_basis_mismatch(source.to_string()))?;
        self.validate_hot_fork_request_basis(request, &retained)?;
        Ok(request)
    }

    fn validate_hot_fork_request_basis(
        &self,
        request: crate::QmpHotForkRequest,
        retained: &QemuHotForkRetainedState,
    ) -> Result<(), QemuNodeChannelError> {
        let resource = retained.template.resource_stage();
        let ring = self.hot_fork_private_ring_stage().ok_or_else(|| {
            hot_fork_request_basis_mismatch("source node retains no private-ring authority")
        })?;
        // A node-owned plan must be the exact plan QEMU retains; an absent
        // node plan defers to QEMU, which rejects a nonempty native graph.
        let child_files_match = match self.hot_fork_child_files_stage.as_ref() {
            Some(stage) => {
                stage.matches_state(&retained.child_files)
                    && stage.generation() == request.child_files_generation()
            }
            None => !retained.child_files.staged(),
        };
        if !child_files_match {
            return Err(hot_fork_request_basis_mismatch(
                "QEMU child file plan does not match the node-owned destinations",
            ));
        }
        let ring_identity = ring.backing_identity();
        let ring_matches = ring.state() == QemuHotForkPrivateRingStageState::Installed
            && retained.private_ring.staged()
            && retained.private_ring.generation() == request.private_ring_generation()
            && retained.private_ring.template_generation() == request.template_generation()
            && retained.private_ring.descriptor_name() == Some(ring.descriptor_name())
            && retained.private_ring.device() == ring_identity.device()
            && retained.private_ring.inode() == ring_identity.inode()
            && retained.private_ring.length() == ring_identity.length()
            && retained.private_ring.shrink_sealed()
            && retained.private_ring.source_mapping_bound()
            && retained.private_ring.source_length()
                == crate::qmp::source_mapping_extent(ring.source_setup_region().length())
            && resource.private_ring_staged();
        if !ring_matches {
            return Err(hot_fork_request_basis_mismatch(
                "QEMU private-ring state does not match the node-owned mapping",
            ));
        }

        let diagnostics = self.hot_fork_child_diagnostic_stage().ok_or_else(|| {
            hot_fork_request_basis_mismatch("source node retains no child-diagnostics authority")
        })?;
        let diagnostics_match = diagnostics.state()
            == QemuHotForkChildDiagnosticStageState::Installed
            && retained.diagnostics.staged()
            && retained.diagnostics.generation() == request.diagnostic_generation()
            && retained.diagnostics.template_generation() == request.template_generation()
            && retained.diagnostics.descriptor_name() == Some(diagnostics.descriptor_name())
            && retained.diagnostics.socket_cookie() == Some(diagnostics.socket_cookie())
            && retained.diagnostics.replacement_plan_bound()
            && diagnostics.replacement_plan_bound()
            && resource.diagnostics_staged();
        if !diagnostics_match {
            return Err(hot_fork_request_basis_mismatch(
                "QEMU child-diagnostics state does not match the node-owned stream",
            ));
        }

        let child_qmp = self.hot_fork_child_qmp_stage().ok_or_else(|| {
            hot_fork_request_basis_mismatch("source node retains no child-QMP authority")
        })?;
        let child_qmp_matches = child_qmp.state() == QemuHotForkChildQmpStageState::Installed
            && retained.child_qmp.descriptor_name() == Some(child_qmp.descriptor_name())
            && retained.child_qmp.socket_cookie() == Some(child_qmp.socket_cookie())
            && retained.child_qmp.template_generation() == child_qmp.template_generation()
            && retained.child_qmp.generation() == child_qmp.qmp_generation()
            && retained.child_qmp.monitor_generation() == child_qmp.monitor_generation()
            && retained.child_qmp.resource_plan_bound() == child_qmp.resource_plan_bound()
            && resource.qmp_staged();
        if !child_qmp_matches {
            return Err(hot_fork_request_basis_mismatch(
                "QEMU child-QMP state does not match the node-owned stream",
            ));
        }

        let child_console = self.hot_fork_child_console_stage().ok_or_else(|| {
            hot_fork_request_basis_mismatch("source node retains no child-console authority")
        })?;
        let child_console_matches = child_console.state()
            == QemuHotForkChildConsoleStageState::Installed
            && retained.child_console.descriptor_name() == Some(child_console.descriptor_name())
            && retained.child_console.socket_cookie() == Some(child_console.socket_cookie())
            && retained.child_console.template_generation() == child_console.template_generation()
            && retained.child_console.generation() == child_console.console_generation()
            && retained.child_console.resource_plan_bound() == child_console.resource_plan_bound()
            && resource.console_staged();
        if !child_console_matches {
            return Err(hot_fork_request_basis_mismatch(
                "QEMU child-console state does not match the node-owned stream",
            ));
        }

        let endpoints = self.hot_fork_plugin_endpoint_stage().ok_or_else(|| {
            hot_fork_request_basis_mismatch("source node retains no plugin-endpoint authority")
        })?;
        let endpoints_match = endpoints.state() == QemuHotForkPluginEndpointStageState::Installed
            && endpoints.generation() == request.plugin_endpoint_generation()
            && endpoints.template_generation() == request.template_generation()
            && endpoints.private_ring_generation() == request.private_ring_generation()
            && endpoints.plugin_barrier_generation() == request.plugin_barrier_generation()
            && endpoints.worker_mask() == resource.worker_mask()
            && endpoints.replacement_plan().is_some()
            && resource.plugin_endpoints_staged();
        if !endpoints_match {
            return Err(hot_fork_request_basis_mismatch(
                "QEMU template state does not match the node-owned plugin endpoints",
            ));
        }

        let process_contract_matches = self
            .hot_fork_child_process_contract_stage
            .as_ref()
            .is_some_and(|stage| stage.matches_state(&retained.process_contract));
        if !process_contract_matches {
            return Err(hot_fork_request_basis_mismatch(
                "QEMU process-contract state does not match the node-owned authority",
            ));
        }
        Ok(())
    }

    /// Forks the exact prepared template basis reported by QEMU and retained by this node.
    ///
    /// The operation brackets the independently queryable QEMU child-resource
    /// reports with an unchanged prepared-template state and compares every
    /// retained generation to the node's linear host authorities before
    /// constructing the request. Callers cannot inject or replay a generation
    /// tuple.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkLaunchError::Rejected`] when request derivation or
    /// explicit pre-fork validation proves that no child was created. All other
    /// variants leave this node quarantined because a child exists or may exist.
    pub fn fork_prepared_hot_fork_template<O>(
        &mut self,
        process_owner: &mut O,
    ) -> Result<QemuHotForkChildLaunch<O::Authority>, QemuHotForkLaunchError>
    where
        O: QemuHotForkChildProcessOwner,
    {
        let request = self
            .derive_hot_fork_request()
            .map_err(|source| QemuHotForkLaunchError::Rejected { source })?;
        self.fork_hot_fork_template(request, process_owner)
    }

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

    /// Forks a prepared template and transfers its private child channels.
    ///
    /// The caller supplies the request derived from the exact prepared template
    /// and sealed child-QMP reports. QEMU revalidates all request generations on
    /// its source main loop. An explicit pre-fork rejection leaves this node and
    /// its endpoint reusable. Every post-fork or ambiguous failure quarantines
    /// this node with all staged ownership still retained. A successful result
    /// moves the QMP endpoint and diagnostics reader exactly once into
    /// [`QemuHotForkChildLaunch`].
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
    pub(crate) fn fork_hot_fork_template<O>(
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
        let console_stage = self.hot_fork_child_console_stage().ok_or_else(|| {
            QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "source node retains no child console stage",
                ),
            }
        })?;
        if console_stage.state() != QemuHotForkChildConsoleStageState::Installed
            || !console_stage.resource_plan_bound()
            || console_stage.template_generation() != request.template_generation()
            || console_stage.console_generation() != request.console_generation()
        {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "child console endpoint does not match the sealed fork request",
                ),
            });
        }
        if !self
            .hot_fork_child_console_stage
            .as_ref()
            .is_some_and(QemuHotForkChildConsoleStage::host_endpoint_available)
        {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "branch-private child console endpoint was already transferred",
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
        if let Some(child_files) = self.hot_fork_child_files_stage()
            && (child_files.consumed()
                || child_files.generation() != request.child_files_generation()
                || child_files.template_generation() != request.template_generation())
        {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "child file plan does not match the fork request",
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
        if !self
            .hot_fork_child_diagnostic_stage
            .as_ref()
            .is_some_and(|diagnostics| {
                diagnostics.consumer_available()
                    && diagnostics.replacement_plan_bound()
                    && diagnostics.template_generation() == request.template_generation()
            })
        {
            return Err(QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "fork retained hot-fork template",
                    "branch-private child diagnostics consumer was already transferred",
                ),
            });
        }
        let node_state = QemuHotForkNodeStateContinuation::capture(self)
            .map_err(|source| QemuHotForkLaunchError::Rejected { source })?;
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
        let host_wake = self
            .hot_fork_plugin_endpoint_stage
            .as_ref()
            .ok_or_else(|| QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "clone hot-fork plugin host wake",
                    "plugin endpoint stage disappeared before child creation",
                ),
            })?
            .clone_host_wake()
            .map_err(|source| QemuHotForkLaunchError::Rejected { source })?;
        let shmem_hot_path = self
            .channels
            .shmem_hot_path
            .clone_hot_fork_host_continuation(mapping)
            .map_err(|source| QemuHotForkLaunchError::Rejected { source })?;
        let host_io_binding = hot_fork_host_io_binding(request, mapping.backing_identity());
        let child_console = self
            .clone_hot_fork_child_console_observation()
            .map_err(|source| QemuHotForkLaunchError::Rejected { source })?;
        let console_spool = child_console.spool();
        let host_io_runtime = self
            .host_io_runtime
            .clone_hot_fork_host_io_continuation(
                host_io_binding,
                mapping.descriptor(),
                host_wake.as_fd(),
                mapping.backing_identity().length(),
                Some(child_console),
            )
            .map_err(|source| QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "clone hot-fork host-I/O continuation",
                    source.to_string(),
                ),
            })?;
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
        let child_files = self
            .hot_fork_child_files_stage
            .as_ref()
            .map(|stage| stage.files().to_vec())
            .unwrap_or_default();
        if let Some(child_files) = self.hot_fork_child_files_stage.as_mut() {
            child_files.mark_consumed();
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
        self.consume_hot_fork_child_console_host_endpoint()
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
        let diagnostics = self
            .take_hot_fork_child_diagnostic_consumer()
            .map_err(|source| {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
                QemuHotForkLaunchError::EndpointTransfer {
                    parent_state: Box::new(parent_state),
                    source,
                }
            })?;
        let host_continuation = QemuHotForkHostContinuation {
            request,
            endpoint: host_endpoint,
            ring_descriptor,
            ring,
            endpoint_stage,
            shmem_hot_path,
            host_io_binding,
            host_io_runtime,
            console_spool: Some(console_spool),
            node_state,
        };
        Ok(QemuHotForkChildLaunch {
            parent_state,
            child_process_id,
            process_authority,
            child_qmp,
            diagnostics,
            host_continuation,
            child_files,
        })
    }
}
