//! Process-neutral scheduler state retained for one hot-fork child.
//!
//! QEMU remains the direct parent of a hot-fork child, so this module does not
//! fabricate a [`std::process::Child`] or claim `waitpid` authority. It instead
//! seals the branch-private plugin, shared-memory, QMP, host-I/O, console, and
//! scheduler-mirror state into one linear continuation. A later process-owner
//! adapter can install that continuation only while it retains the source
//! QEMU's child-status authority and the target attempt's pidfd/cgroup owner.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use crucible::{Icount, VirtualTime};
use crucible_shmem::FaultCapabilityRowV1;
use thiserror::Error;

use super::*;
use crate::QemuQmpVmStateControlChannel;

/// Exact scheduler-owned node state copied at one retained-template fork.
///
/// The value contains no process handle, mutable-ref capability, or host path.
/// It is inseparable from the branch-private transport continuation that was
/// cloned under the same QEMU hot-fork request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkNodeStateContinuation {
    last_observed_time: VirtualTime,
    last_step_ceiling: Option<Icount>,
    last_step_final_state: Option<QemuNodeIdleState>,
    last_step_inbound_frames_consumed: usize,
    console_observation_boundary: VirtualTime,
    pending_preemption: Option<crucible::PreemptionDecision>,
    next_network_output_sequence: u64,
    fault_capabilities: Vec<FaultCapabilityRowV1>,
    ready_markers: std::collections::BTreeSet<crucible::model::FaultObjectId>,
    exact_fault_manifests: Option<crate::fault_capability::QemuExactFaultManifests>,
    next_fault_command_sequence: u64,
    setup_fault_command_sequence_floor: u64,
    next_fault_event_sequence: u64,
}

impl QemuHotForkNodeStateContinuation {
    pub(super) fn capture(source: &QemuNode) -> Result<Self, QemuNodeChannelError> {
        if source.lifecycle_state != QemuNodeLifecycleState::Running {
            return Err(invalid_node_continuation(
                "source node is not in its running lifecycle state",
            ));
        }
        if source.gdbstub.is_some() || source.active_gdbstub.is_some() {
            return Err(invalid_node_continuation(
                "source node retains an operator debug endpoint",
            ));
        }
        if !source.pending_network_outputs.is_empty() {
            return Err(invalid_node_continuation(
                "source node retains uncommitted network output",
            ));
        }
        if !source.pending_priming_observations.is_empty() {
            return Err(invalid_node_continuation(
                "source node retains uncommitted priming observations",
            ));
        }
        if source.fault_event_terminal_failure.is_some() {
            return Err(invalid_node_continuation(
                "source node retains a terminal fault-event transport failure",
            ));
        }

        Ok(Self {
            last_observed_time: source.last_observed_time,
            last_step_ceiling: source.last_step_ceiling,
            last_step_final_state: source.last_step_final_state,
            last_step_inbound_frames_consumed: source.last_step_inbound_frames_consumed,
            console_observation_boundary: source.console_observation_boundary,
            pending_preemption: source.pending_preemption.clone(),
            next_network_output_sequence: source.next_network_output_sequence,
            fault_capabilities: source.fault_capabilities.clone(),
            ready_markers: source.ready_markers.clone(),
            exact_fault_manifests: source.exact_fault_manifests.clone(),
            next_fault_command_sequence: source.next_fault_command_sequence,
            setup_fault_command_sequence_floor: source.setup_fault_command_sequence_floor,
            next_fault_event_sequence: source.next_fault_event_sequence,
        })
    }

    /// Returns the exact scheduler time last observed for the source node.
    #[must_use]
    pub const fn last_observed_time(&self) -> VirtualTime {
        self.last_observed_time
    }

    /// Returns the next scheduler-owned network output sequence.
    #[must_use]
    pub const fn next_network_output_sequence(&self) -> u64 {
        self.next_network_output_sequence
    }

    /// Returns the next scheduler-owned fault command sequence.
    #[must_use]
    pub const fn next_fault_command_sequence(&self) -> u64 {
        self.next_fault_command_sequence
    }

    /// Returns the next scheduler-owned fault event sequence.
    #[must_use]
    pub const fn next_fault_event_sequence(&self) -> u64 {
        self.next_fault_event_sequence
    }
}

/// Linear branch-private scheduler-node continuation.
///
/// This value owns all three modeled channel planes, the reconstructed host-I/O
/// runtime, the exact private-ring descriptor, the cloned console spool, and
/// the scheduler mirror captured at the same fork boundary. It deliberately
/// has no constructor from raw public parts. Turning it into a live
/// [`QemuNode`] additionally requires an externally reaped process authority,
/// which is introduced by the process-owner integration rather than this
/// transport layer.
#[must_use = "retain the scheduler-node continuation through child reconciliation"]
pub struct QemuHotForkSchedulerNodeContinuation {
    request: crate::QmpHotForkRequest,
    channels: QemuNodeChannels,
    host_io_runtime: Box<dyn QemuHostIoRuntime>,
    console_spool: Option<QemuConsoleObservationSpool>,
    state: QemuHotForkNodeStateContinuation,
    ring_descriptor: OwnedFd,
    ring: QemuHotForkPrivateRingStageProof,
    endpoint_stage: QemuHotForkPluginEndpointStageProof,
    host_io_binding: crucible::model::ContentHash,
}

impl std::fmt::Debug for QemuHotForkSchedulerNodeContinuation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkSchedulerNodeContinuation")
            .field("state", &self.state)
            .field("ring", &self.ring)
            .field("endpoint_stage", &self.endpoint_stage)
            .field("host_io_binding", &self.host_io_binding)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkSchedulerNodeContinuation {
    pub(super) fn from_host_continuation(
        continuation: QemuHotForkHostContinuation,
        child_qmp: QemuQmpVmStateControlChannel<UnixStream>,
    ) -> Self {
        let QemuHotForkHostContinuation {
            request,
            endpoint,
            ring_descriptor,
            ring,
            endpoint_stage,
            shmem_hot_path,
            host_io_binding,
            host_io_runtime,
            console_spool,
            node_state,
        } = continuation;
        let channels = QemuNodeChannels {
            plugin_control: Box::new(endpoint),
            shmem_hot_path,
            qmp_machine_control: Box::new(crate::QemuQmpExactSnapshotControlChannel::new(
                child_qmp,
            )),
        };
        Self {
            request,
            channels,
            host_io_runtime,
            console_spool,
            state: node_state,
            ring_descriptor,
            ring,
            endpoint_stage,
            host_io_binding,
        }
    }

    /// Returns the source template generation bound into all child channels.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.endpoint_stage.template_generation()
    }

    /// Returns the exact QMP fork request binding every owned continuation.
    #[must_use]
    pub const fn request(&self) -> crate::QmpHotForkRequest {
        self.request
    }

    /// Returns the private ring generation bound into all child channels.
    #[must_use]
    pub const fn private_ring_generation(&self) -> u64 {
        self.endpoint_stage.private_ring_generation()
    }

    /// Returns the exact fork/ring identity binding the host-I/O continuation.
    #[must_use]
    pub const fn host_io_binding(&self) -> crucible::model::ContentHash {
        self.host_io_binding
    }

    /// Returns the exact scheduler-owned state captured with the transports.
    #[must_use]
    pub const fn node_state(&self) -> &QemuHotForkNodeStateContinuation {
        &self.state
    }

    /// Installs this continuation as one externally parented scheduler node.
    ///
    /// The process-control loan must name the exact fork request and child PID
    /// authenticated during source-template reconciliation. The returned node
    /// owns every modeled child channel and continuation, while source-parent
    /// status release and target-resource cleanup remain with the outer
    /// lifecycle that issued `process`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkSchedulerNodeInstallError`] with both linear inputs
    /// when the process-control basis differs from this continuation.
    pub fn into_qemu_node(
        mut self,
        node: crucible::NodeId,
        process: impl QemuNodeExternalProcessControl + 'static,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
    ) -> Result<QemuNode, QemuHotForkSchedulerNodeInstallError> {
        let process = Box::new(process);
        let basis = process.hot_fork_process_basis();
        if basis.request() != self.request || basis.child_process_id() != process.process_id() {
            return Err(QemuHotForkSchedulerNodeInstallError::new(
                self,
                process,
                QemuNodeChannelError::new(
                    "install hot-fork scheduler node",
                    "external process control does not match the retained fork basis",
                ),
            ));
        }

        // The private ring's fresh slot must carry the counter the child
        // inherited before any host request reaches the plugin; the larger of
        // the observed time and the last step ceiling is where the source
        // stopped.
        let inherited_icount = self
            .state
            .last_step_ceiling
            .map_or(self.state.last_observed_time.ticks, |ceiling| {
                ceiling.retired.max(self.state.last_observed_time.ticks)
            });
        if let Err(source) = self
            .channels
            .shmem_hot_path
            .arm_hot_fork_child_ceiling(inherited_icount)
        {
            return Err(QemuHotForkSchedulerNodeInstallError::new(
                self, process, source,
            ));
        }

        let Self {
            request,
            channels,
            host_io_runtime,
            console_spool,
            state,
            ring_descriptor,
            ring,
            endpoint_stage,
            host_io_binding,
        } = self;
        let console_observation = console_spool.map(|spool| QemuConsoleObservation { node, spool });
        let authority = QemuHotForkInstalledNodeAuthority {
            request,
            _ring_descriptor: ring_descriptor,
            ring,
            endpoint_stage,
            host_io_binding,
        };
        Ok(QemuNode {
            child: QemuNodeProcessControl::External(process),
            channels,
            hot_fork_private_ring_stage: None,
            hot_fork_child_diagnostic_stage: None,
            hot_fork_child_qmp_stage: None,
            hot_fork_child_console_stage: None,
            hot_fork_child_process_contract_stage: None,
            #[cfg(target_os = "linux")]
            hot_fork_child_files_stage: None,
            hot_fork_plugin_endpoint_stage: None,
            _hot_fork_scheduler_authority: Some(authority),
            lifecycle_state: QemuNodeLifecycleState::Running,
            shutdown_policy,
            async_policy,
            crash_detector,
            host_io_runtime,
            last_observed_time: state.last_observed_time,
            last_step_ceiling: state.last_step_ceiling,
            last_step_final_state: state.last_step_final_state,
            last_step_inbound_frames_consumed: state.last_step_inbound_frames_consumed,
            console_observation_boundary: state.console_observation_boundary,
            gdbstub: None,
            active_gdbstub: None,
            pending_preemption: state.pending_preemption,
            pending_network_outputs: Vec::new(),
            pending_priming_observations: Vec::new(),
            next_network_output_sequence: state.next_network_output_sequence,
            console_observation,
            fault_capabilities: state.fault_capabilities,
            ready_markers: state.ready_markers,
            exact_fault_manifests: state.exact_fault_manifests,
            next_fault_command_sequence: state.next_fault_command_sequence,
            setup_fault_command_sequence_floor: state.setup_fault_command_sequence_floor,
            next_fault_event_sequence: state.next_fault_event_sequence,
            fault_event_terminal_failure: None,
        })
    }
}

pub(super) struct QemuHotForkInstalledNodeAuthority {
    request: crate::QmpHotForkRequest,
    _ring_descriptor: OwnedFd,
    ring: QemuHotForkPrivateRingStageProof,
    endpoint_stage: QemuHotForkPluginEndpointStageProof,
    host_io_binding: crucible::model::ContentHash,
}

impl std::fmt::Debug for QemuHotForkInstalledNodeAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkInstalledNodeAuthority")
            .field("request", &self.request)
            .field("ring", &self.ring)
            .field("endpoint_stage", &self.endpoint_stage)
            .field("host_io_binding", &self.host_io_binding)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkHostContinuation {
    /// Seals the branch-private transports into one scheduler-node continuation.
    ///
    /// This operation first requires the exact staged endpoint to match the
    /// retained fork request and then performs its private child handshake. It
    /// consumes every branch-private host transport, so no raw channel can
    /// remain alongside the scheduler continuation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkSchedulerNodeAssemblyError`] with the unchanged host
    /// continuation when the endpoint basis differs or its one-shot QMP
    /// handshake fails. A basis-mismatched endpoint is also returned because it
    /// was not consumed; a failed handshake poisons and consumes that stream.
    pub fn into_scheduler_node_continuation(
        self,
        child_qmp: QemuHotForkChildQmpHostEndpoint,
    ) -> Result<QemuHotForkSchedulerNodeContinuation, QemuHotForkSchedulerNodeAssemblyError> {
        let request = self.request;
        if child_qmp.template_generation() != request.template_generation()
            || child_qmp.qmp_generation() != request.qmp_generation()
            || child_qmp.monitor_generation() != request.monitor_generation()
        {
            return Err(QemuHotForkSchedulerNodeAssemblyError::new(
                self,
                Some(child_qmp),
                QemuNodeChannelError::new(
                    "assemble hot-fork scheduler-node continuation",
                    "child QMP endpoint does not match the retained fork request",
                ),
            ));
        }
        let child_qmp = match child_qmp.connect() {
            Ok(child_qmp) => child_qmp,
            Err(source) => {
                return Err(QemuHotForkSchedulerNodeAssemblyError::new(
                    self,
                    None,
                    QemuNodeChannelError::new(
                        "assemble hot-fork scheduler-node continuation",
                        source.to_string(),
                    ),
                ));
            }
        };
        Ok(QemuHotForkSchedulerNodeContinuation::from_host_continuation(self, child_qmp))
    }
}

/// Failed exact pairing of a private child QMP endpoint and host continuation.
#[derive(Debug, Error)]
#[error("assemble hot-fork scheduler-node continuation failed: {source}")]
#[must_use = "recover the host continuation and any unconsumed child QMP endpoint"]
pub struct QemuHotForkSchedulerNodeAssemblyError {
    continuation: Box<QemuHotForkHostContinuation>,
    child_qmp: Option<Box<QemuHotForkChildQmpHostEndpoint>>,
    #[source]
    source: QemuNodeChannelError,
}

impl QemuHotForkSchedulerNodeAssemblyError {
    fn new(
        continuation: QemuHotForkHostContinuation,
        child_qmp: Option<QemuHotForkChildQmpHostEndpoint>,
        source: QemuNodeChannelError,
    ) -> Self {
        Self {
            continuation: Box::new(continuation),
            child_qmp: child_qmp.map(Box::new),
            source,
        }
    }

    /// Returns the exact typed assembly failure.
    #[must_use]
    pub const fn source_error(&self) -> &QemuNodeChannelError {
        &self.source
    }

    /// Recovers the host continuation and any endpoint not consumed by QMP.
    pub fn into_parts(
        self,
    ) -> (
        QemuHotForkHostContinuation,
        Option<QemuHotForkChildQmpHostEndpoint>,
        QemuNodeChannelError,
    ) {
        (
            *self.continuation,
            self.child_qmp.map(|child_qmp| *child_qmp),
            self.source,
        )
    }
}

/// Failed exact pairing of an assembled node and external process control.
#[derive(Debug, Error)]
#[error("install hot-fork scheduler node failed: {source}")]
#[must_use = "recover the scheduler continuation and external process-control loan"]
pub struct QemuHotForkSchedulerNodeInstallError {
    continuation: Box<QemuHotForkSchedulerNodeContinuation>,
    process: Box<dyn QemuNodeExternalProcessControl>,
    #[source]
    source: QemuNodeChannelError,
}

impl QemuHotForkSchedulerNodeInstallError {
    fn new(
        continuation: QemuHotForkSchedulerNodeContinuation,
        process: Box<dyn QemuNodeExternalProcessControl>,
        source: QemuNodeChannelError,
    ) -> Self {
        Self {
            continuation: Box::new(continuation),
            process,
            source,
        }
    }

    /// Recovers both linear inputs and the exact typed failure.
    pub fn into_parts(
        self,
    ) -> (
        QemuHotForkSchedulerNodeContinuation,
        Box<dyn QemuNodeExternalProcessControl>,
        QemuNodeChannelError,
    ) {
        (*self.continuation, self.process, self.source)
    }
}

fn invalid_node_continuation(message: impl Into<String>) -> QemuNodeChannelError {
    QemuNodeChannelError::new("capture hot-fork scheduler-node continuation", message)
}
