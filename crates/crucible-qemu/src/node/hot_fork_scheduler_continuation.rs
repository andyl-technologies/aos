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
    _channels: QemuNodeChannels,
    _host_io_runtime: Box<dyn QemuHostIoRuntime>,
    _console_spool: Option<QemuConsoleObservationSpool>,
    state: QemuHotForkNodeStateContinuation,
    _ring_descriptor: OwnedFd,
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
            _channels: channels,
            _host_io_runtime: host_io_runtime,
            _console_spool: console_spool,
            state: node_state,
            _ring_descriptor: ring_descriptor,
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

fn invalid_node_continuation(message: impl Into<String>) -> QemuNodeChannelError {
    QemuNodeChannelError::new("capture hot-fork scheduler-node continuation", message)
}
