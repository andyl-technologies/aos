//! Host supervision runtimes for live QEMU nodes.
//!
//! This module owns the production host-side runtimes that bridge synchronous
//! scheduler node steps to real-time child I/O. It is a host-nondeterminism
//! boundary: its members map shared memory and bound child liveness with host
//! time, but never fold host timing into virtual-time ordering state.

mod accelerator_io_servicer;
mod block_io_gate;
mod block_io_servicer;
mod block_node_gate;
mod deadline;
mod device_host_work;
mod host_io_runtime;
mod host_parallel_gate;
mod network_io_gate;
mod network_io_servicer;
mod ninep_io_gate;
mod ninep_io_servicer;
mod node_step_gate;

/// Keeps a host-only QEMU liveness deadline inside the supervision boundary.
pub(super) struct HostSupervisionDeadline(deadline::HostSupervisionDeadline);

impl HostSupervisionDeadline {
    /// Starts a host-only supervision deadline.
    pub(super) fn start(timeout: std::time::Duration) -> Self {
        Self(deadline::HostSupervisionDeadline::start(timeout))
    }

    /// Reports whether the host-only supervision budget remains available.
    pub(super) fn has_time_remaining(&self) -> bool {
        self.0.has_time_remaining()
    }

    /// Returns the remaining host-only supervision budget.
    pub(super) fn remaining(&self) -> Option<std::time::Duration> {
        self.0.remaining()
    }
}

pub use accelerator_io_servicer::{
    QemuLiveAcceleratorCheckpoint, QemuLiveAcceleratorServiceStep, QemuLiveAcceleratorServicer,
    QemuLiveAcceleratorServicerError,
};
pub use block_io_gate::{
    BlockIoAdvanceOutcome, QemuLiveBlockIoGateConfig, QemuLiveBlockIoGateError,
    QemuLiveBlockIoReport, run_qemu_live_block_io_gate,
};
pub use block_io_servicer::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, QemuLiveBlockIoDeliveryStep,
    QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoIntakeStep, QemuLiveBlockIoObservedRequest,
    QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer, QemuLiveBlockIoServicerError,
    QemuSharedBlockDevice,
};
pub use block_node_gate::{
    BlockNodeOutcome, QemuLiveBlockNodeGateConfig, QemuLiveBlockNodeGateError,
    QemuLiveBlockNodeReport, run_qemu_live_block_node_gate,
};
pub use device_host_work::{
    QemuDeviceHostWorkDelay, QemuLiveBlockHostWorkPool, QemuLiveBlockHostWorkPoolError,
    QemuLiveBlockStorageEvents,
};
pub use host_io_runtime::{
    QemuBlockFaultCoordinator, QemuLiveHostIoRuntime, QemuLiveHostIoRuntimeError,
    QemuNinepFaultCoordinator,
};
pub use host_parallel_gate::{
    QemuLiveHostParallelGateError, QemuLiveHostParallelReport, run_qemu_live_host_parallel_gate,
};
pub use network_io_gate::{
    QemuLiveNetworkIoGateConfig, QemuLiveNetworkIoGateError, QemuLiveNetworkIoReport,
    run_qemu_live_network_io_gate,
};
pub use network_io_servicer::{
    LIVE_NETWORK_ACK_PAYLOAD, LIVE_NETWORK_ETHERTYPE, LIVE_NETWORK_PROBE_PAYLOAD,
    LIVE_NETWORK_REPLY_LATENCY_ICOUNT, LIVE_NETWORK_REPLY_PAYLOAD, LiveNetworkIoServiceStep,
    LiveNetworkIoSnapshot, LiveNetworkTxObservation, QemuLiveNetworkIoServicer,
    QemuLiveNetworkIoServicerError,
};
pub use ninep_io_gate::{
    NinepIoAdvanceOutcome, QemuLive9pIoGateConfig, QemuLive9pIoGateError, QemuLive9pIoReport,
    run_qemu_live_9p_io_gate,
};
pub use ninep_io_servicer::{
    NinepIoDiagnostics, NinepIoDiagnosticsSnapshot, QemuLive9pIoRequestPin,
    QemuLive9pIoServiceStep, QemuLive9pIoServicer, QemuLive9pIoServicerError,
    QemuLive9pIoTransactionCheckpoint, QemuLive9pResponseEvidence,
};
pub use node_step_gate::{
    QemuGuardedExactNodeLaunch, QemuGuardedFreshNodeLaunch, QemuLiveExactSnapshotReport,
    QemuLiveNodeIdentity, QemuLiveNodeLifecycleFaultReport, QemuLiveNodeStepGateConfig,
    QemuLiveNodeStepGateError, QemuLiveNodeStepQuantum, QemuLiveNodeStepReport,
    QemuLiveNodeStepSchedule, QemuLiveRetainedNetworkSnapshotReport, launch_qemu_live_node,
    launch_qemu_live_node_exact_snapshot, launch_qemu_live_node_exact_snapshot_guarded,
    launch_qemu_live_node_exact_snapshot_paused,
    launch_qemu_live_node_exact_snapshot_paused_guarded, launch_qemu_live_node_guarded,
    launch_qemu_live_node_restored, run_qemu_live_exact_snapshot_gate,
    run_qemu_live_node_lifecycle_fault_gate, run_qemu_live_node_step_gate,
    run_qemu_live_retained_network_snapshot_gate,
};
