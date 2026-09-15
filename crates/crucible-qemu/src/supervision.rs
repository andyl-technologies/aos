//! Host supervision runtimes for live QEMU nodes.
//!
//! This module owns the production host-side runtimes that bridge synchronous
//! scheduler node steps to real-time child I/O. It is a host-nondeterminism
//! boundary: its members map shared memory and bound child liveness with host
//! time, but never fold host timing into virtual-time ordering state.

mod accelerator_io_servicer;
mod block_io_servicer;
pub(crate) mod bounded_scheduler_preemption;
mod deadline;
mod device_host_work;
mod exact_restore;
pub(crate) mod host_io_runtime;
mod ninep_io_servicer;
mod node_step_gate;
mod rr_control_boundary_trace;
mod runtime_determinism_trace;

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
pub use block_io_servicer::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, QemuLiveBlockIoDeliveryStep,
    QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoIntakeStep, QemuLiveBlockIoObservedRequest,
    QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer, QemuLiveBlockIoServicerError,
    QemuSharedBlockDevice,
};
pub use device_host_work::{
    QemuDeviceHostWorkDelay, QemuLiveBlockHostWorkPool, QemuLiveBlockHostWorkPoolError,
};
pub use exact_restore::{
    QemuProductionExactRestoreLaunch, QemuProductionExactRestoreProfile,
    QemuProductionExactRestoreRequest,
};
pub use host_io_runtime::{
    QemuBlockFaultCoordinator, QemuLiveHostIoRuntime, QemuLiveHostIoRuntimeError,
    QemuNinepFaultCoordinator,
};
pub use ninep_io_servicer::{
    NinepIoDiagnostics, NinepIoDiagnosticsSnapshot, QemuLive9pIoRequestPin,
    QemuLive9pIoServiceStep, QemuLive9pIoServicer, QemuLive9pIoServicerError,
    QemuLive9pIoTransactionCheckpoint, QemuLive9pResponseEvidence,
};
pub use node_step_gate::{
    QemuLiveHotForkChildReport, QemuLiveHotForkChildStressReport, QemuLiveNodeIdentity,
    QemuLiveNodeStepGateConfig, QemuLiveNodeStepGateError, QemuProductionFreshLaunchAdmission,
    launch_qemu_production_fresh_node, run_qemu_live_hot_fork_child_gate,
    run_qemu_live_hot_fork_child_stress_gate,
};
pub use rr_control_boundary_trace::{
    QemuRrControlBoundaryTraceError, QemuRrControlBoundaryTracePhase,
    QemuRrControlBoundaryTraceRecord, parse_qemu_rr_control_boundary_trace,
};
pub use runtime_determinism_trace::{
    QemuRuntimeDeterminismIdlePhase, QemuRuntimeDeterminismIdleRecord,
    QemuRuntimeDeterminismTimerOwner, QemuRuntimeDeterminismTimerRecord,
    QemuRuntimeDeterminismTimerScope, QemuRuntimeDeterminismTimerServicePhase,
    QemuRuntimeDeterminismTimerServiceRecord, QemuRuntimeDeterminismTraceError,
    QemuRuntimeDeterminismTraceRecord, parse_qemu_runtime_determinism_trace,
};
