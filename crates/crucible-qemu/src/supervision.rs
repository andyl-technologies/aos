//! Host supervision runtimes for live QEMU nodes.
//!
//! This module owns the production host-side runtimes that bridge synchronous
//! scheduler node steps to real-time child I/O. It is a host-nondeterminism
//! boundary: its members map shared memory and bound child liveness with host
//! time, but never fold host timing into virtual-time ordering state.

mod block_io_servicer;
mod host_io_runtime;
mod node_step_gate;

pub use block_io_servicer::{
    QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer, QemuLiveBlockIoServicerError,
};
pub use host_io_runtime::{QemuLiveHostIoRuntime, QemuLiveHostIoRuntimeError};
pub use node_step_gate::{
    QemuLiveNodeStepGateConfig, QemuLiveNodeStepGateError, QemuLiveNodeStepQuantum,
    QemuLiveNodeStepReport, QemuLiveNodeStepSchedule, run_qemu_live_node_step_gate,
};
