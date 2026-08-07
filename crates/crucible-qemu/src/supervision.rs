//! Host supervision runtimes for live QEMU nodes.
//!
//! This module owns the production host-side runtimes that bridge synchronous
//! scheduler node steps to real-time child I/O. It is a host-nondeterminism
//! boundary: its members map shared memory and bound child liveness with host
//! time, but never fold host timing into virtual-time ordering state.

mod block_io_gate;
mod block_io_servicer;
mod block_node_gate;
mod device_host_work;
mod host_io_runtime;
mod host_parallel_gate;
mod network_io_gate;
mod network_io_servicer;
mod ninep_io_gate;
mod ninep_io_servicer;
mod node_step_gate;

pub use block_io_gate::{
    BlockIoAdvanceOutcome, QemuLiveBlockIoGateConfig, QemuLiveBlockIoGateError,
    QemuLiveBlockIoReport, run_qemu_live_block_io_gate,
};
pub use block_io_servicer::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, QemuLiveBlockIoDeliveryStep,
    QemuLiveBlockIoHostWorkPin, QemuLiveBlockIoIntakeStep, QemuLiveBlockIoObservedRequest,
    QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer, QemuLiveBlockIoServicerError,
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
    NinepIoDiagnostics, NinepIoDiagnosticsSnapshot, QemuLive9pIoServiceStep, QemuLive9pIoServicer,
    QemuLive9pIoServicerError,
};
pub use node_step_gate::{
    QemuLiveExactSnapshotReport, QemuLiveNodeStepGateConfig, QemuLiveNodeStepGateError,
    QemuLiveNodeStepQuantum, QemuLiveNodeStepReport, QemuLiveNodeStepSchedule,
    launch_qemu_live_node, launch_qemu_live_node_exact_snapshot, launch_qemu_live_node_restored,
    run_qemu_live_exact_snapshot_gate, run_qemu_live_node_step_gate,
};
