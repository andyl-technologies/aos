//! Versioned QEMU-owned hot-fork coordination contracts.
//!
//! The template coordinator owns the retained acquisition and rollback of
//! subsystem barriers. Aggregate states authenticate each required quiescence
//! class without exposing independent observational inventory queries.

mod async_worker_barrier;
mod block_barrier;
mod child_console;
mod child_files;
mod child_process;
mod child_process_contract;
mod child_qmp;
mod child_runtime;
mod diagnostics;
mod fork;
mod plugin;
mod plugin_endpoints;
mod private_rings;
mod rcu_barrier;
mod template;
pub(crate) use async_worker_barrier::QmpHotForkAsyncWorkerBarrierState;
pub(crate) use async_worker_barrier::parse_hot_fork_async_worker_barrier_state;
pub use async_worker_barrier::{
    QMP_HOT_FORK_ASYNC_WORKER_BARRIER_COMMAND, QMP_HOT_FORK_ASYNC_WORKER_BARRIER_SCHEMA_VERSION,
};
pub(crate) use block_barrier::parse_hot_fork_block_barrier_state;
pub use block_barrier::{
    QMP_HOT_FORK_BLOCK_BARRIER_COMMAND, QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION,
    QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES, QMP_HOT_FORK_BLOCK_SOURCE_PROOF_SCHEMA_VERSION,
    QmpHotForkBlockBarrierState, QmpHotForkBlockSnapshotBinding,
    QmpHotForkBlockSnapshotBindingError, QmpHotForkBlockSnapshotRoot, QmpHotForkBlockSourceProof,
};
pub(crate) use child_console::parse_hot_fork_child_console_state;
pub use child_console::{
    QMP_HOT_FORK_CHILD_CONSOLE_COMMAND, QMP_HOT_FORK_CHILD_CONSOLE_SCHEMA_VERSION,
    QmpHotForkChildConsoleState,
};
pub(crate) use child_files::{HotForkChildFilesAction, parse_hot_fork_child_files_state};
pub use child_files::{
    QMP_HOT_FORK_CHILD_FILES_COMMAND, QMP_HOT_FORK_CHILD_FILES_MAX,
    QMP_HOT_FORK_CHILD_FILES_SCHEMA_VERSION, QmpHotForkChildFile, QmpHotForkChildFileRoot,
    QmpHotForkChildFilesState,
};
pub(crate) use child_process::{HotForkChildProcessAction, parse_hot_fork_child_process_state};
pub use child_process::{
    QMP_HOT_FORK_CHILD_PROCESS_COMMAND, QMP_HOT_FORK_CHILD_PROCESS_SCHEMA_VERSION,
    QmpHotForkChildProcessPhase, QmpHotForkChildProcessState,
};
pub(crate) use child_process_contract::{
    HotForkChildProcessContractAction, parse_hot_fork_child_process_contract_state,
};
pub use child_process_contract::{
    QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_COMMAND,
    QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_SCHEMA_VERSION, QmpHotForkChildProcessContractIdentity,
    QmpHotForkChildProcessContractNames, QmpHotForkChildProcessContractState,
};
pub(crate) use child_qmp::parse_hot_fork_child_qmp_state;
pub use child_qmp::{
    QMP_HOT_FORK_CHILD_QMP_COMMAND, QMP_HOT_FORK_CHILD_QMP_SCHEMA_VERSION, QmpHotForkChildQmpState,
};
pub(crate) use child_runtime::parse_hot_fork_child_runtime_state;
pub use child_runtime::{QmpHotForkChildRuntimePhase, QmpHotForkChildRuntimeState};
pub(crate) use diagnostics::parse_hot_fork_child_diagnostic_state;
pub use diagnostics::{
    QMP_HOT_FORK_CHILD_DIAGNOSTICS_COMMAND, QMP_HOT_FORK_CHILD_DIAGNOSTICS_SCHEMA_VERSION,
    QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD, QmpHotForkChildDiagnosticState,
};
pub(crate) use fork::parse_hot_fork_state;
pub use fork::{
    QMP_HOT_FORK_COMMAND, QMP_HOT_FORK_SCHEMA_VERSION, QmpHotForkOutcome, QmpHotForkRequest,
    QmpHotForkRequestError, QmpHotForkState,
};
pub use plugin::{QmpHotForkPluginBarrierState, QmpHotForkPluginResourceInventory};
pub(super) use plugin::{
    parse_hot_fork_plugin_barrier_state, parse_hot_fork_plugin_resource_inventory,
};
pub(crate) use plugin_endpoints::parse_hot_fork_plugin_endpoint_state;
pub use plugin_endpoints::{
    QMP_HOT_FORK_PLUGIN_ENDPOINTS_COMMAND, QMP_HOT_FORK_PLUGIN_ENDPOINTS_SCHEMA_VERSION,
    QmpHotForkPluginEndpointDescriptorPlan, QmpHotForkPluginEndpointIdentity,
    QmpHotForkPluginEndpointState,
};
pub(crate) use private_rings::parse_hot_fork_private_ring_state;
pub(crate) use private_rings::source_mapping_extent;
pub use private_rings::{
    QMP_HOT_FORK_PRIVATE_RINGS_COMMAND, QMP_HOT_FORK_PRIVATE_RINGS_SCHEMA_VERSION,
    QmpHotForkPrivateRingState,
};
pub(crate) use rcu_barrier::parse_hot_fork_rcu_barrier_state;
pub use rcu_barrier::{
    QMP_HOT_FORK_RCU_BARRIER_COMMAND, QMP_HOT_FORK_RCU_BARRIER_SCHEMA_VERSION,
    QmpHotForkRcuBarrierState,
};
pub(crate) use template::parse_hot_fork_template_state;
pub use template::{
    QMP_HOT_FORK_TEMPLATE_COMMAND, QMP_HOT_FORK_TEMPLATE_RESOURCE_STAGE_SCHEMA_VERSION,
    QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION, QmpHotForkTemplateFailureStage,
    QmpHotForkTemplateOutcome, QmpHotForkTemplateResourceStageState, QmpHotForkTemplateState,
};

/// QMP command name used for QEMU's sealed plugin-resource inventory.
pub const QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-plugin-resource-inventory";
/// QMP command name used for QEMU's registered child-runtime observation.
pub const QMP_QUERY_HOT_FORK_CHILD_RUNTIME_COMMAND: &str = "query-crucible-hot-fork-child-runtime";
/// QMP command name used for the reversible plugin callback barrier.
pub const QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND: &str = "crucible-hot-fork-plugin-barrier";
/// Version of the QEMU-owned plugin-resource inventory contract.
pub const QMP_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_SCHEMA_VERSION: u32 = 3;
/// Version of the QEMU-owned plugin callback-and-ring barrier contract.
pub const QMP_HOT_FORK_PLUGIN_BARRIER_SCHEMA_VERSION: u32 = 6;
/// Version of the QEMU-owned child-runtime observation contract.
pub const QMP_HOT_FORK_CHILD_RUNTIME_SCHEMA_VERSION: u32 = 3;
/// Proof bitmap retained by template preparation before child-only proofs run.
pub const QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS: u64 = (1_u64 << 7) - 1;

// The aggregate barriers validate QEMU's bounded subsystem counts without
// exposing the raw inventory query surface.
const QMP_HOT_FORK_RCU_INVENTORY_MAX: usize = 65_536;
const QMP_HOT_FORK_AIO_INVENTORY_MAX: usize = 65_536;
const QMP_HOT_FORK_AIO_HANDLER_INVENTORY_MAX: usize = 65_536;
const QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX: usize = 65_536;
const QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_MAX: usize = 65_536;
const QMP_HOT_FORK_TIMER_INVENTORY_MAX: usize = 65_536;
const QMP_HOT_FORK_PLUGIN_RESOURCE_REQUIRED: u64 = (1_u64 << 10) - 1;
const QMP_HOT_FORK_PLUGIN_RESOURCE_ALL: u64 = QMP_HOT_FORK_PLUGIN_RESOURCE_REQUIRED
    | QMP_HOT_FORK_PLUGIN_RESOURCE_COVERAGE
    | QMP_HOT_FORK_PLUGIN_RESOURCE_WHITEBOX
    | QMP_HOT_FORK_PLUGIN_RESOURCE_FINGERPRINT
    | QMP_HOT_FORK_PLUGIN_RESOURCE_APP_RANDOM;
const QMP_HOT_FORK_PLUGIN_RESOURCE_COVERAGE: u64 = 1_u64 << 10;
const QMP_HOT_FORK_PLUGIN_RESOURCE_WHITEBOX: u64 = 1_u64 << 11;
const QMP_HOT_FORK_PLUGIN_RESOURCE_FINGERPRINT: u64 = 1_u64 << 12;
const QMP_HOT_FORK_PLUGIN_RESOURCE_APP_RANDOM: u64 = 1_u64 << 14;
const QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED: u64 = ((1_u64 << 12) - 1) & !(1_u64 << 1);
const QMP_HOT_FORK_PLUGIN_CALLBACK_TB_TRANSLATION: u64 = 1_u64 << 12;
const QMP_HOT_FORK_PLUGIN_CALLBACK_FLUSH: u64 = 1_u64 << 13;
const QMP_HOT_FORK_PLUGIN_CALLBACK_ALL: u64 = QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED
    | QMP_HOT_FORK_PLUGIN_CALLBACK_TB_TRANSLATION
    | QMP_HOT_FORK_PLUGIN_CALLBACK_FLUSH;
const QMP_HOT_FORK_PLUGIN_WORKER_RUN_CONTROL: u64 = 1_u64 << 0;
const QMP_HOT_FORK_PLUGIN_WORKER_TEARDOWN: u64 = 1_u64 << 1;
const QMP_HOT_FORK_PLUGIN_WORKER_FINGERPRINT: u64 = 1_u64 << 2;
const QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED: u64 =
    QMP_HOT_FORK_PLUGIN_WORKER_RUN_CONTROL | QMP_HOT_FORK_PLUGIN_WORKER_TEARDOWN;
const QMP_HOT_FORK_PLUGIN_WORKER_ALL: u64 = (1_u64 << 3) - 1;

/// One independently acknowledged hot-fork readiness proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QmpHotForkProof {
    /// Precise instruction counting is active.
    PreciseIcount = 0,
    /// The deterministic sim accelerator uses one round-robin TCG thread.
    SingleThreadedSimRoundRobin = 1,
    /// QEMU stopped at an exact boundary and completed device flushes.
    ExactPausedBoundary = 2,
    /// AIO contexts, bottom halves, and timers are drained or parked.
    AioBottomHalvesAndTimers = 3,
    /// Every relevant RCU callback and read-side section is quiescent.
    Rcu = 4,
    /// Every writable block root is at an immutable external-snapshot boundary.
    BlockSnapshot = 5,
    /// Plugin command, event, and shared-memory rings are frozen.
    PluginRings = 6,
    /// Every mapping and descriptor has a closed child disposition.
    MappingAndDescriptors = 7,
    /// Every omitted thread and process-private resource has a child reinitializer.
    ChildReinitialization = 8,
}

impl QmpHotForkProof {
    const fn mask(self) -> u64 {
        1_u64 << self as u8
    }
}
