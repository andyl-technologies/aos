//! Versioned QEMU-owned hot-fork readiness proofs.
//!
//! The readiness report and inventories authenticate which quiescence classes
//! patched QEMU can prove at the current boundary. The template coordinator
//! additionally owns the retained acquisition and rollback of implemented
//! subsystem barriers. Unknown proof and transaction contracts fail closed.

use serde_json::Value;

use super::{QmpCommandKind, QmpError};

mod bh_timer_barrier;
mod block_barrier;
mod child_console;
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
mod thread_inventory;
pub(super) use thread_inventory::parse_hot_fork_thread_inventory;
pub use thread_inventory::{
    QmpHotForkThread, QmpHotForkThreadDisposition, QmpHotForkThreadInventory,
};

pub(crate) use bh_timer_barrier::parse_hot_fork_bh_timer_barrier_state;
pub use bh_timer_barrier::{
    QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND, QMP_HOT_FORK_BH_TIMER_BARRIER_SCHEMA_VERSION,
    QmpHotForkBhTimerBarrierState,
};
pub(crate) use block_barrier::parse_hot_fork_block_barrier_state;
pub use block_barrier::{
    QMP_HOT_FORK_BLOCK_BARRIER_COMMAND, QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION,
    QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES, QmpHotForkBlockBarrierState,
    QmpHotForkBlockSnapshotBinding, QmpHotForkBlockSnapshotBindingError,
    QmpHotForkBlockSnapshotRoot,
};
pub(crate) use child_console::parse_hot_fork_child_console_state;
pub use child_console::{
    QMP_HOT_FORK_CHILD_CONSOLE_COMMAND, QMP_HOT_FORK_CHILD_CONSOLE_SCHEMA_VERSION,
    QmpHotForkChildConsoleState,
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
    QmpHotForkChildProcessContractState,
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
    QMP_HOT_FORK_TEMPLATE_COMMAND, QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION, QmpHotForkTemplateOutcome,
    QmpHotForkTemplateResourceStageState, QmpHotForkTemplateState,
};

/// QMP command name used for the versioned QEMU-owned hot-fork readiness report.
pub const QMP_QUERY_HOT_FORK_READINESS_COMMAND: &str = "query-crucible-hot-fork-readiness";
/// QMP command name used for QEMU's bounded active-thread inventory.
pub const QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-thread-inventory";
/// QMP command name used for QEMU's bounded RCU-state inventory.
pub const QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND: &str = "query-crucible-hot-fork-rcu-inventory";
/// QMP command name used for QEMU's bounded AioContext activity inventory.
pub const QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND: &str = "query-crucible-hot-fork-aio-inventory";
/// QMP command name used for QEMU's bounded allocated-AIO-handler inventory.
pub const QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-aio-handler-inventory";
/// QMP command name used for QEMU's bounded allocated-block-backend inventory.
pub const QMP_QUERY_HOT_FORK_BLOCK_BACKEND_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-block-backend-inventory";
/// QMP command name used for QEMU's sealed plugin-resource inventory.
pub const QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-plugin-resource-inventory";
/// QMP command name used for QEMU's registered child-runtime observation.
pub const QMP_QUERY_HOT_FORK_CHILD_RUNTIME_COMMAND: &str = "query-crucible-hot-fork-child-runtime";
/// QMP command name used for the reversible plugin callback barrier.
pub const QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND: &str = "crucible-hot-fork-plugin-barrier";
/// QMP command name used for QEMU's bounded allocated-bottom-half inventory.
pub const QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-bottom-half-inventory";
/// QMP command name used for QEMU's bounded mutex ownership inventory.
pub const QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-mutex-inventory";
/// QMP command name used for QEMU's bounded live-timer inventory.
pub const QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-timer-inventory";
/// QMP command name used for QEMU's bounded monitor/parser inventory.
pub const QMP_QUERY_HOT_FORK_MONITOR_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-monitor-inventory";

/// Version of the QEMU-owned hot-fork proof-bit contract.
pub const QMP_HOT_FORK_READINESS_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned active-thread inventory contract.
pub const QMP_HOT_FORK_THREAD_INVENTORY_SCHEMA_VERSION: u32 = 4;
/// Version of the QEMU-owned RCU-state inventory contract.
pub const QMP_HOT_FORK_RCU_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned AioContext activity inventory contract.
pub const QMP_HOT_FORK_AIO_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned allocated-AIO-handler inventory contract.
pub const QMP_HOT_FORK_AIO_HANDLER_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned allocated-block-backend inventory contract.
pub const QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned plugin-resource inventory contract.
pub const QMP_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_SCHEMA_VERSION: u32 = 2;
/// Version of the QEMU-owned plugin callback-and-ring barrier contract.
pub const QMP_HOT_FORK_PLUGIN_BARRIER_SCHEMA_VERSION: u32 = 6;
/// Version of the QEMU-owned child-runtime observation contract.
pub const QMP_HOT_FORK_CHILD_RUNTIME_SCHEMA_VERSION: u32 = 3;
/// Version of the QEMU-owned allocated-bottom-half inventory contract.
pub const QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned mutex ownership inventory contract.
pub const QMP_HOT_FORK_MUTEX_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned live-timer inventory contract.
pub const QMP_HOT_FORK_TIMER_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned monitor/parser inventory contract.
pub const QMP_HOT_FORK_MONITOR_INVENTORY_SCHEMA_VERSION: u32 = 1;

/// Complete proof bitmap required by the version-1 hot-fork contract.
pub const QMP_HOT_FORK_REQUIRED_PROOFS: u64 = (1_u64 << 9) - 1;
/// Proof bitmap retained by template preparation before child-only proofs run.
pub const QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS: u64 = (1_u64 << 7) - 1;
/// Maximum active QEMU-created threads retained by one inventory response.
pub const QMP_HOT_FORK_THREAD_INVENTORY_MAX: usize = 65_536;
/// Maximum registered RCU readers retained by one inventory response.
pub const QMP_HOT_FORK_RCU_INVENTORY_MAX: usize = 65_536;
/// Maximum registered AioContexts retained by one inventory response.
pub const QMP_HOT_FORK_AIO_INVENTORY_MAX: usize = 65_536;
/// Maximum allocated AIO handlers retained by one inventory response.
pub const QMP_HOT_FORK_AIO_HANDLER_INVENTORY_MAX: usize = 65_536;
/// Maximum allocated block backends retained by one inventory response.
pub const QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX: usize = 65_536;
/// Maximum allocated bottom halves retained by one inventory response.
pub const QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_MAX: usize = 65_536;
/// Maximum registered mutexes retained by one inventory response.
pub const QMP_HOT_FORK_MUTEX_INVENTORY_MAX: usize = 65_536;
/// Maximum unique pending or callback-active timers retained by one response.
pub const QMP_HOT_FORK_TIMER_INVENTORY_MAX: usize = 65_536;
/// Maximum monitors charged by one inventory response.
pub const QMP_HOT_FORK_MONITOR_INVENTORY_MAX: usize = 256;
/// Maximum UTF-8 bytes retained for one QEMU thread name.
pub const QMP_HOT_FORK_THREAD_NAME_MAX_BYTES: usize = 256;
/// Maximum UTF-8 bytes retained for one QEMU bottom-half diagnostic name.
pub const QMP_HOT_FORK_BOTTOM_HALF_NAME_MAX_BYTES: usize = 128;
/// Maximum UTF-8 bytes retained for one block-backend monitor name.
pub const QMP_HOT_FORK_BLOCK_BACKEND_NAME_MAX_BYTES: usize = 255;

const QMP_HOT_FORK_PLUGIN_RESOURCE_REQUIRED: u64 = (1_u64 << 10) - 1;
const QMP_HOT_FORK_PLUGIN_RESOURCE_ALL: u64 = (1_u64 << 15) - 1;
const QMP_HOT_FORK_PLUGIN_RESOURCE_COVERAGE: u64 = 1_u64 << 10;
const QMP_HOT_FORK_PLUGIN_RESOURCE_WHITEBOX: u64 = 1_u64 << 11;
const QMP_HOT_FORK_PLUGIN_RESOURCE_FINGERPRINT: u64 = 1_u64 << 12;
const QMP_HOT_FORK_PLUGIN_RESOURCE_STATE_DUMP: u64 = 1_u64 << 13;
const QMP_HOT_FORK_PLUGIN_RESOURCE_APP_RANDOM: u64 = 1_u64 << 14;
const QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED: u64 = ((1_u64 << 12) - 1) & !(1_u64 << 1);
const QMP_HOT_FORK_PLUGIN_CALLBACK_ALL: u64 = (1_u64 << 14) - 1;
const QMP_HOT_FORK_PLUGIN_CALLBACK_TB_TRANSLATION: u64 = 1_u64 << 12;
const QMP_HOT_FORK_PLUGIN_CALLBACK_FLUSH: u64 = 1_u64 << 13;
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
    const ALL: [Self; 9] = [
        Self::PreciseIcount,
        Self::SingleThreadedSimRoundRobin,
        Self::ExactPausedBoundary,
        Self::AioBottomHalvesAndTimers,
        Self::Rcu,
        Self::BlockSnapshot,
        Self::PluginRings,
        Self::MappingAndDescriptors,
        Self::ChildReinitialization,
    ];

    const fn mask(self) -> u64 {
        1_u64 << self as u8
    }
}

/// Exact typed hot-fork readiness report returned by patched QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkReadiness {
    acknowledged_proofs: u64,
    ready: bool,
}

impl QmpHotForkReadiness {
    /// Builds one valid version-1 report from its exact acknowledged bitmap.
    ///
    /// The `ready` value is derived rather than supplied, so callers cannot
    /// construct a contradictory typed report.
    #[must_use]
    pub const fn from_acknowledged_proofs(acknowledged_proofs: u64) -> Option<Self> {
        if acknowledged_proofs & !QMP_HOT_FORK_REQUIRED_PROOFS != 0 {
            return None;
        }
        Some(Self {
            acknowledged_proofs,
            ready: acknowledged_proofs == QMP_HOT_FORK_REQUIRED_PROOFS,
        })
    }

    /// Returns whether QEMU attested every required version-1 proof.
    #[must_use]
    pub const fn ready(self) -> bool {
        self.ready
    }

    /// Returns the exact acknowledged version-1 proof bitmap.
    #[must_use]
    pub const fn acknowledged_proofs(self) -> u64 {
        self.acknowledged_proofs
    }

    /// Returns whether QEMU attested one exact proof class.
    #[must_use]
    pub const fn acknowledges(self, proof: QmpHotForkProof) -> bool {
        self.acknowledged_proofs & proof.mask() != 0
    }

    /// Iterates over proof classes that QEMU did not acknowledge.
    pub fn missing_proofs(self) -> impl Iterator<Item = QmpHotForkProof> {
        QmpHotForkProof::ALL
            .into_iter()
            .filter(move |proof| !self.acknowledges(*proof))
    }
}

/// One thread registered as a QEMU RCU read-side participant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkRcuReader {
    thread_id: u32,
    active: bool,
}

impl QmpHotForkRcuReader {
    /// Returns the positive operating-system thread identifier.
    #[must_use]
    pub const fn thread_id(self) -> u32 {
        self.thread_id
    }

    /// Returns whether the reader was active at the inventory instant.
    #[must_use]
    pub const fn active(self) -> bool {
        self.active
    }
}

/// Exact bounded observational snapshot of QEMU's RCU state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkRcuInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    active_readers: usize,
    pending_callbacks: u64,
    drain_active: bool,
    readers: Vec<QmpHotForkRcuReader>,
}

impl QmpHotForkRcuInventory {
    #[cfg(test)]
    pub(crate) fn from_reader_ids(thread_ids: &[u32]) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            active_readers: 0,
            pending_callbacks: 0,
            drain_active: false,
            readers: thread_ids
                .iter()
                .copied()
                .map(|thread_id| QmpHotForkRcuReader {
                    thread_id,
                    active: false,
                })
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: true,
            active_readers: 0,
            pending_callbacks: 0,
            drain_active: false,
            readers: Vec::new(),
        }
    }

    /// Returns the process-local reader register/unregister generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether QEMU retained structurally valid identifiers for every reader.
    ///
    /// Completeness does not prove quiescence and cannot authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether registered readers exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns the exact number of retained active read-side participants.
    #[must_use]
    pub const fn active_readers(&self) -> usize {
        self.active_readers
    }

    /// Returns callbacks submitted but not yet completed.
    #[must_use]
    pub const fn pending_callbacks(&self) -> u64 {
        self.pending_callbacks
    }

    /// Returns whether `drain_call_rcu()` was active at the inventory instant.
    #[must_use]
    pub const fn drain_active(&self) -> bool {
        self.drain_active
    }

    /// Returns every retained reader in ascending thread-identifier order.
    #[must_use]
    pub fn readers(&self) -> &[QmpHotForkRcuReader] {
        &self.readers
    }
}

/// One registered QEMU AioContext and its instantaneous activity counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkAioContext {
    context_id: u64,
    home_thread_id: Option<u32>,
    active_polls: u32,
    active_dispatches: u32,
    pending_bottom_halves: u32,
    active_bottom_halves: u32,
    queued_coroutines: u32,
    notify_pending: bool,
}

impl QmpHotForkAioContext {
    /// Returns the positive process-local AioContext identifier.
    #[must_use]
    pub const fn context_id(self) -> u64 {
        self.context_id
    }

    /// Returns the assigned operating-system home thread, if it has run.
    #[must_use]
    pub const fn home_thread_id(self) -> Option<u32> {
        self.home_thread_id
    }

    /// Returns the number of active `aio_poll()` calls.
    #[must_use]
    pub const fn active_polls(self) -> u32 {
        self.active_polls
    }

    /// Returns the number of active GLib AIO dispatch calls.
    #[must_use]
    pub const fn active_dispatches(self) -> u32 {
        self.active_dispatches
    }

    /// Returns enqueued bottom halves not yet dequeued.
    #[must_use]
    pub const fn pending_bottom_halves(self) -> u32 {
        self.pending_bottom_halves
    }

    /// Returns bottom-half callbacks currently executing.
    #[must_use]
    pub const fn active_bottom_halves(self) -> u32 {
        self.active_bottom_halves
    }

    /// Returns coroutines queued through this context's scheduling bottom half.
    #[must_use]
    pub const fn queued_coroutines(self) -> u32 {
        self.queued_coroutines
    }

    /// Returns whether this context has an unaccepted notification.
    #[must_use]
    pub const fn notify_pending(self) -> bool {
        self.notify_pending
    }
}

/// Exact bounded observational snapshot of QEMU's registered AioContexts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkAioInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    contexts: Vec<QmpHotForkAioContext>,
}

impl QmpHotForkAioInventory {
    #[cfg(test)]
    pub(crate) fn one_idle(context_id: u64, home_thread_id: u32) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            contexts: vec![QmpHotForkAioContext {
                context_id,
                home_thread_id: Some(home_thread_id),
                active_polls: 0,
                active_dispatches: 0,
                pending_bottom_halves: 0,
                active_bottom_halves: 0,
                queued_coroutines: 0,
                notify_pending: false,
            }],
        }
    }

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: true,
            contexts: Vec::new(),
        }
    }

    /// Returns the process-local context lifecycle and home-assignment generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether every retained context has a valid assigned home thread.
    ///
    /// Completeness is observational and does not prove that AIO, bottom
    /// halves, handlers, or timers are drained or authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether registered contexts exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns every retained context in ascending process-local identifier order.
    #[must_use]
    pub fn contexts(&self) -> &[QmpHotForkAioContext] {
        &self.contexts
    }
}

/// One allocated POSIX QEMU AIO handler and its installed callback classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkAioHandler {
    handler_id: u64,
    context_id: u64,
    descriptor: u32,
    deleted: bool,
    read_callback: bool,
    write_callback: bool,
    poll_callback: bool,
    poll_ready_callback: bool,
    poll_begin_callback: bool,
    poll_end_callback: bool,
    active_callbacks: u32,
}

impl QmpHotForkAioHandler {
    /// Returns the positive stable process-local handler identifier.
    #[must_use]
    pub const fn handler_id(self) -> u64 {
        self.handler_id
    }

    /// Returns the positive process-local identity of the owning AioContext.
    #[must_use]
    pub const fn context_id(self) -> u64 {
        self.context_id
    }

    /// Returns the process-local file descriptor monitored by this handler.
    #[must_use]
    pub const fn descriptor(self) -> u32 {
        self.descriptor
    }

    /// Returns whether removal was requested while final free remains deferred.
    #[must_use]
    pub const fn deleted(self) -> bool {
        self.deleted
    }

    /// Returns whether a read callback is installed.
    #[must_use]
    pub const fn read_callback(self) -> bool {
        self.read_callback
    }

    /// Returns whether a write callback is installed.
    #[must_use]
    pub const fn write_callback(self) -> bool {
        self.write_callback
    }

    /// Returns whether a userspace polling callback is installed.
    #[must_use]
    pub const fn poll_callback(self) -> bool {
        self.poll_callback
    }

    /// Returns whether a polling-ready callback is installed.
    #[must_use]
    pub const fn poll_ready_callback(self) -> bool {
        self.poll_ready_callback
    }

    /// Returns whether a polling-entry callback is installed.
    #[must_use]
    pub const fn poll_begin_callback(self) -> bool {
        self.poll_begin_callback
    }

    /// Returns whether a polling-exit callback is installed.
    #[must_use]
    pub const fn poll_end_callback(self) -> bool {
        self.poll_end_callback
    }

    /// Returns the number of this handler's callbacks currently executing.
    #[must_use]
    pub const fn active_callbacks(self) -> u32 {
        self.active_callbacks
    }
}

/// Exact bounded observational snapshot of every allocated POSIX AIO handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkAioHandlerInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    handlers: Vec<QmpHotForkAioHandler>,
}

impl QmpHotForkAioHandlerInventory {
    #[cfg(test)]
    pub(crate) fn one_read(handler_id: u64, context_id: u64, descriptor: u32) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            handlers: vec![QmpHotForkAioHandler {
                handler_id,
                context_id,
                descriptor,
                deleted: false,
                read_callback: true,
                write_callback: false,
                poll_callback: false,
                poll_ready_callback: false,
                poll_begin_callback: false,
                poll_end_callback: false,
                active_callbacks: 0,
            }],
        }
    }

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: true,
            handlers: Vec::new(),
        }
    }

    /// Returns the process-local lifecycle, callback-set, and activity generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether every allocated handler fit and was structurally valid.
    ///
    /// Completeness remains observational and cannot authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether allocated handlers exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns every allocated handler in ascending identifier order.
    #[must_use]
    pub fn handlers(&self) -> &[QmpHotForkAioHandler] {
        &self.handlers
    }
}

/// One allocated QEMU block backend and its instantaneous operational state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkBlockBackend {
    backend_id: u64,
    context_id: u64,
    reference_count: u32,
    name: String,
    named: bool,
    name_valid: bool,
    root_present: bool,
    device_attached: bool,
    permissions: u64,
    shared_permissions: u64,
    write_permission: bool,
    permissions_disabled: bool,
    quiesce_depth: u32,
    in_flight: u32,
    request_queuing_disabled: bool,
}

impl QmpHotForkBlockBackend {
    /// Returns the positive stable process-local backend identifier.
    #[must_use]
    pub const fn backend_id(&self) -> u64 {
        self.backend_id
    }

    /// Returns the positive process-local identity of the owning AioContext.
    #[must_use]
    pub const fn context_id(&self) -> u64 {
        self.context_id
    }

    /// Returns the current positive backend reference count.
    #[must_use]
    pub const fn reference_count(&self) -> u32 {
        self.reference_count
    }

    /// Returns the bounded monitor name, or an empty string for a hidden backend.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the backend is visible through the monitor namespace.
    #[must_use]
    pub const fn named(&self) -> bool {
        self.named
    }

    /// Returns whether the copied monitor name is complete and canonical.
    #[must_use]
    pub const fn name_valid(&self) -> bool {
        self.name_valid
    }

    /// Returns whether the backend currently has a block-graph root.
    #[must_use]
    pub const fn root_present(&self) -> bool {
        self.root_present
    }

    /// Returns whether the backend is attached to a device model.
    #[must_use]
    pub const fn device_attached(&self) -> bool {
        self.device_attached
    }

    /// Returns the requested QEMU `BLK_PERM_*` bit mask.
    #[must_use]
    pub const fn permissions(&self) -> u64 {
        self.permissions
    }

    /// Returns the QEMU `BLK_PERM_*` mask shareable with other users.
    #[must_use]
    pub const fn shared_permissions(&self) -> u64 {
        self.shared_permissions
    }

    /// Returns whether the requested mask includes `BLK_PERM_WRITE`.
    #[must_use]
    pub const fn write_permission(&self) -> bool {
        self.write_permission
    }

    /// Returns whether inactive or migration state suppresses requested permissions.
    #[must_use]
    pub const fn permissions_disabled(&self) -> bool {
        self.permissions_disabled
    }

    /// Returns the instantaneous nested drained-section depth.
    #[must_use]
    pub const fn quiesce_depth(&self) -> u32 {
        self.quiesce_depth
    }

    /// Returns the instantaneous number of in-flight backend I/O requests.
    #[must_use]
    pub const fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// Returns whether drained requests fail instead of waiting in the queue.
    #[must_use]
    pub const fn request_queuing_disabled(&self) -> bool {
        self.request_queuing_disabled
    }
}

/// Exact bounded observational snapshot of every allocated QEMU block backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkBlockBackendInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    backends: Vec<QmpHotForkBlockBackend>,
}

impl QmpHotForkBlockBackendInventory {
    #[cfg(test)]
    pub(crate) fn one_hidden(backend_id: u64, context_id: u64) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            backends: vec![QmpHotForkBlockBackend {
                backend_id,
                context_id,
                reference_count: 1,
                name: String::new(),
                named: false,
                name_valid: true,
                root_present: true,
                device_attached: false,
                permissions: 2,
                shared_permissions: u64::MAX,
                write_permission: true,
                permissions_disabled: false,
                quiesce_depth: 0,
                in_flight: 0,
                request_queuing_disabled: false,
            }],
        }
    }

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: true,
            backends: Vec::new(),
        }
    }

    /// Returns the process-local lifecycle and structural-state generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether every allocated backend fit and was structurally valid.
    ///
    /// Completeness remains observational and cannot authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether allocated backends exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns every allocated backend in ascending identifier order.
    #[must_use]
    pub fn backends(&self) -> &[QmpHotForkBlockBackend] {
        &self.backends
    }
}

/// One allocated QEMU bottom half and its instantaneous lifecycle state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkBottomHalf {
    bottom_half_id: u64,
    context_id: u64,
    name: String,
    name_valid: bool,
    pending: bool,
    scheduled: bool,
    deleted: bool,
    oneshot: bool,
    idle: bool,
    active_callbacks: u32,
}

impl QmpHotForkBottomHalf {
    /// Returns the positive stable process-local bottom-half identifier.
    #[must_use]
    pub const fn bottom_half_id(&self) -> u64 {
        self.bottom_half_id
    }

    /// Returns the positive process-local identity of the owning AioContext.
    #[must_use]
    pub const fn context_id(&self) -> u64 {
        self.context_id
    }

    /// Returns the bounded copied diagnostic callback name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the name is the exact nonempty creation-time value.
    #[must_use]
    pub const fn name_valid(&self) -> bool {
        self.name_valid
    }

    /// Returns whether the bottom half is enqueued for dispatch.
    #[must_use]
    pub const fn pending(&self) -> bool {
        self.pending
    }

    /// Returns whether the pending bottom half is scheduled rather than idle.
    #[must_use]
    pub const fn scheduled(&self) -> bool {
        self.scheduled
    }

    /// Returns whether deletion was requested and final free is deferred.
    #[must_use]
    pub const fn deleted(&self) -> bool {
        self.deleted
    }

    /// Returns whether the bottom half is a self-deleting one-shot callback.
    #[must_use]
    pub const fn oneshot(&self) -> bool {
        self.oneshot
    }

    /// Returns whether the pending bottom half was scheduled as idle work.
    #[must_use]
    pub const fn idle(&self) -> bool {
        self.idle
    }

    /// Returns the number of callbacks currently executing.
    #[must_use]
    pub const fn active_callbacks(&self) -> u32 {
        self.active_callbacks
    }
}

/// Exact bounded observational snapshot of every allocated QEMU bottom half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkBottomHalfInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    stable: bool,
    bottom_halves: Vec<QmpHotForkBottomHalf>,
}

impl QmpHotForkBottomHalfInventory {
    #[cfg(test)]
    pub(crate) fn one_idle(bottom_half_id: u64, context_id: u64) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            stable: true,
            bottom_halves: vec![QmpHotForkBottomHalf {
                bottom_half_id,
                context_id,
                name: "test-bottom-half".to_owned(),
                name_valid: true,
                pending: false,
                scheduled: false,
                deleted: false,
                oneshot: false,
                idle: false,
                active_callbacks: 0,
            }],
        }
    }

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: false,
            stable: false,
            bottom_halves: Vec::new(),
        }
    }

    /// Returns the process-local lifecycle and state generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether the bounded registry snapshot is stable and valid.
    ///
    /// Completeness remains observational and cannot authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether allocated bottom halves exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns whether no bottom-half transition raced the bounded copy.
    #[must_use]
    pub const fn stable(&self) -> bool {
        self.stable
    }

    /// Returns every allocated bottom half in ascending identifier order.
    #[must_use]
    pub fn bottom_halves(&self) -> &[QmpHotForkBottomHalf] {
        &self.bottom_halves
    }
}

/// One live QEMU mutex and its instantaneous ownership state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkMutex {
    mutex_id: u64,
    owner_thread_id: Option<u32>,
    recursion_depth: u32,
    acquisition_waiters: u32,
    condition_waiters: u32,
    recursive: bool,
    unlock_active: bool,
    ownership_valid: bool,
}

impl QmpHotForkMutex {
    /// Returns the positive process-local mutex identifier.
    #[must_use]
    pub const fn mutex_id(self) -> u64 {
        self.mutex_id
    }

    /// Returns the operating-system owner thread, if held.
    #[must_use]
    pub const fn owner_thread_id(self) -> Option<u32> {
        self.owner_thread_id
    }

    /// Returns the current recursive ownership depth.
    #[must_use]
    pub const fn recursion_depth(self) -> u32 {
        self.recursion_depth
    }

    /// Returns threads currently inside lock acquisition.
    #[must_use]
    pub const fn acquisition_waiters(self) -> u32 {
        self.acquisition_waiters
    }

    /// Returns threads sleeping or reacquiring through a condition wait.
    #[must_use]
    pub const fn condition_waiters(self) -> u32 {
        self.condition_waiters
    }

    /// Returns whether this record describes a recursive mutex.
    #[must_use]
    pub const fn recursive(self) -> bool {
        self.recursive
    }

    /// Returns whether an owner is inside the unlock transition.
    #[must_use]
    pub const fn unlock_active(self) -> bool {
        self.unlock_active
    }

    /// Returns whether every observed ownership transition was valid.
    #[must_use]
    pub const fn ownership_valid(self) -> bool {
        self.ownership_valid
    }
}

/// Exact bounded observational snapshot of QEMU mutex ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkMutexInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    mutexes: Vec<QmpHotForkMutex>,
}

impl QmpHotForkMutexInventory {
    #[cfg(test)]
    pub(crate) fn one_owned(mutex_id: u64, owner_thread_id: u32) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            mutexes: vec![QmpHotForkMutex {
                mutex_id,
                owner_thread_id: Some(owner_thread_id),
                recursion_depth: 1,
                acquisition_waiters: 0,
                condition_waiters: 0,
                recursive: false,
                unlock_active: false,
                ownership_valid: true,
            }],
        }
    }

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: true,
            mutexes: Vec::new(),
        }
    }

    /// Returns the process-local mutex lifecycle generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether the bounded registry and ownership records are valid.
    ///
    /// Completeness is observational and does not prove that omitted threads
    /// hold no locks across a later fork operation.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether live mutexes exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns every retained mutex in ascending process-local identifier order.
    #[must_use]
    pub fn mutexes(&self) -> &[QmpHotForkMutex] {
        &self.mutexes
    }
}

/// QEMU clock driving one live timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpHotForkTimerClock {
    /// Monotonic host real time.
    Realtime,
    /// Guest virtual time.
    Virtual,
    /// Host wall time.
    Host,
    /// Real time used for virtual-clock icount warp.
    VirtualRealtime,
}

/// One pending QEMU timer, executing callback, or both when rearmed in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkTimer {
    timer_id: u64,
    timer_list_id: u64,
    clock: QmpHotForkTimerClock,
    expire_time_ns: Option<u64>,
    scale: u32,
    attributes: u32,
    pending: bool,
    callback_active: bool,
}

impl QmpHotForkTimer {
    /// Returns the positive process-local timer identifier.
    #[must_use]
    pub const fn timer_id(self) -> u64 {
        self.timer_id
    }

    /// Returns the positive process-local timer-list identifier.
    #[must_use]
    pub const fn timer_list_id(self) -> u64 {
        self.timer_list_id
    }

    /// Returns the clock driving this timer.
    #[must_use]
    pub const fn clock(self) -> QmpHotForkTimerClock {
        self.clock
    }

    /// Returns the absolute nanosecond expiry while the timer is pending.
    #[must_use]
    pub const fn expire_time_ns(self) -> Option<u64> {
        self.expire_time_ns
    }

    /// Returns the timer's positive nanosecond unit scale.
    #[must_use]
    pub const fn scale(self) -> u32 {
        self.scale
    }

    /// Returns the exact unsigned QEMU timer-attribute bitmap.
    #[must_use]
    pub const fn attributes(self) -> u32 {
        self.attributes
    }

    /// Returns whether the timer is scheduled.
    #[must_use]
    pub const fn pending(self) -> bool {
        self.pending
    }

    /// Returns whether the timer callback is executing.
    #[must_use]
    pub const fn callback_active(self) -> bool {
        self.callback_active
    }
}

/// Exact bounded observational snapshot of QEMU's live timer state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkTimerInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    timers: Vec<QmpHotForkTimer>,
}

impl QmpHotForkTimerInventory {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            timers: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: true,
            timers: Vec::new(),
        }
    }

    /// Returns the process-local scheduled/callback state generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether QEMU retained structurally valid state for every live timer.
    ///
    /// Completeness remains observational and cannot authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether live timer state exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns every retained timer in ascending process-local identifier order.
    #[must_use]
    pub fn timers(&self) -> &[QmpHotForkTimer] {
        &self.timers
    }
}

/// Exact bounded observational snapshot of QEMU monitor and parser state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkMonitorInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    monitor_count: u32,
    qmp_monitors: u32,
    hmp_monitors: u32,
    io_thread_monitors: u32,
    suspended_monitors: u32,
    negotiating_monitors: u32,
    oob_enabled_monitors: u32,
    queued_requests: u64,
    parser_buffered_bytes: u64,
    partial_parsers: u32,
    unstable_monitors: u32,
}

impl QmpHotForkMonitorInventory {
    #[cfg(test)]
    pub(crate) const fn one_supported() -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            monitor_count: 1,
            qmp_monitors: 1,
            hmp_monitors: 0,
            io_thread_monitors: 1,
            suspended_monitors: 0,
            negotiating_monitors: 0,
            oob_enabled_monitors: 1,
            queued_requests: 0,
            parser_buffered_bytes: 0,
            partial_parsers: 0,
            unstable_monitors: 0,
        }
    }

    #[cfg(test)]
    pub(crate) const fn incomplete() -> Self {
        Self {
            complete: false,
            unstable_monitors: 1,
            ..Self::one_supported()
        }
    }

    #[cfg(test)]
    pub(crate) const fn one_queued() -> Self {
        Self {
            queued_requests: 1,
            ..Self::one_supported()
        }
    }

    /// Returns the process-local monitor lifecycle generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns whether every bounded monitor/parser record was stable.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.complete
    }

    /// Returns whether a count or aggregate exceeded its retained bound.
    #[must_use]
    pub const fn overflowed(self) -> bool {
        self.overflowed
    }

    /// Returns the retained monitor count.
    #[must_use]
    pub const fn monitor_count(self) -> u32 {
        self.monitor_count
    }

    /// Returns the number of retained QMP monitors.
    #[must_use]
    pub const fn qmp_monitors(self) -> u32 {
        self.qmp_monitors
    }

    /// Returns the number of retained human monitors.
    #[must_use]
    pub const fn hmp_monitors(self) -> u32 {
        self.hmp_monitors
    }

    /// Returns the number of monitors hosted by the monitor I/O thread.
    #[must_use]
    pub const fn io_thread_monitors(self) -> u32 {
        self.io_thread_monitors
    }

    /// Returns the number of monitors whose input is suspended.
    #[must_use]
    pub const fn suspended_monitors(self) -> u32 {
        self.suspended_monitors
    }

    /// Returns QMP monitors still negotiating capabilities.
    #[must_use]
    pub const fn negotiating_monitors(self) -> u32 {
        self.negotiating_monitors
    }

    /// Returns QMP monitors with out-of-band commands enabled.
    #[must_use]
    pub const fn oob_enabled_monitors(self) -> u32 {
        self.oob_enabled_monitors
    }

    /// Returns queued in-band QMP requests.
    #[must_use]
    pub const fn queued_requests(self) -> u64 {
        self.queued_requests
    }

    /// Returns bytes retained by partial JSON parser state.
    #[must_use]
    pub const fn parser_buffered_bytes(self) -> u64 {
        self.parser_buffered_bytes
    }

    /// Returns parsers retaining a partial JSON message.
    #[must_use]
    pub const fn partial_parsers(self) -> u32 {
        self.partial_parsers
    }

    /// Returns QMP monitors whose parser was busy during the snapshot.
    #[must_use]
    pub const fn unstable_monitors(self) -> u32 {
        self.unstable_monitors
    }

    /// Returns whether this is the one supported parent-template profile.
    #[must_use]
    pub const fn is_supported_parent_profile(self) -> bool {
        self.complete
            && !self.overflowed
            && self.monitor_count == 1
            && self.qmp_monitors == 1
            && self.hmp_monitors == 0
            && self.io_thread_monitors == 1
            && self.suspended_monitors == 0
            && self.negotiating_monitors == 0
            && self.oob_enabled_monitors == 1
            && self.queued_requests == 0
            && self.parser_buffered_bytes == 0
            && self.partial_parsers == 0
            && self.unstable_monitors == 0
    }
}

pub(super) fn parse_hot_fork_readiness(value: &Value) -> Result<QmpHotForkReadiness, QmpError> {
    let schema_version = value.get("schema-version").and_then(Value::as_u64);
    let required_proofs = value.get("required-proofs").and_then(Value::as_u64);
    let acknowledged_proofs = value.get("acknowledged-proofs").and_then(Value::as_u64);
    let ready = value.get("ready").and_then(Value::as_bool);

    match (schema_version, required_proofs, acknowledged_proofs, ready) {
        (Some(schema_version), Some(required_proofs), Some(acknowledged_proofs), Some(ready))
            if schema_version == u64::from(QMP_HOT_FORK_READINESS_SCHEMA_VERSION)
                && required_proofs == QMP_HOT_FORK_REQUIRED_PROOFS
                && acknowledged_proofs & !required_proofs == 0
                && ready == (acknowledged_proofs == required_proofs) =>
        {
            QmpHotForkReadiness::from_acknowledged_proofs(acknowledged_proofs).ok_or_else(|| {
                QmpError::MalformedTypedResponse {
                    command: QmpCommandKind::QueryHotForkReadiness,
                    response: value.to_string(),
                }
            })
        }
        _ => Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::QueryHotForkReadiness,
            response: value.to_string(),
        }),
    }
}

pub(super) fn parse_hot_fork_rcu_inventory(
    value: &Value,
) -> Result<QmpHotForkRcuInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkRcuInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    if object.len() != 9
        || ![
            "schema-version",
            "generation",
            "complete",
            "overflowed",
            "registered-readers",
            "active-readers",
            "pending-callbacks",
            "drain-active",
            "readers",
        ]
        .iter()
        .all(|field| object.contains_key(*field))
    {
        return Err(malformed());
    }
    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let registered_readers = object
        .get("registered-readers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_active_readers = object
        .get("active-readers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let pending_callbacks = object
        .get("pending-callbacks")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let drain_active = object
        .get("drain-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let values = object
        .get("readers")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_RCU_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_RCU_INVENTORY_MAX
        || registered_readers != values.len()
    {
        return Err(malformed());
    }

    let mut readers = Vec::with_capacity(values.len());
    let mut previous_thread_id = None;
    let mut active_readers = 0_usize;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        if entry.len() != 2
            || !["thread-id", "active"]
                .iter()
                .all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }
        let thread_id = entry
            .get("thread-id")
            .and_then(Value::as_i64)
            .and_then(|thread_id| u32::try_from(thread_id).ok())
            .filter(|thread_id| *thread_id != 0)
            .ok_or_else(&malformed)?;
        if previous_thread_id.is_some_and(|previous| previous >= thread_id) {
            return Err(malformed());
        }
        previous_thread_id = Some(thread_id);
        let active = entry
            .get("active")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        active_readers += usize::from(active);
        readers.push(QmpHotForkRcuReader { thread_id, active });
    }
    if declared_active_readers != active_readers || complete == overflowed {
        return Err(malformed());
    }
    Ok(QmpHotForkRcuInventory {
        generation,
        complete,
        overflowed,
        active_readers,
        pending_callbacks,
        drain_active,
        readers,
    })
}

pub(super) fn parse_hot_fork_aio_inventory(
    value: &Value,
) -> Result<QmpHotForkAioInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkAioInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "context-count",
        "assigned-contexts",
        "active-polls",
        "active-dispatches",
        "pending-bottom-halves",
        "active-bottom-halves",
        "queued-coroutines",
        "contexts",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_contexts = object
        .get("context-count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_assigned = object
        .get("assigned-contexts")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let aggregate_fields = [
        "active-polls",
        "active-dispatches",
        "pending-bottom-halves",
        "active-bottom-halves",
        "queued-coroutines",
    ];
    let mut declared_aggregates = [0_u64; 5];
    for (index, field) in aggregate_fields.iter().enumerate() {
        declared_aggregates[index] = object
            .get(*field)
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?;
    }
    let values = object
        .get("contexts")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_AIO_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_AIO_INVENTORY_MAX
        || declared_contexts != values.len()
    {
        return Err(malformed());
    }

    let mut contexts = Vec::with_capacity(values.len());
    let mut previous_context_id = None;
    let mut assigned_contexts = 0_usize;
    let mut actual_aggregates = [0_u64; 5];
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        let entry_fields = [
            "context-id",
            "home-thread-id",
            "active-polls",
            "active-dispatches",
            "pending-bottom-halves",
            "active-bottom-halves",
            "queued-coroutines",
            "notify-pending",
        ];
        if entry.len() != entry_fields.len()
            || !entry_fields.iter().all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }
        let context_id = entry
            .get("context-id")
            .and_then(Value::as_u64)
            .filter(|context_id| *context_id != 0)
            .ok_or_else(&malformed)?;
        if previous_context_id.is_some_and(|previous| previous >= context_id) {
            return Err(malformed());
        }
        previous_context_id = Some(context_id);
        let home_thread_id = match entry.get("home-thread-id").and_then(Value::as_i64) {
            Some(0) => None,
            Some(thread_id) => Some(
                u32::try_from(thread_id)
                    .ok()
                    .filter(|thread_id| *thread_id != 0)
                    .ok_or_else(&malformed)?,
            ),
            None => return Err(malformed()),
        };
        assigned_contexts += usize::from(home_thread_id.is_some());
        let mut counters = [0_u32; 5];
        for (index, field) in aggregate_fields.iter().enumerate() {
            counters[index] = entry
                .get(*field)
                .and_then(Value::as_u64)
                .and_then(|count| u32::try_from(count).ok())
                .ok_or_else(&malformed)?;
            actual_aggregates[index] = actual_aggregates[index]
                .checked_add(u64::from(counters[index]))
                .ok_or_else(&malformed)?;
        }
        let notify_pending = entry
            .get("notify-pending")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        contexts.push(QmpHotForkAioContext {
            context_id,
            home_thread_id,
            active_polls: counters[0],
            active_dispatches: counters[1],
            pending_bottom_halves: counters[2],
            active_bottom_halves: counters[3],
            queued_coroutines: counters[4],
            notify_pending,
        });
    }
    if declared_assigned != assigned_contexts
        || declared_aggregates != actual_aggregates
        || complete != (!overflowed && assigned_contexts == contexts.len())
    {
        return Err(malformed());
    }
    Ok(QmpHotForkAioInventory {
        generation,
        complete,
        overflowed,
        contexts,
    })
}

pub(super) fn parse_hot_fork_aio_handler_inventory(
    value: &Value,
) -> Result<QmpHotForkAioHandlerInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkAioHandlerInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "handler-count",
        "read-handlers",
        "write-handlers",
        "poll-handlers",
        "deleted-handlers",
        "active-callbacks",
        "handlers",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_count = object
        .get("handler-count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_read = object
        .get("read-handlers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_write = object
        .get("write-handlers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_poll = object
        .get("poll-handlers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_deleted = object
        .get("deleted-handlers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_active_callbacks = object
        .get("active-callbacks")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let values = object
        .get("handlers")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_AIO_HANDLER_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_AIO_HANDLER_INVENTORY_MAX
        || declared_count != values.len()
    {
        return Err(malformed());
    }

    let entry_fields = [
        "handler-id",
        "context-id",
        "fd",
        "deleted",
        "read-callback",
        "write-callback",
        "poll-callback",
        "poll-ready-callback",
        "poll-begin-callback",
        "poll-end-callback",
        "active-callbacks",
    ];
    let mut handlers = Vec::with_capacity(values.len());
    let mut previous_handler_id = None;
    let mut read_handlers = 0_usize;
    let mut write_handlers = 0_usize;
    let mut poll_handlers = 0_usize;
    let mut deleted_handlers = 0_usize;
    let mut active_callbacks = 0_u64;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        if entry.len() != entry_fields.len()
            || !entry_fields.iter().all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }

        let handler_id = entry
            .get("handler-id")
            .and_then(Value::as_u64)
            .filter(|identifier| *identifier != 0)
            .ok_or_else(&malformed)?;
        if previous_handler_id.is_some_and(|previous| previous >= handler_id) {
            return Err(malformed());
        }
        previous_handler_id = Some(handler_id);
        let context_id = entry
            .get("context-id")
            .and_then(Value::as_u64)
            .filter(|identifier| *identifier != 0)
            .ok_or_else(&malformed)?;
        let descriptor = entry
            .get("fd")
            .and_then(Value::as_i64)
            .and_then(|descriptor| u32::try_from(descriptor).ok())
            .filter(|descriptor| *descriptor <= i32::MAX as u32)
            .ok_or_else(&malformed)?;
        let deleted = entry
            .get("deleted")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let read_callback = entry
            .get("read-callback")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let write_callback = entry
            .get("write-callback")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let poll_callback = entry
            .get("poll-callback")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let poll_ready_callback = entry
            .get("poll-ready-callback")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let poll_begin_callback = entry
            .get("poll-begin-callback")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let poll_end_callback = entry
            .get("poll-end-callback")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let entry_active_callbacks = entry
            .get("active-callbacks")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(&malformed)?;
        if !read_callback && !write_callback && !poll_callback {
            return Err(malformed());
        }

        read_handlers += usize::from(read_callback);
        write_handlers += usize::from(write_callback);
        poll_handlers += usize::from(poll_callback);
        deleted_handlers += usize::from(deleted);
        active_callbacks = active_callbacks
            .checked_add(u64::from(entry_active_callbacks))
            .ok_or_else(&malformed)?;
        handlers.push(QmpHotForkAioHandler {
            handler_id,
            context_id,
            descriptor,
            deleted,
            read_callback,
            write_callback,
            poll_callback,
            poll_ready_callback,
            poll_begin_callback,
            poll_end_callback,
            active_callbacks: entry_active_callbacks,
        });
    }
    if declared_read != read_handlers
        || declared_write != write_handlers
        || declared_poll != poll_handlers
        || declared_deleted != deleted_handlers
        || declared_active_callbacks != active_callbacks
        || complete == overflowed
    {
        return Err(malformed());
    }

    Ok(QmpHotForkAioHandlerInventory {
        generation,
        complete,
        overflowed,
        handlers,
    })
}

pub(super) fn parse_hot_fork_block_backend_inventory(
    value: &Value,
) -> Result<QmpHotForkBlockBackendInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkBlockBackendInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "backend-count",
        "named-backends",
        "rooted-backends",
        "device-backends",
        "writable-backends",
        "quiesced-backends",
        "in-flight",
        "backends",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_count = object
        .get("backend-count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let aggregate_fields = [
        "named-backends",
        "rooted-backends",
        "device-backends",
        "writable-backends",
        "quiesced-backends",
    ];
    let mut declared_aggregates = [0_usize; 5];
    for (index, field) in aggregate_fields.iter().enumerate() {
        declared_aggregates[index] = object
            .get(*field)
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(&malformed)?;
    }
    let declared_in_flight = object
        .get("in-flight")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let values = object
        .get("backends")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX
        || declared_count != values.len()
    {
        return Err(malformed());
    }

    let entry_fields = [
        "backend-id",
        "context-id",
        "reference-count",
        "name",
        "named",
        "name-valid",
        "root-present",
        "device-attached",
        "permissions",
        "shared-permissions",
        "write-permission",
        "permissions-disabled",
        "quiesce-depth",
        "in-flight",
        "request-queuing-disabled",
    ];
    let mut backends = Vec::with_capacity(values.len());
    let mut previous_backend_id = None;
    let mut actual_aggregates = [0_usize; 5];
    let mut actual_in_flight = 0_u64;
    let mut valid_entries = true;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        if entry.len() != entry_fields.len()
            || !entry_fields.iter().all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }

        let backend_id = entry
            .get("backend-id")
            .and_then(Value::as_u64)
            .filter(|identifier| *identifier != 0)
            .ok_or_else(&malformed)?;
        if previous_backend_id.is_some_and(|previous| previous >= backend_id) {
            return Err(malformed());
        }
        previous_backend_id = Some(backend_id);
        let context_id = entry
            .get("context-id")
            .and_then(Value::as_u64)
            .filter(|identifier| *identifier != 0)
            .ok_or_else(&malformed)?;
        let reference_count = entry
            .get("reference-count")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .filter(|count| *count != 0)
            .ok_or_else(&malformed)?;
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| name.len() <= QMP_HOT_FORK_BLOCK_BACKEND_NAME_MAX_BYTES)
            .ok_or_else(&malformed)?;
        let named = entry
            .get("named")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let name_valid = entry
            .get("name-valid")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        if named == name.is_empty() {
            return Err(malformed());
        }
        valid_entries &= name_valid;
        let root_present = entry
            .get("root-present")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let device_attached = entry
            .get("device-attached")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let permissions = entry
            .get("permissions")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?;
        let shared_permissions = entry
            .get("shared-permissions")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?;
        let write_permission = entry
            .get("write-permission")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        if write_permission != (permissions & 0x02 != 0) {
            return Err(malformed());
        }
        let permissions_disabled = entry
            .get("permissions-disabled")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let quiesce_depth = entry
            .get("quiesce-depth")
            .and_then(Value::as_u64)
            .and_then(|depth| u32::try_from(depth).ok())
            .ok_or_else(&malformed)?;
        let in_flight = entry
            .get("in-flight")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(&malformed)?;
        let request_queuing_disabled = entry
            .get("request-queuing-disabled")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;

        actual_aggregates[0] += usize::from(named);
        actual_aggregates[1] += usize::from(root_present);
        actual_aggregates[2] += usize::from(device_attached);
        actual_aggregates[3] += usize::from(write_permission);
        actual_aggregates[4] += usize::from(quiesce_depth != 0);
        actual_in_flight = actual_in_flight
            .checked_add(u64::from(in_flight))
            .ok_or_else(&malformed)?;
        backends.push(QmpHotForkBlockBackend {
            backend_id,
            context_id,
            reference_count,
            name: name.to_owned(),
            named,
            name_valid,
            root_present,
            device_attached,
            permissions,
            shared_permissions,
            write_permission,
            permissions_disabled,
            quiesce_depth,
            in_flight,
            request_queuing_disabled,
        });
    }
    if declared_aggregates != actual_aggregates
        || declared_in_flight != actual_in_flight
        || complete != (!overflowed && valid_entries)
    {
        return Err(malformed());
    }

    Ok(QmpHotForkBlockBackendInventory {
        generation,
        complete,
        overflowed,
        backends,
    })
}

pub(super) fn parse_hot_fork_bottom_half_inventory(
    value: &Value,
) -> Result<QmpHotForkBottomHalfInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkBottomHalfInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "stable",
        "bottom-half-count",
        "pending-bottom-halves",
        "scheduled-bottom-halves",
        "deleted-bottom-halves",
        "active-callbacks",
        "bottom-halves",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let stable = object
        .get("stable")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_count = object
        .get("bottom-half-count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_pending = object
        .get("pending-bottom-halves")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_scheduled = object
        .get("scheduled-bottom-halves")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_deleted = object
        .get("deleted-bottom-halves")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_active_callbacks = object
        .get("active-callbacks")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let values = object
        .get("bottom-halves")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_MAX
        || declared_count != values.len()
    {
        return Err(malformed());
    }

    let entry_fields = [
        "bottom-half-id",
        "context-id",
        "name",
        "name-valid",
        "pending",
        "scheduled",
        "deleted",
        "oneshot",
        "idle",
        "active-callbacks",
    ];
    let mut bottom_halves = Vec::with_capacity(values.len());
    let mut previous_bottom_half_id = None;
    let mut pending_count = 0_usize;
    let mut scheduled_count = 0_usize;
    let mut deleted_count = 0_usize;
    let mut active_callbacks = 0_u64;
    let mut valid_entries = true;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        if entry.len() != entry_fields.len()
            || !entry_fields.iter().all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }

        let bottom_half_id = entry
            .get("bottom-half-id")
            .and_then(Value::as_u64)
            .filter(|identifier| *identifier != 0)
            .ok_or_else(&malformed)?;
        if previous_bottom_half_id.is_some_and(|previous| previous >= bottom_half_id) {
            return Err(malformed());
        }
        previous_bottom_half_id = Some(bottom_half_id);
        let context_id = entry
            .get("context-id")
            .and_then(Value::as_u64)
            .filter(|identifier| *identifier != 0)
            .ok_or_else(&malformed)?;
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| {
                !name.is_empty() && name.len() <= QMP_HOT_FORK_BOTTOM_HALF_NAME_MAX_BYTES
            })
            .ok_or_else(&malformed)?;
        let name_valid = entry
            .get("name-valid")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let pending = entry
            .get("pending")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let scheduled = entry
            .get("scheduled")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let deleted = entry
            .get("deleted")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let oneshot = entry
            .get("oneshot")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let idle = entry
            .get("idle")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let entry_active_callbacks = entry
            .get("active-callbacks")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(&malformed)?;
        if (scheduled || idle) && !pending {
            return Err(malformed());
        }

        pending_count += usize::from(pending);
        scheduled_count += usize::from(scheduled);
        deleted_count += usize::from(deleted);
        active_callbacks = active_callbacks
            .checked_add(u64::from(entry_active_callbacks))
            .ok_or_else(&malformed)?;
        valid_entries &= name_valid;
        bottom_halves.push(QmpHotForkBottomHalf {
            bottom_half_id,
            context_id,
            name: name.to_owned(),
            name_valid,
            pending,
            scheduled,
            deleted,
            oneshot,
            idle,
            active_callbacks: entry_active_callbacks,
        });
    }
    if declared_pending != pending_count
        || declared_scheduled != scheduled_count
        || declared_deleted != deleted_count
        || declared_active_callbacks != active_callbacks
        || complete != (!overflowed && stable && valid_entries)
    {
        return Err(malformed());
    }

    Ok(QmpHotForkBottomHalfInventory {
        generation,
        complete,
        overflowed,
        stable,
        bottom_halves,
    })
}

pub(super) fn parse_hot_fork_mutex_inventory(
    value: &Value,
) -> Result<QmpHotForkMutexInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkMutexInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "mutex-count",
        "recursive-mutexes",
        "owned-mutexes",
        "acquisition-waiters",
        "condition-waiters",
        "unlock-transitions",
        "invalid-mutexes",
        "mutexes",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_mutexes = object
        .get("mutex-count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_recursive = object
        .get("recursive-mutexes")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_owned = object
        .get("owned-mutexes")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_acquisition_waiters = object
        .get("acquisition-waiters")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let declared_condition_waiters = object
        .get("condition-waiters")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let declared_unlocks = object
        .get("unlock-transitions")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_invalid = object
        .get("invalid-mutexes")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let values = object
        .get("mutexes")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_MUTEX_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_MUTEX_INVENTORY_MAX
        || declared_mutexes != values.len()
    {
        return Err(malformed());
    }

    let mut mutexes = Vec::with_capacity(values.len());
    let mut previous_mutex_id = None;
    let mut recursive_mutexes = 0_usize;
    let mut owned_mutexes = 0_usize;
    let mut acquisition_waiters = 0_u64;
    let mut condition_waiters = 0_u64;
    let mut unlock_transitions = 0_usize;
    let mut invalid_mutexes = 0_usize;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        let entry_fields = [
            "mutex-id",
            "owner-thread-id",
            "recursion-depth",
            "acquisition-waiters",
            "condition-waiters",
            "recursive",
            "unlock-active",
            "ownership-valid",
        ];
        if entry.len() != entry_fields.len()
            || !entry_fields.iter().all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }

        let mutex_id = entry
            .get("mutex-id")
            .and_then(Value::as_u64)
            .filter(|mutex_id| *mutex_id != 0)
            .ok_or_else(&malformed)?;
        if previous_mutex_id.is_some_and(|previous| previous >= mutex_id) {
            return Err(malformed());
        }
        previous_mutex_id = Some(mutex_id);
        let owner_thread_id = match entry.get("owner-thread-id").and_then(Value::as_i64) {
            Some(0) => None,
            Some(thread_id) => Some(
                u32::try_from(thread_id)
                    .ok()
                    .filter(|thread_id| *thread_id != 0)
                    .ok_or_else(&malformed)?,
            ),
            None => return Err(malformed()),
        };
        let recursion_depth = entry
            .get("recursion-depth")
            .and_then(Value::as_u64)
            .and_then(|depth| u32::try_from(depth).ok())
            .ok_or_else(&malformed)?;
        let entry_acquisition_waiters = entry
            .get("acquisition-waiters")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(&malformed)?;
        let entry_condition_waiters = entry
            .get("condition-waiters")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(&malformed)?;
        let recursive = entry
            .get("recursive")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let unlock_active = entry
            .get("unlock-active")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let ownership_valid = entry
            .get("ownership-valid")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        if owner_thread_id.is_some() != (recursion_depth != 0)
            || (!recursive && recursion_depth > 1)
        {
            return Err(malformed());
        }

        recursive_mutexes += usize::from(recursive);
        owned_mutexes += usize::from(owner_thread_id.is_some());
        acquisition_waiters = acquisition_waiters
            .checked_add(u64::from(entry_acquisition_waiters))
            .ok_or_else(&malformed)?;
        condition_waiters = condition_waiters
            .checked_add(u64::from(entry_condition_waiters))
            .ok_or_else(&malformed)?;
        unlock_transitions += usize::from(unlock_active);
        invalid_mutexes += usize::from(!ownership_valid);
        mutexes.push(QmpHotForkMutex {
            mutex_id,
            owner_thread_id,
            recursion_depth,
            acquisition_waiters: entry_acquisition_waiters,
            condition_waiters: entry_condition_waiters,
            recursive,
            unlock_active,
            ownership_valid,
        });
    }
    if declared_recursive != recursive_mutexes
        || declared_owned != owned_mutexes
        || declared_acquisition_waiters != acquisition_waiters
        || declared_condition_waiters != condition_waiters
        || declared_unlocks != unlock_transitions
        || declared_invalid != invalid_mutexes
        || complete != (!overflowed && invalid_mutexes == 0)
    {
        return Err(malformed());
    }

    Ok(QmpHotForkMutexInventory {
        generation,
        complete,
        overflowed,
        mutexes,
    })
}

pub(super) fn parse_hot_fork_timer_inventory(
    value: &Value,
) -> Result<QmpHotForkTimerInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkTimerInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "timer-count",
        "pending-timers",
        "active-callbacks",
        "timers",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_timer_count = object
        .get("timer-count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_pending = object
        .get("pending-timers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_callbacks = object
        .get("active-callbacks")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let values = object
        .get("timers")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_TIMER_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_TIMER_INVENTORY_MAX
        || declared_timer_count != values.len()
    {
        return Err(malformed());
    }

    let mut timers = Vec::with_capacity(values.len());
    let mut previous_timer_id = None;
    let mut pending_timers = 0_usize;
    let mut active_callbacks = 0_usize;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        let entry_fields = [
            "timer-id",
            "timer-list-id",
            "clock",
            "expire-time-ns",
            "scale",
            "attributes",
            "pending",
            "callback-active",
        ];
        if entry.len() != entry_fields.len()
            || !entry_fields.iter().all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }

        let timer_id = entry
            .get("timer-id")
            .and_then(Value::as_u64)
            .filter(|timer_id| *timer_id != 0)
            .ok_or_else(&malformed)?;
        if previous_timer_id.is_some_and(|previous| previous >= timer_id) {
            return Err(malformed());
        }
        previous_timer_id = Some(timer_id);
        let timer_list_id = entry
            .get("timer-list-id")
            .and_then(Value::as_u64)
            .filter(|timer_list_id| *timer_list_id != 0)
            .ok_or_else(&malformed)?;
        let clock = match entry.get("clock").and_then(Value::as_str) {
            Some("realtime") => QmpHotForkTimerClock::Realtime,
            Some("virtual") => QmpHotForkTimerClock::Virtual,
            Some("host") => QmpHotForkTimerClock::Host,
            Some("virtual-realtime") => QmpHotForkTimerClock::VirtualRealtime,
            _ => return Err(malformed()),
        };
        let raw_expire_time_ns = entry
            .get("expire-time-ns")
            .and_then(Value::as_i64)
            .ok_or_else(&malformed)?;
        let scale = entry
            .get("scale")
            .and_then(Value::as_u64)
            .and_then(|scale| u32::try_from(scale).ok())
            .filter(|scale| *scale != 0)
            .ok_or_else(&malformed)?;
        let attributes = entry
            .get("attributes")
            .and_then(Value::as_u64)
            .and_then(|attributes| u32::try_from(attributes).ok())
            .ok_or_else(&malformed)?;
        let pending = entry
            .get("pending")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let callback_active = entry
            .get("callback-active")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let expire_time_ns = match (pending, raw_expire_time_ns) {
            (true, expire_time_ns @ 0..) => Some(expire_time_ns as u64),
            (false, -1) => None,
            _ => return Err(malformed()),
        };
        if !pending && !callback_active {
            return Err(malformed());
        }

        pending_timers += usize::from(pending);
        active_callbacks += usize::from(callback_active);
        timers.push(QmpHotForkTimer {
            timer_id,
            timer_list_id,
            clock,
            expire_time_ns,
            scale,
            attributes,
            pending,
            callback_active,
        });
    }
    if declared_pending != pending_timers
        || declared_callbacks != active_callbacks
        || complete == overflowed
    {
        return Err(malformed());
    }

    Ok(QmpHotForkTimerInventory {
        generation,
        complete,
        overflowed,
        timers,
    })
}

pub(super) fn parse_hot_fork_monitor_inventory(
    value: &Value,
) -> Result<QmpHotForkMonitorInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkMonitorInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "monitor-count",
        "qmp-monitors",
        "hmp-monitors",
        "io-thread-monitors",
        "suspended-monitors",
        "negotiating-monitors",
        "oob-enabled-monitors",
        "queued-requests",
        "parser-buffered-bytes",
        "partial-parsers",
        "unstable-monitors",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let u32_field = |name| {
        object
            .get(name)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(&malformed)
    };
    let schema_version = u32_field("schema-version")?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let monitor_count = u32_field("monitor-count")?;
    let qmp_monitors = u32_field("qmp-monitors")?;
    let hmp_monitors = u32_field("hmp-monitors")?;
    let io_thread_monitors = u32_field("io-thread-monitors")?;
    let suspended_monitors = u32_field("suspended-monitors")?;
    let negotiating_monitors = u32_field("negotiating-monitors")?;
    let oob_enabled_monitors = u32_field("oob-enabled-monitors")?;
    let queued_requests = object
        .get("queued-requests")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let parser_buffered_bytes = object
        .get("parser-buffered-bytes")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let partial_parsers = u32_field("partial-parsers")?;
    let unstable_monitors = u32_field("unstable-monitors")?;

    if schema_version != QMP_HOT_FORK_MONITOR_INVENTORY_SCHEMA_VERSION
        || usize::try_from(monitor_count).ok() > Some(QMP_HOT_FORK_MONITOR_INVENTORY_MAX)
        || qmp_monitors.checked_add(hmp_monitors) != Some(monitor_count)
        || io_thread_monitors > monitor_count
        || suspended_monitors > monitor_count
        || negotiating_monitors > qmp_monitors
        || oob_enabled_monitors > qmp_monitors
        || partial_parsers > qmp_monitors
        || unstable_monitors > qmp_monitors
        || (partial_parsers == 0 && parser_buffered_bytes != 0)
        || complete != (!overflowed && unstable_monitors == 0)
    {
        return Err(malformed());
    }

    Ok(QmpHotForkMonitorInventory {
        generation,
        complete,
        overflowed,
        monitor_count,
        qmp_monitors,
        hmp_monitors,
        io_thread_monitors,
        suspended_monitors,
        negotiating_monitors,
        oob_enabled_monitors,
        queued_requests,
        parser_buffered_bytes,
        partial_parsers,
        unstable_monitors,
    })
}
